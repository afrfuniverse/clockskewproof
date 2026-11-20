"""Compare captured clock readings with certificate and Kerberos timing evidence."""

from argparse import ArgumentParser
from datetime import datetime, timedelta, timezone
from html import escape
import json
from pathlib import Path
import re
import sys

from clock_capture import probe_clock, read_certificate_validity


VERSION = "0.1.0"
TIMESTAMP = re.compile(
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])"
)


def parse_timestamp(value, field):
    message = f"{field} must be an ISO 8601 timestamp with seconds and an explicit UTC offset"
    if not isinstance(value, str) or not TIMESTAMP.fullmatch(value):
        raise ValueError(message)
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except (ValueError, OverflowError) as exc:
        raise ValueError(message) from exc


def require_object(value, field):
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be a JSON object")
    return value


def unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def utc_string(value):
    return value.isoformat().replace("+00:00", "Z")


def window_status(moment, start, end):
    if moment < start:
        return "NOT_YET_VALID"
    if moment > end:
        return "EXPIRED"
    return "WITHIN_WINDOW"


def measurement_details(value, field):
    data = require_object(value, field)
    source = data.get("source")
    if not isinstance(source, str) or not source.strip() or not source.isprintable():
        raise ValueError(f"{field}.source must be a printable hostname or address")
    port = data.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError(f"{field}.port must be between 1 and 65535")
    for key in ("round_trip_us", "uncertainty_us"):
        if type(data.get(key)) is not int or data[key] < 0:
            raise ValueError(f"{field}.{key} must be a nonnegative integer")
    return {
        "source": source,
        "port": port,
        "round_trip_us": data["round_trip_us"],
        "uncertainty_us": data["uncertainty_us"],
    }


def analyze(evidence):
    evidence = require_object(evidence, "evidence")
    client = parse_timestamp(evidence.get("client_time"), "client_time")
    reference = parse_timestamp(evidence.get("reference_time"), "reference_time")
    report = {
        "client_time_utc": utc_string(client),
        "reference_time_utc": utc_string(reference),
        "client_minus_reference_seconds": (client - reference).total_seconds(),
    }
    ref_margin = timedelta()
    if "reference_measurement" in evidence:
        ref_measurement = measurement_details(evidence["reference_measurement"], "reference_measurement")
        report["reference_measurement"] = ref_measurement
        ref_margin = timedelta(microseconds=ref_measurement["uncertainty_us"])

    if "certificate" in evidence:
        cert = require_object(evidence["certificate"], "certificate")
        start = parse_timestamp(cert.get("not_before"), "certificate.not_before")
        end = parse_timestamp(cert.get("not_after"), "certificate.not_after")
        if start > end:
            raise ValueError("certificate.not_before must be on or before certificate.not_after")

        at_client = window_status(client, start, end)
        at_reference = window_status(reference, start, end)
        earliest = window_status(reference - ref_margin, start, end)
        latest = window_status(reference + ref_margin, start, end)
        if earliest != latest:
            finding = "REFERENCE_NEAR_BOUNDARY"
        elif at_reference != "WITHIN_WINDOW":
            finding = "OUTSIDE_REFERENCE_WINDOW"
        elif at_client == "WITHIN_WINDOW":
            finding = "WITHIN_BOTH_WINDOWS"
        else:
            finding = "CLOCK_SKEW_MAY_EXPLAIN"
        report["certificate"] = {
            "not_before_utc": utc_string(start),
            "not_after_utc": utc_string(end),
            "at_client_time": at_client,
            "at_reference_time": at_reference,
            "finding": finding,
        }

    if "kerberos" in evidence:
        kerberos = require_object(evidence["kerberos"], "kerberos")
        kdc = parse_timestamp(kerberos.get("kdc_time"), "kerberos.kdc_time")
        observed_client = client
        if "client_time" in kerberos:
            observed_client = parse_timestamp(kerberos["client_time"], "kerberos.client_time")
        tolerance = kerberos.get("tolerance_seconds")
        if type(tolerance) is not int or tolerance <= 0:
            raise ValueError("kerberos.tolerance_seconds must be a positive integer")

        delta = observed_client - kdc
        magnitude = abs(delta)
        limit = timedelta(seconds=tolerance)
        kdc_measurement = None
        margin = timedelta()
        if "measurement" in kerberos:
            kdc_measurement = measurement_details(kerberos["measurement"], "kerberos.measurement")
            margin = timedelta(microseconds=kdc_measurement["uncertainty_us"])
        if magnitude + margin < limit:
            comparison = "BELOW_TOLERANCE"
        elif magnitude - margin > limit:
            comparison = "ABOVE_TOLERANCE"
        elif not margin and magnitude == limit:
            comparison = "AT_TOLERANCE"
        else:
            comparison = "NEAR_TOLERANCE"
        report["kerberos"] = {
            "client_time_utc": utc_string(observed_client),
            "kdc_time_utc": utc_string(kdc),
            "client_minus_kdc_seconds": delta.total_seconds(),
            "tolerance_seconds": tolerance,
            "comparison": comparison,
        }
        if kdc_measurement is not None:
            report["kerberos"]["measurement"] = kdc_measurement
    return report


def signed_seconds(value):
    return f"{value:+.6f}".rstrip("0").rstrip(".") + " s"


def measurement_rows(data):
    return [
        ("NTP source", f"{data['source']} (UDP {data['port']})"),
        ("Round-trip delay", f"{data['round_trip_us'] / 1000:g} ms"),
        ("Estimated timing margin", f"{data['uncertainty_us'] / 1000:g} ms"),
    ]


def report_sections(report):
    clock = [
        ("Client UTC", report["client_time_utc"]),
        ("Reference UTC", report["reference_time_utc"]),
        ("Client - reference", signed_seconds(report["client_minus_reference_seconds"])),
    ]
    if measurement := report.get("reference_measurement"):
        clock.extend(measurement_rows(measurement))
    blocks = [("Clock readings", clock)]
    if cert := report.get("certificate"):
        blocks.append(("Certificate validity window", [
            ("Begins UTC", cert["not_before_utc"]),
            ("Ends UTC", cert["not_after_utc"]),
            ("At client time", cert["at_client_time"]),
            ("At reference time", cert["at_reference_time"]),
            ("Finding", cert["finding"]),
        ]))
    if kerberos := report.get("kerberos"):
        rows = [
            ("Client UTC", kerberos["client_time_utc"]),
            ("KDC UTC", kerberos["kdc_time_utc"]),
            ("Client - KDC", signed_seconds(kerberos["client_minus_kdc_seconds"])),
            ("Supplied tolerance", f"{kerberos['tolerance_seconds']} s"),
            ("Comparison", kerberos["comparison"]),
        ]
        if measurement := kerberos.get("measurement"):
            rows.extend(measurement_rows(measurement))
        blocks.append(("Kerberos clock comparison", rows))
    return blocks


def format_text(report):
    blocks = []
    for heading, rows in report_sections(report):
        width = max(len(label) for label, _ in rows) + 2
        blocks.append("\n".join([heading, *(f"  {label:<{width}}{value}" for label, value in rows)]))
    return "\n\n".join(blocks)


def format_html(report):
    sections = []
    for title, rows in report_sections(report):
        body = "\n".join(
            f'<tr><th scope="row">{escape(label)}</th><td>{escape(value)}</td></tr>'
            for label, value in rows
        )
        sections.append(f"<section><h2>{escape(title)}</h2><table><tbody>\n{body}\n</tbody></table></section>")
    content = "\n".join(sections)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ClockSkewProof report</title>
<style>
body {{ background: #f0f5f8; color: #152638; font: 1rem system-ui, sans-serif; margin: 1rem; }}
main {{ margin: 2rem auto; max-width: 54rem; }}
h1 {{ margin-bottom: .4rem; }}
p {{ line-height: 1.55; }}
section {{ background: #fff; border: 1px solid #d4e2e9; border-radius: 10px;
          margin: 1.2rem 0; padding: 1.1rem 1.35rem; }}
h2 {{ font-size: 1.2rem; margin: 0 0 .6rem; color: #126368; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ text-align: left; vertical-align: top; padding: .53rem .4rem;
          border-bottom: 1px solid #e1eaef; overflow-wrap: anywhere; }}
th {{ width: 43%; }}
td {{ font: .96rem Consolas, ui-monospace, monospace; }}
</style>
</head>
<body>
<main>
<h1>ClockSkewProof report</h1>
<p>Clock readings and timing checks, expressed in UTC.</p>
{content}
<p>Findings apply to the recorded readings, certificate validity window and supplied
Kerberos tolerance.</p>
</main>
</body>
</html>"""


def sample_metadata(host, port, sample):
    return {
        "source": host,
        "port": port,
        "round_trip_us": sample.round_trip_us,
        "uncertainty_us": sample.uncertainty_us,
    }


def capture_evidence(args):
    reference_port = args.reference_port if args.reference_port is not None else 123
    reference = probe_clock(args.reference, reference_port)
    evidence = {
        "client_time": utc_string(reference.client_time),
        "reference_time": utc_string(reference.server_time),
        "reference_measurement": sample_metadata(args.reference, reference_port, reference),
    }
    if args.kdc:
        kdc_port = args.kdc_port if args.kdc_port is not None else 123
        if (args.kdc.casefold(), kdc_port) == (args.reference.casefold(), reference_port):
            kdc = reference
        else:
            kdc = probe_clock(args.kdc, kdc_port)
        evidence["kerberos"] = {
            "client_time": utc_string(kdc.client_time),
            "kdc_time": utc_string(kdc.server_time),
            "tolerance_seconds": args.kerberos_tolerance_seconds,
            "measurement": sample_metadata(args.kdc, kdc_port, kdc),
        }
    return evidence


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("evidence", nargs="?", type=Path, help="path to a saved JSON evidence file")
    parser.add_argument("--reference", help="hostname or address of the NTP reference to query")
    parser.add_argument("--reference-port", type=int, help="reference UDP port (default 123)")
    parser.add_argument("--kdc", help="hostname or address of the domain controller's NTP service")
    parser.add_argument("--kdc-port", type=int, help="domain controller UDP port (default 123)")
    parser.add_argument("--kerberos-tolerance-seconds", type=int, help="effective policy value for --kdc")
    parser.add_argument("--certificate", type=Path, help="public DER or single PEM X.509 certificate (Windows)")
    parser.add_argument("--format", choices=("text", "json", "html", "evidence"), default="text")
    parser.add_argument("--version", action="version", version=f"ClockSkewProof {VERSION}")
    args = parser.parse_args(argv)
    if (args.evidence is None) == (args.reference is None):
        parser.error("provide either a saved evidence file or --reference")
    ntp_only = (args.reference_port, args.kdc, args.kdc_port, args.kerberos_tolerance_seconds)
    if args.evidence is not None and any(value is not None for value in ntp_only):
        parser.error("live capture options require --reference")
    if (args.kdc is None) != (args.kerberos_tolerance_seconds is None):
        parser.error("--kdc and --kerberos-tolerance-seconds must be supplied together")
    if args.kdc_port is not None and args.kdc is None:
        parser.error("--kdc-port requires --kdc")
    for option, host in [("--reference", args.reference), ("--kdc", args.kdc)]:
        if host is not None and (not host or not host.isprintable() or any(c.isspace() for c in host)):
            parser.error(f"{option} requires a single hostname or IP address")
    for option, port in [("--reference-port", args.reference_port), ("--kdc-port", args.kdc_port)]:
        if port is not None and not 1 <= port <= 65535:
            parser.error(f"{option} must be between 1 and 65535")
    if args.kerberos_tolerance_seconds is not None and args.kerberos_tolerance_seconds <= 0:
        parser.error("--kerberos-tolerance-seconds must be a positive integer")
    try:
        cert_window = read_certificate_validity(args.certificate) if args.certificate else None
        if args.evidence is None:
            evidence = capture_evidence(args)
        else:
            evidence = require_object(
                json.loads(args.evidence.read_text(encoding="utf-8-sig"), object_pairs_hook=unique_fields),
                "evidence",
            )
        if cert_window is not None:
            if "certificate" in evidence:
                raise ValueError("the evidence file already supplies a certificate window")
            begins, ends = cert_window
            evidence["certificate"] = {"not_before": utc_string(begins), "not_after": utc_string(ends)}
        report = analyze(evidence)
    except (OSError, ValueError, OverflowError) as exc:
        print(f"ClockSkewProof: {exc}", file=sys.stderr)
        return 2

    if args.format == "json":
        print(json.dumps(report, indent=2))
    elif args.format == "evidence":
        print(json.dumps(evidence, indent=2))
    elif args.format == "html":
        print(format_html(report))
    else:
        print(format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
