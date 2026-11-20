from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timedelta, timezone
import json
from io import StringIO
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from clock_capture import (
    certificate_der, ntp_timestamp, parse_ntp_reply, probe_clock,
    read_certificate_validity, timestamp_ns,
)
from clockskewproof import analyze, format_html, main


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "clockskewproof-test.pem"
NANO = 1_000_000_000
SENT = 1_790_000_000 * NANO


def ntp_reply(originate, received, sent):
    packet = bytearray(48)
    packet[0] = 0x24
    packet[1] = 2
    packet[24:32] = originate
    packet[32:40] = ntp_timestamp(received)
    packet[40:48] = ntp_timestamp(sent)
    return packet


def timed_reply(offset=420):
    return ntp_reply(
        ntp_timestamp(SENT),
        SENT + offset * NANO + 15_000_000,
        SENT + offset * NANO + 35_000_000,
    )


@contextmanager
def local_ntp(offset):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.settimeout(5)
        problems = []

        def respond():
            try:
                request, address = listener.recvfrom(1024)
                received = time.time_ns() + offset * NANO
                if len(request) != 48 or request[0] != 0x23:
                    raise ValueError("unexpected NTP client request")
                response = ntp_reply(request[40:48], received, time.time_ns() + offset * NANO)
                listener.sendto(response, address)
            except (OSError, ValueError) as exc:
                problems.append(exc)

        worker = threading.Thread(target=respond, daemon=True)
        worker.start()
        try:
            yield listener.getsockname()[1]
        finally:
            worker.join(timeout=6)
            if worker.is_alive() or problems:
                raise AssertionError(f"local NTP fixture failed: {problems}")


class NtpTests(unittest.TestCase):
    def test_epoch_and_fraction_wire_format(self):
        self.assertEqual(ntp_timestamp(500_000_000), struct.pack("!II", 2_208_988_800, 0x80000000))

    def test_era_wrap_both_sides(self):
        wrap = ((1 << 32) - 2_208_988_800) * NANO
        for moment in (wrap - NANO, wrap + NANO):
            with self.subTest(moment=moment):
                self.assertEqual(timestamp_ns(ntp_timestamp(moment), wrap), moment)

    def test_offset_has_correct_sign_and_removes_processing_delay(self):
        for offset in (-420, 420):
            with self.subTest(offset=offset):
                packet = timed_reply(offset)
                struct.pack_into("!iI", packet, 4, 65536, 16384)
                result = parse_ntp_reply(packet, SENT, SENT + 50_000_000)
                actual = (result.server_time - result.client_time).total_seconds()
                self.assertAlmostEqual(actual, offset, places=5)
                self.assertLessEqual(abs(result.round_trip_us - 30000), 1)
                self.assertLessEqual(abs(result.uncertainty_us - 765001), 3)

    def test_rejects_unmatched_origin_and_missing_timestamps(self):
        for start, end in ((24, 32), (32, 40), (40, 48)):
            with self.subTest(start=start), self.assertRaises(ValueError):
                packet = timed_reply()
                packet[start:end] = bytes(end - start)
                parse_ntp_reply(packet, SENT, SENT + 50_000_000)

    def test_rejects_unsynchronized_kiss_of_death_and_wrong_mode(self):
        for header, stratum in [(0xe4, 2), (0x24, 0), (0x24, 16), (0x25, 2), (0x14, 2)]:
            with self.subTest(header=header, stratum=stratum), self.assertRaises(ValueError):
                packet = timed_reply()
                packet[0], packet[1] = header, stratum
                parse_ntp_reply(packet, SENT, SENT + 50_000_000)

    def test_rejects_truncated_and_impossible_timings(self):
        bad = timed_reply()
        with self.assertRaisesRegex(ValueError, "short"):
            parse_ntp_reply(bad[:41], SENT, SENT + 50_000_000)
        with self.assertRaisesRegex(ValueError, "inconsistent"):
            parse_ntp_reply(bad, SENT, SENT + 5_000_000)

    def test_wall_clock_step_is_rejected(self):
        transport = MagicMock()
        with (
            patch("clock_capture.socket.getaddrinfo", return_value=[(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", ("127.0.0.1", 123)
            )]),
            patch("clock_capture.socket.socket", return_value=transport),
            patch("clock_capture.time.time_ns", side_effect=[SENT, SENT + 9 * NANO]),
            patch("clock_capture.time.monotonic_ns", side_effect=[NANO, NANO + 50_000_000]),
        ):
            with self.assertRaisesRegex(ValueError, "wall clock changed"):
                probe_clock("127.0.0.1")

    def test_probe_times_out_cleanly(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener:
            listener.bind(("127.0.0.1", 0))
            with self.assertRaisesRegex(ValueError, "could not read an NTP sample"):
                probe_clock("127.0.0.1", listener.getsockname()[1], timeout=0.05)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.evidence = json.loads((ROOT / "examples" / "client-behind.json").read_text(encoding="utf-8"))
        self.measurement = {
            "source": "clock.example.test",
            "port": 123,
            "round_trip_us": 120,
            "uncertainty_us": 125,
        }

    def test_reference_margin_marks_a_certificate_boundary(self):
        self.evidence["reference_time"] = self.evidence["certificate"]["not_before"]
        self.evidence["reference_measurement"] = self.measurement
        cert = analyze(self.evidence)["certificate"]
        self.assertEqual(cert["at_reference_time"], "WITHIN_WINDOW")
        self.assertEqual(cert["finding"], "REFERENCE_NEAR_BOUNDARY")

    def test_report_still_uses_offset_when_window_is_well_inside_margin(self):
        self.evidence["reference_measurement"] = self.measurement
        self.assertEqual(analyze(self.evidence)["certificate"]["finding"], "CLOCK_SKEW_MAY_EXPLAIN")

    def test_kdc_uses_its_paired_client_reading_and_margin(self):
        self.evidence["kerberos"]["client_time"] = "2026-11-20T10:02:00Z"
        self.evidence["kerberos"]["measurement"] = self.measurement
        report = analyze(self.evidence)
        self.assertEqual(report["client_minus_reference_seconds"], -420)
        self.assertEqual(report["kerberos"]["client_minus_kdc_seconds"], -300)
        self.assertEqual(report["kerberos"]["comparison"], "NEAR_TOLERANCE")

    def test_html_escapes_source_labels(self):
        self.measurement["source"] = "<example>"
        self.evidence["reference_measurement"] = self.measurement
        html = format_html(analyze(self.evidence))
        self.assertIn("&lt;example&gt;", html)
        self.assertNotIn("<example>", html)


class LiveCliTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "clockskewproof.py"), *args],
            capture_output=True, text=True, check=False, timeout=8,
        )

    def require_udp_loopback(self):
        # Test the host transport independently before exercising the product.
        try:
            with (
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as listener,
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender,
            ):
                listener.bind(("127.0.0.1", 0))
                listener.settimeout(0.5)
                sender.sendto(b"udp-check", listener.getsockname())
                payload, _ = listener.recvfrom(32)
                self.assertEqual(payload, b"udp-check")
        except OSError as exc:
            self.skipTest(f"local UDP loopback unavailable: {exc}")

    def test_reference_capture_reuse_and_replay(self):
        self.require_udp_loopback()
        with local_ntp(420) as port:
            result = self.run_cli(
                "--reference", "127.0.0.1", "--reference-port", str(port),
                "--kdc", "127.0.0.1", "--kdc-port", str(port),
                "--kerberos-tolerance-seconds", "300", "--format", "evidence",
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        evidence = json.loads(result.stdout)
        self.assertEqual(evidence["client_time"], evidence["kerberos"]["client_time"])
        self.assertEqual(evidence["reference_time"], evidence["kerberos"]["kdc_time"])
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "captured.json"
            path.write_text(result.stdout, encoding="utf-8")
            replay = self.run_cli(str(path), "--format", "json")
        self.assertEqual(replay.returncode, 0, replay.stderr)
        report = json.loads(replay.stdout)
        self.assertAlmostEqual(report["client_minus_reference_seconds"], -420, delta=0.1)
        self.assertEqual(report["kerberos"]["comparison"], "ABOVE_TOLERANCE")

    def test_two_distinct_servers(self):
        self.require_udp_loopback()
        with local_ntp(420) as ref_port, local_ntp(120) as kdc_port:
            result = self.run_cli(
                "--reference", "127.0.0.1", "--reference-port", str(ref_port),
                "--kdc", "127.0.0.1", "--kdc-port", str(kdc_port),
                "--kerberos-tolerance-seconds", "300", "--format", "json",
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertAlmostEqual(report["client_minus_reference_seconds"], -420, delta=0.1)
        self.assertAlmostEqual(report["kerberos"]["client_minus_kdc_seconds"], -120, delta=0.1)
        self.assertEqual(report["kerberos"]["comparison"], "BELOW_TOLERANCE")

    def test_conflicting_modes_and_incomplete_kdc_options(self):
        for args, expected in [
            (("sample.json", "--reference", "127.0.0.1"), "either a saved evidence file or --reference"),
            (("--reference", "127.0.0.1", "--kdc", "127.0.0.1"), "must be supplied together"),
            (("--reference", ""), "single hostname or IP address"),
        ]:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(result.returncode, 2)
                self.assertIn(expected, result.stderr)


class CapturePipelineTests(unittest.TestCase):
    def run_capture(self, offsets, *args):
        clocks = []
        monotonic = []
        transports = []
        for i, offset in enumerate(offsets):
            sent = SENT + i * 2 * NANO
            clocks.extend([sent, sent + 50_000_000])
            monotonic.extend([i * 2 * NANO, i * 2 * NANO + 50_000_000])
            wire = ntp_reply(
                ntp_timestamp(sent),
                sent + offset * NANO + 15_000_000,
                sent + offset * NANO + 35_000_000,
            )
            transport = MagicMock()
            transport.__enter__.return_value = transport
            transport.recv.return_value = wire
            transports.append(transport)
        output = StringIO()
        addresses = lambda host, port, **unused: [
            (socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP, "", (host, port))
        ]
        with (
            patch("clock_capture.socket.getaddrinfo", side_effect=addresses),
            patch("clock_capture.socket.socket", side_effect=transports) as sockets,
            patch("clock_capture.time.time_ns", side_effect=clocks),
            patch("clock_capture.time.monotonic_ns", side_effect=monotonic),
            redirect_stdout(output),
        ):
            self.assertEqual(main(list(args)), 0)
        self.assertEqual(sockets.call_count, len(offsets))
        return json.loads(output.getvalue())

    def test_same_host_reuses_sample_and_serializes_evidence(self):
        evidence = self.run_capture(
            [420], "--reference", "127.0.0.1", "--kdc", "127.0.0.1",
            "--kerberos-tolerance-seconds", "300", "--format", "evidence",
        )
        self.assertEqual(evidence["reference_time"], evidence["kerberos"]["kdc_time"])
        self.assertEqual(evidence["client_time"], evidence["kerberos"]["client_time"])
        result = analyze(evidence)
        self.assertAlmostEqual(result["client_minus_reference_seconds"], -420, places=5)
        self.assertEqual(result["kerberos"]["comparison"], "ABOVE_TOLERANCE")

    def test_separate_hosts_keep_their_paired_timestamps(self):
        report = self.run_capture(
            [420, 120], "--reference", "127.0.0.1", "--kdc", "127.0.0.2",
            "--kerberos-tolerance-seconds", "300", "--format", "json",
        )
        self.assertNotEqual(report["client_time_utc"], report["kerberos"]["client_time_utc"])
        self.assertAlmostEqual(report["kerberos"]["client_minus_kdc_seconds"], -120, places=5)
        self.assertEqual(report["kerberos"]["comparison"], "BELOW_TOLERANCE")


@unittest.skipUnless(sys.platform == "win32", "certificate file reading uses Windows CryptoAPI")
class WindowsCertificateTests(unittest.TestCase):
    def test_reads_public_pem_and_der_exactly(self):
        expected = (
            datetime(2026, 1, 1, tzinfo=timezone.utc),
            datetime(2036, 1, 1, tzinfo=timezone.utc),
        )
        self.assertEqual(read_certificate_validity(FIXTURE), expected)
        with tempfile.TemporaryDirectory() as folder:
            der = Path(folder) / "fixture.cer"
            der.write_bytes(certificate_der(FIXTURE.read_bytes()))
            self.assertEqual(read_certificate_validity(der), expected)

    def test_rejects_certificate_bundles_and_invalid_der(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "certificate.pem"
            path.write_bytes(FIXTURE.read_bytes() * 2)
            with self.assertRaisesRegex(ValueError, "single PEM"):
                read_certificate_validity(path)
            path.write_bytes(b"not an X.509 certificate")
            with self.assertRaisesRegex(ValueError, "Windows could not read"):
                read_certificate_validity(path)

    def test_cli_attaches_public_certificate_to_saved_readings(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "times.json"
            path.write_text(json.dumps({
                "client_time": "2025-12-31T23:59:59Z",
                "reference_time": "2026-01-01T00:00:01Z",
            }), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-B", str(ROOT / "clockskewproof.py"), str(path),
                 "--certificate", str(FIXTURE), "--format", "json"],
                capture_output=True, text=True, check=False, timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        cert = json.loads(result.stdout)["certificate"]
        self.assertEqual(cert["not_before_utc"], "2026-01-01T00:00:00Z")
        self.assertEqual(cert["finding"], "CLOCK_SKEW_MAY_EXPLAIN")
