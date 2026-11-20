import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from clockskewproof import analyze, parse_timestamp


ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "client-behind.json"


class AnalysisTests(unittest.TestCase):
    def setUp(self):
        self.evidence = json.loads(EXAMPLE.read_text(encoding="utf-8"))

    def test_client_clock_can_explain_window_difference(self):
        report = analyze(self.evidence)
        self.assertEqual(report["client_minus_reference_seconds"], -420)
        self.assertEqual(report["certificate"]["at_client_time"], "NOT_YET_VALID")
        self.assertEqual(report["certificate"]["at_reference_time"], "WITHIN_WINDOW")
        self.assertEqual(report["certificate"]["finding"], "CLOCK_SKEW_MAY_EXPLAIN")
        self.assertEqual(report["kerberos"]["comparison"], "ABOVE_TOLERANCE")

    def test_certificate_can_be_expired_at_both_times(self):
        self.evidence["certificate"].update(
            not_before="2026-11-19T10:00:00Z", not_after="2026-11-20T09:00:00Z"
        )
        cert = analyze(self.evidence)["certificate"]
        self.assertEqual(cert["at_client_time"], "EXPIRED")
        self.assertEqual(cert["at_reference_time"], "EXPIRED")
        self.assertEqual(cert["finding"], "OUTSIDE_REFERENCE_WINDOW")

    def test_client_can_hide_reference_time_expiration(self):
        self.evidence["certificate"].update(
            not_before="2026-11-19T10:00:00Z", not_after="2026-11-20T10:03:00Z"
        )
        cert = analyze(self.evidence)["certificate"]
        self.assertEqual(cert["at_client_time"], "WITHIN_WINDOW")
        self.assertEqual(cert["at_reference_time"], "EXPIRED")
        self.assertEqual(cert["finding"], "OUTSIDE_REFERENCE_WINDOW")

    def test_fast_client_can_see_early_expiration(self):
        self.evidence["client_time"] = "2026-11-21T10:08:00Z"
        report = analyze(self.evidence)
        self.assertGreater(report["client_minus_reference_seconds"], 0)
        self.assertEqual(report["certificate"]["at_client_time"], "EXPIRED")
        self.assertEqual(report["certificate"]["finding"], "CLOCK_SKEW_MAY_EXPLAIN")

    def test_offsets_are_normalized_to_utc(self):
        self.evidence["client_time"] = "2026-11-20T12:07:00+02:00"
        report = analyze(self.evidence)
        self.assertEqual(report["client_time_utc"], report["reference_time_utc"])
        self.assertEqual(report["client_minus_reference_seconds"], 0)

    def test_certificate_window_endpoints_are_inclusive(self):
        cert = self.evidence["certificate"]
        self.evidence["client_time"] = cert["not_before"]
        self.evidence["reference_time"] = cert["not_after"]
        self.assertEqual(analyze(self.evidence)["certificate"]["finding"], "WITHIN_BOTH_WINDOWS")

    def test_kerberos_uses_the_kdc_clock(self):
        self.evidence["kerberos"]["kdc_time"] = "2026-11-20T10:02:00Z"
        report = analyze(self.evidence)
        self.assertEqual(report["client_minus_reference_seconds"], -420)
        self.assertEqual(report["kerberos"]["client_minus_kdc_seconds"], -120)
        self.assertEqual(report["kerberos"]["comparison"], "BELOW_TOLERANCE")

    def test_tolerance_boundary_and_microseconds(self):
        for t, expected in [
            ("10:04:59.999999Z", "BELOW_TOLERANCE"),
            ("10:05:00Z", "AT_TOLERANCE"),
            ("10:05:00.000001Z", "ABOVE_TOLERANCE"),
        ]:
            with self.subTest(t=t):
                self.evidence["kerberos"]["kdc_time"] = "2026-11-20T" + t
                self.assertEqual(analyze(self.evidence)["kerberos"]["comparison"], expected)

    def test_clock_comparison_can_run_on_its_own(self):
        report = analyze({k: self.evidence[k] for k in ("client_time", "reference_time")})
        self.assertEqual(report["client_minus_reference_seconds"], -420)
        self.assertNotIn("certificate", report)
        self.assertNotIn("kerberos", report)

    def test_bad_timestamps_are_rejected(self):
        for value in ["2026-11-20T10:00:00", "2026-11-20T10:00:00+00:60", "2026-02-30T10:00:00Z", None]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_timestamp(value, "client_time")

    def test_reversed_window_and_boolean_tolerance_are_rejected(self):
        original_start = self.evidence["certificate"]["not_before"]
        self.evidence["certificate"]["not_before"] = "2027-01-01T00:00:00Z"
        with self.assertRaisesRegex(ValueError, "certificate.not_before"):
            analyze(self.evidence)
        self.evidence["certificate"]["not_before"] = original_start
        self.evidence["kerberos"]["tolerance_seconds"] = True
        with self.assertRaisesRegex(ValueError, "positive integer"):
            analyze(self.evidence)


class CliTests(unittest.TestCase):
    def run_cli(self, path, *args):
        return subprocess.run(
            [sys.executable, "-B", str(ROOT / "clockskewproof.py"), str(path), *args],
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_report_formats(self):
        for form, expected in [
            ("text", "CLOCK_SKEW_MAY_EXPLAIN"),
            ("json", '"finding": "CLOCK_SKEW_MAY_EXPLAIN"'),
            ("html", "<!doctype html>"),
        ]:
            with self.subTest(form=form):
                result = self.run_cli(EXAMPLE, "--format", form)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)

    def test_duplicate_input_returns_an_error(self):
        with tempfile.TemporaryDirectory() as folder:
            sample = Path(folder) / "evidence.json"
            sample.write_text('{"client_time": "a", "client_time": "b"}', encoding="utf-8")
            result = self.run_cli(sample, "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertIn("duplicate JSON field", result.stderr)
        self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
