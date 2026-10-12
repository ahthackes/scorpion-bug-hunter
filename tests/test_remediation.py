"""Tests for reports.remediation.suggest() -- a small, pure keyword
lookup, so this just checks the matching logic and the always-returns-
something fallback, not every entry's wording.
"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from reports.remediation import suggest  # noqa: E402


class RemediationTestCase(unittest.TestCase):
    def test_xss_title_matches(self):
        self.assertIn("output-encode", suggest("Possible XSS via parameter 'id'"))

    def test_cors_title_matches(self):
        self.assertIn("Access-Control-Allow-Origin", suggest("CORS misconfiguration: reflects Origin"))

    def test_subdomain_takeover_matches(self):
        self.assertIn("DNS record", suggest("Subdomain takeover: old.example.com"))

    def test_is_case_insensitive(self):
        self.assertEqual(suggest("POSSIBLE XSS"), suggest("possible xss"))

    def test_unmatched_title_falls_back_to_default(self):
        guidance = suggest("Something nobody wrote a rule for")
        self.assertIn("Review this finding manually", guidance)


if __name__ == "__main__":
    unittest.main()
