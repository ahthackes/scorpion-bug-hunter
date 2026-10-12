import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.vuln.git_exposure import GitExposureModule  # noqa: E402

REAL_HEAD = "ref: refs/heads/main\n\nHTTP_STATUS:200"
SOFT_404 = "<html>not found</html>\nHTTP_STATUS:200"
REAL_404 = "nope\nHTTP_STATUS:404"


class GitExposureParseTestCase(unittest.TestCase):
    def test_real_git_head_is_confirmed(self):
        module = GitExposureModule()
        findings = module.parse(REAL_HEAD, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertTrue(findings[0].confirmed)

    def test_soft_404_is_flagged_but_unconfirmed(self):
        module = GitExposureModule()
        findings = module.parse(SOFT_404, target_raw="https://example.com")
        self.assertEqual(len(findings), 1)
        self.assertFalse(findings[0].confirmed)

    def test_real_404_produces_no_finding(self):
        module = GitExposureModule()
        self.assertEqual(module.parse(REAL_404, target_raw="https://example.com"), [])

    def test_missing_status_marker_produces_no_finding(self):
        module = GitExposureModule()
        self.assertEqual(module.parse("garbage output", target_raw="https://example.com"), [])


if __name__ == "__main__":
    unittest.main()
