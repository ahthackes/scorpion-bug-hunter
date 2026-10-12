import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.recon.gitdorker import GitDorkerModule  # noqa: E402

SAMPLE_OUTPUT = (
    '[+] Searching in example.com for: "example.com" extension:env\n'
    "https://github.com/someuser/somerepo/blob/main/.env\n"
    "https://github.com/someuser/somerepo/blob/main/.env\n"
    "some other noise line\n"
)


class GitDorkerParseTestCase(unittest.TestCase):
    def test_parses_and_dedupes_blob_urls(self):
        module = GitDorkerModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertEqual(len(findings), 1)
        self.assertIn("github.com/someuser/somerepo/blob/main/.env", findings[0].description)

    def test_findings_are_unconfirmed(self):
        module = GitDorkerModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="example.com")
        self.assertFalse(findings[0].confirmed)

    def test_non_github_lines_are_ignored(self):
        module = GitDorkerModule()
        self.assertEqual(module.parse("just some text\nno urls here\n", target_raw="example.com"), [])

    def test_empty_output_returns_no_findings(self):
        module = GitDorkerModule()
        self.assertEqual(module.parse("", target_raw="example.com"), [])


if __name__ == "__main__":
    unittest.main()
