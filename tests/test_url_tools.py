"""Tests for core.url_tools -- the anew/gf/qsreplace/unfurl/uro glue
utilities Tier 2 uses between scanners. None of the real binaries are
installed in this sandbox, so these exercise each function's pure-Python
fallback path, which is also exactly what runs for anyone who hasn't
installed that particular small utility yet.
"""

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.url_tools import anew, gf_filter, kxss_filter, qsreplace, unfurl_keys, uro_filter  # noqa: E402


class UroFilterTestCase(unittest.TestCase):
    def test_dedupes_exact_duplicates(self):
        urls = ["https://example.com/a", "https://example.com/b", "https://example.com/a"]
        self.assertEqual(uro_filter(urls), ["https://example.com/a", "https://example.com/b"])

    def test_preserves_order(self):
        urls = ["https://example.com/z", "https://example.com/a"]
        self.assertEqual(uro_filter(urls), urls)

    def test_empty_list_returns_empty_list(self):
        self.assertEqual(uro_filter([]), [])


class GfFilterTestCase(unittest.TestCase):
    def test_returns_empty_list_when_gf_not_installed(self):
        # gf isn't installed in this sandbox -- an empty result (not the
        # unfiltered input) is the correct "nothing flagged" behavior.
        result = gf_filter(["https://example.com/?redirect=https://evil.com"], "redirect")
        self.assertEqual(result, [])


class KxssFilterTestCase(unittest.TestCase):
    def test_returns_empty_list_when_kxss_not_installed(self):
        # kxss isn't installed in this sandbox -- an empty result (not the
        # unfiltered input) is the correct "nothing confirmed" behavior,
        # same contract as gf_filter.
        result = kxss_filter(["https://example.com/?q=test"])
        self.assertEqual(result, [])

    def test_empty_input_returns_empty_list(self):
        self.assertEqual(kxss_filter([]), [])


class QsreplaceTestCase(unittest.TestCase):
    def test_replaces_query_values_with_payload(self):
        urls = ["https://example.com/page?id=1&ref=2"]
        result = qsreplace(urls, "FUZZ")
        self.assertEqual(len(result), 1)
        self.assertIn("id=FUZZ", result[0])
        self.assertIn("ref=FUZZ", result[0])

    def test_urls_without_query_string_are_dropped(self):
        urls = ["https://example.com/page", "https://example.com/other?x=1"]
        result = qsreplace(urls, "FUZZ")
        self.assertEqual(len(result), 1)
        self.assertIn("other", result[0])

    def test_empty_list_returns_empty_list(self):
        self.assertEqual(qsreplace([], "FUZZ"), [])


class UnfurlKeysTestCase(unittest.TestCase):
    def test_extracts_unique_sorted_param_names(self):
        urls = [
            "https://example.com/a?id=1&ref=2",
            "https://example.com/b?id=3",
            "https://example.com/c?sort=asc",
        ]
        self.assertEqual(unfurl_keys(urls), ["id", "ref", "sort"])

    def test_urls_without_query_contribute_nothing(self):
        self.assertEqual(unfurl_keys(["https://example.com/plain"]), [])

    def test_empty_list_returns_empty_list(self):
        self.assertEqual(unfurl_keys([]), [])


class AnewTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.state_file = str(Path(self._tmp.name) / "seen.txt")

    def tearDown(self):
        self._tmp.cleanup()

    def test_first_call_returns_everything_as_new(self):
        new = anew(self.state_file, ["a", "b"])
        self.assertEqual(new, ["a", "b"])

    def test_second_call_with_same_items_returns_nothing_new(self):
        anew(self.state_file, ["a", "b"])
        new = anew(self.state_file, ["a", "b"])
        self.assertEqual(new, [])

    def test_second_call_returns_only_the_genuinely_new_items(self):
        anew(self.state_file, ["a", "b"])
        new = anew(self.state_file, ["b", "c"])
        self.assertEqual(new, ["c"])

    def test_state_file_accumulates_across_calls(self):
        anew(self.state_file, ["a"])
        anew(self.state_file, ["b"])
        content = Path(self.state_file).read_text().splitlines()
        self.assertEqual(sorted(content), ["a", "b"])

    def test_empty_candidates_returns_empty_list(self):
        self.assertEqual(anew(self.state_file, []), [])


if __name__ == "__main__":
    unittest.main()
