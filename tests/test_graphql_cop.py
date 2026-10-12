import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.base import ToolError  # noqa: E402
from modules.vuln.graphql_cop import GraphqlCopModule  # noqa: E402

SAMPLE_OUTPUT = json.dumps([
    {"test": "Introspection Query", "vulnerable": True, "severity": "medium", "detail": "introspection enabled"},
    {"test": "Batch Queries", "vulnerable": False},
])


class GraphqlCopParseTestCase(unittest.TestCase):
    def test_only_vulnerable_checks_become_findings(self):
        module = GraphqlCopModule()
        findings = module.parse(SAMPLE_OUTPUT, target_raw="https://example.com/graphql")
        self.assertEqual(len(findings), 1)
        self.assertIn("Introspection Query", findings[0].title)

    def test_empty_output_returns_no_findings(self):
        module = GraphqlCopModule()
        self.assertEqual(module.parse("", target_raw="https://example.com/graphql"), [])

    def test_run_refuses_a_non_graphql_looking_url(self):
        module = GraphqlCopModule()
        with self.assertRaises(ToolError):
            module.run("https://example.com/login", {})


if __name__ == "__main__":
    unittest.main()
