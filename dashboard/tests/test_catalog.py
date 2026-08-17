from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
from catalog import RepositoryCatalog  # noqa: E402


class RepositoryCatalogIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = RepositoryCatalog(REPO_ROOT)

    def test_overview_reconciles_repository(self) -> None:
        overview = self.catalog.overview()
        self.assertGreaterEqual(overview["metrics"]["tools"], 1)
        self.assertEqual(overview["metrics"]["tools"], len(overview["tools"]))
        self.assertGreater(overview["metrics"]["canonical_rules"], 0)

    def test_analyzed_tool_links_rules_and_artifacts(self) -> None:
        tool = self.catalog.tool("rubeus")
        self.assertEqual(tool["status"], "analyzed")
        self.assertEqual(len(tool["rules"]), tool["counts"]["canonical_rules"])
        self.assertIn("yaral", tool["rules"][0]["formats"])
        self.assertTrue(any(item["kind"] == "telemetry" for item in tool["artifacts"]))

    def test_run_journals_are_ordered(self) -> None:
        runs = self.catalog.runs()
        journal_run = next(item for item in runs if item["journal"])
        detail = self.catalog.run(journal_run["id"])
        sequences = [action["sequence"] for action in detail["actions"]]
        self.assertEqual(sequences, sorted(sequences))

    def test_source_browser_is_contained(self) -> None:
        tree = self.catalog.source_tree(depth=3)
        self.assertEqual(tree["path"], "sources")
        with self.assertRaises(ValueError):
            self.catalog.source_tree("../")

    def test_artifact_library_exposes_outputs_but_not_arbitrary_paths(self) -> None:
        tree = self.catalog.library_tree(depth=1)
        names = {item["name"] for item in tree["children"]}
        self.assertIn("dependencies", names)
        self.assertIn("public-rules", names)
        with self.assertRaises(ValueError):
            self.catalog.library_tree(".git")

    def test_artifact_rejects_escape_and_binary(self) -> None:
        with self.assertRaises(ValueError):
            self.catalog.artifact("../outside.md")
        with tempfile.NamedTemporaryFile(dir=REPO_ROOT, suffix=".exe") as binary:
            relative = Path(binary.name).relative_to(REPO_ROOT).as_posix()
            with self.assertRaises(FileNotFoundError):
                self.catalog.artifact(relative)

    def test_search_finds_canonical_detection(self) -> None:
        results = self.catalog.search("rubeus kerberoast", limit=10)
        self.assertTrue(results)
        self.assertTrue(any("rubeus" in item["path"] for item in results))

    def test_markdown_classes_have_structured_presentations(self) -> None:
        examples = {
            "reports/mimikatz/source-analysis.md": "report",
            "reviews/mimikatz/detection-review.md": "review",
            "telemetry/mimikatz.md": "telemetry",
            "public-rules/comparisons/mimikatz/mimikatz_event_log_impairment.md": "comparison",
            "summaries/mimikatz.md": "summary",
            "runs/2026-08-15.md": "run",
            "research/public-detection-rule-sources.md": "research",
            "CHANGELOG.md": "changelog",
        }
        for path, expected in examples.items():
            with self.subTest(path=path):
                presentation = self.catalog.artifact(path)["presentation"]
                self.assertEqual(presentation["class"], expected)
                self.assertTrue(presentation["title"])
                self.assertTrue(presentation["blocks"])

    def test_comparison_presentation_preserves_matrix_and_code(self) -> None:
        presentation = self.catalog.artifact("public-rules/comparisons/mimikatz/mimikatz_event_log_impairment.md")["presentation"]
        self.assertTrue(any(block["type"] == "table" for block in presentation["blocks"]))
        self.assertTrue(any(block["type"] == "code" for block in presentation["blocks"]))
        self.assertGreaterEqual(len(presentation["navigation"]), 5)


if __name__ == "__main__":
    unittest.main()
