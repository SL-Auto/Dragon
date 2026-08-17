import tempfile
import unittest
from pathlib import Path

from tools.knowledge.store import _chunks, _front_matter, _normalise_query, index_knowledge, search_knowledge


class KnowledgeRetrievalTests(unittest.TestCase):
    def test_query_normalisation_groups_case_and_spacing(self):
        self.assertEqual(_normalise_query("  YARA-L   Review? "), "yara-l review")

    def test_front_matter_and_heading_chunks(self):
        metadata, body = _front_matter("---\ndomain: detection-engineering\nauthority: mandatory\n---\n# Rules\n\nIntro\n\n## Review\n\nTrace branches")
        self.assertEqual(metadata["authority"], "mandatory")
        chunks = _chunks(body, target_words=10, max_words=20)
        self.assertEqual([item[0] for item in chunks], ["Rules", "Rules > Review"])
        self.assertEqual(chunks[1][1], "Trace branches")

    def test_rebuild_creates_queryable_database(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "index.db"
            result = index_knowledge(rebuild=True, destination=destination)
            self.assertTrue(destination.exists())
            self.assertGreater(result["documents"], 0)
            self.assertGreater(result["chunks"], result["documents"])

    def test_search_returns_attributed_filtered_chunks(self):
        result = search_knowledge("adversarial review missing branches", domain="detection-engineering", top_k=3)
        self.assertGreater(result["receipt"]["query_id"], 0)
        self.assertEqual(result["receipt"]["result_count"], len(result["results"]))
        self.assertTrue(result["receipt"]["timestamp"])
        self.assertTrue(result["results"])
        self.assertLessEqual(len(result["results"]), 3)
        for item in result["results"]:
            self.assertEqual(item["domain"], "detection-engineering")
            self.assertTrue(item["source"])
            self.assertTrue(item["heading"])


if __name__ == "__main__":
    unittest.main()
