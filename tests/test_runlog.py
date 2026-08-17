import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.runlog.cli import append


class RunLogTests(unittest.TestCase):
    def test_append_writes_ordered_timestamped_jsonl(self):
        with tempfile.TemporaryDirectory() as directory, patch("tools.runlog.cli.LOG_ROOT", Path(directory)):
            first = append("test-run", "retrieval", "search", ".knowledge/index.db", "succeeded", "receipt=1")
            second = append("test-run", "validation", "validate", "repository", "succeeded", "passed")
            self.assertEqual((first["sequence"], second["sequence"]), (1, 2))
            self.assertTrue(first["timestamp"].endswith("+00:00"))
            records = [json.loads(line) for line in (Path(directory) / "test-run.jsonl").read_text().splitlines()]
            self.assertEqual([record["action"] for record in records], ["search", "validate"])


if __name__ == "__main__":
    unittest.main()
