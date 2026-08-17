from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "dashboard"))
from catalog import RepositoryCatalog  # noqa: E402
from workspace import AnalystWorkspace  # noqa: E402


class AnalystWorkspaceInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.workspace = AnalystWorkspace(REPO_ROOT, RepositoryCatalog(REPO_ROOT), Path(self.temporary.name) / "state.json")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_graph_connects_procedures_rules_and_atomic_telemetry(self) -> None:
        graph = self.workspace.query("graph", {"tool": "rubeus"})
        types = {node["type"] for node in graph["nodes"]}
        self.assertTrue({"procedure", "rule", "telemetry"}.issubset(types))
        self.assertTrue(any(link["type"] == "supports" for link in graph["links"]))

    def test_simulator_exposes_disabled_rules_and_at_risk_procedures(self) -> None:
        simulation = self.workspace.query("simulate", {"events": "4768"})
        self.assertGreater(simulation["counts"].get("disabled", 0), 0)
        self.assertTrue(simulation["at_risk_procedures"])

    def test_simulator_progresses_from_no_collection_to_full_collection(self) -> None:
        empty = self.workspace.query("simulate", {"events": ""})
        self.assertEqual(empty["coverage_percent"], 0)
        self.assertEqual(empty["counts"].get("viable", 0), 0)
        self.assertGreater(empty["counts"].get("not_modelled", 0), 0)
        all_events = ",".join({item["event"] for item in self.workspace.query("telemetry")["events"]})
        full = self.workspace.query("simulate", {"events": all_events})
        self.assertEqual(full["coverage_percent"], 100)
        self.assertEqual(full["counts"].get("disabled", 0), 0)
        self.assertEqual(full["counts"].get("weakened", 0), 0)

    def test_simulator_ranks_next_collection_and_supports_tool_scope(self) -> None:
        simulation = self.workspace.query("simulate", {"events": "", "tool": "rubeus"})
        self.assertEqual({rule["tool"] for rule in simulation["rules"]}, {"rubeus"})
        self.assertEqual([item["tool"] for item in simulation["tool_coverage"]], ["rubeus"])
        self.assertTrue(simulation["recommendations"])
        recommendation = simulation["recommendations"][0]
        self.assertGreater(recommendation["rules_unlocked"], 0)
        improved = self.workspace.query("simulate", {"events": recommendation["event"], "tool": "rubeus"})
        self.assertGreater(improved["coverage_percent"], simulation["coverage_percent"])

    def test_telemetry_inventory_enriches_atomic_dependencies(self) -> None:
        inventory = self.workspace.query("telemetry")
        event_7045 = next(item for item in inventory["events"] if item["event"] == "7045")
        self.assertEqual(event_7045["provider"], "Service Control Manager")
        self.assertEqual(event_7045["channel"], "Windows System")
        self.assertTrue(event_7045["fields"])
        self.assertTrue(event_7045["configuration"])
        self.assertGreater(event_7045["rule_count"], 0)
        self.assertIn(event_7045["posture"], {"foundational", "fragile", "supported"})
        self.assertTrue(inventory["provider_summaries"])
        self.assertGreaterEqual(inventory["provider_summaries"][0]["rules"], inventory["provider_summaries"][-1]["rules"])
        self.assertTrue(inventory["collection_priorities"])
        self.assertTrue(all(item["posture"] == "fragile" for item in inventory["collection_priorities"]))
        _, _, telemetry_csv = self.workspace.export("telemetry", "csv")
        self.assertIn(b"provider", telemetry_csv)
        self.assertIn(b"7045", telemetry_csv)

    def test_telemetry_language_rewrites_do_not_rewrite_rule_labels_repeatedly(self) -> None:
        app_js = (REPO_ROOT / "dashboard" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertNotIn("['rules ·','detections ·']", app_js)

    def test_telemetry_page_exposes_priority_and_reverse_rule_views(self) -> None:
        app_js = (REPO_ROOT / "dashboard" / "static" / "app.js").read_text(encoding="utf-8")
        self.assertIn("Log data priorities", app_js)
        self.assertIn("Most dependent rules first", app_js)
        self.assertIn("Rule readiness", app_js)
        self.assertIn("Most missing event types first", app_js)

    def test_rule_workbench_reconciles_artifacts(self) -> None:
        detail = self.workspace.query("rule", {"tool": "rubeus", "rule": "rubeus_as_request_anomaly"})
        self.assertEqual(detail["rule"]["atomic_event_types"], ["4768"])
        self.assertTrue(detail["procedures"])
        self.assertIn("yaral", detail["rule"]["formats"])

    def test_local_state_is_separate_and_persistent(self) -> None:
        target = "rule:rubeus:rubeus_as_request_anomaly"
        self.workspace.change("annotate", {"target": target, "text": "Validate parser mapping"})
        self.workspace.change("bookmark", {"target": target})
        self.workspace.change("save-view", {"name": "Rubeus gaps", "route": "#/gaps?tool=rubeus"})
        self.workspace.change("validate", {"target": target, "checks": {"telemetry_available": True}, "evidence": "Lab collection confirmed"})
        state = self.workspace.query("state")
        self.assertEqual(state["annotations"][0]["target"], target)
        self.assertIn(target, state["bookmarks"])
        self.assertTrue(state["validation"][target]["checks"]["telemetry_available"])

    def test_exports_support_json_csv_and_markdown(self) -> None:
        for extension in ("json", "csv", "md"):
            filename, _, body = self.workspace.export("gaps", extension)
            self.assertTrue(filename.endswith(extension))
            self.assertTrue(body)

    def test_large_views_are_paginated_without_weakening_exports(self) -> None:
        first = self.workspace.query("gaps", {"page": "1", "limit": "5"})
        second = self.workspace.query("gaps", {"page": "2", "limit": "5"})
        self.assertEqual(len(first["items"]), 5)
        self.assertNotEqual(first["items"], second["items"])
        self.assertGreater(first["total"], len(first["items"]))
        _, _, exported = self.workspace.export("gaps", "json")
        self.assertIn(b'"total"', exported)

    def test_analyst_items_can_be_removed(self) -> None:
        state = self.workspace.change("annotate", {"target": "rule:test", "text": "temporary"})
        annotation_id = state["annotations"][0]["id"]
        self.workspace.change("save-view", {"name": "temporary", "route": "#/gaps"})
        self.workspace.change("remove-annotation", {"id": annotation_id})
        state = self.workspace.change("remove-view", {"name": "temporary"})
        self.assertFalse(state["annotations"])
        self.assertFalse(state["saved_views"])


if __name__ == "__main__":
    unittest.main()
