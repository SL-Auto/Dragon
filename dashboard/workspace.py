from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


class AnalystWorkspace:
    """Deep analyst-workspace module over repository facts and local analyst state."""

    CHECKS = ("telemetry_available", "fields_confirmed", "positive_test", "negative_test", "false_positives_sampled", "window_verified", "translations_reviewed")

    def __init__(self, root: Path, catalog: Any, state_path: Path | None = None):
        self.root = root.resolve()
        self.catalog = catalog
        self.state_path = state_path or self.root / "dashboard" / "state" / "analyst-workspace.json"
        self._rules_cache: list[dict[str, Any]] | None = None
        self._procedures_cache: list[dict[str, Any]] | None = None
        self._repository_stamp: int | None = None

    def query(self, view: str, params: dict[str, str] | None = None) -> Any:
        params = params or {}
        self._refresh_if_changed()
        handlers = {
            "graph": self._graph, "gaps": self._gaps, "telemetry": self._telemetry,
            "simulate": self._simulate, "comparisons": self._comparisons,
            "attack": self._attack, "run-diff": self._run_diff,
            "rule": self._rule, "state": lambda _: self._state(),
            "commands": self._commands, "evidence": self._evidence,
        }
        if view not in handlers:
            raise KeyError(view)
        return handlers[view](params)

    def change(self, action: str, payload: dict[str, Any]) -> dict[str, Any]:
        state = self._state()
        target = str(payload.get("target", "")).strip()
        if action == "annotate":
            if not target or not str(payload.get("text", "")).strip():
                raise ValueError("Annotation target and text are required")
            state["annotations"].append({"id": self._id(), "target": target, "text": str(payload["text"]).strip(), "status": payload.get("status", "note"), "timestamp": self._now()})
        elif action == "bookmark":
            if not target:
                raise ValueError("Bookmark target is required")
            bookmarks = state["bookmarks"]
            state["bookmarks"] = [item for item in bookmarks if item != target] if target in bookmarks else bookmarks + [target]
        elif action == "save-view":
            name = str(payload.get("name", "")).strip()
            if not name:
                raise ValueError("Saved view name is required")
            state["saved_views"] = [item for item in state["saved_views"] if item["name"] != name]
            state["saved_views"].append({"name": name, "route": str(payload.get("route", "#/overview")), "timestamp": self._now()})
        elif action == "validate":
            if not target:
                raise ValueError("Validation target is required")
            checks = {key: bool(payload.get("checks", {}).get(key)) for key in self.CHECKS}
            state["validation"][target] = {"checks": checks, "evidence": str(payload.get("evidence", "")).strip(), "updated": self._now()}
        elif action == "remove-annotation":
            annotation_id = str(payload.get("id", ""))
            state["annotations"] = [item for item in state["annotations"] if item.get("id") != annotation_id]
        elif action == "remove-view":
            name = str(payload.get("name", ""))
            state["saved_views"] = [item for item in state["saved_views"] if item.get("name") != name]
        else:
            raise KeyError(action)
        self._write_state(state)
        return state

    def export(self, view: str, fmt: str, params: dict[str, str] | None = None) -> tuple[str, str, bytes]:
        params = {**(params or {}), "limit": "100000", "page": "1"}
        data = self.query(view, params)
        fmt = fmt.lower()
        if fmt == "json":
            return f"{view}.json", "application/json", json.dumps(data, indent=2, ensure_ascii=False).encode()
        rows = data if isinstance(data, list) else data.get("items", data.get("events", data.get("rules", data.get("techniques", [])))) if isinstance(data, dict) else []
        if fmt == "csv":
            flattened = [self._flatten(row) for row in rows if isinstance(row, dict)]
            output = io.StringIO()
            fields = sorted({key for row in flattened for key in row})
            writer = csv.DictWriter(output, fieldnames=fields); writer.writeheader(); writer.writerows(flattened)
            return f"{view}.csv", "text/csv", output.getvalue().encode("utf-8")
        lines = [f"# Export: {view}", "", f"Generated: {self._now()}", ""]
        for row in rows:
            if isinstance(row, dict):
                lines.append(f"## {row.get('name') or row.get('rule') or row.get('id') or 'Item'}")
                lines.extend(f"- **{key}:** {value}" for key, value in row.items()); lines.append("")
        return f"{view}.md", "text/markdown", "\n".join(lines).encode("utf-8")

    def _rules(self) -> list[dict[str, Any]]:
        if self._rules_cache is not None:
            return self._rules_cache
        result = []
        for manifest_path in sorted((self.root / "manifests").glob("*.yml")):
            manifest = self._yaml(manifest_path); tool = manifest.get("tool_id", manifest_path.stem)
            for rule in manifest.get("rules", []):
                dependency_path = self.root / str(rule.get("dependency", "")); dependency = self._yaml(dependency_path)
                formats = {fmt: str(data.get("path")) for fmt, data in dependency.get("translations", {}).items() if isinstance(data, dict)}
                formats["yaral"] = dependency.get("canonical_path", f"detections/{tool}/yaral/{rule['name']}.yaral")
                result.append({**rule, **dependency, "tool": tool, "formats": formats})
        self._rules_cache = result
        return result

    def _procedures(self) -> list[dict[str, Any]]:
        if self._procedures_cache is not None:
            return self._procedures_cache
        result = []
        for path in sorted((self.root / "coverage").glob("*.yml")):
            coverage = self._yaml(path); tool = coverage.get("tool_id", path.stem)
            for item in coverage.get("procedures", []):
                result.append({**item, "tool": tool, "key": f"{tool}:{item.get('id')}"})
        self._procedures_cache = result
        return result

    def _graph(self, params: dict[str, str]) -> dict[str, Any]:
        tool = params.get("tool", "")
        procedures = [p for p in self._procedures() if not tool or p["tool"] == tool]
        rules = [r for r in self._rules() if not tool or r["tool"] == tool]
        nodes, links = {}, []
        for procedure in procedures:
            nodes[procedure["key"]] = {"id": procedure["key"], "type": "procedure", "label": procedure.get("name"), "status": procedure.get("detection_status")}
        for rule in rules:
            rid = f"rule:{rule['tool']}:{rule['name']}"; nodes[rid] = {"id": rid, "type": "rule", "label": rule["name"], "severity": rule.get("severity")}
            for proc in self._ids(rule.get("procedure_ids") or rule.get("procedures")):
                pid = f"{rule['tool']}:{proc}"
                if pid in nodes: links.append({"source": pid, "target": rid, "type": "detected_by"})
            for event in rule.get("atomic_event_types", []):
                eid = f"telemetry:{event}"; nodes[eid] = {"id": eid, "type": "telemetry", "label": str(event)}
                links.append({"source": eid, "target": rid, "type": "supports"})
        return {"nodes": list(nodes.values()), "links": links}

    def _gaps(self, params: dict[str, str]) -> dict[str, Any]:
        items = []
        for procedure in self._procedures():
            if procedure.get("detection_status") != "detected":
                items.append({"type": "procedure", "tool": procedure["tool"], "id": procedure.get("id"), "name": procedure.get("name"), "severity": "high" if procedure.get("detection_status") == "blocked_source" else "medium", "gap": procedure.get("detection_status"), "detail": procedure.get("notes", "No canonical detection")})
        for rule in self._rules():
            if rule.get("validation_status") != "validated":
                items.append({"type": "rule", "tool": rule["tool"], "id": rule["name"], "name": rule["name"], "severity": rule.get("severity", "medium"), "gap": "needs_validation", "detail": rule.get("telemetry_prerequisites", "")})
            for fmt, trans in rule.get("translations", {}).items():
                if isinstance(trans, dict) and trans.get("fidelity") not in {"full", "equivalent"}:
                    items.append({"type": "translation", "tool": rule["tool"], "id": f"{rule['name']}:{fmt}", "name": rule["name"], "severity": "low", "gap": f"{fmt}_fidelity_{trans.get('fidelity', 'unknown')}", "detail": trans.get("status", "")})
        filters = {key: value for key, value in params.items() if value}
        for key in ("tool", "type", "severity", "gap"):
            if key in filters: items = [item for item in items if str(item.get(key)) == filters[key]]
        counts = self._freq(item["gap"] for item in items); total = len(items); page, limit = self._page(params)
        start = (page - 1) * limit
        return {"items": items[start:start + limit], "counts": counts, "total": total, "page": page, "limit": limit, "pages": max(1, (total + limit - 1) // limit)}

    def _telemetry(self, _: dict[str, str]) -> dict[str, Any]:
        dependencies: dict[str, dict[str, Any]] = {}
        for rule in self._rules():
            for event in rule.get("atomic_event_types", []):
                row = dependencies.setdefault(str(event), {"rules": [], "tools": set(), "severities": {}})
                row["rules"].append({"tool": rule["tool"], "rule": rule["name"], "severity": rule.get("severity")})
                row["tools"].add(rule["tool"]); severity = rule.get("severity", "unknown")
                row["severities"][severity] = row["severities"].get(severity, 0) + 1
        events = []
        represented = set()
        for master in self._master_telemetry_rows():
            event = master["event"]; represented.add(event); dependency = dependencies.get(event, {"rules": [], "tools": set(), "severities": {}})
            count = len(dependency["rules"])
            posture = "unmapped" if count == 0 else "foundational" if count >= 5 else "fragile" if master.get("gaps") else "supported"
            events.append({**master, **dependency, "tools": sorted(dependency["tools"]), "rule_count": count, "posture": posture})
        for event, dependency in dependencies.items():
            if event not in represented:
                events.append({"provider": "Normalized / provider mapping required", "channel": "Unspecified", "event": event, "meaning": "Dependency metadata event type", "fields": "See rule dependency record", "configuration": "Confirm backend collection and parser mapping", "gaps": "No atomic master row", **dependency, "tools": sorted(dependency["tools"]), "rule_count": len(dependency["rules"]), "posture": "fragile"})
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 1}
        for row in events:
            row["impact_score"] = sum(weights.get(severity, 1) * count for severity, count in row["severities"].items())
        events.sort(key=lambda row: (-row["rule_count"], row["provider"], row["event"]))
        providers: dict[str, dict[str, Any]] = {}
        for row in events:
            provider = providers.setdefault(row["provider"], {"provider": row["provider"], "rows": 0, "events": set(), "rules": set(), "tools": set(), "fragile_rows": 0, "unmapped_rows": 0, "impact_score": 0})
            provider["rows"] += 1; provider["events"].add(row["event"]); provider["rules"].update(rule["rule"] for rule in row["rules"]); provider["tools"].update(row["tools"]); provider["impact_score"] += row["impact_score"]
            provider["fragile_rows"] += row["posture"] == "fragile"; provider["unmapped_rows"] += row["posture"] == "unmapped"
        provider_summaries = [{**row, "events": len(row["events"]), "rules": len(row["rules"]), "tools": len(row["tools"])} for row in providers.values()]
        provider_summaries.sort(key=lambda row: (-row["rules"], -row["events"], row["provider"]))
        priorities = [row for row in events if row["posture"] == "fragile" and row["rule_count"]]
        priorities.sort(key=lambda row: (-row["severities"].get("critical", 0), -row["severities"].get("high", 0), -row["rule_count"], row["event"]))
        return {"events": events, "providers": self._freq(row["provider"] for row in events), "provider_summaries": provider_summaries, "collection_priorities": priorities[:12], "postures": self._freq(row["posture"] for row in events), "total_rules": len(self._rules()), "mapped_rules": len({rule["rule"] for row in events for rule in row["rules"]})}

    def _master_telemetry_rows(self) -> list[dict[str, str]]:
        path = self.root / "telemetry" / "MASTER.md"
        if not path.exists(): return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = next((index for index, line in enumerate(lines) if line.strip().startswith("| Provider / product")), -1)
        if start < 0: return []
        rows = []
        for line in lines[start + 2:]:
            if not line.strip().startswith("|"): break
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 9: continue
            rows.append({"provider": self._plain_markdown(cells[0]), "channel": self._plain_markdown(cells[1]), "event": self._plain_markdown(cells[2]), "meaning": self._plain_markdown(cells[3]), "fields": self._plain_markdown(cells[4]), "configuration": self._plain_markdown(cells[5]), "gaps": self._plain_markdown(cells[6]), "supported_tools_text": self._plain_markdown(cells[7])})
        return rows

    def _simulate(self, params: dict[str, str]) -> dict[str, Any]:
        enabled = {item for item in params.get("events", "").split(",") if item}
        tool_filter = params.get("tool", "")
        rules = []
        source_rules = [rule for rule in self._rules() if not tool_filter or rule["tool"] == tool_filter]
        for rule in source_rules:
            required = {str(item) for item in rule.get("atomic_event_types", [])}
            missing = sorted(required - enabled)
            status = "not_modelled" if not required else "viable" if not missing else "disabled" if required == set(missing) else "weakened"
            rules.append({"tool": rule["tool"], "rule": rule["name"], "severity": rule.get("severity"), "procedures": self._ids(rule.get("procedure_ids") or rule.get("procedures")), "required": sorted(required), "missing": missing, "status": status})
        blind = sorted({f"{r['tool']}:{proc}" for r in rules if r["status"] in {"disabled", "weakened"} for proc in r["procedures"]})
        counts = self._freq(r["status"] for r in rules); modeled = len(rules) - counts.get("not_modelled", 0)
        coverage = round(counts.get("viable", 0) / modeled * 100, 1) if modeled else 0
        weights = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        recommendations = []
        for event in sorted({event for rule in rules for event in rule["missing"]}):
            affected = [rule for rule in rules if event in rule["missing"]]
            unlocked = [rule for rule in affected if len(rule["missing"]) == 1]
            recommendations.append({"event": event, "rules_improved": len(affected), "rules_unlocked": len(unlocked), "weighted_gain": sum(weights.get(rule.get("severity", ""), 1) for rule in unlocked), "tools": sorted({rule["tool"] for rule in affected})})
        recommendations.sort(key=lambda item: (-item["rules_unlocked"], -item["rules_improved"], item["event"]))
        tool_coverage = []
        for tool in sorted({rule["tool"] for rule in rules}):
            tool_rules = [rule for rule in rules if rule["tool"] == tool]; tool_modeled = [rule for rule in tool_rules if rule["status"] != "not_modelled"]
            viable = sum(rule["status"] == "viable" for rule in tool_modeled)
            tool_coverage.append({"tool": tool, "coverage_percent": round(viable / len(tool_modeled) * 100, 1) if tool_modeled else 0, "viable": viable, "modeled": len(tool_modeled), "not_modelled": len(tool_rules) - len(tool_modeled)})
        return {"enabled": sorted(enabled), "tool_filter": tool_filter, "available_tools": sorted({rule["tool"] for rule in self._rules()}), "rules": rules, "counts": counts, "modeled_rules": modeled, "coverage_percent": coverage, "at_risk_procedures": blind, "recommendations": recommendations[:12], "tool_coverage": tool_coverage}

    def _comparisons(self, params: dict[str, str]) -> dict[str, Any]:
        items = []
        for rule in self._rules():
            if params.get("tool") and params["tool"] != rule["tool"]: continue
            path = self.root / "public-rules" / "comparisons" / rule["tool"] / f"{rule['name']}.md"
            if not path.exists(): continue
            text = path.read_text(encoding="utf-8", errors="replace"); lower = text.lower()
            verdicts = [v for v in ("ours_stronger", "public_stronger", "complementary", "equivalent", "different_scope", "insufficient_evidence") if v in lower]
            items.append({"tool": rule["tool"], "rule": rule["name"], "severity": rule.get("severity"), "verdicts": verdicts, "path": path.relative_to(self.root).as_posix(), "proposal": self._proposal(text), "summary": self._section(text, "conclusion") or self._section(text, "decision")})
        verdict = params.get("verdict")
        if verdict: items = [item for item in items if verdict in item["verdicts"]]
        counts = self._freq(v for item in items for v in item["verdicts"]); total = len(items); page, limit = self._page(params)
        start = (page - 1) * limit
        return {"items": items[start:start + limit], "counts": counts, "total": total, "page": page, "limit": limit, "pages": max(1, (total + limit - 1) // limit)}

    def _attack(self, _: dict[str, str]) -> dict[str, Any]:
        techniques: dict[str, dict[str, Any]] = {}
        for report in (self.root / "reports").rglob("*.md"):
            text = report.read_text(encoding="utf-8", errors="replace")
            for technique in sorted(set(re.findall(r"\bT\d{4}(?:\.\d{3})?\b", text))):
                row = techniques.setdefault(technique, {"id": technique, "tools": set(), "reports": [], "rules": 0})
                tool = report.parent.name; row["tools"].add(tool); row["reports"].append(report.relative_to(self.root).as_posix())
        for row in techniques.values():
            row["rules"] = sum(1 for rule in self._rules() if rule["tool"] in row["tools"])
            row["tools"] = sorted(row["tools"])
        return {"techniques": sorted(techniques.values(), key=lambda item: item["id"])}

    def _run_diff(self, params: dict[str, str]) -> dict[str, Any]:
        left, right = params.get("left", ""), params.get("right", "")
        runs = {item["id"]: self.catalog.run(item["id"]) for item in self.catalog.runs()}
        if not left or not right: return {"runs": list(runs), "left": left, "right": right, "changes": []}
        def facts(run: dict[str, Any]) -> set[str]:
            return {f"{a.get('phase')}|{a.get('action')}|{a.get('target')}|{a.get('outcome')}" for a in run.get("actions", [])}
        a, b = facts(runs.get(left, {})), facts(runs.get(right, {}))
        return {"runs": list(runs), "left": left, "right": right, "changes": [{"change": "added", "fact": item} for item in sorted(b-a)] + [{"change": "removed", "fact": item} for item in sorted(a-b)]}

    def _rule(self, params: dict[str, str]) -> dict[str, Any]:
        tool, name = params.get("tool", ""), params.get("rule", "")
        rule = next((r for r in self._rules() if r["tool"] == tool and r["name"] == name), None)
        if not rule: raise KeyError(name)
        procedures = [p for p in self._procedures() if p["tool"] == tool and p.get("id") in self._ids(rule.get("procedure_ids") or rule.get("procedures"))]
        comparison = self._comparisons({"tool": tool})
        comparison = next((c for c in comparison["items"] if c["rule"] == name), None)
        state = self._state(); target = f"rule:{tool}:{name}"
        return {"rule": rule, "procedures": procedures, "comparison": comparison, "validation": state["validation"].get(target, {}), "annotations": [a for a in state["annotations"] if a["target"] == target], "bookmarked": target in state["bookmarks"]}

    def _commands(self, _: dict[str, str]) -> list[dict[str, str]]:
        commands = [{"label": f"Open {r['tool']} / {r['name']}", "route": f"#/workbench?tool={r['tool']}&rule={r['name']}", "type": "rule"} for r in self._rules()]
        commands += [{"label": f"Explore {t['name']}", "route": f"#/explorer?tool={t['id']}", "type": "tool"} for t in self.catalog.overview()["tools"]]
        commands += [{"label": f"Browse {t['name']} source evidence", "route": f"#/evidence?tool={t['id']}", "type": "evidence"} for t in self.catalog.overview()["tools"]]
        return commands

    def _evidence(self, params: dict[str, str]) -> dict[str, Any]:
        tool = params.get("tool", ""); paths = []
        for report in (self.root / "reports" / tool).glob("*.md") if (self.root / "reports" / tool).exists() else []:
            text = report.read_text(encoding="utf-8", errors="replace")
            refs = re.findall(r"(?:https://github\.com/[^\s)]+|`?([A-Za-z0-9_./-]+\.(?:go|cs|py|c|h|java))(?::L?(\d+))?`?)", text)
            paths.append({"report": report.relative_to(self.root).as_posix(), "references": len(refs), "source_locations": sorted({ref[0] for ref in refs if isinstance(ref, tuple) and ref[0]})[:100]})
        return {"tool": tool, "items": paths}

    def _state(self) -> dict[str, Any]:
        default = {"annotations": [], "bookmarks": [], "saved_views": [], "validation": {}}
        if not self.state_path.exists(): return default
        try: loaded = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError): return default
        return {key: loaded.get(key, value) for key, value in default.items()}

    def _refresh_if_changed(self) -> None:
        paths = []
        for relative in ("manifests", "coverage", "dependencies"):
            paths.extend((self.root / relative).rglob("*.yml"))
        stamp = max((path.stat().st_mtime_ns for path in paths), default=0)
        if self._repository_stamp is not None and stamp != self._repository_stamp:
            self._rules_cache = None
            self._procedures_cache = None
        self._repository_stamp = stamp

    def _write_state(self, state: dict[str, Any]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.state_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(state, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        temporary.replace(self.state_path)

    @staticmethod
    def _yaml(path: Path) -> dict[str, Any]:
        if not path.exists(): return {}
        data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")); return data if isinstance(data, dict) else {}

    @staticmethod
    def _ids(value: Any) -> list[str]:
        if isinstance(value, list): return [str(item) for item in value]
        return [item.strip() for item in str(value or "").split(",") if item.strip()]

    @staticmethod
    def _freq(values: Any) -> dict[str, int]:
        result: dict[str, int] = {}
        for value in values: result[str(value)] = result.get(str(value), 0) + 1
        return result

    @staticmethod
    def _proposal(text: str) -> str:
        matches = re.findall(r"```(?:yaral|yara-l)?\s*\n(.*?)```", text, re.I | re.S)
        return matches[-1].strip() if matches else ""

    @staticmethod
    def _section(text: str, name: str) -> str:
        match = re.search(rf"^##+\s+[^\n]*{re.escape(name)}[^\n]*\n(.*?)(?=^##+\s|\Z)", text, re.I | re.M | re.S)
        return re.sub(r"\s+", " ", match.group(1)).strip()[:700] if match else ""

    @staticmethod
    def _plain_markdown(text: str) -> str:
        return re.sub(r"\[([^]]+)\]\([^)]+\)", r"\1", text).replace("`", "").strip()

    @staticmethod
    def _flatten(row: dict[str, Any]) -> dict[str, str]:
        return {key: json.dumps(value, ensure_ascii=False) if isinstance(value, (dict, list)) else str(value) for key, value in row.items()}

    @staticmethod
    def _now() -> str: return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _id() -> str: return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")

    @staticmethod
    def _page(params: dict[str, str]) -> tuple[int, int]:
        try: page = max(1, int(params.get("page", "1"))); limit = max(1, min(100000, int(params.get("limit", "48"))))
        except ValueError: page, limit = 1, 48
        return page, limit
