from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml

from presenters import MarkdownPresenter


TEXT_EXTENSIONS = {
    ".md", ".yml", ".yaml", ".yaral", ".spl", ".kql", ".sql", ".eql",
    ".json", ".toml", ".txt", ".py", ".ps1", ".go", ".cs", ".c", ".h",
    ".java", ".js", ".ts", ".tsx", ".jsx", ".rs", ".sh",
}
FORMAT_EXTENSIONS = {
    "yaral": ".yaral", "spl": ".spl", "kql": ".kql", "sql": ".sql",
    "eql": ".eql", "sigma": ".yml",
}
LIBRARY_ROOTS = {
    "registry", "reports", "summaries", "coverage", "detections", "dependencies",
    "reviews", "telemetry", "manifests", "schemas", "context", "knowledge",
    "research", "public-rules", "runs", "state", "templates",
}


@dataclass(frozen=True)
class Artifact:
    path: str
    kind: str
    name: str
    bytes: int


class RepositoryCatalog:
    """Read-only catalog over the detection repository.

    The public interface deliberately stays small: callers ask for an overview,
    a tool, runs, a tree, an artifact, or search results. Repository layout and
    cross-artifact reconciliation remain inside this module.
    """

    def __init__(self, root: Path):
        self.root = root.resolve()
        self._registry = self._load_yaml("registry/tools.yml").get("tools", [])
        self._tools = {item["id"]: item for item in self._registry}
        self._markdown = MarkdownPresenter()

    def overview(self) -> dict[str, Any]:
        tools = [self._tool_card(tool_id) for tool_id in self._tools]
        rules = sum(item["rules"] for item in tools)
        procedures = sum(item["procedures"] for item in tools)
        analyzed = sum(item["status"] == "analyzed" for item in tools)
        return {
            "metrics": {
                "tools": len(tools), "analyzed": analyzed, "procedures": procedures,
                "canonical_rules": rules, "comparisons": self._count("public-rules/comparisons", ".md", exclude={"INDEX.md"}),
                "runs": len(self.runs()), "source_codebases": len(self.source_tree(depth=1)["children"]),
            },
            "statuses": self._frequencies(item["status"] for item in tools),
            "tools": tools,
            "recent_runs": self.runs()[:5],
        }

    def tool(self, tool_id: str) -> dict[str, Any]:
        if tool_id not in self._tools:
            raise KeyError(tool_id)
        registry = self._tools[tool_id]
        manifest = self._load_yaml(f"manifests/{tool_id}.yml")
        coverage = self._load_yaml(f"coverage/{tool_id}.yml")
        rules = []
        for rule in manifest.get("rules", []):
            name = rule.get("name", "")
            formats = {}
            for fmt, ext in FORMAT_EXTENSIONS.items():
                relative = f"detections/{tool_id}/{fmt}/{name}{ext}"
                if self._exists(relative):
                    formats[fmt] = relative
            comparison = f"public-rules/comparisons/{tool_id}/{name}.md"
            rules.append({**rule, "formats": formats, "comparison": comparison if self._exists(comparison) else None})
        artifacts = self._tool_artifacts(tool_id, manifest)
        procedures = coverage.get("procedures", [])
        return {
            "id": tool_id, "name": registry.get("name", tool_id), "status": registry.get("status", "unknown"),
            "category": registry.get("category", "unknown"), "revision": manifest.get("analyzed_revision", "unknown"),
            "source": registry.get("source_code", {}), "notes": registry.get("notes", ""),
            "completion": manifest.get("completion_states", {}), "counts": manifest.get("counts", {}),
            "procedures": procedures, "rules": rules, "artifacts": [a.__dict__ for a in artifacts],
        }

    def runs(self) -> list[dict[str, Any]]:
        narrative = {p.stem: p for p in (self.root / "runs").glob("*.md") if p.name != ".gitkeep"}
        journals = sorted((self.root / "runs" / "actions").glob("*.jsonl"), reverse=True)
        result = []
        for journal in journals:
            actions = self._read_jsonl(journal)
            result.append({
                "id": journal.stem, "date": journal.stem[:10], "actions": len(actions),
                "started": actions[0].get("timestamp") if actions else None,
                "finished": actions[-1].get("timestamp") if actions else None,
                "outcomes": self._frequencies(a.get("outcome", "unknown") for a in actions),
                "phases": self._frequencies(a.get("phase", "unknown") for a in actions),
                "journal": self._relative(journal),
                "narrative": self._relative(narrative[journal.stem[:10]]) if journal.stem[:10] in narrative else None,
            })
        for date, path in sorted(narrative.items(), reverse=True):
            if not any(item["date"] == date for item in result):
                result.append({"id": date, "date": date, "actions": 0, "journal": None, "narrative": self._relative(path), "outcomes": {}, "phases": {}})
        return result

    def run(self, run_id: str) -> dict[str, Any]:
        journal = self._safe_path(f"runs/actions/{run_id}.jsonl")
        actions = self._read_jsonl(journal) if journal.exists() else []
        narrative_path = self._safe_path(f"runs/{run_id[:10]}.md")
        return {
            "id": run_id, "actions": actions,
            "narrative": self.artifact(self._relative(narrative_path)) if narrative_path.exists() else None,
        }

    def source_tree(self, relative: str = "sources", depth: int = 2) -> dict[str, Any]:
        base = self._safe_path(relative)
        if base != self.root / "sources" and self.root / "sources" not in base.parents:
            raise ValueError("Source browsing is restricted to sources/")
        return self._tree(base, max(0, min(depth, 4)))

    def library_tree(self, relative: str = "", depth: int = 2) -> dict[str, Any]:
        if not relative:
            return {"name": "Artifact library", "path": "", "type": "directory", "children": [self._tree(self.root / item, 0) for item in sorted(LIBRARY_ROOTS) if (self.root / item).exists()]}
        first = Path(relative).parts[0] if Path(relative).parts else ""
        if first not in LIBRARY_ROOTS:
            raise ValueError("Artifact browsing is restricted to repository output directories")
        return self._tree(self._safe_path(relative), max(0, min(depth, 4)))

    def artifact(self, relative: str) -> dict[str, Any]:
        path = self._safe_path(relative)
        if not path.is_file() or path.suffix.lower() not in TEXT_EXTENSIONS:
            raise FileNotFoundError(relative)
        if path.stat().st_size > 2_000_000:
            raise ValueError("Artifact is too large for inline viewing")
        content = path.read_text(encoding="utf-8", errors="replace")
        result = {"path": self._relative(path), "name": path.name, "extension": path.suffix.lower(), "content": content}
        if path.suffix.lower() == ".md":
            result["presentation"] = self._markdown.present(result["path"], content)
        return result

    def search(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        terms = [term.lower() for term in re.findall(r"[A-Za-z0-9_.-]+", query) if len(term) > 1]
        if not terms:
            return []
        results = []
        roots = ["reports", "summaries", "coverage", "detections", "reviews", "telemetry", "public-rules/comparisons", "runs", "sources"]
        expression = "|".join(re.escape(term) for term in terms)
        command = ["rg", "-i", "-l", "--no-messages", "--max-filesize", "1M"]
        for extension in sorted(TEXT_EXTENSIONS):
            command.extend(["--glob", f"*{extension}"])
        command.extend(["--", expression, *roots])
        completed = subprocess.run(command, cwd=self.root, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15)
        if completed.returncode not in {0, 1}:
            raise RuntimeError("Repository search failed")
        for relative in completed.stdout.splitlines():
            path = self._safe_path(relative)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            lower = text.lower()
            score = sum(lower.count(term) * 2 + path.name.lower().count(term) * 8 for term in terms)
            first = min((lower.find(term) for term in terms if term in lower), default=0)
            snippet = re.sub(r"\s+", " ", text[max(0, first - 100):first + 260]).strip()
            kind = Path(relative).parts[0] if Path(relative).parts else "repository"
            results.append({"path": self._relative(path), "name": path.name, "kind": kind, "score": score, "snippet": snippet})
        return sorted(results, key=lambda item: (-item["score"], item["path"]))[: min(limit, 100)]

    def _tool_card(self, tool_id: str) -> dict[str, Any]:
        registry = self._tools[tool_id]
        manifest = self._load_yaml(f"manifests/{tool_id}.yml")
        counts = manifest.get("counts", {})
        return {"id": tool_id, "name": registry.get("name", tool_id), "category": registry.get("category", "unknown"), "status": registry.get("status", "unknown"), "revision": manifest.get("analyzed_revision", "unknown"), "procedures": counts.get("procedures", 0), "rules": counts.get("canonical_rules", 0), "completion": manifest.get("completion_states", {})}

    def _tool_artifacts(self, tool_id: str, manifest: dict[str, Any]) -> list[Artifact]:
        candidates = {
            "summary": f"summaries/{tool_id}.md", "coverage": f"coverage/{tool_id}.yml",
            "telemetry": f"telemetry/{tool_id}.md", "detection review": f"reviews/{tool_id}/detection-review.md",
            "translation review": f"reviews/{tool_id}/translation-review.md", "comparison index": f"public-rules/comparisons/{tool_id}/INDEX.md",
        }
        report = manifest.get("context_entry_points", {}).get("report")
        if report:
            candidates["source analysis"] = report
        return [Artifact(path, kind, Path(path).name, self._safe_path(path).stat().st_size) for kind, path in candidates.items() if self._exists(path)]

    def _tree(self, path: Path, depth: int) -> dict[str, Any]:
        try:
            is_directory = path.is_dir()
            is_file = path.is_file()
        except OSError:
            return {"name": path.name, "path": self._relative(path), "type": "unavailable", "reason": "Endpoint security or filesystem policy denied access"}
        node = {"name": path.name, "path": self._relative(path), "type": "directory" if is_directory else "file"}
        if is_file:
            try:
                node.update({"bytes": path.stat().st_size, "viewable": path.suffix.lower() in TEXT_EXTENSIONS})
            except OSError:
                node.update({"type": "unavailable", "reason": "Endpoint security or filesystem policy denied access"})
        elif depth > 0:
            try:
                children = sorted(path.iterdir(), key=lambda p: p.name.lower())
            except OSError:
                node.update({"children": [], "unavailable": True})
            else:
                node["children"] = [self._tree(child, depth - 1) for child in children if child.name != ".git"]
        else:
            node["children"] = []
            node["truncated"] = True
        return node

    def _load_yaml(self, relative: str) -> dict[str, Any]:
        path = self._safe_path(relative)
        if not path.exists():
            return {}
        loaded = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
        return loaded if isinstance(loaded, dict) else {}

    def _read_jsonl(self, path: Path) -> list[dict[str, Any]]:
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip()]

    def _safe_path(self, relative: str) -> Path:
        candidate = (self.root / relative).resolve()
        if candidate != self.root and self.root not in candidate.parents:
            raise ValueError("Path escapes repository")
        return candidate

    def _exists(self, relative: str) -> bool:
        return self._safe_path(relative).is_file()

    def _relative(self, path: Path) -> str:
        return path.resolve().relative_to(self.root).as_posix()

    def _count(self, relative: str, suffix: str, exclude: set[str] | None = None) -> int:
        exclude = exclude or set()
        return sum(path.name not in exclude for path in self._safe_path(relative).rglob(f"*{suffix}"))

    @staticmethod
    def _frequencies(values: Iterable[str]) -> dict[str, int]:
        result: dict[str, int] = {}
        for value in values:
            result[value] = result.get(value, 0) + 1
        return result
