from __future__ import annotations

import re
from pathlib import Path
from typing import Any


CLASS_LABELS = {
    "report": "Source analysis",
    "review": "Detection review",
    "comparison": "Public comparison",
    "telemetry": "Telemetry specification",
    "run": "Agent run",
    "summary": "Procedure summary",
    "research": "Research note",
    "changelog": "Change history",
    "documentation": "Documentation",
}


class MarkdownPresenter:
    """Classify Markdown and produce a stable structured presentation model."""

    def present(self, relative_path: str, text: str) -> dict[str, Any]:
        document_class = self._classify(relative_path)
        blocks = self._parse(text)
        title = next((block["text"] for block in blocks if block["type"] == "heading" and block["level"] == 1), Path(relative_path).stem)
        headings = [block for block in blocks if block["type"] == "heading" and block["level"] in {2, 3}]
        return {
            "class": document_class,
            "label": CLASS_LABELS[document_class],
            "title": title,
            "subtitle": self._subtitle(document_class, relative_path, text),
            "stats": self._stats(document_class, blocks, text),
            "navigation": [{"id": block["id"], "text": block["text"], "level": block["level"]} for block in headings],
            "blocks": blocks,
        }

    @staticmethod
    def _classify(relative_path: str) -> str:
        path = relative_path.replace("\\", "/").lower()
        if path == "changelog.md":
            return "changelog"
        if path.startswith("public-rules/comparisons/"):
            return "comparison"
        if path.startswith("reports/") or path.endswith("source_detection_deep_dive.md"):
            return "report"
        if path.startswith("reviews/"):
            return "review"
        if path.startswith("telemetry/"):
            return "telemetry"
        if path.startswith("runs/"):
            return "run"
        if path.startswith("summaries/"):
            return "summary"
        if path.startswith("research/"):
            return "research"
        return "documentation"

    def _parse(self, text: str) -> list[dict[str, Any]]:
        lines = text.splitlines()
        blocks: list[dict[str, Any]] = []
        index = 0
        slug_counts: dict[str, int] = {}
        while index < len(lines):
            line = lines[index]
            if not line.strip():
                index += 1
                continue
            heading = re.match(r"^(#{1,6})\s+(.+)$", line)
            if heading:
                label = heading.group(2).strip()
                slug = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-") or "section"
                slug_counts[slug] = slug_counts.get(slug, 0) + 1
                if slug_counts[slug] > 1:
                    slug = f"{slug}-{slug_counts[slug]}"
                blocks.append({"type": "heading", "level": len(heading.group(1)), "text": label, "id": slug})
                index += 1
                continue
            if line.startswith("```"):
                language = line[3:].strip()
                code: list[str] = []
                index += 1
                while index < len(lines) and not lines[index].startswith("```"):
                    code.append(lines[index]); index += 1
                index += index < len(lines)
                blocks.append({"type": "code", "language": language, "text": "\n".join(code)})
                continue
            if line.lstrip().startswith("|") and index + 1 < len(lines) and re.match(r"^\s*\|?[\s:|-]+\|\s*$", lines[index + 1]):
                header = self._cells(line)
                index += 2
                rows = []
                while index < len(lines) and lines[index].lstrip().startswith("|"):
                    rows.append(self._cells(lines[index])); index += 1
                blocks.append({"type": "table", "headers": header, "rows": rows})
                continue
            if re.match(r"^\s*[-*+]\s+", line) or re.match(r"^\s*\d+[.)]\s+", line):
                items = []
                ordered = bool(re.match(r"^\s*\d+", line))
                while index < len(lines):
                    match = re.match(r"^\s*(?:[-*+]|\d+[.)])\s+(.+)$", lines[index])
                    if not match:
                        break
                    items.append(match.group(1).strip()); index += 1
                blocks.append({"type": "list", "ordered": ordered, "items": items})
                continue
            if line.startswith(">"):
                quote = []
                while index < len(lines) and lines[index].startswith(">"):
                    quote.append(lines[index].lstrip("> ")); index += 1
                blocks.append({"type": "quote", "text": "\n".join(quote)})
                continue
            paragraph = [line.strip()]
            index += 1
            while index < len(lines) and lines[index].strip() and not self._starts_block(lines, index):
                paragraph.append(lines[index].strip()); index += 1
            blocks.append({"type": "paragraph", "text": " ".join(paragraph)})
        return blocks

    @staticmethod
    def _starts_block(lines: list[str], index: int) -> bool:
        line = lines[index]
        return bool(re.match(r"^#{1,6}\s", line) or line.startswith("```") or line.startswith(">") or re.match(r"^\s*(?:[-*+]|\d+[.)])\s+", line) or (line.lstrip().startswith("|") and index + 1 < len(lines) and re.match(r"^\s*\|?[\s:|-]+\|\s*$", lines[index + 1])))

    @staticmethod
    def _cells(line: str) -> list[str]:
        return [cell.strip() for cell in line.strip().strip("|").split("|")]

    @staticmethod
    def _subtitle(document_class: str, relative_path: str, text: str) -> str:
        if document_class == "comparison":
            decision = re.search(r"(?im)^-\s*Decision:\s*`?([^`\n]+)", text)
            return f"Independent logic assessment · {decision.group(1).strip() if decision else 'decision pending'}"
        if document_class == "review":
            return "Adversarial detection-logic findings and same-run remediation"
        if document_class == "telemetry":
            return "Collection prerequisites, event coverage, dependencies, and gaps"
        if document_class == "report":
            return "Pinned evidence, complete procedure inventory, and observable security effects"
        if document_class == "run":
            return "Discovery, implementation, validation, and analyst follow-up record"
        if document_class == "summary":
            return "Compact generated view of procedure coverage"
        if document_class == "changelog":
            return "Capability and workflow evolution"
        return relative_path

    @staticmethod
    def _stats(document_class: str, blocks: list[dict[str, Any]], text: str) -> list[dict[str, Any]]:
        tables = [block for block in blocks if block["type"] == "table"]
        code = [block for block in blocks if block["type"] == "code"]
        level_three = [block for block in blocks if block["type"] == "heading" and block["level"] == 3]
        stats = [
            {"label": "Sections", "value": sum(block["type"] == "heading" and block["level"] >= 2 for block in blocks)},
            {"label": "Matrices", "value": len(tables)},
        ]
        if document_class == "review":
            stats.append({"label": "Findings", "value": sum(block["text"].upper().startswith("REVIEW-") for block in level_three)})
            stats.append({"label": "High / blocker", "value": len(re.findall(r"(?im)^-\s*Severity:\s*`?(?:high|blocker)", text))})
        elif document_class == "comparison":
            stats.append({"label": "Rule proposals", "value": len(code)})
            stats.append({"label": "Branches", "value": sum(len(table["rows"]) for table in tables)})
        elif document_class == "telemetry":
            stats.append({"label": "Event rows", "value": sum(len(table["rows"]) for table in tables)})
            stats.append({"label": "Gaps", "value": len(re.findall(r"(?i)\bgap\b", text))})
        elif document_class == "report":
            stats.append({"label": "Procedures", "value": len(re.findall(r"(?m)^###?\s+(?:P|PROC-|[A-Z]{2,4}-P)\d+", text))})
            stats.append({"label": "Citations", "value": len(re.findall(r"\[[^]]+\]\(https?://", text))})
        elif document_class == "run":
            stats.append({"label": "Validation refs", "value": len(re.findall(r"(?i)validat", text))})
            stats.append({"label": "Blocked refs", "value": len(re.findall(r"(?i)block", text))})
        elif document_class == "summary":
            stats.append({"label": "Procedures", "value": len(re.findall(r"(?m)^[-|].*(?:P|PROC-)\d+", text))})
        else:
            stats.append({"label": "Code blocks", "value": len(code)})
        return stats
