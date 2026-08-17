from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOG_ROOT = ROOT / "runs" / "actions"


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def log_path(run_id: str) -> Path:
    if not run_id or any(character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_." for character in run_id):
        raise ValueError("run-id may contain only letters, numbers, dash, underscore, and dot")
    return LOG_ROOT / f"{run_id}.jsonl"


def append(run_id: str, phase: str, action: str, target: str, outcome: str, details: str) -> dict:
    path = log_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    sequence = 1
    if path.exists():
        sequence += sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip())
    event = {
        "timestamp": timestamp(),
        "sequence": sequence,
        "run_id": run_id,
        "phase": phase,
        "action": action,
        "target": target,
        "outcome": outcome,
        "details": details,
    }
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")
    return event


def main() -> int:
    parser = argparse.ArgumentParser(description="Append-only detection-agent action journal")
    parser.add_argument("run_id")
    parser.add_argument("phase")
    parser.add_argument("action")
    parser.add_argument("--target", default="repository")
    parser.add_argument("--outcome", choices=("started", "succeeded", "failed", "blocked", "skipped"), required=True)
    parser.add_argument("--details", default="")
    args = parser.parse_args()
    print(json.dumps(append(args.run_id, args.phase, args.action, args.target, args.outcome, args.details), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
