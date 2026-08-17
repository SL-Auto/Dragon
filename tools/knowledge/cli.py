from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.knowledge.store import index_knowledge, query_stats, search_knowledge, stats


def main() -> int:
    parser = argparse.ArgumentParser(description="Repository knowledge retrieval")
    commands = parser.add_subparsers(dest="command", required=True)
    index = commands.add_parser("index", help="Incrementally refresh the local index")
    index.add_argument("--rebuild", action="store_true")
    search = commands.add_parser("search", help="Retrieve attributed knowledge chunks")
    search.add_argument("query")
    search.add_argument("--domain")
    search.add_argument("--type")
    search.add_argument("--authority")
    search.add_argument("--top-k", type=int, default=5)
    search.add_argument("--include-neighbours", type=int, default=0)
    search.add_argument("--no-refresh", action="store_true")
    commands.add_parser("stats", help="Show index metadata")
    commands.add_parser("query-stats", help="Show local retrieval telemetry")
    args = parser.parse_args()
    if args.command == "index":
        result = index_knowledge(rebuild=args.rebuild)
    elif args.command == "search":
        result = search_knowledge(args.query, args.domain, args.type, args.authority,
                                  max(1, args.top_k), max(0, args.include_neighbours), not args.no_refresh)
    elif args.command == "stats":
        result = stats()
    else:
        result = query_stats()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
