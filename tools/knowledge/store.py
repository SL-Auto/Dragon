from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = REPO_ROOT / "knowledge" / "config.json"
LOCAL_DIR = REPO_ROOT / ".knowledge"
INDEX_PATH = LOCAL_DIR / "index.db"
QUERY_PATH = LOCAL_DIR / "queries.db"


def _config() -> dict[str, Any]:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))


def _connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=30000")
    return connection


def _create_schema(connection: sqlite3.Connection, config: dict[str, Any]) -> None:
    connection.executescript("""
        CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL, content_hash TEXT NOT NULL,
            title TEXT, domain TEXT, type TEXT, authority TEXT, version TEXT,
            tags TEXT, indexed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS chunks (
            id INTEGER PRIMARY KEY, document_id INTEGER NOT NULL,
            heading TEXT NOT NULL, content TEXT NOT NULL, chunk_index INTEGER NOT NULL,
            FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE
        );
        CREATE VIRTUAL TABLE IF NOT EXISTS chunks_fts USING fts5(
            heading, content, content='chunks', content_rowid='id', tokenize='unicode61'
        );
        CREATE TRIGGER IF NOT EXISTS chunks_ai AFTER INSERT ON chunks BEGIN
            INSERT INTO chunks_fts(rowid, heading, content) VALUES (new.id, new.heading, new.content);
        END;
        CREATE TRIGGER IF NOT EXISTS chunks_ad AFTER DELETE ON chunks BEGIN
            INSERT INTO chunks_fts(chunks_fts, rowid, heading, content) VALUES('delete', old.id, old.heading, old.content);
        END;
        CREATE TRIGGER IF NOT EXISTS chunks_au AFTER UPDATE ON chunks BEGIN
            INSERT INTO chunks_fts(chunks_fts, rowid, heading, content) VALUES('delete', old.id, old.heading, old.content);
            INSERT INTO chunks_fts(rowid, heading, content) VALUES (new.id, new.heading, new.content);
        END;
    """)
    values = {
        "schema_version": str(SCHEMA_VERSION),
        "chunker_version": str(config["chunker_version"]),
        "embedding_adapter": config["embedding"]["adapter"],
    }
    connection.executemany("INSERT OR REPLACE INTO metadata(key,value) VALUES (?,?)", values.items())


def _discover(config: dict[str, Any]) -> dict[str, tuple[Path, dict[str, Any]]]:
    found: dict[str, tuple[Path, dict[str, Any]]] = {}
    for source in config["sources"]:
        base = REPO_ROOT / source["path"]
        paths = [base] if base.is_file() else (base.glob(source.get("glob", "**/*.md")) if base.exists() else [])
        for path in paths:
            if path.is_file() and ".knowledge" not in path.parts:
                found[path.relative_to(REPO_ROOT).as_posix()] = (path, source)
    return found


def _front_matter(text: str) -> tuple[dict[str, Any], str]:
    if not text.startswith("---\n"):
        return {}, text
    end = text.find("\n---\n", 4)
    if end < 0:
        return {}, text
    metadata: dict[str, Any] = {}
    for line in text[4:end].splitlines():
        if ":" not in line or line.startswith((" ", "\t", "-")):
            continue
        key, value = line.split(":", 1)
        value = value.strip().strip('"\'')
        if value.startswith("[") and value.endswith("]"):
            metadata[key.strip()] = [item.strip().strip('"\'') for item in value[1:-1].split(",") if item.strip()]
        else:
            metadata[key.strip()] = value
    return metadata, text[end + 5 :]


def _chunks(text: str, target_words: int, max_words: int) -> list[tuple[str, str]]:
    sections: list[tuple[list[str], list[str]]] = []
    hierarchy: list[str] = []
    current_heading = ["Document"]
    body: list[str] = []
    for line in text.splitlines():
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match:
            if body or current_heading != ["Document"]:
                sections.append((current_heading.copy(), body))
            level, title = len(match.group(1)), match.group(2)
            hierarchy = hierarchy[: level - 1]
            hierarchy.append(title)
            current_heading = hierarchy.copy()
            body = []
        else:
            body.append(line)
    if body or not sections:
        sections.append((current_heading.copy(), body))

    result: list[tuple[str, str]] = []
    for headings, lines in sections:
        heading = " > ".join(headings)
        paragraphs = [part.strip() for part in re.split(r"\n\s*\n", "\n".join(lines)) if part.strip()]
        current: list[str] = []
        count = 0
        for paragraph in paragraphs:
            words = len(paragraph.split())
            if current and count + words > max_words:
                result.append((heading, "\n\n".join(current)))
                current, count = [], 0
            current.append(paragraph)
            count += words
            if count >= target_words:
                result.append((heading, "\n\n".join(current)))
                current, count = [], 0
        if current:
            result.append((heading, "\n\n".join(current)))
    return result


def index_knowledge(rebuild: bool = False, destination: Path | None = None) -> dict[str, int]:
    config = _config()
    target = destination or INDEX_PATH
    if rebuild and target.exists():
        replacement = target.with_suffix(".db.new")
        replacement.unlink(missing_ok=True)
        stats = index_knowledge(False, replacement)
        os.replace(replacement, target)
        return stats
    connection = _connect(target)
    _create_schema(connection, config)
    discovered = _discover(config)
    existing = {row["path"]: row for row in connection.execute("SELECT id,path,content_hash FROM documents")}
    changed = unchanged = deleted = 0
    now = datetime.now(timezone.utc).isoformat()
    with connection:
        for relative, (path, defaults) in discovered.items():
            raw = path.read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            if relative in existing and existing[relative]["content_hash"] == digest:
                unchanged += 1
                continue
            text = raw.decode("utf-8-sig", errors="replace").replace("\r\n", "\n")
            metadata, content = _front_matter(text)
            title_match = re.search(r"(?m)^#\s+(.+)$", content)
            title = metadata.get("title") or (title_match.group(1) if title_match else path.stem)
            values = (relative, digest, title, metadata.get("domain", defaults.get("domain")),
                      metadata.get("type", defaults.get("type")), metadata.get("authority", defaults.get("authority")),
                      str(metadata.get("version", "")), json.dumps(metadata.get("tags", [])), now)
            connection.execute("""INSERT INTO documents(path,content_hash,title,domain,type,authority,version,tags,indexed_at)
                VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(path) DO UPDATE SET content_hash=excluded.content_hash,
                title=excluded.title,domain=excluded.domain,type=excluded.type,authority=excluded.authority,
                version=excluded.version,tags=excluded.tags,indexed_at=excluded.indexed_at""", values)
            document_id = connection.execute("SELECT id FROM documents WHERE path=?", (relative,)).fetchone()[0]
            connection.execute("DELETE FROM chunks WHERE document_id=?", (document_id,))
            parts = _chunks(content, config["chunking"]["target_words"], config["chunking"]["max_words"])
            connection.executemany("INSERT INTO chunks(document_id,heading,content,chunk_index) VALUES (?,?,?,?)",
                                   [(document_id, heading, body, index) for index, (heading, body) in enumerate(parts)])
            changed += 1
        for relative in set(existing) - set(discovered):
            connection.execute("DELETE FROM documents WHERE path=?", (relative,))
            deleted += 1
        connection.execute("INSERT OR REPLACE INTO metadata(key,value) VALUES ('last_indexed',?)", (now,))
    counts = connection.execute("SELECT COUNT(*) documents, (SELECT COUNT(*) FROM chunks) chunks FROM documents").fetchone()
    connection.close()
    return {"changed": changed, "unchanged": unchanged, "deleted": deleted, "documents": counts[0], "chunks": counts[1]}


def _query_terms(query: str) -> str:
    terms = re.findall(r"[A-Za-z0-9_.-]+", query)
    return " OR ".join(f'"{term}"' for term in terms if len(term) > 1)


def _normalise_query(query: str) -> str:
    return " ".join(re.findall(r"[a-z0-9_.-]+", query.lower()))


def _ensure_query_schema(connection: sqlite3.Connection) -> None:
    connection.executescript("""CREATE TABLE IF NOT EXISTS queries (
        id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, query TEXT NOT NULL,
        normalized_query TEXT, filters TEXT, top_k INTEGER, result_count INTEGER, latency_ms REAL);
        CREATE TABLE IF NOT EXISTS query_results (
        query_id INTEGER, source TEXT, heading TEXT, rank INTEGER, score REAL);""")
    columns = {row[1] for row in connection.execute("PRAGMA table_info(queries)")}
    if "normalized_query" not in columns:
        connection.execute("ALTER TABLE queries ADD COLUMN normalized_query TEXT")
    connection.execute("UPDATE queries SET normalized_query=lower(trim(query)) WHERE normalized_query IS NULL")


def _log_query(query: str, filters: dict[str, Any], top_k: int, results: list[dict[str, Any]], latency_ms: float) -> dict[str, Any]:
    connection = _connect(QUERY_PATH)
    with connection:
        _ensure_query_schema(connection)
        timestamp = datetime.now(timezone.utc).isoformat()
        cursor = connection.execute("INSERT INTO queries(timestamp,query,normalized_query,filters,top_k,result_count,latency_ms) VALUES (?,?,?,?,?,?,?)",
            (timestamp, query, _normalise_query(query), json.dumps(filters), top_k, len(results), latency_ms))
        connection.executemany("INSERT INTO query_results(query_id,source,heading,rank,score) VALUES (?,?,?,?,?)",
            [(cursor.lastrowid, item["source"], item["heading"], rank, item["score"]) for rank, item in enumerate(results, 1)])
    connection.close()
    return {"query_id": cursor.lastrowid, "timestamp": timestamp,
            "result_count": len(results), "latency_ms": round(latency_ms, 2)}


def search_knowledge(query: str, domain: str | None = None, type: str | None = None,
                     authority: str | None = None, top_k: int = 5,
                     include_neighbours: int = 0, refresh: bool = True) -> dict[str, Any]:
    started = time.perf_counter()
    if refresh or not INDEX_PATH.exists():
        index_knowledge()
    terms = _query_terms(query)
    if not terms:
        elapsed = (time.perf_counter() - started) * 1000
        filters = {key: value for key, value in {"domain": domain, "type": type, "authority": authority}.items() if value}
        receipt = _log_query(query, filters, top_k, [], elapsed)
        return {"query": query, "filters": filters, "receipt": receipt,
                "results": [], "warning": "No searchable terms"}
    config = _config()
    connection = _connect(INDEX_PATH)
    clauses, parameters = ["chunks_fts MATCH ?"], [terms]
    for column, value in (("d.domain", domain), ("d.type", type), ("d.authority", authority)):
        if value:
            clauses.append(f"{column} = ?")
            parameters.append(value)
    parameters.append(max(top_k * 8, 40))
    rows = connection.execute(f"""SELECT c.id,c.document_id,c.chunk_index,c.heading,c.content,
        d.path,d.title,d.domain,d.type,d.authority,d.version,bm25(chunks_fts,4.0,1.0) rank
        FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid JOIN documents d ON d.id=c.document_id
        WHERE {' AND '.join(clauses)} ORDER BY rank LIMIT ?""", parameters).fetchall()
    max_per_source = config["ranking"]["max_chunks_per_source"]
    boosts = config["ranking"]["authority_boost"]
    ranked = sorted(rows, key=lambda row: (-float(row["rank"])) * boosts.get(row["authority"], 1.0), reverse=True)
    selected, source_counts = [], {}
    for row in ranked:
        if source_counts.get(row["path"], 0) >= max_per_source:
            continue
        selected.append(row)
        source_counts[row["path"]] = source_counts.get(row["path"], 0) + 1
        if len(selected) >= top_k:
            break
    results: list[dict[str, Any]] = []
    for row in selected:
        score = round((-float(row["rank"])) * boosts.get(row["authority"], 1.0), 6)
        item = {"score": score, "source": row["path"], "heading": row["heading"],
                "title": row["title"], "domain": row["domain"], "type": row["type"],
                "authority": row["authority"], "version": row["version"], "content": row["content"]}
        if include_neighbours:
            neighbours = connection.execute("""SELECT heading,content,chunk_index FROM chunks
                WHERE document_id=? AND chunk_index BETWEEN ? AND ? AND id<>? ORDER BY chunk_index""",
                (row["document_id"], row["chunk_index"] - include_neighbours,
                 row["chunk_index"] + include_neighbours, row["id"])).fetchall()
            item["neighbours"] = [dict(neighbour) for neighbour in neighbours]
        results.append(item)
    connection.close()
    elapsed = (time.perf_counter() - started) * 1000
    filters = {key: value for key, value in {"domain": domain, "type": type, "authority": authority}.items() if value}
    receipt = _log_query(query, filters, top_k, results, elapsed)
    return {"query": query, "filters": filters, "retrieval": "sqlite_fts5",
            "receipt": receipt, "results": results}


def stats() -> dict[str, Any]:
    if not INDEX_PATH.exists():
        return {"exists": False}
    connection = _connect(INDEX_PATH)
    counts = connection.execute("SELECT COUNT(*) documents,(SELECT COUNT(*) FROM chunks) chunks FROM documents").fetchone()
    metadata = dict(connection.execute("SELECT key,value FROM metadata"))
    domains = {row[0]: row[1] for row in connection.execute("SELECT domain,COUNT(*) FROM documents GROUP BY domain")}
    connection.close()
    return {"exists": True, "documents": counts[0], "chunks": counts[1], "index_bytes": INDEX_PATH.stat().st_size,
            "metadata": metadata, "domains": domains}


def query_stats() -> dict[str, Any]:
    if not QUERY_PATH.exists():
        return {"exists": False, "queries": 0}
    connection = _connect(QUERY_PATH)
    with connection:
        _ensure_query_schema(connection)
    total = connection.execute("SELECT COUNT(*) FROM queries").fetchone()[0]
    zero = connection.execute("SELECT COUNT(*) FROM queries WHERE result_count=0").fetchone()[0]
    average_latency = connection.execute("SELECT ROUND(AVG(latency_ms),2) FROM queries").fetchone()[0]
    frequent = [dict(row) for row in connection.execute("""SELECT normalized_query query,COUNT(*) count,
        ROUND(AVG(result_count),2) average_results FROM queries GROUP BY normalized_query
        ORDER BY count DESC, normalized_query LIMIT 20""")]
    sources = [dict(row) for row in connection.execute("""SELECT source,COUNT(*) returned_count
        FROM query_results GROUP BY source ORDER BY returned_count DESC, source LIMIT 20""")]
    headings = [dict(row) for row in connection.execute("""SELECT source,heading,COUNT(*) returned_count
        FROM query_results GROUP BY source,heading ORDER BY returned_count DESC,source,heading LIMIT 20""")]
    recent_zero = [dict(row) for row in connection.execute("""SELECT timestamp,query,filters
        FROM queries WHERE result_count=0 ORDER BY id DESC LIMIT 20""")]
    connection.close()
    return {"exists": True, "database": str(QUERY_PATH.relative_to(REPO_ROOT)), "queries": total,
            "zero_result_queries": zero, "average_latency_ms": average_latency,
            "most_requested": frequent, "most_returned_sources": sources,
            "most_returned_headings": headings, "recent_zero_result_queries": recent_zero}
