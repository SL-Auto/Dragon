from __future__ import annotations

import argparse
import json
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from catalog import RepositoryCatalog
from workspace import AnalystWorkspace


HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"


class DashboardHandler(BaseHTTPRequestHandler):
    catalog: RepositoryCatalog
    workspace: AnalystWorkspace

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path.startswith("/api/"):
                self._api(parsed.path, parse_qs(parsed.query))
            else:
                self._static(parsed.path)
        except (KeyError, FileNotFoundError):
            self._json({"error": "not_found"}, 404)
        except ValueError as exc:
            self._json({"error": "invalid_request", "detail": str(exc)}, 400)
        except Exception as exc:
            self._json({"error": "server_error", "detail": str(exc)}, 500)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            parts = [unquote(part) for part in parsed.path.split("/") if part]
            if len(parts) != 3 or parts[:2] != ["api", "workspace"]:
                return self._json({"error": "not_found"}, 404)
            length = int(self.headers.get("Content-Length", "0"))
            if length > 1_000_000:
                raise ValueError("Request is too large")
            payload = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(payload, dict):
                raise ValueError("JSON object required")
            self._json(self.workspace.change(parts[2], payload))
        except (KeyError, FileNotFoundError):
            self._json({"error": "not_found"}, 404)
        except (ValueError, json.JSONDecodeError) as exc:
            self._json({"error": "invalid_request", "detail": str(exc)}, 400)
        except Exception as exc:
            self._json({"error": "server_error", "detail": str(exc)}, 500)

    def _api(self, path: str, query: dict[str, list[str]]) -> None:
        parts = [unquote(part) for part in path.split("/") if part][1:]
        if parts == ["overview"]:
            return self._json(self.catalog.overview())
        if parts == ["tools"]:
            return self._json(self.catalog.overview()["tools"])
        if len(parts) == 2 and parts[0] == "tools":
            return self._json(self.catalog.tool(parts[1]))
        if parts == ["runs"]:
            return self._json(self.catalog.runs())
        if len(parts) == 2 and parts[0] == "runs":
            return self._json(self.catalog.run(parts[1]))
        if parts == ["sources"]:
            return self._json(self.catalog.source_tree(query.get("path", ["sources"])[0], int(query.get("depth", ["2"])[0])))
        if parts == ["library"]:
            return self._json(self.catalog.library_tree(query.get("path", [""])[0], int(query.get("depth", ["2"])[0])))
        if parts == ["artifact"]:
            return self._json(self.catalog.artifact(query.get("path", [""])[0]))
        if parts == ["search"]:
            return self._json(self.catalog.search(query.get("q", [""])[0]))
        if len(parts) == 2 and parts[0] == "workspace":
            params = {key: values[0] for key, values in query.items()}
            if parts[1] == "export":
                filename, content_type, body = self.workspace.export(params.pop("view", "gaps"), params.pop("format", "json"), params)
                return self._download(filename, content_type, body)
            return self._json(self.workspace.query(parts[1], params))
        self._json({"error": "not_found"}, 404)

    def _static(self, path: str) -> None:
        relative = "index.html" if path in {"", "/"} else path.lstrip("/")
        candidate = (STATIC / relative).resolve()
        if STATIC not in candidate.parents or not candidate.is_file():
            candidate = STATIC / "index.html"
        body = candidate.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(candidate.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, value: object, status: int = 200) -> None:
        body = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _download(self, filename: str, content_type: str, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[dashboard] {self.address_string()} {format % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Detection Research Dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--repo", type=Path, default=HERE.parent)
    args = parser.parse_args()
    DashboardHandler.catalog = RepositoryCatalog(args.repo)
    DashboardHandler.workspace = AnalystWorkspace(args.repo, DashboardHandler.catalog)
    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"Detection Research Dashboard: http://{args.host}:{args.port}")
    print(f"Repository: {args.repo.resolve()}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
