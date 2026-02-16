import argparse
import json
import re
from datetime import datetime
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


class SafeStaticHandler(SimpleHTTPRequestHandler):
    # Avoid writing to a detached stderr, which can break requests in some launch modes.
    def log_message(self, format, *args):  # noqa: A003
        return

    def handle(self):
        try:
            super().handle()
        except BrokenPipeError:
            return
        except ConnectionResetError:
            return

    def _repo_root(self):
        return Path(self.directory).resolve()

    def _reports_dir(self):
        return self._repo_root() / "reports"

    def _review_state_path(self):
        return self._reports_dir() / "review_state.json"

    def _load_review_state(self):
        p = self._review_state_path()
        if not p.exists():
            return {"items": {}}
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {"items": {}}
        if not isinstance(data, dict):
            return {"items": {}}
        items = data.get("items")
        if not isinstance(items, dict):
            data["items"] = {}
        return data

    def _save_review_state(self, payload):
        p = self._review_state_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(p)

    def _write_json(self, code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _list_findings_files(self):
        reports = self._reports_dir()
        reports.mkdir(parents=True, exist_ok=True)
        files = []
        patterns = ["findings__*.json", "safe_ai_risk__*.json", "uploaded__*.json"]
        candidates = []
        for pat in patterns:
            candidates.extend(list(reports.rglob(pat)))
        unique = {}
        for p in candidates:
            try:
                rel = p.resolve().relative_to(reports.resolve()).as_posix()
                unique[rel] = p
            except Exception:
                continue
        sorted_paths = sorted(unique.values(), key=lambda x: x.stat().st_mtime, reverse=True)
        for p in sorted_paths:
            rel = p.resolve().relative_to(reports.resolve()).as_posix()
            files.append(
                {
                    "name": rel,
                    "size": p.stat().st_size,
                    "modified_utc": datetime.utcfromtimestamp(p.stat().st_mtime).isoformat() + "Z",
                }
            )
        latest = reports / "findings.json"
        if latest.exists():
            files.insert(
                0,
                {
                    "name": latest.name,
                    "size": latest.stat().st_size,
                    "modified_utc": datetime.utcfromtimestamp(latest.stat().st_mtime).isoformat() + "Z",
                },
            )
        latest_safe = reports / "safe_ai_risk.json"
        if latest_safe.exists():
            files.insert(
                0,
                {
                    "name": latest_safe.name,
                    "size": latest_safe.stat().st_size,
                    "modified_utc": datetime.utcfromtimestamp(latest_safe.stat().st_mtime).isoformat() + "Z",
                },
            )
        return files

    def _extract_upload(self):
        content_type = self.headers.get("content-type", "")
        m = re.search(r"boundary=(.+)", content_type)
        if "multipart/form-data" not in content_type.lower() or not m:
            return None, "Use multipart/form-data with file field"

        boundary = m.group(1).strip().strip('"')
        content_length = int(self.headers.get("content-length", "0"))
        body = self.rfile.read(content_length)
        marker = ("--" + boundary).encode("utf-8")
        parts = body.split(marker)
        for part in parts:
            if b"Content-Disposition" not in part:
                continue
            header_end = part.find(b"\r\n\r\n")
            if header_end == -1:
                continue
            headers = part[:header_end].decode("utf-8", errors="ignore")
            if 'name="file"' not in headers:
                continue
            filename_match = re.search(r'filename="([^"]*)"', headers)
            filename = filename_match.group(1) if filename_match else "findings.json"
            content = part[header_end + 4 :]
            if content.endswith(b"\r\n"):
                content = content[:-2]
            if content.endswith(b"--"):
                content = content[:-2]
            return {"filename": filename, "content": content}, None
        return None, "Missing upload file"

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/findings-files":
            return self._write_json(200, {"files": self._list_findings_files()})

        if parsed.path == "/api/review-state":
            data = self._load_review_state()
            return self._write_json(200, data)

        if parsed.path == "/api/findings-file":
            query = parse_qs(parsed.query)
            name = unquote((query.get("name") or [""])[0]).strip()
            if not name:
                return self._write_json(400, {"error": "Invalid file name"})
            normalized = Path(name.replace("\\", "/"))
            if normalized.is_absolute() or ".." in normalized.parts:
                return self._write_json(400, {"error": "Invalid file name"})
            target = (self._reports_dir() / name).resolve()
            if not str(target).startswith(str(self._reports_dir().resolve())) or not target.exists():
                return self._write_json(404, {"error": "File not found"})
            try:
                data = json.loads(target.read_text(encoding="utf-8"))
            except Exception as exc:
                return self._write_json(500, {"error": f"Failed to parse JSON: {exc}"})
            return self._write_json(200, {"name": name, "data": data})

        return super().do_GET()

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/api/review-state":
            length = int(self.headers.get("content-length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                body = json.loads(raw.decode("utf-8"))
            except Exception:
                return self._write_json(400, {"error": "Invalid JSON payload"})
            finding_key = str((body or {}).get("finding_key") or "").strip()
            status = str((body or {}).get("status") or "").strip().lower()
            file_name = str((body or {}).get("file_name") or "").strip()
            allowed = {"todo", "in_progress", "verified", "resolved"}
            if not finding_key:
                return self._write_json(400, {"error": "finding_key is required"})
            if status not in allowed:
                return self._write_json(400, {"error": f"Invalid status. Allowed: {sorted(allowed)}"})

            state = self._load_review_state()
            items = state.get("items") if isinstance(state.get("items"), dict) else {}
            entry = {
                "status": status,
                "file_name": file_name,
                "updated_utc": datetime.utcnow().isoformat() + "Z",
            }
            items[finding_key] = entry
            state["items"] = items
            self._save_review_state(state)
            return self._write_json(200, {"ok": True, "finding_key": finding_key, "entry": entry})

        if parsed.path != "/api/upload-findings":
            return self._write_json(404, {"error": "Unknown endpoint"})

        upload, upload_error = self._extract_upload()
        if upload_error:
            return self._write_json(400, {"error": upload_error})

        raw_name = Path(upload["filename"] or "findings.json").name
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = f"uploaded__{ts}__{raw_name}"
        target = self._reports_dir() / safe_name
        payload = upload["content"]
        try:
            json.loads(payload.decode("utf-8"))
        except Exception:
            return self._write_json(400, {"error": "Uploaded file is not valid JSON"})
        target.write_bytes(payload)
        return self._write_json(201, {"saved_as": safe_name})


def main():
    parser = argparse.ArgumentParser(description="Serve NFR Audit Workbench UI locally")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[1]
    handler = partial(SafeStaticHandler, directory=str(repo_root))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    server.daemon_threads = True
    server.allow_reuse_address = True

    print(f"Serving NFR Audit Workbench UI at http://{args.host}:{args.port}/ui/index.html", flush=True)
    print(f"Reading report from http://{args.host}:{args.port}/reports/findings.json", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
