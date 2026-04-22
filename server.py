#!/usr/bin/env python3
"""
Umbrel Share - Backend
Sirve el frontend y expone una API para explorar y descargar archivos del servidor.
"""

import os
import json
import mimetypes
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, unquote
import jwt as pyjwt

# ── Config ────────────────────────────────────────────────────────────────────
PORT = int(os.environ.get("PORT", 3000))
SERVE_ROOT = os.environ.get("SERVE_ROOT", "/data")       # Volumen montado en Docker
UMBREL_JWT_SECRET = os.environ.get("UMBREL_JWT_SECRET", "")  # Secret para validar JWT
HIDDEN_DIRS = set(os.environ.get("HIDDEN_DIRS", "umbrel,.ssh,secrets,postgres,.git").split(","))
FRONTEND_DIR = Path(__file__).parent / "static"

# ── JWT Validation ─────────────────────────────────────────────────────────────
def validate_jwt(token: str) -> bool:
    """
    Valida el JWT de Umbrel.
    Si no tenemos el secret configurado, hacemos decode sin verificar firma
    (modo permisivo — para usar solo en red local).
    """
    if not token:
        return False
    try:
        if UMBREL_JWT_SECRET:
            pyjwt.decode(token, UMBREL_JWT_SECRET, algorithms=["HS256"])
        else:
            # Sin secret: decodificamos sin verificar (solo red local)
            pyjwt.decode(token, options={"verify_signature": False})
        return True
    except Exception:
        return False

def extract_token(handler) -> str:
    auth = handler.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return ""

# ── File helpers ───────────────────────────────────────────────────────────────
def safe_path(requested: str) -> Path | None:
    """Resuelve la ruta y se asegura de que esté dentro de SERVE_ROOT."""
    root = Path(SERVE_ROOT).resolve()
    target = (root / requested.lstrip("/")).resolve()
    if not str(target).startswith(str(root)):
        return None
    return target

def list_dir(path: Path) -> list:
    items = []
    try:
        for entry in sorted(path.iterdir(), key=lambda e: (not e.is_dir(), e.name.lower())):
            if entry.name.startswith("."):
                continue
            if entry.is_dir() and entry.name in HIDDEN_DIRS:
                continue
            rel = "/" + str(entry.relative_to(Path(SERVE_ROOT).resolve()))
            item = {
                "name": entry.name,
                "path": rel,
                "type": "dir" if entry.is_dir() else "file",
            }
            if entry.is_file():
                try:
                    item["size"] = entry.stat().st_size
                except Exception:
                    item["size"] = 0
            items.append(item)
    except PermissionError:
        pass
    return items

# ── HTTP Handler ───────────────────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

    def send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(body))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, msg, status=403):
        self.send_json({"error": msg}, status)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        # ── API: list files ──────────────────────────────────────────────────
        if path == "/api/files":
            token = extract_token(self)
            if not validate_jwt(token):
                return self.send_error_json("Unauthorized", 401)

            req_path = qs.get("path", ["/"])[0]
            target = safe_path(req_path)
            if not target or not target.exists() or not target.is_dir():
                return self.send_error_json("Not found", 404)

            return self.send_json(list_dir(target))

        # ── API: download file ───────────────────────────────────────────────
        elif path == "/api/download":
            token = extract_token(self)
            if not validate_jwt(token):
                return self.send_error_json("Unauthorized", 401)

            req_path = qs.get("path", [""])[0]
            target = safe_path(req_path)
            if not target or not target.exists() or not target.is_file():
                return self.send_error_json("Not found", 404)

            mime, _ = mimetypes.guess_type(str(target))
            mime = mime or "application/octet-stream"
            size = target.stat().st_size

            self.send_response(200)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", size)
            self.send_header("Content-Disposition", f'attachment; filename="{target.name}"')
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            with open(target, "rb") as f:
                while chunk := f.read(65536):
                    self.wfile.write(chunk)

        # ── Static files ─────────────────────────────────────────────────────
        else:
            file_path = FRONTEND_DIR / ("index.html" if path == "/" else path.lstrip("/"))
            if not file_path.exists():
                file_path = FRONTEND_DIR / "index.html"

            if file_path.exists():
                mime, _ = mimetypes.guess_type(str(file_path))
                mime = mime or "text/html"
                content = file_path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", len(content))
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_response(404)
                self.end_headers()


# ── Main ──────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print(f"🚀 Umbrel Share backend corriendo en http://0.0.0.0:{PORT}")
    print(f"📁 Sirviendo archivos desde: {SERVE_ROOT}")
    print(f"🙈 Carpetas ocultas: {HIDDEN_DIRS}")
    server = HTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
