import os, json, mimetypes
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

PORT        = int(os.environ.get('PORT', 3005))
SERVE_ROOT  = os.environ.get('SERVE_ROOT', '/data')
PASSWORD    = os.environ.get('APP_PASSWORD', 'umbrel')
HIDDEN_DIRS = set(os.environ.get('HIDDEN_DIRS', 'umbrel,.ssh,secrets,postgres,.git,.config,lost+found').split(','))
STATIC_DIR  = Path('/app/static')

def check_password(pwd):
    return pwd == PASSWORD

def extract_token(h):
    a = h.headers.get('Authorization','')
    return a[7:] if a.startswith('Bearer ') else ''

def safe_path(req):
    root = Path(SERVE_ROOT).resolve()
    t = (root / req.lstrip('/')).resolve()
    return t if str(t).startswith(str(root)) else None

def list_dir(path):
    items = []
    try:
        for e in sorted(path.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower())):
            if e.name.startswith('.') or (e.is_dir() and e.name in HIDDEN_DIRS): continue
            rel = '/' + str(e.relative_to(Path(SERVE_ROOT).resolve()))
            item = {'name': e.name, 'path': rel, 'type': 'dir' if e.is_dir() else 'file'}
            if e.is_file():
                try: item['size'] = e.stat().st_size
                except: item['size'] = 0
            items.append(item)
    except PermissionError: pass
    return items

class H(BaseHTTPRequestHandler):
    def log_message(self, f, *a): print(f'[{self.address_string()}] {f%a}')

    def json(self, d, s=200):
        b = json.dumps(d).encode()
        self.send_response(s)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',len(b))
        self.send_header('Access-Control-Allow-Origin','*')
        self.end_headers(); self.wfile.write(b)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Headers','Authorization,Content-Type')
        self.end_headers()

    def do_POST(self):
        p = urlparse(self.path)
        if p.path == '/api/login':
            length = int(self.headers.get('Content-Length', 0))
            body = json.loads(self.rfile.read(length))
            pwd = body.get('password','')
            if check_password(pwd):
                return self.json({'ok': True})
            return self.json({'ok': False, 'error': 'Contraseña incorrecta'}, 401)
        self.send_response(404); self.end_headers()

    def do_GET(self):
        p = urlparse(self.path); qs = parse_qs(p.query)

        if p.path == '/api/files':
            if not check_password(extract_token(self)):
                return self.json({'error':'Unauthorized'},401)
            t = safe_path(qs.get('path',['/'])[0])
            if not t or not t.exists() or not t.is_dir(): return self.json({'error':'Not found'},404)
            return self.json(list_dir(t))

        elif p.path == '/api/download':
            if not check_password(extract_token(self)):
                return self.json({'error':'Unauthorized'},401)
            t = safe_path(qs.get('path',[''])[0])
            if not t or not t.exists() or not t.is_file(): return self.json({'error':'Not found'},404)
            mime,_ = mimetypes.guess_type(str(t)); mime = mime or 'application/octet-stream'
            self.send_response(200)
            self.send_header('Content-Type',mime)
            self.send_header('Content-Length',t.stat().st_size)
            self.send_header('Content-Disposition',f'attachment; filename="{t.name}"')
            self.send_header('Access-Control-Allow-Origin','*')
            self.end_headers()
            with open(t,'rb') as f:
                while chunk := f.read(65536): self.wfile.write(chunk)

        else:
            fp = STATIC_DIR / ('index.html' if p.path=='/' else p.path.lstrip('/'))
            if not fp.exists(): fp = STATIC_DIR / 'index.html'
            if fp.exists():
                mime,_ = mimetypes.guess_type(str(fp)); c = fp.read_bytes()
                self.send_response(200)
                self.send_header('Content-Type', mime or 'text/html')
                self.send_header('Content-Length',len(c))
                self.end_headers(); self.wfile.write(c)
            else: self.send_response(404); self.end_headers()

print(f'🚀 Umbrel Share en http://0.0.0.0:{PORT}')
HTTPServer(('0.0.0.0', PORT), H).serve_forever()
