#!/usr/bin/env python3
"""
Serveur d'upload sécurisé - Sans dépendances
Usage: python3 upload_server.py
"""

import http.server
import socketserver
import cgi
import os
import secrets
import hashlib
import html
from pathlib import Path
from urllib.parse import unquote_plus

# ============ CONFIGURATION ============
PORT = 8080
HOST = "0.0.0.0"
ACCESS_CODE = "MonCodeSecret2024"  # ⚠️ CHANGE-MOI !
UPLOAD_DIR = "./uploads"
MAX_FILE_SIZE = 500 * 1024 * 1024  # 500 MB
ALLOWED_EXTENSIONS = None  # None = tout autorisé, sinon: {'.jpg', '.png', '.pdf'}
# =======================================

Path(UPLOAD_DIR).mkdir(parents=True, exist_ok=True)
SESSIONS = set()

HTML_LOGIN = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Login</title>
<style>
body{font-family:sans-serif;background:#1e1e2e;color:#cdd6f4;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
.box{background:#313244;padding:2em;border-radius:10px;box-shadow:0 4px 20px rgba(0,0,0,.5)}
input{padding:.7em;border:none;border-radius:5px;background:#45475a;color:#cdd6f4;width:250px;font-size:1em}
button{padding:.7em 1.5em;border:none;border-radius:5px;background:#89b4fa;color:#1e1e2e;font-weight:bold;cursor:pointer;margin-left:.5em}
button:hover{background:#74c7ec}
.err{color:#f38ba8;margin-top:1em}
h2{margin-top:0}
</style></head>
<body><div class="box"><h2>🔒 Authentification</h2>
<form method="POST" action="/login">
<input type="password" name="code" placeholder="Code d'accès" autofocus required>
<button type="submit">Entrer</button>
</form>__ERROR__</div></body></html>"""

HTML_UPLOAD = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Upload</title>
<style>
body{font-family:sans-serif;background:#1e1e2e;color:#cdd6f4;max-width:800px;margin:2em auto;padding:1em}
.box{background:#313244;padding:2em;border-radius:10px;margin-bottom:1em}
input[type=file]{padding:.5em;background:#45475a;color:#cdd6f4;border-radius:5px;border:none;width:100%;margin-bottom:1em}
button{padding:.7em 1.5em;border:none;border-radius:5px;background:#a6e3a1;color:#1e1e2e;font-weight:bold;cursor:pointer}
button:hover{background:#94e2d5}
.logout{background:#f38ba8;float:right;text-decoration:none;padding:.5em 1em;border-radius:5px;color:#1e1e2e;font-weight:bold}
h2{margin-top:0}
ul{list-style:none;padding:0}
li{background:#45475a;padding:.7em;margin:.3em 0;border-radius:5px;display:flex;justify-content:space-between}
a{color:#89b4fa;text-decoration:none}
a:hover{text-decoration:underline}
.msg{padding:1em;border-radius:5px;background:#a6e3a1;color:#1e1e2e;margin-bottom:1em}
</style></head>
<body>
<a class="logout" href="/logout">Déconnexion</a>
<h1>📤 Serveur d'Upload</h1>
__MESSAGE__
<div class="box"><h2>Envoyer un fichier</h2>
<form method="POST" action="/upload" enctype="multipart/form-data">
<input type="file" name="file" required>
<button type="submit">Uploader</button>
</form></div>
<div class="box"><h2>📁 Fichiers (__COUNT__)</h2>
<ul>__FILES__</ul></div>
</body></html>"""


class UploadHandler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        print(f"[{self.address_string()}] {format % args}")

    def get_session_token(self):
        cookie = self.headers.get('Cookie', '')
        for part in cookie.split(';'):
            part = part.strip()
            if part.startswith('session='):
                return part[8:]
        return None

    def is_authenticated(self):
        token = self.get_session_token()
        return token in SESSIONS

    def send_html(self, content, status=200, headers=None):
        self.send_response(status)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(content.encode('utf-8'))

    def redirect(self, location, headers=None):
        self.send_response(302)
        self.send_header('Location', location)
        if headers:
            for k, v in headers.items():
                self.send_header(k, v)
        self.end_headers()

    def render_login(self, error=""):
        page = HTML_LOGIN.replace("__ERROR__", error)
        self.send_html(page, status=401 if error else 200)

    def render_upload_page(self, message=""):
        files = sorted(os.listdir(UPLOAD_DIR))
        files_html = ""
        count = 0
        for f in files:
            fpath = os.path.join(UPLOAD_DIR, f)
            if os.path.isfile(fpath):
                count += 1
                size = os.path.getsize(fpath)
                size_str = f"{size/1024:.1f} KB" if size < 1024*1024 else f"{size/(1024*1024):.1f} MB"
                safe_name = html.escape(f)
                files_html += f'<li><a href="/files/{safe_name}">📄 {safe_name}</a><span>{size_str}</span></li>'
        if not files_html:
            files_html = "<li>Aucun fichier</li>"
        msg_html = f'<div class="msg">{html.escape(message)}</div>' if message else ""
        page = (HTML_UPLOAD
                .replace("__MESSAGE__", msg_html)
                .replace("__FILES__", files_html)
                .replace("__COUNT__", str(count)))
        self.send_html(page)

    def do_GET(self):
        if self.path == '/':
            if self.is_authenticated():
                self.render_upload_page()
            else:
                self.render_login()
        elif self.path == '/logout':
            token = self.get_session_token()
            if token:
                SESSIONS.discard(token)
            self.redirect('/', headers={'Set-Cookie': 'session=; Max-Age=0; Path=/'})
        elif self.path.startswith('/files/'):
            if not self.is_authenticated():
                self.redirect('/')
                return
            filename = os.path.basename(unquote_plus(self.path[7:]))
            filepath = os.path.join(UPLOAD_DIR, filename)
            if not os.path.isfile(filepath):
                self.send_error(404)
                return
            try:
                with open(filepath, 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/octet-stream')
                self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
                self.send_header('Content-Length', str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_error(500, str(e))
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == '/login':
            length = int(self.headers.get('Content-Length', 0))
            if length > 1024:
                self.send_error(400)
                return
            body = self.rfile.read(length).decode('utf-8')
            params = {}
            for pair in body.split('&'):
                if '=' in pair:
                    k, v = pair.split('=', 1)
                    params[k] = unquote_plus(v.replace('+', ' '))
            code = params.get('code', '')
            if hashlib.sha256(code.encode()).digest() == hashlib.sha256(ACCESS_CODE.encode()).digest():
                token = secrets.token_urlsafe(32)
                SESSIONS.add(token)
                print(f"[+] Login OK depuis {self.address_string()}")
                self.redirect('/', headers={'Set-Cookie': f'session={token}; HttpOnly; Path=/; SameSite=Strict'})
            else:
                print(f"[!] Login FAIL depuis {self.address_string()}")
                self.render_login('<div class="err">❌ Code incorrect</div>')

        elif self.path == '/upload':
            if not self.is_authenticated():
                self.send_error(403)
                return
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > MAX_FILE_SIZE:
                self.send_error(413, "Fichier trop gros")
                return
            try:
                form = cgi.FieldStorage(
                    fp=self.rfile,
                    headers=self.headers,
                    environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers['Content-Type']}
                )
                if 'file' not in form:
                    self.render_upload_page("⚠️ Aucun fichier")
                    return
                fileitem = form['file']
                if not fileitem.filename:
                    self.render_upload_page("⚠️ Nom de fichier vide")
                    return
                filename = os.path.basename(fileitem.filename)
                filename = ''.join(c for c in filename if c.isalnum() or c in '._- ')
                if not filename:
                    filename = "upload_" + secrets.token_hex(4)
                if ALLOWED_EXTENSIONS:
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in ALLOWED_EXTENSIONS:
                        self.render_upload_page(f"❌ Extension non autorisée: {ext}")
                        return
                filepath = os.path.join(UPLOAD_DIR, filename)
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(filepath):
                    filepath = os.path.join(UPLOAD_DIR, f"{base}_{counter}{ext}")
                    counter += 1
                with open(filepath, 'wb') as f:
                    while True:
                        chunk = fileitem.file.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                print(f"[+] Upload: {os.path.basename(filepath)} depuis {self.address_string()}")
                self.render_upload_page(f"✅ Fichier '{os.path.basename(filepath)}' uploadé !")
            except Exception as e:
                print(f"[!] Erreur upload: {e}")
                self.send_error(500, str(e))
        else:
            self.send_error(404)


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


if __name__ == "__main__":
    print(f"""
╔══════════════════════════════════════════╗
║   🔒 Serveur d'Upload Sécurisé           ║
╠══════════════════════════════════════════╣
║ URL    : http://{HOST}:{PORT}
║ Code   : {ACCESS_CODE}
║ Upload : {os.path.abspath(UPLOAD_DIR)}
╚══════════════════════════════════════════╝
""")
    try:
        with ThreadedServer((HOST, PORT), UploadHandler) as httpd:
            httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Arrêt du serveur")
