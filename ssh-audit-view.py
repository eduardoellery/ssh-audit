#!/usr/bin/python3
import html
import http.server
import json
import pathlib
import re
import urllib.parse
import codecs
import base64
import hmac
import ssl
import os

ROOT = pathlib.Path.home() / "ssh-audit"
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
SIZES = (50, 100, 500, 1000)

def url(**params):
    return "/?" + urllib.parse.urlencode(params)

def searchable(row):
    sid = row.get("id", "")
    parts = [str(row.get(k, "")) for k in ("id", "kind", "command", "started_utc", "exit_code")]
    for ext in ("stdout", "stderr", "terminal"):
        path = ROOT / (sid + "." + ext)
        if path.is_file():
            try: parts.append(path.read_bytes().decode("utf-8", "replace"))
            except OSError: pass
    return "\n".join(parts).casefold()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        expected = (ROOT / ".viewer-password").read_text().strip()
        header = self.headers.get("Authorization", "")
        try:
            supplied = base64.b64decode(header.removeprefix("Basic "), validate=True).decode().split(":", 1)
        except (ValueError, UnicodeError):
            supplied = []
        if not (header.startswith("Basic ") and len(supplied) == 2 and supplied[0] == os.environ.get("SSH_AUDIT_USER", "kali") and hmac.compare_digest(supplied[1], expected)):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="SSH audit"')
            self.end_headers()
            return
        params = urllib.parse.parse_qs(urllib.parse.urlsplit(self.path).query)
        sid = params.get("id", [""])[0]
        query = params.get("q", [""])[0].strip()[:200]
        try: size = int(params.get("n", ["50"])[0])
        except ValueError: size = 50
        if size not in SIZES: size = 50
        try: page = max(1, int(params.get("page", ["1"])[0]))
        except ValueError: page = 1
        if sid and not re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}", sid):
            self.send_error(400); return
        if params.get("replay") == ["1"]:
            output = ROOT / (sid + ".terminal")
            timing = ROOT / (sid + ".timing")
            if not sid or not output.is_file() or not timing.is_file():
                self.send_error(404); return
            decoder = codecs.getincrementaldecoder("utf-8")("replace")
            events = []
            with output.open("rb") as stream:
                for line in timing.read_text().splitlines():
                    try: delay, count = line.split(); delay = float(delay); count = int(count)
                    except ValueError: continue
                    events.append([delay, decoder.decode(stream.read(count))])
            data = json.dumps(events).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)
            return
        rows = []
        for path in sorted(ROOT.glob("*.json"), reverse=True):
            try:
                row = json.loads(path.read_text())
                if re.fullmatch(r"[0-9]{8}T[0-9]{6}Z-[a-f0-9]{8}", str(row.get("id", ""))): rows.append(row)
            except (OSError, ValueError): pass
        terms = query.casefold().split()
        if terms: rows = [row for row in rows if (lambda text: all(term in text for term in terms))(searchable(row))]
        total = len(rows)
        pages = max(1, (total + size - 1) // size)
        page = min(page, pages)
        body = ["<meta charset=utf-8><title>SSH audit</title><style>body{font:16px sans-serif;max-width:1000px;margin:2em auto;background:#111;color:#eee}a{color:#8cf}pre{white-space:pre-wrap;background:#222;padding:1em;overflow:auto}small{color:#aaa}input,select,button{font:inherit;padding:.4em}nav a{margin-right:1em}li{margin:.35em 0}</style><h1>SSH audit</h1>"]
        if sid:
            row = next((r for r in rows if r.get("id") == sid), None)
            if row is None: self.send_error(404); return
            index = rows.index(row)
            back = url(q=query, n=size, page=page)
            nav = ["<nav><a href='" + html.escape(back, quote=True) + "'>← Voltar aos resultados</a>"]
            if index > 0: nav.append("<a href='" + html.escape(url(id=rows[index-1]["id"], q=query, n=size, page=page), quote=True) + "'>← Anterior</a>")
            if index + 1 < total: nav.append("<a href='" + html.escape(url(id=rows[index+1]["id"], q=query, n=size, page=page), quote=True) + "'>Próximo →</a>")
            nav.append("</nav>")
            body += nav + ["<h2>" + html.escape(sid) + "</h2>"]
            body.append("<p>Tipo: %s · Início UTC: %s · Código: %s</p>" % tuple(html.escape(str(row.get(k))) for k in ("kind", "started_utc", "exit_code")))
            if row.get("command"): body.append("<h3>Comando</h3><pre>" + html.escape(row["command"]) + "</pre>")
            for ext in (["stdout", "stderr"] if row.get("kind") == "command" else ["terminal"]):
                path = ROOT / (sid + "." + ext)
                content = path.read_bytes().decode("utf-8", "replace") if path.exists() else ""
                body.append("<h3>" + ext + "</h3><pre>" + html.escape(ANSI.sub("", content)) + "</pre>")
            if row.get("kind") == "interactive":
                body.append("<button id='play'>Reproduzir</button><small> Reprodução da saída registrada.</small>")
                body.append("""<script>document.querySelector('#play').onclick=async()=>{const events=await(await fetch('?id=""" + sid + """&replay=1')).json();const screen=document.querySelector('pre:last-of-type');screen.textContent='';for(const [delay,chunk] of events){await new Promise(r=>setTimeout(r,Math.min(delay*1000,2000)));screen.textContent+=chunk.replace(/\\x1b\\[[0-?]*[ -/]*[@-~]/g,'');}}</script>""")
            body += nav
        else:
            body.append("<form method='get'><input name='q' type='search' placeholder='Buscar sessões e saídas' value='" + html.escape(query, quote=True) + "'> <select name='n'>")
            body += ["<option value='%d'%s>%d entradas</option>" % (n, " selected" if n == size else "", n) for n in SIZES]
            body.append("</select> <button>Buscar</button></form>")
            body.append("<p>%d resultado(s) · página %d de %d</p>" % (total, page, pages))
            body.append("<ul>")
            for row in rows[(page-1)*size:page*size]:
                link = url(id=row["id"], q=query, n=size, page=page)
                body.append("<li><a href='%s'>%s</a> · %s · código %s</li>" % (html.escape(link, quote=True), html.escape(row["id"]), html.escape(str(row.get("kind"))), html.escape(str(row.get("exit_code")))))
            body.append("</ul><nav>")
            if page > 1: body.append("<a href='" + html.escape(url(q=query, n=size, page=page-1), quote=True) + "'>← Página anterior</a>")
            if page < pages: body.append("<a href='" + html.escape(url(q=query, n=size, page=page+1), quote=True) + "'>Próxima página →</a>")
            body.append("</nav>")
        data = "\n".join(body).encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

server = http.server.HTTPServer((os.environ.get("SSH_AUDIT_BIND", "127.0.0.1"), 8765), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(ROOT / ".viewer-cert.pem"), str(ROOT / ".viewer-key.pem"))
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
