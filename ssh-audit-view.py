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
import datetime as dt
from zoneinfo import ZoneInfo

ROOT = pathlib.Path.home() / "ssh-audit"
ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
ORPHAN_CSI = re.compile(r"\[(?:\d{1,3}(?:;\d{1,3})*)?[ABCDGHJKfsum](?![A-Za-z0-9])")
SIZES = (50, 100, 500, 1000)
TIMEZONE = ZoneInfo(os.environ.get("SSH_AUDIT_TZ", "America/Fortaleza"))

def local_start(row):
    try: return dt.datetime.fromisoformat(row["started_utc"]).astimezone(TIMEZONE)
    except (KeyError, TypeError, ValueError): return None

def parse_day(value):
    if not value: return None
    return dt.date.fromisoformat(value)

class TerminalRenderer:
    def __init__(self):
        self.lines = [[]]
        self.row = self.col = 0
        self.state = "text"
        self.csi = ""

    def feed(self, text):
        for char in text:
            if self.state == "escape":
                if char == "[": self.state, self.csi = "csi", ""
                elif char == "]": self.state = "osc"
                else: self.state = "text"
                continue
            if self.state == "csi":
                if "@" <= char <= "~":
                    self.control(char)
                    self.state = "text"
                else: self.csi += char
                continue
            if self.state == "osc":
                if char == "\x07": self.state = "text"
                elif char == "\x1b": self.state = "osc_escape"
                continue
            if self.state == "osc_escape":
                self.state = "text" if char == "\\" else "osc"
                continue
            if char == "\x1b": self.state = "escape"
            elif char == "\r": self.col = 0
            elif char == "\n": self.row += 1; self.col = 0
            elif char == "\b": self.col = max(0, self.col - 1)
            elif char == "\t": self.col = (self.col // 8 + 1) * 8
            elif ord(char) >= 32 and ord(char) != 127 and char != "\ufffd":
                self.ensure_row()
                line = self.lines[self.row]
                if self.col >= len(line): line.extend(" " * (self.col - len(line) + 1))
                line[self.col] = char
                self.col += 1

    def ensure_row(self):
        while self.row >= len(self.lines): self.lines.append([])

    def control(self, code):
        args = self.csi.lstrip("?").split(";")
        try: n = int(args[0]) if args[0] else 1
        except ValueError: n = 1
        if code == "D": self.col = max(0, self.col - n)
        elif code == "C": self.col += n
        elif code == "G": self.col = max(0, n - 1)
        elif code == "A": self.row = max(0, self.row - n)
        elif code == "B": self.row += n
        elif code in "Hf":
            self.row = max(0, n - 1)
            try: self.col = max(0, int(args[1]) - 1)
            except (IndexError, ValueError): self.col = 0
        elif code in "KJ":
            self.ensure_row()
            self.lines[self.row] = self.lines[self.row][:self.col]
            if code == "J": self.lines = self.lines[:self.row + 1]

    def render(self):
        lines = ["".join(line).rstrip() for line in self.lines]
        while lines and not lines[-1]: lines.pop()
        return ORPHAN_CSI.sub("", "\n".join(lines)).replace("\ufffd", "")

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
        mode = params.get("mode", ["all"])[0]
        if mode not in ("all", "day", "range"): mode = "all"
        day_text = params.get("day", [""])[0]
        from_text = params.get("from", [""])[0]
        to_text = params.get("to", [""])[0]
        try: day, date_from, date_to = map(parse_day, (day_text, from_text, to_text))
        except ValueError: self.send_error(400, "Data inválida"); return
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
            renderer = TerminalRenderer()
            events = []
            previous = ""
            with output.open("rb") as stream:
                for line in timing.read_text().splitlines():
                    try: delay, count = line.split(); delay = float(delay); count = int(count)
                    except ValueError: continue
                    renderer.feed(decoder.decode(stream.read(count)))
                    current = renderer.render()
                    keep = 0
                    while keep < min(len(previous), len(current)) and previous[keep] == current[keep]: keep += 1
                    events.append([delay, keep, current[keep:]])
                    previous = current
                renderer.feed(decoder.decode(stream.read(), final=True))
                current = renderer.render()
                if current != previous:
                    keep = 0
                    while keep < min(len(previous), len(current)) and previous[keep] == current[keep]: keep += 1
                    events.append([0, keep, current[keep:]])
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
        if mode == "day" and day:
            rows = [row for row in rows if (started := local_start(row)) and started.date() == day]
        elif mode == "range":
            rows = [row for row in rows if (started := local_start(row)) and (not date_from or started.date() >= date_from) and (not date_to or started.date() <= date_to)]
        filters = dict(q=query, n=size, mode=mode, day=day_text, **{"from": from_text, "to": to_text})
        total = len(rows)
        pages = max(1, (total + size - 1) // size)
        page = min(page, pages)
        body = ["<meta charset=utf-8><title>SSH audit</title><style>body{font:16px sans-serif;max-width:1000px;margin:2em auto;background:#111;color:#eee}a{color:#8cf}pre{white-space:pre-wrap;background:#222;padding:1em;overflow:auto}small{color:#aaa}input,select,button{font:inherit;padding:.4em}nav a{margin-right:1em}li{margin:.35em 0}</style><h1>SSH audit</h1>"]
        if sid:
            row = next((r for r in rows if r.get("id") == sid), None)
            if row is None: self.send_error(404); return
            index = rows.index(row)
            back = url(**filters, page=page)
            nav = ["<nav><a href='" + html.escape(back, quote=True) + "'>← Voltar aos resultados</a>"]
            if index > 0: nav.append("<a href='" + html.escape(url(id=rows[index-1]["id"], **filters, page=page), quote=True) + "'>← Anterior</a>")
            if index + 1 < total: nav.append("<a href='" + html.escape(url(id=rows[index+1]["id"], **filters, page=page), quote=True) + "'>Próximo →</a>")
            nav.append("</nav>")
            body += nav + ["<h2>" + html.escape(sid) + "</h2>"]
            started = local_start(row)
            body.append("<p>Tipo: %s · Início (%s): %s · Código: %s</p>" % (html.escape(str(row.get("kind"))), html.escape(str(TIMEZONE)), html.escape(started.strftime("%Y-%m-%d %H:%M:%S") if started else str(row.get("started_utc"))), html.escape(str(row.get("exit_code")))))
            if row.get("command"): body.append("<h3>Comando</h3><pre>" + html.escape(row["command"]) + "</pre>")
            for ext in (["stdout", "stderr"] if row.get("kind") == "command" else ["terminal"]):
                path = ROOT / (sid + "." + ext)
                content = path.read_bytes().decode("utf-8", "replace") if path.exists() else ""
                if ext == "terminal":
                    renderer = TerminalRenderer()
                    renderer.feed(content)
                    shown = renderer.render()
                else: shown = content
                body.append("<h3>" + ext + "</h3><pre>" + html.escape(shown) + "</pre>")
            if row.get("kind") == "interactive":
                body.append("<button id='play'>Reproduzir</button><small> Reprodução da saída registrada.</small>")
                body.append("""<script>document.querySelector('#play').onclick=async()=>{const events=await(await fetch('?id=""" + sid + """&replay=1')).json();const screen=document.querySelector('pre:last-of-type');screen.textContent='';let shown='';for(const [delay,keep,tail] of events){await new Promise(r=>setTimeout(r,Math.min(delay*1000,2000)));shown=shown.slice(0,keep)+tail;screen.textContent=shown}}</script>""")
            body += nav
        else:
            body.append("<form method='get'><input name='q' type='search' placeholder='Buscar sessões e saídas' value='" + html.escape(query, quote=True) + "'> <select name='n'>")
            body += ["<option value='%d'%s>%d entradas</option>" % (n, " selected" if n == size else "", n) for n in SIZES]
            body.append("</select> <label>Período <select name='mode' id='mode'>")
            body += ["<option value='%s'%s>%s</option>" % (value, " selected" if mode == value else "", label) for value, label in (("all", "Todos os dias"), ("day", "Dia específico"), ("range", "Intervalo"))]
            body.append("</select></label> <label>Dia <input type='date' name='day' value='" + html.escape(day_text, quote=True) + "'></label> <label>De <input type='date' name='from' value='" + html.escape(from_text, quote=True) + "'></label> <label>Até <input type='date' name='to' value='" + html.escape(to_text, quote=True) + "'></label> <button>Filtrar</button></form>")
            body.append("<script>for(const name of ['day','from','to'])document.querySelector(`[name=${name}]`).addEventListener('change',()=>{document.querySelector('#mode').value=name==='day'?'day':'range'})</script>")
            body.append("<p>Datas no fuso " + html.escape(str(TIMEZONE)) + ".</p>")
            body.append("<p>%d resultado(s) · página %d de %d</p>" % (total, page, pages))
            body.append("<ul>")
            for row in rows[(page-1)*size:page*size]:
                link = url(id=row["id"], **filters, page=page)
                body.append("<li><a href='%s'>%s</a> · %s · código %s</li>" % (html.escape(link, quote=True), html.escape(row["id"]), html.escape(str(row.get("kind"))), html.escape(str(row.get("exit_code")))))
            body.append("</ul><nav>")
            if page > 1: body.append("<a href='" + html.escape(url(**filters, page=page-1), quote=True) + "'>← Página anterior</a>")
            if page < pages: body.append("<a href='" + html.escape(url(**filters, page=page+1), quote=True) + "'>Próxima página →</a>")
            body.append("</nav>")
        data = "\n".join(body).encode()
        self.send_response(200); self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

server = http.server.HTTPServer((os.environ.get("SSH_AUDIT_BIND", "127.0.0.1"), 8765), Handler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(str(ROOT / ".viewer-cert.pem"), str(ROOT / ".viewer-key.pem"))
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
