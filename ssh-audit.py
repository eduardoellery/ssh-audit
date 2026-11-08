#!/usr/bin/python3
import datetime as dt
import json
import os
import pathlib
import selectors
import subprocess
import sys
import uuid

ROOT = pathlib.Path.home() / "ssh-audit"
ROOT.mkdir(mode=0o700, exist_ok=True)
os.chmod(ROOT, 0o700)
sid = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
meta = ROOT / (sid + ".json")
command = os.environ.get("SSH_ORIGINAL_COMMAND")
kind = "command" if command else "interactive"

def save(status=None):
    tmp = meta.with_suffix(".tmp")
    tmp.write_text(json.dumps({"id": sid, "kind": kind, "command": command,
        "started_utc": started, "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat() if status is not None else None,
        "exit_code": status}, ensure_ascii=False))
    os.chmod(tmp, 0o600)
    tmp.replace(meta)

started = dt.datetime.now(dt.timezone.utc).isoformat()
save()
if command and command.startswith("/usr/lib/openssh/sftp-server"):
    os.execv("/usr/lib/openssh/sftp-server", ["sftp-server"])

if command:
    out = ROOT / (sid + ".stdout")
    err = ROOT / (sid + ".stderr")
    with out.open("wb") as fo, err.open("wb") as fe:
        os.chmod(out, 0o600); os.chmod(err, 0o600)
        child = subprocess.Popen([os.environ.get("SHELL", "/bin/sh"), "-c", command],
            stdin=sys.stdin.buffer, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sel = selectors.DefaultSelector()
        sel.register(child.stdout, selectors.EVENT_READ, (fo, sys.stdout.buffer))
        sel.register(child.stderr, selectors.EVENT_READ, (fe, sys.stderr.buffer))
        while sel.get_map():
            for key, _ in sel.select():
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    sel.unregister(key.fileobj)
                    continue
                log, live = key.data
                log.write(chunk); log.flush()
                live.write(chunk); live.flush()
        status = child.wait()
else:
    output = ROOT / (sid + ".terminal")
    timing = ROOT / (sid + ".timing")
    status = subprocess.call(["/usr/bin/script", "-qef", "-O", str(output),
        "-T", str(timing), "--", os.environ.get("SHELL", "/bin/sh"), "-l"])
    for path in (output, timing):
        if path.exists(): os.chmod(path, 0o600)
save(status)
sys.exit(status)
