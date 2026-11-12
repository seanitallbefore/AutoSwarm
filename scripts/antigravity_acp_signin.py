"""One-time Google sign-in for Google Antigravity's ACP server.

Optional: with `providers.antigravity.auth_method` set, AutoSwarm calls ACP
`authenticate` itself when the server refuses `session/new` for want of a credential.
Use this to sign in ahead of time instead. It runs `initialize` and `authenticate`
over stdio once; the server opens the browser for the sign-in and stores its own
credential. Prints only the advertised method names and the outcome. Run one sign-in
at a time: a failed or abandoned `authenticate` can make the server clear its credential.

Usage: python3 scripts/antigravity_acp_signin.py /path/to/agy_acp_server.par [method-id]
"""
import json
import subprocess
import sys
import threading

server = sys.argv[1]
wanted = sys.argv[2] if len(sys.argv) > 2 else "oauth-personal"
process = subprocess.Popen([server], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
replies = {}
ready = threading.Condition()


def read():
    for line in process.stdout:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, dict) and "id" in event and "method" not in event:
            with ready:
                replies[event["id"]] = event
                ready.notify_all()


def call(request_id, method, params, timeout):
    process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n")
    process.stdin.flush()
    with ready:
        if not ready.wait_for(lambda: request_id in replies, timeout):
            sys.exit(f"{method}: no reply after {timeout}s")
    return replies[request_id]


threading.Thread(target=read, daemon=True).start()
try:
    init = call(1, "initialize", {"protocolVersion": 1, "clientInfo": {"name": "autoswarm-signin", "version": "1"},
                                  "clientCapabilities": {"fs": {"readTextFile": False, "writeTextFile": False}, "terminal": False}}, 60)
    if "error" in init:
        sys.exit("initialize failed: " + json.dumps(init["error"]))
    result = init["result"]
    methods = result.get("authMethods", [])
    print("protocolVersion:", result.get("protocolVersion"))
    print("auth methods:", ", ".join(f"{m.get('id')} ({m.get('name')})" for m in methods) or "none")
    if wanted not in {m.get("id") for m in methods}:
        sys.exit(f"method {wanted!r} not offered; rerun with one of the ids above")
    print(f"authenticating with {wanted}; finish the sign-in in your browser...")
    auth = call(2, "authenticate", {"methodId": wanted}, 600)
    if "error" in auth:
        sys.exit("authenticate failed: " + json.dumps(auth["error"]))
    print("authenticated")
finally:
    process.terminate()
