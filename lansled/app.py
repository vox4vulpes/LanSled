"""LanSled's web UI: one page, one streaming endpoint."""
import json

from flask import Flask, Response, request, send_from_directory

from . import scan
from .paths import static_dir

STATIC_DIR = static_dir()

app = Flask(__name__, static_folder=None)


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/<path:filename>")
def static_files(filename):
    # oui.json, app.js, style.css -- everything else is a 404, there's nothing else here
    return send_from_directory(STATIC_DIR, filename)


@app.route("/api/scan")
def api_scan():
    subnet = request.args.get("subnet", "")
    ports = request.args.get("ports", "")
    want_ports = request.args.get("ports_on", "1") != "0"
    want_hostnames = request.args.get("hostnames_on", "1") != "0"

    def stream():
        for event in scan.scan_network(subnet, ports, want_ports, want_hostnames):
            yield f"data: {json.dumps(event)}\n\n"

    return Response(stream(), mimetype="text/event-stream",
                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def main():
    import argparse
    import threading
    import webbrowser

    p = argparse.ArgumentParser(prog="lansled", description="Find devices on a network you specify.")
    p.add_argument("--host", default="127.0.0.1", help="interface to bind the web UI to (default: 127.0.0.1, this machine only)")
    p.add_argument("--port", type=int, default=5151, help="port for the web UI (default: 5151)")
    p.add_argument("--no-browser", action="store_true", help="don't open a browser tab automatically")
    args = p.parse_args()

    url = f"http://{args.host if args.host != '0.0.0.0' else 'localhost'}:{args.port}"
    print(f"LanSled is up: {url}")
    print("ARP scanning needs this to run as root/admin to open a raw socket; without it, LanSled falls back to a ping sweep.")
    if not args.no_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host=args.host, port=args.port, threaded=True)


if __name__ == "__main__":
    main()
