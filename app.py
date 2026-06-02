"""RDPGraph — Flask app for visualizing RDP activity from .evtx files."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

from flask import Flask, jsonify, render_template, request, abort
from werkzeug.utils import secure_filename

from evtx_parser import parse_many
from graph_builder import build_graph


BASE = Path(__file__).resolve().parent
UPLOAD_DIR = BASE / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

ALLOWED_EXT = {".evtx"}
MAX_UPLOAD_MB = 256

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024

# In-memory store of parsed sessions keyed by upload-session id.
# Single-user local tool; no need for Redis.
_SESSIONS: dict[str, list[dict]] = {}


def _save_uploads(files) -> list[str]:
    """Persist uploaded files to a per-session directory, return their paths."""
    session_dir = UPLOAD_DIR / uuid.uuid4().hex
    session_dir.mkdir(parents=True, exist_ok=True)
    paths = []
    for f in files:
        if not f or not f.filename:
            continue
        ext = Path(f.filename).suffix.lower()
        if ext not in ALLOWED_EXT:
            continue
        dest = session_dir / secure_filename(f.filename)
        f.save(dest)
        paths.append(str(dest))
    return paths


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/upload", methods=["POST"])
def upload():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "no files provided"}), 400

    paths = _save_uploads(files)
    if not paths:
        return jsonify({"error": "no valid .evtx files"}), 400

    try:
        events = parse_many(paths)
    except Exception as exc:
        return jsonify({"error": f"parse failed: {exc}"}), 500

    session_id = uuid.uuid4().hex
    _SESSIONS[session_id] = events
    graph = build_graph(events)

    return jsonify({
        "session_id": session_id,
        "files": [os.path.basename(p) for p in paths],
        "graph": graph,
    })


@app.route("/api/graph/<session_id>")
def api_graph(session_id):
    events = _SESSIONS.get(session_id)
    if events is None:
        abort(404)

    # Optional filters via querystring
    user = request.args.get("user", "").strip().lower()
    host = request.args.get("host", "").strip().lower()
    status = request.args.get("status", "").strip().lower()

    def keep(ev: dict) -> bool:
        if user and user not in ev.get("user", "").lower():
            return False
        if host:
            haystack = " ".join([
                ev.get("computer", ""),
                ev.get("source_host", ""),
                ev.get("source_ip", ""),
            ]).lower()
            if host not in haystack:
                return False
        if status and ev.get("status") != status:
            return False
        return True

    filtered = [e for e in events if keep(e)]
    return jsonify(build_graph(filtered))


@app.route("/api/debug/<session_id>")
def api_debug(session_id):
    """Quick diagnostic — first 30 parsed events + stats on field presence."""
    events = _SESSIONS.get(session_id)
    if events is None:
        abort(404)

    presence = {
        "with_source_ip": sum(1 for e in events if e.get("source_ip")),
        "with_source_host": sum(1 for e in events if e.get("source_host")),
        "with_user": sum(1 for e in events if e.get("user")),
        "total": len(events),
    }
    return jsonify({
        "presence": presence,
        "sample_events": [
            {k: v for k, v in e.items() if k != "raw_xml"} for e in events[:30]
        ],
    })


@app.route("/api/events/<session_id>")
def api_events(session_id):
    events = _SESSIONS.get(session_id)
    if events is None:
        abort(404)

    node = request.args.get("node", "").strip().lower()
    if not node:
        return jsonify(events[:500])

    def touches(ev: dict) -> bool:
        target = (ev.get("computer", "") or "").lower()
        source_host = (ev.get("source_host", "") or "").lower()
        source_ip = (ev.get("source_ip", "") or "").lower()
        return node in target or node in source_host or node in source_ip

    return jsonify([e for e in events if touches(e)][:500])


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
