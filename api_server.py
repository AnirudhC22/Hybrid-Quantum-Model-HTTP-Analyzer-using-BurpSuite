"""
Flask REST API  —  exposes the detection engine over HTTP.

Endpoints:
  GET  /            — live dashboard (dashboard.html)
  GET  /health      — liveness check
  GET  /log         — recent detections (JSON)
  POST /analyze     — analyze a single request
  POST /analyze_batch — analyze a list of requests
"""

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, send_from_directory
from detection_engine import DetectionEngine
from datetime import datetime

app = Flask(__name__)

_engine = None
_detection_log = []   # in-memory log, last 500 detections


def get_engine():
    global _engine
    if _engine is None:
        use_qml = os.environ.get("USE_QML", "false").lower() == "true"
        try:
            _engine = DetectionEngine(use_qml=use_qml)
            qml_status = "enabled" if use_qml else "disabled"
            print(f"[Engine] Loaded successfully. QML: {qml_status}")
        except FileNotFoundError:
            print("[Engine] Models not found — run train.py first.")
            raise
    return _engine


def _log(req, result):
    entry = {
        "time":         datetime.now().strftime("%H:%M:%S"),
        "method":       req.get("method", "GET"),
        "url":          req.get("url", "")[:120],
        "label":        result.get("label", "unknown"),
        "confidence":   result.get("confidence", 0),
        "is_malicious": result.get("is_malicious", False),
        "stage":        result.get("stage", "-"),
    }
    _detection_log.append(entry)
    if len(_detection_log) > 500:
        _detection_log.pop(0)


@app.route("/")
def index():
    base = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(base, "dashboard.html")


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/log")
def get_log():
    return jsonify({"detections": list(reversed(_detection_log))})


@app.route("/stats")
def stats():
    total   = len(_detection_log)
    attacks = [d for d in _detection_log if d["is_malicious"]]
    counts  = {}
    for d in attacks:
        counts[d["label"]] = counts.get(d["label"], 0) + 1
    return jsonify({
        "total":      total,
        "malicious":  len(attacks),
        "clean":      total - len(attacks),
        "by_type":    counts,
    })


@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    if not data:
        return jsonify({"error": "Empty body"}), 400
    req = {k: data.get(k, "") for k in ("url", "params", "headers", "method")}
    if not req["method"]:
        req["method"] = "GET"
    try:
        result = get_engine().analyze(req)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    _log(req, result)
    return jsonify(result)


@app.route("/analyze_batch", methods=["POST"])
def analyze_batch():
    data = request.get_json(force=True)
    reqs = data.get("requests", [])
    if not reqs:
        return jsonify({"error": "No requests provided"}), 400
    try:
        results = get_engine().analyze_batch(reqs)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    for req, result in zip(reqs, results):
        _log(req, result)
    return jsonify({"results": results})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  Dashboard -> http://127.0.0.1:{port}/")
    print(f"  Health    -> http://127.0.0.1:{port}/health\n")
    app.run(host="0.0.0.0", port=port, debug=False)
