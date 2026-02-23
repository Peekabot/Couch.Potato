"""
Flask API Server - iSH Backend
Receives leads from Pythonista and exposes a simple REST API.

Run in iSH:
    pip3 install flask
    python3 flask_api.py
"""

from flask import Flask, request, jsonify
import sqlite3
import datetime
import json
import os

app = Flask(__name__)

DB_PATH = os.path.join(os.path.dirname(__file__), "leads.db")


def get_db():
    """Open a database connection for the current request."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS leads (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            data      TEXT    NOT NULL,
            source    TEXT    NOT NULL DEFAULT 'unknown',
            timestamp TEXT    NOT NULL
        )
        """
    )
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/api/lead", methods=["POST"])
def add_lead():
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("text", "").strip()
    source = payload.get("source", "unknown")

    if not text:
        return jsonify({"error": "text is required"}), 400

    conn = get_db()
    cur = conn.execute(
        "INSERT INTO leads (data, source, timestamp) VALUES (?, ?, ?)",
        (json.dumps({"text": text}), source, datetime.datetime.utcnow().isoformat()),
    )
    conn.commit()
    new_id = cur.lastrowid
    conn.close()

    return jsonify({"status": "success", "id": new_id}), 200


@app.route("/api/leads", methods=["GET"])
def get_leads():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM leads ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()

    leads = [
        {
            "id": row["id"],
            "data": json.loads(row["data"]),
            "source": row["source"],
            "timestamp": row["timestamp"],
        }
        for row in rows
    ]
    return jsonify(leads)


@app.route("/api/lead/<int:lead_id>", methods=["DELETE"])
def delete_lead(lead_id):
    conn = get_db()
    conn.execute("DELETE FROM leads WHERE id = ?", (lead_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": lead_id})


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("Server running on http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
