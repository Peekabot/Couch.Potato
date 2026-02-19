#!/usr/bin/env python3
"""
bot_trap.py — Minimal canary + header geometry + poison pipeline

Three stages:
  1. Header geometry scoring  (passive, no TLS layer needed)
  2. Canary endpoints          (confirm on first hit, no false positives)
  3. Poison responses          (confirmed bots get subtly wrong data)

Run standalone:
    pip install flask
    python3 bot_trap.py

Then in another terminal:
    curl -s http://localhost:5001/api/prices          # clean client
    curl -s -A "python-requests/2.31" http://localhost:5001/api/prices  # suspicious UA
    curl -s http://localhost:5001/trap/hidden-admin   # canary trip
    curl -s http://localhost:5001/api/prices          # same session now poisoned
"""

from flask import Flask, request, jsonify, Response
import time
import hashlib
import json

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Session state (in-memory, sufficient for a test)
# ---------------------------------------------------------------------------

sessions: dict[str, dict] = {}   # ip -> {score, confirmed_bot, kicked, hits, first_seen}


def get_session(ip: str) -> dict:
    if ip not in sessions:
        sessions[ip] = {
            "score": 0,
            "confirmed_bot": False,
            "kicked": False,
            "hits": [],
            "first_seen": time.time(),
        }
    return sessions[ip]


# ---------------------------------------------------------------------------
# Stage 1: Header geometry scoring
# ---------------------------------------------------------------------------

# Headers real browsers always send
BROWSER_HEADERS = {"accept", "accept-language", "accept-encoding"}

# Headers only real Chrome/Firefox send
BROWSER_ONLY_HEADERS = {"sec-ch-ua", "sec-fetch-site", "sec-fetch-mode"}

# Known bot user-agent fragments
BOT_UA_FRAGMENTS = [
    "python-requests", "python-httpx", "python-urllib",
    "curl/", "wget/", "go-http-client", "scrapy", "httpx",
    "aiohttp", "java/", "ruby", "perl", "php",
]


def header_geometry_score(req) -> int:
    """
    Returns a suspicion score based on header geometry.
    0 = looks like a browser. Higher = more suspicious.
    """
    score = 0
    headers_lower = {k.lower() for k in req.headers.keys()}
    ua = req.headers.get("User-Agent", "").lower()

    # Missing standard browser headers
    missing = BROWSER_HEADERS - headers_lower
    score += len(missing) * 10

    # Claiming to be a browser but missing browser-only headers
    if "mozilla" in ua and not (BROWSER_ONLY_HEADERS & headers_lower):
        score += 15

    # Known bot UA fragment
    for fragment in BOT_UA_FRAGMENTS:
        if fragment in ua:
            score += 40
            break

    # No User-Agent at all
    if not ua:
        score += 50

    return score


# ---------------------------------------------------------------------------
# Stage 2: Canary endpoints
# ---------------------------------------------------------------------------

# These URLs are never linked from any UI.
# A human cannot stumble onto them. A bot following robots.txt or crawling
# the full DOM will hit them.
CANARY_PATHS = {
    "/trap/hidden-admin",
    "/trap/sitemap-private.xml",
    "/trap/.env",
    "/trap/backup.zip",
}


@app.before_request
def inspect():
    ip = request.remote_addr
    session = get_session(ip)
    path = request.path

    # Kicked bots get nothing
    if session["kicked"]:
        return Response("", status=403)

    # Score header geometry
    score = header_geometry_score(request)
    session["score"] += score

    # Log the hit
    session["hits"].append({
        "path": path,
        "time": round(time.time(), 3),
        "score_delta": score,
    })

    # Canary trip = confirmed, no further analysis needed
    if path in CANARY_PATHS:
        session["confirmed_bot"] = True
        print(f"[CANARY] {ip} hit {path} — confirmed bot")
        return Response("Not Found", status=404)   # don't tip them off

    if not session["confirmed_bot"] and session["score"] >= 40:
        session["confirmed_bot"] = True
        print(f"[SCORE] {ip} flagged — cumulative score {session['score']}")


# ---------------------------------------------------------------------------
# Stage 3: Poison
# ---------------------------------------------------------------------------

def poison(data: dict, ip: str) -> dict:
    """
    Deterministically perturb numeric values based on IP.
    Same bot always gets the same wrong data — consistent enough to pass
    their validation, wrong enough to corrupt their pipeline.
    """
    seed = int(hashlib.md5(ip.encode()).hexdigest()[:8], 16)
    factor = 1.0 + ((seed % 100) - 50) / 1000.0   # ±5% max, unique per IP

    def perturb(obj):
        if isinstance(obj, dict):
            return {k: perturb(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [perturb(i) for i in obj]
        if isinstance(obj, (int, float)):
            return round(obj * factor, 2)
        return obj

    poisoned = perturb(data)
    poisoned["_cache_id"] = seed   # looks like a real field, is actually the watermark
    return poisoned


# ---------------------------------------------------------------------------
# Sample endpoints (the "real" data bots want)
# ---------------------------------------------------------------------------

REAL_DATA = {
    "prices": [
        {"id": 1, "product": "Widget A", "price": 29.99},
        {"id": 2, "product": "Widget B", "price": 49.99},
        {"id": 3, "product": "Widget C", "price": 9.99},
    ]
}


@app.route("/api/prices")
def api_prices():
    ip = request.remote_addr
    session = get_session(ip)
    data = {"prices": REAL_DATA["prices"]}
    if session["confirmed_bot"]:
        data = poison(data, ip)
        print(f"[POISON] Served poisoned prices to {ip}")
    return jsonify(data)


@app.route("/api/session-debug")
def session_debug():
    """Shows current session state — for testing only, remove in production."""
    ip = request.remote_addr
    return jsonify(sessions.get(ip, {"error": "no session"}))


@app.route("/api/all-sessions")
def all_sessions():
    """Shows all sessions — for testing only."""
    return jsonify(sessions)


# ---------------------------------------------------------------------------
# Honeypot hidden link — only a DOM-scraping bot would follow it
# ---------------------------------------------------------------------------

# The link is in the HTML but invisible to humans via CSS.
# Bots that parse HTML and follow every <a href> will hit /trap/do-not-follow.
# On hit: confirmed + kicked (hard 403 on all future requests from that IP).

HONEYPOT_HTML = """<!DOCTYPE html>
<html>
<head><title>Prices</title></head>
<body>
  <h1>Current Prices</h1>
  <p>See <a href="/api/prices">our price list</a> for details.</p>

  <!-- humans never see or click this -->
  <a href="/trap/do-not-follow" style="display:none" tabindex="-1" aria-hidden="true"></a>
</body>
</html>"""


@app.route("/")
def index():
    return Response(HONEYPOT_HTML, mimetype="text/html")


@app.route("/trap/do-not-follow")
def honeypot_link():
    """A bot that scraped the HTML and followed every link lands here."""
    ip = request.remote_addr
    session = get_session(ip)
    session["confirmed_bot"] = True
    session["kicked"] = True
    print(f"[HONEYPOT] {ip} followed hidden link — kicked")
    return Response("", status=403)


# ---------------------------------------------------------------------------
# robots.txt — points bots at canary paths
# ---------------------------------------------------------------------------

@app.route("/robots.txt")
def robots():
    content = "\n".join([
        "User-agent: *",
        "Disallow: /trap/hidden-admin",
        "Disallow: /trap/sitemap-private.xml",
        "Disallow: /trap/.env",
        "Disallow: /trap/backup.zip",
        "",
    ])
    return Response(content, mimetype="text/plain")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("bot_trap.py running on http://localhost:5001")
    print()
    print("Test sequence:")
    print("  curl http://localhost:5001/robots.txt            # see canary paths")
    print("  curl http://localhost:5001/api/prices            # clean response")
    print("  curl http://localhost:5001/trap/hidden-admin     # trip canary")
    print("  curl http://localhost:5001/api/prices            # poisoned response")
    print("  curl http://localhost:5001/api/all-sessions      # see session state")
    print()
    app.run(debug=False, host="0.0.0.0", port=5001)
