"""Live color editor for an ELK-BLEDOB light.

Run:   python app.py
Open:  http://127.0.0.1:5000

Env vars:
  ELK_MAC   Bluetooth address of the light (default below)
  DRY_RUN   set to 1 to run the UI without a light attached
  HOST/PORT where to serve (use HOST=0.0.0.0 to control it from your phone)
"""
import os
import re
import threading
import time

from flask import Flask, jsonify, request, send_from_directory

BASE = os.path.dirname(os.path.abspath(__file__))
COLORS_FILE = os.path.join(BASE, "colors.txt")
MAC = os.environ.get("ELK_MAC", "BE:27:A2:00:0C:00")
DRY_RUN = os.environ.get("DRY_RUN") == "1"

HEX_RE = re.compile(r"^#[0-9a-fA-F]{6}$")
DEFAULT_COLORS = ["#ff0000", "#00ff00", "#0000ff"]

app = Flask(__name__)
lock = threading.RLock()


# ---------- colors.txt <-> hex list ----------

def rgb_to_hex(r, g, b):
    return f"#{r:02x}{g:02x}{b:02x}"


def parse_colors(text):
    """Accepts lines like '255,0,128', '255 0 128' or '#ff0080'. Bad lines are skipped."""
    colors = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if HEX_RE.match(line):
            colors.append(line.lower())
            continue
        parts = line.replace(",", " ").split()
        if len(parts) != 3:
            continue
        try:
            r, g, b = (max(0, min(255, int(p))) for p in parts)
        except ValueError:
            continue
        colors.append(rgb_to_hex(r, g, b))
    return colors


def load_colors():
    try:
        with open(COLORS_FILE) as f:
            return parse_colors(f.read()) or list(DEFAULT_COLORS)
    except FileNotFoundError:
        return list(DEFAULT_COLORS)


def save_colors(colors):
    lines = []
    for c in colors:
        lines.append(f"{int(c[1:3], 16)},{int(c[3:5], 16)},{int(c[5:7], 16)}")
    with open(COLORS_FILE, "w") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))


# ---------- shared state ----------

state = {
    "colors": load_colors(),
    "delay_ms": 50,
    "running": True,
    "next": 0,          # index the worker will send next
    "playing": 0,       # index most recently sent
    "current": "#000000",
    "preview_color": None,
    "preview_until": 0.0,
    "error": None,
    "version": 0,       # bumps whenever the color list changes
}


# ---------- worker: the only thread that talks to the light ----------

def worker():
    SyncELKLight = None
    if not DRY_RUN:
        from elkbledob import SyncELKLight  # imported here so DRY_RUN works without it

    light = None
    last_sent = None
    last_attempt = 0.0

    while True:
        # (Re)connect if needed
        if not DRY_RUN and light is None and time.time() - last_attempt >= 5:
            last_attempt = time.time()
            try:
                light = SyncELKLight(MAC)
                with lock:
                    state["error"] = None
            except Exception as e:
                with lock:
                    state["error"] = f"Can't reach the light: {e}"

        # Decide what to show
        with lock:
            now = time.monotonic()
            colors = state["colors"]
            if state["preview_color"] and now < state["preview_until"]:
                color, wait = state["preview_color"], 0.05
            elif state["running"] and colors:
                idx = state["next"] % len(colors)
                color = colors[idx]
                state["playing"] = idx
                state["next"] = idx + 1
                wait = state["delay_ms"] / 1000
            else:
                color, wait = None, 0.05
            if color:
                state["current"] = color

        # Send it (skip if it's identical to what the light already shows)
        if color and color != last_sent:
            if DRY_RUN:
                last_sent = color
            elif light is not None:
                try:
                    light.set_color(color)
                    last_sent = color
                except Exception as e:
                    with lock:
                        state["error"] = f"Lost the light: {e}"
                    try:
                        light.close()
                    except Exception:
                        pass
                    light = None
                    last_sent = None

        time.sleep(wait)


# ---------- routes ----------

def snapshot():
    with lock:
        return {
            "colors": list(state["colors"]),
            "delay_ms": state["delay_ms"],
            "running": state["running"],
            "playing": state["playing"],
            "current": state["current"],
            "error": state["error"],
            "version": state["version"],
            "dry_run": DRY_RUN,
            "mac": MAC,
        }


@app.get("/")
def index():
    return send_from_directory(BASE, "index.html")


@app.get("/api/state")
def api_state():
    return jsonify(snapshot())


@app.put("/api/colors")
def api_colors():
    data = request.get_json(silent=True) or {}
    if "text" in data:
        colors = parse_colors(str(data["text"]))
    else:
        colors = data.get("colors")
        if not isinstance(colors, list) or not all(
            isinstance(c, str) and HEX_RE.match(c) for c in colors
        ):
            return jsonify(error="colors must be a list of #rrggbb strings"), 400
        colors = [c.lower() for c in colors]
    with lock:
        state["colors"] = colors
        state["version"] += 1
        if colors:
            state["next"] %= len(colors)
        save_colors(colors)
    return jsonify(snapshot())


@app.post("/api/settings")
def api_settings():
    data = request.get_json(silent=True) or {}
    with lock:
        if "delay_ms" in data:
            try:
                state["delay_ms"] = max(5, min(2000, int(data["delay_ms"])))
            except (TypeError, ValueError):
                return jsonify(error="delay_ms must be a number"), 400
        if "running" in data:
            state["running"] = bool(data["running"])
    return jsonify(snapshot())


@app.post("/api/preview")
def api_preview():
    """Show one color right now and hold the cycle for a moment."""
    data = request.get_json(silent=True) or {}
    color = str(data.get("color", ""))
    if not HEX_RE.match(color):
        return jsonify(error="color must be #rrggbb"), 400
    with lock:
        state["preview_color"] = color.lower()
        state["preview_until"] = time.monotonic() + 1.5
    return jsonify(ok=True)


if __name__ == "__main__":
    threading.Thread(target=worker, daemon=True).start()
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", 5000)),
        debug=False,  # the reloader would start a second Bluetooth connection
        threaded=True,
    )
