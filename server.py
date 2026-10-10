#!/usr/bin/env python3
"""
Mist: voice control for ELK-BLEDOB lights.

  * This program (on the computer near your lights) does the Bluetooth.
  * The page in your browser does the listening. In Chrome that uses Google's
    speech recognition and the microphone of whatever device the page is open on
    (your phone, laptop, tablet).
  * Optional: --server-mic makes this computer listen too (offline, via Vosk).

Install:
    pip install aiohttp bleak cryptography
    (only for --server-mic:  pip install vosk sounddevice)

Run on this computer only:
    python server.py
Run so your phone / another device can use it:
    python server.py --host 0.0.0.0
    then open the https://<this-computer's-IP>:8765 address it prints, in Chrome.
    Chrome will warn about the certificate (it's your own, self-signed): tap
    Advanced, then Proceed. That's needed because Chrome only allows microphones on
    secure pages.

Other options:
    --address XX:XX:XX:XX:XX:XX   skip scanning for the lights
    --http                        force plain http (mic only works on localhost then)
    --new-cert                    regenerate the certificate (e.g. after your IP changed)
    --server-mic [--mic N] [--model PATH] [--debug] [--free-vocab]
"""

import argparse
import asyncio
import datetime
import ipaddress
import json
import pathlib
import random
import re
import socket
import ssl
import time
import webbrowser

from aiohttp import web, WSMsgType
from bleak import BleakClient, BleakScanner

HERE = pathlib.Path(__file__).parent
DEVICE_NAME_PREFIX = "ELK-BLEDOB"
PREFERRED_WRITE_UUID = "0000fff3-0000-1000-8000-00805f9b34fb"

COLORS = {
    "red": (255, 0, 0), "green": (0, 255, 0), "blue": (0, 0, 255), "white": (255, 255, 255),
    "yellow": (255, 255, 0), "cyan": (0, 255, 255), "aqua": (0, 255, 255), "magenta": (255, 0, 255),
    "orange": (255, 100, 0), "purple": (128, 0, 255), "pink": (255, 60, 150), "warm": (255, 147, 41),
    "warm white": (255, 147, 41), "cool white": (200, 225, 255), "teal": (0, 200, 150),
    "lime": (140, 255, 0), "violet": (160, 60, 255), "gold": (255, 170, 0), "turquoise": (0, 255, 200),
    "lavender": (180, 140, 255), "light blue": (80, 170, 255), "sky blue": (80, 170, 255),
    "read": (255, 0, 0),  # "red" is often heard as "read"
}


# ---------------------------------------------------------------- packets
def pkt_on():  return bytes.fromhex("7e0704ff00010201ef")
def pkt_off(): return bytes.fromhex("7e07040000000201ef")
def pkt_color(r, g, b): return bytes([0x7E, 0x07, 0x05, 0x03, r, g, b, 0x10, 0xEF])
def pkt_brightness(p): return bytes([0x7E, 0x04, 0x01, p, 0x01, 0xFF, 0x02, 0x01, 0xEF])
def pkt_effect(m): return bytes([0x7E, 0x07, 0x03, m, 0x03, 0xFF, 0xFF, 0x00, 0xEF])
def pkt_speed(s): return bytes([0x7E, 0x07, 0x02, s, 0xFF, 0xFF, 0xFF, 0x00, 0xEF])
def pkt_time():
    n = datetime.datetime.now()
    return bytes([0x7E, 0x06, 0x83, n.hour, n.minute, n.second, n.isoweekday(), 0x00, 0xEF])


# ---------------------------------------------------------------- language
U = {"zero": 0, "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8,
     "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
     "sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19}
T = {"twenty": 20, "thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90}
UK, TK = "|".join(U), "|".join(T)

WAKE = re.compile(
    r"\b(?:(?:hey|hay|hi|ok|okay|a|hate|hey a)\s+(?:orb|misty|missed|miss|mists|mitt|mister|mrs)|mist)\b"
)


def norm(s):
    s = s.lower().replace("colour", "color").replace("per cent", "percent")
    s = re.sub(r"[^a-z0-9% ]+", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def numify(s):
    s = re.sub(rf"\b({TK})[ -]+({UK})\b", lambda m: str(T[m[1]] + U[m[2]]), s)
    s = re.sub(r"\b(?:one |a )?hundred\b", "100", s)
    s = re.sub(rf"\b({TK})\b", lambda m: str(T[m[1]]), s)
    s = re.sub(rf"\b({UK})\b", lambda m: str(U[m[1]]), s)
    return s


def vocabulary():
    words = set("""hey hi okay mist misty missed miss mister turn the lights light lamp on off switch set color
        colors to make it please and change brightness bright brighter dimmer dim lower higher darker full max
        maximum half percent effect mode pattern number next random party speed faster slower stop listening go
        sleep never mind thanks thank you goodnight good night that s all""".split())
    for name in COLORS:
        words.update(name.split())
    words.update(U)
    words.update(T)
    words.add("hundred")
    return sorted(words) + ["[unk]"]


# ---------------------------------------------------------------- networking helpers
def lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # no packet is sent; this just picks the right network interface
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def ensure_cert(ips, force=False):
    """Create a self-signed certificate once so Chrome treats the page as secure (needed for the mic)."""
    cert, key = HERE / "mist-cert.pem", HERE / "mist-key.pem"
    if cert.exists() and key.exists() and not force:
        return cert, key
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Mist")])
    san = [x509.DNSName("localhost")] + [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    now = datetime.datetime.now(datetime.timezone.utc)
    c = (x509.CertificateBuilder()
         .subject_name(name).issuer_name(name).public_key(k.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(now - datetime.timedelta(days=1))
         .not_valid_after(now + datetime.timedelta(days=825))
         .add_extension(x509.SubjectAlternativeName(san), critical=False)
         .sign(k, hashes.SHA256()))
    key.write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                    serialization.NoEncryption()))
    cert.write_bytes(c.public_bytes(serialization.Encoding.PEM))
    print("Created a self-signed certificate:", cert.name)
    return cert, key


class Mist:
    def __init__(self, args):
        self.args = args
        self.clients = set()
        # lamp state
        self.on, self.rgb, self.bright, self.effect, self.speed = True, [255, 147, 41], 100, -1, 50
        self.connected, self.lamp_name = False, None
        self.client, self.char = None, None
        self.write_lock = asyncio.Lock()
        # server-side voice state (only used with --server-mic)
        self.mode = "idle"            # idle | listening | awake
        self.awake_until = 0.0
        self.speaking = False
        self.muted_until = 0.0
        self.note_text = ""
        self.rec = None

    # ------------------------------------------------------------ to the page
    def emit(self, msg):
        data = json.dumps(msg)
        for ws in list(self.clients):
            asyncio.ensure_future(self._safe_send(ws, data))

    async def _safe_send(self, ws, data):
        try:
            await ws.send_str(data)
        except Exception:
            self.clients.discard(ws)

    def push_state(self):
        self.emit({"type": "state", "on": self.on, "rgb": self.rgb, "bright": self.bright,
                   "effect": self.effect, "speed": self.speed, "connected": self.connected,
                   "lampName": self.lamp_name, "mode": self.mode})

    def note(self, text):
        self.note_text = text
        if text:
            print("note:", text)
        self.emit({"type": "note", "text": text})

    def heard(self, text, interim=False):
        self.emit({"type": "heard", "text": text, "interim": interim})

    def say(self, text):
        self.muted_until = time.time() + 0.4 + 0.08 * len(text)
        self.emit({"type": "say", "text": text})

    def set_mode(self, mode):
        if mode != self.mode:
            self.mode = mode
            self.push_state()

    def muted(self):
        return self.speaking or time.time() < self.muted_until

    # ------------------------------------------------------------ Bluetooth
    async def send(self, data):
        if not self.connected or not self.char:
            return
        async with self.write_lock:
            try:
                resp = "write-without-response" not in self.char.properties
                await self.client.write_gatt_char(self.char, data, response=resp)
            except Exception as e:
                self.note(f"Couldn't reach the lamp: {e}")

    async def find_lamp(self):
        for d in await BleakScanner.discover(timeout=6.0):
            if d.name and d.name.startswith(DEVICE_NAME_PREFIX):
                return d
        return None

    async def supervise_lamp(self):
        """Keep the lights connected, reconnecting if the link drops."""
        while True:
            try:
                target, name = self.args.address, None
                if not target:
                    self.note("Looking for your lights...")
                    d = await self.find_lamp()
                    if not d:
                        self.note("No ELK-BLEDOB found. Close the phone app and check the lights have power.")
                        await asyncio.sleep(4)
                        continue
                    target, name = d.address, d.name
                gone = asyncio.Event()
                loop = asyncio.get_running_loop()
                async with BleakClient(target, disconnected_callback=lambda _c: loop.call_soon_threadsafe(gone.set)) as c:
                    self.client, self.char = c, self._find_write_char(c)
                    if self.char is None:
                        raise RuntimeError("no writable channel on this device")
                    self.connected, self.lamp_name = True, name or self.args.address
                    self.note("")
                    print("Lamp connected:", self.lamp_name)
                    self.push_state()
                    await self.send(pkt_time())
                    await gone.wait()
            except Exception as e:
                self.note(f"Lamp: {e}")
            finally:
                self.connected, self.char = False, None
                self.push_state()
            await asyncio.sleep(3)

    @staticmethod
    def _find_write_char(client):
        fallback = None
        for svc in client.services:
            for ch in svc.characteristics:
                if ch.uuid.lower() == PREFERRED_WRITE_UUID:
                    return ch
                if fallback is None and ("write" in ch.properties or "write-without-response" in ch.properties):
                    fallback = ch
        return fallback

    # ------------------------------------------------------------ lamp actions
    async def set_power(self, on):
        self.on = on
        self.push_state()
        await self.send(pkt_on() if on else pkt_off())

    async def set_color(self, rgb):
        was_off = not self.on
        self.rgb, self.on, self.effect = [int(v) for v in rgb], True, -1
        self.push_state()
        if was_off:
            await self.send(pkt_on())
        await self.send(pkt_color(*self.rgb))

    async def set_bright(self, p):
        self.bright = max(1, min(100, round(p)))
        self.push_state()
        await self.send(pkt_brightness(self.bright))

    async def set_effect(self, n):
        self.effect, self.on = n % 22, True
        self.push_state()
        await self.send(pkt_effect(0x87 + self.effect))

    async def set_speed(self, s):
        self.speed = max(0, min(100, round(s)))
        await self.send(pkt_speed(self.speed))

    # ------------------------------------------------------------ understanding
    def parse(self, raw):
        t = numify(norm(raw))
        acts = []
        if re.search(r"\b(stop listening|go to sleep|never mind|that s all|thank you|thanks)\b", t):
            return [{"type": "sleep"}]

        if re.search(r"\b(off|goodnight|good night)\b", t):
            acts.append({"type": "power", "on": False})
        elif re.search(r"\bon\b", t):
            acts.append({"type": "power", "on": True})

        best = None  # earliest colour mention wins, longer names beat shorter ones
        for name in COLORS:
            m = re.search(rf"\b{name}\b", t)
            if m and (best is None or m.start() < best[1] or (m.start() == best[1] and len(name) > len(best[0]))):
                best = (name, m.start())
        if best:
            label = "red" if best[0] == "read" else best[0]
            acts.append({"type": "color", "name": label, "rgb": COLORS[best[0]]})

        num = re.search(r"\b(\d{1,3})\b", t)
        if re.search(r"bright|dim|percent|%|\bfull\b|\bmax|\bhalf\b", t) and not re.search(r"effect|mode|pattern|speed", t):
            if re.search(r"\b(dimmer|lower|darker)\b", t):
                acts.append({"type": "bright", "to": self.bright - 25})
            elif re.search(r"\b(brighter|higher)\b", t):
                acts.append({"type": "bright", "to": self.bright + 25})
            elif num:
                acts.append({"type": "bright", "to": int(num[1])})
            elif re.search(r"\bhalf\b", t):
                acts.append({"type": "bright", "to": 50})
            elif re.search(r"\b(full|max|maximum)\b", t):
                acts.append({"type": "bright", "to": 100})
            elif re.search(r"\bdim\b", t):
                acts.append({"type": "bright", "to": 20})

        m = re.search(r"\b(?:effect|mode|pattern)(?: number)? (\d{1,3})\b", t)
        if m:
            n = int(m[1])
            acts.append({"type": "effect", "n": n - 0x87 if n > 21 else n})
        elif re.search(r"\bnext (effect|mode|pattern)\b", t):
            acts.append({"type": "effect", "n": self.effect + 1})
        elif re.search(r"\brandom (effect|mode|pattern)\b|\bparty\b", t):
            acts.append({"type": "effect", "n": random.randrange(22)})

        m = re.search(r"\bspeed (?:to )?(\d{1,3})\b", t)
        if m:
            acts.append({"type": "speed", "to": int(m[1])})
        elif re.search(r"\bfaster\b", t):
            acts.append({"type": "speed", "to": self.speed + 20})
        elif re.search(r"\bslower\b", t):
            acts.append({"type": "speed", "to": self.speed - 20})
        return acts

    async def run(self, raw):
        """Run a spoken/typed command. Tells the pages how it went so they can stay awake or go back to sleep."""
        print("command:", raw)
        self.heard(f"\u201c{raw.strip()}\u201d")
        acts = self.parse(raw)
        if not acts:
            self.awake_until = time.time() + 6
            self.set_mode("awake")
            self.say("Sorry, I didn't catch that.")
            self.emit({"type": "result", "ok": False, "sleep": False})
            return
        replies = []
        for a in acts:
            k = a["type"]
            if k == "sleep":
                self.awake_until = 0
                self.set_mode("listening" if self.mode != "idle" else "idle")
                self.say("Okay.")
                self.emit({"type": "result", "ok": True, "sleep": True})
                return
            if k == "power":
                await self.set_power(a["on"]); replies.append("Lights on" if a["on"] else "Lights off")
            elif k == "color":
                await self.set_color(a["rgb"]); replies.append(a["name"].capitalize())
            elif k == "bright":
                await self.set_bright(a["to"]); replies.append(f"Brightness {self.bright}")
            elif k == "effect":
                await self.set_effect(a["n"]); replies.append(f"Effect {self.effect}")
            elif k == "speed":
                await self.set_speed(a["to"]); replies.append(f"Speed {self.speed}")
        self.awake_until = 0
        self.set_mode("listening" if self.mode != "idle" else "idle")
        self.say(", ".join(replies) + ".")
        self.emit({"type": "result", "ok": True, "sleep": False})

    # ------------------------------------------------------------ server-side wake word (--server-mic)
    async def on_partial(self, text):
        if self.args.debug:
            print("partial:", text)
        self.heard(text, interim=True)
        if self.mode == "listening" and WAKE.search(norm(text)):
            self.awake_until = time.time() + 7
            self.set_mode("awake")

    async def on_final(self, text):
        print("heard:", text)
        t = norm(text)
        w = WAKE.search(t)
        if w:
            rest = t[w.end():].strip()
            if rest:
                await self.run(rest)
            else:
                print("wake word detected")
                self.emit({"type": "chime"})
                self.say("Yes?")
                self.awake_until = time.time() + 7
                self.set_mode("awake")
                self.heard("")
            return
        if time.time() < self.awake_until:
            await self.run(t)
            return
        self.heard(f"\u201c{text.strip()}\u201d")
        if self.mode == "awake":
            self.set_mode("listening")

    async def sleep_watcher(self):
        while True:
            await asyncio.sleep(0.3)
            if self.mode == "awake" and time.time() > self.awake_until:
                self.set_mode("listening")

    def find_model(self):
        if self.args.model:
            return pathlib.Path(self.args.model)
        for p in sorted(HERE.iterdir()):
            if p.is_dir() and (p.name == "model" or p.name.startswith("vosk-model")):
                return p
        return None

    async def start_voice(self):
        try:
            import sounddevice as sd
            from vosk import Model, KaldiRecognizer, SetLogLevel
        except ImportError as e:
            self.note(f"--server-mic needs extra packages ({e.name}). Run: pip install vosk sounddevice")
            return
        except OSError as e:
            self.note(f"Audio library problem: {e}. On Linux run: sudo apt install libportaudio2")
            return
        path = self.find_model()
        if not path or not path.exists():
            self.note("No speech model found. Download vosk-model-small-en-us-0.15 and unzip it next to server.py.")
            return

        SetLogLevel(-1)
        info = sd.query_devices(self.args.mic, "input")
        rate = 16000
        try:
            sd.check_input_settings(device=self.args.mic, channels=1, dtype="int16", samplerate=rate)
        except Exception:
            rate = int(info["default_samplerate"])

        model = Model(str(path))
        self.rec = KaldiRecognizer(model, rate) if self.args.free_vocab else \
            KaldiRecognizer(model, rate, json.dumps(vocabulary()))

        loop = asyncio.get_running_loop()
        q = asyncio.Queue()

        def callback(indata, frames, t, status):
            if self.mode != "idle" and not self.muted():
                loop.call_soon_threadsafe(q.put_nowait, bytes(indata))

        try:
            stream = sd.RawInputStream(samplerate=rate, blocksize=rate // 5, device=self.args.mic,
                                       dtype="int16", channels=1, callback=callback)
            stream.start()
        except Exception as e:
            self.note(f"Couldn't open the microphone: {e}")
            return
        print(f"Server mic on: {info['name']} ({rate} Hz)")
        self.set_mode("listening")

        was_muted = False
        while True:
            data = await q.get()
            if self.muted():
                was_muted = True
                continue
            if was_muted:
                self.rec.Reset()
                was_muted = False
            if self.rec.AcceptWaveform(data):
                text = json.loads(self.rec.Result()).get("text", "")
                if text:
                    await self.on_final(text)
            else:
                partial = json.loads(self.rec.PartialResult()).get("partial", "")
                if partial:
                    await self.on_partial(partial)

    # ------------------------------------------------------------ web
    async def ws_handler(self, request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        self.clients.add(ws)
        self.push_state()
        if self.note_text:
            await ws.send_str(json.dumps({"type": "note", "text": self.note_text}))
        async for msg in ws:
            if msg.type != WSMsgType.TEXT:
                continue
            try:
                m = json.loads(msg.data)
                k = m.get("type")
                if k == "power": await self.set_power(bool(m["on"]))
                elif k == "color": await self.set_color(m["rgb"])
                elif k == "bright": await self.set_bright(float(m["value"]))
                elif k == "text": await self.run(WAKE.sub("", norm(m["text"])))
                elif k == "listen":
                    if self.rec is None:
                        self.note("The server microphone isn't running (start with --server-mic).")
                    elif m["value"]:
                        self.rec.Reset(); self.set_mode("listening")
                    else:
                        self.awake_until = 0; self.set_mode("idle"); self.heard("")
                elif k == "speaking":
                    self.speaking = bool(m["value"])
                    if not self.speaking:
                        self.muted_until = time.time() + 0.5
            except Exception as e:
                self.note(f"Error: {e}")
        self.clients.discard(ws)
        return ws

    async def index(self, request):
        return web.FileResponse(HERE / "index.html")


async def main():
    p = argparse.ArgumentParser(description="Mist: voice control for ELK-BLEDOB lights")
    p.add_argument("--host", default="127.0.0.1", help="Address to serve on (0.0.0.0 = whole network)")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--address", help="Bluetooth address of the lights (skips scanning)")
    p.add_argument("--http", action="store_true", help="Force plain http even on the network")
    p.add_argument("--new-cert", action="store_true", help="Regenerate the self-signed certificate")
    p.add_argument("--no-browser", action="store_true", help="Don't open the page automatically")
    p.add_argument("--server-mic", action="store_true", help="Also listen on this computer's mic (offline Vosk)")
    p.add_argument("--model", help="Vosk model folder (with --server-mic)")
    p.add_argument("--mic", help="Microphone index or name (with --server-mic)")
    p.add_argument("--debug", action="store_true", help="Print partial results (with --server-mic)")
    p.add_argument("--free-vocab", action="store_true", help="Let Vosk hear any word (with --server-mic)")
    args = p.parse_args()
    if args.mic and args.mic.isdigit():
        args.mic = int(args.mic)

    mist = Mist(args)
    app = web.Application()
    app.add_routes([web.get("/", mist.index), web.get("/ws", mist.ws_handler)])
    runner = web.AppRunner(app)
    await runner.setup()

    networked = args.host not in ("127.0.0.1", "localhost")
    use_https = networked and not args.http
    ssl_ctx = None
    ip = lan_ip()
    if use_https:
        cert, key = ensure_cert(["127.0.0.1", ip], force=args.new_cert)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cert, key)
    await web.TCPSite(runner, args.host, args.port, ssl_context=ssl_ctx).start()

    scheme = "https" if use_https else "http"
    print(f"\nMist is running.")
    print(f"  On this computer:  {scheme}://localhost:{args.port}")
    if networked:
        print(f"  On your phone:     {scheme}://{ip}:{args.port}   (use Chrome)")
        if use_https:
            print("  Chrome will warn about the certificate: tap Advanced, then Proceed. It's your own certificate.")
    print()
    if not args.no_browser and not use_https:
        webbrowser.open(f"{scheme}://localhost:{args.port}")

    tasks = [mist.supervise_lamp(), mist.sleep_watcher()]
    if args.server_mic:
        tasks.append(mist.start_voice())
    await asyncio.gather(*tasks)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
