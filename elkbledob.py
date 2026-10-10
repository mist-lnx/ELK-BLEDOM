"""
elk_bledob - a small library for controlling ELK-BLEDOB Bluetooth LE lights
(the cheap USB LED strips driven by the "LotusLamp X" app).

Packet formats come from https://github.com/8none1/elk-bledob

Install:  pip install bleak

Async usage (recommended):

    import asyncio
    from elk_bledob import ELKLight

    async def main():
        async with ELKLight() as light:          # auto-discovers the first light
            await light.set_color("red")
            await light.fade("blue", duration=3)
            await light.rainbow(duration=10)

    asyncio.run(main())

Blocking usage (no asyncio needed):

    from elk_bledob import SyncELKLight

    with SyncELKLight() as light:
        light.set_color("#ff8800")
        light.flash("white", times=3)

Notes:
  * The lights accept ONE connection at a time - close the phone app first.
  * The lights never report their state, so `light.color`, `light.is_on` etc.
    are what we last *sent*, not what the light confirmed.
"""

from __future__ import annotations

import asyncio
import colorsys
import datetime
import inspect
import math
import threading
from typing import Any, Awaitable, Callable, List, Optional, Sequence, Tuple, Union

__all__ = [
    "ELKLight", "SyncELKLight", "ELKError", "discover",
    "parse_color", "hsv_to_rgb", "lerp_color", "scale_color", "NAMED_COLORS",
]

RGB = Tuple[int, int, int]
ColorLike = Union[str, Sequence[int]]

DEFAULT_NAME_PREFIX = "ELK-BLEDOB"
PREFERRED_WRITE_UUID = "0000fff3-0000-1000-8000-00805f9b34fb"  # common on ELK strips

EFFECT_BASE = 0x87   # effects are numbered 0x87..0x9c (135..156)
EFFECT_COUNT = 22

NAMED_COLORS = {
    "red": (255, 0, 0), "green": (0, 255, 0), "blue": (0, 0, 255),
    "white": (255, 255, 255), "yellow": (255, 255, 0), "cyan": (0, 255, 255),
    "magenta": (255, 0, 255), "orange": (255, 100, 0), "purple": (128, 0, 255),
    "pink": (255, 60, 150), "warm": (255, 147, 41), "black": (0, 0, 0),
}


class ELKError(Exception):
    """Raised for discovery, connection and argument problems."""


# --------------------------------------------------------------------------
# Colour helpers (pure functions, no Bluetooth needed)
# --------------------------------------------------------------------------

def parse_color(value: ColorLike, *more: int) -> RGB:
    """
    Turn a friendly colour description into an (r, g, b) tuple of 0-255 ints.

    Accepts a name ("red"), hex ("#ff8800" / "ff8800"), an (r, g, b) tuple/list,
    or three separate ints: parse_color(255, 0, 128).
    """
    if more:
        rgb = (value, *more)
    elif isinstance(value, str):
        s = value.strip().lower()
        if s in NAMED_COLORS:
            return NAMED_COLORS[s]
        s = s.lstrip("#")
        if len(s) != 6:
            raise ELKError(f"Unknown colour {value!r}")
        try:
            return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16))
        except ValueError:
            raise ELKError(f"Unknown colour {value!r}") from None
    else:
        rgb = tuple(value)
    if len(rgb) != 3:
        raise ELKError("A colour needs exactly three values (r, g, b)")
    r, g, b = (int(round(v)) for v in rgb)
    if not all(0 <= v <= 255 for v in (r, g, b)):
        raise ELKError("RGB values must be between 0 and 255")
    return (r, g, b)


def hsv_to_rgb(h: float, s: float = 1.0, v: float = 1.0) -> RGB:
    """Hue 0-1 (wraps around), saturation 0-1, value 0-1 -> (r, g, b)."""
    r, g, b = colorsys.hsv_to_rgb(h % 1.0, max(0.0, min(1.0, s)), max(0.0, min(1.0, v)))
    return (round(r * 255), round(g * 255), round(b * 255))


def lerp_color(a: RGB, b: RGB, t: float) -> RGB:
    """Blend from colour a (t=0) to colour b (t=1)."""
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))  # type: ignore[return-value]


def scale_color(color: RGB, factor: float) -> RGB:
    """Dim (or brighten) a colour by a factor; result is clamped to 0-255."""
    return tuple(max(0, min(255, round(c * factor))) for c in color)  # type: ignore[return-value]


# --------------------------------------------------------------------------
# Raw packet builders
# --------------------------------------------------------------------------

def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, int(v)))


def pkt_on() -> bytes:
    return bytes.fromhex("7e0704ff00010201ef")


def pkt_off() -> bytes:
    return bytes.fromhex("7e07040000000201ef")


def pkt_color(r: int, g: int, b: int) -> bytes:
    return bytes([0x7E, 0x07, 0x05, 0x03, r, g, b, 0x10, 0xEF])


def pkt_brightness(pct: int) -> bytes:
    return bytes([0x7E, 0x04, 0x01, _clamp(pct, 0, 100), 0x01, 0xFF, 0x02, 0x01, 0xEF])


def pkt_effect(mode: int) -> bytes:
    return bytes([0x7E, 0x07, 0x03, mode, 0x03, 0xFF, 0xFF, 0x00, 0xEF])


def pkt_speed(speed: int) -> bytes:
    return bytes([0x7E, 0x07, 0x02, _clamp(speed, 0, 100), 0xFF, 0xFF, 0xFF, 0x00, 0xEF])


def pkt_time(now: Optional[datetime.datetime] = None) -> bytes:
    now = now or datetime.datetime.now()
    return bytes([0x7E, 0x06, 0x83, now.hour, now.minute, now.second,
                  now.isoweekday(), 0x00, 0xEF])


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

async def discover(timeout: float = 8.0, name_prefix: Optional[str] = DEFAULT_NAME_PREFIX
                   ) -> List[Tuple[str, str]]:
    """
    Scan for lights. Returns a list of (address, name).
    Pass name_prefix=None to list every BLE device you can see.
    """
    from bleak import BleakScanner

    found = []
    for d in await BleakScanner.discover(timeout=timeout):
        if name_prefix is None or (d.name and d.name.startswith(name_prefix)):
            found.append((d.address, d.name or ""))
    return found


# --------------------------------------------------------------------------
# The light
# --------------------------------------------------------------------------

class ELKLight:
    """
    One ELK-BLEDOB light. Use as an async context manager, or call
    connect()/disconnect() yourself.

    Args:
        address:        Bluetooth address. If omitted, the first light found by
                        scanning is used.
        name_prefix:    Device name to look for when scanning.
        scan_timeout:   Seconds to scan for.
        min_interval:   Minimum seconds between writes. Stops fast fades from
                        flooding the light with packets.
        auto_reconnect: If a write fails, reconnect once and retry.
        client_factory: Advanced/testing: callable(address) -> a BleakClient-like
                        object. Defaults to bleak's BleakClient.
    """

    def __init__(self, address: Optional[str] = None, *,
                 name_prefix: str = DEFAULT_NAME_PREFIX,
                 scan_timeout: float = 8.0,
                 min_interval: float = 0.03,
                 auto_reconnect: bool = True,
                 client_factory: Optional[Callable[[str], Any]] = None):
        self.address = address
        self.name_prefix = name_prefix
        self.scan_timeout = scan_timeout
        self.min_interval = min_interval
        self.auto_reconnect = auto_reconnect
        self._client_factory = client_factory

        self._client: Any = None
        self._char: Any = None
        self._lock: Optional[asyncio.Lock] = None
        self._last_write = 0.0

        # Last-sent (optimistic) state - the light can't tell us its real state.
        self.color: RGB = (255, 255, 255)
        self.brightness: int = 100
        self.is_on: Optional[bool] = None
        self.effect: Optional[int] = None

    # ---- connection -------------------------------------------------------

    @property
    def connected(self) -> bool:
        return bool(self._client and self._client.is_connected)

    async def connect(self) -> "ELKLight":
        if self._lock is None:
            self._lock = asyncio.Lock()
        if not self.address:
            lights = await discover(self.scan_timeout, self.name_prefix)
            if not lights:
                raise ELKError(
                    f"No {self.name_prefix} light found. Is it powered, and is the "
                    "phone app disconnected? You can also pass address=...")
            self.address = lights[0][0]
        await self._open()
        return self

    async def _open(self) -> None:
        if self._client_factory:
            self._client = self._client_factory(self.address)
        else:
            from bleak import BleakClient
            self._client = BleakClient(self.address)
        await self._client.connect()
        self._char = self._find_write_char()
        await self._raw_write(pkt_time())  # the official app syncs the clock on connect

    def _find_write_char(self) -> Any:
        fallback = None
        for service in self._client.services:
            for char in service.characteristics:
                if char.uuid.lower() == PREFERRED_WRITE_UUID:
                    return char
                if fallback is None and (
                        "write" in char.properties or "write-without-response" in char.properties):
                    fallback = char
        if fallback is None:
            raise ELKError("No writable Bluetooth characteristic found on this device")
        return fallback

    async def disconnect(self) -> None:
        if self._client is not None:
            try:
                await self._client.disconnect()
            finally:
                self._client = None
                self._char = None

    async def __aenter__(self) -> "ELKLight":
        return await self.connect()

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()

    # ---- low-level sending -------------------------------------------------

    async def _raw_write(self, data: bytes) -> None:
        with_response = "write-without-response" not in self._char.properties
        await self._client.write_gatt_char(self._char, data, response=with_response)
        self._last_write = asyncio.get_running_loop().time()

    async def send(self, data: bytes) -> None:
        """Send a raw packet (throttled, with one automatic reconnect on failure)."""
        if self._lock is None or self._client is None:
            raise ELKError("Not connected - call connect() or use 'async with'")
        async with self._lock:
            wait = self.min_interval - (asyncio.get_running_loop().time() - self._last_write)
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                await self._raw_write(data)
            except Exception:
                if not self.auto_reconnect:
                    raise
                try:
                    await self._client.disconnect()
                except Exception:
                    pass
                await self._open()
                await self._raw_write(data)

    # ---- basic controls ----------------------------------------------------

    async def on(self) -> None:
        await self.send(pkt_on())
        self.is_on = True

    async def off(self) -> None:
        await self.send(pkt_off())
        self.is_on = False

    async def set_color(self, color: ColorLike, *more: int) -> None:
        """set_color("red") / set_color("#ff8800") / set_color((255,0,0)) / set_color(255,0,0)"""
        rgb = parse_color(color, *more)
        await self.send(pkt_color(*rgb))
        self.color = rgb
        self.effect = None

    async def set_hsv(self, h: float, s: float = 1.0, v: float = 1.0) -> None:
        """Hue 0-1, saturation 0-1, value 0-1."""
        await self.set_color(hsv_to_rgb(h, s, v))

    async def set_brightness(self, percent: int) -> None:
        """0-100."""
        percent = _clamp(percent, 0, 100)
        await self.send(pkt_brightness(percent))
        self.brightness = percent

    async def set_effect(self, index: int) -> None:
        """Built-in effect, 0-21 (maps to the light's 0x87-0x9c modes)."""
        if not 0 <= index < EFFECT_COUNT:
            raise ELKError(f"Effect must be 0-{EFFECT_COUNT - 1}")
        await self.send(pkt_effect(EFFECT_BASE + index))
        self.effect = index

    async def set_speed(self, percent: int) -> None:
        """Speed of built-in effects (0-100; range is a best guess)."""
        await self.send(pkt_speed(percent))

    async def sync_time(self) -> None:
        await self.send(pkt_time())

    # ---- routines ------------------------------------------------------------
    # All routines are plain coroutines. Await them in sequence, or run one in
    # the background with asyncio.create_task() and .cancel() it later.

    async def fade(self, to: ColorLike, duration: float = 1.0, *,
                   start: Optional[ColorLike] = None, fps: int = 20) -> None:
        """Smoothly blend from `start` (default: current colour) to `to`."""
        a = parse_color(start) if start is not None else self.color
        b = parse_color(to)
        steps = max(1, int(duration * fps))
        delay = duration / steps
        for i in range(1, steps + 1):
            await self.set_color(lerp_color(a, b, i / steps))
            await asyncio.sleep(delay)

    async def rainbow(self, duration: float = 10.0, *, loops: Optional[int] = 1,
                      fps: int = 20, saturation: float = 1.0, value: float = 1.0) -> None:
        """
        Cycle through the colour wheel. `duration` is seconds per full cycle.
        loops=None repeats forever (cancel the task to stop it).
        """
        steps = max(1, int(duration * fps))
        delay = duration / steps
        n = 0
        while loops is None or n < loops:
            for i in range(steps):
                await self.set_color(hsv_to_rgb(i / steps, saturation, value))
                await asyncio.sleep(delay)
            n += 1

    async def pulse(self, color: ColorLike, period: float = 2.0, *,
                    count: Optional[int] = 3, floor: float = 0.05, fps: int = 20) -> None:
        """Breathe a colour in and out. count=None repeats forever."""
        rgb = parse_color(color)
        steps = max(2, int(period * fps))
        delay = period / steps
        n = 0
        while count is None or n < count:
            for i in range(steps):
                # smooth 0 -> 1 -> 0 curve
                level = floor + (1 - floor) * (0.5 - 0.5 * math.cos(2 * math.pi * i / steps))
                await self.set_color(scale_color(rgb, level))
                await asyncio.sleep(delay)
            n += 1
        await self.set_color(rgb)

    async def flash(self, color: ColorLike, times: int = 3, *,
                    on_time: float = 0.3, off_time: float = 0.3) -> None:
        """Blink a colour on and off, then leave the light off (black)."""
        rgb = parse_color(color)
        for _ in range(times):
            await self.set_color(rgb)
            await asyncio.sleep(on_time)
            await self.set_color((0, 0, 0))
            await asyncio.sleep(off_time)

    async def sequence(self, steps: Sequence[Tuple[ColorLike, float]], *,
                       fade_time: float = 0.0, loops: Optional[int] = 1) -> None:
        """
        Step through [(colour, hold_seconds), ...]. With fade_time > 0, each
        step is blended in over that many seconds first.
        Example: await light.sequence([("red", 1), ("green", 1), ("blue", 1)], fade_time=0.5)
        """
        n = 0
        while loops is None or n < loops:
            for color, hold in steps:
                if fade_time > 0:
                    await self.fade(color, fade_time)
                else:
                    await self.set_color(color)
                await asyncio.sleep(hold)
            n += 1

    async def run_for(self, seconds: float, routine: Awaitable[Any]) -> None:
        """Run a routine (e.g. an endless rainbow) but stop it after `seconds`."""
        try:
            await asyncio.wait_for(routine, timeout=seconds)
        except asyncio.TimeoutError:
            pass


# --------------------------------------------------------------------------
# Blocking wrapper
# --------------------------------------------------------------------------

class SyncELKLight:
    """
    Same API as ELKLight, but every method blocks until it finishes - handy for
    simple scripts. Takes the same constructor arguments as ELKLight and
    connects immediately.

        with SyncELKLight() as light:
            light.set_color("green")
            light.rainbow(duration=5)

    Forever-running routines (loops=None / count=None) will block forever here;
    use the async ELKLight if you need to cancel them.
    """

    def __init__(self, *args, **kwargs):
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._loop.run_forever, daemon=True)
        self._thread.start()
        self._light = ELKLight(*args, **kwargs)
        self._run(self._light.connect())

    def _run(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def __getattr__(self, name: str):
        attr = getattr(self._light, name)
        if inspect.iscoroutinefunction(attr):
            return lambda *a, **k: self._run(attr(*a, **k))
        return attr

    def close(self) -> None:
        if self._loop.is_running():
            try:
                self._run(self._light.disconnect())
            finally:
                self._loop.call_soon_threadsafe(self._loop.stop)
                self._thread.join(timeout=2)

    def __enter__(self) -> "SyncELKLight":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
