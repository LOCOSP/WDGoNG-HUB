"""EXTRAS Phase 2 — sandbox HOST side (runs inside the root game process).

An extra runs in a separate, freshly exec'd Python interpreter that locks itself
down before any extra code executes (see wdgo_extras_child): empty chroot, a
dedicated unprivileged uid, no network namespace, no fork, bounded memory. It is
a headless logic process: it cannot draw or touch hardware. This module is the
other end of its only file descriptor:

  * draw-ops   the child returns a list of primitives per frame; every op is
               re-validated and clamped here, then painted through the bridge
  * broker     the child asks for storage / loot by name; each request is checked
               against the permissions in the extra's manifest and bounded
  * watchdog   a child that stops answering is SIGKILLed; the game never blocks
               on it (a late frame just re-paints the previous one)
  * sources    the child never reads the extra's folder: the host ships the
               exact bytes of the approved Snapshot ("src" messages after the
               hello) and the child re-checks their hash before running them
  * budgets    per game frame the pump reads, decodes and handles a bounded
               amount (bytes / messages / time); an accepted frame is bounded in
               ops, characters and covered pixels, and painting it in time

Nothing received from the child is trusted. A protocol violation kills it. A root
game never runs a child that did not establish full isolation.

SandboxHost mirrors ExtraHost's surface (meta / state / error / open / frame /
close) so the game drives both the same way. Pure stdlib — never imports raylib.
"""
import base64
import collections
import inspect
import itertools
import math
import os
import re
import select
import signal
import socket
import subprocess
import sys
import time

import wdgo_extras as wx
import wdgo_extras_ipc as ipc

SANDBOX_UID = 61184           # dedicated, otherwise-unused numeric uid/gid
SANDBOX_GID = 61184
JAIL_DIR = "/run/wdgo-extras-jail"
MEM_LIMIT = 512 * 1024 * 1024

START_TIMEOUT = 8.0           # hello -> ready (includes shipping the sources)
FRAME_KILL_AFTER = 3.0        # no frame reply for this long -> SIGKILL
FRAME_WAIT_BUDGET = 0.010     # max time the game loop waits for a frame reply
EXIT_GRACE = 0.30             # on_exit window before the kill
MAX_OUT_BUF = 2 * 1024 * 1024
SRC_CHUNK = 192 * 1024        # raw source bytes per "src" message (base64 stays < ipc.MAX_MSG)
SRC_TOPUP = 256 * 1024        # keep at most this much startup data queued in user space
CALL_BURST = 128              # broker calls: token bucket (burst / refill per second)
CALL_RATE = 256.0
# One budget for EVERYTHING the pump does in one game frame (see SandboxHost.frame):
PUMP_MAX_BYTES = 128 * 1024   # read from the socket
PUMP_MAX_MSGS = 16            # messages handled
PUMP_MAX_TIME = 0.004         # seconds spent decoding + handling
RECV_CHUNK = 16 * 1024        # one recv(); new data is read only when the queue is empty
# Drawing budget for one accepted frame (host side, after validation and clipping):
HOST_MAX_OPS = 512
HOST_MAX_CHARS = 4096
HOST_MAX_AREA_SCREENS = 2.0   # covered pixels, in viewport areas
RENDER_MAX_TIME = 0.008       # painting one frame through the bridge
STORAGE_MAX_FILE = wx.STORAGE_MAX_FILE
STORAGE_MAX_FILES = wx.STORAGE_MAX_FILES
LOOT_SAVE_MAX = wx.LOOT_SAVE_MAX
LOOT_LIST_MAX = 500
LOOT_CACHE_TTL = 1.0          # loot.networks / loot.counts answers are reused this long
LOG_BURST = 30                # log lines accepted per LOG_WINDOW seconds
LOG_WINDOW = 10.0

_CHILD = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wdgo_extras_child.py")


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def full_isolation_possible() -> bool:
    return sys.platform.startswith("linux") and _is_root()


def available(require_isolation=True) -> bool:
    """Can the sandbox run here? With require_isolation the kernel jail must be
    achievable (Linux + root); without it (desktop simulator) any POSIX host works,
    with the child reporting isolation level 'none'. A root process ALWAYS needs the
    jail: there is no unisolated mode for root."""
    if not os.path.isfile(_CHILD) or not hasattr(socket, "socketpair"):
        return False
    if _is_root() or require_isolation:
        return full_isolation_possible()
    return True


def reap_orphans() -> int:
    """SIGKILL every process running as the dedicated sandbox uid (Linux, as root).
    Only extras ever run as that uid, and at most one is active, so anything left is
    an orphan of an earlier game process (crash, restart). Returns the count."""
    if not full_isolation_possible():
        return 0
    n = 0
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return 0
    for p in pids:
        try:
            with open("/proc/%s/status" % p, "rb") as f:
                for line in f:
                    if line.startswith(b"Uid:"):
                        if any(int(u) == SANDBOX_UID for u in line.split()[1:5]):
                            os.kill(int(p), signal.SIGKILL)
                            n += 1
                        break
        except (OSError, ValueError):
            continue
    return n


# ----------------------------------------------------------------------
# validation helpers — everything from the child goes through these
# ----------------------------------------------------------------------
def _num(v, lo, hi, default=0.0):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return default
    if v != v or v in (float("inf"), float("-inf")):
        return default
    return lo if v < lo else hi if v > hi else v


def _color(v):
    return v if isinstance(v, str) and v in wx.PALETTE else "txt"


def _clean_text(v, limit):
    if not isinstance(v, str):
        v = str(v)
    if len(v) > limit:
        v = v[:limit]
    return "".join(ch if (ch >= " " or ch == "\t") and ch != "\x7f" else " " for ch in v)


_C = 20000.0      # coordinate clamp (the host scissor does the real clipping)


_IMG_NAME = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]{0,63}\.png$")


def sanitize_images(raw, have: dict, parts: dict) -> None:
    """Accept image strips an untrusted child sends: {name: [w, h, y0, base64 RGBA rows]}.
    Rows must arrive in order from row 0; a finished image moves to have[name] =
    (w, h, pixels). The child decoded the file - all the host checks is that the
    numbers describe a small image and that each strip is whole rows of it. Anything
    inconsistent drops that image's partial data."""
    if not isinstance(raw, dict):
        return
    for name, v in list(raw.items())[:2]:
        try:
            if not (isinstance(name, str) and _IMG_NAME.match(name) and ".." not in name):
                continue
            if name in have:
                continue
            w, h, y0, b64 = v
            if not all(isinstance(n, int) and not isinstance(n, bool) for n in (w, h, y0)) \
                    or not isinstance(b64, str):
                continue
            if not (1 <= w <= wx.IMG_MAX_PX and 1 <= h <= wx.IMG_MAX_PX):
                continue
            if len(b64) > (ipc.IMG_STRIP_BYTES + w * 4) * 4 // 3 + 8:
                continue
            part = parts.get(name)
            if part is None:
                if y0 != 0 or len(have) + len(parts) >= wx.IMG_MAX_COUNT:
                    continue
                part = parts[name] = [w, h, bytearray()]
            if (part[0], part[1]) != (w, h) or y0 * w * 4 != len(part[2]):
                parts.pop(name, None)
                continue
            px = base64.b64decode(b64, validate=True)
            if not px or len(px) % (w * 4) or len(part[2]) + len(px) > w * h * 4:
                parts.pop(name, None)
                continue
            part[2] += px
            if len(part[2]) == w * h * 4:
                have[name] = (w, h, bytes(part[2]))
                del parts[name]
        except Exception:
            parts.pop(name, None) if isinstance(name, str) else None
            continue


def _span(a, b, lim):
    """Length of [min(a,b), max(a,b)] inside [0, lim]."""
    lo, hi = (a, b) if a <= b else (b, a)
    return max(0.0, min(hi, lim) - max(lo, 0.0))


def _op_cost(op, vw, vh, images):
    """Pixels an op covers after clipping to the viewport (rough, never below 1)."""
    k = op[0]
    if k == "t":
        size = op[4]
        c = _span(op[2], op[2] + len(op[1]) * size * 0.6, vw) * _span(op[3], op[3] + size, vh)
    elif k == "r":
        cw, ch = _span(op[1], op[1] + op[3], vw), _span(op[2], op[2] + op[4], vh)
        c = cw * ch if op[6] else min(cw * ch, 2.0 * (cw + ch))
    elif k == "l":
        bw, bh = _span(op[1], op[3], vw), _span(op[2], op[4], vh)
        if (bw <= 0 and op[1] != op[3]) or (bh <= 0 and op[2] != op[4]):
            c = 0.0
        else:
            c = min(math.hypot(op[3] - op[1], op[4] - op[2]), math.hypot(vw, vh)) * op[6]
    elif k == "c":
        r = op[3]
        c = 0.785 * _span(op[1] - r, op[1] + r, vw) * _span(op[2] - r, op[2] + r, vh)
    elif k == "i":
        w, h, _ = images[op[1]]
        c = _span(op[2], op[2] + w * op[4], vw) * _span(op[3], op[3] + h * op[4], vh)
    else:
        c = 0.0
    return max(1.0, c)


def sanitize_ops(raw, images=None, view=None) -> list:
    """Turn an untrusted op list into a list of safe tuples; bad ops are dropped.
    The accepted frame is also bounded in what it costs the game to paint: at most
    HOST_MAX_OPS ops, HOST_MAX_CHARS characters and HOST_MAX_AREA_SCREENS viewports
    of covered pixels (after clipping); ops beyond the budget are dropped."""
    out = []
    if not isinstance(raw, list):
        return out
    try:
        vw, vh = float(_num(view[0], 1, 16384, 800)), float(_num(view[1], 1, 16384, 480))
    except Exception:
        vw, vh = 800.0, 480.0
    area = HOST_MAX_AREA_SCREENS * vw * vh
    chars = HOST_MAX_CHARS
    for op in raw[:ipc.MAX_OPS]:
        if len(out) >= HOST_MAX_OPS:
            break
        if not isinstance(op, list) or not op:
            continue
        k = op[0]
        try:
            if k == "t" and len(op) == 7:
                if chars <= 0:
                    continue
                s = _clean_text(op[1], min(ipc.MAX_TEXT, chars))
                t = ("t", s, _num(op[2], -_C, _C), _num(op[3], -_C, _C),
                     _num(op[4], 6, 80, 16), _color(op[5]), bool(op[6]))
            elif k == "r" and len(op) == 8:
                t = ("r", _num(op[1], -_C, _C), _num(op[2], -_C, _C),
                     _num(op[3], 0, _C), _num(op[4], 0, _C), _color(op[5]),
                     bool(op[6]), int(_num(op[7], 0, 255, 255)))
            elif k == "l" and len(op) == 7:
                t = ("l", _num(op[1], -_C, _C), _num(op[2], -_C, _C),
                     _num(op[3], -_C, _C), _num(op[4], -_C, _C),
                     _color(op[5]), _num(op[6], 1, 64, 1))
            elif k == "c" and len(op) == 5:
                t = ("c", _num(op[1], -_C, _C), _num(op[2], -_C, _C),
                     _num(op[3], 0, 4000), _color(op[4]))
            elif k == "i" and len(op) == 6 and images and isinstance(op[1], str) and op[1] in images:
                t = ("i", op[1], _num(op[2], -_C, _C), _num(op[3], -_C, _C),
                     int(_num(op[4], 1, 8, 1)), int(_num(op[5], 0, 255, 255)))
            else:
                continue
            cost = _op_cost(t, vw, vh, images)
        except Exception:
            continue
        if cost > area:
            continue
        area -= cost
        if k == "t":
            chars -= len(t[1])
        out.append(t)
    return out


def _call_limited(fn, limit):
    """fn(limit=limit) when the provider accepts a limit (so it can stop before
    copying a huge set), else fn()."""
    try:
        params = inspect.signature(fn).parameters
        takes = "limit" in params or any(p.kind == p.VAR_KEYWORD for p in params.values())
    except (TypeError, ValueError):
        takes = False
    return fn(limit=limit) if takes else fn()


class _BrokerStorage(wx.SafeStorage):
    """Per-extra storage executed by the host on the child's behalf, with quotas.
    Confined to <data_dir>/<basename>; never follows a symlink (see wx.SafeStorage)."""
    def __init__(self, d):
        super().__init__(d, STORAGE_MAX_FILE, STORAGE_MAX_FILES)


class SandboxHost:
    """One sandboxed extra. Same surface as wdgo_extras.ExtraHost."""
    def __init__(self, meta, bridge, data_dir, require_isolation=True, snapshot=None):
        self.meta = meta
        self._bridge = bridge
        self._data_dir = data_dir
        self._snap = snapshot
        # a root game never accepts an unisolated child, whatever the caller asked
        self._require_iso = bool(require_isolation) or _is_root()
        self.state = "loading"       # loading | running | closing | faulted | closed
        self.error = None
        self.faults = 0
        self.sandboxed = True
        self.isolation = "?"         # "full" | "none" (dev simulator only)
        self.content_hash = ""
        self._perms = set(meta.permissions or []) & wx._KNOWN_PERMS
        self._store = _BrokerStorage(data_dir)
        self._proc = None
        self._sock = None
        self._framer = ipc.Framer()
        self._inq = collections.deque()      # decoded, not yet handled messages
        self._out = bytearray()
        self._src_files = []                 # [(rel, bytes)] still to ship at startup
        self._src_pos = [0, 0]               # file index, offset
        self._ops = []
        self._imgs = {}              # name -> (w, h, rgba) declared by the child, validated
        self._img_parts = {}         # name -> [w, h, bytearray] still arriving in strips
        self._awaiting = False
        self._frame_n = 0
        self._t_sent = 0.0
        self._t_spawn = 0.0
        self._acc_dt = 0.0
        self._pressed = set()
        self._chars = []
        self._tokens = float(CALL_BURST)
        self._tok_t = time.monotonic()
        self._log_t0 = 0.0
        self._log_n = 0
        self._bud_bytes = PUMP_MAX_BYTES
        self._bud_msgs = PUMP_MAX_MSGS
        self._bud_time = PUMP_MAX_TIME
        self._calls_seen = 0
        self._nets_cache = None
        self._counts_cache = None
        self._loot_bytes = 0
        self._loot_names = set()
        self.render_overruns = 0
        self.ops_serial = 0          # +1 per accepted frame: a renderer may cache until it changes
        self._keys = list(getattr(bridge, "key_names", None) or ipc.KEY_NAMES)

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def open(self):
        try:
            snap = self._snap
            if snap is None:
                snap = self._snap = wx.snapshot(self.meta.dir)
            # the snapshot's own manifest is the one that was approved: use ITS permissions
            self.meta = snap.meta
            self._perms = set(snap.meta.permissions or []) & wx._KNOWN_PERMS
            if snap.meta.entry_file not in snap.src:
                raise ValueError("entry file '%s' is not a regular file" % snap.meta.entry_file)
            self.content_hash = snap.sha
            reap_orphans()
            host_s, child_s = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                for so, opt in ((host_s, socket.SO_SNDBUF), (child_s, socket.SO_RCVBUF)):
                    try:
                        so.setsockopt(socket.SOL_SOCKET, opt, 1024 * 1024)
                    except OSError:
                        pass
                host_s.setblocking(False)
                # A fresh interpreter, never a fork: the game's memory (API keys,
                # radio state, GL context) must not exist in the extra's address space.
                self._proc = subprocess.Popen(
                    [sys.executable, "-I", "-B", _CHILD, str(child_s.fileno())],
                    pass_fds=[child_s.fileno()], close_fds=True,
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, cwd="/", start_new_session=True,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
            except Exception:
                host_s.close()
                raise
            finally:
                child_s.close()
            self._sock = host_s
            self._t_spawn = time.monotonic()
            vw, vh = self._view()
            self._src_files = sorted(snap.src.items())
            self._src_pos = [0, 0]
            # The child never reads the extra's folder: the approved bytes travel
            # over the socket and the child re-checks their hash before running them.
            self._send({
                "t": "hello", "proto": ipc.PROTO, "api": wx.EXTRAS_API,
                "id": snap.meta.id, "host_pid": os.getpid(),
                "src": [[rel, len(data)] for rel, data in self._src_files],
                "entry_file": snap.meta.entry_file, "entry_symbol": snap.meta.entry_symbol,
                "sha": snap.sha, "perms": sorted(self._perms),
                "view": [vw, vh], "mw": self._measure_fit(),
                "iso": self._require_iso, "uid": SANDBOX_UID, "gid": SANDBOX_GID,
                "jail": JAIL_DIR, "mem": MEM_LIMIT,
            })
        except Exception as exc:
            self._fault("sandbox start failed: %s: %s" % (type(exc).__name__, exc))

    def frame(self, dt):
        if self.state in ("faulted", "closed"):
            return
        self._new_budget()
        try:
            self._acc_dt += max(0.0, float(dt))
            self._collect_input()
            self._pump()
            if self.state == "loading" and self._startup_pending():
                self._push_startup(FRAME_WAIT_BUDGET)
            if self.state == "running" and not self._awaiting:
                self._send_frame()
                self._wait_frame(FRAME_WAIT_BUDGET)
            elif self.state == "running" and self._calls_seen:
                # the extra is mid-frame making broker calls: keep serving them
                # (within this frame's budget) instead of one per game frame
                self._wait_frame(FRAME_WAIT_BUDGET)
            self._watchdog()
        except ipc.ProtocolError as exc:
            self._fault("protocol violation: %s" % exc)
        except Exception as exc:
            self._fault("sandbox host error: %s: %s" % (type(exc).__name__, exc))
        self._render()

    def event(self, key):
        pass          # input travels in the frame snapshot

    def close(self):
        try:
            if self._proc is not None and self._proc.poll() is None and self.state == "running":
                try:
                    self._send({"t": "exit"})
                    end = time.monotonic() + EXIT_GRACE
                    self.state = "closing"
                    while time.monotonic() < end and self._proc.poll() is None:
                        self._new_budget()
                        if self._pump(wait=0.02) == "exited":
                            break
                except Exception:
                    pass
        finally:
            self._kill()
            try:
                self._bridge.release_all()
            except Exception:
                pass
            self.state = "closed"

    # ------------------------------------------------------------------
    # plumbing
    # ------------------------------------------------------------------
    def _new_budget(self):
        self._calls_seen = 0
        self._bud_bytes = PUMP_MAX_BYTES
        self._bud_msgs = PUMP_MAX_MSGS
        self._bud_time = PUMP_MAX_TIME

    def _view(self):
        try:
            w, h = self._bridge.view()
            return int(_num(w, 1, 16384, 800)), int(_num(h, 1, 16384, 480))
        except Exception:
            return 800, 480

    def _measure_fit(self):
        """Monospace text width is linear in the character count; fit it once on the
        host font so the child can answer ctx.measure() without a round trip:
        width(s, size) ~= size * (a * len(s) + c)."""
        try:
            m10 = float(self._bridge.measure("M" * 10, 40))
            m20 = float(self._bridge.measure("M" * 20, 40))
            a = (m20 - m10) / 400.0
            c = m10 / 40.0 - 10.0 * a
            if not (0.05 < a < 3.0) or not math.isfinite(c):
                raise ValueError
            return [a, c]
        except Exception:
            return [0.55, 0.0]

    def _send(self, obj):
        self._out += ipc.pack(obj)
        if len(self._out) > MAX_OUT_BUF:
            raise ipc.ProtocolError("child is not reading")
        self._flush()

    def _startup_pending(self) -> bool:
        return bool(self._out) or self._src_pos[0] < len(self._src_files)

    def _next_src_chunk(self):
        """The next {"t":"src"} message of the approved sources, or None when done."""
        fi, off = self._src_pos
        while fi < len(self._src_files) and off >= len(self._src_files[fi][1]):
            fi, off = fi + 1, 0
        if fi >= len(self._src_files):
            self._src_pos = [fi, 0]
            return None
        data = self._src_files[fi][1]
        part = data[off:off + SRC_CHUNK]
        self._src_pos = [fi, off + len(part)]
        return {"t": "src", "i": fi, "o": off, "b": base64.b64encode(part).decode("ascii")}

    def _flush(self):
        while self._sock is not None:
            while len(self._out) < SRC_TOPUP and self._src_pos[0] < len(self._src_files):
                msg = self._next_src_chunk()
                if msg is None:
                    break
                self._out += ipc.pack(msg)
            if not self._out:
                return
            try:
                n = self._sock.send(self._out[:65536])
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                self._out.clear()
                self._src_files = []
                return
            if n <= 0:
                return
            del self._out[:n]

    def _push_startup(self, budget):
        """While loading, spend up to `budget` seconds pushing the sources out."""
        end = time.monotonic() + budget
        while self._sock is not None and self._startup_pending():
            left = end - time.monotonic()
            if left <= 0:
                return
            try:
                select.select([], [self._sock], [], left)
            except Exception:
                return
            self._flush()

    def _pump(self, wait=0.0):
        """Flush pending output, read what the child sent and dispatch it, within the
        frame's budget (bytes read, messages handled, time spent). Anything over the
        budget stays queued (or in the socket) for the next frame. Returns
        "frame"/"exited" when that message was handled, else None."""
        if self._sock is None:
            return None
        self._flush()
        got = None
        if wait > 0 and not self._inq:
            try:
                select.select([self._sock], [], [], wait)
            except Exception:
                pass
        while self.state not in ("faulted", "closed"):
            if not self._inq:
                if self._bud_bytes <= 0 or self._bud_time <= 0:
                    break
                try:
                    data = self._sock.recv(min(RECV_CHUNK, self._bud_bytes))
                except (BlockingIOError, InterruptedError):
                    break
                except OSError:
                    data = b""
                if not data:
                    if self.state in ("loading", "running"):
                        code = self._proc.poll() if self._proc is not None else None
                        self._fault("sandbox process ended unexpectedly (exit %s)" % code)
                    return got
                self._bud_bytes -= len(data)
                t0 = time.monotonic()
                self._inq.extend(self._framer.feed(data))
                self._bud_time -= time.monotonic() - t0
                continue
            if self._bud_msgs <= 0 or self._bud_time <= 0:
                break
            msg = self._inq.popleft()
            self._bud_msgs -= 1
            t0 = time.monotonic()
            r = self._handle(msg)
            self._bud_time -= time.monotonic() - t0
            if r:
                got = r
        return got

    def _budget_left(self) -> bool:
        return (self._bud_msgs > 0 and self._bud_time > 0
                and (self._bud_bytes > 0 or bool(self._inq)))

    def _wait_frame(self, budget):
        end = time.monotonic() + budget
        while self._awaiting and self.state == "running" and self._budget_left():
            left = end - time.monotonic()
            if left <= 0:
                break
            self._pump(wait=left)

    def _collect_input(self):
        b = self._bridge
        for nm in self._keys:
            try:
                if b.key_pressed(nm):
                    self._pressed.add(nm)
            except Exception:
                pass
        try:
            for ch in (b.chars() or []):
                if isinstance(ch, str) and len(ch) == 1 and len(self._chars) < ipc.MAX_CHARS:
                    self._chars.append(ch)
        except Exception:
            pass

    def _gps(self):
        if "gps" not in self._perms:
            return None
        try:
            f = self._bridge.gps()
        except Exception:
            f = None
        if not isinstance(f, dict):
            return None
        return {"valid": bool(f.get("valid")),
                "lat": float(_num(f.get("lat"), -90, 90)),
                "lon": float(_num(f.get("lon"), -180, 180)),
                "sats": int(_num(f.get("sats"), 0, 255)),
                "speed_kmh": float(_num(f.get("speed_kmh"), 0, 2000)),
                "heading": float(_num(f.get("heading"), 0, 360))}

    def _send_frame(self):
        b = self._bridge
        down = []
        for nm in self._keys:
            try:
                if b.key_down(nm):
                    down.append(nm)
            except Exception:
                pass
        vw, vh = self._view()
        self._frame_n += 1
        self._send({"t": "frame", "n": self._frame_n, "dt": round(min(self._acc_dt, 1.0), 5),
                    "view": [vw, vh], "down": down, "pressed": sorted(self._pressed),
                    "chars": self._chars, "gps": self._gps(), "now": time.time()})
        self._acc_dt = 0.0
        self._pressed = set()
        self._chars = []
        self._awaiting = True
        self._t_sent = time.monotonic()

    def _watchdog(self):
        now = time.monotonic()
        if self.state == "loading" and now - self._t_spawn > START_TIMEOUT:
            self._fault("sandbox did not start within %ds" % START_TIMEOUT)
        elif self.state == "running" and self._awaiting and now - self._t_sent > FRAME_KILL_AFTER:
            self._fault("unresponsive for %ds - killed by the watchdog" % FRAME_KILL_AFTER)
        elif (self.state in ("loading", "running") and self._proc is not None
              and self._proc.poll() is not None):
            self._fault("sandbox process ended unexpectedly (exit %s)" % self._proc.returncode)

    # ------------------------------------------------------------------
    # message handling (each type is accepted only in the state that expects it)
    # ------------------------------------------------------------------
    def _handle(self, msg):
        t = msg.get("t")
        if t == "frame":
            if self.state == "closing":
                return None                      # a reply that crossed our "exit"
            if self.state != "running" or not self._awaiting or msg.get("n") != self._frame_n:
                raise ipc.ProtocolError("unexpected frame reply")
            sanitize_images(msg.get("imgs"), self._imgs, self._img_parts)
            self._ops = sanitize_ops(msg.get("ops"), self._imgs, self._view())
            self.ops_serial += 1
            self._take_logs(msg.get("logs"))
            self._awaiting = False
            return "frame"
        if t == "call":
            if self.state not in ("running", "closing"):
                raise ipc.ProtocolError("broker call before the extra is running")
            self._broker(msg)
            return None
        if t == "ready":
            if self.state != "loading" or self._startup_pending():
                raise ipc.ProtocolError("unexpected ready")
            iso = msg.get("iso") if isinstance(msg.get("iso"), dict) else {}
            level = iso.get("level")
            if level != "full" and (self._require_iso or level != "none"):
                self._fault("isolation not established (%s) - refused to run"
                            % _clean_text(iso.get("why", "?"), 120))
                return None
            self.isolation = level
            self.state = "running"
            return None
        if t == "fault":
            self._fault(_clean_text(msg.get("err", "extra faulted"), 300), from_child=True)
            return None
        if t == "exited":
            if self.state != "closing":
                raise ipc.ProtocolError("unexpected exited")
            return "exited"
        raise ipc.ProtocolError("unknown message type")

    def _take_logs(self, logs):
        if not isinstance(logs, list):
            return
        now = time.monotonic()
        if now - self._log_t0 > LOG_WINDOW:
            self._log_t0, self._log_n = now, 0
        for item in logs[:ipc.MAX_LOGS]:
            if self._log_n >= LOG_BURST:
                break
            if isinstance(item, list) and len(item) == 2:
                lvl = item[0] if item[0] in ("info", "ok", "warn", "error") else "info"
                self._log_n += 1
                try:
                    self._bridge.log(_clean_text(item[1], ipc.MAX_LOG_LEN), lvl)
                except Exception:
                    pass

    def _loot_networks(self):
        now = time.monotonic()
        if self._nets_cache is not None and now - self._nets_cache[0] < LOOT_CACHE_TTL:
            return self._nets_cache[1]
        out = []
        src = _call_limited(self._bridge.loot_networks, LOOT_LIST_MAX) or []
        for n in itertools.islice(iter(src), LOOT_LIST_MAX):
            if isinstance(n, dict):
                out.append({"ssid": _clean_text(n.get("ssid", ""), 64),
                            "bssid": _clean_text(n.get("bssid", ""), 32),
                            "channel": int(_num(n.get("channel", 0), 0, 255))})
        self._nets_cache = (now, out)
        return out

    def _loot_counts(self):
        now = time.monotonic()
        if self._counts_cache is not None and now - self._counts_cache[0] < LOOT_CACHE_TTL:
            return self._counts_cache[1]
        raw = self._bridge.loot_counts() or {}
        items = raw.items() if isinstance(raw, dict) else []
        v = {str(k)[:32]: int(_num(c, 0, 10 ** 9)) for k, c in itertools.islice(items, 32)}
        self._counts_cache = (now, v)
        return v

    def _broker(self, msg):
        """Capability broker: the ONLY way the child reaches anything outside its
        process. Method names are a fixed allowlist; permission and size checks are
        done here, on the trusted side, regardless of what the child's ctx thinks."""
        cid = msg.get("id")
        if isinstance(cid, bool) or not isinstance(cid, int):
            raise ipc.ProtocolError("bad call id")
        self._calls_seen += 1
        now = time.monotonic()
        self._tokens = min(float(CALL_BURST), self._tokens + (now - self._tok_t) * CALL_RATE)
        self._tok_t = now
        self._tokens -= 1.0
        if self._tokens < 0:
            raise ipc.ProtocolError("broker call flood")
        m = msg.get("m")
        a = msg.get("a") if isinstance(msg.get("a"), list) else []
        try:
            if m == "storage.read" and len(a) == 1:
                v = self._store.read(a[0])
            elif m == "storage.write" and len(a) == 2:
                v = self._store.write(a[0], a[1])
            elif m in ("loot.networks", "loot.counts"):
                if "loot_read" not in self._perms:
                    raise PermissionError("permission 'loot_read' not granted")
                v = self._loot_networks() if m == "loot.networks" else self._loot_counts()
            elif m == "loot.save" and len(a) == 2:
                if "loot_write" not in self._perms:
                    raise PermissionError("permission 'loot_write' not granted")
                if not isinstance(a[0], str) or not isinstance(a[1], str):
                    raise ValueError("bad loot.save arguments")
                size = len(a[1].encode("utf-8", "replace"))
                if size > LOOT_SAVE_MAX:
                    raise ValueError("bad loot.save arguments")
                name = a[0][:80]
                # defence in depth: a per-session quota even if the game's own
                # loot_save does not enforce one (wdgo_extras.loot_save does)
                if (self._loot_bytes + size > wx.LOOT_MAX_BYTES
                        or (name not in self._loot_names and len(self._loot_names) >= wx.LOOT_MAX_FILES)):
                    raise ValueError("loot quota for this extra is used up")
                v = self._bridge.loot_save(name, a[1])
                v = str(v) if v else None
                if v:
                    self._loot_bytes += size
                    self._loot_names.add(name)
            else:
                raise ValueError("unknown broker method")
            self._send({"t": "reply", "id": cid, "ok": True, "v": v})
        except ipc.ProtocolError:
            raise
        except Exception as exc:
            self._send({"t": "reply", "id": cid, "ok": False,
                        "err": "%s: %s" % (type(exc).__name__, _clean_text(exc, 160))})

    # ------------------------------------------------------------------
    # failure + teardown
    # ------------------------------------------------------------------
    def _fault(self, reason, from_child=False):
        if self.state in ("faulted", "closed"):
            return
        self.faults += 1
        self.error = reason
        self.state = "faulted"
        self._ops = []
        self._kill()
        try:
            self._bridge.log("faulted: %s" % reason, "error")
        except Exception:
            pass
        try:
            self._bridge.release_all()
        except Exception:
            pass

    def _kill(self):
        p, self._proc = self._proc, None
        if p is not None:
            try:
                if p.poll() is None:
                    try:
                        os.killpg(p.pid, signal.SIGKILL)   # own session -> own group
                    except Exception:
                        p.kill()
                p.wait(timeout=1.0)
            except Exception:
                pass
        s, self._sock = self._sock, None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass
        self._out.clear()
        self._inq.clear()
        self._src_files = []
        self._awaiting = False

    def _render(self):
        b = self._bridge
        if self.state == "loading":
            try:
                b.draw_text("starting sandbox...", 0, 0, 16, "dim", False)
            except Exception:
                pass
            return
        if self.state not in ("running", "closing"):
            return
        t_end = time.monotonic() + RENDER_MAX_TIME
        for i, op in enumerate(self._ops):
            if (i & 15) == 15 and time.monotonic() > t_end:
                self.render_overruns += 1        # paint budget spent: rest of this frame dropped
                break
            try:
                k = op[0]
                if k == "t":
                    b.draw_text(op[1], op[2], op[3], op[4], op[5], op[6])
                elif k == "r":
                    b.draw_rect(op[1], op[2], op[3], op[4], op[5], op[6], op[7])
                elif k == "l":
                    b.draw_line(op[1], op[2], op[3], op[4], op[5], op[6])
                elif k == "c":
                    b.draw_circle(op[1], op[2], op[3], op[4])
                elif k == "i":
                    w, h, px = self._imgs[op[1]]
                    b.draw_image(op[1], w, h, px, op[2], op[3], op[4], op[5])
            except Exception:
                pass
