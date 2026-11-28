"""EXTRAS Phase 2 — sandbox CHILD (the process an extra actually runs in).

Started by wdgo_extras_sandbox.SandboxHost as a fresh interpreter:

    python -I -B wdgo_extras_child.py <ipc-fd>

Order matters and is the whole point of this file:

  1. (still root, trusted code only) read the "hello" and the extra's sources,
     which the host SENDS over the socket (the approved snapshot - this process
     never reads the extra's folder), verify their exact hash, check that the
     parent is the game that started us, pre-import the allowed stdlib modules.
  2. LOCK DOWN — new network/IPC/UTS namespaces, rlimits, chroot into an empty
     root-owned directory, drop to a dedicated unprivileged uid/gid for good,
     no_new_privs, die-with-parent.
  3. only now execute the extra, against the same `ctx` facade as Phase 1, with a
     bridge that turns draw calls into ops and capability calls into broker RPCs.

After step 2 the process has: no filesystem (so `import` of anything not already
loaded fails — the pre-import list IS the stdlib allowlist), no network, no
ability to fork, no way back to root, and exactly one file descriptor that
matters: the socket to the host. The host validates everything sent over it.

If lockdown is required and any step fails, no extra code is ever executed. A
process started as root never runs extra code without the full jail.
"""
import os
import sys


def _die(code=0):
    try:
        sys.stdout.flush()
    except Exception:
        pass
    os._exit(code)


# Modules an extra may `import` inside the sandbox. Everything else is unreachable
# after the chroot. Keep this list boring: pure computation, no I/O, no processes.
ALLOWED_STDLIB = (
    "math", "cmath", "json", "time", "random", "re", "collections", "collections.abc",
    "itertools", "functools", "operator", "datetime", "_strptime", "calendar", "struct",
    "base64", "binascii", "hashlib", "hmac", "string", "textwrap", "statistics", "enum",
    "dataclasses", "typing", "abc", "copy", "heapq", "bisect", "array", "decimal",
    "fractions", "numbers", "zlib", "colorsys", "difflib", "unicodedata", "io", "codecs",
    "weakref", "contextlib", "types", "pprint", "secrets", "fnmatch", "html", "csv",
    "uuid", "encodings.utf_8", "encodings.ascii", "encodings.latin_1",
    "encodings.utf_16", "encodings.cp1250", "encodings.cp1252", "encodings.idna",
)

# Never importable from inside the sandbox, even though the runner used some of them.
_SCRUB = ("ctypes", "_ctypes", "subprocess", "_posixsubprocess", "multiprocessing",
          "socket", "_socket", "select", "selectors", "resource", "importlib.resources",
          "shutil", "tempfile", "pty", "fcntl", "mmap", "signal")


def _preimport():
    import importlib
    for name in ALLOWED_STDLIB:
        try:
            importlib.import_module(name)
        except Exception:
            pass


def _pin_timezone():
    """After the chroot /etc/localtime is gone; freeze the current UTC offset in TZ
    so time.localtime() inside the extra still matches the device clock."""
    import time
    try:
        off = time.localtime().tm_gmtoff          # seconds east of UTC
        sign = "-" if off >= 0 else "+"           # POSIX TZ sign is inverted
        off = abs(int(off))
        os.environ["TZ"] = "WDG%s%d:%02d" % (sign, off // 3600, (off % 3600) // 60)
        time.tzset()
    except Exception:
        pass


_PR_SET_PDEATHSIG, _PR_GET_PDEATHSIG, _PR_SET_DUMPABLE, _PR_SET_NO_NEW_PRIVS = 1, 2, 4, 38


def _arm_pdeathsig(libc=None) -> bool:
    """Ask the kernel to SIGKILL us when the game dies; True when confirmed."""
    if not sys.platform.startswith("linux"):
        return False
    try:
        import ctypes
        import signal
        libc = libc or ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_PDEATHSIG, int(signal.SIGKILL), 0, 0, 0) != 0:
            return False
        got = ctypes.c_int(0)
        if libc.prctl(_PR_GET_PDEATHSIG, ctypes.byref(got), 0, 0, 0) != 0:
            return False
        return got.value == int(signal.SIGKILL)
    except Exception:
        return False


def _lockdown(hello, ipc_fd, ppid0) -> dict:
    """Establish the kernel jail. Returns {"level": "full"|"none"|"failed", "why": str}.
    "none" = this platform cannot jail (desktop simulator, never root); "failed" = it
    should have worked and did not. Only "full" is acceptable when the host requires
    isolation, and always when this process is root."""
    if not sys.platform.startswith("linux"):
        if os.geteuid() == 0:
            return {"level": "failed", "why": "cannot isolate a root process on this platform"}
        return {"level": "none", "why": "not Linux"}
    if os.geteuid() != 0:
        return {"level": "none", "why": "not started as root"}
    step = "init"
    try:
        import resource
        import stat
        uid, gid = int(hello["uid"]), int(hello["gid"])
        jail = str(hello["jail"])
        if uid < 1000 or gid < 1000:
            raise ValueError("refusing privileged uid/gid")

        step = "libc"
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)

        step = "stdio"
        dn = os.open("/dev/null", os.O_RDWR)
        for fd in (0, 1, 2):
            if fd != ipc_fd:
                os.dup2(dn, fd)
        if dn > 2:
            os.close(dn)
        for fd in range(3, 512):
            if fd != ipc_fd:
                try:
                    os.close(fd)
                except OSError:
                    pass

        step = "jail dir"
        os.makedirs(jail, mode=0o555, exist_ok=True)
        st = os.lstat(jail)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or (st.st_mode & 0o022):
            raise OSError("jail dir is not a root-owned, non-writable directory")
        if os.listdir(jail):
            raise OSError("jail dir is not empty")

        step = "namespaces"
        flags = 0x40000000 | 0x08000000 | 0x04000000      # NEWNET | NEWIPC | NEWUTS
        if hasattr(os, "unshare"):
            os.unshare(flags)
        elif libc.unshare(flags) != 0:
            raise OSError(ctypes.get_errno(), "unshare failed")

        step = "rlimits"
        mem = int(hello.get("mem") or 512 * 1024 * 1024)
        resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
        resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))   # no fork, no threads

        step = "chroot"
        os.chroot(jail)
        os.chdir("/")

        step = "drop privileges"
        os.setgroups([])
        os.setresgid(gid, gid, gid)
        os.setresuid(uid, uid, uid)

        step = "verify"
        if os.getuid() != uid or os.geteuid() != uid or os.getgid() != gid:
            raise OSError("uid/gid did not change")
        regained = False
        try:
            os.setuid(0)
            regained = True
        except OSError:
            pass
        if regained or os.geteuid() == 0:
            raise OSError("privileges can be regained")
        if os.listdir("/"):
            raise OSError("filesystem is still visible")

        step = "prctl"
        if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            raise OSError("no_new_privs failed")
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
            raise OSError("set_dumpable failed")
        # The uid change above cleared any earlier death signal: arm it again (and
        # confirm it took), then re-check the parent. If the game died before the
        # signal was armed we were re-parented, and must not go on.
        if not _arm_pdeathsig(libc):
            raise OSError("parent-death signal could not be armed")
        if os.getppid() != ppid0:
            _die(0)
        return {"level": "full", "why": "chroot+uid %d+netns+rlimits" % uid}
    except Exception as exc:
        return {"level": "failed", "why": "%s: %s: %s" % (step, type(exc).__name__, exc)}


def _scrub():
    for k in list(os.environ.keys()):
        if k != "TZ":
            try:
                del os.environ[k]
            except Exception:
                pass
    for name in list(sys.modules.keys()):
        if name in _SCRUB or name.split(".")[0] in _SCRUB:
            sys.modules.pop(name, None)
    sys.path[:] = []
    sys.argv[:] = ["extra"]


class _MemImporter:
    """Serves the extra's own modules from the sources read before lockdown, and
    turns any other import into a clear error (the stdlib is not on disk any more)."""
    def __init__(self, src, origin_prefix):
        self._mods = {}
        self._prefix = origin_prefix
        for rel, data in src.items():
            if not rel.endswith(".py"):
                continue
            parts = rel[:-3].split("/")
            if parts[-1] == "__init__":
                name, pkg = ".".join(parts[:-1]), True
            else:
                name, pkg = ".".join(parts), False
            if name and all(p.isidentifier() for p in name.split(".")):
                self._mods[name] = (rel, data, pkg)

    def find_spec(self, name, path=None, target=None):
        import importlib.util
        ent = self._mods.get(name)
        if ent is None:
            raise ModuleNotFoundError(
                "No module named %r (not available inside the EXTRAS sandbox)" % name,
                name=name)
        return importlib.util.spec_from_loader(
            name, self, origin=self._prefix + ent[0], is_package=ent[2])

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        rel, data, _pkg = self._mods[module.__name__]
        exec(compile(data.decode("utf-8"), self._prefix + rel, "exec"), module.__dict__)


def _describe(exc, prefix) -> str:
    """'ZeroDivisionError: division by zero (main.py:42 in on_frame)' without the
    traceback module (it lazily imports things that no longer exist on disk)."""
    where = ""
    tb = exc.__traceback__
    while tb is not None:
        fn = tb.tb_frame.f_code.co_filename
        if fn.startswith(prefix):
            where = " (%s:%d in %s)" % (fn[len(prefix):], tb.tb_lineno,
                                        tb.tb_frame.f_code.co_name)
        tb = tb.tb_next
    msg = str(exc)
    return ("%s: %s%s" % (type(exc).__name__, msg[:200], where))[:300]


def _receive_sources(hello, recv_msg, wx, base64) -> dict:
    """Collect the approved sources the host sends after the hello:
    hello.src = [[relpath, size], ...], then {"t":"src", "i", "o", "b": base64}
    chunks in order. Every bound the host's collect_sources() applies is applied
    again here; any deviation raises."""
    table = hello.get("src")
    if not isinstance(table, list) or not table or len(table) > wx.SRC_MAX_FILES:
        raise ValueError("bad source table")
    names, sizes, total = [], [], 0
    for ent in table:
        if not (isinstance(ent, list) and len(ent) == 2 and isinstance(ent[0], str)
                and isinstance(ent[1], int) and not isinstance(ent[1], bool)):
            raise ValueError("bad source table entry")
        rel, size = ent
        parts = rel.split("/")
        if (len(rel) > 256 or len(parts) > 4 or rel in names
                or any(not p or p.startswith(".") or "\x00" in p or "\\" in p for p in parts)
                or not (rel.endswith(".py") or rel.endswith(".png") or rel == "extra.json")):
            raise ValueError("bad source name %r" % rel[:80])
        if not 0 <= size <= wx.SRC_MAX_FILE_BYTES:
            raise ValueError("bad source size")
        total += size
        if total > wx.SRC_MAX_TOTAL_BYTES:
            raise ValueError("sources too large")
        names.append(rel)
        sizes.append(size)
    bufs = [bytearray() for _ in names]
    fi = 0
    while True:
        while fi < len(names) and len(bufs[fi]) == sizes[fi]:
            fi += 1
        if fi >= len(names):
            break
        msg = recv_msg()
        if msg.get("t") != "src" or msg.get("i") != fi or msg.get("o") != len(bufs[fi]) \
                or not isinstance(msg.get("b"), str):
            raise ValueError("out-of-order source data")
        part = base64.b64decode(msg["b"], validate=True)
        if not part or len(bufs[fi]) + len(part) > sizes[fi]:
            raise ValueError("source data larger than announced")
        bufs[fi] += part
    return {rel: bytes(b) for rel, b in zip(names, bufs)}


def main():
    import socket
    ppid0 = os.getppid()          # the host game process; used for the pdeathsig race guard
    ipc_fd = int(sys.argv[1])
    sock = socket.socket(fileno=ipc_fd)
    sock.settimeout(10.0)
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import collections
    import time
    import types
    import base64
    import wdgo_extras as wx
    import wdgo_extras_ipc as ipc

    framer = ipc.Framer()
    inbox = collections.deque()
    _arm_pdeathsig()              # while still root; re-armed after the uid change

    def recv_msg():
        while not inbox:
            try:
                data = sock.recv(65536)
            except Exception:
                _die(0)
            if not data:
                _die(0)                 # host is gone
            try:
                inbox.extend(framer.feed(data))
            except Exception:
                _die(3)
        return inbox.popleft()

    def send(obj):
        try:
            sock.sendall(ipc.pack(obj))
        except ipc.ProtocolError:
            raise
        except Exception:
            _die(0)

    # ---- 1. trusted setup (root): hello, sources, pre-imports -------------
    hello = recv_msg()
    if hello.get("t") != "hello" or hello.get("proto") != ipc.PROTO:
        _die(2)
    hp = hello.get("host_pid")
    if not isinstance(hp, int) or isinstance(hp, bool) or hp != ppid0:
        _die(2)                   # not started by the game that is talking to us
    try:
        src = _receive_sources(hello, recv_msg, wx, base64)
        if wx.sources_hash(src) != hello["sha"]:
            raise ValueError("sources do not match the approved fingerprint")
        entry_file = str(hello["entry_file"])
        entry_symbol = str(hello["entry_symbol"])
        entry_src = src[entry_file].decode("utf-8")
    except Exception as exc:
        send({"t": "fault", "err": "cannot load extra: %s: %s" % (type(exc).__name__, exc)})
        _die(1)
    extra_id = str(hello["id"])
    prefix = "<extra:%s>/" % extra_id
    _preimport()
    _pin_timezone()

    # ---- 2. lock down -------------------------------------------------------
    started_as_root = os.geteuid() == 0
    iso = _lockdown(hello, ipc_fd, ppid0)
    if iso["level"] != "full" and (hello.get("iso") or iso["level"] != "none"
                                   or started_as_root or os.geteuid() == 0):
        send({"t": "ready", "iso": iso})          # host will refuse and kill us
        _die(1)
    _scrub()
    sock.settimeout(None)
    # LAST on meta_path: builtin/frozen modules keep resolving; everything that
    # would have come from disk falls through to the extra's own modules or a clear error.
    sys.meta_path.append(_MemImporter(src, prefix))
    img_src = {r: bytes(d) for r, d in src.items() if r.endswith(".png")}
    del src
    send({"t": "ready", "iso": iso})

    # ---- 3. the extra, behind the Phase-1 ctx facade ------------------------
    snap = {"view": list(hello.get("view") or [800, 480]), "down": set(),
            "pressed": set(), "chars": [], "gps": None, "exit": False}
    ops, logs = [], []
    mw = hello.get("mw") or [0.55, 0.0]
    call_id = [0]

    def call(method, *args):
        """Synchronous broker RPC. Frames/exit that arrive while waiting are kept."""
        call_id[0] += 1
        cid = call_id[0]
        send({"t": "call", "id": cid, "m": method, "a": list(args)})
        held = []
        while True:
            msg = recv_msg()
            if msg.get("t") == "reply" and msg.get("id") == cid:
                inbox.extendleft(reversed(held))
                if msg.get("ok"):
                    return msg.get("v")
                err = str(msg.get("err", "broker error"))
                if err.startswith("PermissionError"):
                    raise PermissionError(err.partition(": ")[2] or err)
                raise RuntimeError(err)
            held.append(msg)

    def r2(v):
        return round(float(v), 2)

    def add(op):
        if len(ops) < ipc.MAX_OPS:
            ops.append(op)

    def log(msg, level="info"):
        if len(logs) < ipc.MAX_LOGS:
            logs.append([level if level in ("info", "ok", "warn", "error") else "info",
                         str(msg)[:ipc.MAX_LOG_LEN]])

    def chars():
        out, snap["chars"] = snap["chars"], []
        return out

    b = types.SimpleNamespace()
    b.draw_text = lambda s, x, y, size, color, bold: add(
        ["t", str(s)[:ipc.MAX_TEXT], r2(x), r2(y), r2(size), str(color), bool(bold)])
    b.draw_rect = lambda x, y, w, h, color, fill, alpha: add(
        ["r", r2(x), r2(y), r2(w), r2(h), str(color), bool(fill), int(alpha)])
    b.draw_line = lambda x1, y1, x2, y2, color, thick: add(
        ["l", r2(x1), r2(y1), r2(x2), r2(y2), str(color), r2(thick)])
    b.draw_circle = lambda x, y, r, color: add(["c", r2(x), r2(y), r2(r), str(color)])

    img_sent, img_todo = set(), {}       # todo: name -> [w, h, rgba, next row]

    def draw_image(name, w, h, rgba, x, y, scale, alpha):
        # Pixels travel once, as raw RGBA the host re-checks, in strips of rows spread
        # over a few frames (every message stays small); afterwards only the name.
        if name not in img_sent and name not in img_todo:
            img_todo[name] = [int(w), int(h), rgba, 0]
        add(["i", name, r2(x), r2(y), int(scale), int(alpha)])

    def image_strip():
        """The next strip to ship: ({name: [w, h, y0, base64 rows]}, commit) or (None, None)."""
        if not img_todo:
            return None, None
        name = next(iter(img_todo))
        w, h, rgba, y0 = img_todo[name]
        rows = max(1, ipc.IMG_STRIP_BYTES // (w * 4))
        y1 = min(h, y0 + rows)

        def commit():
            if y1 >= h:
                img_sent.add(name)
                del img_todo[name]
            else:
                img_todo[name][3] = y1
        return {name: [w, h, y0, base64.b64encode(rgba[y0 * w * 4:y1 * w * 4]).decode("ascii")]}, commit

    b.draw_image = draw_image
    b.measure = lambda s, size=16: max(6, min(80, size)) * (mw[0] * len(str(s)) + mw[1])
    b.key_down = lambda name: str(name).lower() in snap["down"]
    b.key_pressed = lambda name: str(name).lower() in snap["pressed"]
    b.chars = chars
    b.view = lambda: (snap["view"][0], snap["view"][1])
    b.gps = lambda: (dict(snap["gps"]) if snap["gps"] and snap["gps"].get("valid") else None)
    b.loot_networks = lambda: call("loot.networks") or []
    b.loot_counts = lambda: call("loot.counts") or {}
    b.loot_save = lambda name, text: call("loot.save", str(name), str(text))
    b.log = log
    b.release_all = lambda: None

    class _RpcStorage(wx._Storage):
        def __init__(self):
            self.path = ""

        def read(self, name, default=""):
            v = call("storage.read", str(name))
            return default if v is None else v

        def write(self, name, text):
            return bool(call("storage.write", str(name), str(text)))

    class _LogStream:
        def __init__(self, level):
            self._lvl, self._buf = level, ""

        def write(self, s):
            self._buf += str(s)
            while "\n" in self._buf:
                line, self._buf = self._buf.split("\n", 1)
                if line.strip():
                    log(line, self._lvl)
            self._buf = self._buf[-ipc.MAX_LOG_LEN:]
            return len(s)

        def flush(self):
            pass

    sys.stdout, sys.stderr = _LogStream("info"), _LogStream("warn")

    meta = wx.ExtraMeta("/" + extra_id)
    meta.permissions = [p for p in (hello.get("perms") or []) if p in wx._KNOWN_PERMS]
    ctx = wx.ExtraContext(b, meta, "", storage=_RpcStorage(), images=img_src)

    def fault(exc):
        send({"t": "fault", "err": _describe(exc, prefix)})
        _die(1)

    try:
        mod = types.ModuleType("wdgo_extra_%s" % extra_id)
        mod.__file__ = prefix + entry_file
        sys.modules[mod.__name__] = mod
        exec(compile(entry_src, prefix + entry_file, "exec"), mod.__dict__)
        cls = getattr(mod, entry_symbol, None)
        if cls is None:
            raise AttributeError("entry symbol '%s' not found" % entry_symbol)
        inst = cls()
        for hook in ("on_load", "on_enter"):
            fn = getattr(inst, hook, None)
            if fn is not None:
                fn(ctx)
    except BaseException as exc:
        if isinstance(exc, SystemExit):
            _die(0)
        fault(exc)

    on_frame = getattr(inst, "on_frame", None)
    while True:
        msg = recv_msg()
        t = msg.get("t")
        if t == "frame":
            v = msg.get("view") or snap["view"]
            snap["view"] = [v[0], v[1]]
            snap["down"] = set(msg.get("down") or [])
            snap["pressed"] = set(msg.get("pressed") or [])
            snap["chars"] = list(msg.get("chars") or [])
            snap["gps"] = msg.get("gps")
            del ops[:]
            del logs[:]
            try:
                if on_frame is not None:
                    on_frame(ctx, float(msg.get("dt") or 0.0))
            except BaseException as exc:
                if isinstance(exc, SystemExit):
                    _die(0)
                fault(exc)
            try:
                out = {"t": "frame", "n": msg.get("n"), "ops": ops, "logs": logs}
                strip, commit = image_strip()
                if strip:
                    out["imgs"] = strip
                send(out)
                if commit:
                    commit()
            except ipc.ProtocolError:
                # frame too big to ship: drop the drawing, keep the extra alive
                send({"t": "frame", "n": msg.get("n"), "ops": [],
                      "logs": [["warn", "frame dropped: too much drawing"]]})
        elif t == "exit":
            try:
                fn = getattr(inst, "on_exit", None)
                if fn is not None:
                    fn(ctx)
            except BaseException:
                pass
            send({"t": "exited"})
            _die(0)
        # anything else (stray reply) is ignored


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        _die(4)
