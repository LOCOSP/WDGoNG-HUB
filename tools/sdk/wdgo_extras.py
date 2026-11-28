"""WatchDogsGo EXTRAS — platform core (manifest, discovery, consent, ctx facade).

Third-party mini-apps dropped into ~/.wdgo/extras/<id>/ are discovered here,
listed under the EXTRAS menu, and driven through a small, documented `ctx`
facade. See docs/EXTRAS_spec.md (design) and docs/EXTRAS_authoring.md (author
guide).

Runtime: every extra runs in the SANDBOX (wdgo_extras_sandbox: a non-root,
jailed child process + capability broker). The in-process host below exists
for the desktop simulator only; it never runs while the game is root.

What the player approves is exactly what runs: launch() reads the extra ONCE
into memory (a Snapshot: manifest + permissions + code + images, with its
content hash), the consent card shows that snapshot, and the runtime is fed
those same bytes - the extra's folder is never re-read after the decision.

Every file the (root) game touches on behalf of an extra goes through the small
safe-file layer below: directories are opened component by component without
following symlinks, files are opened O_NOFOLLOW|O_NONBLOCK and checked with
fstat, reads are size-capped, writes go to a fresh private temp file that is
fsync'ed and renamed into place.

This module is pure stdlib — it never imports raylib. The host (main.py) injects
a small `bridge` of drawing/input/sensor callables; everything raylib-specific
stays in main.py.
"""
import errno
import importlib.util
import json
import os
import re
import stat
import sys
import time
import traceback

EXTRAS_API = 2                       # bump on any breaking change to ctx / hook contract

_ID_RE = re.compile(r"^[a-z0-9_]{3,32}$")
# capabilities an extra may declare in its manifest "permissions" (v1 grantable).
# draw / input / log / clock / storage are always available and need no permission.
_KNOWN_PERMS = {"gps", "loot_read", "loot_write"}
PALETTE = ("txt", "hi", "dim", "teal", "danger", "warn",
           "success", "magenta", "ice", "void", "edge", "purple")

# ---- limits (bounded memory / time for everything read from an extra) ----
MANIFEST_MAX = 32 * 1024            # extra.json, checked before JSON parsing
VERSION_MAX = 16                    # characters in "version"
PERMS_MAX = 16                      # entries in "permissions" (before de-duplication)
PKG_MAX_ENTRIES = 1024              # names seen while walking one package (skipped ones too)
ROOT_MAX_ENTRIES = 256              # names seen in one extras folder
STATE_FILE_MAX = 256 * 1024         # registry / consent / trust json
STORAGE_MAX_FILE = 256 * 1024       # ctx.storage: one file
STORAGE_MAX_FILES = 64              # ctx.storage: files per extra
LOOT_SAVE_MAX = 1024 * 1024         # ctx.loot_save: one request
LOOT_MAX_BYTES = 16 * 1024 * 1024   # loot/extras/<id>/ total
LOOT_MAX_FILES = 128                # loot/extras/<id>/ files
FS_RESERVE_BYTES = 64 * 1024 * 1024  # free space an extra may never eat into
FS_RESERVE_INODES = 256
KEEP_BACKUPS = 3                    # previous versions kept per extra after an update


# ======================================================================
# Safe-file layer (shared by the scanner, the broker, the registry and the installer)
# ======================================================================
class UnsafePath(OSError):
    """A path component was a symlink, the wrong type, or not ours."""


_O_DIR = (os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
          | getattr(os, "O_CLOEXEC", 0))
_O_FILE = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
           | getattr(os, "O_CLOEXEC", 0))
_O_NEW = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
          | getattr(os, "O_CLOEXEC", 0))
_TMP_PREFIX = ".wdgo-tmp-"


def _euid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else -1


def _trusted_uid(uid) -> bool:
    return uid == 0 or uid == _euid()


def _guards_entries(st) -> bool:
    """A directory in which only root or this process's user can create or rename
    entries (or a sticky dir such as /tmp, where only an entry's owner can)."""
    return (stat.S_ISDIR(st.st_mode) and _trusted_uid(st.st_uid)
            and (not (st.st_mode & 0o022) or bool(st.st_mode & stat.S_ISVTX)))


def _check_name(name):
    if (not isinstance(name, str) or not name or name in (".", "..") or "/" in name
            or "\x00" in name or len(name) > 255):
        raise UnsafePath(errno.EINVAL, "bad file name %r" % (name,))


def open_dir(path, create=False, mode=0o755, private=False) -> int:
    """Open a directory as an fd, walking it component by component from "/" with
    O_DIRECTORY|O_NOFOLLOW. A symlinked component is followed only when root or we
    own both the link and a directory nobody else can write (e.g. macOS /var); the
    LAST component is never a symlink. create=True makes missing components with
    `mode`. private=True also requires every directory on the way to be writable by
    root/us only and the last one to be ours. Caller closes the fd."""
    parts = [p for p in os.path.abspath(str(path)).split("/") if p]
    fd = os.open("/", _O_DIR)
    hops = 0
    try:
        i = 0
        while i < len(parts):
            name = parts[i]
            last = i == len(parts) - 1
            try:
                nfd = os.open(name, _O_DIR, dir_fd=fd)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(name, mode, dir_fd=fd)
                except FileExistsError:
                    pass
                nfd = os.open(name, _O_DIR, dir_fd=fd)
            except OSError as exc:
                if exc.errno not in (errno.ELOOP, errno.ENOTDIR, getattr(errno, "EMLINK", -1)):
                    raise
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISLNK(st.st_mode):
                    raise UnsafePath(errno.ENOTDIR, "not a directory: %s" % name)
                if last:
                    raise UnsafePath(errno.ELOOP, "%s is a symlink - refused" % path)
                if hops >= 8 or not (_trusted_uid(st.st_uid) and _guards_entries(os.fstat(fd))):
                    raise UnsafePath(errno.ELOOP, "untrusted symlink in %s" % path)
                hops += 1
                target = os.readlink(name, dir_fd=fd)
                if target.startswith("/"):
                    os.close(fd)
                    fd = os.open("/", _O_DIR)
                parts = [p for p in target.split("/") if p and p != "."] + parts[i + 1:]
                i = 0
                continue
            if private:
                st = os.fstat(nfd)
                ok = _guards_entries(st) and (not last or (st.st_uid == _euid()
                                                           and not st.st_mode & 0o022))
                if not ok:
                    os.close(nfd)
                    raise UnsafePath(errno.EPERM, "%s is writable by another account" % path)
            os.close(fd)
            fd = nfd
            i += 1
        return fd
    except BaseException:
        os.close(fd)
        raise


def _subdir(dfd, name, create=False, mode=0o755) -> int:
    """Open one child directory of an open directory (never through a symlink)."""
    _check_name(name)
    try:
        return os.open(name, _O_DIR, dir_fd=dfd)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode, dir_fd=dfd)
        except FileExistsError:
            pass
        return os.open(name, _O_DIR, dir_fd=dfd)


def read_at(dfd, name, limit, single_link=False, own=False) -> bytes:
    """Read a small REGULAR file `name` inside the open directory `dfd`. Symlinks,
    FIFOs, devices and directories are refused without blocking; more than `limit`
    bytes raises ValueError. single_link refuses a hard-linked file, own a file not
    owned by this process's user."""
    _check_name(name)
    fd = os.open(name, _O_FILE, dir_fd=dfd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise UnsafePath(errno.EINVAL, "%s is not a regular file" % name)
        if single_link and st.st_nlink != 1:
            raise UnsafePath(errno.EMLINK, "%s is hard-linked - refused" % name)
        if own and st.st_uid != _euid():
            raise UnsafePath(errno.EPERM, "%s has a foreign owner - refused" % name)
        if st.st_size > limit:
            raise ValueError("%s is too large (max %d bytes)" % (name, limit))
        chunks, n = [], 0
        while n <= limit:
            b = os.read(fd, min(65536, limit + 1 - n))
            if not b:
                break
            chunks.append(b)
            n += len(b)
        if n > limit:
            raise ValueError("%s is too large (max %d bytes)" % (name, limit))
        return b"".join(chunks)
    finally:
        os.close(fd)


def write_atomic_at(dfd, name, data, mode=0o600):
    """Replace `name` in the open directory `dfd` atomically: a fresh, unique temp
    file (O_EXCL|O_NOFOLLOW, never an existing name), fsync, rename, fsync of the
    directory. An existing symlink/hard link under `name` is replaced, never written
    through. Raises on any error and leaves the previous file intact."""
    _check_name(name)
    tmp = "%s%s-%s" % (_TMP_PREFIX, os.urandom(8).hex(), name[:32])
    fd = os.open(tmp, _O_NEW, mode, dir_fd=dfd)
    try:
        try:
            view = memoryview(bytes(data))
            while view:
                view = view[os.write(fd, view):]
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise
    try:
        os.fsync(dfd)
    except OSError:
        pass


class dir_lock:
    """Exclusive flock on an open directory fd (between threads AND processes):
    `with dir_lock(fd): ...`. Gives up after `timeout` seconds."""
    def __init__(self, dfd, timeout=15.0):
        self._fd = os.dup(dfd)
        self._timeout = timeout

    def __enter__(self):
        import fcntl
        end = time.monotonic() + self._timeout
        while True:
            try:
                fcntl.flock(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except BlockingIOError:
                if time.monotonic() > end:
                    os.close(self._fd)
                    raise TimeoutError("extras state is locked by another operation")
                time.sleep(0.02)
            except BaseException:
                os.close(self._fd)
                raise

    def __exit__(self, *exc):
        import fcntl
        try:
            fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
        return False


def fs_has_room(dfd, need_bytes, inodes=1) -> bool:
    """True if writing need_bytes (+inodes) keeps the game's reserve free."""
    try:
        sv = os.fstatvfs(dfd)
    except (OSError, AttributeError):
        return True
    free = sv.f_bavail * sv.f_frsize
    if free - int(need_bytes) < FS_RESERVE_BYTES:
        return False
    if sv.f_files and sv.f_favail - inodes < FS_RESERVE_INODES:
        return False
    return True


def secure_chain(path) -> bool:
    """True when no account other than root / this process's user can replace or
    rename any directory on `path` (the part that does not exist yet would be
    created by us). Trusted symlinks (see open_dir) are followed."""
    parts = [p for p in os.path.abspath(str(path)).split("/") if p]
    cur, hops = "/", 0
    try:
        if not _guards_entries(os.lstat("/")):
            return False
        i = 0
        while i < len(parts):
            nxt = os.path.join(cur, parts[i])
            try:
                st = os.lstat(nxt)
            except FileNotFoundError:
                return True
            if stat.S_ISLNK(st.st_mode):
                if hops >= 8 or not _trusted_uid(st.st_uid):
                    return False
                hops += 1
                tgt = os.readlink(nxt)
                base = "/" if tgt.startswith("/") else cur
                parts = [p for p in os.path.normpath(os.path.join(base, tgt)).split("/") if p] \
                    + parts[i + 1:]
                cur, i = "/", 0
                continue
            if not _guards_entries(st):
                return False
            cur = nxt
            i += 1
        return True
    except OSError:
        return False


def _rmtree_at(dfd, name):
    import shutil
    try:
        shutil.rmtree(name, dir_fd=dfd)          # fd-based, never follows symlinks
    except NotADirectoryError:
        os.unlink(name, dir_fd=dfd)
    except FileNotFoundError:
        pass


def _lexists_at(dfd, name) -> bool:
    try:
        os.stat(name, dir_fd=dfd, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


# ======================================================================
# Locations
# ======================================================================
def extras_root() -> str:
    """User drop-in dir for third-party extras (survives game OTA)."""
    return os.path.join(os.path.expanduser("~"), ".wdgo", "extras")


def examples_dir() -> str:
    """Bundled example extras, in the repo. Scanned directly so they always
    match the installed game version (they update with the game's OTA)."""
    return os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "extras", "examples")


PROTECTED_STATE_DIR = "/var/lib/wdgo/extras"


def state_dir() -> str:
    """Where decisions live (installed registry, consent, trust pins, extra data).
    ~/.wdgo when no other account can rename anything on that path (the game's
    HOME is root's own, or we are not root); otherwise, for a root game with a
    user-owned HOME, a root-only directory under /var/lib. Old decisions in an
    unprotected HOME are deliberately NOT imported - the player is asked again."""
    env = os.environ.get("WDGO_EXTRAS_STATE_DIR")
    if env and (_euid() != 0 or secure_chain(env)):
        return os.path.abspath(env)
    home = os.path.join(os.path.expanduser("~"), ".wdgo")
    if _euid() != 0 or secure_chain(home):
        return home
    return PROTECTED_STATE_DIR


def data_root() -> str:
    """Persistent per-extra writable data, separate from the extra's code so it
    survives game updates and works for in-repo examples too (<data_root>/<id>/)."""
    return os.path.join(state_dir(), "extras-data")


def legacy_data_dir(d):
    """The pre-hardening location of the data dir `d` (~/.wdgo/extras-data/<id>)
    when data_root() moved to the protected state dir, else None."""
    try:
        eid = os.path.basename(os.path.abspath(d))
        if os.path.abspath(d) != os.path.abspath(os.path.join(data_root(), eid)):
            return None
        old = os.path.join(os.path.expanduser("~"), ".wdgo", "extras-data", eid)
        return old if os.path.abspath(old) != os.path.abspath(d) else None
    except Exception:
        return None


# ======================================================================
# Manifest
# ======================================================================
class ExtraMeta:
    def __init__(self, d):
        self.dir = d
        self.id = os.path.basename(d.rstrip(os.sep))
        self.name = self.id
        self.author = ""
        self.version = "0.0.0"
        self.api = 0
        self.entry = "main:Extra"
        self.entry_symbol = "Extra"
        self.entry_file = "main.py"
        self.permissions = []
        self.hardware = []
        self.icon = None
        self.description = ""      # one-line (menu subtitle + hub card)
        self.about = ""            # long "what it does / how it works" (hub detail)
        self.category = "misc"
        self.tags = []
        self.homepage = ""
        self.error = None          # str -> invalid: shown greyed, cannot launch
        self.update_note = None    # set when a newer version superseded an installed copy


# digits-and-dots (1 to 4 numbers) with an optional -pre-release / +build suffix, ASCII only
_VERSION_RE = re.compile(r"^[0-9]{1,6}(?:\.[0-9]{1,6}){0,3}(?:[-+][0-9A-Za-z][0-9A-Za-z.-]{0,14})?$")
_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")


def valid_version(v) -> bool:
    return isinstance(v, str) and len(v) <= VERSION_MAX and bool(_VERSION_RE.match(v))


def _vkey(v):
    """Comparable key for a manifest version; never raises. Numbers compare as
    numbers (1.10 > 1.9), a '-suffix' pre-release sorts before its release, '+build'
    is ignored, and anything invalid sorts below every valid version."""
    if not valid_version(v):
        return (0, (0, 0, 0, 0), 0, "")
    core = re.match(r"[0-9.]+", v).group(0).rstrip(".")
    rest = v[len(core):]
    nums = tuple(int(x) for x in core.split("."))
    nums = (nums + (0, 0, 0, 0))[:4]
    if rest.startswith("-"):
        return (1, nums, 0, rest[1:].split("+")[0])
    return (1, nums, 1, "")


def _norm_perms(v):
    """Sorted unique permission names, or None when the value is not a list of str."""
    if not isinstance(v, list) or len(v) > PERMS_MAX or not all(isinstance(p, str) for p in v):
        return None
    return sorted(set(v))


def _entry_file_ok(rel) -> bool:
    parts = rel.split("/")
    return (rel.endswith(".py") and len(parts) <= 4
            and all(p and not p.startswith(".") and "\\" not in p and "\x00" not in p
                    for p in parts))


def _meta_from_manifest(d, raw, has_file) -> ExtraMeta:
    """Parse + validate extra.json bytes. has_file(relpath) -> bool says whether the
    package has that regular file. Never raises: problems land in meta.error."""
    m = ExtraMeta(d)
    if raw is None:
        m.error = "no extra.json"
        return m
    if len(raw) > MANIFEST_MAX:
        m.error = "extra.json is too large (max %d bytes)" % MANIFEST_MAX
        return m
    try:
        doc = json.loads(bytes(raw).decode("utf-8"))
    except Exception as exc:
        m.error = "bad extra.json: %s" % str(exc)[:120]
        return m
    e = doc.get("extra", doc) if isinstance(doc, dict) else {}
    if not isinstance(e, dict):
        e = {}
    try:
        m.name = str(e.get("name", m.id))[:32]
        m.author = str(e.get("author", ""))[:40]
        ver = e.get("version", "0.0.0")
        if isinstance(ver, (int, float)) and not isinstance(ver, bool):
            ver = str(ver)                       # "version": 1.2 written as a number
        m.version = (ver if isinstance(ver, str) else "?")[:VERSION_MAX]
        api = e.get("api", 0)
        if isinstance(api, str) and len(api) <= 4 and api.isascii() and api.isdigit():
            api = int(api)
        elif isinstance(api, float) and api.is_integer() and 0 < api < 1000:
            api = int(api)
        m.api = api if isinstance(api, int) and not isinstance(api, bool) and 0 < api < 1000 else 0
        m.entry = str(e.get("entry", "main:Extra"))[:128]
        m.entry_symbol = m.entry.partition(":")[2] or "Extra"
        _mf = m.entry.partition(":")[0] or "main"
        m.entry_file = _mf if _mf.endswith(".py") else _mf + ".py"
        perms = _norm_perms(e.get("permissions") if e.get("permissions") is not None else [])
        m.permissions = perms if perms is not None else []
        hw = e.get("hardware")
        m.hardware = [str(x)[:20] for x in hw][:8] if isinstance(hw, list) else []
        m.icon = e.get("icon") if isinstance(e.get("icon"), str) else None
        m.description = str(e.get("description", ""))[:120]
        m.about = str(e.get("about", ""))[:2000]
        m.category = str(e.get("category", "misc"))[:24]
        tags = e.get("tags")
        m.tags = [str(x)[:20] for x in tags][:8] if isinstance(tags, list) else []
        m.homepage = str(e.get("homepage", ""))[:200]
    except Exception as exc:
        m.error = "manifest error: %s" % str(exc)[:120]
        return m
    # ---- validation (reject -> greyed, with a reason the author can read) ----
    if not _ID_RE.match(m.id):
        m.error = "bad id '%s' (need ^[a-z0-9_]{3,32}$ and == folder name)" % m.id[:40]
        return m
    if not valid_version(ver):
        m.error = "bad version %r (digits and dots, e.g. 1.2.0, max %d chars)" % (
            m.version, VERSION_MAX)
        return m
    if m.api <= 0:
        m.error = "manifest missing a valid integer 'api'"
        return m
    if m.api > EXTRAS_API:
        m.error = "needs api %d (game has %d) — update the game [U]" % (m.api, EXTRAS_API)
        return m
    if not _entry_file_ok(m.entry_file) or not _IDENT_RE.match(m.entry_symbol):
        m.error = "bad entry '%s' (use module:Class)" % m.entry[:60]
        return m
    if perms is None:
        m.error = "'permissions' must be a list of names (max %d)" % PERMS_MAX
        return m
    bad = [p for p in m.permissions if p not in _KNOWN_PERMS]
    if bad:
        m.error = "unknown permission(s): %s (allowed: %s)" % (
            ", ".join(p[:20] for p in bad[:4]), ", ".join(sorted(_KNOWN_PERMS)))
        return m
    if not has_file(m.entry_file):
        m.error = "entry file '%s' missing" % m.entry_file
        return m
    return m


def _is_regular_rel(dfd, rel) -> bool:
    parts = rel.split("/")
    fds = []
    try:
        cur = dfd
        for p in parts[:-1]:
            cur = os.open(p, _O_DIR, dir_fd=cur)
            fds.append(cur)
        st = os.stat(parts[-1], dir_fd=cur, follow_symlinks=False)
        return stat.S_ISREG(st.st_mode)
    except OSError:
        return False
    finally:
        for f in fds:
            os.close(f)


def _meta_at(dfd, d) -> ExtraMeta:
    try:
        raw = read_at(dfd, "extra.json", MANIFEST_MAX)
    except FileNotFoundError:
        raw = None
    except ValueError:
        m = ExtraMeta(d)
        m.error = "extra.json is too large (max %d bytes)" % MANIFEST_MAX
        return m
    except OSError as exc:
        m = ExtraMeta(d)
        m.error = "cannot read extra.json: %s" % (exc.strerror or exc)
        return m
    return _meta_from_manifest(d, raw, lambda rel: _is_regular_rel(dfd, rel))


def _load_meta(d) -> ExtraMeta:
    """Read and validate one extra folder's manifest (never follows a symlinked
    folder or manifest, never blocks on a FIFO, never reads more than 32 KiB)."""
    try:
        dfd = open_dir(d)
    except Exception as exc:
        m = ExtraMeta(d)
        m.error = ("extra folder is a symlink - copy the folder instead"
                   if isinstance(exc, UnsafePath) else "cannot open extra folder: %s" % exc)
        return m
    try:
        return _meta_at(dfd, d)
    finally:
        os.close(dfd)


def scan() -> list:
    """Discover the extras the player has: the user dir (~/.wdgo/extras), which is
    where the Hub installs and where hand-copied extras go. Reads manifests only —
    never imports an extra's code (that happens lazily on launch). Never raises.

    The examples shipped in the repository are reference code for authors; they are
    published through the hub like any other extra, so they are NOT listed here by
    default. A developer can list them too with WDGO_EXTRAS_EXAMPLES=1.

    When the same id exists in both places, a VALID manifest beats an invalid one,
    then the HIGHER manifest 'version' wins (ties -> the shipped example). Returns
    ExtraMeta list, valid first, by name.
    """
    try:
        recover_installs()
    except Exception:
        pass
    cands = {}      # id -> list of (origin, meta); origin 0=user dir, 1=shipped example
    roots = [(0, extras_root())]
    if os.environ.get("WDGO_EXTRAS_EXAMPLES") == "1":
        roots.append((1, examples_dir()))
    extra_rows = []
    for origin, root in roots:
        try:
            rfd = open_dir(root, create=(origin == 0))
        except Exception:
            continue
        try:
            names, overflow = [], False
            try:
                with os.scandir(rfd) as it:
                    for n, ent in enumerate(it):
                        if n >= ROOT_MAX_ENTRIES:
                            overflow = True
                            break
                        names.append(ent.name)
            except OSError:
                pass
            for nm in sorted(names):
                if nm.startswith(("_", ".")):
                    continue
                d = os.path.join(root, nm)
                try:
                    try:
                        dfd = os.open(nm, _O_DIR, dir_fd=rfd)
                    except OSError:
                        st = os.stat(nm, dir_fd=rfd, follow_symlinks=False)
                        if stat.S_ISLNK(st.st_mode):
                            m = ExtraMeta(d)
                            m.error = "extra folder is a symlink - copy the folder instead"
                            cands.setdefault(m.id, []).append((origin, m))
                        continue
                    try:
                        m = _meta_at(dfd, d)
                    finally:
                        os.close(dfd)
                except Exception as exc:
                    m = ExtraMeta(d)
                    m.error = "cannot read extra: %s" % str(exc)[:100]
                cands.setdefault(m.id, []).append((origin, m))
            if overflow:
                m = ExtraMeta(os.path.join(root, "too_many_entries"))
                m.name = "(folder overflow)"
                m.error = ("more than %d entries in %s - only the first %d were read"
                           % (ROOT_MAX_ENTRIES, root, ROOT_MAX_ENTRIES))
                extra_rows.append(m)
        finally:
            os.close(rfd)
    out = []
    for lst in cands.values():
        best = max(lst, key=lambda om: (om[1].error is None, _vkey(om[1].version), om[0]))[1]
        if best.error is None:
            superseded = [m for o, m in lst if m is not best and m.error is None
                          and _vkey(best.version) > _vkey(m.version)]
            if superseded:
                best.update_note = "updated to v%s" % best.version
        out.append(best)
    out.extend(extra_rows)
    out.sort(key=lambda m: (m.error is not None, m.name.lower()))
    return out


# ======================================================================
# Source collection + content hash (shared by the host, the installer and tools)
# ======================================================================
SRC_MAX_FILES = 64
SRC_MAX_FILE_BYTES = 512 * 1024
SRC_MAX_TOTAL_BYTES = 2 * 1024 * 1024
from wdgo_extras_png import IMG_MAX_BYTES, IMG_MAX_COUNT, IMG_MAX_PX, IMG_MAX_TOTAL    # noqa: E402,F401


def _collect_at(rootfd) -> dict:
    out = {}
    total = [0]
    images = [0, 0]                 # count, bytes
    seen = [0]

    def _walk(dfd, rel, depth):
        names = []
        with os.scandir(dfd) as it:
            for ent in it:
                seen[0] += 1
                if seen[0] > PKG_MAX_ENTRIES:
                    raise ValueError("extra has too many files and folders (max %d)"
                                     % PKG_MAX_ENTRIES)
                try:
                    isdir = ent.is_dir(follow_symlinks=False)
                except OSError:
                    isdir = False
                names.append((ent.name, isdir))
        for nm, isdir in sorted(names):
            if nm.startswith(".") or nm == "__pycache__":
                continue
            r = (rel + "/" + nm) if rel else nm
            if isdir:
                if depth >= 3:
                    continue
                try:
                    cfd = os.open(nm, _O_DIR, dir_fd=dfd)
                except OSError:
                    continue                        # symlink / vanished: never followed
                try:
                    _walk(cfd, r, depth + 1)
                finally:
                    os.close(cfd)
                continue
            is_img = nm.endswith(".png")
            if not (nm.endswith(".py") or r == "extra.json" or is_img):
                continue
            try:
                fd = os.open(nm, _O_FILE, dir_fd=dfd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOENT, errno.ENOTDIR, errno.EISDIR):
                    continue                        # symlink / vanished: never followed
                raise
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    continue                        # FIFO, device, directory: skipped
                if is_img:
                    images[0] += 1
                    if st.st_size > IMG_MAX_BYTES:
                        raise ValueError("image too large: %s (max %d bytes)" % (r, IMG_MAX_BYTES))
                    images[1] += st.st_size
                    if images[0] > IMG_MAX_COUNT:
                        raise ValueError("too many images (max %d)" % IMG_MAX_COUNT)
                    if images[1] > IMG_MAX_TOTAL:
                        raise ValueError("images too large in total (max %d bytes)" % IMG_MAX_TOTAL)
                if st.st_size > SRC_MAX_FILE_BYTES:
                    raise ValueError("source file too large: %s" % r)
                chunks, n = [], 0
                while n <= SRC_MAX_FILE_BYTES:
                    b = os.read(fd, min(65536, SRC_MAX_FILE_BYTES + 1 - n))
                    if not b:
                        break
                    chunks.append(b)
                    n += len(b)
                if n > SRC_MAX_FILE_BYTES:
                    raise ValueError("source file too large: %s" % r)
                data = b"".join(chunks)
            finally:
                os.close(fd)
            total[0] += len(data)
            if len(out) >= SRC_MAX_FILES or total[0] > SRC_MAX_TOTAL_BYTES:
                raise ValueError("extra has too much code (max %d files / %d bytes)"
                                 % (SRC_MAX_FILES, SRC_MAX_TOTAL_BYTES))
            out[r] = data

    _walk(rootfd, "", 0)
    return out


def collect_sources(d) -> dict:
    """Read an extra's content into memory: {relpath: bytes} for extra.json, every
    *.py and every *.png (small images, see wdgo_extras_png) up to 3 directories
    deep. The walk holds directory fds: symlinks are never followed (the folder
    itself must not be one either), FIFOs/devices are skipped without blocking, and
    entries, counts and sizes are capped. Raises ValueError when a cap is exceeded."""
    fd = open_dir(d)
    try:
        return _collect_at(fd)
    finally:
        os.close(fd)


def sources_hash(src: dict) -> str:
    """Stable sha256 over (relpath, content) pairs — the extra's content identity."""
    import hashlib
    h = hashlib.sha256()
    for r in sorted(src):
        rb = r.encode("utf-8")
        h.update(len(rb).to_bytes(4, "big")); h.update(rb)
        h.update(len(src[r]).to_bytes(8, "big")); h.update(src[r])
    return h.hexdigest()


class Snapshot:
    """One immutable, in-memory reading of an extra: its sources, their hash and the
    manifest parsed FROM THOSE BYTES. Consent is given to it and the runtime runs
    it; the folder on disk is not consulted again."""
    __slots__ = ("dir", "src", "sha", "meta")

    def __init__(self, d, src, sha, meta):
        self.dir, self.src, self.sha, self.meta = d, src, sha, meta

    def images(self) -> dict:
        return {r: b for r, b in self.src.items() if r.endswith(".png")}


def snapshot(d) -> Snapshot:
    """Read an extra once (bounded, symlink-safe). Raises ValueError/OSError when it
    cannot be read or its manifest is invalid."""
    src = collect_sources(d)
    meta = _meta_from_manifest(d, src.get("extra.json"), lambda rel: rel in src)
    if meta.error:
        raise ValueError(meta.error)
    return Snapshot(d, src, sources_hash(src), meta)


_take_snapshot = snapshot


# ======================================================================
# Protected state (registry / consent / trust): safe reads, locked atomic writes
# ======================================================================
def _wdgo_dir() -> str:
    return state_dir()


def _state_private() -> bool:
    return _euid() == 0


def _read_json_file(path, default):
    try:
        dfd = open_dir(os.path.dirname(path), private=_state_private()
                       and os.path.dirname(path) == state_dir())
        try:
            raw = read_at(dfd, os.path.basename(path), STATE_FILE_MAX)
        finally:
            os.close(dfd)
        v = json.loads(raw.decode("utf-8"))
        return v if isinstance(v, type(default)) else default
    except Exception:
        return default


def _open_state_dir(path) -> int:
    d = os.path.dirname(path)
    return open_dir(d, create=True, mode=0o700, private=_state_private() and d == state_dir())


def _store_json(path, obj):
    """Atomic, private (0600) write. Raises on failure."""
    data = json.dumps(obj, indent=1, sort_keys=True).encode("utf-8")
    if len(data) > STATE_FILE_MAX:
        raise ValueError("%s would be too large" % os.path.basename(path))
    dfd = _open_state_dir(path)
    try:
        write_atomic_at(dfd, os.path.basename(path), data, 0o600)
    finally:
        os.close(dfd)


def _write_json_file(path, obj) -> bool:
    try:
        _store_json(path, obj)
        return True
    except Exception:
        return False


def update_json(path, fn, default=None):
    """Read-modify-write one state file under an exclusive lock (threads and
    processes). fn(current) returns the new object. Raises on failure; on failure the
    previous file is intact."""
    dfd = _open_state_dir(path)
    try:
        with dir_lock(dfd):
            try:
                cur = json.loads(read_at(dfd, os.path.basename(path), STATE_FILE_MAX).decode("utf-8"))
            except FileNotFoundError:
                cur = None
            except (ValueError, UnicodeDecodeError):
                cur = None
            base = {} if default is None else default
            if not isinstance(cur, type(base)):
                cur = base
            new = fn(cur)
            data = json.dumps(new, indent=1, sort_keys=True).encode("utf-8")
            if len(data) > STATE_FILE_MAX:
                raise ValueError("%s would be too large" % os.path.basename(path))
            write_atomic_at(dfd, os.path.basename(path), data, 0o600)
            return new
    finally:
        os.close(dfd)


def installed_file() -> str:
    """Registry of extras installed from the hub: {id: {version, sha, source}}."""
    return os.path.join(_wdgo_dir(), "extras-installed.json")


def consent_file() -> str:
    """Per-extra consent, pinned to the content hash: {id: {sha, perms, t}}."""
    return os.path.join(_wdgo_dir(), "extras-consent.json")


def trust_file() -> str:
    """User-maintained allowlist of extras allowed to run IN-PROCESS in the desktop
    simulator: {"<id>": "<sha256 from sources_hash>"}. Pinned to the content hash.
    Never used while the game is root (then everything runs sandboxed)."""
    return os.path.join(_wdgo_dir(), "extras-trusted.json")


def txn_file() -> str:
    """Journal of an install in progress (recovered by recover_installs())."""
    return os.path.join(_wdgo_dir(), "extras-txn.json")


def is_bundled(meta) -> bool:
    try:
        return os.path.dirname(os.path.abspath(meta.dir)) == os.path.abspath(examples_dir())
    except Exception:
        return False


def is_trusted(meta, sha=None) -> bool:
    """True when this exact code may skip the consent card: a bundled example (ships
    with the game) or an id+hash the user pinned in trust_file(). `sha` is the hash
    of the snapshot that will run; without it the folder is read once."""
    try:
        if is_bundled(meta):
            return True
        pins = _read_json_file(trust_file(), {})
        want = pins.get(meta.id)
        if not (isinstance(want, str) and want):
            return False
        if sha is None:
            sha = sources_hash(collect_sources(meta.dir))
        return want == sha
    except Exception:
        return False


def provenance(meta, sha) -> str:
    """'bundled' (ships with the game) | 'hub' (installed from the signed hub and
    byte-identical to what was verified) | 'local' (anything else - unverified)."""
    if is_bundled(meta):
        return "bundled"
    ent = _read_json_file(installed_file(), {}).get(meta.id)
    if isinstance(ent, dict) and ent.get("source") == "hub" and ent.get("sha") == sha:
        return "hub"
    return "local"


def is_official(meta, sha) -> bool:
    """True only for an extra installed from the signed hub, byte-identical to what was
    verified, whose catalogue entry carried official=true (the maintainer's own list)."""
    ent = _read_json_file(installed_file(), {}).get(meta.id)
    return (isinstance(ent, dict) and ent.get("source") == "hub" and ent.get("sha") == sha
            and ent.get("official") is True)


def consent_ok(meta, sha) -> bool:
    ent = _read_json_file(consent_file(), {}).get(meta.id)
    if not (isinstance(ent, dict) and ent.get("sha") == sha):
        return False
    have = _norm_perms(ent.get("perms") or [])
    return have is not None and have == _norm_perms(list(meta.permissions or []))


def consent_grant(meta, sha) -> bool:
    """Record the player's yes for exactly this content + permission set. False (and
    nothing recorded) when it cannot be saved."""
    perms = _norm_perms(list(meta.permissions or [])) or []

    def put(allc):
        allc[meta.id] = {"sha": sha, "perms": perms, "t": int(time.time())}
        return allc
    try:
        update_json(consent_file(), put, {})
        return True
    except Exception:
        return False


# ======================================================================
# Host selection
# ======================================================================
def make_host(meta, bridge, data_dir, require_isolation=True, snapshot=None):
    """Pick the runtime for an extra.

    Default is the SANDBOX (non-root, jailed subprocess + capability broker; see
    wdgo_extras_sandbox), fed the given snapshot. When the sandbox cannot run, a
    root game refuses to start the extra - there is no root fallback. Only in the
    non-root desktop simulator may trusted code (bundled examples, or a hash pinned
    in trust_file()) run in-process, still from the snapshot.
    """
    snap = snapshot
    if snap is None:
        try:
            snap = _take_snapshot(meta.dir)
        except Exception as exc:
            return _RefusedHost(meta, "cannot read extra: %s" % exc)
    try:
        import wdgo_extras_sandbox as _sb
    except Exception:
        _sb = None
    try:
        if _sb is not None and _sb.available(require_isolation):
            return _sb.SandboxHost(snap.meta, bridge, data_dir,
                                   require_isolation=require_isolation, snapshot=snap)
    except Exception as exc:
        return _RefusedHost(snap.meta, "sandbox error: %s" % exc)
    if _euid() == 0:
        return _RefusedHost(snap.meta, "sandbox unavailable - extras never run with the "
                                       "game's root privileges (see docs/EXTRAS_authoring.md)")
    if is_trusted(snap.meta, snap.sha):
        try:
            bridge.log("sandbox unavailable here - trusted extra runs in-process", "warn")
        except Exception:
            pass
        return ExtraHost(snap.meta, bridge, data_dir, snapshot=snap)
    return _RefusedHost(snap.meta, "sandbox unavailable on this system - untrusted extras "
                                   "cannot run (see docs/EXTRAS_authoring.md)")


_PERM_TEXT = {
    "gps": "read your GPS position",
    "loot_read": "read the list of scanned networks",
    "loot_write": "save files into loot/extras/%s/",
}


class ConsentScreen:
    """Shown instead of an extra the user has not approved yet (or whose code or
    permissions changed since). Drawn through the bridge like an extra; on [Y] it
    records the grant (id + content hash) and hands over `next_host`. The whole
    permission set is shown; when it does not fit, [Y] works only after the player
    scrolled to the end."""
    builtin = True
    sandboxed = True

    def __init__(self, meta, bridge, sha, source, make_next):
        self.meta = meta
        self._b = bridge
        self._sha = sha
        self._source = source
        self._make_next = make_next
        self.state = "running"
        self.error = None
        self.faults = 0
        self.next_host = None
        self._t0 = time.monotonic()
        self._scroll = 0
        self._seen_end = False
        self._fail = None
        try:
            self._official = source == "hub" and is_official(meta, sha)
        except Exception:
            self._official = False

    def open(self):
        pass

    def event(self, key):
        pass

    def close(self):
        self.state = "closed"

    def _lines(self):
        m = self.meta
        L = [("ALLOW THIS EXTRA TO RUN?", 24, "hi", True, 40),
             ("%s  v%s  by %s" % (m.name, m.version, m.author or "?"), 18, "txt", True, 30)]
        if self._source == "hub":
            L.append(("SOURCE: WDGo extras hub - reviewed, signature + checksum verified", 15, "success", False, 26))
        else:
            L.append(("SOURCE: UNVERIFIED LOCAL CODE - nobody reviewed this copy", 15, "warn", True, 26))
        L.append(("code fingerprint  %s" % self._sha[:32], 13, "dim", False, 30))
        if self._source == "hub" and self._official:
            L.append(("Official extra by LOCOSP - marked official in the signed hub catalogue.", 15, "success", True, 22))
            L.append(("It still runs sandboxed and gets only what it asks for below.", 15, "success", False, 32))
        elif self._source == "hub":
            L.append(("Third-party extra: written by its author, NOT by LOCOSP. A hub review", 15, "warn", True, 22))
            L.append(("is not a guarantee. You install and use it at your own risk.", 15, "warn", True, 32))
        else:
            L.append(("Third-party extra: NOT made, reviewed or supported by LOCOSP.", 15, "warn", True, 22))
            L.append(("You install and use it entirely at your own risk.", 15, "warn", True, 32))
        L.append(("It runs SANDBOXED: no files, no network, no other programs.", 15, "txt", False, 24))
        L.append(("It can draw on this screen, read the keyboard, keep its own small data,", 15, "txt", False, 22))
        perms = list(m.permissions or [])
        if perms:
            L.append(("and it asks for (%d):" % len(perms), 15, "txt", False, 26))
            for p in perms:
                t = _PERM_TEXT.get(p, "?")
                txt = t % m.id if "%s" in t else t
                L.append(("  + %s   (%s)" % (txt, p), 16, "ice", True, 24))
        else:
            L.append(("and it asks for nothing else.", 15, "txt", False, 24))
        return L

    def frame(self, dt):
        b, m = self._b, self.meta
        try:
            vh = int(b.view()[1])
        except Exception:
            vh = 480
        lines = self._lines()
        foot = 16 + 30 + 22 + (24 if self._fail else 0)       # keys + note (+ error)
        body_h = vh - 6 - foot
        total = sum(ln[4] for ln in lines)
        # scroll by whole lines; the body never hides a line silently
        max_scroll = 0
        while max_scroll < len(lines) and sum(ln[4] for ln in lines[max_scroll:]) > body_h:
            max_scroll += 1
        if time.monotonic() - self._t0 > 0.4:
            try:
                if b.key_pressed("down"):
                    self._scroll = min(max_scroll, self._scroll + 1)
                if b.key_pressed("up"):
                    self._scroll = max(0, self._scroll - 1)
            except Exception:
                pass
        self._scroll = max(0, min(self._scroll, max_scroll))
        if self._scroll >= max_scroll:
            self._seen_end = True
        y = 6
        for txt, size, col, bold, step in lines[self._scroll:]:
            if y + step > 6 + body_h and total > body_h:
                break
            b.draw_text(txt, 0, y, size, col, bold)
            y += step
        y += 16
        if not self._seen_end:
            b.draw_text("[DOWN] show the rest - all permissions must be seen first        [ESC] cancel",
                        0, y, 18, "warn", True)
        else:
            b.draw_text("[Y] allow and run        [ESC] cancel", 0, y, 18, "teal", True)
        y += 30
        b.draw_text("Asked once per version: any change to its code or permissions asks again.", 0, y, 13, "dim", False)
        y += 22
        if self._fail:
            b.draw_text(self._fail, 0, y, 15, "danger", True)
        if time.monotonic() - self._t0 > 0.4 and self.next_host is None and self._seen_end:
            try:
                if b.key_pressed("y"):
                    if consent_grant(m, self._sha):
                        self._fail = None
                        self.next_host = self._make_next()
                    else:
                        self._fail = "could not save your decision - the extra was NOT started"
            except Exception as exc:
                self._fail = "could not start: %s" % str(exc)[:80]


def launch(meta, bridge, data_dir, require_isolation=True):
    """What the game calls when the user picks an extra. Reads the extra ONCE into a
    Snapshot and returns the runtime for it, or a ConsentScreen in front of it when
    this exact code + permission set has not been approved yet. The bytes approved
    on the card are the bytes that run. Bundled examples and hand-pinned trusted
    extras (trust_file) skip the question."""
    try:
        snap = snapshot(meta.dir)
    except Exception as exc:
        return _RefusedHost(meta, "cannot read extra: %s" % exc)

    def _mk():
        return make_host(snap.meta, bridge, data_dir, require_isolation=require_isolation,
                         snapshot=snap)
    if is_trusted(snap.meta, snap.sha):
        return _mk()
    if consent_ok(snap.meta, snap.sha):
        return _mk()
    return ConsentScreen(snap.meta, bridge, snap.sha, provenance(snap.meta, snap.sha), _mk)


class _RefusedHost:
    """Stand-in host for an extra we will not run. Same surface as ExtraHost."""
    def __init__(self, meta, reason):
        self.meta = meta
        self.state = "faulted"
        self.error = reason
        self.faults = 1
        self.sandboxed = False

    def open(self):
        pass

    def frame(self, dt):
        pass

    def event(self, key):
        pass

    def close(self):
        self.state = "closed"


def extras_tab_items(metas) -> list:
    """Build the menu item 5-tuples for the EXTRAS category. Caller wraps with
    (name, color, items). First row is a live Rescan."""
    items = [("r", "Rescan", "_extra_rescan", "_extra_rescan", None),
             ("h", "Hub", "_extra_hub", "_extra_hub", None)]
    pool = list("123456789abcdefghjklmnopqstuvwxyz")
    pi = 0
    for m in metas:
        hk = pool[pi] if pi < len(pool) else ""
        pi += 1
        label = m.name[:18] + ("" if not m.error else "  X")
        items.append((hk, label, "_extra:%s" % m.id, "_extra_%s" % m.id, None))
    return items


# ======================================================================
# Installed packages: atomic activation with a recoverable journal
# ======================================================================
BACKUP_DIR = ".backup"               # inside extras_root(): hidden, never scanned
_STAGE_RE = re.compile(r"^\.[a-z0-9_]{3,32}\.stage-[0-9a-f]{16}$")
_BACKUP_RE = re.compile(r"^[a-z0-9_]{3,32}-[0-9]{10}-[0-9a-f]{8}$")


class PackageCollision(Exception):
    """A different (hand-installed or locally edited) extra already uses this id."""


def _write_tree_at(rfd, name, src):
    os.mkdir(name, 0o755, dir_fd=rfd)
    sfd = os.open(name, _O_DIR, dir_fd=rfd)
    dirs = {"": sfd}
    try:
        for rel in sorted(src):
            parts = rel.split("/")
            for p in parts:
                _check_name(p)
                if p.startswith("."):
                    raise UnsafePath(errno.EINVAL, "bad path %r" % rel)
            cur, key = sfd, ""
            for p in parts[:-1]:
                key += p + "/"
                if key not in dirs:
                    dirs[key] = _subdir(cur, p, create=True)
                cur = dirs[key]
            fd = os.open(parts[-1], _O_NEW, 0o644, dir_fd=cur)
            try:
                view = memoryview(src[rel])
                while view:
                    view = view[os.write(fd, view):]
                os.fsync(fd)
            finally:
                os.close(fd)
        for fd in dirs.values():
            try:
                os.fsync(fd)
            except OSError:
                pass
    finally:
        for fd in dirs.values():
            os.close(fd)


def _hash_at(rfd, name):
    try:
        fd = os.open(name, _O_DIR, dir_fd=rfd)
    except OSError:
        return None
    try:
        return sources_hash(_collect_at(fd))
    except Exception:
        return None
    finally:
        os.close(fd)


def _set_reg(eid, entry):
    def put(reg):
        if entry is None:
            reg.pop(eid, None)
        else:
            reg[eid] = entry
        return reg
    update_json(installed_file(), put, {})


def _prune_backups(rfd, eid):
    try:
        bfd = os.open(BACKUP_DIR, _O_DIR, dir_fd=rfd)
    except OSError:
        return
    try:
        mine = []
        with os.scandir(bfd) as it:
            for n, ent in enumerate(it):
                if n > 4 * ROOT_MAX_ENTRIES:
                    break
                if _BACKUP_RE.match(ent.name) and ent.name.rsplit("-", 2)[0] == eid:
                    mine.append(ent.name)
        for nm in sorted(mine)[:-KEEP_BACKUPS] if len(mine) > KEEP_BACKUPS else []:
            _rmtree_at(bfd, nm)
    finally:
        os.close(bfd)


def _backup_name(eid):
    return "%s-%010d-%s" % (eid, int(time.time()), os.urandom(4).hex())


def _move_to_backup(rfd, eid, name=None):
    """Move extras_root()/<eid> into the hidden backup area; returns its name."""
    bfd = _subdir(rfd, BACKUP_DIR, create=True, mode=0o700)
    try:
        name = name or _backup_name(eid)
        os.rename(eid, name, src_dir_fd=rfd, dst_dir_fd=bfd)
        try:
            os.fsync(bfd)
        except OSError:
            pass
        return name
    finally:
        os.close(bfd)


def _restore_backup(rfd, name, eid):
    bfd = os.open(BACKUP_DIR, _O_DIR, dir_fd=rfd)
    try:
        os.rename(name, eid, src_dir_fd=bfd, dst_dir_fd=rfd)
    finally:
        os.close(bfd)


def package_state(eid):
    """('none'|'hub'|'hub-modified'|'local', current_sha|None) for extras_root()/<eid>."""
    rfd = open_dir(extras_root(), create=True)
    try:
        return _package_state_at(rfd, eid)
    finally:
        os.close(rfd)


def _package_state_at(rfd, eid):
    if not _lexists_at(rfd, eid):
        return "none", None
    cur = _hash_at(rfd, eid)
    reg = _read_json_file(installed_file(), {}).get(eid)
    if isinstance(reg, dict) and reg.get("source") == "hub":
        return ("hub" if cur is not None and cur == reg.get("sha") else "hub-modified"), cur
    return "local", cur


def activate_package(eid, src, sha, reg_entry, replace_local=None) -> str:
    """Install verified bytes as the active version of extra `eid`, atomically:
    stage + fsync + re-hash, journal, move the previous folder to the backup area,
    rename the stage into place, record it in the registry, drop the journal. A
    crash at any point leaves either the whole old or the whole new version (see
    recover_installs). A hand-installed extra with the same id is replaced only with
    replace_local=True; a locally edited hub copy unless replace_local=False. The
    previous folder is always kept (newest KEEP_BACKUPS per extra)."""
    if not _ID_RE.match(str(eid)):
        raise ValueError("bad extra id")
    rfd = open_dir(extras_root(), create=True)
    try:
        with dir_lock(rfd):
            _recover_at(rfd)
            kind, _cur = _package_state_at(rfd, eid)
            if kind == "local" and not replace_local:
                raise PackageCollision("a hand-installed extra named '%s' is already there" % eid)
            if kind == "hub-modified" and replace_local is False:
                raise PackageCollision("the installed '%s' was edited locally" % eid)
            if not fs_has_room(rfd, sum(len(b) for b in src.values()), len(src) + 8):
                raise OSError(errno.ENOSPC, "not enough free space to install")
            stage = ".%s.stage-%s" % (eid, os.urandom(8).hex())
            try:
                _write_tree_at(rfd, stage, src)
                if _hash_at(rfd, stage) != sha:
                    raise ValueError("installed copy does not match the verified checksum")
            except BaseException:
                _rmtree_at(rfd, stage)
                raise
            # the journal names the backup BEFORE the move, so a failure at any later
            # point can always find the previous version again
            backup = _backup_name(eid) if kind != "none" else None
            journal = {"id": eid, "stage": stage, "backup": backup, "sha": sha, "entry": reg_entry}
            try:
                _store_json(txn_file(), journal)
            except BaseException:
                _rmtree_at(rfd, stage)
                raise
            try:
                if backup:
                    _move_to_backup(rfd, eid, backup)
                os.rename(stage, eid, src_dir_fd=rfd, dst_dir_fd=rfd)
                try:
                    os.fsync(rfd)
                except OSError:
                    pass
            except BaseException:
                _recover_at(rfd, forward=False)
                raise
            try:
                _set_reg(eid, reg_entry)
            except BaseException as exc:
                # cannot record it: put the previous version back, report failure
                try:
                    os.rename(eid, stage, src_dir_fd=rfd, dst_dir_fd=rfd)
                    if backup:
                        _restore_backup(rfd, backup, eid)
                    _rmtree_at(rfd, stage)
                    _clear_txn()
                except Exception:
                    pass
                raise OSError(errno.EIO, "could not record the install (%s) - previous version kept"
                              % exc)
            _clear_txn()
            _prune_backups(rfd, eid)
            return os.path.join(extras_root(), eid)
    finally:
        os.close(rfd)


def remove_package(eid) -> bool:
    """Remove a hub-installed extra (its saved data is kept). A copy that was edited
    locally is moved to the backup area instead of being deleted."""
    if not _ID_RE.match(str(eid)):
        return False
    reg = _read_json_file(installed_file(), {})
    if eid not in reg:
        return False
    rfd = open_dir(extras_root(), create=True)
    try:
        with dir_lock(rfd):
            _recover_at(rfd)
            kind, _cur = _package_state_at(rfd, eid)
            if kind == "hub":
                _rmtree_at(rfd, eid)
            elif kind != "none":
                _move_to_backup(rfd, eid)
                _prune_backups(rfd, eid)
            _set_reg(eid, None)
            return True
    finally:
        os.close(rfd)


def _clear_txn():
    try:
        dfd = _open_state_dir(txn_file())
        try:
            os.unlink(os.path.basename(txn_file()), dir_fd=dfd)
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except FileNotFoundError:
        pass


def _sweep_stages(rfd):
    """Remove staging folders no journal refers to (a crash before the journal)."""
    stale = []
    with os.scandir(rfd) as it:
        for n, ent in enumerate(it):
            if n >= 4 * ROOT_MAX_ENTRIES:
                break
            if _STAGE_RE.match(ent.name):
                stale.append(ent.name)
    for nm in stale:
        _rmtree_at(rfd, nm)


def _recover_at(rfd, forward=True):
    j = _read_json_file(txn_file(), {})
    if not j:
        _sweep_stages(rfd)
        return
    eid, stage, backup, sha = j.get("id"), j.get("stage"), j.get("backup"), j.get("sha")
    if not (isinstance(eid, str) and _ID_RE.match(eid) and isinstance(stage, str)
            and _STAGE_RE.match(stage) and isinstance(sha, str)
            and (backup is None or (isinstance(backup, str) and _BACKUP_RE.match(backup)))):
        _clear_txn()
        return
    entry = j.get("entry") if isinstance(j.get("entry"), dict) else None
    have = _lexists_at(rfd, eid)
    if have and forward and _hash_at(rfd, eid) == sha:
        if entry is not None:
            reg = _read_json_file(installed_file(), {})
            if reg.get(eid) != entry:
                _set_reg(eid, entry)
    elif not have:
        if forward and _lexists_at(rfd, stage) and _hash_at(rfd, stage) == sha:
            os.rename(stage, eid, src_dir_fd=rfd, dst_dir_fd=rfd)
            if entry is not None:
                _set_reg(eid, entry)
        elif backup:
            try:
                _restore_backup(rfd, backup, eid)
            except OSError:
                pass                             # the move never happened: nothing to undo
    _clear_txn()
    _sweep_stages(rfd)
    try:
        os.fsync(rfd)
    except OSError:
        pass


def recover_installs():
    """Finish or undo an install that was interrupted (power loss, crash). Never
    waits: when another install holds the lock, it will finish (or recover) itself."""
    rfd = open_dir(extras_root(), create=True)
    try:
        try:
            lock = dir_lock(rfd, timeout=0)
            lock.__enter__()
        except TimeoutError:
            return
        try:
            _recover_at(rfd)
        finally:
            lock.__exit__(None, None, None)
    finally:
        os.close(rfd)


# ======================================================================
# Bounded, symlink-safe storage (ctx.storage) and loot writes (ctx.loot_save)
# ======================================================================
class SafeStorage:
    """Per-extra persistent storage confined to one directory, with quotas. Never
    follows a symlink, never reads a FIFO/device/hard link or a file it did not
    create, always writes through a fresh temp file + rename, and refuses writes
    that would eat into the game's free-space reserve."""
    def __init__(self, d, max_file=STORAGE_MAX_FILE, max_files=STORAGE_MAX_FILES, legacy="auto"):
        self.dir = d
        self.path = d
        self.max_file = max_file
        self.max_files = max_files
        self._legacy = legacy_data_dir(d) if legacy == "auto" else legacy

    def _migrate(self):
        """One-time copy of this extra's saved data from its old location (when the
        data root moved to protected state): regular, single-link files only, within
        the quotas, never following a link. The old folder is left as it was."""
        old, self._legacy = self._legacy, None
        if not old or os.path.lexists(self.dir):
            return
        try:
            ofd = open_dir(old)
        except Exception:
            return
        try:
            names = []
            with os.scandir(ofd) as it:
                for n, ent in enumerate(it):
                    if n >= 4 * self.max_files:
                        break
                    if not ent.name.startswith(_TMP_PREFIX) and ent.is_file(follow_symlinks=False):
                        names.append(ent.name)
            nfd = open_dir(self.dir, create=True, mode=0o700)
            try:
                for nm in sorted(names)[:self.max_files]:
                    try:
                        write_atomic_at(nfd, nm, read_at(ofd, nm, self.max_file, single_link=True), 0o600)
                    except Exception:
                        continue
            finally:
                os.close(nfd)
        except Exception:
            pass
        finally:
            os.close(ofd)

    @staticmethod
    def _name(name):
        nm = os.path.basename(str(name))
        if (not nm or nm in (".", "..") or len(nm) > 64 or "\x00" in nm
                or nm.startswith(_TMP_PREFIX)):
            raise ValueError("bad storage name")
        return nm

    def read(self, name):
        """-> str or None."""
        if self._legacy:
            self._migrate()
        try:
            nm = self._name(name)
            dfd = open_dir(self.dir)
        except Exception:
            return None
        try:
            return read_at(dfd, nm, self.max_file, single_link=True, own=True).decode("utf-8", "replace")
        except Exception:
            return None
        finally:
            os.close(dfd)

    def write(self, name, text) -> bool:
        if not isinstance(text, str):
            return False
        data = text.encode("utf-8", "replace")
        if len(data) > self.max_file:
            return False
        if self._legacy:
            self._migrate()
        try:
            nm = self._name(name)
            dfd = open_dir(self.dir, create=True, mode=0o700)
        except Exception:
            return False
        try:
            with dir_lock(dfd):
                try:
                    st = os.stat(nm, dir_fd=dfd, follow_symlinks=False)
                except FileNotFoundError:
                    st = None
                if st is not None and stat.S_ISDIR(st.st_mode):
                    return False
                if st is None:
                    n = 0
                    with os.scandir(dfd) as it:
                        for ent in it:
                            if not ent.name.startswith(_TMP_PREFIX):
                                n += 1
                            if n >= self.max_files:
                                return False
                if not fs_has_room(dfd, len(data)):
                    return False
                write_atomic_at(dfd, nm, data, 0o600)
                return True
        except Exception:
            return False
        finally:
            os.close(dfd)


def loot_save(loot_root, eid, name, text) -> str:
    """Write one text file for extra `eid` into <loot_root>/extras/<eid>/ ONLY (the
    extra's own namespace, never a core loot file). Symlink-safe, atomic, and
    bounded: LOOT_SAVE_MAX per file, LOOT_MAX_BYTES / LOOT_MAX_FILES per extra, and
    never into the game's free-space reserve. Returns the file path; raises
    ValueError/OSError with a readable reason when refused."""
    if not _ID_RE.match(str(eid)):
        raise ValueError("bad extra id")
    safe = re.sub(r"[^A-Za-z0-9._ -]", "_", str(name)[:80]).strip(" ._") or "untitled"
    safe = os.path.basename(safe)
    if "." not in safe:
        safe += ".txt"
    data = str(text).encode("utf-8", "replace")
    if len(data) > LOOT_SAVE_MAX:
        raise ValueError("loot file too large (max %d bytes)" % LOOT_SAVE_MAX)
    lfd = open_dir(loot_root, create=True)
    try:
        efd = _subdir(lfd, "extras", create=True)
    finally:
        os.close(lfd)
    try:
        ifd = _subdir(efd, eid, create=True)
    finally:
        os.close(efd)
    try:
        with dir_lock(ifd):
            used = files = old = 0
            with os.scandir(ifd) as it:
                for n, ent in enumerate(it):
                    if n > 4 * LOOT_MAX_FILES:
                        raise ValueError("loot folder of this extra is full")
                    if ent.name.startswith(_TMP_PREFIX):
                        continue
                    try:
                        st = ent.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    files += 1
                    used += st.st_size if stat.S_ISREG(st.st_mode) else 0
                    if ent.name == safe:
                        if not stat.S_ISREG(st.st_mode):
                            raise ValueError("'%s' exists and is not a regular file" % safe)
                        old = st.st_size
                        files -= 1
            if files >= LOOT_MAX_FILES:
                raise ValueError("this extra already saved %d loot files (limit)" % files)
            if used - old + len(data) > LOOT_MAX_BYTES:
                raise ValueError("this extra's loot quota (%d MiB) is used up" % (LOOT_MAX_BYTES >> 20))
            if not fs_has_room(ifd, len(data)):
                raise OSError(errno.ENOSPC, "not enough free space (the game keeps a reserve)")
            write_atomic_at(ifd, safe, data, 0o644)
        return os.path.join(loot_root, "extras", eid, safe)
    finally:
        os.close(ifd)


# ======================================================================
# ctx facade
# ======================================================================
class _Storage:
    """Per-extra persistent storage, confined to the extra's own data/ dir."""
    def __init__(self, d):
        self.path = d
        self._safe = SafeStorage(d)

    def read(self, name, default=""):
        v = self._safe.read(name)
        return default if v is None else v

    def write(self, name, text):
        return self._safe.write(name, str(text))

    def read_json(self, name, default=None):
        raw = self.read(name, "")
        if not raw:
            return default
        try:
            return json.loads(raw)
        except Exception:
            return default

    def write_json(self, name, obj):
        try:
            return self.write(name, json.dumps(obj))
        except Exception:
            return False


class _GpsCap:
    def __init__(self, fn):
        self._fn = fn

    def fix(self):
        """-> dict(valid, lat, lon, sats, speed_kmh, heading) or None."""
        try:
            return self._fn()
        except Exception:
            return None


class _LootCap:
    def __init__(self, nets, counts):
        self._nets, self._counts = nets, counts

    def networks(self):
        try:
            return list(self._nets())
        except Exception:
            return []

    def counts(self):
        try:
            return dict(self._counts())
        except Exception:
            return {}


class ExtraContext:
    """The only object an extra talks to. Verbs only — never the raw game."""
    def __init__(self, bridge, meta, data_dir, storage=None, images=None):
        self._b = bridge
        self._meta = meta
        # {relpath: png bytes}; None = read them from the extra's folder on first use.
        # Decoded lazily, once, by the extra's own process (the sandbox for third parties).
        self._img_src = images
        self._img = {}
        self.api_version = EXTRAS_API
        # In the sandbox the child has no filesystem: storage is a broker proxy.
        self.storage = storage if storage is not None else _Storage(data_dir)
        perms = set(meta.permissions or [])
        self.gps = _GpsCap(bridge.gps) if "gps" in perms else None
        self.loot = (_LootCap(bridge.loot_networks, bridge.loot_counts)
                     if "loot_read" in perms else None)
        # loot_save(name, text) -> absolute path | None. Writes into the game's loot
        # tree under loot/extras/<id>/ ONLY (own namespace; never core loot files).
        self.loot_save = bridge.loot_save if "loot_write" in perms else None
        self.mesh = None     # Phase 2 (sandbox + arbiter lease) — not yet granted

    # ---- geometry (read-only) ----
    @property
    def w(self):
        return self._b.view()[0]

    @property
    def h(self):
        return self._b.view()[1]

    def require(self, cap):
        v = getattr(self, cap, None)
        if v is None:
            raise PermissionError("capability '%s' not granted (declare it in permissions)" % cap)
        return v

    # ---- drawing (local coords 0,0..w,h; clamped to the extra's viewport) ----
    def text(self, s, x, y, size=16, color="txt", bold=False):
        self._b.draw_text(s, x, y, size, color, bold)

    def rect(self, x, y, w, h, color="txt", fill=True, alpha=255):
        self._b.draw_rect(x, y, w, h, color, fill, alpha)

    def line(self, x1, y1, x2, y2, color="txt", thick=1):
        self._b.draw_line(x1, y1, x2, y2, color, thick)

    def circle(self, x, y, r, color="txt"):
        self._b.draw_circle(x, y, r, color)

    def measure(self, s, size=16):
        return self._b.measure(s, size)

    # ---- images (api 2): small PNGs shipped in the extra's own folder ----
    def _image(self, name):
        name = str(name)
        got = self._img.get(name)
        if got is None:
            if self._img_src is None:
                self._img_src = {r: b for r, b in collect_sources(self._meta.dir).items()
                                 if r.endswith(".png")}
            if name not in self._img_src:
                raise KeyError("no image '%s' in this extra" % name)
            import wdgo_extras_png
            got = self._img[name] = wdgo_extras_png.decode(self._img_src[name])
        return got

    def image_size(self, name):
        """(width, height) in pixels of one of the extra's own .png files."""
        w, h, _ = self._image(name)
        return (w, h)

    def image(self, name, x, y, scale=1, alpha=255):
        """Draw one of the extra's own .png files (max 512x512 px) at x, y.
        scale is a whole number 1..8 (pixels are kept crisp)."""
        w, h, rgba = self._image(name)
        self._b.draw_image(str(name), w, h, rgba, x, y,
                           max(1, min(8, int(scale))), max(0, min(255, int(alpha))))

    # ---- input (only while the extra is active; ESC is the host's) ----
    def key_down(self, name):
        return self._b.key_down(name)

    def key_pressed(self, name):
        return self._b.key_pressed(name)

    def chars(self):
        """Printable characters typed this frame, as a list of str (for text entry)."""
        try:
            return self._b.chars()
        except Exception:
            return []

    # ---- misc ----
    def log(self, msg, level="info"):
        self._b.log(msg, level)

    def now(self):
        return time.time()


# ======================================================================
# In-process host (desktop simulator only) — runs a Snapshot, with error isolation
# ======================================================================
class _SnapFinder:
    """meta_path finder serving the extra's own modules from its snapshot, so the
    in-process host never re-reads (or imports anything else from) its folder."""
    def __init__(self, src, prefix):
        self._prefix = prefix
        self._mods = {}
        for rel, data in src.items():
            if not rel.endswith(".py"):
                continue
            parts = rel[:-3].split("/")
            pkg = parts[-1] == "__init__"
            name = ".".join(parts[:-1] if pkg else parts)
            if name and all(p.isidentifier() for p in name.split(".")):
                self._mods[name] = (rel, data, pkg)

    def find_spec(self, name, path=None, target=None):
        ent = self._mods.get(name)
        if ent is None:
            return None
        return importlib.util.spec_from_loader(name, self, origin=self._prefix + ent[0],
                                               is_package=ent[2])

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        rel, data, _pkg = self._mods[module.__name__]
        exec(compile(data.decode("utf-8"), self._prefix + rel, "exec"), module.__dict__)


def _exec_entry(snap):
    meta = snap.meta
    prefix = os.path.join(os.path.abspath(snap.dir), "")
    name = "wdgo_extra_%s" % meta.id
    mod = type(sys)(name)
    mod.__file__ = prefix + meta.entry_file
    sys.modules[name] = mod
    finder = _SnapFinder(snap.src, prefix)
    sys.meta_path.insert(0, finder)
    try:
        exec(compile(snap.src[meta.entry_file].decode("utf-8"), mod.__file__, "exec"), mod.__dict__)
    finally:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
    return mod


class ExtraHost:
    """One running extra, in-process (desktop simulator only). Every hook call is
    wrapped: a fault disables the extra and surfaces the reason, but never
    propagates into the game loop. Refuses to run while the game is root."""
    def __init__(self, meta, bridge, data_dir, snapshot=None):
        self.meta = meta
        self._bridge = bridge
        self._data_dir = data_dir
        self._snap = snapshot
        self.ctx = ExtraContext(bridge, meta, data_dir,
                                images=snapshot.images() if snapshot is not None else None)
        self.state = "loading"       # loading | running | faulted | closed
        self.error = None
        self.instance = None
        self.faults = 0
        self.sandboxed = False       # in-process tier (trusted code only)

    def open(self):
        try:
            if _euid() == 0:
                raise PermissionError("in-process extras never run as root - use the sandbox")
            if self._snap is None:
                self._snap = snapshot(self.meta.dir)
                self.meta = self._snap.meta
                self.ctx = ExtraContext(self._bridge, self.meta, self._data_dir,
                                        images=self._snap.images())
            mod = _exec_entry(self._snap)
            cls = getattr(mod, self.meta.entry_symbol, None)
            if cls is None:
                raise AttributeError("entry symbol '%s' not found" % self.meta.entry_symbol)
            self.instance = cls()
            self._call("on_load")
            self._call("on_enter")
            if self.state == "loading":
                self.state = "running"
        except Exception as exc:
            self._fault(exc)

    def frame(self, dt):
        if self.state == "running":
            self._call("on_frame", dt)

    def event(self, key):
        if self.state == "running":
            self._call("on_event", key)

    def close(self):
        try:
            if self.instance and self.state in ("running", "faulted"):
                fn = getattr(self.instance, "on_exit", None)
                if fn:
                    try:
                        fn(self.ctx)
                    except Exception:
                        pass
        finally:
            try:
                self._bridge.release_all()
            except Exception:
                pass
            self.state = "closed"

    def _call(self, hook, *a):
        fn = getattr(self.instance, hook, None)
        if fn is None:
            return
        try:
            fn(self.ctx, *a)
        except Exception as exc:
            self._fault(exc)

    def _fault(self, exc):
        self.faults += 1
        self.error = "%s: %s" % (type(exc).__name__, exc)
        try:
            tb = traceback.format_exc().strip().splitlines()
            self._bridge.log("faulted: %s" % (tb[-1] if tb else self.error), "error")
        except Exception:
            pass
        self.state = "faulted"
