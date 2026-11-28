#!/usr/bin/env python3
"""Build the hub catalogue from <hub-root>/extras/*/.

    python3 hub_build_index.py <hub-root> [--sdk <dir with wdgo_extras.py>] [--out <file>]

--out is relative to the hub root (default index.json). CI writes the CANDIDATE
to pending/index.json; the maintainer reviews it and publishes the signed
index.json offline (the signing key never exists on a CI runner).

For every extra it records the manifest summary plus `sha` = the game's own
content hash (wdgo_extras.sources_hash) of the reviewed files. The game installs
an extra only when its files hash to exactly this value, and only when index.json
carries a valid signature. Output is deterministic (sorted keys, no timestamps),
so an unchanged hub produces a byte-identical index.

`catalog_seq` is the release number the game uses against rollback (an older
signed catalogue replayed to a device is refused). It comes from the last signed
release in <hub-root>/index.json: the same number while the candidate is
byte-identical to that release, +1 for any change, 1 for the first numbered
release. An unreadable release or a bad number stops the build.

"""
import json
import os
import sys


def _find_sdk(here):
    """Directory holding wdgo_extras.py: a 'sdk' dir next to this tool (the hub
    repository layout), else the game package found near the repository root."""
    cand = [os.path.join(here, "sdk")]
    root = here
    for _ in range(3):
        root = os.path.dirname(root)
        try:
            cand += [os.path.join(root, d) for d in sorted(os.listdir(root))]
        except OSError:
            pass
    for c in cand:
        if os.path.isfile(os.path.join(c, "wdgo_extras.py")):
            return c
    return os.path.join(here, "sdk")


def main():
    args = sys.argv[1:]
    sdk = None
    if "--sdk" in args:
        i = args.index("--sdk")
        sdk = args[i + 1]
        del args[i:i + 2]
    out_rel = "index.json"
    if "--out" in args:
        i = args.index("--out")
        out_rel = args[i + 1]
        del args[i:i + 2]
    if len(args) != 1:
        print(__doc__)
        sys.exit(2)
    root = os.path.abspath(args[0])
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, sdk or _find_sdk(here))
    import wdgo_extras as wx

    import hub_official
    official = hub_official.load(os.path.join(root, "official.json"))
    extras = {}
    base = os.path.join(root, "extras")
    for eid in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        d = os.path.join(base, eid)
        if eid.startswith((".", "_")) or not os.path.isdir(d) or os.path.islink(d):
            continue
        m = wx._load_meta(d)
        if m.error:
            print("SKIP  %s: %s" % (eid, m.error))
            sys.exit(1)
        extras[m.id] = {
            "name": m.name, "version": m.version, "author": m.author, "api": m.api,
            "permissions": sorted(m.permissions), "description": m.description,
            "category": m.category, "tags": m.tags, "homepage": m.homepage,
            "sha": wx.sources_hash(wx.collect_sources(d)),
        }
        if hub_official.reserved_name_misuse(official, m.id, m.author):
            print("SKIP  %s: author name '%s' is reserved" % (eid, official["author"]))
            sys.exit(1)
        if hub_official.is_official(official, m.id, m.author):
            extras[m.id]["official"] = True  # from the maintainer - shown in green by game and store
        icon = os.path.join(d, "icon.png")
        if os.path.isfile(icon) and not os.path.islink(icon):
            import wdgo_extras_png
            try:
                with open(icon, "rb") as f:
                    wdgo_extras_png.check_icon(f.read(wdgo_extras_png.ICON_MAX_BYTES + 1))
                extras[m.id]["icon"] = True      # extras/<id>/icon.png - shown by the storefront
            except ValueError as exc:
                print("SKIP  %s: %s" % (eid, exc))
                sys.exit(1)
        print("ok    %-20s v%-8s %s" % (m.id, m.version, extras[m.id]["sha"][:16]))
    doc = {"schema": 1, "extras": extras}
    try:
        doc["catalog_seq"] = _catalog_seq(os.path.join(root, "index.json"), doc)
    except ValueError as exc:
        print("FAIL  %s" % exc)
        sys.exit(1)
    out = out_rel if os.path.isabs(out_rel) else os.path.join(root, out_rel)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(_dump(doc))
    print("wrote %s (%d extras, release %d)" % (out, len(extras), doc["catalog_seq"]))


SEQ_MAX = 2 ** 53 - 1      # stays exact in every JSON reader; the game accepts up to 2**64-1


def _dump(doc) -> str:
    return json.dumps(doc, indent=1, sort_keys=True, ensure_ascii=True) + "\n"


def _catalog_seq(released_path, doc):
    """Release number for the game's anti-rollback check, derived only from the
    last signed release (<hub-root>/index.json), so CI and the maintainer's local
    rebuild get the same bytes:
      - no release yet, or a release from before numbering -> 1;
      - the candidate is byte-identical to the release at its number -> that number;
      - anything else changed -> the next number.
    A release file that cannot be read or carries a bad number stops the build
    (ValueError) instead of silently restarting at 1, which devices would refuse."""
    try:
        with open(released_path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return 1
    except OSError as exc:
        raise ValueError("cannot read the released index.json (%s)" % exc)
    try:
        prev = json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ValueError("the released index.json is not valid JSON - refusing to number a release")
    if not isinstance(prev, dict):
        raise ValueError("the released index.json is not a catalogue - refusing to number a release")
    if "catalog_seq" not in prev:
        return 1                                  # first numbered release
    seq = prev["catalog_seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or not 1 <= seq <= SEQ_MAX:
        raise ValueError("the released index.json has a bad catalog_seq - refusing")
    if _dump(dict(doc, catalog_seq=seq)).encode("utf-8") == raw:
        return seq
    if seq >= SEQ_MAX:
        raise ValueError("catalog_seq is at its limit - refusing")
    return seq + 1


if __name__ == "__main__":
    main()
