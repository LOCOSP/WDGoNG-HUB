"""Surveillance Spotter - flags Flock ALPR cameras and related surveillance gear
in the networks your wardrive picks up, with a GPS position for every sighting.

Detection is tiered, because a vendor MAC prefix alone is NOT proof of a camera
(the same Liteon / Silicon Labs radios ship in plenty of ordinary devices):

  CONFIRMED  the SSID itself names the device: "Flock", "Flock-XXXXXX",
             "Penguin...", "Pigvision...", "FS Ext Battery"
  SUSPECT    MAC prefix registered to / strongly tied to Flock hardware
  WEAK       contract-manufacturer MAC prefix seen on Flock units but also on
             lots of unrelated gear - hidden unless you turn it on with [W]
  KEYWORD    an SSID contains one of your own watch words (add with [K])

Known look-alikes (ClickShare, WiFi-Direct printers, Android hotspots, other
detectors' "Flock ALPR [...]" output) are excluded before matching.

Positions are only ever taken from the moment a network is first seen while this
screen is open. Networks already in the wardrive list when you open the screen
are "backlog": their capture position and time are unknown to an extra, so they
are recorded without a position and never re-counted or moved.

Pure stdlib + ctx. Permissions: gps, loot_read, loot_write.
"""
import json
import time

# ---- detection rules -------------------------------------------------------
CONFIRM_EXACT = ("flock",)                       # bare "Flock" (case-insensitive)
CONFIRM_PREFIX = ("flock-", "flock_", "penguin", "pigvision", "fs ext battery")
EXCLUDE_SUBSTR = ("flock alpr", "clickshare", "smartgate_", "direct-", "androidap",
                  "audi hud", "max-printer")
SUSPECT_OUI = {
    "70:c9:4e": "Flock WiFi (high-tier OUI)",
    "b4:1e:52": "Flock Safety (registered OUI)",
    "3c:91:80": "Flock WiFi device",
    "d8:f3:bc": "Flock WiFi device",
}
WEAK_OUI = {
    "58:8e:81": "Silicon Labs (FS Ext Battery)",
    "ec:1b:bd": "Silicon Labs (FS Ext Battery)",
    "90:35:ea": "Silicon Labs",
    "74:4c:a1": "Liteon", "f4:6a:dd": "Liteon", "9c:2f:9d": "Liteon",
    "c0:35:32": "Liteon", "14:5a:fc": "Liteon", "08:3a:88": "Liteon",
    "e4:aa:ea": "Liteon/USI", "e0:4f:43": "USI", "d0:39:57": "contract mfr",
}
TIER_COLOR = {"CONFIRMED": "danger", "SUSPECT": "warn", "KEYWORD": "magenta", "WEAK": "dim"}
TIER_RANK = {"CONFIRMED": 0, "SUSPECT": 1, "KEYWORD": 2, "WEAK": 3}

POLL_S = 2.0           # how often to re-read the loot list (each read is an IPC call)
ALERT_S = 8.0          # how long the big alert banner stays up
HISTORY_MAX = 1500     # soft cap on records
STATE_MAX_BYTES = 200 * 1024   # the sandbox refuses files over 256 KiB - keep a margin
SAVE_EVERY_S = 10.0
LOG_PER_FRAME = 2      # sandbox accepts 8 ctx.log calls per frame ...
LOG_BURST = 25         # ... and the host 30 per 10 s - stay under both
LOG_WINDOW_S = 10.0
FORMULA_LEAD = ("=", "+", "-", "@")


def _norm_mac(b):
    b = (b or "").strip().lower().replace("-", ":")
    if len(b) == 12 and ":" not in b:
        b = ":".join(b[i:i + 2] for i in range(0, 12, 2))
    return b


def is_excluded(ssid):
    """A known look-alike (printer, screen-share, hotspot, another detector's output)."""
    sl = (ssid or "").strip().lower()
    return any(x in sl for x in EXCLUDE_SUBSTR)


def classify(ssid, bssid, keywords, include_weak):
    """-> (tier, reason) or None."""
    s = (ssid or "").strip()
    sl = s.lower()
    if is_excluded(s):
        return None
    if sl in CONFIRM_EXACT or any(sl.startswith(p) for p in CONFIRM_PREFIX):
        return ("CONFIRMED", "SSID '%s'" % s)
    oui = _norm_mac(bssid)[:8]
    if oui in SUSPECT_OUI:
        return ("SUSPECT", SUSPECT_OUI[oui])
    for k in keywords:
        if k and k in sl:
            return ("KEYWORD", "watch word '%s'" % k)
    if include_weak and oui in WEAK_OUI:
        return ("WEAK", WEAK_OUI[oui])
    return None


def _stamp():
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())


def _csv_field(v):
    """CSV-escape one cell. Text cells that a spreadsheet would run as a formula
    (SSIDs are chosen by whoever owns the AP) get a leading apostrophe; numbers
    such as negative longitudes are left alone."""
    if isinstance(v, str) and (v.lstrip().startswith(FORMULA_LEAD)
                               or v.startswith(("\t", "\r", "\n"))):
        v = "'" + v
    v = str(v)
    if any(c in v for c in ',"\r\n'):
        v = '"' + v.replace('"', '""') + '"'
    return v


class Extra:
    def on_load(self, ctx):
        st = ctx.storage.read_json("state.json", default=None) or {}
        self.history = st.get("history", {})          # bssid -> record (all time)
        self.keywords = [str(k).lower() for k in st.get("keywords", [])][:20]
        self.include_weak = bool(st.get("include_weak", False))
        self.dirty = False
        self.last_save = 0.0

    def on_enter(self, ctx):
        self.gps = ctx.gps
        self.loot = ctx.loot
        self.seen = {}               # key -> SSID it was classified with (cleared when the
                                     #        rules change; a changed SSID is re-checked)
        self.counted = set()         # keys whose sighting was already counted this visit
        self.obs = {}                # key -> (lat, lon, stamp) when first seen this visit;
                                     #        (None, None, None) for backlog entries
        self.baselined = False       # first poll of a visit = backlog
        self.session = []            # keys flagged since you opened the screen
        self.logq = []               # pending (msg, level) terminal lines
        self.log_t0, self.log_n = 0.0, 0
        self.save_failed = False
        self.checked = 0
        self.last_poll = -POLL_S
        self.alert = None            # (record, until)
        self.scroll = 0
        self.typing = None           # str while adding a watch word
        self.msg = ("", 0.0)

    # ---- helpers -----------------------------------------------------------
    def _state_text(self):
        return json.dumps({"history": self.history, "keywords": self.keywords,
                           "include_weak": self.include_weak}, separators=(",", ":"))

    def _save(self, ctx, force=False):
        if not self.dirty and not force:
            return
        self.last_save = ctx.now()
        if len(self.history) > HISTORY_MAX:
            self._trim(len(self.history) - HISTORY_MAX)
        text = self._state_text()
        while len(text.encode("utf-8")) > STATE_MAX_BYTES and self.history:
            # drop the oldest-seen ~5% (at least one) until the file fits the quota
            self._trim(max(1, len(self.history) // 20))
            text = self._state_text()
        if ctx.storage.write("state.json", text):
            self.dirty = False                 # only a successful write clears it
            self.save_failed = False
        else:
            self.save_failed = True            # keep dirty: retried on the next save tick
            self._note(ctx, "could not save history - will retry")

    def _trim(self, n):
        """Drop the n records with the oldest last-seen time (weakest tiers first on ties)."""
        order = sorted(self.history.items(),
                       key=lambda kv: (kv[1].get("last", ""), -TIER_RANK.get(kv[1].get("tier"), 9)))
        for k, _ in order[:n]:
            del self.history[k]
        self.session = [k for k in self.session if k in self.history]

    def _withdraw(self, ctx, key, ssid):
        rec = self.history.pop(key, None)
        if rec is None:
            return
        self.session = [k for k in self.session if k != key]
        self.counted.discard(key)
        if self.alert and self.alert[0] is rec:
            self.alert = None
        self.dirty = True
        self._log("dropped %s %s - now named '%s', a known look-alike"
                  % (rec.get("tier", ""), rec.get("bssid", ""), ssid), "info")

    def _log(self, msg, level):
        self.logq.append((msg, level))
        if len(self.logq) > 200:               # never grow without bound
            self.logq = self.logq[-200:]

    def _drain_logs(self, ctx):
        now = ctx.now()
        if now - self.log_t0 >= LOG_WINDOW_S:
            self.log_t0, self.log_n = now, 0
        sent = 0
        while self.logq and sent < LOG_PER_FRAME and self.log_n < LOG_BURST:
            msg, level = self.logq.pop(0)
            ctx.log(msg, level)
            sent += 1
            self.log_n += 1

    def _alert(self, ctx, rec, tier, reason, suffix):
        if tier not in ("CONFIRMED", "SUSPECT", "KEYWORD"):
            return
        self.alert = (rec, ctx.now() + ALERT_S)
        self._log("%s %s %s (%s)%s" % (tier, rec.get("ssid") or "<hidden>", rec.get("bssid", ""),
                                       reason, suffix),
                  "warn" if tier != "CONFIRMED" else "error")

    def _note(self, ctx, text):
        self.msg = (text, ctx.now() + 4.0)

    def _poll(self, ctx):
        if self.loot is None:
            return
        fix = self.gps.fix() if self.gps is not None else None
        live = bool(fix and fix.get("valid"))
        backlog = not self.baselined
        nets = self.loot.networks()
        self.baselined = True                  # an empty list at open = nothing in the backlog
        now = _stamp()
        for n in nets:
            b = _norm_mac(n.get("bssid", ""))
            key = b or ("ssid:" + n.get("ssid", ""))
            if key not in self.obs:
                # remember WHERE/WHEN we first saw it, so a later re-check (new watch
                # word, weak toggle) uses the observation, not wherever we are now
                if backlog:
                    self.obs[key] = (None, None, None)
                elif live:
                    self.obs[key] = (round(fix["lat"], 6), round(fix["lon"], 6), now)
                else:
                    self.obs[key] = (None, None, now)
            ssid_now = n.get("ssid", "")
            if key in self.seen and self.seen[key] == ssid_now:
                continue
            if (key in self.history and is_excluded(ssid_now)
                    and self.history[key].get("ssid", "") != ssid_now):
                # e.g. a hidden AP flagged by its MAC prefix turns out to be a
                # "DIRECT-..." printer: an explicit look-alike, so withdraw the detection.
                # (Records that stop matching only because weak matches or a watch word
                # were switched off are kept - those never reach this branch.)
                self._withdraw(ctx, key, ssid_now)
            if key not in self.seen:
                self.checked += 1
            # a hidden network whose name the scan learns later is classified again
            self.seen[key] = ssid_now
            hit = classify(n.get("ssid", ""), b, self.keywords, self.include_weak)
            if not hit:
                continue
            tier, reason = hit
            lat, lon, when = self.obs[key]
            rec = self.history.get(key)
            new = rec is None
            if new:
                rec = {"bssid": b, "ssid": n.get("ssid", ""), "tier": tier, "reason": reason,
                       "channel": n.get("channel", 0), "first": when or "", "last": when or "",
                       "sightings": 0, "lat": None, "lon": None}
                if when is None:
                    rec["note"] = "in wardrive list before screen opened - position unknown"
                self.history[key] = rec
            promoted = TIER_RANK.get(tier, 9) < TIER_RANK.get(rec.get("tier"), 9)
            if promoted:
                rec["tier"], rec["reason"] = tier, reason
            if key not in self.session and (new or promoted or key not in self.counted):
                self.session.insert(0, key)
            if ssid_now and rec.get("ssid") != ssid_now:
                rec["ssid"] = ssid_now                 # e.g. a hidden network now named
                self.dirty = True
            if key in self.counted:
                # a re-check of something already counted this visit: no new sighting,
                # but an upgrade to an alerting tier is news
                if promoted:
                    self.dirty = True
                    self._alert(ctx, rec, tier, reason, " - upgraded")
                continue
            self.counted.add(key)
            if when is None and not new:
                # backlog entry we already have on file: leave its count/position alone
                if promoted:
                    self.dirty = True
                    self._alert(ctx, rec, tier, reason, " - upgraded")
                continue
            if when is None:                   # new backlog find: one sighting, time/place unknown
                rec["sightings"] = max(1, int(rec.get("sightings", 0)))
            else:                              # a real observation made while open
                rec["sightings"] = int(rec.get("sightings", 0)) + 1
                rec["last"] = when
                if n.get("channel"):
                    rec["channel"] = n.get("channel")
                if not rec.get("first"):
                    rec["first"] = when
                if lat is not None:
                    rec["lat"], rec["lon"] = lat, lon
                    rec["pos_time"] = when             # the position belongs to THIS sighting
                    rec.pop("note", None)
            rec["ssid"] = n.get("ssid", "") or rec.get("ssid", "")
            self.dirty = True
            self._alert(ctx, rec, tier, reason,
                        " - seen before" if not new else (" - no position (backlog)" if when is None else ""))

    @staticmethod
    def _pos_time(r):
        """When the stored position was taken. Records from 1.0.0-1.0.3 have no
        pos_time; their position came from their last fixed sighting, unknown which."""
        return r.get("pos_time", "") if r.get("lat") is not None else ""

    def _export(self, ctx):
        if ctx.loot_save is None:
            self._note(ctx, "export needs the loot_write permission")
            return
        # lat/lon are the last position we HAD a fix for; position_time says which
        # sighting that was (it can be older than last_seen if later sightings had no fix)
        cols = ["tier", "ssid", "bssid", "reason", "channel", "lat", "lon", "position_time",
                "first_seen", "last_seen", "sightings"]
        rows = [",".join(cols)]
        recs = sorted(self.history.values(),
                      key=lambda r: (TIER_RANK.get(r.get("tier"), 9), r.get("last", "")))
        for r in recs:
            rows.append(",".join(_csv_field(x) for x in (
                r.get("tier"), r.get("ssid", ""), r.get("bssid", ""), r.get("reason", ""),
                r.get("channel", 0), "" if r.get("lat") is None else r["lat"],
                "" if r.get("lon") is None else r["lon"], self._pos_time(r), r.get("first", ""),
                r.get("last", ""), r.get("sightings", 0))))
        name = "spotter_%s.csv" % time.strftime("%Y%m%d_%H%M%S", time.localtime())
        p = ctx.loot_save(name, "\n".join(rows) + "\n")
        self._note(ctx, ("exported %d sightings -> %s" % (len(recs), name)) if p else "export failed")

    # ---- input -------------------------------------------------------------
    def _keys(self, ctx):
        if self.typing is not None:
            for c in ctx.chars():
                if len(self.typing) < 24:
                    self.typing += c
            if ctx.key_pressed("backspace"):
                if not self.typing:            # backspace on an empty word = cancel
                    self.typing = None
                    return
                self.typing = self.typing[:-1]
            if ctx.key_pressed("enter"):
                w = self.typing.strip().lower()
                if w and w not in self.keywords and len(self.keywords) < 20:
                    self.keywords.append(w)
                    self.seen = {}             # re-check this session's nets
                    self.dirty = True
                    self._note(ctx, "watching for '%s'" % w)
                self.typing = None
            return
        if ctx.key_pressed("k"):
            self.typing = ""
            ctx.chars()                        # drop the 'k' itself
        elif ctx.key_pressed("w"):
            self.include_weak = not self.include_weak
            self.seen = {}
            self.dirty = True
            self._note(ctx, "weak vendor matches %s" % ("ON" if self.include_weak else "OFF"))
        elif ctx.key_pressed("e"):
            self._save(ctx, force=True)
            self._export(ctx)
        elif ctx.key_pressed("x") and self.keywords:
            gone = self.keywords.pop()
            self.dirty = True
            self._note(ctx, "removed watch word '%s'" % gone)
        elif ctx.key_pressed("c"):
            self.session = []
            self.alert = None
            self._note(ctx, "session list cleared (history kept)")
        elif ctx.key_pressed("down"):
            self.scroll += 1
        elif ctx.key_pressed("up"):
            self.scroll = max(0, self.scroll - 1)

    # ---- frame -------------------------------------------------------------
    def on_frame(self, ctx, dt):
        now = ctx.now()
        self._keys(ctx)
        if now - self.last_poll >= POLL_S:
            self.last_poll = now
            self._poll(ctx)
        if self.dirty and now - self.last_save >= SAVE_EVERY_S:
            self._save(ctx)
        self._drain_logs(ctx)

        w, h = ctx.w, ctx.h
        if self.loot is None:
            ctx.text("needs the loot_read permission", 10, 10, 18, "danger")
            return
        fix = self.gps.fix() if self.gps is not None else None
        gps_ok = bool(fix and fix.get("valid"))
        tiers = {}
        for r in self.history.values():
            tiers[r.get("tier")] = tiers.get(r.get("tier"), 0) + 1
        status = "checked %d nets   all-time: %d confirmed  %d suspect  %d keyword%s" % (
            self.checked, tiers.get("CONFIRMED", 0), tiers.get("SUSPECT", 0),
            tiers.get("KEYWORD", 0),
            ("  %d weak" % tiers.get("WEAK", 0)) if self.include_weak else "")
        ctx.text(status, 10, 8, 16, "txt")
        gtxt = "GPS OK" if gps_ok else "NO GPS FIX - hits logged without position"
        ctx.text(gtxt, w - 10 - int(ctx.measure(gtxt, 16)), 8, 16,
                 "success" if gps_ok else "warn", bold=True)

        y = 36
        if self.alert and now < self.alert[1]:
            r = self.alert[0]
            col = TIER_COLOR.get(r.get("tier"), "warn")
            ctx.rect(6, y, w - 12, 112, col, fill=True, alpha=70)
            ctx.rect(6, y, w - 12, 112, col, fill=False)
            ctx.text("%s: %s" % (r.get("tier"), r.get("ssid") or "<hidden SSID>"),
                     18, y + 8, 34, col, bold=True)
            if r.get("lat") is None:
                pos = "no position"
            elif self._pos_time(r) and self._pos_time(r) != r.get("last"):
                # seen now without a fix: don't present the old coordinates as current
                pos = "no fix now - last known %.5f, %.5f (%s)" % (r["lat"], r["lon"], self._pos_time(r))
            else:
                pos = "%.5f, %.5f" % (r["lat"], r["lon"])
            ctx.text("%s   ch %s   %s   seen %dx" % (r.get("bssid", ""), r.get("channel", "?"),
                                                    r.get("reason", ""), r.get("sightings", 1)),
                     18, y + 52, 17, "txt")
            ctx.text(pos, 18, y + 80, 17, "txt" if "no fix now" not in pos else "warn")
            y += 124

        ctx.text("THIS SESSION", 10, y, 16, "teal", bold=True)
        y += 24
        row_h = 24
        visible = [k for k in self.session
                   if self.include_weak or self.history.get(k, {}).get("tier") != "WEAK"]
        rows_fit = max(1, (h - y - 70) // row_h)
        self.scroll = min(self.scroll, max(0, len(visible) - rows_fit))
        if not visible:
            ctx.text("nothing flagged yet - start a WiFi wardrive and keep driving",
                     10, y, 16, "dim")
        for key in visible[self.scroll:self.scroll + rows_fit]:
            r = self.history.get(key)
            if not r:
                continue
            col = TIER_COLOR.get(r.get("tier"), "txt")
            ctx.text("%-9s" % r.get("tier"), 10, y, 16, col, bold=True)
            ctx.text((r.get("ssid") or "<hidden>")[:26], 120, y, 16, "hi")
            ctx.text(r.get("bssid", ""), 420, y, 16, "txt")
            ctx.text(r.get("last", "")[11:] or "backlog", 610, y, 16, "dim")
            ctx.text(r.get("reason", "")[:40], 700, y, 16, "dim")
            y += row_h

        # footer
        kw = ", ".join(self.keywords) if self.keywords else "none"
        ctx.text("watch words: " + kw[:110], 10, h - 46, 14, "magenta")
        if self.typing is not None:
            ctx.rect(6, h - 28, w - 12, 24, "void", fill=True, alpha=230)
            ctx.text("new watch word: %s_   [ENTER] save  [BKSP] on empty = cancel" % self.typing,
                     10, h - 26, 16, "hi")
        elif self.msg[0] and now < self.msg[1]:
            ctx.text(self.msg[0], 10, h - 24, 15, "success")
        else:
            ctx.text("[K] add watch word  [X] remove last  [W] weak vendor matches %s  "
                     "[E] export CSV  [C] clear list  [UP/DN] scroll" %
                     ("ON" if self.include_weak else "OFF"), 10, h - 24, 14, "dim")

    def on_exit(self, ctx):
        self._save(ctx)

    def on_unload(self, ctx):
        self._save(ctx)
