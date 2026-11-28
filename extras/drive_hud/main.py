"""Drive HUD - big, glanceable wardrive numbers for a car screen or tablet.

Six tiles: speed, networks this trip, networks per minute, networks per mile (or
km), distance and trip time, plus a 10-minute rate sparkline. The trip survives
leaving the screen and restarting the game; [R] starts a new one.

Pure stdlib + ctx. Permissions: gps, loot_read.
"""
import math

KM_PER_MI = 1.609344
RATE_WINDOW_S = 60.0      # nets/min is measured over the last minute
SPARK_BUCKET_S = 30.0     # one sparkline bar per 30 s ...
SPARK_BARS = 20           # ... for the last 10 minutes
MIN_STEP_M = 8.0          # ignore GPS jitter smaller than this
MAX_KMH = 250.0           # ignore jumps implying more than this
STILL_S = 30.0            # no 8 m of movement for this long = parked (~1 km/h still counts)
SAVE_EVERY_S = 15.0
POLL_S = 1.0
SESSION_CHECK_S = 5.0     # how often to compare the list itself (an IPC read of up to 500 rows)


def _haversine_km(a_lat, a_lon, b_lat, b_lon):
    r = 6371.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dphi = math.radians(b_lat - a_lat)
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


def _fmt_time(s):
    s = int(s)
    return "%d:%02d:%02d" % (s // 3600, (s // 60) % 60, s % 60) if s >= 3600 else "%d:%02d" % (s // 60, s % 60)


class Extra:
    def on_load(self, ctx):
        st = ctx.storage.read_json("trip.json", default=None) or {}
        self.metric = bool(st.get("metric", False))          # default miles (US)
        self.trip = st.get("trip") or self._new_trip()
        self.last_save = 0.0

    @staticmethod
    def _new_trip():
        return {"nets": 0, "km": 0.0, "secs": 0.0, "best_rate": 0, "last_count": None,
                "session_sample": None, "since_check": 0}

    def on_enter(self, ctx):
        self.gps, self.loot = ctx.gps, ctx.loot
        self.last_fix = None          # (lat, lon, t) distance anchor: last point that counted
        self.prev_fix = None          # (lat, lon, t) previous raw sample, for jump detection
        self.speed = 0.0
        self.samples = []             # (t, trip_nets) for the rolling rate
        self.spark = []               # per-bucket new-net counts
        self.bucket_t = ctx.now()
        self.bucket_n = 0
        self.last_poll = -POLL_S
        self.last_session_check = -SESSION_CHECK_S
        self.msg = ("", 0.0)
        self._poll(ctx, check_session=True)   # pick up nets collected while closed ...
        self.bucket_n = 0             # ... into the trip total, not into this 30 s bar

    def _save(self, ctx):
        ctx.storage.write_json("trip.json", {"metric": self.metric, "trip": self.trip})
        self.last_save = ctx.now()

    # ---- data --------------------------------------------------------------
    def _list_was_cleared(self, c):
        """True if the game's network list was cleared (a new scan/wardrive started)
        since the last check, False if not, None if it can't tell right now.

        Within one session the list holds every network seen exactly once (re-seen
        ones are moved to the end, never dropped), so all networks remembered from
        the last check are still in it - unless the list was cleared. That only
        works while the whole list is visible to extras (they get the first 500)."""
        nets = self.loot.networks()
        if len(nets) != c or c >= 500:
            return None                                    # partial view or failed read
        keys = set(n.get("bssid") or ("ssid:" + (n.get("ssid") or "")) for n in nets)
        sample = self.trip.get("session_sample")
        cleared = bool(sample) and not set(sample) <= keys
        self.trip["session_sample"] = sorted(keys)[:40]
        return cleared

    def _poll(self, ctx, check_session=False):
        if self.loot is None:
            return
        counts = self.loot.counts()
        if "networks" not in counts:  # failed read ({}): keep the baseline, try again next poll
            return
        c = int(counts["networks"])
        last = self.trip.get("last_count")
        dropped = last is not None and c < last            # count went down: new session
        cleared = None
        if check_session or dropped:
            cleared = self._list_was_cleared(c)            # True / False / None (can't tell)
        # networks credited by plain count polls since the last confirmed list check
        since = int(self.trip.get("since_check") or 0)
        if last is not None:
            if dropped:
                d = c                                      # list restarted at zero: all c are new
            elif cleared:
                # the list was cleared sometime after the last confirmed check, and the
                # 1 s count polls in between may already have credited part of the new
                # session - credit only the rest (never double-count; at worst a few
                # finds of the old session from those seconds go uncounted)
                d = max(0, c - since)
            else:
                d = c - last
            self.trip["nets"] += d
            self.bucket_n += d
        else:
            d = 0
        self.trip["since_check"] = 0 if cleared is not None else since + d
        self.trip["last_count"] = c

    def _gps(self, ctx, now):
        fix = self.gps.fix() if self.gps is not None else None
        if not fix or not fix.get("valid"):
            self.last_fix = self.prev_fix = None
            self.speed *= 0.9
            return None
        lat, lon = fix["lat"], fix["lon"]
        rep = fix.get("speed_kmh")
        if self.last_fix is None:
            self.last_fix = self.prev_fix = (lat, lon, now)
        elif now - self.prev_fix[2] >= 1.0:
            # jump check against the previous raw sample, not the (possibly old) anchor
            step = _haversine_km(self.prev_fix[0], self.prev_fix[1], lat, lon)
            if step / (now - self.prev_fix[2]) * 3600.0 > MAX_KMH:
                self.last_fix = self.prev_fix = (lat, lon, now)     # GPS glitch: re-anchor
            else:
                self.prev_fix = (lat, lon, now)
                km = _haversine_km(self.last_fix[0], self.last_fix[1], lat, lon)
                held = now - self.last_fix[2]
                if km * 1000.0 >= MIN_STEP_M:
                    # counts even when it took many seconds to get here (slow driving)
                    self.trip["km"] += km
                    self.speed = self.speed * 0.5 + (km / held * 3600.0) * 0.5
                    self.last_fix = (lat, lon, now)
                elif held >= 3.0:
                    self.speed *= 0.5                                # not moving much: decay the display
                    if held >= STILL_S:
                        # parked: drop the anchor so slow GPS drift never adds up to "distance"
                        # (the game reports speed 0 when unknown, so it can't be used for this)
                        self.last_fix = (lat, lon, now)
        if rep is not None and rep > 0.5:      # trust the receiver's own speed when it has one
            self.speed = self.speed * 0.4 + rep * 0.6
        return fix

    def _rate(self, now):
        self.samples.append((now, self.trip["nets"]))
        while self.samples and now - self.samples[0][0] > RATE_WINDOW_S:
            self.samples.pop(0)
        if len(self.samples) < 2:
            return 0.0
        dt = self.samples[-1][0] - self.samples[0][0]
        if dt < 5.0:
            return 0.0
        return (self.samples[-1][1] - self.samples[0][1]) / dt * 60.0

    # ---- frame -------------------------------------------------------------
    def on_frame(self, ctx, dt):
        now = ctx.now()
        self.trip["secs"] += max(0.0, min(dt, 1.0))
        if ctx.key_pressed("u"):
            self.metric = not self.metric
            self._save(ctx)
        if ctx.key_pressed("r"):
            self.trip = self._new_trip()
            self.samples, self.spark, self.bucket_n = [], [], 0
            self.last_fix = None
            self._poll(ctx, check_session=True)
            self._save(ctx)
            self.msg = ("new trip started", now + 3.0)
            ctx.log("Drive HUD: new trip")
        if now - self.last_poll >= POLL_S:
            self.last_poll = now
            check = now - self.last_session_check >= SESSION_CHECK_S
            if check:
                self.last_session_check = now
            self._poll(ctx, check_session=check)
        if now - self.bucket_t >= SPARK_BUCKET_S:
            self.spark.append(self.bucket_n)
            self.spark = self.spark[-SPARK_BARS:]
            self.bucket_t, self.bucket_n = now, 0
        fix = self._gps(ctx, now)
        rate = self._rate(now)
        self.trip["best_rate"] = max(self.trip.get("best_rate", 0), int(round(rate)))
        if now - self.last_save >= SAVE_EVERY_S:
            self._save(ctx)

        unit = "km" if self.metric else "mi"
        dist = self.trip["km"] if self.metric else self.trip["km"] / KM_PER_MI
        spd = self.speed if self.metric else self.speed / KM_PER_MI
        per_unit = (self.trip["nets"] / dist) if dist >= 0.25 else 0.0

        w, h = ctx.w, ctx.h
        if self.loot is None:
            ctx.text("needs the loot_read permission", 10, 10, 20, "danger")
            return
        tiles = [
            ("SPEED", "%.0f" % spd, "mph" if not self.metric else "km/h", "ice"),
            ("NETS THIS TRIP", "{:,}".format(self.trip["nets"]), "", "hi"),
            ("NETS / MIN", "%.0f" % rate, "best %d" % self.trip["best_rate"], "success"),
            ("NETS / " + unit.upper(), "%.0f" % per_unit if per_unit else "--", "", "teal"),
            ("DISTANCE", "%.1f" % dist, unit, "txt"),
            ("TRIP TIME", _fmt_time(self.trip["secs"]), "", "txt"),
        ]
        cols, rows = 3, 2
        pad, foot = 10, 96
        tw = (w - pad * (cols + 1)) // cols
        th = (h - foot - pad * (rows + 1)) // rows
        big = max(28, min(80, int(th * 0.55)))
        for i, (label, val, sub, col) in enumerate(tiles):
            x = pad + (i % cols) * (tw + pad)
            y = pad + (i // cols) * (th + pad)
            ctx.rect(x, y, tw, th, "edge", fill=True, alpha=60)
            ctx.rect(x, y, tw, th, "edge", fill=False)
            ctx.text(label, x + 12, y + 8, 18, "dim", bold=True)
            vw = ctx.measure(val, big)
            size = big
            if vw > tw - 24:                 # long value: shrink to fit the tile (measure is linear in size)
                size = max(12, int(big * (tw - 24) / vw))
                vw = ctx.measure(val, size)
            ctx.text(val, x + (tw - int(vw)) // 2, y + (th - size) // 2 + 6, size, col, bold=True)
            if sub:
                ctx.text(sub, x + tw - 12 - int(ctx.measure(sub, 18)), y + th - 28, 18, "dim")

        # sparkline: new nets per 30 s over the last 10 minutes
        sy = h - foot + 6
        sh = 44
        ctx.text("last 10 min", pad, sy, 14, "dim")
        bars = (self.spark + [self.bucket_n])[-(SPARK_BARS + 1):]   # history + the current bar
        peak = max([1] + bars)
        gap, x0 = 2, pad + 100
        avail = (w // 2 + 10) - x0                                   # stop short of the GPS text
        bw = max(1, (avail - gap * SPARK_BARS) // (SPARK_BARS + 1))  # 21 bars, 20 gaps
        for i, n in enumerate(bars):
            bh = int(sh * n / peak)
            ctx.rect(x0 + i * (bw + gap), sy + sh - bh, bw, max(1, bh),
                     "success" if i == len(bars) - 1 else "teal", fill=True)

        gps_txt = ("GPS OK  %d sats" % fix.get("sats", 0)) if fix else "NO GPS FIX - distance & speed paused"
        ctx.text(gps_txt, w // 2 + 20, sy, 18, "success" if fix else "warn", bold=True)
        if self.msg[0] and now < self.msg[1]:
            ctx.text(self.msg[0], w // 2 + 20, sy + 28, 16, "success")
        else:
            ctx.text("[U] %s   [R] new trip" % ("miles" if self.metric else "kilometres"),
                     w // 2 + 20, sy + 28, 16, "dim")

    def on_exit(self, ctx):
        self._poll(ctx, check_session=True)   # confirm the session as we leave, for the next visit
        self._save(ctx)

    def on_unload(self, ctx):
        self._save(ctx)
