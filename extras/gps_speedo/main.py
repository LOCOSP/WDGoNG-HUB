"""GPS Speedometer — reference EXTRA for WatchDogsGo.

Demonstrates the one-shot sensor-read shape of the ctx API: read the GPS fix,
compute speed from successive positions, draw, read a key. Pure stdlib + ctx.
See docs/EXTRAS_authoring.md.
"""
import math


def _haversine_km(a_lat, a_lon, b_lat, b_lon):
    r = 6371.0
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dphi = math.radians(b_lat - a_lat)
    dl = math.radians(b_lon - a_lon)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(min(1.0, math.sqrt(h)))


class Extra:
    def on_enter(self, ctx):
        self.gps = ctx.require("gps")   # raises if the 'gps' permission wasn't granted
        self.last = None                # (lat, lon, t) of the previous fix
        self.speed = 0.0                # smoothed km/h
        self.heading = 0.0

    def on_frame(self, ctx, dt):
        w, h = ctx.w, ctx.h
        ctx.text("GPS SPEEDOMETER", 8, 6, 20, "ice", bold=True)

        fix = self.gps.fix()
        if not fix or not fix.get("valid"):
            ctx.text("waiting for a GPS fix...", 8, h // 2 - 10, 20, "dim")
            self.last = None
            return

        now = ctx.now()
        lat, lon = fix["lat"], fix["lon"]
        if self.last is not None:
            dts = now - self.last[2]
            if dts >= 0.4:
                km = _haversine_km(self.last[0], self.last[1], lat, lon)
                inst = (km / dts) * 3600.0
                self.speed = self.speed * 0.6 + inst * 0.4   # light smoothing
                self.heading = _bearing(self.last[0], self.last[1], lat, lon)
                self.last = (lat, lon, now)
        else:
            self.last = (lat, lon, now)

        big = "%.0f" % self.speed
        bx = w // 2 - int(ctx.measure(big, 80) / 2)
        ctx.text(big, bx, h // 2 - 56, 80, "hi", bold=True)
        ctx.text("km/h", w // 2 - 28, h // 2 + 34, 22, "teal")
        ctx.text("heading %03.0f deg" % self.heading, 8, h - 50, 16, "txt")
        ctx.text("sats %d   %.5f, %.5f" % (fix.get("sats", 0), lat, lon), 8, h - 28, 14, "dim")

        if ctx.key_pressed("r"):
            self.speed = 0.0
            ctx.log("speed reset")

    def on_exit(self, ctx):
        pass


def _bearing(a_lat, a_lon, b_lat, b_lon):
    p1, p2 = math.radians(a_lat), math.radians(b_lat)
    dl = math.radians(b_lon - a_lon)
    y = math.sin(dl) * math.cos(p2)
    x = math.cos(p1) * math.sin(p2) - math.sin(p1) * math.cos(p2) * math.cos(dl)
    return (math.degrees(math.atan2(y, x)) + 360) % 360
