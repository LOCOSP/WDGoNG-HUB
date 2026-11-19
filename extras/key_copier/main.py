"""Key Copier — a 1:1 pin-tumbler key bitting tracer/editor for WatchDogsGo.

Inspired by the Flipper Zero KeyCopier app (zinongli/KeyCopier). Original code.
Like the Flipper app, the key blade is drawn at TRUE physical size (1:1) so you
can lay a real key on the screen, align its shoulder to the reference line, and
read/trace the cuts. Pure UI + per-extra storage; no hardware, no permissions.

Scale: the uConsole 5" 1280x720 panel is ~294 PPI ~= 11.57 px/mm. Because exact
DPI / compositor scaling varies, the scale is CALIBRATABLE with [+]/[-] — set it
so the on-screen "10 mm" bar measures 10 mm against a real ruler, then it is 1:1.

NOTE: depth & spacing values are approximate references for learning. Verify
against a real manufacturer depth-and-spacing (DSD) chart before cutting a key.
"""

# name, pins, dmin, dmax, macs, spacing_mm (cut-to-cut), step_mm (per depth number),
# first_mm (shoulder -> first cut centre), blade_mm (uncut blade height)
KEYWAYS = [
    {"name": "Kwikset KW1", "pins": 5, "dmin": 1, "dmax": 7, "macs": 4,
     "spacing": 3.81, "step": 0.584, "first": 5.92, "blade": 8.0},
    {"name": "Schlage SC1", "pins": 5, "dmin": 0, "dmax": 9, "macs": 7,
     "spacing": 3.97, "step": 0.381, "first": 5.87, "blade": 8.0},
    {"name": "Schlage SC4", "pins": 6, "dmin": 0, "dmax": 9, "macs": 7,
     "spacing": 3.97, "step": 0.381, "first": 5.87, "blade": 8.0},
    {"name": "Yale Y1",     "pins": 5, "dmin": 1, "dmax": 9, "macs": 7,
     "spacing": 3.96, "step": 0.457, "first": 4.75, "blade": 8.0},
    {"name": "Master M1",   "pins": 4, "dmin": 1, "dmax": 9, "macs": 7,
     "spacing": 3.73, "step": 0.512, "first": 4.14, "blade": 7.6},
    {"name": "Weiser WR5",  "pins": 5, "dmin": 1, "dmax": 7, "macs": 4,
     "spacing": 3.81, "step": 0.584, "first": 5.92, "blade": 8.0},
]
_STORE = "bittings.json"
_DEFAULT_PPM = 11.57     # px per mm on the uConsole panel (calibrate to be sure)


class Extra:
    def on_enter(self, ctx):
        self.kw = 0
        self.pin = 0
        self.save = ctx.storage.read_json(_STORE, {}) or {}
        self.ppm = float(self.save.get("_ppm", _DEFAULT_PPM))
        self.depths = self._init_depths()
        self.naming = False      # typing a filename to export to loot
        self.fname = ""
        self.flash = ""          # transient "saved to ..." message
        self.flash_t = 0.0

    # ---- model -------------------------------------------------------------
    def _spec(self):
        return KEYWAYS[self.kw]

    def _mid(self, s):
        return [(s["dmin"] + s["dmax"]) // 2] * s["pins"]

    def _init_depths(self):
        s = self._spec()
        d = self.save.get(s["name"])
        if isinstance(d, list) and len(d) == s["pins"]:
            return [max(s["dmin"], min(s["dmax"], int(x))) for x in d]
        return self._mid(s)

    def _macs_bad(self):
        s = self._spec()
        return {i for i in range(len(self.depths) - 1)
                if abs(self.depths[i] - self.depths[i + 1]) > s["macs"]}

    def _code(self):
        return "-".join(str(d) for d in self.depths)

    # ---- lifecycle ---------------------------------------------------------
    def on_frame(self, ctx, dt):
        s = self._spec()
        self._input(ctx, s)
        self._draw(ctx, s)

    def on_exit(self, ctx):
        pass

    def _default_name(self):
        base = self._spec()["name"].lower().replace(" ", "_")
        return "%s_%s" % (base, self._code())

    def _report(self, s):
        bad = self._macs_bad()
        lines = ["WatchDogsGo - Key Copier export",
                 "keyway : %s" % s["name"],
                 "pins   : %d" % s["pins"],
                 "bitting: %s" % self._code(),
                 "depths : %s (range %d-%d)" % (self.depths, s["dmin"], s["dmax"]),
                 "spacing: %.2f mm   step: %.3f mm/number" % (s["spacing"], s["step"]),
                 "MACS   : %s (spec max adjacent %d)" % ("VIOLATION" if bad else "ok", s["macs"]),
                 "scale  : %.2f px/mm (calibrated 1:1)" % self.ppm,
                 "",
                 "NOTE: approximate reference values - verify against a real DSD chart."]
        return "\n".join(lines) + "\n"

    def _export(self, ctx, s):
        if ctx.loot_save is None:
            ctx.log("loot save not permitted (needs 'loot_write')", "warn")
            return
        name = (self.fname.strip() or self._default_name())
        path = ctx.loot_save(name + ".txt", self._report(s))
        if path:
            self.flash = "saved -> " + path
            self.flash_t = ctx.now()
            ctx.log("saved to loot: %s" % path, "ok")
        else:
            self.flash = "save failed"
            self.flash_t = ctx.now()

    # ---- input -------------------------------------------------------------
    def _input(self, ctx, s):
        # filename entry mode: type the name, ENTER saves to loot, W cancels
        if self.naming:
            for ch in ctx.chars():
                if len(self.fname) < 40 and ch not in "/\\":
                    self.fname += ch
            if ctx.key_pressed("backspace") and self.fname:
                self.fname = self.fname[:-1]
            if ctx.key_pressed("enter"):     # ENTER saves; ESC leaves the extra (cancels)
                self._export(ctx, s)
                self.naming = False
            return
        if ctx.key_pressed("w"):             # begin export: prefill a sensible name
            self.naming = True
            self.fname = self._default_name()
            return
        if ctx.key_pressed("left"):
            self.pin = (self.pin - 1) % s["pins"]
        if ctx.key_pressed("right"):
            self.pin = (self.pin + 1) % s["pins"]
        if ctx.key_pressed("up"):
            self.depths[self.pin] = min(s["dmax"], self.depths[self.pin] + 1)
        if ctx.key_pressed("down"):
            self.depths[self.pin] = max(s["dmin"], self.depths[self.pin] - 1)
        if ctx.key_pressed("f"):
            self.kw = (self.kw + 1) % len(KEYWAYS)
            self.pin = 0
            self.depths = self._init_depths()
        if ctx.key_pressed("r"):
            self.depths = self._mid(s)
        if ctx.key_pressed("equal") or ctx.key_pressed("period"):   # "+" / ">"
            self.ppm = min(30.0, self.ppm + 0.1)
        if ctx.key_pressed("minus") or ctx.key_pressed("comma"):    # "-" / "<"
            self.ppm = max(5.0, self.ppm - 0.1)
        if ctx.key_pressed("s"):
            self.save[s["name"]] = list(self.depths)
            self.save["_ppm"] = round(self.ppm, 2)
            ctx.storage.write_json(_STORE, self.save)
            ctx.log("saved %s = %s (ppm %.2f)" % (s["name"], self._code(), self.ppm), "ok")
        if ctx.key_pressed("l"):
            self.depths = self._init_depths()
            ctx.log("loaded %s" % s["name"])

    # ---- drawing (1:1 physical) --------------------------------------------
    def _draw(self, ctx, s):
        w, h = ctx.w, ctx.h
        ppm = self.ppm
        bad = self._macs_bad()

        ctx.text("KEY COPIER  //  1:1 TRACE", 8, 4, 20, "ice", bold=True)
        ctx.text("keyway: %s  [F]" % s["name"], 8, 32, 16, "teal")
        ctx.text("bitting: %s" % self._code(), 300, 32, 16, "hi", bold=True)
        if bad:
            ctx.text("MACS violation (max adj %d)" % s["macs"], 560, 32, 15, "danger")
        else:
            ctx.text("MACS ok (<= %d)" % s["macs"], 560, 32, 15, "success")

        # --- the key blade at true size, CENTRED on screen so a real key can be laid
        # on it clear of the bezel (both axes centred) ---
        n = s["pins"]
        blade_w = (s["first"] + (n - 1) * s["spacing"] + s["spacing"] * 0.8) * ppm
        blade_h = s["blade"] * ppm
        shoulder_x = (w - blade_w) / 2.0
        top_y = h * 0.5 - blade_h / 2.0
        blade_bottom = top_y + blade_h
        tip_x = shoulder_x + blade_w
        # shoulder reference line (align the real key's shoulder here)
        ctx.line(shoulder_x, top_y - 10, shoulder_x, blade_bottom + 24, "warn", 2)
        ctx.text("shoulder", shoulder_x - 24, top_y - 28, 13, "warn")

        # blade body (faint) + flat top edge + tip
        ctx.rect(shoulder_x, top_y, tip_x - shoulder_x, blade_bottom - top_y, "edge", True, 50)
        ctx.line(shoulder_x, top_y, tip_x, top_y, "dim", 2)
        ctx.line(tip_x, top_y, tip_x, blade_bottom, "dim", 2)

        def cut_y(d):
            return blade_bottom - (d - s["dmin"]) * s["step"] * ppm

        # toothed bottom edge through each cut
        prev = (shoulder_x, blade_bottom)
        for i in range(n):
            cx = shoulder_x + (s["first"] + i * s["spacing"]) * ppm
            cy = cut_y(self.depths[i])
            col = "danger" if (i in bad or (i - 1) in bad) else "teal"
            ctx.line(prev[0], prev[1], cx, cy, col, 2)
            prev = (cx, cy)
            if i == self.pin:
                ctx.line(cx, top_y, cx, blade_bottom + 18, "warn", 1)
                ctx.circle(cx, cy, 4, "warn")
            else:
                ctx.circle(cx, cy, 3, col)
            ds = str(self.depths[i])
            ctx.text(ds, cx - ctx.measure(ds, 16) / 2, blade_bottom + 22, 16,
                     "hi" if i == self.pin else "txt", bold=(i == self.pin))
        ctx.line(prev[0], prev[1], tip_x, blade_bottom, "teal", 2)

        ctx.text("lay a real key here, shoulder on the line, to trace its cuts",
                 shoulder_x, blade_bottom + 46, 14, "dim")

        # --- calibration: a 10 mm bar to check against a ruler ---
        bar_y = h - 54
        ctx.text("scale %.2f px/mm   [+/-] calibrate" % ppm, 8, bar_y - 20, 14, "ice")
        ctx.line(8, bar_y, 8 + 10 * ppm, bar_y, "hi", 3)
        ctx.line(8, bar_y - 5, 8, bar_y + 5, "hi", 2)
        ctx.line(8 + 10 * ppm, bar_y - 5, 8 + 10 * ppm, bar_y + 5, "hi", 2)
        ctx.text("10 mm (check with a ruler)", 8 + 10 * ppm + 10, bar_y - 7, 13, "dim")

        # transient "saved to loot" confirmation
        if self.flash and (ctx.now() - self.flash_t) < 6.0:
            ctx.text(self.flash[:120], 8, h - 74, 14, "success")

        # filename entry overlay (export to the loot folder)
        if self.naming:
            bw, bh = min(w - 40, 760), 86
            bx, by = (w - bw) // 2, (h - bh) // 2
            ctx.rect(bx, by, bw, bh, "void", True, 240)
            ctx.rect(bx, by, bw, bh, "ice", False, 255)
            ctx.text("SAVE TO LOOT  //  loot/extras/key_copier/", bx + 16, by + 12, 15, "ice", bold=True)
            cur = self.fname + "_"
            ctx.text(cur + ".txt", bx + 16, by + 40, 20, "hi", bold=True)
            ctx.text("[type a name]  [ENTER] save   [ESC] cancel", bx + 16, by + 66, 13, "dim")

        ctx.text("[<>] pin  [^v] depth  [F] keyway  [+/-] scale  [W] save->loot  [S/L] store  [R] reset",
                 8, h - 22, 13, "dim")
