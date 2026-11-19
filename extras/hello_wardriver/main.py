"""Hello Wardriver - the welcome card, and the reference EXTRA for images.

Three pages (LEFT / RIGHT to turn): what extras are, the ground rules, and how to
write your own. It needs no permissions: text, rectangles and two small PNG files
from this folder, drawn with ctx.image(). Pure stdlib + ctx.

Images live in the extra's own folder as plain PNG files:
  icon.png   the listing icon - at most 64x64 pixels and 16 KB
  others     drawn by the extra - at most 512x512 pixels and 256 KB each,
             8 files and 512 KB per extra in total
ctx.image(name, x, y, scale=1) draws one; scale is a whole number (pixels stay crisp).
"""

HUB = "github.com/LOCOSP/WDGoNG-HUB"

PAGES = ("WELCOME", "GROUND RULES", "WRITE YOUR OWN")

RULES = (
    ("warn", "Your gear, or gear you are allowed to test. Nothing else."),
    ("txt",  "Scanning and attacking networks or devices without the owner's"),
    ("txt",  "permission is illegal in most places. That part is on you."),
    ("",     ""),
    ("warn", "Extras are written by their authors - not by LOCOSP."),
    ("txt",  "They are reviewed and run in a sandbox, but you install and run"),
    ("txt",  "them at your own risk. Read what an extra asks for before you allow it."),
    ("",     ""),
    ("warn", "Don't be a skid."),
    ("txt",  "Learn how it works. Break your own stuff. Share what you find."),
)

HOWTO = (
    ("ice", "1  One folder:  extra.json  +  main.py"),
    ("dim", "   extra.json says who you are and which permissions you need."),
    ("ice", "2  One class with  on_enter / on_frame / on_exit"),
    ("dim", "   You only ever talk to ctx: draw, keys, gps, loot, storage."),
    ("ice", "3  Standard library only - no files, network or processes"),
    ("dim", "   The sandbox has none of them. That is the point."),
    ("ice", "4  Test on any computer:  tools/run_in_sim.py <dir> 30 --sandbox"),
    ("dim", "   Then  tools/hub_check.py <dir>  - the same check CI runs."),
    ("ice", "5  Open a pull request to the hub"),
    ("dim", "   Reviewed, signed, and it shows up under EXTRAS > Hub."),
)


class Extra:
    def on_enter(self, ctx):
        self.page = 0
        self.t = 0.0

    def on_frame(self, ctx, dt):
        self.t += dt
        if ctx.key_pressed("right") or ctx.key_pressed("space") or ctx.key_pressed("enter"):
            self.page = (self.page + 1) % len(PAGES)
        if ctx.key_pressed("left"):
            self.page = (self.page - 1) % len(PAGES)

        w, h = ctx.w, ctx.h
        # header: the icon, the title, the page tabs
        ctx.image("icon.png", 8, 6)                              # 48x48, drawn 1:1
        ctx.text("HELLO, WARDRIVER", 68, 8, 28, "ice", bold=True)
        ctx.text(PAGES[self.page], 68, 40, 16, "dim")
        x = w - 12
        for i in range(len(PAGES) - 1, -1, -1):
            x -= 22
            ctx.rect(x, 22, 16, 6, "ice" if i == self.page else "edge")
        ctx.rect(8, 62, w - 16, 1, "edge")

        top = 78
        if self.page == 0:
            self._welcome(ctx, w, h, top)
        elif self.page == 1:
            self._lines(ctx, RULES, 24, top + 6, 20, 30)
        else:
            self._lines(ctx, HOWTO, 24, top, 18, 25)
            ctx.text("Guide, examples, tools:  " + HUB, 24, top + 10 * 25 + 14, 18, "success", bold=True)

        ctx.text("[LEFT] [RIGHT] turn the page      [ESC] back", 8, h - 24, 16, "dim")

    def _welcome(self, ctx, w, h, top):
        # draw the logo as large as a whole-number scale allows in the space we have
        iw, ih = ctx.image_size("logo.png")
        scale = max(1, min(8, (h - top - 40) // ih, (w // 2 - 40) // iw))
        ctx.image("logo.png", 24, top + 4, scale=scale)
        x = 24 + iw * scale + 32
        ctx.text("Scan. Drive. Connect.", x, top + 8, 26, "hi", bold=True)
        lines = (
            ("txt", "Extras are small apps that plug into the game."),
            ("txt", "Anyone can write one. Every extra in the hub was"),
            ("txt", "reviewed, is listed in a signed catalogue, and runs"),
            ("txt", "in a sandbox - no files, no network, no radios unless"),
            ("txt", "you allow it."),
            ("", ""),
            ("dim", "This card is an extra too: about a hundred lines"),
            ("dim", "of Python and two tiny PNG files."),
        )
        self._lines(ctx, lines, x, top + 52, 18, 26)
        if int(self.t * 2) % 2 == 0:                              # a blinking cue
            ctx.text(">", x, top + 52 + len(lines) * 26 + 10, 20, "warn", bold=True)
        ctx.text("  press RIGHT for the rules", x, top + 52 + len(lines) * 26 + 10, 20, "warn")

    @staticmethod
    def _lines(ctx, lines, x, y, size, step):
        for color, s in lines:
            if s:
                ctx.text(s, x, y, size, color, bold=(color in ("warn", "ice")))
            y += step
