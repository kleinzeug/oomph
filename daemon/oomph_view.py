"""The dashboard of `oomph top`, drawn into a grid of cells (roadmap 04-tui, step T0).

Pure: no I/O, no clock, no terminal. `render(model, width, height, caps, ui)` returns a Frame;
the Frame prints itself as plain text, as ANSI escape sequences, or in the golden format the
self-test compares. oomph_top.py reads the files and builds the model.

The chart maths of the first table in the design (mapper, multires and worst, find_gaps,
calm_bands, stack_reservations, strip_top, res_color_index, merge_reservations) are ports of
the app's own functions in app/oomph.swift and must give the same numbers: the vectors in
tools/vectors/chart.json are written by the app (`oomph --chart-vectors`) and checked
against both programs (tools/chartvectors.py). The rest (columns, axis labels, the y top, the
cell rules) is the terminal's own and is tested by the golden frames.

Standard library only, Python 3.9.
"""
import math
import time
import unicodedata

BOLD, REV, UL, DIM = 1, 2, 4, 8
KEEP = object()          # Frame.put(..., bg=KEEP): leave the cell's background as it is
MIN_AGE = 300.0          # ages below this share the right edge of the log axis (MemoryChart.minAge)
GAP_S = 300.0            # longer than this without a sample is a gap (Store.gapSeconds)
QUEUE_STALE_S = 180.0    # a queue place not polled for this long has lapsed (oomph.QUEUE_STALE_S)
KEEP_DAYS = 14           # reservations and samples shown (the log keeps 14 days)
MERGE_KEEP = ("res", "peak", "v", "agent", "user")  # a later record's null does not undo these (oomph.MERGE_KEEP)
LEVELS = (604800, 86400, 21600, 3600, 900, 300, 60)   # grid levels, coarse first (MemoryChart.levels)
SERIES = ("wired", "app", "comp", "swap")             # stacked bottom to top
RES_ROLES = ("r0", "r1", "r2", "r3", "r4", "r5", "r6")  # teal purple pink indigo gold brown green
STRIP_TOPS = (2.0, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256)
Y_TOPS = (4, 5, 6, 8, 10, 12, 14, 16, 20, 24, 28, 32, 36, 40, 48, 56, 64, 72, 80, 96, 112, 128, 144, 160, 192, 224,
          256, 320, 384, 448, 512, 640, 768, 1024, 1536, 2048)
SPANS = {"inf": None, "24h": 86400.0, "6h": 21600.0, "1h": 3600.0}
SPAN_ORDER = ("inf", "24h", "6h", "1h")
DAYS = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")   # built in: frames are the same in every locale
RIGHT_W = 48             # the second column of the wide layout
FULL = "█"               # a fully covered cell; colour terminals get a space on a coloured background


# ------------------------------------------------------------------ themes and the colour rule
# `fg` and `bg` are what the terminal shows for "default" (SGR 39 / 49); they are never painted.
# `ink` is primary text on a background the program painted (bar, selection, capsule).
THEMES = {
    "dark": {
        "fg": "#DDDDDD", "bg": "#1E1E1E", "ink": "#DADADA", "dim": "#949494", "faint": "#6C6C6C", "line": "#4E4E4E",
        "grid": "#3A3A3A", "bar": "#262626", "wired": "#98989D", "app": "#0091FF", "comp": "#FF9230", "swap": "#FF4245",
        "incident": "#FF4245", "ok": "#30D158", "warn": "#FFD60A", "warntx": "#D78700", "crit": "#FF4245",
        "away": "#303031", "hatch": "#6C6C6C", "sel": "#5F5F5F", "selfg": "#FFFFFF", "trough": "#2B2B2B",
        "accent": "#0091FF", "onblock": "#111111", "rowsel": "#3A3A3A",
        "r0": "#06AEB9", "r1": "#BF5AF2", "r2": "#E8507A", "r3": "#7A78F5", "r4": "#D69E00", "r5": "#AC8E68",
        "r6": "#4CB85C",
    },
    "light": {
        "fg": "#262626", "bg": "#FFFFFF", "ink": "#262626", "dim": "#767676", "faint": "#9E9E9E", "line": "#C4C4C4",
        "grid": "#E2E2E2", "bar": "#EEEEEE", "wired": "#8E8E93", "app": "#0088FF", "comp": "#FF8D28", "swap": "#FF383C",
        "incident": "#FF383C", "ok": "#1F8A3B", "warn": "#8A6A00", "warntx": "#8A6A00", "crit": "#C4262A",
        "away": "#EEEEEF", "hatch": "#A8A8A8", "sel": "#FFFFFF", "selfg": "#000000", "trough": "#E4E4E4",
        "accent": "#0088FF", "onblock": "#FFFFFF", "rowsel": "#DCDCDC",
        "r0": "#12A5B0", "r1": "#A550E0", "r2": "#F04F78", "r3": "#5E5CE6", "r4": "#C89400", "r5": "#A2845E",
        "r6": "#34A853",
    },
}
ON_PAINT = ("ink", "selfg", "onblock")      # text colours that only make sense on a painted background
# One stable character per role for the golden format: a new style never renames the others.
ROLE_CODE = {None: ".", "fg": ".", "ink": "I", "dim": "d", "faint": "f", "line": "l", "grid": "g", "bar": "B",
             "trough": "T", "sel": "S", "selfg": "s", "wired": "w", "app": "a", "comp": "c", "swap": "p",
             "incident": "i", "ok": "o", "warn": "W", "warntx": "x", "crit": "C", "away": "y", "hatch": "h",
             "accent": "A", "onblock": "k", "rowsel": "R", "r0": "0", "r1": "1", "r2": "2", "r3": "3", "r4": "4", "r5": "5", "r6": "6"}
MOD_CODE = {"": ".", "off": "o"}
# 16 colours: the index (0-7 normal, 8-15 bright) or None for the terminal's default. Whatever is a
# block or a background is one of the eight base colours, so it works as SGR 40-47 too.
ROLE16 = {"fg": None, "ink": None, "selfg": None, "dim": 8, "faint": 8, "line": 8, "grid": 8, "hatch": 8,
          "wired": 7, "app": 4, "comp": 3, "swap": 1, "incident": 9, "crit": 1, "ok": 2, "warn": 3, "warntx": 3,
          "accent": 12, "onblock": 0, "r0": 6, "r1": 5, "r2": 1, "r3": 4, "r4": 3, "r5": 7, "r6": 2}
# The reference theme: hand-picked xterm-256 indexes where the nearest one loses the hue.
# "name@off" is the muted palette of what is no longer live.
PICK256 = {"dark": {"comp": 208, "ok": 41, "warn": 220, "warntx": 172, "swap": 203, "incident": 203, "r4": 178,
                    "ink": 253, "dim": 246, "faint": 242, "hatch": 242, "bar": 235, "trough": 236, "sel": 59,
                    "rowsel": 237, "wired@off": 243, "app@off": 67, "comp@off": 137, "swap@off": 131},
           "light": {"comp": 208, "ok": 28, "warn": 94, "warntx": 94, "swap": 203, "incident": 203, "away": 254,
                     "bar": 255, "trough": 253, "sel": 231, "ink": 235, "dim": 243, "faint": 247, "hatch": 248, "rowsel": 253,
                     "wired@off": 247, "app@off": 110, "comp@off": 180, "swap@off": 174}}
_CUBE = (0, 95, 135, 175, 215, 255)


def _rgb(h):
    return int(h[1:3], 16), int(h[3:5], 16), int(h[5:7], 16)


def _hex(r, g, b):
    return "#%02X%02X%02X" % (int(round(r)), int(round(g)), int(round(b)))


def _blend(a, b, k):
    """k of the way from colour a to colour b."""
    ra, ga, ba = _rgb(a)
    rb, gb, bb = _rgb(b)
    return _hex(ra + (rb - ra) * k, ga + (gb - ga) * k, ba + (bb - ba) * k)


def _muted(h, keep=0.38):
    """Desaturated to about a third: the hue stays readable, the colour stops shouting."""
    r, g, b = _rgb(h)
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    return _hex(y + (r - y) * keep, y + (g - y) * keep, y + (b - y) * keep)


def _xterm(i):
    if i >= 232:
        return (8 + 10 * (i - 232),) * 3
    i -= 16
    return _CUBE[i // 36], _CUBE[(i // 6) % 6], _CUBE[i % 6]


def nearest256(h):
    """The xterm-256 index (16-255: the cube and the grey ramp, never the 16 themable ones)."""
    r, g, b = _rgb(h)
    best, bd = 16, 1e18
    for i in range(16, 256):
        x, y, z = _xterm(i)
        d = (x - r) ** 2 * 0.30 + (y - g) ** 2 * 0.59 + (z - b) ** 2 * 0.11
        if d < bd:
            best, bd = i, d
    return best


class Caps:
    """What the terminal can do. color: truecolor | 256 | 16 | none; glyphs: unicode | cells | ascii;
    theme: dark | light (a guess about the terminal's background: everything stays readable when
    it is wrong)."""

    def __init__(self, color="256", glyphs="unicode", theme="dark"):
        self.color, self.glyphs, self.theme = color, glyphs, theme

    def true_hex(self, role):
        t = THEMES[self.theme]
        name, _, mod = role.partition("@")
        h = t[name]
        if mod == "off":        # no longer live: muted, pulled toward the background
            h = _blend(_muted(h), t["bg"], 0.30 if name in SERIES or name in RES_ROLES or name == "incident" else 0.38)
        return h

    def index(self, role):
        key = (self.theme, role)
        i = _INDEX.get(key)
        if i is None:
            i = _INDEX[key] = PICK256[self.theme].get(role) or nearest256(self.true_hex(role))
        return i


_INDEX = {}         # (theme, role) → xterm-256 index: the search over 240 colours runs once per role
_PAINT = {}         # (depth, glyphs, theme, full?, fg, bg, flags) → (character for a full cell, SGR)


GLYPHS = {
    "unicode": dict(h="─", v="│", tl="╭", tr="╮", bl="╰", br="╯", lt="├", rt="┤", eighths=" ▁▂▃▄▅▆▇█",
                    hatch="╱", grid="┊", inc="┃", awaydot="·", sw="■", swq="□", dot="●", odot="○",
                    sel="›", ell="…", inf="∞", mid="·", shades="█▓▒░", queued="▒", ram=("_", "╌", "‾"),
                    meter="█", meterbg="░", arrows="←→", updown="↑↓", legend_sw="■", legend_away="░",
                    more_l="‹", more_r="›", up="▴", down="▾", dash="–", arrow="→"),
    "ascii": dict(h="-", v="|", tl="+", tr="+", bl="+", br="+", lt="+", rt="+", eighths=" ...::###",
                  hatch="/", grid=" ", inc="!", awaydot=".", sw="#", swq="o", dot="*", odot="o",
                  sel=">", ell="~", inf="all", mid="-", shades="#=:*", queued="?", ram=("_", "-", "-"),
                  meter="#", meterbg=".", arrows="<>", updown="^v", legend_sw="#", legend_away=".",
                  more_l="<", more_r=">", up="^", down="v", dash="-", arrow="->"),
}
GLYPHS["cells"] = dict(GLYPHS["unicode"])      # --glyphs cells: the rasteriser differs, the characters do not


def resolve(cell, caps):
    """A cell → (char, fg SGR, bg SGR, flags) as this terminal gets it (None: the terminal's own).
    The rules, in one place:
      1. Primary text on an unpainted cell is the terminal's own foreground, never a colour of ours.
      2. A painted background gets a painted foreground of the same theme ('fg' becomes 'ink').
      3. A fully covered cell is a space on a coloured background (backgrounds tile in every
         terminal; a FULL BLOCK glyph depends on the font). Without colour it stays the glyph."""
    ch, fg, bg, fl = cell
    if caps.color == "none":
        mod = (fg or "").partition("@")[2] or (bg or "").partition("@")[2]
        return ch, None, None, fl | (DIM if mod else 0)
    fg = fg or "fg"
    fname, _, fmod = fg.partition("@")
    bname, _, bmod = (bg or "").partition("@")
    if caps.color == "16":
        if bname in ("sel", "rowsel"):                       # selection is reverse video
            fl, bname = fl | REV, ""
        elif bname in ("bar", "trough", "away"):             # surfaces are not painted
            bname = ""
        if fmod or bmod:
            fl |= DIM
        fi = ROLE16.get(fname)
        bi = ROLE16.get(bname) if bname else None
        if ch == FULL and fi is not None and fi < 8:
            ch, bi, fi = " ", fi, None
        return (ch, None if fi is None else str(30 + fi if fi < 8 else 82 + fi),
                None if bi is None else str(40 + bi if bi < 8 else 92 + bi), fl)
    if bg is None:
        fspec = None if fg == "fg" else fg                   # rule 1
    else:
        fspec = "ink" + ("@" + fmod if fmod else "") if fname == "fg" else fg   # rule 2
    bspec = bg
    if ch == FULL and fspec is not None:                     # rule 3
        ch, bspec, fspec = " ", fspec, None

    def sgr(role, lead):
        if role is None:
            return None
        if caps.color == "truecolor":
            return "%s;2;%d;%d;%d" % ((lead,) + _rgb(caps.true_hex(role)))
        return "%s;5;%d" % (lead, caps.index(role))
    return ch, sgr(fspec, "38"), sgr(bspec, "48"), fl


def paint(cell, caps):
    """(char to write, the SGR sequence that must be in force). Remembered per style: a frame has a
    few dozen styles and thousands of cells."""
    key = (caps.color, caps.glyphs, caps.theme, cell[0] == FULL, cell[1], cell[2], cell[3])
    hit = _PAINT.get(key)
    if hit is None:
        ch, f, b, fl = resolve(cell, caps)
        codes = ["0"]
        for bit, code in ((BOLD, "1"), (DIM, "2"), (UL, "4"), (REV, "7")):
            if fl & bit:
                codes.append(code)
        codes += [c for c in (f, b) if c]
        if len(_PAINT) > 4096:
            _PAINT.clear()
        hit = _PAINT[key] = (ch if cell[0] == FULL else None, "\x1b[%sm" % ";".join(codes))
    return (cell[0] if hit[0] is None else hit[0]), hit[1]


def lint_pairing(frame):
    """The colour rule as a test: no text colour of a painted surface on an unpainted cell."""
    return [(x, y, ch) for y, row in enumerate(frame.c) for x, (ch, fg, bg, fl) in enumerate(row)
            if bg is None and (fg or "fg").partition("@")[0] in ON_PAINT and ch not in (" ", "")]


# ------------------------------------------------------------------ text that cannot hurt
# Two cells wide: exactly these ranges (CJK, kana, Hangul, fullwidth forms). A table of our own: the
# interpreter's differs by version, and golden frames must be the same on every runner.
WIDE2 = ((0x1100, 0x115F), (0x2E80, 0x303E), (0x3041, 0x33FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xA000, 0xA4CF),
         (0xA960, 0xA97F), (0xAC00, 0xD7A3), (0xF900, 0xFAFF), (0xFE30, 0xFE6F), (0xFF01, 0xFF60), (0xFFE0, 0xFFE6),
         (0x20000, 0x2FFFD), (0x30000, 0x3FFFD))
# Never drawn: jamo that terminals join or draw zero-width, and the blocks whose width differs between
# terminals (emoji and their neighbours).
HOLES = ((0x1160, 0x11FF), (0xD7B0, 0xD7FF), (0x231A, 0x231B), (0x2329, 0x232A), (0x23E9, 0x23F3), (0x25FD, 0x25FE),
         (0x2600, 0x27BF), (0x2B1B, 0x2B1C), (0x2B50, 0x2B55), (0x1F000, 0x1FAFF), (0xE0000, 0xE0FFF))
VARIATION = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))      # dropped: they only select a presentation
PLACEHOLDER = "·"
_CLASS = {}


def _in(cp, ranges):
    return any(a <= cp <= b for a, b in ranges)


def _classify(ch):
    """1 or 2: cells · 'm': a mark that joins the cell before it · 0: dropped · -1: replaced."""
    cp = ord(ch)
    if 0x20 <= cp < 0x7F:
        return 1
    if _in(cp, VARIATION):
        return 0
    if _in(cp, HOLES):
        return -1
    cat = unicodedata.category(ch)
    if cat in ("Mn", "Me"):
        return "m"
    if cat[0] not in "LNPS" and cat != "Zs":      # Cc Cf Cs Co Cn Zl Zp Mc
        return -1
    if unicodedata.bidirectional(ch) in ("R", "AL", "AN"):   # terminals reorder these runs themselves
        return -1
    return 2 if _in(cp, WIDE2) else 1


def cells_of(text, ascii_only=False):
    """Untrusted text → a list of cell strings: a base character with at most two marks, or "" for
    the second half of a two-cell character. Nothing that could move the cursor, change a colour,
    reorder the row or take an unknown width gets through."""
    if text.isascii() and text.isprintable():
        return list(text)
    out = []
    for ch in unicodedata.normalize("NFC", text):
        k = _CLASS.get(ch)
        if k is None:
            if len(_CLASS) > 4096:              # a day of hostile text must not grow it without end
                _CLASS.clear()
            k = _CLASS[ch] = _classify(ch)
        if k == 1:
            c = " " if unicodedata.category(ch) == "Zs" else ch
            out.append(c if (not ascii_only or ord(c) < 128) else "?")
        elif k == 2:
            out += ["?", "?"] if ascii_only else [ch, ""]
        elif k == "m":
            if out and out[-1] not in ("", PLACEHOLDER, "?") and len(out[-1]) < 3 and not ascii_only:
                out[-1] += ch
        elif k == -1:
            out.append("." if ascii_only else PLACEHOLDER)
    return out


def tw(text):
    """Display width in cells."""
    return len(cells_of(text))


def fit(text, n, g=None):
    """Cut to n cells with an ellipsis; never splits a two-cell character. Only the first 4n + 8
    characters are looked at: a longer text ends in the ellipsis wherever those end (a frame must
    not pay for megabytes of a planted purpose)."""
    cut = len(text) > 4 * n + 8
    cells = cells_of(text[:4 * n + 8] if cut else text)
    if len(cells) <= n and not cut:
        return "".join(cells)
    ell = (g or GLYPHS["unicode"])["ell"][:1]
    keep = cells[:max(n - 1, 0)]
    if len(keep) < len(cells) and cells[len(keep)] == "" and keep:      # the cut fell inside a pair
        keep[-1] = " "
    return "".join(keep) + (ell if n > 0 else "")


# ------------------------------------------------------------------ the frame
class Frame:
    """The whole screen as cells [char, fg role, bg role, flags]; char is "" in the second cell of a
    two-cell character. put() is the only way text gets in, and it cleans."""

    def __init__(self, w, h, ascii_only=False):
        self.w, self.h, self.ascii_only = w, h, ascii_only
        self.yhold = None           # what the plot's y axis holds for the next frame (the loop keeps it)
        self.c = [[[" ", None, None, 0] for _ in range(w)] for _ in range(h)]

    def put(self, x, y, text, fg=None, bg=KEEP, fl=0):
        cells = cells_of(text, self.ascii_only)
        if not 0 <= y < self.h:
            return x + len(cells)
        row = self.c[y]
        i = 0
        while i < len(cells):
            ch = cells[i]
            wide = i + 1 < len(cells) and cells[i + 1] == ""
            if wide and not (0 <= x and x + 1 < self.w):
                ch, wide = " ", False                  # half of it would be outside: a blank instead
                cells[i + 1] = " "
            if 0 <= x < self.w:
                self._unpair(row, x)
                cell = row[x]
                cell[0], cell[1], cell[3] = ch, fg, fl
                if bg is not KEEP:
                    cell[2] = bg
                if wide:
                    self._unpair(row, x + 1)
                    nxt = row[x + 1]
                    nxt[0], nxt[1], nxt[3] = "", fg, fl
                    if bg is not KEEP:
                        nxt[2] = bg
            x += 2 if wide else 1
            i += 2 if wide else 1
        return x

    def _unpair(self, row, x):
        """Writing over half of a two-cell character blanks the other half, as a terminal does."""
        if row[x][0] == "" and x > 0:
            row[x - 1][0] = " "
        elif x + 1 < self.w and row[x + 1][0] == "":
            row[x + 1][0] = " "

    def rput(self, x_right, y, text, fg=None, bg=KEEP, fl=0):
        """Right-aligned: the last cell lands on x_right."""
        self.put(x_right - tw(text) + 1, y, text, fg, bg, fl)

    def fill(self, x, y, w, h, ch=" ", fg=None, bg=None, fl=0):
        for yy in range(y, y + h):
            self.put(x, yy, ch * max(w, 0), fg, bg, fl)

    def hline(self, x, y, w, g, fg="line", left=None, right=None):
        self.put(x, y, g["h"] * w, fg)
        if left:
            self.put(x, y, left, fg)
        if right:
            self.put(x + w - 1, y, right, fg)

    def box(self, x, y, w, h, g, fg="line"):
        self.hline(x, y, w, g, fg, g["tl"], g["tr"])
        self.hline(x, y + h - 1, w, g, fg, g["bl"], g["br"])
        for yy in range(y + 1, y + h - 1):
            self.put(x, yy, g["v"], fg)
            self.put(x + w - 1, yy, g["v"], fg)

    def bg(self, x, y, w, h, role):
        """Paint the background of a rectangle, keeping what is drawn there."""
        for yy in range(max(y, 0), min(y + h, self.h)):
            for xx in range(max(x, 0), min(x + w, self.w)):
                self.c[yy][xx][2] = role

    def flag(self, x, y, w, h, fl):
        for yy in range(max(y, 0), min(y + h, self.h)):
            for xx in range(max(x, 0), min(x + w, self.w)):
                self.c[yy][xx][3] |= fl

    def restyle(self, x, y, w, h, mod):
        """Append a role modifier ('off') to every colour in a rectangle."""
        for yy in range(max(y, 0), min(y + h, self.h)):
            for xx in range(max(x, 0), min(x + w, self.w)):
                cell = self.c[yy][xx]
                cell[1] = (cell[1] or "fg").partition("@")[0] + "@" + mod
                if cell[2]:
                    cell[2] = cell[2].partition("@")[0] + "@" + mod

    # ---- exporters
    def text(self):
        return "\n".join("".join(cell[0] for cell in row) for row in self.c) + "\n"

    def ansi(self, caps):
        """SGR escape sequences, one line per row: `cat` it in a terminal."""
        lines = []
        for row in self.c:
            s, last = [], None
            for cell in row:
                if cell[0] == "":
                    continue
                ch, sgr = paint(cell, caps)
                if sgr != last:
                    s.append(sgr)
                    last = sgr
                s.append(ch)
            lines.append("".join(s) + "\x1b[0m")
        return "\n".join(lines) + "\n"

    def golden(self, header):
        """The snapshot-test format: the characters, then one plane each for foreground role,
        background role, attributes and (where used) the role modifier. Every role has a fixed code
        (ROLE_CODE), so a new style never renames the others; a role without one fails loudly."""
        fgp, bgp, atp, mdp, used, any_mod = [], [], [], [], set(), False
        for row in self.c:
            f, b, a, m = [], [], [], []
            for ch, fg, bg, fl in row:
                fn, _, fm = (fg or "").partition("@")
                bn, _, bm = (bg or "").partition("@")
                if (fn or None) not in ROLE_CODE or (bn or None) not in ROLE_CODE:
                    raise KeyError("no golden code for role %r / %r" % (fg, bg))
                f.append(ROLE_CODE[fn or None])
                b.append(ROLE_CODE[bn or None])
                a.append("." if not fl else "%x" % fl)
                m.append(MOD_CODE[fm or bm])
                any_mod = any_mod or bool(fm or bm)
                used.update((fn or "fg", bn or None))
            fgp.append("".join(f))
            bgp.append("".join(b))
            atp.append("".join(a))
            mdp.append("".join(m))
        legend = "  ".join("%s=%s" % (ROLE_CODE[r], r) for r in sorted(used - {None, "fg"}))
        out = ["# %s" % header, "--- text", self.text().rstrip("\n"), "--- fg", "\n".join(fgp), "--- bg",
               "\n".join(bgp), "--- attr (1 bold, 2 reverse, 4 underline, 8 dim; hex sum)", "\n".join(atp)]
        if any_mod:
            out += ["--- mod (o no longer live)", "\n".join(mdp)]
        out += ["--- roles", ". = primary text (fg plane) / not painted (bg plane)  " + legend]
        return "\n".join(out) + "\n"


# ------------------------------------------------------------------ chart maths: ports of the app's
# Keep these in step with app/oomph.swift; tools/vectors/chart.json holds both to the same numbers.
def mapper(now, first, span_s):
    """MemoryChart.mapper with blend 0 (linear: the last span_s seconds) or, span_s None, blend 1 (log
    in age over all history, ages under MIN_AGE at the right edge). Time → x in 0…1 (1 = now), and
    its inverse."""
    if span_s is None:
        sp = math.log10(max(now - first, 3600.0) / MIN_AGE)
        return (lambda t: 1 - math.log10(max(now - t, MIN_AGE) / MIN_AGE) / sp,
                lambda x: now - MIN_AGE * 10 ** ((1 - x) * sp))
    return (lambda t: 1 - max(now - t, 0) / span_s), (lambda x: now - (1 - x) * span_s)


def find_gaps(pts, now):
    """Store.findGaps: more than GAP_S between samples as logged (before thinning), and from the last
    sample to now."""
    gaps = [(a["t"], b["t"]) for a, b in zip(pts, pts[1:]) if b["t"] - a["t"] > GAP_S]
    if pts and now - pts[-1]["t"] > GAP_S:
        gaps.append((pts[-1]["t"], now))
    return gaps


def worst(bucket):
    """Store.worst: the point with the most app + compressed + swap, away if any was, kills summed."""
    w = max(bucket, key=lambda p: p["app"] + p["comp"] + p["swap"])
    if len(bucket) == 1:
        return w
    return dict(w, away=any(p["away"] for p in bucket), kills=sum(p["kills"] for p in bucket))


def multires(pts, now):
    """Store.multires: buckets max(30 s, age/720) wide, each its worst point, never across a gap."""
    out, j = [], len(pts) - 1
    while j >= 0:
        width = max(30.0, (now - pts[j]["t"]) / 720)
        i = j
        while i > 0 and pts[i - 1]["t"] > pts[j]["t"] - width and pts[i]["t"] - pts[i - 1]["t"] <= GAP_S:
            i -= 1
        out.append(worst(pts[i:j + 1]))
        j = i - 1
    out.reverse()
    return out


def calm_bands(away, gaps, tolerance):
    """MemoryChart.calmBands: spans closer than `tolerance` merge. Grey: away spans, bridged by the
    no-data stretches that touch them. Returns (grey spans, hatched spans). The app calls it with
    pixels and 2 px; the terminal with columns and 0."""
    def merge(spans):
        out = []
        for a, b, flag in sorted(spans, key=lambda s: s[0]):
            if out and a - out[-1][1] <= tolerance:
                out[-1] = (out[-1][0], max(out[-1][1], b), out[-1][2] or flag)
            else:
                out.append((a, b, flag))
        return out
    grey = [(a, b) for a, b, flag in merge([(a, b, True) for a, b in away] + [(a, b, False) for a, b in gaps]) if flag]
    return grey, [(a, b) for a, b, _ in merge([(a, b, True) for a, b in gaps])]


def strip_top(tallest):
    """MemoryChart.stripTop: the strip's scale, the first round figure at or above the tallest stack."""
    return next((s for s in STRIP_TOPS if s >= tallest), tallest)


def res_color_index(purpose):
    """Reservation.colorIndex: the same purpose always gets the same colour, by a stable hash over its
    Unicode scalars."""
    h = 5381
    for ch in purpose:
        h = ((h * 33) & 0xFFFFFFFF) ^ ord(ch)
    return h % len(RES_ROLES)


def res_color(purpose):
    return RES_ROLES[res_color_index(purpose)]


def gb_at(r, t):
    """Reservation.gb(at:): its size at time t."""
    return ([g for s, g in r["segments"] if s <= t] or [r["segments"][0][1]])[-1]


def stack_reservations(rs, now):
    """ResBlock.stack: lanes first-fit by request time; steps [a, b) with the stacked GB below (lo) and
    at the top (hi) of each block. An unchanged step is extended instead of repeated, except at the
    moment of the grant."""
    blocks = [dict(res=r, end=max(r["ended"] if r.get("ended") is not None else now, r["requested"] + 1), lane=0,
                   steps=[]) for r in sorted(rs, key=lambda r: r["requested"])]
    lane_end = []
    for b in blocks:
        for k, e in enumerate(lane_end):
            if e <= b["res"]["requested"]:
                b["lane"], lane_end[k] = k, b["end"]
                break
        else:
            b["lane"] = len(lane_end)
            lane_end.append(b["end"])
    bps = set()
    for b in blocks:
        r = b["res"]
        bps.update((r["requested"], b["end"]))
        if r.get("granted") is not None and r["requested"] < r["granted"] < b["end"]:
            bps.add(r["granted"])
        bps.update(t for t, _ in r["segments"] if r["requested"] < t < b["end"])
    ts = sorted(bps)
    active, nxt = [], 0
    for a, bb in zip(ts, ts[1:]):
        while nxt < len(blocks) and blocks[nxt]["res"]["requested"] <= a:
            active.append(nxt)
            nxt += 1
        active = [k for k in active if blocks[k]["end"] > a]
        acc = 0.0
        for k in sorted(active, key=lambda k: blocks[k]["lane"]):
            r = blocks[k]["res"]
            steps, hi = blocks[k]["steps"], acc + gb_at(r, a)
            if steps and steps[-1][1] == a and steps[-1][2] == acc and steps[-1][3] == hi and r.get("granted") != a:
                steps[-1] = (steps[-1][0], bb, acc, hi)
            else:
                steps.append((a, bb, acc, hi))
            acc = hi
    return blocks


def _key(o):
    return o.get("key") or "%s@%d" % (o["id"], int(o.get("requested") or 0))


def _s(x, default=None):
    """A string of the shared ledger, cut to LIMITS["str"] (any user can plant a file of megabytes
    there; a frame looks at its strings every second). oomph writes at most 80 characters."""
    return x[:200] if isinstance(x, str) else default


def _norm(o):
    """Reservation(_:): a lease, a ledger history entry or a history log record, in one shape. The
    strings are cut to 200 characters; the key stays whole (it is matched, not drawn)."""
    segs = [(s["t"], s["gb"]) for s in (o.get("segments") or [])
            if isinstance(s, dict) and isinstance(s.get("t"), (int, float)) and isinstance(s.get("gb"), (int, float))]
    h = o.get("holder")
    return dict(key=_key(o), id=_s(o["id"]), purpose=_s(o.get("purpose"), "?"),
                project=_s(o.get("project")), holder=_s(h.get("kind") if isinstance(h, dict) else h),
                pid=h.get("pid") if isinstance(h, dict) and isinstance(h.get("pid"), int) else None,
                requested=o["requested"], granted=o.get("granted"), ended=o.get("ended"), outcome=_s(o.get("outcome")),
                peak=o.get("peak_gb") or 0, used=o.get("used_gb"), expires=o.get("expires"),
                segments=segs or [(o["requested"], o["gb"])])


def merge_reservations(records, ledger, now, holder_alive=None, own_ns=None):
    """Store.mergeReservations: the records of the history log merged per key (a later record
    overrides the fields it has, a null not those of MERGE_KEEP; an "end" is never undone by a
    later record of another kind, an "edit" or a newer writer's "grant"; oomph.merge_history), then
    the ledger's own short history, then the live leases. As in the app, a grant past its expiry
    ends as "expired", a queue place not polled for QUEUE_STALE_S as "lapsed", a lease whose holder
    is gone as "holder_gone" (only when holder_alive is given: the local machine; and only for a
    holder without `ns` or with own_ns, the viewer's pid namespace, None on a Mac: another's pid
    means something else here; oomph._holder_gone), and a
    reservation whose records end in no "end" and whose lease is no longer in the ledger as
    "unknown" (the ledger was reset under it). Returns what ended in the last KEEP_DAYS or is
    live, by request time."""
    def ok(o):
        return (isinstance(o, dict) and isinstance(o.get("id"), str) and isinstance(o.get("requested"), (int, float))
                and isinstance(o.get("gb"), (int, float)))
    merged, events = {}, {}
    for o in records:
        if not ok(o):
            continue
        ev = o["event"] if isinstance(o.get("event"), str) else "end"
        k = _key(o)
        if k not in merged:
            merged[k], events[k] = dict(o), ev
        elif ev == "end" or events[k] != "end":
            merged[k].update((f, x) for f, x in o.items() if not (x is None and f in MERGE_KEEP))
            events[k] = ev
    by = {k: _norm(o) for k, o in merged.items()}
    ledger = ledger if isinstance(ledger, dict) else {}
    for h in ledger.get("history") or []:
        if ok(h):
            by.setdefault(_key(h), _norm(h))
    live = set()
    for pos, lease in enumerate(ledger.get("leases") or []):
        if not ok(lease):
            continue
        r, k = _norm(lease), _key(lease)
        r["queue"] = pos                    # the ledger's order is the queue's (a grown request moves back)
        live.add(k)
        seen = lease.get("seen") if isinstance(lease.get("seen"), (int, float)) else r["requested"]
        h = lease.get("holder")
        pid = h.get("pid") if isinstance(h, dict) and isinstance(h.get("pid"), int) \
            and h.get("ns") in (None, own_ns) else 0
        if r["expires"] is not None and r["granted"] is not None and r["expires"] < now:
            r.update(ended=r["expires"], outcome="expired")
        elif r["granted"] is None and now - seen > QUEUE_STALE_S:
            r.update(ended=seen + QUEUE_STALE_S, outcome="lapsed")
        elif holder_alive is not None and pid > 0 and not holder_alive(pid):
            r.update(ended=max(seen, r["granted"] if r["granted"] is not None else r["requested"]), outcome="holder_gone")
        by[k] = r
    for k, ev in events.items():
        if ev != "end" and by[k]["ended"] is None and k not in live:
            by[k].update(ended=by[k]["segments"][-1][0], outcome="unknown")
    keep = now - KEEP_DAYS * 86400
    return sorted((r for r in by.values() if (r["ended"] if r["ended"] is not None else now) >= keep),
                  key=lambda r: (r["requested"], r["key"]))


# ------------------------------------------------------------------ chart maths: the terminal's own
def columns(pts, gaps, f, finv, W, now, first=None):
    """One entry per screen column: ('data', point) | ('gap', None) | ('none', None) (before history).
    A column between two samples less than a gap apart repeats its nearer neighbour."""
    buckets = [[] for _ in range(W)]
    for p in pts:
        x = f(p["t"])
        if x < 0:
            continue
        buckets[min(W - 1, int(x * W))].append(p)
    cols = []
    if first is None:
        first = pts[0]["t"] if pts else now
    for c in range(W):
        if buckets[c]:
            cols.append(("data", worst(buckets[c])))
            continue
        ta, tb = finv(c / float(W)), finv((c + 1) / float(W))
        if c == W - 1:
            tb = now
        if tb <= first:
            cols.append(("none", None))
        elif any(g0 < tb and g1 > ta for g0, g1 in gaps):
            cols.append(("gap", None))
        else:
            cols.append(("hold", None))
    for c in range(W):
        if cols[c][0] == "hold":
            near = None
            for d in range(1, W):
                for k in (c - d, c + d):
                    if 0 <= k < W and cols[k][0] == "data":
                        near = cols[k][1]
                        break
                if near:
                    break
            cols[c] = ("data", near) if near else ("none", None)
    return cols


def _lt(t):
    return time.localtime(t)


def day_label(t):
    lt = _lt(t)
    return "%s %d" % (DAYS[lt.tm_wday], lt.tm_mday)


def hhmm(t):
    lt = _lt(t)
    return "%02d:%02d" % (lt.tm_hour, lt.tm_min)


def day_hhmm(t):
    return "%s %s" % (day_label(t), hhmm(t))


def axis_labels(f, W, now, log=False):
    """Labels on clock-aligned grid lines, coarsest level first, none closer than 7 cells. On the log
    axis the right edge is always labelled 'now'."""
    tz = _lt(now).tm_gmtoff
    min_gap, min_spacing = max(7.0, 0.102 * W), 0.044 * W
    out = [(1.0, "now")] if log else []
    for unit in LEVELS:
        off = 4 * 86400 if unit == 604800 else 0   # weeks start on Monday
        t = math.floor((now + tz - off) / unit) * unit - tz + off
        for _ in range(400):
            x = f(t)
            if x < 0 or (x - f(t - unit)) * W < min_spacing:
                break
            if 0.03 <= x <= (1.0 if log else 0.95) and all(abs(o[0] - x) * W >= min_gap for o in out):
                out.append((x, day_label(t) if unit >= 86400 else hhmm(t)))
            t -= unit
    return sorted(out)


def nice_top(v, steps=Y_TOPS):
    """The y axis tops out at the first of these that holds v: at most a fifth of the height is
    headroom (16 GB → 20, 36 → 40, 64 → 72)."""
    return next((s for s in steps if s >= v), v)


def y_top(ram, cols, hold=None, left=None, now=0):
    """The first round value that holds 1.1 x RAM and 1.02 x the highest stack in view. It steps up at
    once and down only when the peak that raised it has left the view: `hold` is (top, time of that
    peak), kept by the caller between frames (--once has none). Returns (top, new hold)."""
    best_t, peak = None, 0.0
    for st, p in cols:
        if st == "data":
            v = p["wired"] + p["app"] + p["comp"] + p["swap"]
            if v > peak:
                peak, best_t = v, p["t"]
    top = nice_top(max((ram or 0) * 1.1, peak * 1.02, 1.0))
    if hold and hold[0] > top and (left is None or hold[1] >= left):
        return hold[0], hold
    return top, (top, best_t if best_t is not None else now)


def stack_cells(segs, H, eighths, empty_bg=None):
    """segs: [(lo, hi, role)] in levels (8 per row), bottom to top, contiguous from 0. Returns H cells
    bottom-up as (char, fg, bg): at most two colours per cell, the lower part the glyph's foreground,
    the part above it the cell's background."""
    out = []
    for r in range(H):
        a, b = 8 * r, 8 * r + 8
        occ = []
        for lo, hi, col in segs:
            lo_, hi_ = max(lo, a), min(hi, b)
            if hi_ > lo_:
                occ.append([hi_ - lo_, lo_, col])
        filled = sum(o[0] for o in occ)
        if not occ:
            out.append((" ", None, empty_bg))
            continue
        if filled < 8:
            occ.append([8 - filled, a + filled, None])
        if len(occ) == 1:
            out.append((eighths[8], occ[0][2], None))
            continue
        lower, upper = sorted(sorted(occ, key=lambda o: -o[0])[:2], key=lambda o: o[1])
        if lower[2] is None:
            out.append((" ", None, empty_bg))
            continue
        n = max(1, min(7, int(round(8.0 * lower[0] / (lower[0] + upper[0])))))
        out.append((eighths[n], lower[2], upper[2] if upper[2] is not None else empty_bg))
    return out


def stack_cells_whole(segs, H):
    """--glyphs cells (and no colour): no partial block anywhere. A cell at least half full takes the
    series that owns most of it, the others stay empty: half-row accuracy, nothing for a font to get
    wrong. Returns (char FULL or ' ', owner role or None) per row, bottom-up."""
    out = []
    for r in range(H):
        a, b = 8 * r, 8 * r + 8
        best, col, filled = 0, None, 0
        for lo, hi, c in segs:
            n = min(hi, b) - max(lo, a)
            if n > 0:
                filled += n
                if n > best:
                    best, col = n, c
        out.append((FULL, col) if filled >= 4 else (" ", None))
    return out


# ------------------------------------------------------------------ the row plan
def plan(W, H, has_res=True, has_inc=True):
    """Where everything goes: a function of the terminal's size and of two slow facts (a reservation
    in the last 14 days; an incident on record), never of how many there are right now, so the plot
    keeps its rectangle when an agent is granted memory or an incident opens."""
    y0 = 1
    wide = W >= 120                                   # two columns from 120 columns, whatever the height
    lw = W - RIGHT_W if wide else W
    stats = 0 if wide else (2 if H >= 16 else 1)
    S = R = Inc = 0
    bh = H - 1 - y0 - stats
    tier = (2, 4, 2) if bh < 30 else (3, 6, 4) if bh < 36 else (3, 8, 6) if bh < 44 else (4, 8, 6)
    if has_res:
        S, R = tier[0], tier[1]
    if has_inc:
        Inc = tier[2]

    def plot_h():
        return (H - 1 - y0 - stats) - 3 - ((1 + S + R) if (S or R) else 0) - ((1 + Inc) if Inc else 0)
    while plot_h() < 5 and Inc:
        Inc -= 1
    while plot_h() < 5 and R:
        R -= 1
    if plot_h() < 5 and S > 1:
        S = 1
    if plot_h() < 4 and S:
        S = 0
    if plot_h() < 4 and stats == 2:
        stats = 1
    p = dict(W=W, H=H, wide=wide, lw=lw, stats_y=y0, stats=stats, S=S, R=R, I=Inc)
    y = y0 + stats
    p["box_y"] = y
    p["plot_x"], p["plot_y"], p["plot_w"], p["plot_h"] = 1, y + 1, lw - 7, plot_h()
    y += 1 + plot_h()
    p["axis_y"] = y
    y += 1
    p["cap_y"] = p["strip_y"] = p["list_y"] = p["inc_cap_y"] = p["inc_y"] = None
    if S or R:
        p["cap_y"], p["strip_y"], p["list_y"] = y, y + 1, y + 1 + S
        y += 1 + S + R
    if Inc:
        p["inc_cap_y"], p["inc_y"] = y, y + 1
        y += 1 + Inc
    p["bottom_y"] = y
    p["right"] = (lw, y0, RIGHT_W, H - 1 - y0) if wide else None
    return p


def res_columns(w):
    """(width of the purpose, column of the project) of a reservation row, from the width alone: a
    reservation that comes or goes never pushes the projects sideways."""
    pw = max(10, min(28, (w - 34) // 2))
    return pw, 11 + pw + 2


# ------------------------------------------------------------------ small words
def left_of(sec):
    sec = int(max(sec, 0))
    if sec >= 3600:
        return "%dh%02d" % (sec // 3600, sec % 3600 // 60)
    return "%dm" % round(sec / 60.0) if sec >= 60 else "%ds" % sec


def ago(sec):
    sec = int(max(sec, 0))
    if sec < 90:
        return "%d s" % sec
    if sec < 5400:
        return "%d min" % round(sec / 60.0)
    return "%d h %02d min" % (sec // 3600, sec % 3600 // 60)


def gfmt(v):
    return "%dG" % v if abs(v - round(v)) < 0.05 else "%.1fG" % v


def _gb(x):
    return x if isinstance(x, (int, float)) else 0.0


# ------------------------------------------------------------------ row 0 and the readings
def capsule(model):
    """(text, role): the pressure, or "No readings" while the logger says nothing."""
    cur = model.get("cur")
    if not cur or model.get("logger") == "silent":
        return "No readings", "faint"
    p = cur.get("pressure") or "Normal"
    return p, {"Normal": "ok", "Warning": "warn", "Critical": "crit"}.get(p, "ok")


def tab_bar(fr, model, caps, g):
    """Row 0 for one machine: the name, this machine's host name, free memory, the capsule, the clock.
    What gives way when columns are short: the name, then the clock, then the free memory. A long
    host name is cut first, to no less than 12 cells, so it never pushes the others out of a wide row."""
    W, mono = fr.w, caps.color == "none"
    fr.fill(0, 0, W, 1, " ", None, "bar")
    cap_text, cap_role = capsule(model)
    cap_w = len(cap_text) + 2
    cur = model.get("cur")
    free = "%.1fG free" % cur["free"] if cur and model.get("logger") != "silent" else None
    host = model.get("host") or "this Mac"
    room = W - 1 - 1 - cap_w - 1 - 3
    rest = (len(model.get("brand") or "") + 1) + 6 + (len(free) + 2 if free else 0)
    label = fit(host, max(4, room - rest if room - rest >= 12 else room), g)
    left = [(" " + label + " ", "selfg", "sel", BOLD | (REV if mono else 0))]
    used = 1 + 1 + cap_w + 1 + sum(tw(s[0]) for s in left)
    fre = bool(free) and used + len(free) + 2 <= W
    used += len(free) + 2 if fre else 0
    clk = used + 6 <= W
    used += 6 if clk else 0
    brand = model.get("brand") or ""      # oomph.BRAND, from the loader
    wm = bool(brand) and used + len(brand) + 1 <= W
    x = 1
    if wm:
        x = fr.put(x, 0, brand, "fg", "bar", BOLD) + 1
    for text, fg, bg, fl in left:
        x = fr.put(x, 0, text, fg, bg, fl)
    xr = W - 2
    if clk:
        clock = hhmm(model["now"])
        fr.rput(xr, 0, clock, "dim", "bar")
        xr -= len(clock) + 1
    if mono:
        fr.rput(xr, 0, "[" + cap_text + "]", "fg", "bar", BOLD)
    elif caps.color == "16" and cap_role == "faint":    # no grey among the eight base colours: brackets
        fr.rput(xr, 0, "[" + cap_text + "]", "dim", "bar", BOLD)
    elif cap_role == "faint":                           # a grey fill, the words in the primary colour
        fr.rput(xr, 0, " " + cap_text + " ", "selfg", "sel", BOLD)
    else:
        fr.rput(xr, 0, " " + cap_text + " ", "onblock", cap_role, BOLD)
    xr -= cap_w + 1
    if fre:
        fr.rput(xr, 0, free, "dim", "bar")


def draw_stats(fr, x, y, w, model, g, rows=2):
    """The live readings. Two rows: value over label; tiles that do not fit are dropped, least
    important first. One row: a sentence, whole items dropped, never a label cut in half."""
    c = model.get("cur")
    if not c:
        fr.put(x, y, "No readings yet", "dim")
        return
    idle = c.get("idle") or 0
    idle_s = "%d min" % (idle // 60) if idle >= 120 else "%d s" % idle
    if rows == 1:
        items = [("%.1fG" % c["app"], "App"), ("%.1fG" % c["comp"], "Compressed"), ("%.1fG" % c["wired"], "Wired"),
                 ("%.0fG" % c["ram"], "RAM"), ("%.1f/%.0fG" % (c["swap"], c["swap_total"]), "swap"),
                 ("%.0fG" % c["disk"], "disk free"), (idle_s, "idle")]
        sep = " %s " % g["mid"]
        while items and sum(len(v) + 1 + len(lab) for v, lab in items) + len(sep) * (len(items) - 1) > w:
            items.pop()
        for i, (v, lab) in enumerate(items):
            if i:
                x = fr.put(x, y, sep, "faint")
            x = fr.put(x, y, v, "fg", KEEP, BOLD)
            x = fr.put(x + 1, y, lab, "dim")
        return
    # (value, label, width, priority: the highest number gives way first)
    tiles = [("%.1f GB" % c["app"], "App memory", 12, 0), ("%.1f GB" % c["comp"], "Compressed", 12, 1),
             ("%.1f GB" % c["wired"], "Wired", 9, 2), ("%.0f GB" % c["ram"], "RAM total", 11, 4),
             ("%.1f / %.0f GB" % (c["swap"], c["swap_total"]), "Swap / size", 13, 3),
             ("%.0f GB" % c["disk"], "Free disk", 11, 5), (idle_s, "Idle", 7, 6)]
    if c.get("groups"):
        name, gb, _ = c["groups"][0]
        tiles.append(("%.1f GB" % gb, "#1 " + name, 18, 7))
    while sum(t[2] for t in tiles) > w:
        tiles.remove(max(tiles, key=lambda t: t[3]))
    pad = min(6, max(0, (w - sum(t[2] for t in tiles)) // max(len(tiles) - 1, 1)))
    for val, lab, twid, _ in tiles:
        fr.put(x, y, val, "fg", KEEP, BOLD)
        fr.put(x, y + 1, fit(lab, twid + pad - 1, g), "dim")
        x += twid + pad


# ------------------------------------------------------------------ the chart
SERIES_WORDS = (("Wired", "wired"), ("App", "app"), ("Compressed", "comp"), ("Swap", "swap"))
LEGEND_ORDER = ("away", "no data", "incident")       # as drawn, left to right
LEGEND_YIELD = ("away", "incident", "no data")       # what gives way, first to last


def legend_items(g, caps, short, initials=False):
    mono = caps.color == "none"
    shade = dict(zip(SERIES, g["shades"]))
    names = [("Compr." if short and n == "Compressed" else n, role, shade[role] if mono else g["legend_sw"])
             for n, role in SERIES_WORDS]
    if initials:
        names = [(n[0], role, s) for n, role, s in names]
    plain_band = mono or caps.color == "16"
    extra = {"no data": ("no data", "hatch", g["hatch"]), "incident": ("incident", "incident", g["inc"]),
             "away": ("away", "dim" if not mono else "fg", g["awaydot"] if plain_band else g["legend_away"])}
    return names, extra


def draw_chart_head(fr, x, y, w, ui, caps, g, title=None):
    """The top edge of the chart box: the span selector on the left (it never gives way; below room
    for all four only the selected one stays), the legend on the right (it shortens, then goes)."""
    mono = caps.color == "none"
    fr.hline(x, y, w, g, "line", g["tl"], g["tr"])
    cx = x + 2
    if title and w >= 100:
        cx = fr.put(cx, y, " %s " % title, "fg", None, BOLD) + 1
    labels = [(k, " %s " % (g["inf"] if k == "inf" else k)) for k in SPAN_ORDER]
    if cx + sum(len(lab) for _, lab in labels) > x + w - 2:
        labels = [(k, "%s%s%s" % (g["more_l"], lab.strip(), g["more_r"])) for k, lab in labels if k == ui["span"]]
    for key, lab in labels:
        if key == ui["span"]:
            cx = fr.put(cx, y, lab, "selfg", "sel", BOLD | (REV if mono else 0))
        else:
            cx = fr.put(cx, y, lab, "dim", None if mono else "trough")
    room = x + w - 2 - cx
    chosen = None
    for short, drop, initials in ((False, 0, False), (True, 0, False), (True, 1, False), (True, 2, False),
                                  (True, 3, False), (True, 3, True)):
        names, extra = legend_items(g, caps, short, initials)
        items = names + [extra[k] for k in LEGEND_ORDER if k not in LEGEND_YIELD[:drop]]
        need = sum(len(n) + 2 for n, _, _ in items) + 1
        if need <= room:
            chosen = (items, need)
            break
    if chosen is None:
        return
    items, need = chosen
    lx = x + w - 2 - need
    for name, role, sw in items:
        lx = fr.put(lx, y, " ", None, None)
        lx = fr.put(lx, y, sw, role if not mono else "fg", None)
        lx = fr.put(lx, y, name, "dim", None)
    fr.put(lx, y, " ", None, None)


def _runs(flags):
    out, c, W = [], 0, len(flags)
    while c < W:
        if flags[c]:
            c1 = c
            while c1 < W and flags[c1]:
                c1 += 1
            out.append((c, c1))
            c = c1
        else:
            c += 1
    return out


def _owner(segs, r):
    best, col = 0, None
    for lo, hi, s in segs:
        n = min(hi, 8 * r + 8) - max(lo, 8 * r)
        if n > best:
            best, col = n, s
    return col


def plot_geometry(model, span, W, hold=None):
    """The mapper, the columns and the y top of the plot; with the hold the loop kept from the frame
    before (see y_top), and the hold for the next one."""
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[span])
    cols = columns(model["pts"], model["gaps"], f, finv, W, now, first)
    top, new = y_top(model.get("ram"), cols, hold, finv(0.0), now)
    return f, finv, cols, top, new


_PLOT = {}          # the last plot drawn: its key and its cells (04 §4.8: "rasters are cached")


def draw_plot(fr, x0, y0, W, H, model, ui, caps, g):
    """The plot, from the raster of the frame before when nothing it draws has changed: the same
    points, gaps, incidents, span, size, y hold and style, and "now" in the same column (a minute on
    the log axis). The clock alone moving costs no plot."""
    held = ui.get("yhold")
    held = held[1] if held and held[0] == ui["span"] else None
    sp = SPANS[ui["span"]]
    epoch = int(model["now"] // (sp / float(W) if sp else 60.0))
    pv = model.get("pts_v") or hash(tuple((p["t"], p["wired"], p["app"], p["comp"], p["swap"], p["away"])
                                         for p in model["pts"]))
    key = (pv, len(model["pts"]), tuple(model["gaps"]), model.get("first"), model.get("ram"),
           tuple((i["start"], i["open"]) for i in model["incidents"]), ui["span"], W, H, x0, y0, held, epoch,
           caps.color, caps.glyphs, caps.theme, fr.ascii_only)
    hit = _PLOT.get("key") == key
    if hit:
        for dy, row in enumerate(_PLOT["cells"]):
            fr.c[y0 + dy][x0:x0 + len(row)] = [list(c) for c in row]
        fr.yhold = _PLOT["yhold"]
        return _PLOT["gridcols"]
    gridcols = _draw_plot(fr, x0, y0, W, H, model, ui, caps, g)
    _PLOT.update(key=key, gridcols=gridcols, yhold=fr.yhold,
                 cells=[[tuple(c) for c in fr.c[y0 + dy][x0:min(x0 + W + 5, fr.w)]] for dy in range(H + 1)])
    return gridcols


def _draw_plot(fr, x0, y0, W, H, model, ui, caps, g):
    """The stacked areas, the away band, the no-data hatch, grid, the RAM line, incident rules, the
    y labels in the gutter and the time axis under it. Returns the grid columns (the strip
    continues them)."""
    mono = caps.color == "none"
    plain_band = mono or caps.color == "16"       # no background colour to spare: the away band is dots
    whole = mono or caps.glyphs in ("cells", "ascii")
    now = model["now"]
    held = ui.get("yhold")
    f, finv, cols, ymax, fr.yhold = plot_geometry(model, ui["span"], W, held[1] if held and held[0] == ui["span"] else None)
    L = 8 * H
    # MemoryChart.calmBands with columns as the unit: a no-data stretch that touches an away band is part of it
    grey, _ = calm_bands(_runs([st == "data" and p["away"] for st, p in cols]), _runs([st == "gap" for st, p in cols]), 0)
    band = [False] * W
    for a, b in grey:
        band[int(a):int(b)] = [True] * (int(b) - int(a))
    labels = axis_labels(f, W, now, log=SPANS[ui["span"]] is None)
    gridcols = set(min(W - 1, int(round(x * W))) for x, text in labels if text != "now")
    inc = set(min(W - 1, int(f(i["start"]) * W)) for i in model["incidents"] if 0 <= f(i["start"]) <= 1)
    ram = model.get("ram") or 0
    rl = ram / float(ymax) * H
    ram_row = min(H - 1, int(rl - 1e-9)) if ram else -1
    ram_glyph = g["ram"][min(2, int((rl - ram_row) * 3 - 1e-9))] if ram else " "
    shade = dict(zip(SERIES, g["shades"]))
    for c in range(W):
        st, p = cols[c]
        bgc = "away" if band[c] and not plain_band else None
        if st == "data":
            segs, lo, cum = [], 0, 0.0
            for s in SERIES:
                cum += p[s]
                hi = min(L, int(round(cum / ymax * L)))
                if p[s] > 0.08 and hi == lo and lo < L:
                    hi = lo + 1                          # a sliver of swap must not vanish
                if hi > lo:
                    segs.append((lo, hi, s))
                    lo = hi
            if whole:
                cells = []
                for ch, own in stack_cells_whole(segs, H):
                    if own is None:
                        cells.append((" ", None, None))
                    elif mono or caps.glyphs == "ascii":     # a shade per series; colour, if any, tells them apart too
                        cells.append((shade[own], None if mono else own, None))
                    else:
                        cells.append((FULL, own, None))
            else:
                cells = stack_cells(segs, H, g["eighths"], bgc)
        else:
            cells = [(" ", None, bgc)] * H
        for r in range(H):
            ch, fg, bg = cells[r]
            if ch == " ":
                bg = bgc
                if st == "gap":
                    ch, fg = g["hatch"], "hatch"
                elif c in gridcols:
                    ch, fg = g["grid"], "grid"
                elif r == ram_row and c % 2 == 0:
                    ch, fg = ram_glyph, "dim"
                elif plain_band and band[c]:
                    ch, fg = g["awaydot"], None if mono else "faint"
            fl = 0
            if c in inc:
                if mono:
                    bg, fl = None, BOLD
                elif ch in (g["hatch"], g["grid"], ram_glyph, g["awaydot"], " "):
                    bg = bgc
                elif ch == FULL or ch in g["eighths"][4:8]:
                    bg = fg                              # the area goes on behind the rule
                ch, fg = g["inc"], "incident"
            fr.put(x0 + c, y0 + H - 1 - r, ch, fg, bg, fl)
    # y labels: the RAM line names itself; round values where a row is free; the top if it has a row
    ticks = {ram_row: (gfmt(ram), "fg")} if ram else {}
    for v in ([ymax / 2.0] if H < 12 else [ymax * 0.75, ymax / 2.0, ymax * 0.25]):
        row = max(0, min(H - 1, int(v / float(ymax) * H - 1e-9)))
        ticks.setdefault(row, (gfmt(v), "dim"))
    ticks.setdefault(H - 1, (gfmt(ymax), "dim"))
    for row, (text, role) in ticks.items():
        fr.rput(x0 + W + 4, y0 + H - 1 - row, text, role)
    for x, text in labels:      # centred on their grid lines ('now' ends at the right edge)
        cx = min(max(int(round(x * W)) - len(text) // 2, 0), W - len(text))
        fr.put(x0 + cx, y0 + H, text, "dim")
    return gridcols


def draw_strip(fr, x0, y0, W, H, model, ui, caps, g, gridcols=()):
    """The reservation blocks on the plot's time axis: height ∝ GB, stacked in lanes; queued
    stretches in a shade. A column shows the instant inside it with the tallest stack."""
    mono = caps.color == "none"
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[ui["span"]])
    blocks = [b for b in model["blocks"] if f(b["end"]) >= 0]
    top = strip_top(max([st[3] for b in blocks for st in b["steps"] if f(st[1]) >= 0] or [0]))
    L = 8 * H
    for c in range(W):
        ta, tb = finv(c / float(W)), finv((c + 1) / float(W))
        if c == W - 1:
            tb = now + 1
        cand = [(st, k) for k, b in enumerate(blocks) if b["res"]["requested"] < tb and b["end"] > ta
                for st in b["steps"] if st[0] < tb and st[1] > ta]
        best, best_total = [], 0
        for ti in sorted(set(max(st[0], ta) for st, _ in cand)):   # the instant with the tallest stack
            stack = [(st[2], st[3], k) for st, k in cand if st[0] <= ti < st[1]]
            total = max([s[1] for s in stack] or [0])
            if total > best_total:
                best, best_total = stack, total
        segs, lo = [], 0
        for a, b_, k in sorted(best):
            r = blocks[k]["res"]
            queued = r.get("granted") is None or f(r["granted"]) * W >= c + 1
            hi = min(L, max(lo + 1, int(round(b_ / float(top) * L))))
            if hi > lo:
                segs.append((lo, hi, (res_color(r["purpose"]), queued, k)))
            lo = hi
        cells = []
        if mono or caps.glyphs in ("ascii", "cells"):
            for r_ in range(H):
                own = _owner(segs, r_)
                filled = sum(min(hi, 8 * r_ + 8) - max(lo_, 8 * r_) for lo_, hi, _ in segs
                             if hi > 8 * r_ and lo_ < 8 * r_ + 8)
                if not own or (filled < 4 and not (r_ == 0 and segs)):   # whatever is reserved keeps one cell
                    cells.append((" ", None, None))
                elif own[1]:
                    cells.append((g["queued"], None if mono else own[0], None))
                elif caps.glyphs == "cells" and not mono:
                    cells.append((FULL, own[0], None))
                else:
                    cells.append((g["eighths"][8] if filled >= 8 or g["eighths"][8] != FULL else g["eighths"][filled],
                                  None if mono else own[0], None))
        else:
            for ch, fg, bg in stack_cells(segs, H, g["eighths"], None):
                if fg and fg[1]:                    # queued: hatched in the app, a shade here
                    ch, bg = g["queued"], None
                cells.append((ch, fg[0] if fg else None, bg[0] if bg else None))
        for r_ in range(H):
            ch, fg, bg = cells[r_]
            if ch == " " and c in gridcols:
                ch, fg = g["grid"], "grid"
            fr.put(x0 + c, y0 + H - 1 - r_, ch, fg, bg)
    fr.rput(x0 + W + 4, y0, "%dG" % top, "faint")


# ------------------------------------------------------------------ the lists
def _queue_key(r):
    """Where a waiting reservation stands: its place in the ledger's list of leases (a queued request
    that grows moves to the back), the request time where that is not known."""
    q = r.get("queue")
    return (q is None, q if isinstance(q, int) else 0, r["requested"], r["key"])


def ordered_res(res):
    """Waiting first (the queue, head on top), then grants by time left, soonest first (a grant
    without a ttl last), then finished ones newest first: whatever a short list cuts off is never
    the reservation that explains why an agent waits. The live part is the app's order too
    (Reservation.listOrder; roadmap C13), held to it by tools/vectors/chart.json."""
    live = [r for r in res if r.get("ended") is None]
    waiting = sorted([r for r in live if r.get("granted") is None], key=_queue_key)
    granted = sorted([r for r in live if r.get("granted") is not None],
                     key=lambda r: (r.get("expires") is None, r.get("expires") or 0, r["requested"], r["key"]))
    done = sorted([r for r in res if r.get("ended") is not None], key=lambda r: (-r["ended"], r["key"]))
    return waiting, granted, done


def res_seq(model):
    """The reservation list as one sequence: waiting, granted, then the finished ones of the last 24 h.
    Returns (sequence, live count, waiting count)."""
    waiting, granted, done = ordered_res(model["res"])
    return waiting + granted + [r for r in done if r["ended"] >= model["now"] - 86400], len(waiting) + len(granted), \
        len(waiting)


def res_visible(R, n_live, off):
    """How many reservations R rows show: all R, or R - 1 above a position line when live ones are
    hidden or the list has been scrolled. A list of one row has no position line while it is
    focused: it shows the selected reservation (unfocused it counts, 04 §3.2)."""
    return R if (R < 2 or (n_live <= R and off == 0)) else R - 1


def list_rows(model, R, ui=None):
    """The R rows of the reservation list: ('res', r, index) … and, when live reservations are hidden
    or the list has been scrolled, a last row ('more', above, below_live, below_waiting, below_all).
    A single row counts ("3 granted · 1 waiting") until the list has the focus; then it is the
    selected reservation (the caption counts instead)."""
    seq, n_live, n_wait = res_seq(model)
    off = min((ui or {}).get("res_off", 0), max(len(seq) - 1, 0))
    if R <= 0:
        return [], n_live, n_wait
    if (R < 2 and (ui or {}).get("focus") == "res") or (n_live <= R and off == 0):
        return [("res", r, off + i) for i, r in enumerate(seq[off:off + R])], n_live, n_wait
    shown = seq[off:off + R - 1]
    below = [r for r in seq[off + R - 1:] if r.get("ended") is None]
    rows = [("res", r, off + i) for i, r in enumerate(shown)]
    rows.append(("more", off, len(below), sum(1 for r in below if r.get("granted") is None),
                 len(seq) - off - len(shown)))
    return rows, n_live, n_wait


def panel_area(P):
    """Where a panel (a s e) goes: in the place of the two lists, below the strip ("lists"); or, in a
    pane whose list area has fewer than 4 rows, the whole chart box ("chart"). (y of its caption,
    rows below the caption, where `esc` leads)."""
    if P["R"] or P["I"]:
        y0 = P["list_y"] if P["R"] else P["inc_cap_y"]
        if P["bottom_y"] - y0 >= 4:
            return y0, P["bottom_y"] - y0 - 1, "lists"
    return P["box_y"], P["bottom_y"] - P["box_y"] - 1, "chart"


def panel_items(model, panel):
    """The rows of a panel: apps (name, GB, processes), sessions (pid, cwd, GB, processes, biggest),
    events (t, text, alarming)."""
    cur = model.get("cur") or {}
    if panel == "a":
        return cur.get("groups") or []
    if panel == "s":
        return cur.get("claude") or []
    return model.get("events") or []


def press(ui, key, model, P):
    """What a key does to the selection (04 §3.4, "Selecting and scrolling"): the two lists are two
    focus stops. Nothing selected: down enters Reservations at its first row, up enters Incidents at
    the newest (where the plan has no incident rows, up opens the newest incident's card). Inside a
    list up and down move by a row and stop at its ends; pgup / pgdn move by a page, home / end
    jump; space moves the focus to the other list. Each list keeps its own row and its own scroll
    offset until esc, which lets go of both. An offset moves as little as keeps the row on screen.
    With a panel open (a s e) the panel is the one focus stop. Changes `ui`; returns it."""
    if ui.get("panel"):
        return _press_panel(ui, key, model, P)
    R, I = P["R"], P["I"]
    seq, n_live, _ = res_seq(model)
    incs = model["incidents"]
    has = {"res": bool(R and seq), "inc": bool(I and incs)}
    f = ui.get("focus")
    if key == "esc":
        for k in ("focus", "res_sel", "res_off", "inc_sel", "inc_off"):
            ui.pop(k, None)
        return ui
    if f is None:
        if key == "up" and incs and not I:
            ui["overlay"] = {"kind": "inc", "id": incs[0]["id"]}
        elif key in ("down", "up"):
            want = "res" if key == "down" else "inc"
            if not has[want]:
                want = "inc" if want == "res" else "res"
            if has[want]:
                ui["focus"] = want
                ui.setdefault(want + "_sel", 0)
        return ui
    if key == "space":
        other = "inc" if f == "res" else "res"
        if has[other]:
            ui["focus"] = other
            ui.setdefault(other + "_sel", 0)
        return ui
    n = len(seq) if f == "res" else len(incs)
    if n == 0:
        return ui
    page = max(1, (res_visible(R, n_live, ui.get("res_off", 0)) if f == "res" else I) - 1)
    sel = ui.get(f + "_sel", 0)
    sel = {"down": sel + 1, "up": sel - 1, "pgdn": sel + page, "pgup": sel - page, "home": 0, "end": n - 1}.get(key, sel)
    sel = max(0, min(n - 1, sel))
    off = ui.get(f + "_off", 0)
    if f == "res":
        off = min(off, sel)
        while sel > off + res_visible(R, n_live, off) - 1:
            off += 1
    else:
        off = max(min(off, sel), sel - I + 1, 0)
        off = min(off, max(len(incs) - I, 0))
    ui[f + "_sel"], ui[f + "_off"] = sel, off
    return ui


def panel_page(P, model, panel):
    """(rows per column, columns, rows shown) of a panel: Top apps in two columns from 72 cells when
    one does not hold them all; a last row says what is above and below when not all fit."""
    _, rows, _ = panel_area(P)
    n = len(panel_items(model, panel))
    if panel == "e":
        return rows, 1, max(1, rows)
    ncol = 2 if panel == "a" and P["lw"] - 2 >= 72 and rows < n else 1
    body = rows - 1 if n > rows * ncol else rows
    return body, ncol, max(1, body * ncol)


def _press_panel(ui, key, model, P):
    items = panel_items(model, ui["panel"])
    _, _, per = panel_page(P, model, ui["panel"])
    if key == "esc":
        for k in ("panel", "focus", "panel_sel", "panel_off"):
            ui.pop(k, None)
        return ui
    n = len(items)
    if ui["panel"] == "e":                          # events scroll; nothing is selected
        off = ui.get("panel_off", 0)
        off = {"down": off + 1, "up": off - 1, "pgdn": off + per - 1, "pgup": off - per + 1, "home": 0,
               "end": n}.get(key, off)
        ui["panel_off"] = max(0, min(off, max(n - per, 0)))
        return ui
    if not n or key not in ("down", "up", "pgdn", "pgup", "home", "end"):
        return ui
    if ui.get("focus") != "panel":
        ui["focus"], ui["panel_sel"], ui["panel_off"] = "panel", 0, 0
        return ui
    sel = ui.get("panel_sel", 0)
    sel = {"down": sel + 1, "up": sel - 1, "pgdn": sel + per - 1, "pgup": sel - per + 1, "home": 0,
           "end": n - 1}.get(key, sel)
    sel = max(0, min(n - 1, sel))
    off = ui.get("panel_off", 0)
    off = max(min(off, sel), sel - per + 1, 0)
    ui["panel_sel"], ui["panel_off"] = sel, off
    return ui


def highlight(fr, x, y, w, caps, g, focus):
    """The selected row: a painted row with an accent mark while its list has the focus; a faint mark
    only (where `space` leads back to) while it has not."""
    if focus:
        if caps.color == "none":
            fr.flag(x, y, w, 1, REV)
        else:
            for xx in range(max(x, 0), min(x + w, fr.w)):
                cell = fr.c[y][xx]
                if cell[2] is None:
                    cell[2] = "rowsel"
        fr.put(x, y, g["sel"], "accent", KEEP, BOLD | (REV if caps.color == "none" else 0))
    else:
        fr.put(x, y, g["sel"], "faint", KEEP)


def draw_res_rows(fr, x, y, w, rows, model, caps, g, ui=None):
    ui = ui or {}
    mono = caps.color == "none"
    now = model["now"]
    pw, px = res_columns(w)
    focus, sel = ui.get("focus") == "res", ui.get("res_sel")
    for i, row in enumerate(rows):
        yy = y + i
        if row[0] == "more":
            _, above, below, waiting, rest = row
            parts = []
            if above:
                parts.append(("%s %d above" % (g["up"], above), "dim"))
            if below and not above and len(rows) == 1:      # the only row: it counts, in words that add up
                if below - waiting:
                    parts.append(("%d granted" % (below - waiting), "fg"))
                if waiting:
                    parts.append(("%d waiting" % waiting, "warntx"))
            elif below:
                parts.append(("%s %d more" % (g["down"], below), "dim"))
                if waiting:
                    parts.append(("%d waiting" % waiting, "warntx"))
            elif rest:
                parts.append(("%s %d finished" % (g["down"], rest), "dim"))
            xx = x + 2
            for k, (text, role) in enumerate(parts):
                if k:
                    xx = fr.put(xx, yy, " %s " % g["mid"], "faint")
                xx = fr.put(xx, yy, text, role)
            if not focus and w >= 44 and len(rows) > 1 and (below or rest):
                fr.rput(x + w - 2, yy, "%s scrolls" % g["updown"][1], "faint")
            continue
        r, idx = row[1], row[2]
        live = r.get("ended") is None
        granted = r.get("granted") is not None
        fr.put(x + 2, yy, g["sw"] if granted else g["swq"], None if mono else res_color(r["purpose"]), KEEP)
        fr.put(x + 4, yy, "%4.1fG" % r["segments"][-1][1], "fg" if live else "dim", KEEP, BOLD if live else 0)
        if not live:
            tail = "peak %.1fG %s %s %s" % (_gb(r.get("peak")), g["mid"], (r.get("outcome") or "ended").replace("_", " "),
                                            hhmm(r["ended"]))
            trole = "faint"
        elif granted:
            used = "using %.1fG" % _gb(r.get("used"))
            tail = used + (" %s %s left" % (g["mid"], left_of(r["expires"] - now)) if r.get("expires") is not None else "")
            trole = "dim"
        else:
            tail = "waiting %s" % ago(now - r["requested"])
            trole = "warntx"
        if w < 44:                           # a narrow pane keeps the state, shortened
            tail = tail.replace("using ", "").replace(" left", "").replace("waiting ", "wait ")
        fr.rput(x + w - 2, yy, tail, trole, KEEP)
        end = w - 2 - tw(tail) - 1
        fr.put(x + 11, yy, fit(r["purpose"], max(4, min(pw, end - 11)), g), "fg" if live else "dim", KEEP)
        project = r.get("project")
        if isinstance(project, str) and project and end - px >= 3:
            fr.put(x + px, yy, fit(project.rstrip("/").rsplit("/", 1)[-1], end - px, g), "dim", KEEP)
        if idx == sel:
            highlight(fr, x, yy, w, caps, g, focus)


def draw_incident_rows(fr, x, y, w, rows, model, caps, g, ui=None, first=0):
    ui = ui or {}
    focus, sel = ui.get("focus") == "inc", ui.get("inc_sel")
    for i, inc in enumerate(rows):
        yy = y + i
        fr.put(x + 2, yy, g["dot"] if inc["open"] else g["odot"], "incident" if inc["open"] else "faint", KEEP)
        fr.put(x + 4, yy, day_hhmm(inc["start"]), "fg", KEEP)
        end = model["now"] if inc["open"] or inc.get("end") is None else inc["end"]
        dur = ago(end - inc["start"])
        tail = "open %s" % dur if inc["open"] else dur
        fr.rput(x + w - 2, yy, tail, "incident" if inc["open"] else "dim", KEEP)
        xr = x + w - 2 - len(tail)
        if inc.get("kills") and w >= 60:
            k = "%d kill%s %s " % (inc["kills"], "" if inc["kills"] == 1 else "s", g["mid"])
            fr.rput(xr, yy, k, "incident", KEEP)
            xr -= len(k)
        fr.put(x + 18, yy, fit(inc.get("desc") or "", xr - (x + 18) - 1, g), "dim", KEEP)
        if first + i == sel:
            highlight(fr, x, yy, w, caps, g, focus)


def section(fr, x, y, w, g, title, right=None, top=False, right_role="dim"):
    """A titled rule across a box: ├─ title ──── right ─┤ (or the box's own top edge)."""
    fr.hline(x, y, w, g, "line", g["tl"] if top else g["lt"], g["tr"] if top else g["rt"])
    x1 = fr.put(x + 2, y, " %s " % title, "fg", None, BOLD)
    if right and tw(right) + 4 <= x + w - 2 - x1:
        fr.rput(x + w - 3, y, " %s " % right, right_role, None)


# ------------------------------------------------------------------ the panels: a s e, in the place of the lists
PANELS = {"a": "Top apps", "s": "Claude sessions", "e": "Events"}


def session_reservations(model, pid):
    """The live reservations a Claude session holds (its holder is the session's root process)."""
    return [r for r in model["res"] if r.get("ended") is None and r.get("pid") == pid]


def draw_panel(fr, model, ui, P, caps, g):
    """The panel that a, s or e opened, with the rows the lists had: nothing above it moves."""
    panel = ui["panel"]
    y0, rows, where = panel_area(P)
    lw = P["lw"]
    fr.fill(1, y0 + 1, lw - 2, rows, " ", None, None)
    for yy in range(y0 + 1, y0 + 1 + rows):         # the sides, where a section's ├ ┤ was
        fr.put(0, yy, g["v"], "line")
        fr.put(lw - 1, yy, g["v"], "line")
    cur = model.get("cur") or {}
    items = panel_items(model, panel)
    right = None
    if panel == "a":
        bits = []
        if cur.get("procs"):
            bits.append("%d processes" % cur["procs"])
        if cur.get("unowned") is not None:
            bits.append("%.1f GB not owned%s" % (cur["unowned"], " by a process" if lw >= 72 else ""))
        right = (" %s " % g["mid"]).join(bits) or None
    elif panel == "s":
        right = "%.1f GB in %d session%s" % (sum(s[2] for s in items), len(items), "" if len(items) == 1 else "s") \
            if items else None
    else:
        right = "newest first"
    section(fr, 0, y0, lw, g, PANELS[panel], right, top=(where == "chart"))
    x, w = 1, lw - 2
    focus = ui.get("focus") == "panel"
    sel, off = ui.get("panel_sel", 0), ui.get("panel_off", 0)
    if not items:
        fr.put(x + 2, y0 + 1, {"a": "No readings yet", "s": "No Claude sessions running",
                               "e": "No events yet"}[panel], "dim")
        return
    if panel == "e":
        shown = items[off:off + rows]
        last_day = None
        for i, (t, text, alarm) in enumerate(shown):
            ry = y0 + 1 + i
            day = DAYS[_lt(t).tm_wday]
            fr.put(x + 1, ry, day if day != last_day else "   ", "faint")
            last_day = day
            fr.put(x + 5, ry, hhmm(t), "dim")
            fr.put(x + 11, ry, fit(text.replace("→", g["arrow"]), w - 13, g), "incident" if alarm else "fg")
        return
    body, ncol, per = panel_page(P, model, panel)
    shown = items[off:off + per]
    cw = w // ncol
    if panel == "a":
        top = max((gb for _, gb, _ in items), default=0) or 1
        for i, (name, gb, n) in enumerate(shown):
            cx, ry = x + (i // body) * cw, y0 + 1 + i % body
            fr.put(cx + 2, ry, "%2d" % (off + i + 1), "faint", KEEP)
            nw = max(8, min(18, cw - 24))
            fr.put(cx + 5, ry, fit(name, nw, g), "fg", KEEP)
            fr.put(cx + 5 + nw + 1, ry, "%3d" % n, "faint", KEEP)
            bw = cw - (5 + nw + 5) - 7
            if bw >= 3:
                bar = min(bw, max(1, int(round(gb / top * bw))))
                fr.put(cx + 5 + nw + 5, ry, (g["eighths"][5] if g["eighths"][8] == FULL else g["meter"]) * bar,
                       "app" if caps.color != "none" else None, KEEP)
            fr.rput(cx + cw - 2, ry, "%.1fG" % gb, "fg", KEEP)
            if off + i == sel and focus:
                highlight(fr, cx, ry, cw, caps, g, True)
    else:
        for i, (pid, cwd, gb, n, big) in enumerate(shown):
            ry = y0 + 1 + i
            fr.put(x + 2, ry, "%5.1fG" % gb, "fg", KEEP, BOLD)
            fr.put(x + 9, ry, fit(cwd, 18 if w >= 70 else 12, g), "fg", KEEP)
            xr = fr.put(x + (28 if w >= 70 else 22), ry, "%2d procs" % n, "faint", KEEP) + 2
            held = session_reservations(model, pid)
            tail = x + w - 2
            if held:
                text = "%.1fG %s" % (sum(r["segments"][-1][1] for r in held), held[0]["purpose"])
                if len(held) > 1:
                    text += " +%d" % (len(held) - 1)
                text = fit(text, max(8, min(30, w - (xr - x) - 12)), g)
                fr.rput(tail, ry, text, "dim", KEEP)
                tail -= tw(text) + 1
                fr.put(tail - 1, ry, g["sw"], None if caps.color == "none" else res_color(held[0]["purpose"]), KEEP)
                tail -= 3
            if big and tail - xr >= 6:
                fr.put(xr, ry, fit(big, tail - xr, g), "dim", KEEP)
            if off + i == sel and focus:
                highlight(fr, x, ry, w, caps, g, True)
    if len(items) > per or off:
        below = max(0, len(items) - off - per)
        text = ("%s %d above" % (g["up"], off) if off else "") + (" %s " % g["mid"] if off and below else "") + \
               ("%s %d more" % (g["down"], below) if below else "")
        if text:
            fr.put(x + 2, y0 + rows, text, "dim")


# ------------------------------------------------------------------ the second column (from 120 columns)
def draw_apps(fr, x, y, w, rows, model, caps, g):
    """The biggest apps of the current sample, two columns when there is room."""
    groups = (model.get("cur") or {}).get("groups") or []
    if not groups or rows <= 0:
        return
    ncol = 2 if w >= 72 and rows < len(groups) else 1
    cw = w // ncol
    top = max((gb for _, gb, _ in groups), default=0) or 1
    for i, (name, gb, n) in enumerate(groups[:rows * ncol]):
        cx, ry = x + (i // rows) * cw, y + i % rows
        fr.put(cx + 2, ry, "%2d" % (i + 1), "faint", KEEP)
        nw = max(8, min(18, cw - 24))
        fr.put(cx + 5, ry, fit(name, nw, g), "fg", KEEP)
        fr.put(cx + 5 + nw + 1, ry, "%3d" % n, "faint", KEEP)
        bw = cw - (5 + nw + 5) - 7
        if bw >= 3:
            bar = min(bw, max(1, int(round(gb / top * bw))))
            fr.put(cx + 5 + nw + 5, ry, (g["eighths"][5] if g["eighths"][8] == FULL else g["meter"]) * bar,
                   "app" if caps.color != "none" else None, KEEP)
        fr.rput(cx + cw - 2, ry, "%.1fG" % gb, "fg", KEEP)


def draw_sessions(fr, x, y, w, rows, model, caps, g):
    for i, (pid, cwd, gb, n, big) in enumerate(((model.get("cur") or {}).get("claude") or [])[:rows]):
        ry = y + i
        fr.put(x + 1, ry, "%5.1fG" % gb, "fg", KEEP, BOLD)
        fr.put(x + 8, ry, fit(cwd, 16, g), "fg")
        fr.put(x + 25, ry, "%2d procs" % n, "faint")
        if big:
            fr.rput(x + w - 2, ry, fit(big, max(w - 37, 4), g), "dim")


def draw_events(fr, x, y, w, rows, model, caps, g):
    last_day = None
    for i, (t, text, alarm) in enumerate(model.get("events", [])[:rows]):
        ry = y + i
        day = DAYS[_lt(t).tm_wday]
        fr.put(x + 1, ry, day if day != last_day else "   ", "faint")
        last_day = day
        fr.put(x + 5, ry, hhmm(t), "dim")
        fr.put(x + 11, ry, fit(text.replace("→", g["arrow"]), w - 13, g), "incident" if alarm else "fg")


def meter(fr, x, y, w, parts, total, g, caps):
    """One stacked bar: [(value, role)] of `total`."""
    mono = caps.color == "none"
    filled = 0
    for i, (v, role) in enumerate(parts):
        n = max(0, min(int(round(v / float(total) * w)), w - filled)) if total else 0
        fr.put(x + filled, y, (g["shades"][i % 4] if mono else g["meter"]) * n, None if mono else role)
        filled += n
    fr.put(x + filled, y, g["meterbg"] * max(w - filled, 0), "grid" if not mono else None)


def draw_right(fr, P, model, caps, g):
    """Now, Top apps, Claude sessions and Events in one box. What fits depends on the height alone:
    Events give way first, then Sessions, then Top apps shorten."""
    x, y, w, h = P["right"]
    c = model.get("cur")
    fr.box(x, y, w, h, g)
    fr.put(x + 2, y, " Now ", "fg", None, BOLD)
    if model.get("os"):
        fr.rput(x + w - 3, y, " %s " % fit(model["os"], w - 12, g), "dim")
    inner = h - 2
    if not c:
        fr.put(x + 2, y + 1, "No readings yet", "dim")
        return
    idle = c.get("idle") or 0
    rows = [("App memory", "%.1f GB" % c["app"], "app"), ("Compressed", "%.1f GB" % c["comp"], "comp"),
            ("Wired", "%.1f GB" % c["wired"], "wired"), ("Free", "%.1f of %.0f GB" % (c["free"], c["ram"]), None),
            ("Swap used / size", "%.1f / %.0f GB" % (c["swap"], c["swap_total"]), "swap"),
            ("Free disk", "%.0f GB" % c["disk"], None)]
    if c.get("unowned") is not None:
        rows.append(("Not owned by a process", "%.1f GB" % c["unowned"], None))
    rows.append(("Idle", ("%d min" % (idle // 60) if idle >= 120 else "%d s" % idle) +
                 ("" if c.get("display_on") is None else " %s display %s" % (g["mid"], "on" if c["display_on"] else "off")), None))
    meter(fr, x + 2, y + 1, w - 4, [(c["wired"], "wired"), (c["app"], "app"), (c["comp"], "comp"), (c["swap"], "swap")],
          c["ram"] + c["swap"], g, caps)
    shown = rows[:max(inner - 1, 0)]
    for i, (lab, val, role) in enumerate(shown):
        ry = y + 2 + i
        if role:
            fr.put(x + 2, ry, g["sw"], role if caps.color != "none" else None)
        fr.put(x + 4, ry, lab, "dim")
        fr.rput(x + w - 3, ry, val, "fg", KEEP, BOLD)
    rem = inner - 1 - len(shown)
    apps = sess = ev = 0
    if rem >= 21:
        apps, sess = 13, (6 if rem >= 32 else 4)
        ev = rem - apps - sess
    elif rem >= 17:
        apps, sess = rem - 4, 4
    elif rem >= 4:
        apps = rem
    yy = y + 2 + len(shown)
    if apps:
        section(fr, x, yy, w, g, "Top apps", "%d processes" % c["procs"] if c.get("procs") else None)
        draw_apps(fr, x + 1, yy + 1, w - 2, apps - 1, model, caps, g)
        yy += apps
    if sess:
        cl = c.get("claude") or []
        section(fr, x, yy, w, g, "Claude sessions", "%.1f GB in %d" % (sum(s[2] for s in cl), len(cl)) if cl else None)
        draw_sessions(fr, x + 1, yy + 1, w - 2, sess - 1, model, caps, g)
        yy += sess
    if ev:
        section(fr, x, yy, w, g, "Events")
        draw_events(fr, x + 1, yy + 1, w - 2, ev - 1, model, caps, g)
    if model.get("logger") == "silent":     # the last sample's readings are not live: grey. Events are history.
        fr.restyle(x + 1, y + 1, w - 2, h - 2 - ev, "off")


# ------------------------------------------------------------------ dialogs: help and the cards
def _wrap(text, w):
    """Words into lines of at most w cells (never splits a word that fits a line)."""
    out, line = [], ""
    for word in text.split():
        if line and tw(line) + 1 + tw(word) > w:
            out.append(line)
            line = word
        else:
            line = (line + " " + word) if line else word
    if line:
        out.append(line)
    return out or [""]


def dialog(fr, g, caps, title, bw, bh, lines, hints):
    """One mechanism for every dialog (04 §3.8). Where the box fits with a margin under row 0 it is a
    box, centred, over the dimmed pane. Anywhere smaller it takes everything below row 0: no border,
    the title a rule in row 1, the hints on the key line, and its lines give way by priority (the
    highest number first; a paragraph as a whole). lines: [(priority, draw(fr, x, y, w, bg) or None,
    group)]. Works down to 40 x 10. Returns whether it was boxed."""
    W, H = fr.w, fr.h
    boxed = W >= bw + 2 and H >= bh + 3
    if boxed:
        x, y = (W - bw) // 2, max(1, (H - bh) // 2)
        fr.restyle(0, 1, W, H - 1, "off")
        fr.fill(x, y, bw, bh, " ", None, "bar")
        fr.box(x, y, bw, bh, g, "dim")
        fr.bg(x, y, bw, bh, "bar")
        fr.put(x + 2, y, " %s " % fit(title, bw - 6, g), "fg", "bar", BOLD)
        cx, cy, cw, n, bg, hy, hx, hend = x + 3, y + 1, bw - 6, bh - 3, "bar", y + bh - 2, x + 3, x + bw - 3
    else:
        fr.fill(0, 1, W, H - 1, " ", None, None)
        fr.hline(0, 1, W, g, "line")
        fr.put(1, 1, " %s " % fit(title, W - 6, g), "fg", None, BOLD)
        cx, cy, cw, n, bg, hy, hx, hend = 1, 2, W - 2, H - 3, None, H - 1, 1, W - 1
    lines = [tuple(l) + (None,) * (3 - len(l)) for l in lines]
    while len(lines) > n:
        worst = max(range(len(lines)), key=lambda i: (lines[i][0], i))
        if lines[worst][0] == 0:
            break
        group = lines[worst][2]
        lines = [l for i, l in enumerate(lines) if i != worst and (group is None or l[2] is not group)]
    for i, (_, fn, _) in enumerate(lines[:n]):
        if fn:
            fn(fr, cx, cy + i, cw, bg)
    for k, d in hints:
        if hx + tw(k) + tw(d) + 1 > hend:
            break
        if k:
            hx = fr.put(hx, hy, k, "fg", bg, BOLD) + 1
        hx = fr.put(hx, hy, d, "dim", bg) + 2
    return boxed


def _text(text, role="fg", fl=0):
    return lambda fr, x, y, w, bg: fr.put(x, y, fit(text, w, GLYPHS["ascii" if fr.ascii_only else "unicode"]), role, bg, fl)


def _para(text, w, pri, role="dim"):
    group = object()
    return [(pri, _text(line, role), group) for line in _wrap(text, w)]


def _kv(k, v, role="fg", kw=11):
    def fn(fr, x, y, w, bg):
        fr.put(x, y, k, "dim", bg)
        fr.put(x + kw, y, fit(v, w - kw), role, bg)
    return fn


def help_pages(g, model):
    """The help (04 §3.10), built from what this build has: the keys of T1, no machines, no
    inspect, no mouse. Returns (left column, right column, 'what you see' rows)."""
    A, U = g["arrows"], g["updown"]
    left = [("Chart", None), ("%s %s" % (A[0], A[1]), "longer %s shorter" % g["mid"]),
            ("t  T", "cycle spans %s back" % g["mid"]), ("", ""),
            ("Panels", None), ("a", "top apps"), ("s", "Claude sessions"), ("e", "events"),
            ("enter", "its processes"), ("", ""),
            ("General", None), ("?  F1", "help %s next page" % g["mid"]), ("esc", "close %s back" % g["mid"]),
            ("q  ctrl-c", "quit")]
    right = [("Lists", None), (U[1], "into Reservations"), (U[0], "into Incidents"),
             ("%s %s  j k" % (U[0], U[1]), "move in the list"), ("space", "the other list"),
             ("pgup pgdn", "a page"), ("home end", "first %s last row" % g["mid"]), ("enter", "details"),
             ("o", "open the report"), ("y", "copy its path"), ("", ""),
             ("Terminal", None), ("ctrl-l", "redraw"), ("ctrl-z", "suspend")]
    away = model.get("os", "").startswith("macOS") or "os" not in model
    see = [("Chart", None),
           ([(g["sw"], role) for _, role in SERIES_WORDS], "%s, stacked; %s is the RAM" % (
               ", ".join(n for n, _ in SERIES_WORDS), g["ram"][1]))]
    if away:
        see.append(([(g["legend_away"], "dim")], "away: idle for 5 min, screen locked or display off"))
    see += [([(g["hatch"], "hatch")], "no data: asleep or off, or the logger was not running"),
            ([(g["inc"], "incident")], "an incident began here"),
            ("Reserved by agents", None),
            ([(g["eighths"][5] * 2, "r0"), (" ", None), (g["queued"] * 2, "r3")],
             "a block per reservation; height is GB; %s is waiting" % g["queued"]),
            ([(g["swq"], "r3"), (" ", None), (g["sw"], "r0")], "waiting %s granted; a dimmed row has ended" % g["mid"]),
            ("Incidents", None),
            ([(g["dot"], "incident"), (" ", None), (g["odot"], "faint")], "still open %s closed" % g["mid"])]
    return left, right, see


def help_entries(g, model):
    """Both pages as one column, for the full-pane form that scrolls."""
    left, right, see = help_pages(g, model)
    return [e for e in left + right if e != ("", "")] + [("", ""), ("What you see", None)] + see


def overlay_help(fr, caps, g, model, ui, ov):
    """? opens the keys; ? again turns to "What you see". Where the box does not fit, both pages are
    one column that scrolls."""
    left, right, see = help_pages(g, model)
    mono = caps.color == "none"

    def entry(k, d, kw):
        def fn(fr, x, y, w, bg):
            if d is None:
                fr.put(x, y, k, "accent" if not mono else None, bg, BOLD)
            elif isinstance(k, list):
                xx = x
                for text, role in k:
                    xx = fr.put(xx, y, text, None if mono else role, bg)
                fr.put(x + kw, y, fit(d, w - kw, g), "fg", bg)
            elif k or d:
                fr.put(x, y, k, "fg", bg, BOLD)
                fr.put(x + kw, y, fit(d, w - kw, g), "dim", bg)
        return fn

    if fr.w >= 76 and fr.h >= 24:
        if ov.get("page", 1) == 1:
            def row(i):
                def fn(fr, x, y, w, bg):
                    if i < len(left):
                        entry(left[i][0], left[i][1], 11)(fr, x, y, 34, bg)
                    if i < len(right):
                        entry(right[i][0], right[i][1], 11)(fr, x + 36, y, w - 36, bg)
                return fn
            rows = [(1, row(i)) for i in range(15)]
        else:
            rows = [(1, entry(k, d, 8)) for k, d in see] + [(1, None)] * (15 - len(see))
        lines = [(9, None)] + rows + [(8, None), (5, _text(ui.get("detected") or "", "faint"))]
        return dialog(fr, g, caps, "Keys" if ov.get("page", 1) == 1 else "What you see", 74, 21, lines,
                      [("esc", "close"), ("?", "what you see" if ov.get("page", 1) == 1 else "keys"),
                       ("", "page %d of 2" % ov.get("page", 1))])
    entries = help_entries(g, model)
    n = fr.h - 3
    off = max(0, min(ov.get("off", 0), len(entries) - n))
    lines = [(1, entry(k, d, 12 if not isinstance(k, list) else 6)) for k, d in entries[off:off + n]]
    pos = "%d%s%d of %d" % (off + 1, g["dash"], min(off + n, len(entries)), len(entries))
    return dialog(fr, g, caps, "Help", 74, 21, lines, [("esc", "close"), (g["updown"], "scroll"), ("", pos)])


def help_rows(fr_w, fr_h, g, model):
    """How many entries the scrolling help has, and how many fit (the loop clamps its offset)."""
    return len(help_entries(g, model)), fr_h - 3


def selected(model, ui):
    """The reservation or incident the selection is on, by list: (kind, item) or (None, None)."""
    f = ui.get("focus")
    if f == "res":
        seq = res_seq(model)[0]
        i = ui.get("res_sel", 0)
        return ("res", seq[i]) if 0 <= i < len(seq) else (None, None)
    if f == "inc":
        incs = model["incidents"]
        i = ui.get("inc_sel", 0)
        return ("inc", incs[i]) if 0 <= i < len(incs) else (None, None)
    if f == "panel" and ui.get("panel") in ("a", "s"):
        items = panel_items(model, ui["panel"])
        i = ui.get("panel_sel", 0)
        return (ui["panel"], items[i]) if 0 <= i < len(items) else (None, None)
    return None, None


def _holder_text(r):
    kind = {"session": "Claude session", "run": "oomph run", "process": "process"}.get(r.get("holder") or "", r.get("holder"))
    if not kind:
        return "unknown"
    return "%s (pid %d)" % (kind, r["pid"]) if r.get("pid") else str(kind)


def card_res(fr, caps, g, model, r):
    """enter on a reservation: the app's ReservationCard. For a waiting one: what it waits for."""
    now = model["now"]
    waiting, granted, _ = ordered_res(model["res"])
    mono = caps.color == "none"
    gb = r["segments"][-1][1]

    def head(fr, x, y, w, bg):
        fr.put(x, y, g["sw"] if r.get("granted") is not None else g["swq"], None if mono else res_color(r["purpose"]), bg)
        fr.put(x + 2, y, fit("%.1f GB  %s" % (gb, r["purpose"]), w - 2, g), "fg", bg, BOLD)
    project = r.get("project") if isinstance(r.get("project"), str) else None
    lines = [(9, None), (0, head), (8, None)]
    if project:
        lines.append((1, _kv("Project", project)))
    lines.append((2, _kv("Holder", _holder_text(r))))
    if len(r["segments"]) > 1:
        lines.append((3, _kv("Sizes", (" %s " % g["arrow"]).join(
            "%s %s" % (gfmt(s_gb), hhmm(t)) for t, s_gb in r["segments"][-4:]))))
    if r.get("ended") is not None:
        lines += [(0, _kv("Ended", "%s at %s" % ((r.get("outcome") or "ended").replace("_", " "), hhmm(r["ended"])))),
                  (1, _kv("Peak", "%.1f GB" % _gb(r.get("peak"))))]
        if r.get("granted") is not None:
            lines.append((2, _kv("Ran", "%s, after waiting %s" % (ago(r["ended"] - r["granted"]),
                                                                     ago(r["granted"] - r["requested"])))))
    elif r.get("granted") is None:
        ahead = [w_ for w_ in waiting if _queue_key(w_) < _queue_key(r)]
        st = model.get("ledger_state") or {}
        owed = sum(max(0.0, x_["segments"][-1][1] - _gb(x_.get("used"))) for x_ in granted)
        lines.append((0, _kv("Waiting", "%s, %s" % (ago(now - r["requested"]), "first in the queue" if not ahead else
                                                    "behind %d in the queue" % len(ahead)), "warntx")))
        if isinstance(st.get("free_gb"), (int, float)) and isinstance(st.get("margin_gb"), (int, float)):
            avail = st["free_gb"] - owed - st["margin_gb"]
            lines += [(1, _kv("Needs", "%.1f GB; %.1f GB can be granted now" % (gb, max(0.0, avail)))),
                      (2, _kv("", "%.1f GB free, %.1f GB still owed to grants, %.1f GB margin"
                              % (st["free_gb"], owed, st["margin_gb"]), "dim"))]
        else:
            lines.append((1, _kv("Needs", "%.1f GB" % gb)))
        lines.append((3, _kv("Ahead", "nobody: it is granted as soon as it fits" if not ahead else
                             ", ".join("%s %s" % (a["purpose"], gfmt(a["segments"][-1][1])) for a in ahead[:3]) +
                             (" %s" % g["ell"] if len(ahead) > 3 else ""))))
        if granted:
            big = sorted(granted, key=lambda x_: -x_["segments"][-1][1])
            lines.append((2, _kv("Holding", ", ".join("%s %s" % (x_["purpose"], gfmt(x_["segments"][-1][1]))
                                                      for x_ in big[:3]) + (" %s" % g["ell"] if len(big) > 3 else ""))))
    else:
        lines.append((0, _kv("Using", "%.1f GB now %s peak %.1f GB" % (_gb(r.get("used")), g["mid"], _gb(r.get("peak"))))))
        lines.append((1, _kv("Granted", "%s, after waiting %s" % (hhmm(r["granted"]), ago(r["granted"] - r["requested"])))))
        if r.get("expires") is not None:
            lines.append((1, _kv("Expires", "in %s, unless its holder renews it" % left_of(r["expires"] - now))))
    lines += [(4, _kv("Requested", "%s as %s" % (time.strftime("%H:%M:%S", _lt(r["requested"])), r.get("id") or "?"))),
              (9, None)]
    return dialog(fr, g, caps, "Reservation", 76, len(lines) + 3, lines,
                  [("esc", "close"), (g["updown"], "previous %s next" % g["mid"])])


def card_inc(fr, caps, g, model, inc):
    """enter on an incident: the summary of its incident.json, in place."""
    now = model["now"]
    end = now if inc["open"] or inc.get("end") is None else inc["end"]
    head = "%s %s %s%s" % (day_hhmm(inc["start"]), g["mid"], "open " if inc["open"] else "", ago(end - inc["start"]))
    lines = [(9, None), (0, _text(head, "incident" if inc["open"] else "fg", BOLD)), (8, None)]
    reasons = inc.get("reasons") or ([inc["desc"]] if inc.get("desc") else [])
    for i, d in enumerate(reasons[:3]):
        lines.append((0 if i == 0 else 1, _kv("Triggers" if i == 0 else "", d, "incident")))
    s = inc.get("summary") or {}
    peak = []
    if s.get("peak_pressure"):
        peak.append("%s%s" % (s["peak_pressure"], " at %s" % s["peak_at"][11:16] if isinstance(s.get("peak_at"), str)
                              and len(s["peak_at"]) >= 16 else ""))
    if isinstance(s.get("max_swap_used_gb"), (int, float)):
        peak.append("swap %.1f of %.1f GB" % (s["max_swap_used_gb"], _gb(s.get("max_swap_total_gb"))))
    if peak:
        lines.append((1, _kv("Peak", (" %s " % g["mid"]).join(peak))))
    if inc.get("kills"):
        mk = s.get("most_killed") or []
        lines.append((1, _kv("Killed", "%d%s" % (inc["kills"], (": " + ", ".join("%s %d" % kv for kv in mk[:3])) if mk else
                                                 ""))))
    if s.get("risers"):
        lines.append((2, _kv("Grew most", (" %s " % g["mid"]).join("%s +%.1fG" % kv for kv in s["risers"][:3]))))
    if s.get("on_top"):
        lines.append((2, _kv("On top", (" %s " % g["mid"]).join("%s %.1fG" % kv for kv in s["on_top"][:4]))))
    if s.get("sessions"):
        lines.append((3, _kv("Sessions", (" %s " % g["mid"]).join("%s %.1fG" % kv for kv in s["sessions"][:2]))))
    if isinstance(s.get("away_fraction"), (int, float)):
        lines.append((4, _kv("Away", "%d %% of the time" % round(100 * s["away_fraction"]))))
    if inc.get("report"):
        lines.append((5, _kv("Report", inc["report"], "dim")))
    elif inc["open"]:
        lines.append((5, _kv("Report", "written when it closes", "dim")))
    lines.append((9, None))
    return dialog(fr, g, caps, "Incident %s" % inc["id"], 76, len(lines) + 3, lines,
                  [("esc", "close"), ("o", "open the report"), ("y", "copy its path")])


def card_procs(fr, caps, g, model, kind, item):
    """enter on an app or a Claude session: its processes among the 25 biggest of the sample, and
    for a session what it holds reserved."""
    procs = (model.get("cur") or {}).get("top") or []
    if kind == "a":
        name, gb, n = item
        title, mine = name, [p for p in procs if p[3] == name]
        head = "%.1f GB in %d process%s" % (gb, n, "" if n == 1 else "es")
    else:
        pid, cwd, gb, n, _ = item
        title, mine = cwd, [p for p in procs if p[4] == pid]
        head = "%.1f GB in %d process%s %s session pid %d" % (gb, n, "" if n == 1 else "es", g["mid"], pid)
    lines = [(9, None), (0, _text(head, "fg", BOLD)), (8, None)]
    for p in mine[:12]:
        lines.append((1, _kv("%6.2fG" % p[2], "%s  (pid %d)" % (p[1], p[0]), "fg", 9)))
    if not mine:
        lines.append((1, _text("none among the 25 biggest processes of the last sample", "dim")))
    elif len(mine) > 12:
        lines.append((2, _text("%d more among the 25 biggest" % (len(mine) - 12), "dim")))
    if kind == "s":
        held = session_reservations(model, pid)
        if held:
            lines.append((3, None))
            for r in held[:4]:
                lines.append((3, _kv("Reserved", "%s %s" % (gfmt(r["segments"][-1][1]), r["purpose"]), "fg")))
    lines.append((9, None))
    return dialog(fr, g, caps, fit(title, 60, g), 76, len(lines) + 3, lines,
                  [("esc", "close"), (g["updown"], "previous %s next" % g["mid"])])


# ------------------------------------------------------------------ the frame
def keys_main(g, model):
    """The hints of the key line, most useful first. While pressure is not normal or an incident is
    open, `s sessions` moves up: "what is using the memory?" is the question then."""
    cur = model.get("cur") or {}
    hot = cur.get("pressure") not in (None, "Normal") or any(i["open"] for i in model["incidents"])
    k = [("q", "quit"), ("?", "help"), ("a", "apps")]
    if hot:
        k.append(("s", "sessions"))
    k += [(g["arrows"], "span"), (g["updown"], "select")]
    if not hot:
        k.append(("s", "sessions"))
    k.append(("e", "events"))
    return k


def keys_of(g, model, ui, P):
    """The key line of the mode the dashboard is in; every mode but the plain view starts with esc
    and where it leads."""
    if ui.get("panel"):
        where = panel_area(P)[2]
        k = [("esc", where)]
        k += [(p, {"a": "apps", "s": "sessions", "e": "events"}[p]) for p in "ase" if p != ui["panel"]]
        if ui["panel"] == "e":
            k.append((g["updown"], "scroll"))
        else:
            k += [(g["updown"], "select"), ("enter", "its processes")]
        return k + [("q", "quit"), ("?", "help")]
    f = ui.get("focus")
    if f in ("res", "inc"):
        k = [("esc", "deselect"), (g["updown"], "move")]
        other = "inc" if f == "res" else "res"
        if (P["I"] if other == "inc" else P["R"]) and (model["incidents"] if other == "inc" else model["res"]):
            k.append(("space", "incidents" if other == "inc" else "reservations"))
        k.append(("enter", "details"))
        if f == "inc":
            k += [("o", "report"), ("y", "copy path")]
        return k
    return keys_main(g, model)


def status_of(model, g, ui=None):
    """(text, role) at the right of the key line, in the app's words."""
    ui = ui or {}
    if ui.get("note"):
        return ui["note"][0], ui["note"][1]
    if model.get("status"):
        return model["status"], model.get("status_role", "faint")
    for i in model["incidents"]:
        if i["open"]:
            return "Incident open %s %s" % (g["mid"], ago(model["now"] - i["start"])), "crit"
    if ui.get("readonly"):
        return ui["readonly"], "warntx"
    lg = model.get("logger")
    if lg == "off":
        return model.get("off_text") or "Logging is off", "warntx"
    if lg == "silent":
        return "Logger not reporting since %s" % hhmm(model.get("logger_t") or model["now"]), "warntx"
    return "Logging every %d s" % (model.get("interval") or 30), "faint"


def draw_footer(fr, y, g, status, keys, status_role="faint", must=("a",)):
    """The key line. The status sits at its right; hints give way from the right. The status never
    displaces a hint named in `must`: where both do not fit, the status goes."""
    def shown(limit):
        out, x = [], 1
        for k, d in keys:
            if x + tw(k) + len(d) + 1 > limit:
                break
            out.append((k, d))
            x += tw(k) + len(d) + 3
        return out
    limit = fr.w - (tw(status) + 3 if status else 1)
    want = [k for k, _ in keys if k in must]
    if status and any(k not in [s[0] for s in shown(limit)] for k in want):
        status, limit = None, fr.w - 1
    x = 1
    for k, d in shown(limit):
        x = fr.put(x, y, k, "fg", None, BOLD)
        x = fr.put(x + 1, y, d, "dim") + 2
    if status:
        fr.rput(fr.w - 2, y, fit(status, fr.w - 2, g), status_role)


def too_small(W, H, caps):
    fr = Frame(W, H, caps.glyphs == "ascii")
    lines = ["oomph top", "needs 40 x 10", "this is %d x %d" % (W, H)]
    for i, text in enumerate(lines):
        fr.put(max((W - len(text)) // 2, 0), max(H // 2 - 1, 0) + i, text, "fg" if i == 0 else "dim", None,
               BOLD if i == 0 else 0)
    return fr


def layout(model, W, H):
    """The row plan for this model at this size (its slow facts: reservations and incidents on record)."""
    return plan(W, H, has_res=bool(model["res"]), has_inc=bool(model["incidents"]))


def render(model, W, H, caps, ui):
    """The whole frame: a pure function of the model, the size, the terminal's capabilities and the
    ui state ({"span": "24h"} and, while running, the selection, the panel, the dialog, a note).
    model: see oomph_top.load_model. The frame's `yhold` is what the loop keeps for the next one."""
    g = GLYPHS[caps.glyphs]
    if W < 40 or H < 10:
        return too_small(W, H, caps)
    fr = Frame(W, H, caps.glyphs == "ascii")
    P = layout(model, W, H)
    tab_bar(fr, model, caps, g)
    if P["stats"]:
        draw_stats(fr, 1, P["stats_y"], W - 2, model, g, P["stats"])
        if model.get("logger") == "silent":     # readings that are not live any more stay, greyed
            fr.restyle(0, P["stats_y"], W, P["stats"], "off")
    draw_body(fr, P, model, ui, caps, g)
    if P["wide"]:
        draw_right(fr, P, model, caps, g)
    status, srole = status_of(model, g, ui)
    keys = keys_of(g, model, ui, P)
    ov = ui.get("overlay")
    if ov:
        boxed = draw_overlay(fr, model, ui, ov, caps, g)
        if not boxed:
            return fr                           # its hints are on the key line
        fr.fill(0, H - 1, W, 1, " ", None, None)
        keys = [("esc", "close")]
    draw_footer(fr, H - 1, g, status, keys, srole, must=("esc",) if keys[0][0] == "esc" else ("a",))
    if ov:
        fr.restyle(0, H - 1, W, 1, "off")
    return fr


def draw_overlay(fr, model, ui, ov, caps, g):
    kind = ov.get("kind")
    if kind == "help":
        return overlay_help(fr, caps, g, model, ui, ov)
    if kind == "inc":
        inc = next((i for i in model["incidents"] if i["id"] == ov.get("id")), None)
        if inc:
            return card_inc(fr, caps, g, model, inc)
    elif kind == "res":
        r = next((r for r in model["res"] if r["key"] == ov.get("key")), None)
        if r:
            return card_res(fr, caps, g, model, r)
    elif kind in ("a", "s"):
        items = panel_items(model, kind)
        item = next((x for x in items if (x[0] == ov.get("id"))), None)
        if item:
            return card_procs(fr, caps, g, model, kind, item)
    return dialog(fr, g, caps, "Gone", 60, 6, [(9, None), (0, _text("This is no longer in the data.", "dim")), (9, None)],
                  [("esc", "close")])


def draw_body(fr, P, model, ui, caps, g):
    """The chart box: span selector and legend, plot, time axis, the reservation strip, the lists (or
    the panel that took their place)."""
    lw = P["lw"]
    x0, pw, ph = P["plot_x"], P["plot_w"], P["plot_h"]
    for yy in range(P["box_y"] + 1, P["bottom_y"]):
        fr.put(0, yy, g["v"], "line")
        fr.put(lw - 1, yy, g["v"], "line")
    fr.hline(0, P["bottom_y"], lw, g, "line", g["bl"], g["br"])
    draw_chart_head(fr, 0, P["box_y"], lw, ui, caps, g, "Memory")
    gridcols = draw_plot(fr, x0, P["plot_y"], pw, ph, model, ui, caps, g)
    now = model["now"]
    rows, n_live, n_wait = list_rows(model, P["R"], ui)
    if P["cap_y"] is not None:
        live = [r for r in model["res"] if r.get("ended") is None]
        reserved = sum(r["segments"][-1][1] for r in live if r.get("granted") is not None)
        n24 = sum(1 for r in model["res"] if (r["ended"] if r.get("ended") is not None else now) >= now - 86400)
        summary = "%.1f GB reserved %s %d in the last 24 h" % (reserved, g["mid"], n24)
        if tw(summary) + 4 > lw - 2 - (24 if lw >= 64 else 14):      # too long beside the title: the count gives way
            summary = summary.split(" %s " % g["mid"])[0]
        hidden = n_live - sum(1 for r in rows if r[0] == "res" and r[1].get("ended") is None)
        if hidden and not any(r[0] == "more" for r in rows):         # no list at all: the caption counts
            summary = "%d granted%s %s %s" % (n_live - n_wait, " %s %d waiting" % (g["mid"], n_wait) if n_wait else "",
                                             g["mid"], summary.split(" %s " % g["mid"])[0])
        section(fr, 0, P["cap_y"], lw, g, "Reserved by agents" if lw >= 64 else "Reserved", summary)
        if P["S"]:
            draw_strip(fr, x0, P["strip_y"], pw, P["S"], model, ui, caps, g, gridcols)
    if P["R"]:
        draw_res_rows(fr, 1, P["list_y"], lw - 2, rows, model, caps, g, ui)
    if P["I"]:
        incs = model["incidents"]
        n = model.get("incidents_90d", len(incs))
        off = min(ui.get("inc_off", 0), max(len(incs) - P["I"], 0))
        right = "%d in 90 days" % n
        if n > P["I"] or off:
            last = min(off + P["I"], len(incs))
            right = "%d%s%d of %s %s" % (off + 1, g["dash"], last, right, g["down"] if last < n else g["up"])
        section(fr, 0, P["inc_cap_y"], lw, g, "Incidents", right)
        draw_incident_rows(fr, 1, P["inc_y"], lw - 2, incs[off:off + P["I"]], model, caps, g, ui, off)
    if ui.get("panel"):
        draw_panel(fr, model, ui, P, caps, g)


# ------------------------------------------------------------------ the writer: two frames → bytes
def diff_ansi(prev, cur, caps, join=4):
    """The bytes that turn a screen showing `prev` into `cur` (prev None: clear and paint all). Changed
    cells are grouped into runs; runs fewer than `join` cells apart are written as one (moving the
    cursor costs more than repainting a few cells). A two-cell character is atomic: a run never
    starts on its second cell and never ends on its first. One synchronized update per frame; no
    change writes nothing. Only sequences built here from numbers reach the terminal."""
    full = prev is None or prev.w != cur.w or prev.h != cur.h
    out, style = ["\x1b[?2026h" + ("\x1b[0m\x1b[2J" if full else "")], None
    blank = [" ", None, None, 0]
    for y in range(cur.h):
        row = cur.c[y]
        old = None if full else prev.c[y]
        x = 0
        while x < cur.w:
            if old is not None and old[x] == row[x]:
                x += 1
                continue
            if old is None and row[x] == blank:      # after a clear, blanks are there already
                x += 1
                continue
            end, k, same = x + 1, x + 1, 0
            while k < cur.w and same < join:
                unchanged = old[k] == row[k] if old is not None else row[k] == blank
                if unchanged:
                    same += 1
                else:
                    same, end = 0, k + 1
                k += 1
            while x > 0 and (row[x][0] == "" or (old is not None and old[x][0] == "")):   # not inside a pair
                x -= 1
            while end < cur.w and (row[end][0] == "" or (old is not None and old[end][0] == "")):
                end += 1
            out.append("\x1b[%d;%dH" % (y + 1, x + 1))
            for cell in row[x:end]:
                if cell[0] == "":
                    continue
                ch, sgr = paint(cell, caps)
                if sgr != style:
                    out.append(sgr)
                    style = sgr
                out.append(ch)
            x = end
    if len(out) == 1 and not full:
        return ""
    out.append("\x1b[0m\x1b[?2026l")
    return "".join(out)
