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
import bisect
import collections
import math
import re
import time
import unicodedata
import zlib

BOLD, REV, UL, DIM = 1, 2, 4, 8
KEEP = object()          # Frame.put(..., bg=KEEP): leave the cell's background as it is
MIN_AGE = 300.0          # ages below this share the right edge of the log axis (TimeAxis.minAge)
GAP_S = 300.0            # longer than this without a sample is a gap (Store.gapSeconds)
QUEUE_STALE_S = 180.0    # a queue place not polled for this long has lapsed (oomph.QUEUE_STALE_S)
KEEP_DAYS = 14           # reservations and samples shown (the log keeps 14 days)
MERGE_KEEP = ("res", "peak", "v", "agent", "user")  # a later record's null does not undo these (oomph.MERGE_KEEP)
LEVELS = (604800, 86400, 21600, 3600, 900, 300, 60)   # grid levels, coarse first (TimeAxis.levels)
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
        "r6": "#4CB85C", "r7": "#2D6BAB", "g0": "#7E9A2E", "g1": "#9C4B36", "g2": "#9580C4", "g3": "#B5CF70", "g4": "#D99A82",
        "g5": "#CBB0F5", "gx": "#6E6E73",
    },
    "light": {
        "fg": "#262626", "bg": "#FFFFFF", "ink": "#262626", "dim": "#767676", "faint": "#9E9E9E", "line": "#C4C4C4",
        "grid": "#E2E2E2", "bar": "#EEEEEE", "wired": "#8E8E93", "app": "#0088FF", "comp": "#FF8D28", "swap": "#FF383C",
        "incident": "#FF383C", "ok": "#1F8A3B", "warn": "#8A6A00", "warntx": "#8A6A00", "crit": "#C4262A",
        "away": "#EEEEEF", "hatch": "#A8A8A8", "sel": "#FFFFFF", "selfg": "#000000", "trough": "#E4E4E4",
        "accent": "#0088FF", "onblock": "#FFFFFF", "rowsel": "#DCDCDC",
        "r0": "#12A5B0", "r1": "#A550E0", "r2": "#F04F78", "r3": "#5E5CE6", "r4": "#C89400", "r5": "#A2845E",
        "r6": "#34A853", "r7": "#2B48A9", "g0": "#0E9021", "g1": "#8A3D24", "g2": "#986AC5", "g3": "#7BC98A", "g4": "#D08A5E",
        "g5": "#CDA0EE", "gx": "#A3A3A8",
    },
}
ON_PAINT = ("ink", "selfg", "onblock")      # text colours that only make sense on a painted background
# One stable character per role for the golden format: a new style never renames the others.
ROLE_CODE = {None: ".", "fg": ".", "ink": "I", "dim": "d", "faint": "f", "line": "l", "grid": "g", "bar": "B",
             "trough": "T", "sel": "S", "selfg": "s", "wired": "w", "app": "a", "comp": "c", "swap": "p",
             "incident": "i", "ok": "o", "warn": "W", "warntx": "x", "crit": "C", "away": "y", "hatch": "h",
             "accent": "A", "onblock": "k", "rowsel": "R", "r0": "0", "r1": "1", "r2": "2", "r3": "3", "r4": "4", "r5": "5", "r6": "6", "r7": "7",
             "g0": "u", "g1": "v", "g2": "z", "g3": "q", "g4": "j", "g5": "e", "gx": "n"}
MOD_CODE = {"": ".", "off": "o"}
# 16 colours: the index (0-7 normal, 8-15 bright) or None for the terminal's default. Whatever is a
# block or a background is one of the eight base colours, so it works as SGR 40-47 too.
ROLE16 = {"fg": None, "ink": None, "selfg": None, "dim": 8, "faint": 8, "line": 8, "grid": 8, "hatch": 8,
          "wired": 7, "app": 4, "comp": 3, "swap": 1, "incident": 9, "crit": 1, "ok": 2, "warn": 3, "warntx": 3,
          "accent": 12, "onblock": 0, "r0": 6, "r1": 5, "r2": 1, "r3": 4, "r4": 3, "r5": 7, "r6": 2, "r7": 4,
          "g0": None, "g1": None, "g2": None, "g3": None, "g4": None, "g5": None, "gx": 8}
# With 16 colours an agent is the text colour, neighbouring slots alternating full and medium (dim) shade:
# every free index is a state's or a resource's hue (02 §3.8.3, §16 "04 Terminal dashboard").
AGENT16_DIM = ("g1", "g3", "g5")
# The reference theme: hand-picked xterm-256 indexes where the nearest one loses the hue.
# "name@off" is the muted palette of what is no longer live.
AGENT256 = {"g0": 28, "g1": 94, "g2": 140, "g3": 114, "g4": 173, "g5": 183, "gx": 248}   # 02 §3.8.3, both themes
PICK256 = {"dark": {"comp": 208, "ok": 41, "warn": 220, "warntx": 172, "swap": 203, "incident": 203, "r4": 178,
                    "ink": 253, "dim": 246, "faint": 242, "hatch": 242, "bar": 235, "trough": 236, "sel": 59,
                    "rowsel": 237, "wired@off": 243, "app@off": 67, "comp@off": 137, "swap@off": 131},
           "light": {"comp": 208, "ok": 28, "warn": 94, "warntx": 94, "swap": 203, "incident": 203, "away": 254,
                     "bar": 255, "trough": 253, "sel": 231, "ink": 235, "dim": 243, "faint": 247, "hatch": 248, "rowsel": 253,
                     "wired@off": 247, "app@off": 110, "comp@off": 180, "swap@off": 174}}
for _t in PICK256.values():
    _t.update(AGENT256)
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
    """What the terminal can do. color: truecolor | 256 | 16 | none; glyphs: unicode | cells | ascii | cp437;
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
                    more_l="‹", more_r="›", up="▴", down="▾", dash="–", arrow="→", miss=":", close="×", queue="◻", upper="▀",
                    marks=dict(ok="●", warn="◐", crit="◆", silent="◦", busy="↻", off="⊘", att="▲")),
    "ascii": dict(h="-", v="|", tl="+", tr="+", bl="+", br="+", lt="+", rt="+", eighths=" ...::###",
                  hatch="/", grid=" ", inc="!", awaydot=".", sw="#", swq="o", dot="*", odot="o",
                  sel=">", ell="~", inf="all", mid="-", shades="#=:*", queued="?", ram=("_", "-", "-"),
                  meter="#", meterbg=".", arrows="<>", updown="^v", legend_sw="#", legend_away=".",
                  more_l="<", more_r=">", up="^", down="v", dash="-", arrow="->", miss=":", close="x", queue="#", upper="=",
                  marks=dict(ok="*", warn="w", crit="C", silent="-", busy="~", off="o", att="^")),
}
GLYPHS["cells"] = dict(GLYPHS["unicode"])      # --glyphs cells: the rasteriser differs, the characters do not
# --glyphs cp437, the Linux console (TERM=linux; 04 §3.11, T3): its font has the full and lower half block, the three
# shades, single-line boxes and a few symbols of code page 437, but no eighths, no rounded corners and no circles. The
# chart drops to half-row accuracy (a cell is empty, half or full); the marks are the ASCII set's.
GLYPHS["cp437"] = dict(GLYPHS["unicode"], tl="┌", tr="┐", bl="└", br="┘", eighths="  ▄▄▄▄███", hatch="/", grid="·",
                       inc="│", sw="■", swq="o", dot="*", odot="o", sel="►", ell="~",
                       mid="·", queued="▒", ram=("_", "─", "─"), legend_away="░", more_l="◄", more_r="►", up="▲",
                       down="▼", dash="-", arrow="→", miss=":", close="x", queue="■", arrows="←→", updown="↑↓",
                       marks=dict(GLYPHS["ascii"]["marks"]))
# The view's own words hold a few characters code page 437 does not have (an ellipsis, a dash, rounded corners, a
# circle): on the Linux console a frame puts them as these (one cell for one cell; no-data is "/", not a shade, so
# that without colour it differs from Swap's shade and from away).
CP437_WORDS = {ord(k): v for k, v in {
    "…": "~", "–": "-", "—": "-", "›": ">", "‹": "<", "×": "x", "“": '"', "”": '"', "‘": "'", "’": "'", "◻": "■",
    "●": "*", "○": "o", "◦": "o", "◐": "w", "◆": "C", "⊘": "o", "↻": "~", "╭": "┌", "╮": "┐", "╰": "└", "╯": "┘",
    "╱": "/", "┊": "│", "┃": "│", "╌": "─", "‾": "─", "▴": "▲", "▾": "▼", "▁": "_", "▂": "▄", "▃": "▄", "▅": "▄",
    "▆": "█", "▇": "█"}.items()}


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
        if fmod or bmod or fname in AGENT16_DIM or bname in AGENT16_DIM:
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

    def __init__(self, w, h, ascii_only=False, cp437=False):
        self.w, self.h, self.ascii_only, self.cp437 = w, h, ascii_only, cp437   # cp437: CP437_WORDS on every put
        self.yhold = None           # what the plot's y axis holds for the next frame (the loop keeps it)
        self.tab_hits = []          # row 0's tabs, counters and + as drawn: (x0, x1, kind, which), for a click
        self.c = [[[" ", None, None, 0] for _ in range(w)] for _ in range(h)]

    def put(self, x, y, text, fg=None, bg=KEEP, fl=0):
        if self.cp437 and not text.isascii():
            text = text.translate(CP437_WORDS)
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
    """TimeAxis.mapper with blend 0 (linear: the last span_s seconds) or, span_s None, blend 1 (log
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
    """Store.worst: the point with the most app + compressed + swap, away if any was, kills summed;
    the other resources, where the points carry them, aggregated (res_agg)."""
    w = max(bucket, key=lambda p: p["app"] + p["comp"] + p["swap"])
    if len(bucket) == 1:
        return w
    out = dict(w, away=any(p["away"] for p in bucket), kills=sum(p["kills"] for p in bucket))
    if "cpu" in w:
        out.update(res_agg(bucket))
    return out


RES_POINT = ("cpu", "sys", "gpu", "gmem", "disk", "nd", "nu")   # a point's other resources (oomph_top.res_point)
NET_MIXED = 255         # a bucket's `nk` when its samples were on more than one network (net_key)


def net_key(nb):
    """A sample's network as a 7-bit mark, 1-127 (0: none named; Point.netKey): enough to tell that the last samples
    were not all on one network (the stale hint, 12.8), at the cost of a byte per sample. Two networks share a mark
    one time in 127: the hint may then read a sample of the network before, as it did without the mark."""
    k = nb.get("network") if isinstance(nb, dict) else None
    return 1 + zlib.crc32(k[:200].encode("utf-8", "replace")) % 127 if isinstance(k, str) and k else 0


def res_agg(rows):
    """Point.aggregate: the mean of the rates, the GPU's of the newest kind only (a bucket never averages
    busy time with the figure at full speed, 02 §3.4.11), the most GPU memory, the least free disk."""
    def mean(xs):
        return sum(xs) / len(xs) if xs else None
    full = next((r["gfull"] for r in reversed(rows) if r.get("gpu") is not None), False)
    gm, dk = [r["gmem"] for r in rows if r.get("gmem") is not None], [r["disk"] for r in rows if r.get("disk") is not None]
    nd, nu = [r for r in rows if r.get("nd") is not None], [r for r in rows if r.get("nu") is not None]
    return {"nd": mean([r["nd"] for r in nd]), "nu": mean([r["nu"] for r in nu]),     # the network: mean and peak
            "ndp": max([r.get("ndp", r["nd"]) for r in nd]) if nd else None,
            "nup": max([r.get("nup", r["nu"]) for r in nu]) if nu else None,
            "nf": all(r.get("nf") is True for r in rows),
            "nk": rows[0].get("nk", 0) if all(r.get("nk", 0) == rows[0].get("nk", 0) for r in rows) else NET_MIXED,
            "cpu": mean([r["cpu"] for r in rows if r.get("cpu") is not None]),
            "sys": mean([r["sys"] for r in rows if r.get("sys") is not None]),
            "gpu": mean([r["gpu"] for r in rows if r.get("gpu") is not None and r["gfull"] == full]), "gfull": full,
            "gmem": max(gm) if gm else None, "disk": min(dk) if dk else None}


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
    """TimeAxis.calmBands: spans closer than `tolerance` merge. Grey: away spans, bridged by the
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


def res_role(model, r):
    """A reservation's colour: its purpose's, or with the resources on its agent's (D11, 02 §3.8)."""
    if model.get("rv"):
        i = r.get("agent", -1)
        return AGENT_ROLES[i] if isinstance(i, int) and 0 <= i < len(AGENT_ROLES) else "gx"
    return res_color(r["purpose"])


def gb_at(r, t):
    """Reservation.gb(at:): its size at time t."""
    return ([g for s, g in r["segments"] if s <= t] or [r["segments"][0][1]])[-1]


def amount_at(r, k, t):
    """Reservation.amount(_:at:): its amount of resource k at time t."""
    if k == "memory":
        return gb_at(r, t)
    segs = amount_segs(r, k)
    return ([x for s, x in segs if s <= t] or [segs[0][1]])[-1]


def stack_reservations(rs, now, kind="memory"):
    """ResBlock.stack: lanes first-fit by request time; steps [a, b) with the stacked GB below (lo) and
    at the top (hi) of each block. An unchanged step is extended instead of repeated, except at the
    moment of the grant. `kind`: the band's resource (its amounts over time, amount_segs); the caller passes
    the reservations that hold it."""
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
        bps.update(t for t, _ in amount_segs(r, kind) if r["requested"] < t < b["end"])
    ts = sorted(bps)
    active, nxt = [], 0
    for a, bb in zip(ts, ts[1:]):
        while nxt < len(blocks) and blocks[nxt]["res"]["requested"] <= a:
            active.append(nxt)
            nxt += 1
        active = [j for j in active if blocks[j]["end"] > a]
        acc = 0.0
        for j in sorted(active, key=lambda j: blocks[j]["lane"]):
            r = blocks[j]["res"]
            steps, hi = blocks[j]["steps"], acc + amount_at(r, kind, a)
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
    r = dict(key=_key(o), id=_s(o["id"]), purpose=_s(o.get("purpose"), "?"),
             project=_s(o.get("project")), holder=_s(h.get("kind") if isinstance(h, dict) else h),
             pid=h.get("pid") if isinstance(h, dict) and isinstance(h.get("pid"), int) else None,
             requested=o["requested"], granted=o.get("granted"), ended=o.get("ended"), outcome=_s(o.get("outcome")),
             peak=o.get("peak_gb") or 0, used=o.get("used_gb"), expires=o.get("expires"),
             segments=segs or [(o["requested"], o["gb"])], agent=agent_index(o.get("agent")))
    r.update(res_vector(o))
    return r


# ------------------------------------------------------------------ a reservation's resources (B3, T4b: 02 §3.4.5, §3.4.6)
BAND_RES = ("memory", "cpu", "disk", "net")     # what agents reserve, in tile order (the GPU from 1.14; the network 1.15)
RES_WORD = {"memory": "memory", "cpu": "CPU", "gpu": "GPU", "disk": "disk",   # in "waiting for CPU", "over on disk"
            "net": "the network"}
NET_PARTS = ("net", "net_up")            # a lease's rate parts on the line, download and upload (NET 12.9)


def _amt(x):
    """An amount of the shared ledger: a finite number 0 … 1e6, else None (any user can write the ledger)."""
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and 0 <= x <= 1e6 else None


def _since(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and 0 < x < 1e11 else None


def res_vector(o):
    """Reservation(_:)'s resources (Reservation.vector): what a lease (`res` of parts) or a record (`res` of amounts,
    02 §6.2) holds besides its gb mirror. `mem`: does it hold memory (a vector without `ram` whose gb is the 0.01
    mirror does not); `cpu` cores and `disk` GB (granted, or asked while queued; None: not held), `pool` and
    `pool_name` of the disk; `cpu_used`, `disk_w` (written since the grant); `flags` {resource: [over|idle, since]}
    (a grant's advice, 02 §6.3); `waiting` the resources a queued lease waits for, in tile order; `rsegs` the
    amounts over time {cpu: [(t, cores)], disk: [...]} from its segments. Only what differs from "memory alone,
    nothing else" is returned (readers use .get with those defaults): 14 days of records stay small in oomph top.
    The network (NET 12.9, 1.15): `net`, `net_up` the rate in Mbit/s (granted, else asked; none for an unmanaged part),
    `net_gb`, `net_up_gb` the volume, `net_moved`, `net_up_moved` what it moved, `net_used` the download it uses,
    `net_eta` when it should be done, `net_unmanaged` (a network without a figure); its advice is flags["net"]."""
    res = o.get("res") if isinstance(o.get("res"), dict) else None
    out = {}
    if res is None:
        if o.get("granted") is None and o.get("ended") is None:
            w = [k for k in RESOURCES if k in {waited_resource(i) for i in _waiting_ids(o, ["ram"])}]
            if w:
                out["waiting"] = w
        return out
    lease = any(isinstance(x, dict) for x in res.values())
    mem = "ram" in res or (_amt(o.get("gb")) or 0.0) > 0.015
    if not mem:
        out["mem"] = False
    granted = o.get("granted") is not None
    if lease:
        flags = {}
        for k in ("cpu", "disk"):
            part = res.get(k) if isinstance(res.get(k), dict) else {}
            amt = (_amt(part.get("got")) if granted else None)
            amt = amt if amt is not None else _amt(part.get("ask"))
            if amt is None:
                continue
            out[k] = amt
            if granted and part.get("flag") in ("over", "idle"):
                flags[k] = [part["flag"], _since(part.get("over_t" if part["flag"] == "over" else "low_t"))]
        if flags:
            out["flags"] = flags
        d = res.get("disk") if isinstance(res.get("disk"), dict) else {}
        if "disk" in out:
            for f, x in (("pool", _s(d.get("pool"))), ("pool_name", _s(d.get("name")))):
                if x is not None:
                    out[f] = x
        x = _amt((res.get("cpu") or {}).get("used")) if isinstance(res.get("cpu"), dict) else None
        if x is not None:
            out["cpu_used"] = x
        x = _amt(d.get("w"))
        if x is not None:
            out["disk_w"] = x
        for k in NET_PARTS:
            part = res.get(k) if isinstance(res.get(k), dict) else None
            if part is None:
                continue
            unmanaged = part.get("unmanaged") is True     # no rate: its `ask` is kept for a later network's figure
            rate = _amt(part.get("got")) if granted and not unmanaged else None
            rate = rate if rate is not None or unmanaged else _amt(part.get("ask"))
            for f, x in ((k, rate), (k + "_gb", _amt(part.get("gb"))), (k + "_moved", _amt(part.get("moved")))):
                if x is not None:
                    out[f] = x
            if k == "net" and _amt(part.get("used")) is not None:
                out["net_used"] = _amt(part.get("used"))
            if _since(part.get("eta")) is not None and "net_eta" not in out:
                out["net_eta"] = _since(part["eta"])
            if unmanaged:
                out["net_unmanaged"] = True
            if granted and part.get("flag") in ("over", "idle") and "net" not in flags:
                flags["net"] = [part["flag"], _since(part.get("over_t" if part["flag"] == "over" else "low_t"))]
        if flags:
            out["flags"] = flags
    else:
        for k in ("cpu", "disk", "net", "net_up", "net_gb", "net_up_gb"):
            x = _amt(res.get(k))
            if x is not None:
                out[k] = x
        x = _s(res.get("disk_pool")) if "disk" in out else None
        if x is not None:
            out["pool"] = x
    rsegs = {}
    for k in ("cpu", "disk", "net"):
        if k not in out:
            continue
        seq = [(sg["t"], _amt(sg["res"].get(k))) for sg in (o.get("segments") or [])
               if isinstance(sg, dict) and isinstance(sg.get("t"), (int, float)) and isinstance(sg.get("res"), dict)]
        seq = [(t, x) for t, x in seq if x is not None]
        if seq:
            rsegs[k] = seq
    if rsegs:
        out["rsegs"] = rsegs
    if not granted and o.get("ended") is None:
        got = {waited_resource(i) for i in _waiting_ids(o, (["ram"] if mem else []) +
                                                        [k for k in ("cpu", "disk") if k in out] +
                                                        (["net.down"] if holds(out, "net", band=True) else
                                                         ["net.up"] if holds(out, "net") else []))}
        w = [k for k in RESOURCES if k in got]
        if w:
            out["waiting"] = w
    return out


def _waiting_ids(o, default):
    """A queued lease's `waiting_on` (pool ids, 02 §6.4); `default` where it has none (written by older code, or not
    evaluated yet: what it asks for)."""
    w = o.get("waiting_on")
    return [x for x in w[:16] if isinstance(x, str)] if isinstance(w, list) and w else default


def waited_resource(pool_id):
    """The resource of a pool id in `waiting_on` (02 §6.4): ram and mem, and "critical" (memory is critical), are
    memory; cpu; gpu and vram; net.down, net.up and net.quota the network (NET 1.15, the Network tile's band);
    disk:<id> is disk."""
    i = str(pool_id)
    return "memory" if i in ("ram", "mem", "critical") else "cpu" if i == "cpu" else \
        "gpu" if i.startswith(("gpu", "vram")) else "net" if i.startswith("net.") else "disk"


def holds(r, k, pool=None, band=False):
    """Does reservation r hold resource k (for disk: on `pool`, when one is named)? `band`: in k's band, which for the
    network is the download's (NET 12.15): a lease with an upload part alone has a row but no block there."""
    if k == "memory":
        return r.get("mem", True)
    if k == "disk":
        return r.get("disk") is not None and (pool is None or r.get("pool") == pool)
    if k == "net":              # a rate or a volume, either way (an unmanaged part has a volume only)
        return any(r.get(f) is not None for f in (("net", "net_gb") if band else ("net", "net_up", "net_gb", "net_up_gb")))
    return r.get(k) is not None


def amount_segs(r, k):
    """r's amount of k over time: [(t, amount)], the first from its request."""
    if k == "memory":
        return r["segments"]
    return (r.get("rsegs") or {}).get(k) or [(r["requested"], r.get(k) or 0.0)]


def bands(res, shown, focus, pool=None):
    """The strip's bands (02 §3.4.5, §3.7.6; Reservation.bands): of the resources shown, those with a reservation in
    the 14 days kept (a slow fact: the strip changes height when a resource is reserved for the first time, and 14
    days after the last), the focus's first (the tall one), then the others in tile order. The Disk band is the
    tile's pool's."""
    have = [k for k in BAND_RES if k in shown and any(holds(r, k, pool, band=True) for r in res)]
    return ([focus] if focus in have else []) + [k for k in have if k != focus]


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
def columns(pts, gaps, f, finv, W, now, first=None, missing=()):
    """One entry per screen column: ('data', point) | ('gap', None) | ('miss', kind) (another
    machine's stretch not received, 01's coverage) | ('none', None) (before history). A column
    between two samples less than a gap apart repeats its nearer neighbour."""
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
        miss = [k for m0, m1, k in missing if m0 < tb and m1 > ta]
        if tb <= first:
            cols.append(("none", None))
        elif miss:
            cols.append(("miss", miss[-1]))
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
def plan(W, H, has_res=True, has_inc=True, mline=False, spark=0):
    """Where everything goes: a function of the terminal's size and of two slow facts (a reservation
    in the last 14 days; an incident on record), never of how many there are right now, so the plot
    keeps its rectangle when an agent is granted memory or an incident opens. With several machines
    (`mline`) row 1 is the machine line (04 §3.7). With the resources on, `spark` other shown resources
    get a row each under the plot, taken from it, from 30 rows of height (04 §3.14); never below."""
    sp = spark if H >= 30 else 0
    y0 = 2 if mline else 1
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
        return (H - 1 - y0 - stats) - 3 - ((1 + S + R) if (S or R) else 0) - ((1 + Inc) if Inc else 0) - sp
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
    if plot_h() < 4 and stats == 1 and mline:          # 40 x 10 with the machine line: the readings go
        stats = 0
    p = dict(W=W, H=H, wide=wide, lw=lw, stats_y=y0, stats=stats, S=S, R=R, I=Inc, mline=mline)
    y = y0 + stats
    p["box_y"] = y
    p["plot_x"], p["plot_y"], p["plot_w"], p["plot_h"] = 1, y + 1, lw - 7, plot_h()
    y += 1 + plot_h()
    p["spark_y"], p["spark_n"] = y, sp
    y += sp
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
    """(text, role): the pressure, or "No readings" while the logger says nothing; with the resources
    on, the verdict's words (capsule_rv)."""
    if model.get("rv"):
        return capsule_rv(model)
    cur = model.get("cur")
    if not cur or model.get("logger") == "silent":
        return "No readings", "faint"
    p = cur.get("pressure") or "Normal"
    return p, {"Normal": "ok", "Warning": "warn", "Critical": "crit"}.get(p, "ok")


# ------------------------------------------------------------------ four resources (M6–M8 and T4a: 02 §3.7, §3.8)
# Behind the resources switch (`"resourcesUI": true` in top.json; the app's resourcesUI): model["rv"] is then
# {"sel": [...], "focus": ...}, the resources shown and the one with the plot. The selection, the tiles' words and
# the agent's colour are the app's too, held together by tools/vectors/chart.json.
RESOURCES = ("memory", "cpu", "gpu", "disk", "net")     # tile order; the network from 1.15 (NET D-N17)
RES_WORDS = {"memory": "Memory", "cpu": "CPU", "gpu": "GPU", "disk": "Disk", "net": "Network"}
# w for the network: n is the next machine (04 §3.10; NET 12.16)
RES_KEYS = {"m": "memory", "c": "cpu", "g": "gpu", "d": "disk", "w": "net"}
# blue, teal, violet, magenta (02 §3.4); the network navy (light) and steel blue (dark), chosen with the dataviz
# validator in N4 against the four, the six agent colours, red, amber and the memory chart's grey and orange
RES_HUE = {"memory": "app", "cpu": "r0", "gpu": "r1", "disk": "r2", "net": "r7"}
AGENT_ROLES = ("g0", "g1", "g2", "g3", "g4", "g5")
AGENT_SLOTS = len(AGENT_ROLES)


def agent_index(agent):
    """Reservation.agentIndex: the palette slot a lease or record carries (02 §3.8.2), or -1 for "agent
    not known" (gray): a key of 8 hex digits and a slot 0–5, or nothing."""
    if not isinstance(agent, dict) or not isinstance(agent.get("key"), str) or len(agent["key"]) != 8 \
            or any(c not in "0123456789abcdef" for c in agent["key"]):
        return -1
    sl = agent.get("slot")
    return sl if isinstance(sl, int) and not isinstance(sl, bool) and 0 <= sl < AGENT_SLOTS else -1


def agent_role(agent):
    i = agent_index(agent)
    return AGENT_ROLES[i] if i >= 0 else "gx"


def available(s):
    """The resources a sample's machine shows tiles for: every one, except a GPU the logger looked for
    and found none of (`gpu: []`, a VM), and the network where the logger reports none (before 1.15: four tiles,
    NET 12.15). A logger older than 1.9.1 has no `cpu` or `gpu`: those tiles stay and say "–" (02 §3.7.10)."""
    net = isinstance(s, dict) and isinstance(s.get("net"), dict)
    return [r for r in RESOURCES if not (r == "gpu" and isinstance(s, dict) and s.get("gpu") == []) and
            (r != "net" or net)]


def selection_shown(sel, focus, avail):
    """(the resources drawn, in tile order; the focus) for a remembered selection: one that is not
    available is skipped, not forgotten; an unavailable focus gives way to the first shown, and an
    empty selection is Memory alone (02 §3.7.9)."""
    shown = [r for r in RESOURCES if r in sel and r in avail]
    if not shown:
        shown = ["memory"]
    return shown, focus if focus in shown else shown[0]


def selection_apply(sel, focus, gesture, res, avail):
    """Selection.apply (02 §3.7.2): a gesture on a tile. gesture: "click" (m c g d), "cmd" (M C G D, a
    ⌘-click), "shift" (a ⇧-click). Returns (selection, focus, outcome): "changed", "callout" (a click
    on the focus shown alone), "refused" (the last resource shown can't be removed) or "none". The
    focus moves only by a plain click, or to the next shown resource (wrapping) when it is removed."""
    shown, focus = selection_shown(sel, focus, avail)
    if res not in avail:
        return shown, focus, "none"
    if gesture == "click":
        if res != focus:
            return [res], res, "changed"
        return ([focus], focus, "changed") if len(shown) > 1 else (shown, focus, "callout")
    if gesture == "cmd":
        if res not in shown:
            return [r for r in RESOURCES if r in shown or r == res], focus, "changed"
        if res != focus:
            return [r for r in shown if r != res], focus, "changed"
        if len(shown) == 1:
            return shown, focus, "refused"
        i = shown.index(res)
        return [r for r in shown if r != res], shown[(i + 1) % len(shown)], "changed"
    if gesture == "shift":
        if res == focus:
            return shown, focus, "none"
        order = [r for r in RESOURCES if r in avail]
        a, b = sorted((order.index(focus), order.index(res)))
        out = [r for r in RESOURCES if r in shown or r in order[a:b + 1]]
        return out, focus, "changed" if out != shown else "none"
    return shown, focus, "none"


def _n(x):
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) else None


def fit_mid(text, n, g=None):
    """fit() that keeps the start and the end and gives way in the middle (02 §3.4.6: purposes of one project
    differ at the end, "harbor playwright…mium) shard 12"); never splits a two-cell character. Under 8 cells, or
    for a text longer than the 200 characters a purpose is cut to, it is fit()."""
    cells = cells_of(text[:400])
    if len(cells) <= n or n < 8 or len(text) > 400:
        return fit(text, n, g)
    a = n // 2
    head, tail = cells[:a], cells[len(cells) - (n - 1 - a):]
    if head and len(cells) > a and cells[a] == "":         # the cut fell inside a pair
        head[-1] = " "
    if tail and tail[0] == "":
        tail[0] = " "
    return "".join(head) + (g or GLYPHS["unicode"])["ell"][:1] + "".join(tail)


def mid_fit(text, n):
    """A name shortened in its middle to n characters, keeping its start and its end (02 §3.4.2)."""
    text = str(text)
    if len(text) <= n:
        return text
    a = (n - 1 + 1) // 2
    return text[:a] + "…" + text[len(text) - (n - 1 - a):]


def tile_pool(s):
    """The pool the Disk tile shows: the one that holds the home folder or the temp directory, else the
    first watched one, else the first; None for a sample without `disks` (the tile reads disk_free_gb)."""
    pools = [d for d in (s.get("disks") if isinstance(s.get("disks"), list) else []) if isinstance(d, dict)
             and _n(d.get("free_gb")) is not None]
    for want in (lambda d: any(r in ("home", "tmp") for r in (d.get("roles") if isinstance(d.get("roles"), list) else [])),
                 lambda d: d.get("watch") is True, lambda d: True):
        for d in pools:
            if want(d):
                return d, pools
    return None, pools


def _busiest(rows, key):
    """The biggest consumer by name: rows grouped by app (`g`, else the name), summed."""
    tot, order = {}, []
    for x in rows if isinstance(rows, list) else []:
        if isinstance(x, dict) and _n(x.get(key)) is not None:
            name = str(x.get("g") or x.get("name") or "")
            if name and name not in tot:
                order.append(name)
            tot[name] = tot.get(name, 0.0) + x[key]
    best = max(order, key=lambda k: tot[k], default=None)
    return best


def waiting_on(leases):
    """{resource: how many queued requests wait for it}, from the ledger's leases: a request without
    `waiting_on` (every writer before 1.12) waits for memory; pool ids name the others (02 §6.4)."""
    out = {}
    for r in leases if isinstance(leases, list) else []:
        if not isinstance(r, dict) or r.get("state") != "queued":
            continue
        ids = r.get("waiting_on") if isinstance(r.get("waiting_on"), list) and r.get("waiting_on") else ["ram"]
        got = {waited_resource(i) for i in ids}     # "critical" (memory is critical) is memory's
        for k in got:
            out[k] = out.get(k, 0) + 1
    return out


def tiles(s, cap, waiting=None, recent=None, hint=False):
    """Tile.facts (02 §3.4.1): what each tile says for a sample. `cap`: oomph.capsule of it (the
    memory and disk levels); `waiting`: waiting_on of the ledger; `recent` and `hint`: the network's (net_tile).
    {resource: {"reading", "short" (where five tiles leave too little room, NET 12.15), "flag" (the one
    flag slot: "critical", "tight", "low", "+1 critical", "+1 low", "throttled", "busy", the network's metered
    words, or None), "level" (2 red, 1 amber, 0 quiet), "queue" (requests waiting for it), "top" (the biggest
    consumer), "note" (the network's line 4 in place of it), "meter" (0…1, a tank for Disk), "full" (the GPU figure
    is at full speed)}}. The word "waiting" is the renderer's: a queue shows as "n waiting" alone, or after a flag
    of rank 1 to 6."""
    waiting = waiting or {}
    out = {}
    ram = _n(s.get("ram_gb")) or 0.0
    used = sum(_n(s.get(k)) or 0.0 for k in ("app_gb", "wired_gb", "compressed_gb"))
    lv = cap.get("memory", 0)
    groups = s.get("groups") if isinstance(s.get("groups"), list) else []
    out["memory"] = {"reading": "%.1f / %.0f GB" % (used, ram), "short": "%.1f/%.0f GB" % (used, ram),
                     "meter": used / ram if ram else 0.0,
                     "flag": "critical" if lv == 2 else "tight" if lv == 1 else None, "level": lv,
                     "top": next((str(x.get("name")) for x in groups if isinstance(x, dict) and x.get("name")), None)}
    c = s.get("cpu") if isinstance(s.get("cpu"), dict) else {}
    n, busy = _n(c.get("n")), _n(c.get("busy"))
    flag = "throttled" if (_n(c.get("therm")) or 0) >= 2 else "busy" if n and busy is not None and busy >= 0.9 * n \
        else None
    out["cpu"] = {"reading": "%.1f / %d cores" % (busy, n) if n and busy is not None else "–",
                  "short": "%.1f/%d" % (busy, n) if n and busy is not None else None,
                  "meter": busy / n if n and busy is not None else 0.0, "flag": flag, "level": 0,
                  "top": _busiest(s.get("top_cpu"), "cpu")}
    gl = s.get("gpu") if isinstance(s.get("gpu"), list) else []
    g = gl[0] if gl and isinstance(gl[0], dict) else {}
    util, mem, full = _n(g.get("util")), _n(g.get("mem_gb")), g.get("src") == "ioreport"
    reading = "–"
    if util is not None:
        reading = "%.0f %%%s" % (util, "" if full else " busy") + (" · %.1f GB" % mem if mem is not None else "")
    out["gpu"] = {"reading": reading, "short": "%.0f %%" % util if util is not None else None,
                  "meter": util / 100.0 if util is not None else 0.0, "full": full,
                  "flag": "busy" if full and util is not None and util >= 90 else None, "level": 0,
                  "top": _busiest(s.get("top_gpu"), "gpu")}
    d, pools = tile_pool(s)
    free = _n(d.get("free_gb")) if d else _n(s.get("disk_free_gb"))
    dl = cap.get("disk", 0)
    flag = "critical" if dl == 2 else "low" if dl == 1 else None
    if flag is None:
        others = [p.get("level") for p in pools if p is not d and p.get("watch") is True]
        k = sum(1 for x in others if x == "critical")
        if k:
            flag, dl = "+%d critical" % k, 2
        elif any(x == "low" for x in others):
            flag, dl = "+%d low" % sum(1 for x in others if x == "low"), 1
    reading = "–" if free is None else "%.0f GB free" % free
    if d is not None and len(pools) > 1:
        reading += " · " + mid_fit(d.get("name") or d.get("id") or "?", 12)
    total = _n(d.get("total_gb")) if d else None
    out["disk"] = {"reading": reading, "short": "–" if free is None else "%.0f GB" % free,
                   "meter": min(1.0, free / total) if free is not None and total else 0.0,
                   "flag": flag, "level": dl, "top": _busiest(s.get("top_io"), "w")}
    out["net"] = net_tile(s, recent, hint)
    for r in RESOURCES:
        out[r]["queue"] = int(waiting.get(r, 0))
    return out


def flag_text(t, g=None, short=False):
    """The flag slot's words (02 §3.4.1): a flag of rank 1 to 6 keeps the queue after it ("critical ◻2");
    a queue alone is "n waiting" (it outranks busy), or `short` "◻n" where a tile is narrow, where the network's
    metered words also drop "metered · " (NET 12.15)."""
    box = (g or GLYPHS["unicode"]).get("queue", "◻")
    f, q = t.get("flag"), t.get("queue") or 0
    if short and f and f.startswith("metered · "):
        f = f[len("metered · "):]
    if q and (f is None or f == "busy"):
        return "%s%d" % (box, q) if short else "%d waiting" % q
    if f and q:
        return "%s %s%d" % (f, box, q)
    return f or ""


# ------------------------------------------------------------------ the network (NET N4, 1.15: 12.15, 12.16)
NET_STALE_X = 1.1       # this machine alone above its line's figure by this much: the figure is stale (oomph_traffic)
NET_QUOTA_X = 0.1       # under this share of a metered cap left the network warns (oomph_traffic.QUOTA_X)


def mbps(x):
    """Mbit/s as the tiles say them (oomph_traffic._mb): 212, 41, 8.1, 0.4."""
    return "%.0f" % x if x >= 10 else "%.1f" % x


def _fig(x, lo, hi):
    x = _n(x)
    return x if x is not None and lo <= x <= hi else None


def net_rate(nb, k):
    """A net block's rate `k` (down_mbps, up_mbps): a finite Mbit/s 0 … 1e6 or None (another logger's figures)."""
    return _fig(nb.get(k), 0, 1e6) if isinstance(nb, dict) else None


def net_pools(s):
    """(down, up, quota): what a sample's pools say about its network (current.json; a mirror's from 1.15), each a
    dict of checked numbers or None. down and up exist while the line has a figure (D-N3): {"cap", "margin",
    "reserved", "busy" (its level is busy)}; quota while the network is metered: {"cap", "used"} in GB."""
    pools = s.get("pools") if isinstance(s, dict) and isinstance(s.get("pools"), dict) else {}
    out = []
    for k in ("net.down", "net.up"):
        P = pools.get(k) if isinstance(pools.get(k), dict) else {}
        cap = _fig(P.get("cap"), 0.5, 1e5)
        out.append(None if cap is None else {"cap": cap, "margin": _fig(P.get("margin"), 0, cap) or 0.0,
                                             "reserved": _fig(P.get("reserved"), 0, 1e6) or 0.0,
                                             "busy": P.get("level") == "busy"})
    q = pools.get("net.quota") if isinstance(pools.get("net.quota"), dict) else {}
    cap, used = _fig(q.get("cap"), 0.1, 1e5), _fig(q.get("used"), 0, 1e6)
    out.append({"cap": cap, "used": used} if cap is not None and used is not None else None)
    return tuple(out)


def net_stale(down, up, recent):
    """The stale-figure hint (D-N8, 12.8; oomph_traffic.stale): (direction, seen, figure) when the mean of the last three
    samples is above NET_STALE_X × the line's figure, else None. `recent`: [(down_mbps, up_mbps, flows, key)] oldest
    first; all three must have told the LAN from the internet (`flows`): a total alone holds the LAN's traffic too; and
    all three must be on one network (`key`, net_key; a bucket over a change is NET_MIXED): after a move from a fast
    line to a slower one the fast line's samples say nothing about the slow one's figure (oomph_traffic.stale). A
    remote tab's samples name no network (its key stays home, oomph.FULL_BLOCKS): there every mark is 0, and for three
    samples after a move the hint may still read the network before."""
    rows = list(recent or [])[-3:]
    if len(rows) < 3 or not all(r[2] is True for r in rows):
        return None
    keys = {r[3] if len(r) > 3 else 0 for r in rows}
    if len(keys) > 1 or NET_MIXED in keys:
        return None
    for i, P in ((0, down), (1, up)):
        v = [r[i] for r in rows if _fig(r[i], 0, 1e6) is not None]
        if P and len(v) == 3 and sum(v) / 3 > NET_STALE_X * P["cap"]:
            return ("down" if i == 0 else "up", round(sum(v) / 3, 1), P["cap"])
    return None


def net_names_top(rows):
    """The busiest name of net_names (by down + up; a tie keeps the earlier row)."""
    best, most = None, -1.0
    for x in rows if isinstance(rows, list) else []:
        if not isinstance(x, dict) or not isinstance(x.get("name"), str) or not x["name"]:
            continue
        v = (_fig(x.get("down"), 0, 1e6) or 0.0) + (_fig(x.get("up"), 0, 1e6) or 0.0)
        if v > most:
            best, most = x["name"][:200], v
    return best


def _q(x):
    return "%.0f" % x if x >= 10 else "%.1f" % x


def net_tile(s, recent=None, hint=False):
    """The Network tile (12.15): ↓ and ↑ now in Mbit/s (the unit is the tooltip's and the legend's), "offline" without
    an interface; the meter the download against the line's figure (no fill without one); the flag slot "metered ·
    12/20 GB", "1.8 GB left" (amber, under 10 % of the cap), "busy" (the logger's level); line 4 (`note`, in place of
    the busiest name): the stale hint "seen 940 > 500", "metered?" (`hint`: the app's, from the system), or "line not
    tested". `recent`: as net_stale."""
    nb = s.get("net") if isinstance(s, dict) and isinstance(s.get("net"), dict) else None
    down, up, quota = net_pools(s)
    d, u = net_rate(nb, "down_mbps"), net_rate(nb, "up_mbps")
    if nb is None:
        reading = "–"
    elif not (isinstance(nb.get("if"), str) and nb["if"]):
        reading = "offline"
    else:
        reading = "↓%s ↑%s" % ("–" if d is None else mbps(d), "–" if u is None else mbps(u))
    t = {"reading": reading, "short": reading, "meter": min(1.0, d / down["cap"]) if down and d is not None else 0.0,
         "flag": None, "level": 0, "top": net_names_top(s.get("net_names")) if isinstance(s, dict) else None,
         "note": None, "full": False}
    if quota:
        left = quota["cap"] - quota["used"]
        if left < NET_QUOTA_X * quota["cap"]:
            t["flag"], t["level"] = "%.1f GB left" % max(0.0, left), 1
        else:
            t["flag"] = "metered · %s/%s GB" % (_q(quota["used"]), _q(quota["cap"]))
    elif (down and down["busy"]) or (up and up["busy"]):
        t["flag"] = "busy"
    st = net_stale(down, up, recent)
    if st:
        t["note"] = "seen %s%s > %s" % ("" if st[0] == "down" else "↑", mbps(st[1]), mbps(st[2]))
    elif hint and not quota:
        t["note"] = "metered?"
    elif nb is not None and isinstance(nb.get("if"), str) and nb["if"] and not down and not up:
        t["note"] = "line not tested"
    return t


def net_scale(top):
    """The network chart's scale (12.15): 0 to the first 1, 2, 5 × 10ⁿ Mbit/s at or above `top`, at least 1."""
    top = max(_n(top) or 0.0, 1.0)
    e = 10 ** math.floor(math.log10(top))
    return next(m * e for m in (1, 2, 5, 10) if m * e >= top - 1e-9)


def capsule_rv(model):
    """(text, role) of the capsule with the resources on: oomph's verdict in two words (02 §3.4.9,
    §15.13: "Memory tight", "Disk critical"), "No readings" while the logger says nothing."""
    cap = model.get("capsule")
    if not model.get("cur") or model.get("logger") == "silent" or not cap:
        return "No readings", "faint"
    return cap["text"], ("ok", "warn", "crit")[max(0, min(2, cap.get("level", 0)))]


def tab_bar(fr, model, caps, g):
    """Row 0 for one machine: the name, this machine's host name, free memory, the capsule, the clock.
    What gives way when columns are short: the name, then the clock, then the free memory. A long
    host name is cut first, to no less than 12 cells, so it never pushes the others out of a wide row."""
    W, mono = fr.w, caps.color == "none"
    fr.fill(0, 0, W, 1, " ", None, "bar")
    cap_text, cap_role = capsule(model)
    cap_w = len(cap_text) + 2
    cur = model.get("cur")
    free = "%.1fG %s" % (cur["free"], free_word(cur)) if cur and model.get("logger") != "silent" else None
    host = model.get("host") or "this Mac"
    room = W - 1 - 1 - cap_w - 1 - 3
    rest = (len(model.get("brand") or "") + 1) + 6 + (len(free) + 2 if free else 0)
    label = fit(host, max(4, min(room, max(12, room - rest))), g)
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


# ------------------------------------------------------------------ machines (04 §3.7: 01 revision 3, in cells)
# A tab (model["tabs"], built by oomph_top from machines.json and each mirror's files): mid ("local" for this
# machine), local, label, addr, transport, status (the mirror's status.json), pid_alive (its engine exists),
# cur (pressure, t, silent, incident, free of its current.json), known (where its coverage ends, the machine's
# clock), synced (sync.json's), opened (when this run opened it, and whether its link was live then), version,
# system. model["wall"] is this computer's clock (status.json's times are), model["now"] the selected machine's.
BRAND = None                # oomph.BRAND, set by oomph_top (this module reads no settings of its own)
MAX_TABS = 12               # other machines as tabs, after this one (01's limit, the engine's MAX_MACHINES)
MARK_ROLE = {"ok": "ok", "warn": "warn", "crit": "crit", "silent": "faint", "busy": "accent", "off": "faint",
             "att": "warntx"}
ATTENTION_WORDS = {"identity_changed": ("Key changed", "Its key changed"), "revoked": ("Access revoked", "Access revoked"),
                   "incompatible": ("Too old", "Its version can't talk to this one"),
                   "ssh": ("SSH can't sign in", "SSH can't sign in"),
                   "refused": ("Sharing is off there", None), "turned_away": ("Sharing is off there", None)}
MISSING_WORDS = {"not_connected": "not connected", "not_received": "not received", "gone": "no longer available",
                 "fetching": "fetching history"}
LIVE_FRESH_S = 10.0         # a status.json older than this is not live, whatever it says (01 §4.4)


def _f(x):
    """A finite number or None (an int too big for a float is none)."""
    if isinstance(x, bool) or not isinstance(x, (int, float)):
        return None
    try:
        return x if math.isfinite(x) else None
    except OverflowError:
        return None


def _t(x):
    """A moment from a file (status.json, a mirror) or None: oomph's range, so that localtime can tell it."""
    x = _f(x)
    return x if x is not None and 0 <= x <= 1e11 else None


def when(t, now):
    """A moment in the words of the machine line: 10:15, yesterday 18:40, Mon 9 Nov 17:02."""
    a, b = _lt(t), _lt(now)
    if a[:3] == b[:3]:
        return hhmm(t)
    if _lt(now - 86400)[:3] == a[:3]:
        return "yesterday " + hhmm(t)
    return "%s %d %s %s" % (DAYS[a.tm_wday], a.tm_mday, MONTHS[a.tm_mon - 1], hhmm(t))


MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def link_view(t, wall, engine="on"):
    """One tab's link as 04 §3.7's tables tell it (01 §3.2–§3.6). A dict: live (what claims to be
    now is now), stale (it is greyed), phase (the opening: grace, connecting or None), mark (a key
    of the glyphs' marks), dim (the last mark, during a grace), badge (an incident open there, the
    link up), capsule (text, role), cause (the table's row), retry (r can help), attention (enter
    explains). Pure: `wall` is this computer's clock, `engine` "on", or why nobody syncs."""
    cur = t.get("cur") or None
    p = (cur or {}).get("pressure") or "Normal"
    pmark = {"Warning": "warn", "Critical": "crit"}.get(p, "ok")
    pcap = (p, {"Warning": "warn", "Critical": "crit"}.get(p, "ok"))
    silent = cur is None or bool(cur.get("silent"))
    v = dict(live=False, stale=True, phase=None, mark="off", dim=False, badge=False, retry=False, attention=False,
             capsule=("Not connected", "faint"), cause="offline")
    if t.get("local"):
        v.update(live=True, stale=False, mark="silent" if silent else pmark, badge=bool(cur and cur.get("incident")),
                 capsule=("No readings", "faint") if silent else pcap, cause="local")
        return v
    st = t.get("status") if isinstance(t.get("status"), dict) else {}
    state, err = (x if isinstance(x, str) else None for x in (st.get("state"), st.get("error")))
    upd = _t(st.get("updated"))
    if state in ("live", "catching_up") and upd is not None and wall - upd < LIVE_FRESH_S and t.get("pid_alive"):
        v.update(live=True, stale=False, badge=bool(cur and cur.get("incident")))
        if state == "catching_up":
            v.update(mark="busy", capsule=pcap, cause="catching_up")
        elif silent:
            v.update(mark="silent", capsule=("No readings", "faint"), cause="silent")
        else:
            v.update(mark=pmark, capsule=pcap, cause="live")
        return v
    if engine != "on":
        v.update(capsule=("Not syncing", "faint"), cause="not_syncing")
        return v
    if state == "needs_attention" or (state == "offline" and err in ("refused", "turned_away")):
        v.update(mark="att", capsule=(ATTENTION_WORDS.get(err, ("Needs attention",))[0], "warntx"),
                 cause=err if err in ATTENTION_WORDS else "attention", attention=True,
                 retry=err in ("ssh", "refused", "turned_away"))
        return v
    if state == "offline" and err == "local_network_denied":
        v.update(capsule=("Blocked by macOS", "faint"), cause="blocked", attention=True, retry=True)
        return v
    if state == "pairing":
        v.update(mark="busy", capsule=("Pairing…", "faint"), cause="pairing")
        return v
    at, was_live = t.get("opened") or (None, False)
    if was_live and at is not None and state != "offline":
        ssh = (st.get("transport") or t.get("transport")) == "ssh"
        lo, hi = (1.5, 6.0) if ssh else (0.8, 3.0)
        age = wall - at
        if age < min(hi, max(lo, 2 * (_f(st.get("connect_ms")) or 0) / 1000.0)):
            v.update(phase="grace", stale=False, dim=True, mark="silent" if silent else pmark,
                     capsule=("No readings", "faint") if silent else pcap, cause="grace")
            return v
        if age < (20.0 if ssh else 8.0):
            v.update(phase="connecting", mark="busy", capsule=("Connecting…", "faint"), cause="connecting")
            return v
    if state == "connecting":
        v.update(mark="busy", capsule=("Connecting…", "faint"), cause="connecting")
        return v
    v["retry"] = True               # offline (no answer, not found, not oomph, busy), or idle: not connected
    return v


def machine_sentence(t, v, model):
    """The machine line's sentence (01 §3.5's words, 04 §3.7's table)."""
    now, wall = model["now"], model.get("wall", model["now"])
    st = t.get("status") if isinstance(t.get("status"), dict) else {}
    cur = t.get("cur") or {}
    last = "last data " + (when(t["known"], now) if _t(t.get("known")) else "never")
    c = v["cause"]
    if c == "local":
        lg = model.get("logger") if model.get("tab_mid", "local") == "local" else None
        words = ("Logging every %d s" % (cur.get("interval") or 30)) if not cur.get("silent") else \
            "Logger not reporting since %s" % hhmm(cur["t"]) if _t(cur.get("t")) else "Logging is off"
        if lg == "off":
            words = "Logging is off"
        return "this machine %s %s" % (MIDDOT, words)
    if c in ("live", "grace"):
        s = "Logging every %d s" % (cur.get("interval") or 30)
        off = _f((t.get("sync") or {}).get("offset_s"))
        if off is not None and abs(off) > 30:
            s += " %s clock %s %s" % (MIDDOT, ago(abs(off)), "ahead" if off > 0 else "behind")
        return s
    if c == "catching_up":
        synced = (t.get("sync") or {}).get("synced")
        if isinstance(synced, dict) and not all(synced.get(k) for k in ("ledger", "incidents")):
            return "Fetching history…"
        return "Catching up: fetching missed history…"
    if c == "silent":
        return "Connected, but its logger stopped at %s" % (when(cur["t"], now) if _t(cur.get("t")) else "?")
    if c == "pairing":
        return "Pairing…"
    if c == "connecting":
        s = last[0].upper() + last[1:]
    elif c == "not_syncing":
        s = "Not syncing (%s) %s %s" % ("running as root" if model.get("engine") == "root" else "--no-connect", MIDDOT, last)
    elif c == "blocked":
        s = last[0].upper() + last[1:]
    elif v["attention"] and ATTENTION_WORDS.get(c, (None, None))[1]:
        s = "%s %s %s" % (ATTENTION_WORDS[c][1], MIDDOT, last)
    elif v["attention"]:
        s = last[0].upper() + last[1:]
    else:
        lc = _t(st.get("last_contact")) or _t(t.get("known"))
        s = "No answer since %s" % when(lc, wall) if lc else "No answer yet"
        nt = _t(st.get("next_try"))
        if st.get("state") == "offline" and nt is not None and nt - wall >= 0.5:
            s += " %s next try in %d s" % (MIDDOT, round(nt - wall))
    p = cur.get("pressure")
    if p in ("Warning", "Critical"):
        s += " %s pressure was %s" % (MIDDOT, p.lower())
    return s


MIDDOT = "·"
ASCII_WORDS = {ord("·"): "-", ord("…"): "~", ord("“"): '"', ord("”"): '"', ord("›"): ">", ord("‹"): "<", ord("–"): "-",
               ord("×"): "x", ord("↓"): "v", ord("↑"): "^", ord("▲"): "^", ord("≈"): "~"}   # ↓ ↑: the network (12.16)


def asc(text, fr):
    """The machines' words in the ASCII glyph set: their punctuation as the glyph set has it."""
    return text.translate(ASCII_WORDS) if fr.ascii_only and isinstance(text, str) else text


def state_words(t, v):
    """The machine list's last column: the state in words."""
    c = v["cause"]
    if c == "local" and v["mark"] == "silent":
        return "no readings"
    if c in ("live", "grace", "local"):
        p = (t.get("cur") or {}).get("pressure")
        w = "memory %s" % p.lower() if p in ("Warning", "Critical") else "connected"
        return w + (" %s incident" % MIDDOT if v["badge"] else "")
    return {"silent": "connected, no readings", "catching_up": "catching up", "connecting": "connecting",
            "pairing": "pairing", "not_syncing": "not syncing", "blocked": "blocked by macOS",
            "refused": "sharing is off there", "turned_away": "sharing is off there"}.get(c) or \
        ("needs attention: %s" % ATTENTION_WORDS[c][0].lower() if c in ATTENTION_WORDS else
         "needs attention" if v["attention"] else "not connected")


def tab_views(model):
    """link_view of every tab, once per frame."""
    if "views" not in model:
        model["views"] = [link_view(t, model.get("wall", model["now"]), model.get("engine", "on"))
                          for t in model["tabs"]]
    return model["views"]


def several(model):
    return len(model.get("tabs") or ()) > 1


def _urgent(hidden, g):
    """What a counter shows of the machines it hides, in the order of the app's » (01 §3.2)."""
    if any(v["mark"] == "att" for v in hidden):
        return g["marks"]["att"], "warntx"
    if any(v["badge"] or (v["live"] and v["mark"] == "crit") for v in hidden):
        return "!", "crit"
    if any(v["mark"] == "off" for v in hidden):
        return g["marks"]["off"], "faint"
    return "", None


def tab_plan(model, W, g):
    """The tab bar's ladder (04 §3.7, "When columns are short"): which tabs show how, and what of the
    name, the clock and the free memory fits. Returns (items, extras): items are ("tab", i, label
    width or None for number and mark) and ("more", side, count, glyph, role); extras a subset of
    {"free", "clock", "brand"}. The selected tab with its label and ×, the + and the capsule are
    always there, down to 40 columns."""
    tabs, sel = model["tabs"], model.get("sel", 0)
    views = tab_views(model)
    n = len(tabs)
    plus_w = 3
    cap_w = len(views[sel]["capsule"][0]) + 2 if not tabs[sel].get("local") else len(capsule(model)[0]) + 2
    fixed = 1 + plus_w + 2 + cap_w + 1

    def tab_w(i, lw):
        t, v = tabs[i], views[i]
        num = len(str(i + 1))
        badge = 1 if v["badge"] and i != sel else 0
        close = 2 if i == sel and not t.get("local") else 0
        if lw is None:
            return num + 1 + badge
        return num + 1 + tw(fit(t.get("label") or "?", lw, g)) + (2 + badge if n > 1 else 0) + close

    def width(items):
        w = 0
        for it in items:
            if it[0] == "tab":
                w += tab_w(it[1], it[2])
            else:
                w += 2 + len(str(it[2])) + len(it[3])
        return w + 2 * (len(items) - 1)
    chosen = None
    for lw in (16, 6, 5, 4):
        items = [("tab", i, lw) for i in range(n)]
        if fixed + width(items) <= W:
            chosen = items
            break
    if chosen is None:
        for lw in (6, 5, 4):
            items = [("tab", i, lw if i == sel else None) for i in range(n)]
            if fixed + width(items) <= W:
                chosen = items
                break
    if chosen is None:
        for slw in (6, 5, 4, 3, 2):
            lo = hi = sel
            while True:
                grew = False
                for side in ("r", "l"):
                    a, b = (lo, hi + 1) if side == "r" else (lo - 1, hi)
                    if a < 0 or b >= n:
                        continue
                    if fixed + width(_window(views, a, b, sel, slw, n, g)) <= W:
                        lo, hi, grew = a, b, True
                if not grew:
                    break
            items = _window(views, lo, hi, sel, slw, n, g)
            if fixed + width(items) <= W or slw == 2:
                chosen = items
                break
    room = W - fixed - width(chosen)
    extras = set()
    cur = model.get("cur")
    free = "%.1fG %s" % (cur["free"], free_word(cur)) if cur and model.get("logger") != "silent" and not model.get("stale") else None
    for name, need in (("free", len(free) + 2 if free else None), ("clock", 6), ("brand", len(model.get("brand") or "") + 2)):
        if need is not None and need <= room and (name != "brand" or model.get("brand")):
            extras.add(name)
            room -= need
    return chosen, extras, free


def _window(views, lo, hi, sel, slw, n, g):
    items = []
    if lo > 0:
        items.append(("more", "l", lo) + _urgent(views[:lo], g))
    items += [("tab", i, slw if i == sel else None) for i in range(lo, hi + 1)]
    if hi < n - 1:
        items.append(("more", "r", n - 1 - hi) + _urgent(views[hi + 1:], g))
    return items


def draw_capsule(fr, xr, text, role, caps, dim=False):
    """The capsule at row 0, right-aligned at xr; returns the column left of it."""
    if caps.color == "none":
        fr.rput(xr, 0, "[" + text + "]", "fg", "bar", BOLD)
    elif caps.color == "16" and role == "faint":        # no grey among the eight base colours: brackets
        fr.rput(xr, 0, "[" + text + "]", "dim", "bar", BOLD)
    elif role == "faint":                               # a grey fill, the words in the primary colour
        fr.rput(xr, 0, " " + text + " ", "selfg", "sel", BOLD)
    else:
        fr.rput(xr, 0, " " + text + " ", "onblock", role, BOLD)
    if dim:
        fr.restyle(xr - tw(text) - 1, 0, tw(text) + 2, 1, "off")
    return xr - tw(text) - 2


def machine_tabs(fr, model, caps, g):
    """Row 0 with machines (04 §3.7): the name, a tab per machine (number, label, mark, badge; the
    selected one bold on the selection colour, with × on another machine's), the +, the selected
    machine's capsule, the clock."""
    W, mono = fr.w, caps.color == "none"
    tabs, sel = model["tabs"], model.get("sel", 0)
    views = tab_views(model)
    fr.fill(0, 0, W, 1, " ", None, "bar")
    items, extras, free = tab_plan(model, W, g)
    x = 1
    if "brand" in extras:
        x = fr.put(x, 0, model["brand"], "fg", "bar", BOLD) + 2
    hits = []
    for k, it in enumerate(items):
        if k:
            x += 2
        if it[0] == "more":
            _, side, count, glyph, role = it
            x0 = x
            if side == "l":
                x = fr.put(x, 0, "%s+%d" % (g["more_l"], count), "dim", "bar")
                x = fr.put(x, 0, glyph, None if mono else role, "bar", BOLD)
            else:
                x = fr.put(x, 0, glyph, None if mono else role, "bar", BOLD)
                x = fr.put(x, 0, "+%d%s" % (count, g["more_r"]), "dim", "bar")
            hits.append((x0, x, "more", side))
            continue
        i, lw = it[1], it[2]
        t, v = tabs[i], views[i]
        on = i == sel
        bg, fl = ("sel", BOLD | (REV if mono else 0)) if on else ("bar", 0)
        quiet = not on and not v["live"] and v["phase"] != "grace"
        red = not on and v["live"] and v["mark"] == "crit"
        name_role = "selfg" if on else "crit" if red else "dim" if quiet else "fg"
        x0 = x
        x = fr.put(x, 0, str(i + 1), name_role, bg, fl | (BOLD if red else 0))
        if lw is not None:
            x = fr.put(x + 1, 0, fit(t.get("label") or "?", lw, g), name_role, bg, fl | (BOLD if red else 0))
        if len(tabs) == 1:              # one machine: its name and the +; the capsule tells its pressure
            hits.append((x0, x, "tab", i))
            continue
        if lw is not None:
            if on:
                fr.put(x, 0, " ", None, bg)
            x += 1
        mark = g["marks"][v["mark"]]
        x = fr.put(x, 0, mark, None if mono else MARK_ROLE[v["mark"]], bg, (fl if on else 0) | (DIM if v["dim"] else 0))
        if v["badge"] and not on:
            x = fr.put(x, 0, "!", None if mono else "crit", bg, BOLD)
        if on and not t.get("local"):
            fr.put(x, 0, " ", None, bg)
            x = fr.put(x + 1, 0, g["close"], "selfg", bg, fl)
        hits.append((x0, x, "tab", i))
    x += 2
    hits.append((x, x + 1, "plus", None))
    fr.put(x, 0, "+", "fg", "bar", BOLD)
    xr = W - 2
    if "clock" in extras:
        clock = hhmm(model.get("wall", model["now"]))
        fr.rput(xr, 0, clock, "dim", "bar")
        xr -= len(clock) + 1
    v = views[sel]
    text, role = capsule(model) if tabs[sel].get("local") else v["capsule"]
    xr = draw_capsule(fr, xr, asc(text, fr), role, caps, v["dim"]) - 1
    if "free" in extras:
        fr.rput(xr, 0, free, "dim", "bar")
    fr.tab_hits = hits


def machine_line(fr, y, model, caps, g):
    """Row 1 with several machines: the selected one's mark, name and sentence; at the right its
    oomph and system ("oomph 1.10.0 · macOS 27.2"), the system giving way first, then all of it,
    never the sentence."""
    W, mono = fr.w, caps.color == "none"
    t = model["tabs"][model.get("sel", 0)]
    v = tab_views(model)[model.get("sel", 0)]
    sentence = asc(machine_sentence(t, v, model), fr)
    x = fr.put(1, y, g["marks"][v["mark"]], None if mono else MARK_ROLE[v["mark"]], None, DIM if v["dim"] else 0)
    x = fr.put(x + 1, y, fit(t.get("label") or "?", 24, g), "fg", None, BOLD)
    left = "%s %s" % (g["mid"], sentence)
    right_parts = [p for p in ("%s %s" % (model.get("brand") or "", t["version"]) if t.get("version") else None,
                               t.get("system")) if p]
    for k in (len(right_parts), 1, 0):
        right = (" %s " % g["mid"]).join(right_parts[:k])
        if not right or x + 1 + tw(left) + 2 + tw(right) <= W - 1:
            break
    else:
        right = ""
    fr.put(x + 1, y, fit(left, max(0, W - x - 2 - (tw(right) + 2 if right else 0)), g), "dim")
    if right:
        fr.rput(W - 2, y, right, "faint")


def mirror_gaps(no_data, have, gone, oldest, now, down):
    """MachineStore.mirrorGaps (01 §3.5, §5.7): (the no-data stretches inside the coverage map,
    the stretches not received with their kind). Outside the map, from the remote's oldest sample
    (or the first covered moment) to now, a stretch the remote no longer keeps is `gone`, the one
    that reaches now while the link is down `not_connected`, every other `not_received`. While the
    link is up the youngest stretch counts only once it is longer than a chart's gap. Every list is
    sorted and merged first and then walked once (sync.json may hold a megabyte of spans)."""
    no_data, have, gone = _merged(no_data), _merged(have), _merged(gone)
    nd, i, j = [], 0, 0
    while i < len(no_data) and j < len(have):
        a, b = max(no_data[i][0], have[j][0]), min(no_data[i][1], have[j][1])
        if b > a:
            nd.append((a, b))
        if no_data[i][1] < have[j][1]:
            i += 1
        else:
            j += 1
    if not have:
        return nd, [(oldest if oldest is not None else now - KEEP_DAYS * 86400, now,
                     "not_connected" if down else "not_received")]
    first = min(have[0][0], gone[0][0] if gone else have[0][0], oldest if oldest is not None else have[0][0])
    at, holes, out = first, [], []
    for a, b in have:
        if a > at:
            holes.append((at, a))
        at = max(at, b)
    if now - at > (0 if down else GAP_S):
        holes.append((at, now))
    k = 0
    for a, b in holes:
        x = a
        while k < len(gone) and gone[k][1] <= x:
            k += 1
        while k < len(gone) and gone[k][0] < b:
            ga, gb = gone[k]
            if ga > x:
                out.append((x, ga, "not_received"))
            out.append((max(ga, x), min(gb, b), "gone"))
            x = min(gb, b)
            if gb > b:              # it reaches into the next hole
                break
            k += 1
        if b > x:
            out.append((x, b, "not_connected" if down and b >= now - 1 else "not_received"))
    return nd, out


def _merged(spans):
    """Spans sorted by start, overlapping and touching ones joined."""
    out = []
    for a, b in sorted(spans):
        if out and a <= out[-1][1]:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def draw_stats(fr, x, y, w, model, g, rows=2):
    """The live readings. Two rows: value over label; tiles that do not fit are dropped, least
    important first. One row: a sentence, whole items dropped, never a label cut in half. A Linux
    machine's in its own words (linux_tiles)."""
    c = model.get("cur")
    if not c:
        fr.put(x, y, "No readings yet", "dim")
        return
    idle = c.get("idle")
    idle_s = g["dash"] if idle is None else "%d min" % (idle // 60) if idle >= 120 else "%d s" % idle  # None: not known
    lin = c.get("linux")
    if rows == 1:
        items = [(v, lab, "fg") for v, lab in (
            ("%.1fG" % c["app"], "App"), ("%.1fG" % c["comp"], "Compressed"), ("%.1fG" % c["wired"], "Wired"),
            ("%.0fG" % c["ram"], "RAM"), ("%.1f/%.0fG" % (c["swap"], c["swap_total"]), "swap"),
            ("%.0fG" % c["disk"], "disk free"), (idle_s, "idle"))] if lin is None else \
            [(v.replace(" GB", "G").replace(" / ", "/"), short, role) for v, _, short, _, _, role in linux_tiles(c, g)[:7]]
        sep = " %s " % g["mid"]
        while items and sum(tw(v) + 1 + len(lab) for v, lab, _ in items) + len(sep) * (len(items) - 1) > w:
            items.pop()
        for i, (v, lab, role) in enumerate(items):
            if i:
                x = fr.put(x, y, sep, "faint")
            x = fr.put(x, y, v, role, KEEP, BOLD)
            x = fr.put(x + 1, y, lab, "dim")
        return
    # (value, label, width, priority: the highest number gives way first, role of the value)
    if lin is not None:
        tiles = [(v, lab, wd, pr, role) for v, lab, _, wd, pr, role in linux_tiles(c, g)]
    else:
        tiles = [(v, lab, wd, pr, "fg") for v, lab, wd, pr in (
            ("%.1f GB" % c["app"], "App memory", 12, 0), ("%.1f GB" % c["comp"], "Compressed", 12, 1),
            ("%.1f GB" % c["wired"], "Wired", 9, 2), ("%.0f GB" % c["ram"], "RAM total", 11, 4),
            ("%.1f / %.0f GB" % (c["swap"], c["swap_total"]), "Swap / size", 13, 3),
            ("%.0f GB" % c["disk"], "Free disk", 11, 5), (idle_s, "Idle", 7, 6))]
        if c.get("groups"):
            name, gb, _ = c["groups"][0]
            tiles.append(("%.1f GB" % gb, "#1 " + name, 18, 7, "fg"))
    while sum(t[2] for t in tiles) > w:
        tiles.remove(max(tiles, key=lambda t: t[3]))
    pad = min(6, max(0, (w - sum(t[2] for t in tiles)) // max(len(tiles) - 1, 1)))
    for val, lab, twid, _, role in tiles:
        fr.put(x, y, fit(val, twid + pad - 1, g) if lin is not None else val, role, KEEP, BOLD)
        fr.put(x, y + 1, fit(lab, twid + pad - 1, g), "dim")
        x += twid + pad


def free_word(cur):
    """What the header calls the memory left: "free" on a Mac, "avail" on Linux (03 §5.2: MemAvailable)."""
    return "avail" if (cur or {}).get("linux") is not None else "free"


def stall_pct(x):
    """A stall figure as the app's LinuxTab.pct writes it: one decimal under 10 %, whole numbers above."""
    return "%.1f %%" % x if x < 9.95 else "%.0f %%" % x


def linux_group(name):
    """A Linux group's name as a tile shows it (03 §3.9 state 7, LinuxTab.groupName): a container's program
    first and its runtime after it ("nginx · docker"), cut in the middle beyond 22 characters."""
    m = re.match(r"^(docker|podman|pod):[^ ]+ \((.+)\)$", name)
    return mid_fit("%s · %s" % (m.group(2), m.group(1)) if m else name, 22)


def linux_tiles(c, g):
    """A Linux machine's eight tiles (03 §3.9's matrix, as LinuxTab.tiles in the app): App, Available (or
    Compressed where memory is compressed), Kernel, the RAM with its decimal (or the container's limit),
    swap (or zram where it is the only swap), free disk, stall time on a server (Idle on a desktop, what
    is available where PSI is off), the biggest group. Each (value, label, one-row label, width, priority,
    role of the value)."""
    f = c["linux"]
    avail = c["free"]
    out = [("%.1f GB" % c["app"], "App memory", "App", 12, 0, "fg")]
    out.append(("%.1f GB" % c["comp"], "Compressed", "Compressed", 12, 1, "fg") if f["comp"] else
               ("%.1f GB" % avail, "Available", "avail", 12, 1, "fg"))
    out.append(("%.1f GB" % c["wired"], "Kernel", "Kernel", 9, 2, "fg"))
    out.append(("%.1f GB" % c["ram"], "Memory limit" if f["cgroup"] else "RAM total", "limit" if f["cgroup"] else "RAM", 12, 4,
                "fg"))
    if f["zram_only"]:
        z = f.get("zram")
        out.append(("%.1f / %.1f GB" % z if z else g["dash"], "zram / size", "zram", 13, 3, "fg"))
    else:
        out.append(("%.1f / %.0f GB" % (c["swap"], c["swap_total"]), "Swap / size", "swap", 13, 3, "fg"))
    out.append(("%.0f GB" % c["disk"], "Free disk", "disk free", 11, 5, "fg"))
    if f["desktop"]:
        idle = c.get("idle")
        out.append((g["dash"] if idle is None else "%d min" % (idle // 60) if idle >= 120 else "%d s" % idle,
                    "Idle", "idle", 7, 6, "fg"))
    elif f["psi"]:
        v = stall_pct(f["some"]) + (" +" + stall_pct(f["limit"]) if f["limit"] >= 0.05 else "")
        out.append((v, "Stalled", "stalled", 9 if f["limit"] < 0.05 else 16, 6,
                    "crit" if f["some"] >= 10 or f["full"] >= 5 else "fg"))
    else:
        share = f["free_pct"] if f["free_pct"] is not None else (100 * avail / c["ram"] if c["ram"] else 0)
        out.append(("%.0f %%" % share, "of RAM available", "of RAM avail", 12, 6, "fg"))
    if not f["all_procs"]:
        out.append((g["dash"], "#1 not visible", "", 18, 7, "fg"))
    elif c.get("groups"):
        name, gb, _ = c["groups"][0]
        out.append(("%.1f GB" % gb, "#1 " + linux_group(name), "", 18, 7, "fg"))
    return out


def series_words(cur):
    """The memory series as this machine has them, bottom to top, (name, role): a Mac's four; on Linux Kernel
    for Wired (the same field), and only the series the machine has (03 §3.9: no Compressed without zram or
    zswap, no Swap without swap: a swap total, swap in use or a swap file, as LinuxTab.Facts in the app)."""
    f = (cur or {}).get("linux")
    if f is None:
        return SERIES_WORDS
    sw = (cur.get("swap_total") or 0) > 0 or (cur.get("swap") or 0) > 0 or (f.get("swapfiles") or 0) > 0
    return tuple(x for x in (("Kernel", "wired"), ("App", "app"), ("Compressed", "comp"), ("Swap", "swap"))
                 if (x[1] != "comp" or f["comp"]) and (x[1] != "swap" or sw))


# ------------------------------------------------------------------ the chart
SERIES_WORDS = (("Wired", "wired"), ("App", "app"), ("Compressed", "comp"), ("Swap", "swap"))
LEGEND_ORDER = ("away", "no data", "incident")       # as drawn, left to right
LEGEND_YIELD = ("away", "incident", "no data")       # what gives way, first to last
LEGEND_ORDER_MISS = ("away", "no data", "not received", "incident")
LEGEND_YIELD_MISS = ("away", "incident", "no data", "not received")


def legend_items(g, caps, short, initials=False, words=SERIES_WORDS):
    mono = caps.color == "none"
    shade = dict(zip(SERIES, g["shades"]))
    names = [("Compr." if short and n == "Compressed" else n, role, shade[role] if mono else g["legend_sw"])
             for n, role in words]
    if initials:
        names = [(n[0], role, s) for n, role, s in names]
    plain_band = mono or caps.color == "16"
    extra = {"no data": ("no data", "hatch", g["hatch"]), "incident": ("incident", "incident", g["inc"]),
             "not received": ("not received", "faint", g["miss"]),
             "away": ("away", "dim" if not mono else "fg", g["awaydot"] if plain_band else g["legend_away"])}
    return names, extra


def draw_chart_head(fr, x, y, w, ui, caps, g, title=None, miss=False, values=None, words=SERIES_WORDS, away=True):
    """The top edge of the chart box: the span selector on the left (it never gives way; below room
    for all four only the selected one stays), the legend on the right (it shortens, then goes).
    `miss`: a stretch not received is in view, and the legend explains its dots (04 §3.3). `values`
    (the resources on): the focus's series with their live values instead (04 §3.14)."""
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
    if values is not None:
        draw_values(fr, x + w - 2, y, room, values, caps, g)
        return
    chosen = None
    for short, drop, initials in ((False, 0, False), (True, 0, False), (True, 1, False), (True, 2, False),
                                  (True, 3, False), (True, 3, True)) + (((True, 4, True),) if miss else ()):
        names, extra = legend_items(g, caps, short, initials, words)
        order, yld = (LEGEND_ORDER_MISS, LEGEND_YIELD_MISS) if miss else (LEGEND_ORDER, LEGEND_YIELD)
        items = names + [extra[k] for k in order if k not in yld[:drop] and (away or k != "away")]
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


def legend_values(model, focus):
    """The focus's series and their live values (02 §3.4.2, 04 §3.14): [(name, value, role)] and a unit."""
    cur, tiles = model.get("cur") or {}, model.get("tiles") or {}
    if focus == "memory":
        sw = "%.1f/%.0f" % (cur.get("swap", 0), cur.get("swap_total", 0)) if cur.get("swap") else "%.1f" % cur.get("swap", 0)
        vals = {"wired": "%.1f" % cur.get("wired", 0), "app": "%.1f" % cur.get("app", 0), "comp": "%.1f" % cur.get("comp", 0),
                "swap": sw}
        return [(n, vals[role], role) for n, role in series_words(cur)] + [("GB", None, None)]
    rf = model.get("rfacts") or {}
    if focus == "cpu":
        return [("System", _g1(rf.get("sys")), "wired"), ("User", _g1(rf.get("user")), "r0"), ("cores", None, None)]
    if focus == "gpu":
        util = "%.0f" % rf["util"] if isinstance(rf.get("util"), (int, float)) else "–"
        return [("Full speed" if rf.get("full") else "Busy", util + " %", "r1"), ("Memory", _g1(rf.get("gmem")) + " GB", "wired")]
    if focus == "net":
        d, u = rf.get("net_d"), rf.get("net_u")
        return [("Down", "–" if d is None else mbps(d), "r7"), ("Up", "–" if u is None else mbps(u), "r7"),
                ("Mbit/s", None, None)]
    free = "%.0f" % rf["free"] if isinstance(rf.get("free"), (int, float)) else "–"
    return [("Free on " + mid_fit(rf.get("pool") or "disk", 12), free, "r2"), ("GB", None, None)]


def _g1(x):
    return "%.1f" % x if isinstance(x, (int, float)) else "–"


def draw_values(fr, xr, y, room, values, caps, g):
    """The legend with values, right-aligned at xr: "Compressed" gives way to "Compr.", then the names
    go; the values stay (02 §3.4.2's overflow rule)."""
    mono = caps.color == "none"
    for short in (0, 1, 2):
        items = []
        for name, val, role in values:
            if role is None:
                items.append((" " + name, None, None))
                continue
            nm = "Compr." if short >= 1 and name == "Compressed" else name
            items.append((g["legend_sw"], role, (" " if short < 2 else "") + (nm if short < 2 else "") + " " + val))
        need = sum(tw(a) + (tw(c) if c else 0) for a, _, c in items) + len(items) + 1
        if need <= room:
            break
    else:
        return
    x = xr - need + 1
    for sw, role, text in items:
        x = fr.put(x, y, " ", None, None)
        if role is None:
            x = fr.put(x, y, sw.strip(), "dim", None)
            continue
        x = fr.put(x, y, sw, role if not mono else "fg", None)
        x = fr.put(x, y, text, "dim", None)
    fr.put(x, y, " ", None, None)


def draw_tiles(fr, x, y, w, model, g, caps, rows=2):
    """The resource tiles in the place of the readings (T4a, 04 §3.14, 02 §3.7.12): name and flag over the
    reading. The focus is in reverse video, the other shown resources bold; a flag is a word (red for
    critical, amber for tight or low), so nothing depends on colour alone. One row: names and readings."""
    tiles = model.get("tiles")
    if not tiles:
        fr.put(x, y, "No readings yet", "dim")
        return
    shown, focus = rv_shown(model)
    avail = model.get("avail") or available(None)
    mono = caps.color == "none"
    n = len(avail)
    cw = (w - (n - 1)) // n
    for i, r in enumerate(avail):
        t, tx = tiles[r], x + i * (cw + 1)
        name, flag = RES_WORDS[r], flag_text(t, g)
        role = "crit" if t["level"] >= 2 else "warntx" if t["level"] == 1 else "dim"
        if r == focus:
            nx = fr.put(tx, y, " %s " % name, "selfg", "sel", BOLD | (REV if mono else 0))
        else:
            nx = fr.put(tx, y, name, "fg" if r in shown else "dim", None, BOLD if r in shown else 0)
        reading = asc(t["reading"], fr)
        if tw(reading) > cw and t.get("short"):     # five tiles leave 14 cells at 80 columns (NET 12.16)
            reading = asc(t["short"], fr)
        if rows == 1:
            fr.put(nx + 1, y, fit(reading, max(cw - (nx - tx) - 1, 0), g), "fg")
            continue
        room = cw - (nx - tx) - 1
        if flag and tw(flag) > room:
            flag = flag_text(t, g, short=True)
        flag = asc(flag, fr) if flag else flag
        if flag and room >= 2:
            fr.rput(tx + cw - 1, y, fit(flag, room, g), role, None, BOLD if t["level"] else 0)
        fr.put(tx, y + 1, fit(reading, cw, g), "fg", None, BOLD)


def _rvalue(p, r):
    """A point's value of resource r, or None (the small rows and the resource plot)."""
    if r == "memory":
        return p["wired"] + p["app"] + p["comp"]
    return p.get({"cpu": "cpu", "gpu": "gpu", "disk": "disk", "net": "nd"}[r])


def r_scale(model, r, pts=None):
    """A resource's scale (02 §3.4.3): RAM, the cores, 100 %, free disk on 1, 2, 4, 8 × 10ⁿ steps."""
    if r == "memory":
        return max(model.get("ram") or 0, 1.0)
    if r == "cpu":
        return float((model.get("rfacts") or {}).get("n") or 1)
    if r == "gpu":
        return 100.0
    if r == "net":              # the download, to the line's figure or the busiest moment (net_scale)
        return net_scale(max([(model.get("rfacts") or {}).get("net_cap_d") or 0.0] +
                             [p.get("ndp") or p.get("nd") or 0.0 for p in (pts or model["pts"])]))
    vals = [v for v in (_rvalue(p, r) for p in (pts or model["pts"])) if v is not None]
    top = max(vals + [1.0])
    e = 10 ** math.floor(math.log10(top))
    return next(m * e for m in (1, 2, 4, 8, 10) if m * e >= top - 1e-9)


def draw_rplot(fr, x0, y0, W, H, model, ui, caps, g, r):
    """The plot of the focus when it is not memory (T4a): the cores busy (the system's part grey under the
    apps' teal), the GPU (violet) or the free space of the Disk tile's pool (magenta), each column the mean
    of what it holds (the least free for disk), with the grid, no-data hatching, incident rules and the
    time axis of the memory plot. Returns the grid columns (the strip continues them)."""
    mono = caps.color == "none"
    whole = mono or caps.glyphs in ("cells", "ascii")
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[ui["span"]])
    cols = columns(model["pts"], model["gaps"], f, finv, W, now, first, model.get("missing") or ())
    top = r_scale(model, r, [p for st, p in cols if st == "data"])
    labels = axis_labels(f, W, now, log=SPANS[ui["span"]] is None)
    gridcols = set(min(W - 1, int(round(x * W))) for x, text in labels if text != "now")
    inc = set(min(W - 1, int(f(i["start"]) * W)) for i in model["incidents"] if 0 <= f(i["start"]) <= 1)
    L = 8 * H
    hue = RES_HUE[r]
    for c in range(W):
        st, p = cols[c]
        cells = [(" ", None, None)] * H
        if st == "data":
            v = _rvalue(p, r)
            if v is not None:
                parts = [(min(p.get("sys") or 0.0, v), "wired"), (max(v - (p.get("sys") or 0.0), 0.0), hue)] if r == "cpu" \
                    else [(v, hue)]
                segs, lo, cum = [], 0, 0.0
                for amount, role in parts:
                    cum += amount
                    hi = min(L, int(round(cum / top * L)))
                    if hi > lo:
                        segs.append((lo, hi, role))
                        lo = hi
                if whole:
                    shaded = mono or caps.glyphs == "ascii"        # a shade per part, as the memory plot has
                    cells = [((g["shades"][0 if own == hue else 2] if shaded else FULL), None if mono else own, None)
                             if own else (" ", None, None) for _, own in stack_cells_whole(segs, H)]
                else:
                    cells = stack_cells(segs, H, g["eighths"])
        for row in range(H):
            ch, fg, bg = cells[row]
            if ch == " ":
                if st == "gap":
                    ch, fg = g["hatch"], "hatch"
                elif st == "miss":
                    ch, fg = g["miss"], "faint"
                elif c in gridcols:
                    ch, fg = g["grid"], "grid"
            if c in inc:
                ch, fg, bg = g["inc"], "incident", None
            fr.put(x0 + c, y0 + H - 1 - row, ch, fg, bg)
    unit = {"cpu": "", "gpu": "%", "disk": "G"}[r]
    for v in (top, top / 2.0):
        row = max(0, min(H - 1, int(v / top * H - 1e-9)))
        fr.rput(x0 + W + 4, y0 + H - 1 - row, ("%d" % v if v == int(v) else "%.1f" % v) + unit, "dim")
    for x, text in labels:
        cx = min(max(int(round(x * W)) - len(text) // 2, 0), W - len(text))
        fr.put(x0 + cx, y0 + H, text, "dim")
    return gridcols


def net_gutter(v, arrow):
    """A network scale in the plot's gutter, at most five cells: "↓500", "↓1000", "↓20k", "↓1G" (a million Mbit/s,
    the most net_rate lets through)."""
    return arrow + ("%d" % v if v < 10000 else "%dk" % (v // 1000) if v < 1e6 else "1G")


def draw_netplot(fr, x0, y0, W, H, model, ui, caps, g):
    """The Network plot (NET 12.16): the upper half the download, eighth blocks rising from the middle; the lower half
    the upload, falling from it (half a row at a time: a terminal has no upper eighths); one Mbit/s scale for both
    (net_scale over the line's figures and the busiest moment in view); each figure a dashed row on its side; the
    grid, no-data hatching, incident rules and the time axis of the other plots. Returns the grid columns."""
    mono = caps.color == "none"
    whole = mono or caps.glyphs in ("cells", "ascii")
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[ui["span"]])
    cols = columns(model["pts"], model["gaps"], f, finv, W, now, first, model.get("missing") or ())
    rf = model.get("rfacts") or {}
    capd, capu = rf.get("net_cap_d"), rf.get("net_cap_u")
    peak = max([max(p.get("ndp") or p.get("nd") or 0.0, p.get("nup") or p.get("nu") or 0.0)
                for st, p in cols if st == "data"] + [0.0])
    top = net_scale(max(capd or 0.0, capu or 0.0, peak))
    Hd = (H + 1) // 2
    Hu = H - Hd
    labels = axis_labels(f, W, now, log=SPANS[ui["span"]] is None)
    gridcols = set(min(W - 1, int(round(x * W))) for x, text in labels if text != "now")
    inc = set(min(W - 1, int(f(i["start"]) * W)) for i in model["incidents"] if 0 <= f(i["start"]) <= 1)
    hue = None if mono else RES_HUE["net"]
    shaded = mono or caps.glyphs == "ascii"

    def cap_row(cap, h):        # the row (from the axis out) the figure falls in, or -1
        return min(h - 1, int(cap / top * h - 1e-9)) if cap and h else -1
    rd, ru = cap_row(capd, Hd), cap_row(capu, Hu)

    def cells(v, h, falling):   # h cells from the axis out: (character, fg)
        if v is None or h == 0:
            return [(" ", None)] * h
        L = min(8 * h, int(round(v / top * 8 * h)))
        if v > 0 and L == 0 and v >= top / 200.0:
            L = 1                   # something moved: a sliver
        out = []
        for r in range(h):
            n = max(0, min(8, L - 8 * r))
            if whole:
                full = n >= 4 or (r == 0 and n > 0)
                out.append(((g["shades"][0] if shaded else FULL) if full else " ", hue if full else None))
            elif falling:
                ch = FULL if n >= 6 else g["upper"] if n >= 2 or (r == 0 and n > 0) else " "
                out.append((ch, hue if ch != " " else None))
            else:
                out.append((g["eighths"][n], hue if n else None))
        return out
    for c in range(W):
        st, p = cols[c]
        down = cells(p.get("nd") if st == "data" else None, Hd, False)
        up = cells(p.get("nu") if st == "data" else None, Hu, True)
        for r, (ch, fg), y, capr in [(r, down[r], y0 + Hd - 1 - r, rd) for r in range(Hd)] + \
                                    [(r, up[r], y0 + Hd + r, ru) for r in range(Hu)]:
            if ch == " ":
                if st == "gap":
                    ch, fg = g["hatch"], "hatch"
                elif st == "miss":
                    ch, fg = g["miss"], "faint"
                elif c in gridcols:
                    ch, fg = g["grid"], "grid"
                elif r == capr and c % 2 == 0:
                    ch, fg = g["ram"][1], "dim"
            if c in inc:
                ch, fg = g["inc"], "incident"
            fr.put(x0 + c, y, ch, fg, None)
    fr.rput(x0 + W + 4, y0, asc(net_gutter(top, "↓"), fr), "dim")
    if Hu:
        fr.rput(x0 + W + 4, y0 + H - 1, asc(net_gutter(top, "↑"), fr), "dim")
    for x, text in labels:
        cx = min(max(int(round(x * W)) - len(text) // 2, 0), W - len(text))
        fr.put(x0 + cx, y0 + H, text, "dim")
    return gridcols


def draw_spark(fr, x0, y, W, model, ui, caps, g, r):
    """One row of eighth blocks for another shown resource, on the plot's time axis, its name in the
    gutter (02 §3.7.12: from 30 rows of height)."""
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[ui["span"]])
    cols = columns(model["pts"], model["gaps"], f, finv, W, now, first, model.get("missing") or ())
    top = r_scale(model, r)
    eighths = g["eighths"]
    for c in range(W):
        st, p = cols[c]
        v = _rvalue(p, r) if st == "data" else None
        if st == "gap":
            fr.put(x0 + c, y, g["hatch"], "hatch")
        elif v is None:
            fr.put(x0 + c, y, " ", None)
        else:
            n = max(1 if v > 0 else 0, min(8, int(round(v / top * 8))))
            fr.put(x0 + c, y, eighths[n] if caps.glyphs != "ascii" else eighths[n], None if caps.color == "none" else RES_HUE[r])
    fr.rput(x0 + W + 4, y, {"memory": "Mem", "cpu": "CPU", "gpu": "GPU", "disk": "Disk", "net": "Net"}[r], "dim")


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
    cols = columns(model["pts"], model["gaps"], f, finv, W, now, first, model.get("missing") or ())
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
    key = (pv, len(model["pts"]), tuple(model["gaps"]), tuple(model.get("missing") or ()), model.get("first"), model.get("ram"),
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
    # TimeAxis.calmBands with columns as the unit: a no-data stretch that touches an away band is part of it
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
                elif st == "miss":
                    ch, fg = g["miss"], "faint"
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
                elif ch in (g["hatch"], g["grid"], ram_glyph, g["awaydot"], " ") or st == "miss":
                    bg = bgc
                elif ch == FULL or ch in g["eighths"][4:8]:
                    bg = fg                              # the area goes on behind the rule
                ch, fg = g["inc"], "incident"
            fr.put(x0 + c, y0 + H - 1 - r, ch, fg, bg, fl)
    if H >= 3:                  # a stretch wide enough names itself (not connected, not received, …)
        c = 0
        while c < W:
            if cols[c][0] != "miss":
                c += 1
                continue
            k, e = cols[c][1], c
            while e < W and cols[e] == ("miss", k):
                e += 1
            word = MISSING_WORDS.get(k, "")
            if word and e - c >= len(word) + 2:
                fr.put(x0 + c + (e - c - len(word)) // 2, y0 + H // 2, word, "dim")
            c = e
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


_RBLOCKS = {"res": None, "bands": {}}   # the reservations the blocks are of, and (resource, pool, 10 s) → blocks


def band_blocks(model, k):
    """The blocks of band k (stack_reservations over what holds k; the Disk band: the tile's pool), kept while the
    model's reservations are the same list (they are reloaded as a new one) and for at most 10 s of its clock,
    as the memory blocks are kept between reloads. The cache holds the list itself and compares by identity: a
    reloaded list can never be taken for the one before it (an id alone can be reused once that one is freed)."""
    res, pool = model["res"], rv_pool(model) if k == "disk" else None
    c = _RBLOCKS
    if c["res"] is not res or len(c["bands"]) > 16:
        c["res"], c["bands"] = res, {}
    key = (k, pool, int(model["now"] // 10))
    if key not in c["bands"]:
        c["bands"][key] = stack_reservations([r for r in res if holds(r, k, pool, band=True)], model["now"], k)
    return c["bands"][key]


def band_top(tallest, k, line=None):
    """Reservation.bandTop: a band's scale, the first round figure at or above its tallest stack in view; GB of
    disk go on in steps up to 64 TB; the network's what the line has to share (`line`: its figure less the margin,
    NET 12.15: a block's height is got / (cap − margin)), else net_scale's steps."""
    if k == "net":
        return line if _n(line) is not None and line >= max(tallest, 1.0) else net_scale(tallest)
    if k == "disk" and tallest > 256:
        return next((t for t in (384, 512, 768, 1024, 1536, 2048, 3072, 4096, 8192, 16384, 32768, 65536)
                     if t >= tallest), tallest)
    return strip_top(tallest)


def band_scale(top, k):
    """The scale of a tall band in the gutter: "24G", "12c", "320G", "145M" (Mbit/s)."""
    return ("%dc" if k == "cpu" else "%dM" if k == "net" else "%dG") % top


def strip_plan(model, S):
    """[(resource, first row, rows)] of a strip of S rows with the resources on (02 §3.7.6; 04 §3.14): a band per
    shown resource that has one, the first (the focus's) takes what the others leave, each other one a row; with
    more bands than rows the last ones are left out (the list still has them)."""
    shown, focus = rv_shown(model)
    bs = bands(model["res"], shown, focus, rv_pool(model))[:max(S, 0)]
    if not bs:
        return []
    out, y = [(bs[0], 0, S - (len(bs) - 1))], S - (len(bs) - 1)
    for k in bs[1:]:
        out.append((k, y, 1))
        y += 1
    return out


def draw_bands(fr, x0, y0, W, H, model, ui, caps, g, gridcols=()):
    """The strip with the resources on: a band per reserved resource shown (strip_plan), each on its own scale, the
    first tall with its scale in the gutter, the others a row with their name there. The memory alone is today's
    strip."""
    plan_ = strip_plan(model, H)
    for k, dy, h in plan_:
        draw_strip(fr, x0, y0 + dy, W, h, model, ui, caps, g, gridcols, kind=k, label=None if dy == 0 else
                   {"memory": "Mem", "cpu": "CPU", "disk": "Disk", "net": "Net"}[k])


def draw_strip(fr, x0, y0, W, H, model, ui, caps, g, gridcols=(), kind=None, label=None):
    """The reservation blocks on the plot's time axis: height ∝ GB, stacked in lanes; queued
    stretches in a shade. A column shows the instant inside it with the tallest stack. `kind`: one band of
    the resources (draw_bands), with its own scale or, a row high, its `label` in the gutter."""
    mono = caps.color == "none"
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[ui["span"]])
    blocks = [b for b in (model["blocks"] if kind is None else band_blocks(model, kind)) if f(b["end"]) >= 0]
    top = band_top(max([st[3] for b in blocks for st in b["steps"] if f(st[1]) >= 0] or [0]), kind or "memory",
                   (model.get("rfacts") or {}).get("net_line"))
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
                segs.append((lo, hi, (res_role(model, r), queued, k)))
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
    if label:
        fr.rput(x0 + W + 4, y0, label, "faint")
    elif kind is None or kind == "memory":
        fr.rput(x0 + W + 4, y0, "%dG" % top, "faint")
    else:
        fr.rput(x0 + W + 4, y0, band_scale(top, kind), "faint")


# ------------------------------------------------------------------ the lists
def _queue_key(r):
    """Where a waiting reservation stands: its place in the ledger's list of leases (a queued request
    that grows moves to the back), the request time where that is not known."""
    q = r.get("queue")
    return (q is None, q if isinstance(q, int) else 0, r["requested"], r["key"])


def ordered_res(res, flags_first=False):
    """Waiting first (the queue, head on top), then grants by time left, soonest first (a grant
    without a ttl last), then finished ones newest first: whatever a short list cuts off is never
    the reservation that explains why an agent waits. With `flags_first` (the resources on, 02 §3.4.6)
    a grant with an `over` or `idle` flag comes before them all. The live part is the app's order too
    (Reservation.listOrder; roadmap C13), held to it by tools/vectors/chart.json."""
    live = [r for r in res if r.get("ended") is None]
    waiting = sorted([r for r in live if r.get("granted") is None], key=_queue_key)
    granted = sorted([r for r in live if r.get("granted") is not None],
                     key=lambda r: (r.get("expires") is None, r.get("expires") or 0, r["requested"], r["key"]))
    if flags_first:
        flagged = [r for r in granted if r.get("flags")]
        waiting = flagged + waiting
        granted = [r for r in granted if not r.get("flags")]
    done = sorted([r for r in res if r.get("ended") is not None], key=lambda r: (-r["ended"], r["key"]))
    return waiting, granted, done


def short_duration(sec):
    """MemoryChart.shortDuration: '17m', '1h05', '2h' (a time left, in the strip and the list)."""
    m = max(int(math.floor(sec / 60.0 + 0.5)), 0)
    return "%dm" % m if m < 60 else "%dh" % (m // 60) if m % 60 == 0 or m >= 600 else "%dh%02d" % (m // 60, m % 60)


def amt_g(x):
    """'6G', '2.5G': GB in a row (no ".0")."""
    return "%dG" % int(round(x)) if abs(x - round(x)) < 0.05 else "%.1fG" % x


def cores_words(x):
    """'1 core', '6 cores', '2.5 cores' (one decimal, as printf rounds it; no ".0")."""
    t = "%.1f" % x
    t = t[:-2] if t.endswith(".0") else t
    return t + (" core" if t == "1" else " cores")


def amounts_text(r, pool=None):
    """Reservation.amountsText (02 §3.8.5): every amount of a row as text, "5G · 6 cores · 20G disk"; disk space on
    another pool than the tile's is named ("300G Scratch")."""
    parts = []
    if r.get("mem", True):
        parts.append(amt_g(r["segments"][-1][1]))
    if r.get("cpu") is not None:
        parts.append(cores_words(r["cpu"]))
    if r.get("disk") is not None:
        other = pool is not None and r.get("pool") not in (None, pool)
        parts.append(amt_g(r["disk"]) + " " + (mid_fit(r.get("pool_name") or r.get("pool"), 12) if other else "disk"))
    return " · ".join(parts + net_amounts(r)) or "–"


def net_num(x):
    """A rate or a volume of the network as people write it: 150, 18.5, 0.5."""
    return "%d" % round(x) if abs(x - round(x)) < 0.05 else "%.1f" % x


def net_amounts(r):
    """The network's amounts of a row (NET 12.15): "150 Mbit/s · 40 GB" down, "↑20 Mbit/s · ↑5 GB" up; a volume
    without a rate (unmanaged, a network without a figure) "↓40 GB"."""
    out = []
    if r.get("net") is not None:
        out.append(net_num(r["net"]) + " Mbit/s")
    if r.get("net_gb") is not None:
        out.append(("" if r.get("net") is not None else "↓") + net_num(r["net_gb"]) + " GB")
    if r.get("net_up") is not None:
        out.append("↑" + net_num(r["net_up"]) + " Mbit/s")
    if r.get("net_up_gb") is not None:
        out.append("↑" + net_num(r["net_up_gb"]) + " GB")
    return out


def _and(words):
    return words[0] if len(words) == 1 else ", ".join(words[:-1]) + " and " + words[-1]


def use_figure(r, k, now=None):
    """One use figure of a grant (02 §3.4.6): "using 2.1G", "using 5.2 cores", "wrote 11G of 20G"; the network's
    "12.3 of 40 GB · ≈ 24 min left" (12.15) or "using 143 Mbit/s"; None unmeasured."""
    if k == "net":
        if r.get("net_gb") is not None and r.get("net_moved") is not None:
            eta = r.get("net_eta")
            return "%.1f of %s GB" % (r["net_moved"], net_num(r["net_gb"])) + \
                (" · ≈ %s left" % duration(eta - now) if eta is not None and now is not None and eta > now else "")
        return "using %s Mbit/s" % mbps(r["net_used"]) if r.get("net_used") is not None else None
    if k == "memory":
        return "using %.1fG" % _gb(r.get("used"))
    if k == "cpu" and r.get("cpu_used") is not None:
        return "using " + cores_words(r["cpu_used"])
    if k == "disk" and r.get("disk_w") is not None and r.get("disk") is not None:
        return "wrote %s of %s" % (amt_g(r["disk_w"]), amt_g(r["disk"]))
    return None


def status_text(r, shown, focus, now):
    """Reservation.statusText (02 §3.4.6, §3.7.7): a waiting row says for how long and what it waits for ("waiting
    40 s · for CPU"); a grant its flag ("over", "idle 12 min", "over on CPU" when it is not about the focus), one use
    figure (of the focus if it holds it, else of the first shown resource it holds; none after `idle`), then the
    time left."""
    if r.get("granted") is None:
        w = [RES_WORD[k] for k in r.get("waiting") or []]
        return "waiting " + duration(now - r["requested"]) + (" · for " + _and(w) if w else "")
    parts, idle = [], False
    fl = r.get("flags") or {}
    fk = next((k for k in [focus] + list(RESOURCES) if k in fl), None)
    if fk:
        f, since = fl[fk][0], fl[fk][1]
        parts.append(f + ("" if fk == focus else " on " + RES_WORD[fk]) +
                     (" " + duration(now - since) if f == "idle" and since is not None else ""))
        idle = f == "idle"
    held = [k for k in RESOURCES if holds(r, k)]
    if not idle and held:
        fig = use_figure(r, focus if focus in held else next((k for k in held if k in shown), held[0]), now)
        if fig:
            parts.append(fig)
    if r.get("expires") is not None:
        parts.append(short_duration(r["expires"] - now) + " left")
    return " · ".join(parts)


def rv_split(live, shown):
    """(the live reservations that hold a shown resource, the rest) (02 §3.7.7)."""
    rows = [r for r in live if any(holds(r, k) for k in shown)]
    return rows, [r for r in live if not any(holds(r, k) for k in shown)]


def _totals(rs, which):
    """The granted totals of `which` over rs, as words: "14.0 GB", "6 cores", "20 GB disk"."""
    out = []
    g = [r for r in rs if r.get("granted") is not None]
    if "memory" in which and any(r.get("mem", True) for r in g):
        out.append("%.1f GB" % sum(r["segments"][-1][1] for r in g if r.get("mem", True)))
    if "cpu" in which and any(r.get("cpu") is not None for r in g):
        out.append(cores_words(sum(r["cpu"] for r in g if r.get("cpu") is not None)))
    if "disk" in which and any(r.get("disk") is not None for r in g):
        out.append("%s GB disk" % amt_g(sum(r["disk"] for r in g if r.get("disk") is not None))[:-1])
    if "net" in which and any(r.get("net") is not None for r in g):
        out.append("%s Mbit/s" % net_num(sum(r["net"] for r in g if r.get("net") is not None)))
    if "net" in which and any(r.get("net_up") is not None for r in g):
        out.append("↑%s Mbit/s" % net_num(sum(r["net_up"] for r in g if r.get("net_up") is not None)))
    return out


def caption_text(live, shown, n24):
    """Reservation.captionText (02 §3.7.7): the live grants of the shown resources summed, as text, and how many
    reservations the last 24 h saw: "14.0 GB · 6 cores · 46 in the last 24 h"."""
    return " · ".join(_totals(live, shown) + ["%d in the last 24 h" % n24])


def other_text(rest, short=False):
    """Reservation.otherText (02 §3.7.7): the line for what holds no shown resource: its granted totals and how many
    of it wait, for what. "On other resources: 6 cores and 20 GB disk reserved · 1 waiting for CPU"; short "Other: 6
    cores, 20 GB disk · 1 waiting". None when there is nothing."""
    if not rest:
        return None
    tot = _totals(rest, RESOURCES)
    waiting = [r for r in rest if r.get("granted") is None]
    what = [RES_WORD[k] for k in RESOURCES if any(k in (r.get("waiting") or ()) for r in waiting)]
    if short:
        return "Other: " + ", ".join(tot) + (" · " if tot and waiting else "") + \
            ("%d waiting" % len(waiting) if waiting else "")
    return "On other resources: " + (_and(tot) + " reserved" if tot else "") + (" · " if tot and waiting else "") + \
        ("%d waiting%s" % (len(waiting), " for " + _and(what) if what else "") if waiting else "")


def res_seq(model):
    """The reservation list as one sequence: waiting, granted, then the finished ones of the last 24 h.
    With the resources on, only what holds a shown resource, flagged grants first (02 §3.7.7; the rest is
    counted by rv_other). Returns (sequence, live count, waiting count)."""
    res = model["res"]
    if model.get("rv"):
        shown = rv_shown(model)[0]
        res = [r for r in res if any(holds(r, k) for k in shown)]
    waiting, granted, done = ordered_res(res, flags_first=bool(model.get("rv")))
    n_wait = sum(1 for r in waiting if r.get("granted") is None)
    return waiting + granted + [r for r in done if r["ended"] >= model["now"] - 86400], len(waiting) + len(granted), \
        n_wait


def rv_other(model, short=False):
    """With the resources on, the line for the live reservations that hold no shown resource (other_text)."""
    if not model.get("rv"):
        return None
    live = [r for r in model["res"] if r.get("ended") is None]
    return other_text(rv_split(live, rv_shown(model)[0])[1], short)


def res_room(model, R):
    """How many of the list's R rows are for reservations: one less while the "other" line needs one."""
    return R - 1 if R >= 2 and rv_other(model) else R


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
    other = [("other",)] if res_room(model, R) < R else []     # the resources on: "On other resources: …"
    R = res_room(model, R)
    if (R < 2 and (ui or {}).get("focus") == "res") or (n_live <= R and off == 0):
        return [("res", r, off + i) for i, r in enumerate(seq[off:off + R])] + other, n_live, n_wait
    shown = seq[off:off + R - 1]
    below = [r for r in seq[off + R - 1:] if r.get("ended") is None]
    rows = [("res", r, off + i) for i, r in enumerate(shown)]
    rows.append(("more", off, len(below), sum(1 for r in below if r.get("granted") is None),
                 len(seq) - off - len(shown)))
    return rows + other, n_live, n_wait


def panel_area(P):
    """Where a panel (a s e) goes: in the place of the two lists, below the strip ("lists"); or, in a
    pane whose list area has fewer than 4 rows, the whole chart box ("chart"). (y of its caption,
    rows below the caption, where `esc` leads)."""
    if P["R"] or P["I"]:
        y0 = P["list_y"] if P["R"] else P["inc_cap_y"]
        if P["bottom_y"] - y0 >= 4:
            return y0, P["bottom_y"] - y0 - 1, "lists"
    return P["box_y"], P["bottom_y"] - P["box_y"] - 1, "chart"


def net_focus(model):
    """Does the network have the plot (the resources on)? Then `a` lists the busiest names on the line."""
    return bool(model.get("rv")) and rv_shown(model)[1] == "net"


def panel_items(model, panel):
    """The rows of a panel: apps (name, GB, processes), sessions (pid, cwd, GB, processes, biggest),
    events (t, text, alarming)."""
    cur = model.get("cur") or {}
    if panel == "a" and net_focus(model):     # the network has the plot: its busiest names (NET 12.16)
        return cur.get("net_names") or []
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
    R, I = res_room(model, P["R"]), P["I"]
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


def amounts_width(model):
    """The amounts column of the list with the resources on: as wide as the widest row of the 14 days (a slow
    fact, so rows that come and go do not push the purposes sideways), 6 to 20 cells."""
    pool = rv_pool(model)
    return max(6, min(20, max([tw(amounts_text(r, pool)) + 1 for r in model["res"]] or [6])))


def rv_pool(model):
    """The id of the disk pool the Disk tile shows (its band's), None where the sample names none."""
    return (model.get("rfacts") or {}).get("pool_id")


def draw_res_rows(fr, x, y, w, rows, model, caps, g, ui=None):
    ui = ui or {}
    mono = caps.color == "none"
    now = model["now"]
    rv = model.get("rv")
    aw = max(6, min(amounts_width(model), w // 3)) if rv else 6
    pw, px = res_columns(w - (aw - 6))
    px += aw - 6
    focus, sel = ui.get("focus") == "res", ui.get("res_sel")
    if rv:
        shown, rfocus = rv_shown(model)
        pool = rv_pool(model)
    for i, row in enumerate(rows):
        yy = y + i
        if row[0] == "other":
            text = rv_other(model, short=w < 64) or ""
            fr.put(x + 2, yy, fit(asc(text, fr), w - 4, g), "dim")
            continue
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
            elif below and rv and not above:    # the app's words (02 §3.4.6): "▾ 3 more: 2 granted, 1 waiting"
                parts.append(("%s %d more" % (g["down"], below), "dim"))
                if below - waiting:
                    parts.append(("%d granted" % (below - waiting), "dim"))
                if waiting:
                    parts.append(("%d waiting" % waiting, "warntx"))
            elif below:
                parts.append(("%s %d more" % (g["down"], below), "dim"))
                if waiting:
                    parts.append(("%d waiting" % waiting, "warntx"))
            elif rest:
                parts.append(("%s %d finished" % (g["down"], rest), "dim"))
            xx = x + 2
            listed = rv and below and not above and len(parts) > 1 and parts[0][0].startswith(g["down"])
            for k, (text, role) in enumerate(parts):
                if k:
                    xx = fr.put(xx, yy, (": " if k == 1 else ", ") if listed else " %s " % g["mid"], "faint")
                xx = fr.put(xx, yy, text, role)
            if not focus and w >= 44 and len(rows) > 1 and (below or rest):
                fr.rput(x + w - 2, yy, "%s scrolls" % g["updown"][1], "faint")
            continue
        r, idx = row[1], row[2]
        live = r.get("ended") is None
        granted = r.get("granted") is not None
        fr.put(x + 2, yy, g["sw"] if granted else g["swq"], None if mono else res_role(model, r), KEEP)
        raw = aw                  # this row's amounts column: wider than the list's where its amounts need it
        if rv:                    # (02 §3.4.6: the amounts and the status are never cut; the project goes first,
            amounts = asc(amounts_text(r, pool), fr)        # then the purpose is shortened in its middle)
            raw = max(aw, min(tw(amounts) + 1, w - 2 - 5 - 4))
            fr.put(x + 4, yy, fit(amounts, raw - 1, g), "fg" if live else "dim", KEEP, BOLD if live else 0)
        else:
            fr.put(x + 4, yy, "%4.1fG" % r["segments"][-1][1], "fg" if live else "dim", KEEP, BOLD if live else 0)
        if not live:
            tail = "peak %.1fG %s %s %s" % (_gb(r.get("peak")), g["mid"], (r.get("outcome") or "ended").replace("_", " "),
                                            hhmm(r["ended"]))
            trole = "faint"
        elif granted and model.get("stale"):
            tail, trole = "was using %.1fG" % _gb(r.get("used")), "dim"
        elif rv:
            tail = status_text(r, shown, rfocus, now)
            trole = "warntx" if not granted else "fg" if r.get("flags") else "dim"
        elif granted:
            used = "using %.1fG" % _gb(r.get("used"))
            tail = used + (" %s %s left" % (g["mid"], left_of(r["expires"] - now)) if r.get("expires") is not None else "")
            trole = "dim"
        else:
            tail = "waiting %s" % ago(now - r["requested"])
            trole = "warntx"
        if w < 44 or (rv and tw(tail) > w - 4 - raw - 14):     # a narrow pane keeps the state, shortened
            tail = tail.replace("using ", "").replace(" left", "").replace("waiting ", "wait ").replace(" cores", "c")
        if rv:                    # still too long beside a 4-cell purpose: the middle gives way, then all but the first
            parts = tail.split(" · ")
            room = w - 2 - (5 + raw) - 5
            while tw(" · ".join(parts)) > room and len(parts) > 1:
                parts.pop(1 if len(parts) > 2 else -1)
            tail = asc(" · ".join(parts), fr)
        fr.rput(x + w - 2, yy, tail, trole, KEEP, BOLD if rv and r.get("flags") and live else 0)
        end = w - 2 - tw(tail) - 1
        pwid = max(4, min(pw - (raw - aw), end - 5 - raw))
        fr.put(x + 5 + raw, yy, (fit_mid if rv else fit)(r["purpose"], pwid, g), "fg" if live else "dim", KEEP)
        project = r.get("project")
        if isinstance(project, str) and project and end - px >= 3 and px > 5 + raw + pwid:
            fr.put(x + px, yy, fit(project.rstrip("/").rsplit("/", 1)[-1], end - px, g), "dim", KEEP)
        if live and model.get("stale"):      # what claims to be now, of a machine not connected: grey
            fr.restyle(x, yy, w, 1, "off")
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
    if panel == "a" and net_focus(model):
        right = "Mbit/s " + asc("↓ ↑", fr)
    title = "Top network" if panel == "a" and net_focus(model) else \
        "Top groups" if panel == "a" and cur.get("linux") is not None else PANELS[panel]
    section(fr, 0, y0, lw, g, title, right, top=(where == "chart"))
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
    if panel == "a" and net_focus(model):     # name, processes, a bar of down + up, "↓212 ↑8.1"
        top = max((x[1] for x in items), default=0) or 1
        for i, (name, tot, n, d, u) in enumerate(shown):
            cx, ry = x + (i // body) * cw, y0 + 1 + i % body
            fr.put(cx + 2, ry, "%2d" % (off + i + 1), "faint", KEEP)
            nw = max(8, min(18, cw - 28))
            fr.put(cx + 5, ry, fit(name, nw, g), "fg", KEEP)
            fr.put(cx + 5 + nw + 1, ry, "%3d" % n, "faint", KEEP)
            rate = asc("↓%s ↑%s" % (mbps(d), mbps(u)), fr)
            bw = cw - (5 + nw + 5) - tw(rate) - 3
            if bw >= 3:
                bar = min(bw, max(1, int(round(tot / top * bw))))
                fr.put(cx + 5 + nw + 5, ry, (g["eighths"][5] if g["eighths"][8] == FULL else g["meter"]) * bar,
                       RES_HUE["net"] if caps.color != "none" else None, KEEP)
            fr.rput(cx + cw - 2, ry, rate, "fg", KEEP)
            if off + i == sel and focus:
                highlight(fr, cx, ry, cw, caps, g, True)
    elif panel == "a":
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
                fr.put(tail - 1, ry, g["sw"], None if caps.color == "none" else res_role(model, held[0]), KEEP)
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
    idle = c.get("idle")
    lin = c.get("linux")
    if lin is not None:  # 03 §3.9 (T3): Kernel, what is available, zram, the stall time on a server
        t = {lab: v for v, lab, _, _, _, _ in linux_tiles(c, g)}
        rows = [("App memory", "%.1f GB" % c["app"], "app")] + \
            ([("Compressed", "%.1f GB" % c["comp"], "comp")] if lin["comp"] else []) + \
            [("Kernel", "%.1f GB" % c["wired"], "wired"), ("Available", "%.1f of %.1f GB" % (c["free"], c["ram"]), None)]
        rows += [(lab, t[lab], "swap" if lab == "Swap / size" else None) for lab in ("zram / size", "Swap / size") if lab in t]
        rows.append(("Free disk", "%.0f GB" % c["disk"], None))
        rows += [("Stalled on memory" if lab == "Stalled" else lab, t[lab], None) for lab in ("Stalled", "of RAM available")
                 if lab in t]
    else:
        rows = [("App memory", "%.1f GB" % c["app"], "app"), ("Compressed", "%.1f GB" % c["comp"], "comp"),
                ("Wired", "%.1f GB" % c["wired"], "wired"), ("Free", "%.1f of %.0f GB" % (c["free"], c["ram"]), None),
                ("Swap used / size", "%.1f / %.0f GB" % (c["swap"], c["swap_total"]), "swap"),
                ("Free disk", "%.0f GB" % c["disk"], None)]
        if c.get("unowned") is not None:
            rows.append(("Not owned by a process", "%.1f GB" % c["unowned"], None))
    if lin is None or lin["desktop"]:
        rows.append(("Idle", (g["dash"] if idle is None else "%d min" % (idle // 60) if idle >= 120 else "%d s" % idle) +
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
        section(fr, x, yy, w, g, "Top groups" if c.get("linux") is not None else "Top apps",
                "%d processes" % c["procs"] if c.get("procs") else None)
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
    if model.get("logger") == "silent" or model.get("stale"):   # not live: grey. Events are history.
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


# ------------------------------------------------------------------ dialogs of the machines (04 §3.8)
CONNECT_WORDS = {
    "refused": "{h} answered, but sharing is off there. On {n}: sudo oomph share on (or the app's + › Share this Mac).",
    "turned_away": "{h} closed the connection right away. Sharing there is limited to the networks it was turned on "
                   "for: if {n} moved, run sudo oomph share on there.",
    "local_network_denied": "This terminal may not reach the local network: allow it in System Settings › Privacy & "
                            "Security › Local Network.",
    "timeout": "No answer from {h}. Is it awake and on this network?",
    "dns": "Can't find “{h}”.",
    "pair_failed": "That code wasn't accepted. Codes work once, for 10 minutes, and five wrong tries void them. Get a "
                   "new one there.",
    "too_many": "Twelve machines are connected. Disconnect one to add another.",
    "busy": "{n} has as many viewers as it serves at once. Try again in a minute.",
    "ssh": "ssh could not sign in to {h} without asking for something, and {b} never types a password. Try it in a "
           "terminal: ssh {t}",
    "identity_changed": "{h} answered with another key than the one shown: nothing was sent. Try again, and compare "
                        "the key with oomph share status there.",
    "revoked": "{n} no longer knows this computer: its access was revoked, or sharing was reset there. Pair again with "
               "a new code.",
    "bad_address": "That isn't an address. Type a host name, host:port or user@host, or paste a pairing link.",
    "ask": "Nothing was added. The pairing made just now was given back there and its code is used up: get a new one "
           "there to try again.",
}


def connect_message(code, target, detail="", side=None):
    """The connect dialog's words for what `oomph remote add --json` answered: the app's (01 §3.7's
    table), with "this Mac" read as "this computer"."""
    host = target.rpartition("@")[2]
    if host.startswith("ssh://"):
        host = host[6:]
    h = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    n = h.split(".")[0] or h
    b = BRAND or "?"
    if code == "not_oomph":
        if "@" in target or target.startswith("ssh://"):
            return ("{b} is not installed on {h}. Install it there, then try again." if "not installed" in detail
                    else "The {b} on {h} is too old for remote access. Update it there.").format(b=b, h=h)
        return "Something answers there, but it isn't %s." % b
    if code == "incompatible":
        return {"old": "{n}'s {b} is too old for remote access. Update it there.",
                "new": "{n}'s {b} is newer than this dashboard understands. Upgrade {b} here."}.get(
            side, "{n}'s {b} and this one can't talk to each other. Update the older one.").format(n=n, b=b)
    w = CONNECT_WORDS.get(code)
    if w:
        return w.format(h=h, n=n, t=target, b=b)
    return detail or "Connecting to %s failed." % h


def is_address(text):
    """A complete address by itself (04 §3.8): then nothing is completed and "as typed" is the
    highlighted row. An IPv4 or bracketed IPv6 literal, a name with a dot, user@host, a link."""
    t = text.strip()
    if t.startswith(("oomph://", "ssh://", "[")) or "@" in t:
        return True
    host = t.rsplit(":", 1)[0] if t.count(":") == 1 else t
    return "." in host.strip(".") or t.count(":") >= 2


def known_names(e):
    return [n for n in [e.get("label"), e.get("name"), e.get("host")] + list(e.get("addrs") or []) if isinstance(n, str) and n]


def connect_rows(text, known):
    """The rows under the address (04 §3.8): with nothing typed the Recents, else the machines of
    which a name, the host name or a remembered address starts with the text, then "as typed".
    Returns (rows, the row the highlight starts on): rows are ("known", entry, what matched) and
    ("typed", text)."""
    t = text.strip()
    if not t:
        rec = sorted((e for e in known if not e.get("pinned")), key=lambda e: -(_f(e.get("last_connected")) or 0))
        rows = [("known", e, label_of(e)) for e in rec[:5]]
        return rows, (0 if rows else None)
    low = t.lower()
    rows = []
    for e in known:
        hit = next((n for n in known_names(e) if n.lower().startswith(low)), None)
        if hit is not None:
            rows.append(("known", e, hit))
    rows = rows[:5] + [("typed", t)]
    return rows, (0 if len(rows) > 1 and not is_address(t) else len(rows) - 1)


def label_of(e):
    return e.get("label") or e.get("name") or e.get("host") or e.get("mid") or "?"


def _field(label, text, kw=10, fresh=False, cursor=True):
    """A text field: its label, the text (its tail, when longer), the cursor; a prefilled text
    that typing replaces is drawn selected."""
    def fn(fr, x, y, w, bg):
        fr.put(x, y, label, "dim", bg)
        room = max(1, w - kw - 1)
        g = GLYPHS["ascii" if fr.ascii_only else "unicode"]
        cells = cells_of(text, fr.ascii_only)
        shown = text if len(cells) <= room else g["ell"] + "".join(cells[-(room - 1):])
        if fresh and text:
            xx = fr.put(x + kw, y, shown, "fg", bg, REV)
        else:
            xx = fr.put(x + kw, y, shown, "fg", bg, BOLD)
        if cursor:
            fr.put(xx, y, " ", "fg", bg, REV if not (fresh and text) else 0)
    return fn


def _row(text, on, right=None, role="fg"):
    def fn(fr, x, y, w, bg):
        g = GLYPHS["ascii" if fr.ascii_only else "unicode"]
        text_, right_ = asc(text, fr), asc(right, fr)
        if on:
            fr.put(x, y, g["sel"], "accent", bg, BOLD)
        r = tw(right_) + 2 if right_ else 0
        fr.put(x + 2, y, fit(text_, max(1, w - 2 - r), g), role, bg, BOLD if on else 0)
        if right_ and w - 2 - r > 8:
            fr.rput(x + w - 1, y, right_, "dim", bg)
    return fn


def _line(text, role="dim"):
    return lambda fr, x, y, w, bg: fr.put(x, y, fit(asc(text, fr), w, GLYPHS["ascii" if fr.ascii_only else "unicode"]),
                                          role, bg)


def _mpara(text, w, pri, role="dim"):
    """A paragraph of a machines' dialog: _para with the ASCII punctuation where it is needed."""
    group = object()
    return [(pri, _line(line, role), group) for line in _wrap(text, w)]


def _cw(fr, bw, bh):
    """The width a dialog's lines have: inside the box, or the whole pane where the box does not fit."""
    return bw - 6 if fr.w >= bw + 2 and fr.h >= bh + 3 else fr.w - 2


def _err(ov, cw=62):
    """The dialog's error line (warning colour), or what it is doing (busy)."""
    if ov.get("busy"):
        return [(0, _line(ov["busy"], "dim"))]
    if ov.get("error"):
        return [(0, _line(l, "warntx")) for l in _wrap(ov["error"], cw)[:3]]
    return []


def overlay_connect(fr, caps, g, model, ov):
    """+: Connect to a machine (01 §3.7, mockups 07 and 08)."""
    cw = _cw(fr, 68, 16)
    text = ov.get("text", "")
    rows, start = connect_rows(text, model.get("book") or [])
    sel = ov.get("sel") if ov.get("sel") is not None else start
    lines = [(9, None), (0, _field("Address", text, fresh=ov.get("fresh", False), cursor=not ov.get("busy"))), (9, None)]
    if rows:
        head = "Recents" if not text.strip() else "Matches"
        hint = "enter connects" if not text.strip() else \
            "tab completes %s enter connects as typed" % g["mid"] if rows[-1][0] == "typed" and sel == len(rows) - 1 \
            else "tab completes %s enter connects" % g["mid"]
        lines.append((0, lambda fr, x, y, w, bg: (fr.put(x, y, head, "dim", bg),
                                                  fr.rput(x + w - 1, y, hint, "faint", bg) if w > 40 else None)))
        for i, r in enumerate(rows):
            if r[0] == "typed":
                lines.append((0, _row("+ connect to “%s” as typed" % r[1], i == sel)))
                continue
            e = r[1]
            about = (" %s " % g["mid"]).join(x for x in (
                (e.get("addrs") or [None])[0] if (e.get("addrs") or [None])[0] != label_of(e) else None,
                e.get("os_version") or (e.get("os") == "linux" and "Linux") or None,
                "%.0f GB" % e["ram_gb"] if _f(e.get("ram_gb")) else None) if x)
            last = _f(e.get("last_connected"))
            right = when(last, model.get("wall", model["now"])) if last else None
            lines.append((0, _row("%-10s %s" % (label_of(e), about), i == sel, right)))
    lines += _err(ov, cw)
    if not (len(rows) > 1 and text.strip() and is_address(text)) and rows and rows[-1][0] == "typed" and not ov.get("error"):
        lines.append((6, _line("    a new machine asks for a pairing code once", "faint")))
    lines.append((8, None))
    lines += _mpara("Encrypted direct connection, TCP port 6674. Nothing is sent until you press enter. For SSH "
                   "instead, type ssh://user@host or user@host.", cw, 5)
    return dialog(fr, g, caps, "Connect to a machine", 68, 16, lines,
                  [("esc", "cancel"), ("enter", "connect"), ("tab", "complete"), (g["updown"], "choose"),
                   ("^D", "forget")])


def show_code(code):
    groups = [code[i:i + 4] for i in range(0, len(code), 4)] or [""]
    return "  -  ".join(groups)


def overlay_pair(fr, caps, g, model, ov):
    """The pairing code (01 mockup 09): the command to run there, three groups of four, the key."""
    cw = _cw(fr, 68, 16)
    target = ov.get("target", "")
    h = target.rpartition("@")[2]
    lines = [(9, None)]
    if ov.get("revoked"):
        lines += _mpara("%s no longer knows this computer: its access was revoked, or sharing was reset there. Ask it "
                       "for a new one-time code:" % h, cw, 3)
    else:
        lines += _mpara("First connection to this machine. Sharing must be on there; then ask it for a one-time code:",
                       cw, 3)
    lines += [(9, None), (0, lambda fr, x, y, w, bg: (fr.put(x + 2, y, "sudo oomph share pair", "fg", bg, BOLD),
                                                      fr.rput(x + w - 1, y, "^Y copies", "faint", bg) if w > 40 else None)),
              (9, None), (0, _field("Code", show_code(ov.get("code", "")), kw=8, cursor=not ov.get("busy")))]
    lines += _err(ov, cw)
    lines += [(8, None)]
    lines += _mpara("Works once, for 10 minutes. The code also proves that nobody sits in between: a wrong machine "
                   "cannot answer it.", cw, 4)
    if ov.get("fp_short"):
        lines += [(8, None), (2, _line("Key %s  same as oomph share status there" % ov["fp_short"], "dim"))]
    return dialog(fr, g, caps, "Pair with %s" % h, 68, 16, lines,
                  [("esc", "back"), ("enter", "pair"), ("^Y", "copy the command")])


def overlay_ssh(fr, caps, g, model, ov):
    """Through SSH the dialog carries the consent (01's mockup 37): the command that will run."""
    cw = _cw(fr, 68, 12)
    t = ov.get("target", "")
    user, _, host = t[6:].rpartition("@") if t.startswith("ssh://") else t.rpartition("@")
    who = user or "you"
    cmd = "ssh %s-- %s oomph serve --stdio" % ("-l %s " % user if user else "", host)
    lines = [(9, None), (0, _line("    " + cmd, "fg")), (9, None)]
    lines += _mpara("Whoever can sign in to %s as %s can read what %s logs there; no pairing code is asked."
                   % (host, who, BRAND or "?"), cw, 2)
    lines += [(9, None)] + _err(ov, cw)
    return dialog(fr, g, caps, "Connect to %s over SSH" % host, 68, 12, lines,
                  [("esc", "back"), ("enter", "connect")])


def overlay_ask(fr, caps, g, model, ov):
    """A known machine id with another key is a question, never a merge (01 §4.5, mockup 29)."""
    cw = _cw(fr, 68, 12)
    lab = ov.get("label") or "?"
    lines = [(9, None)]
    lines += _mpara("It reports the same machine id as %s, but has a different key or address. That is normal after "
                   "reinstalling %s or resetting sharing there, and for cloned systems." % (lab, BRAND or "?"), cw, 3)
    lines += [(9, None), (0, _row("Add separately", ov.get("sel", 0) == 0, "keeps both, in two tabs")),
              (0, _row("Replace %s" % lab, ov.get("sel", 0) == 1, "keeps its history, trusts the new key")), (9, None)]
    return dialog(fr, g, caps, "Same machine as %s?" % lab, 68, 12, lines,
                  [("esc", "cancel"), ("enter", "confirm"), (g["updown"], "choose")])


def overlay_name(fr, caps, g, model, ov):
    """After a pairing: the tab's name, prefilled with the host name (selected: typing replaces)."""
    cw = _cw(fr, 68, 10)
    lines = [(9, None)]
    if ov.get("about"):
        lines.append((3, _line(ov["about"], "dim")))
        lines.append((9, None))
    lines += [(0, _field("Tab name", ov.get("text", ""), fresh=ov.get("fresh", False))), (9, None)]
    if ov.get("other"):
        lines += _mpara("It is not a Mac: the app gives it a tab once it knows that system's words; here it is a tab "
                       "now.", cw, 4)
    title = ("Paired with %s" if ov.get("kind") == "name" else "Rename %s") % (ov.get("name") or "?")
    return dialog(fr, g, caps, title, 68, 10, lines,
                  [("esc", "keep the name" if ov.get("kind") == "name" else "cancel"),
                   ("enter", "add" if ov.get("kind") == "name" else "rename")])


def overlay_forget(fr, caps, g, model, ov):
    """X: forgetting deletes the token needed to tell the other side later, so it says what is true
    for this link (04 §3.7)."""
    cw = _cw(fr, 66, 12)
    lab = ov.get("label") or "?"
    me = (model.get("tabs") or [{}])[0].get("label") or "this computer"
    lines = [(9, None), (0, _line("Forget %s?" % lab, "fg")), (9, None)]
    lines += _mpara("Its history on this computer is deleted, and connecting again needs a new pairing code.", cw, 4)
    if ov.get("ssh"):
        lines += _mpara("It was reached over SSH: nothing is kept there.", cw, 3)
    elif ov.get("connected"):
        lines += _mpara("%s is told to forget this computer." % lab, cw, 3)
    else:
        lines += _mpara("%s cannot be reached now, so it is not told: this computer stays in its list of paired machines "
                       "until `sudo oomph share revoke %s` is run there." % (lab, me), cw, 3)
    lines.append((9, None))
    return dialog(fr, g, caps, "Forget this machine", 66, 12, lines, [("esc", "keep"), ("n", "keep"), ("y", "forget")])


ATTENTION_TEXT = {
    "identity_changed": ("Its key changed.", "{n} answers with a different key than the one pinned when it was paired. "
                         "That is normal after reinstalling {b} or resetting sharing there. It is also what another "
                         "machine in its place would look like. Nothing is sent to it until you decide."),
    "revoked": ("Its access was revoked.", "{n} no longer knows this computer: its access was revoked, or sharing was "
                "reset there. Pair again with a new code from {n}."),
    "incompatible": ("Its {b} can't talk to this one.", "{n}'s {b} and this one don't speak the same version of the "
                     "protocol. Update the older one."),
    "ssh": ("SSH can't sign in.", "ssh could not sign in to {h} without asking for something, and {b} never types a "
            "password. Try it in a terminal: ssh {t}"),
    "refused": ("Sharing is off there.", "{n} answered, but sharing is off there. On {n}: sudo oomph share on."),
    "turned_away": ("Sharing is off there.", "{n} closed the connection right away. Sharing there is limited to the "
                    "networks it was turned on for: if {n} moved, run sudo oomph share on there."),
    "blocked": ("Blocked by macOS.", "If this terminal app is not allowed on the local network (System Settings › "
                "Privacy & Security › Local Network), that is the cause."),
}


def attention_keys(cause, ssh=False):
    """The ways out of a "what happened" card, each a key of its own."""
    k = []
    if cause in ("identity_changed", "revoked") and not ssh:
        k.append(("p", "pair again"))
    if cause in ("ssh", "refused", "turned_away", "blocked", "incompatible", "attention"):
        k.append(("r", "try again"))
    return k + [("X", "forget")]


def overlay_attention(fr, caps, g, model, ov):
    """enter on a tab with an orange capsule: 01's callout as a card (04 §3.7, mockup)."""
    cw = _cw(fr, 68, 16)
    sel = model.get("sel", 0)
    t, v = model["tabs"][sel], tab_views(model)[sel]
    lab = t.get("label") or "?"
    head, body = ATTENTION_TEXT.get(v["cause"], ("It needs attention.", "{n} can't be reached the usual way."))
    target = t.get("addr") or lab
    body = body.format(n=lab, h=target.rpartition("@")[2], t=target, b=BRAND or "?")
    head = head.format(b=BRAND or "?")
    lines = [(9, None), (0, _line(head, "fg")), (9, None)] + _mpara(body, cw, 3) + [(9, None)]
    known = _f(t.get("known"))
    lines.append((4, _line("Last data %s; what was received stays here." % (when(known, model["now"]) if known else "never"),
                           "dim")))
    keys = attention_keys(v["cause"], t.get("transport") == "ssh")
    return dialog(fr, g, caps, "%s needs attention" % lab, 68, 16, lines + [(9, None)], [("esc", "close")] + keys)


def list_rows_machines(model, filt):
    """The machine list's rows: (index, tab) of the tabs whose name or address contains the filter."""
    f = filt.strip().lower()
    return [(i, t) for i, t in enumerate(model["tabs"])
            if not f or f in (t.get("label") or "").lower() or f in (t.get("addr") or "").lower()]


def overlay_list(fr, caps, g, model, ov):
    """0: every machine in one list, with its address and state in words (04 §3.7)."""
    views = tab_views(model)
    rows = list_rows_machines(model, ov.get("filter", ""))
    sel = max(0, min(ov.get("sel", 0), len(rows) - 1))
    n = max(1, (fr.h - 8) if fr.w >= 74 and fr.h >= 24 else fr.h - 6)
    off = max(0, min(sel - n + 1, len(rows) - n)) if sel >= n else 0
    lines = [(9, None), (0, _field("Filter", ov.get("filter", ""), kw=8)), (9, None)]
    mono = caps.color == "none"
    for k, (i, t) in enumerate(rows[off:off + n]):
        v = views[i]

        def fn(fr, x, y, w, bg, i=i, t=t, v=v, on=(off + k == sel)):
            if on:
                fr.put(x, y, g["sel"], "accent", bg, BOLD)
            fr.rput(x + 4, y, str(i + 1), "fg", bg)
            xx = fr.put(x + 6, y, g["marks"][v["mark"]], None if mono else MARK_ROLE[v["mark"]], bg)
            if v["badge"]:
                fr.put(xx, y, "!", None if mono else "crit", bg, BOLD)
            words = asc(state_words(t, v), fr)
            fr.put(x + 9, y, fit(t.get("label") or "?", 14, g), "fg", bg, BOLD if on else 0)
            if w > 44:
                fr.put(x + 24, y, fit(t.get("addr") or "", max(4, w - 26 - tw(words) - 2), g), "dim", bg)
            fr.rput(x + w - 1, y, fit(words, max(4, w - 26), g), "dim" if v["live"] else "warntx" if v["attention"]
                    else "dim", bg)
        lines.append((0, fn))
    if not rows:
        lines.append((0, _line("  no machine matches", "faint")))
    return dialog(fr, g, caps, "Machines", 74, min(24, max(10, len(rows) + 8)), lines,
                  [("esc", "close"), ("enter", "show"), (g["updown"], "choose"), ("", "type to filter")])


def machine_help(g):
    """The help's third page: the machines' keys and marks."""
    m = g["marks"]
    keys = [("Machines", None), ("1%s9  0" % g["dash"], "a tab %s every machine" % g["mid"]),
            ("tab  n p", "next %s previous tab" % g["mid"]), ("+", "connect to a machine"),
            ("x  u", "disconnect %s undo" % g["mid"]), ("X", "forget it"), ("r", "retry now"), ("R", "rename the tab"),
            ("enter", "what happened there")]
    marks = [("Marks", None), ([(m["ok"], "ok"), (m["warn"], "warn"), (m["crit"], "crit")], "normal, warning, critical"),
             ([(m["silent"], "faint")], "its logger is silent"), ([(m["busy"], "accent")], "connecting, catching up"),
             ([(m["off"], "faint")], "not connected"), ([(m["att"], "warntx")], "needs attention"),
             ([("!", "crit")], "an incident is open there"), ([(g["miss"] * 2, "faint")], "not received")]
    return keys, marks


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
    """The help (04 §3.10), built from what this build has: the keys of T1, inspect and the mouse
    (T1b), no machines. Returns (left column, right column, 'what you see' rows)."""
    A, U = g["arrows"], g["updown"]
    left = [("Chart", None), ("%s %s" % (A[0], A[1]), "longer %s shorter" % g["mid"]),
            ("t  T", "cycle spans %s back" % g["mid"]), ("i", "inspect a moment"), ("", ""),
            ("Panels", None), ("a", "top apps"), ("s", "Claude sessions"), ("e", "events"),
            ("enter", "its processes"), ("", ""),
            ("General", None), ("?  F1", "help %s next page" % g["mid"]), ("esc", "close %s back" % g["mid"]),
            ("q  ctrl-c", "quit")]
    right = [("Lists", None), (U[1], "into Reservations"), (U[0], "into Incidents"),
             ("%s %s  j k" % (U[0], U[1]), "move in the list"), ("space", "the other list"),
             ("pgup pgdn", "a page"), ("home end", "first %s last row" % g["mid"]), ("enter", "details"),
             ("o", "open the report"), ("y", "copy its path"),
             ("Terminal", None), ("ctrl-o", "mouse on %s off" % g["mid"]), ("ctrl-l", "redraw"), ("ctrl-z", "suspend")]
    if model.get("rv"):         # the four resources (02 §3.7.12): the tiles' keys open the left column
        w = "net" in (model.get("avail") or ())     # w: the network (NET 12.16; n is the next machine)
        left = [("Resources", None), ("m c g d" + (" w" if w else ""), "one alone, with the plot"),
                ("M C G D" + (" W" if w else ""), "add %s remove" % g["mid"]), ("", "")] + left
    away = model.get("os", "").startswith("macOS") or "os" not in model
    see = [("Chart", None),
           ([(g["sw"], role) for _, role in series_words(model.get("cur"))], "%s, stacked; %s is the RAM" % (
               ", ".join(n for n, _ in series_words(model.get("cur"))), g["ram"][1]))]
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
    """Both pages (three with machines) as one column, for the full-pane form that scrolls."""
    left, right, see = help_pages(g, model)
    more = []
    if model.get("tabs"):
        keys, marks = machine_help(g)
        more = [("", "")] + keys + marks
    return [e for e in left + right if e != ("", "")] + [("", ""), ("What you see", None)] + see + more


def help_count(model):
    """How many pages the boxed help has: keys, what you see, and with machines their keys and marks."""
    return 3 if model.get("tabs") else 2


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
        page, npages = ov.get("page", 1), help_count(model)
        if page == 3:
            keys, marks = machine_help(g)

            def row3(i):
                def fn(fr, x, y, w, bg):
                    if i < len(keys):
                        entry(keys[i][0], keys[i][1], 11)(fr, x, y, 34, bg)
                    if i < len(marks):
                        entry(marks[i][0], marks[i][1], 4)(fr, x + 36, y, w - 36, bg)
                return fn
            rows = [(1, row3(i)) for i in range(15)]
        elif page == 1:
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
        nxt = page % npages + 1
        return dialog(fr, g, caps, ("Keys", "What you see", "Machines")[page - 1], 74, 21, lines,
                      [("esc", "close"), ("?", ("keys", "what you see", "machines")[nxt - 1]),
                       ("", "page %d of %d" % (page, npages))])
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

    rv = model.get("rv")
    amounts = asc(amounts_text(r, rv_pool(model)), fr) if rv else "%.1f GB" % gb
    mem = not rv or r.get("mem", True)      # with the resources on, memory facts only where it holds memory

    def head(fr, x, y, w, bg):
        fr.put(x, y, g["sw"] if r.get("granted") is not None else g["swq"], None if mono else res_role(model, r), bg)
        fr.put(x + 2, y, fit("%s  %s" % (amounts, r["purpose"]), w - 2, g), "fg", bg, BOLD)
    project = r.get("project") if isinstance(r.get("project"), str) else None
    lines = [(9, None), (0, head), (8, None)]
    if project:
        lines.append((1, _kv("Project", project)))
    lines.append((2, _kv("Holder", _holder_text(r))))
    if rv:                      # the vector card (02 §3.4.5): each resource it holds besides memory, and its advice
        lines += res_card_lines(r, now, fr, g)
    if len(r["segments"]) > 1:
        lines.append((3, _kv("Sizes", (" %s " % g["arrow"]).join(
            "%s %s" % (gfmt(s_gb), hhmm(t)) for t, s_gb in r["segments"][-4:]))))
    if r.get("ended") is not None:
        lines.append((0, _kv("Ended", "%s at %s" % ((r.get("outcome") or "ended").replace("_", " "), hhmm(r["ended"])))))
        if mem:
            lines.append((1, _kv("Peak", "%.1f GB" % _gb(r.get("peak")))))
        if r.get("granted") is not None:
            lines.append((2, _kv("Ran", "%s, after waiting %s" % (ago(r["ended"] - r["granted"]),
                                                                     ago(r["granted"] - r["requested"])))))
    elif r.get("granted") is None:
        ahead = [w_ for w_ in waiting if _queue_key(w_) < _queue_key(r)]
        if rv:                  # ahead of it: those that wait for a resource it asks for too (02 §6.4)
            ahead = [w_ for w_ in ahead if any(holds(w_, k) and holds(r, k) for k in BAND_RES)]
        st = model.get("ledger_state") or {}
        owed = sum(max(0.0, x_["segments"][-1][1] - _gb(x_.get("used"))) for x_ in granted)
        lines.append((0, _kv("Waiting", "%s, %s" % (ago(now - r["requested"]), "first in the queue" if not ahead else
                                                    "behind %d in the queue" % len(ahead)), "warntx")))
        if rv and r.get("waiting"):     # what it waits for (02 §3.4.6): "Waits for  CPU and disk"
            lines.append((0, _kv("Waits for", _and([RES_WORD[k] for k in r["waiting"]]), "warntx")))
        if mem and isinstance(st.get("free_gb"), (int, float)) and isinstance(st.get("margin_gb"), (int, float)):
            avail = st["free_gb"] - owed - st["margin_gb"]
            lines += [(1, _kv("Needs", "%.1f GB; %.1f GB can be granted now" % (gb, max(0.0, avail)))),
                      (2, _kv("", "%.1f GB free, %.1f GB still owed to grants, %.1f GB margin"
                              % (st["free_gb"], owed, st["margin_gb"]), "dim"))]
        elif mem:
            lines.append((1, _kv("Needs", "%.1f GB" % gb)))
        lines.append((3, _kv("Ahead", "nobody: it is granted as soon as it fits" if not ahead else
                             ", ".join("%s %s" % (a["purpose"], asc(amounts_text(a), fr) if rv else
                                                  gfmt(a["segments"][-1][1])) for a in ahead[:3]) +
                             (" %s" % g["ell"] if len(ahead) > 3 else ""))))
        if granted and mem:
            big = sorted(granted, key=lambda x_: -x_["segments"][-1][1])
            lines.append((2, _kv("Holding", ", ".join("%s %s" % (x_["purpose"], gfmt(x_["segments"][-1][1]))
                                                      for x_ in big[:3]) + (" %s" % g["ell"] if len(big) > 3 else ""))))
    else:
        if mem:
            lines.append((0, _kv("Using", "%.1f GB now %s peak %.1f GB" % (_gb(r.get("used")), g["mid"],
                                                                         _gb(r.get("peak"))))))
        lines.append((1, _kv("Granted", "%s, after waiting %s" % (hhmm(r["granted"]), ago(r["granted"] - r["requested"])))))
        if r.get("expires") is not None:
            lines.append((1, _kv("Expires", "in %s, unless its holder renews it" % left_of(r["expires"] - now))))
    lines += [(4, _kv("Requested", "%s as %s" % (time.strftime("%H:%M:%S", _lt(r["requested"])), r.get("id") or "?"))),
              (9, None)]
    return dialog(fr, g, caps, "Reservation", 76, len(lines) + 3, lines,
                  [("esc", "close"), (g["updown"], "previous %s next" % g["mid"])])


def res_card_lines(r, now, fr, g):
    """A reservation card's lines for its cores, its disk space and its advice (the app's ReservationCard)."""
    out = []
    live = r.get("ended") is None and r.get("granted") is not None
    if r.get("cpu") is not None:
        out.append((1, _kv("Cores", cores_words(r["cpu"]) + (" %s using %s" % (g["mid"], cores_words(r["cpu_used"]))
                                                            if live and r.get("cpu_used") is not None else ""))))
    if r.get("disk") is not None:
        out.append((1, _kv("Disk", "%s on %s" % (amt_g(r["disk"]), mid_fit(asc(r.get("pool_name") or r.get("pool") or "?", fr),
                                                                          24)) +
                           (" %s wrote %s" % (g["mid"], amt_g(r["disk_w"])) if live and r.get("disk_w") is not None else ""))))
    if holds(r, "net"):         # NET 12.15: its rate and volume, what it moved and when it should be done
        fig = use_figure(r, "net", now) if live else None
        out.append((1, _kv("Network", asc(" · ".join(net_amounts(r)), fr) +
                           (" %s %s" % (g["mid"], asc(fig, fr)) if fig else "") +
                           (" %s unmanaged: the line has no figure" % g["mid"] if r.get("net_unmanaged") else ""))))
    for k, (f, since) in sorted((r.get("flags") or {}).items()) if live else ():
        out.append((0, _kv("Advice", advice_words(k, f, since, now), "warntx")))
    return out


def advice_words(k, f, since, now):
    """Reservation.adviceWords: "over on CPU since 13:26: its processes use more than it got", "idle on CPU for
    12 min: it could be released"."""
    if f == "idle":
        return "idle on %s%s: it could be released or made smaller" % (RES_WORD[k], " for " + duration(now - since)
                                                                      if since is not None else "")
    return "over on %s%s: %s" % (RES_WORD[k], " since " + hhmm(since) if since is not None else "",
                                 "it wrote more than it reserved" if k == "disk" else "it uses more than it got")


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
    res = []                                    # the other resources' peaks (1.9.5): only where recorded
    if s.get("cpu") is not None:
        res.append("cores %.1f%s" % (s["cpu"], " of %d" % s["cpu_n"] if s.get("cpu_n") else ""))
    if s.get("gpu_util") is not None:
        res.append("GPU %.0f %% of full speed" % s["gpu_util"])
    elif s.get("gpu_busy") is not None:
        res.append("GPU busy %.0f %%" % s["gpu_busy"])
    if s.get("data_free") is not None:
        res.append("Data %.1f GB free" % s["data_free"])
    if res:
        lines.append((3, _kv("Resources", (" %s " % g["mid"]).join(res))))
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
    if kind == "a" and len(item) == 5:          # a name on the internet line: its processes there (NET 12.16)
        name, _, n, d, u = item
        mine = [p for p in (model.get("cur") or {}).get("top_net") or [] if p[1] == name or p[4] == name]
        lines = [(9, None), (0, _text(asc("↓%s ↑%s Mbit/s in %d process%s" % (mbps(d), mbps(u), n, "" if n == 1 else "es"),
                                          fr), "fg", BOLD)), (8, None)]
        for p in mine[:8]:
            lines.append((1, _kv(asc("↓%s ↑%s" % (mbps(p[2]), mbps(p[3])), fr), "%s  (pid %d)" % (p[1], p[0]), "fg", 14)))
        if not mine:
            lines.append((1, _text("none among the busiest processes of the last sample", "dim")))
        lines.append((9, None))
        return dialog(fr, g, caps, fit(name, 60, g), 76, len(lines) + 3, lines,
                      [("esc", "close"), (g["updown"], "previous %s next" % g["mid"])])
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


# ------------------------------------------------------------------ inspect: the keyboard's hover card (04 §3.9)
# The readout is the app's hover card (MemoryChart.hoverInfo), held to it by the "hover" group of
# tools/vectors/chart.json: the same column of time, the same readings, words and caps.
def duration(sec):
    """MemoryChart.duration: '45 s', '12 min', '3 h 20 min', '11 h', '2 d 4 h'."""
    s_ = int(math.floor(sec + 0.5)) if sec >= 0 else -int(math.floor(-sec + 0.5))   # Swift's rounded(): half away from 0
    if s_ < 90:
        return "%d s" % s_
    if s_ < 3600:
        return "%d min" % (s_ // 60)
    if s_ < 86400:
        return "%d h" % (s_ // 3600) if s_ % 3600 // 60 == 0 or s_ >= 36000 else "%d h %d min" % (s_ // 3600, s_ % 3600 // 60)
    d, h = s_ // 86400, s_ % 86400 // 3600
    return "%d d" % d if h == 0 else "%d d %d h" % (d, h)


def time_at(u, f, first, now):
    """TimeAxis.time(at:): the time at x = u, by bisection over [first - 1, now] (the mapper is
    monotonic), clamped to that range."""
    lo, hi = first - 1, now
    if u >= f(hi):
        return hi
    if u <= f(lo):
        return lo
    for _ in range(50):
        mid = (lo + hi) / 2
        if f(mid) < u:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def _between(a, lo, hi, key):
    """The elements of a sorted list with key in lo...hi (MemoryChart.slice)."""
    i = bisect.bisect_left([key(x) for x in a], lo) if a else 0
    out = []
    for x in a[i:]:
        if key(x) > hi:
            break
        out.append(x)
    return out


ChartEv = collections.namedtuple("ChartEv", "t kind text alarming kills top seconds")
ChartEv.__doc__ = """One line of events.jsonl as the app's ChartEvent has it (a tuple: the inspector keeps thousands)."""
HOVER_SERIES = (("App", "app"), ("Compressed", "comp"), ("Wired", "wired"), ("Swap", "swap"))


def hover_series(cur):
    """The hover's and the readout's series, top to bottom, (name, point key): on Linux in its words, only
    those the machine has (series_words)."""
    if (cur or {}).get("linux") is None:
        return HOVER_SERIES
    have = dict((role, n) for n, role in series_words(cur))
    return tuple((have[k], k) for k in ("app", "comp", "wired", "swap") if k in have)


def hover_info(pts, gaps, incidents, events, blocks, now, first, f, u, du, max_res=4, max_ev=6, series=HOVER_SERIES,
               avail_of=None):
    """MemoryChart.hoverInfo: everything under one column of the plot (u: its middle, du: its width,
    both in 0…1), aggregated, since on the log axis one column can hold hours. pts: the thinned points;
    gaps: (from, to); incidents: as load_incidents gives them; events: ChartEv, oldest first; blocks: stack_reservations' output.
    `series` and `avail_of` (a Linux machine's RAM: what is available in place of the peak, 03 §3.9) its words."""
    t0, t1 = time_at(max(u - du / 2, 0), f, first, now), time_at(min(u + du / 2, 1), f, first, now)
    tc = (t0 + t1) / 2
    info = {"t0": t0, "t1": t1, "tc": tc}
    if t1 - t0 < 90:
        info["when"] = "%s %s" % (day_label(tc), hhmm(tc))
    elif _lt(t0)[:3] == _lt(t1)[:3]:
        info["when"] = "%s %s–%s" % (day_label(t0), hhmm(t0), hhmm(t1))
    else:
        info["when"] = "%s %s – %s %s" % (day_label(t0), hhmm(t0), day_label(t1), hhmm(t1))
    info["ago"] = "now" if now - tc < 90 else duration(now - tc) + " ago"
    gap_here = next((g for g in gaps if g[0] < tc < g[1]), None)
    here = _between(pts, t0, t1, lambda p: p["t"])
    if not here and gap_here is None and pts:
        i = bisect.bisect_left([p["t"] for p in pts], tc)
        cand = [pts[k] for k in (i - 1, i) if 0 <= k < len(pts)]
        if cand:
            before = [p for p in cand if p["t"] < tc]
            after = [p for p in cand if p["t"] >= tc]
            near = (before[-1] if before and (not after or tc - before[-1]["t"] <= after[0]["t"] - tc)
                    else after[0] if after else before[-1])
            if abs(near["t"] - tc) <= 60:
                here = [near]
    info["samples"] = len(here)
    info["readings"], info["away"], info["peak"] = [], False, 0.0
    if here:
        info["readings"] = [(name, min(p[k] for p in here), max(p[k] for p in here)) for name, k in series]
        if avail_of:
            av = [max(0.0, avail_of - p["wired"] - p["app"] - p["comp"]) for p in here]
            info["avail"] = (min(av), max(av))
        info["away"] = any(p["away"] for p in here)
        info["peak"] = max(p["wired"] + p["app"] + p["comp"] + p["swap"] for p in here)
    over = [g for g in gaps if g[0] < t1 and g[1] > t0]
    info["no_data"] = None
    if len(over) == 1:
        info["no_data"] = "no data %s–%s (%s)" % (hhmm(over[0][0]), hhmm(over[0][1]), duration(over[0][1] - over[0][0]))
    elif len(over) > 1:
        info["no_data"] = "%d stretches without data, %s in all" % (len(over), duration(sum(b - a for a, b in over)))
    e0, e1 = time_at(max(u - 3 * du, 0), f, first, now), time_at(min(u + 3 * du, 1), f, first, now)
    info["incidents"] = ["incident " + hhmm(i["start"]) + (": " + i.get("desc", "") if i.get("nreasons", 1 if i.get("desc")
                                                                                              else 0) else "")
                         for i in incidents if i["start"] <= e1 and (i["end"] if i.get("end") is not None else now) >= e0]
    lines, order, by = [], [], {}
    for e in _between(events, e0, e1, lambda e: e.t):
        if e.kind not in by:
            order.append(e.kind)
        by.setdefault(e.kind, []).append(e)
    for k in order:
        es = by[k]
        if len(es) == 1:
            lines.append((es[0].text, es[0].alarming))
        elif k == "jetsam":
            kills, top = sum(e.kills for e in es), {}
            for e in es:
                for name, n in (e.top or {}).items():
                    top[name] = top.get(name, 0) + n
            names = ", ".join("%s ×%d" % kv for kv in sorted(top.items(), key=lambda kv: -kv[1])[:2])
            lines.append(("%d killed by jetsam" % kills + (" · " + names if names else "") if kills > 0 else
                          "%d jetsam reports" % len(es), True))
        elif k == "pressure_change":
            lines.append(("pressure changed %d× · last: " % len(es) + es[-1].text.replace("pressure ", ""), False))
        elif k in ("sleep_gap", "stall"):
            lines.append(("%s %d×, %s in all" % ("system stalled" if k == "stall" else "asleep", len(es),
                                                duration(sum(e.seconds for e in es))), es[0].alarming))
        else:
            lines.append(("%s ×%d" % (es[-1].text, len(es)), es[0].alarming))
    info["events"], info["more_events"] = lines[:max_ev], max(len(lines) - max_ev, 0)
    res = [b for b in blocks if b["res"]["requested"] <= t1 and b["end"] >= t0]
    info["reserved"] = []
    for b in res[:max_res]:
        r = b["res"]
        queued = (r["granted"] if r.get("granted") is not None else float("inf")) > tc
        info["reserved"].append(("%.1f GB " % gb_at(r, min(max(tc, r["requested"]), b["end"])) + r["purpose"] +
                                 (" (queued)" if queued else ""), res_color(r["purpose"])))
    info["more_reserved"] = max(len(res) - max_res, 0)
    return info


def inspect_geometry(model, ui, P):
    """(mapper, its inverse, first, plot width, the cursor's column) while inspecting."""
    now = model["now"]
    first = model.get("first") or (model["pts"][0]["t"] if model["pts"] else now)
    f, finv = mapper(now, first, SPANS[ui["span"]])
    W = P["plot_w"]
    t = (ui.get("inspect") or {}).get("t", now)
    col = max(0, min(W - 1, int(f(t) * W))) if f(t) < 1 else W - 1
    return f, finv, first, W, col


def inspect_info(model, ui, P, max_res=6):
    f, finv, first, W, col = inspect_geometry(model, ui, P)
    cur = model.get("cur")
    lin = (cur or {}).get("linux") is not None
    return hover_info(model["pts"], model["gaps"], model["incidents"], model.get("cevents") or [], model.get("blocks") or [],
                      model["now"], first, f, (col + 0.5) / W, 1.0 / W, max_res=max_res, series=hover_series(cur),
                      avail_of=model.get("ram") if lin else None), col


def inspect_at(ui, model, P, col):
    """The cursor to column `col` (clamped); it remembers the time in the middle of that column, so it
    stays on that time when the span changes."""
    f, finv, first, W, _ = inspect_geometry(model, ui, P)
    col = max(0, min(W - 1, col))
    ui["inspect"] = {"t": model["now"] if col == W - 1 else finv((col + 0.5) / W)}
    return ui


def inspect_key(ui, key, model, P):
    """A key while inspecting (04 §3.9): ← → by a column, shift-← → (or < >) by ten, home / end the oldest
    column and now, enter selects the incident or reservation under the cursor and leaves, esc (or i)
    leaves. Returns True when the key was the inspector's."""
    col = inspect_geometry(model, ui, P)[4]
    step = {"left": -1, "right": 1, "shift-left": -10, "shift-right": 10, "<": -10, ">": 10}
    if key in step:
        inspect_at(ui, model, P, col + step[key])
    elif key in ("home", "end"):
        inspect_at(ui, model, P, 0 if key == "home" else P["plot_w"] - 1)
    elif key in ("esc", "i"):
        ui.pop("inspect", None)
    elif key == "enter":
        info, _ = inspect_info(model, ui, P)
        ui.pop("inspect", None)
        return inspect_select(ui, model, P, info)
    else:
        return False
    return True


def inspect_select(ui, model, P, info):
    """enter: the incident under the cursor (the newest), else the reservation, selected in its list."""
    e0, e1 = info["t0"], info["t1"]
    for i, inc in enumerate(model["incidents"]):
        if inc["start"] <= e1 and (inc["end"] if inc.get("end") is not None else model["now"]) >= e0 and P["I"]:
            ui.update(focus="inc", inc_sel=i)
            press(ui, "noop", model, P)
            return True
    seq = res_seq(model)[0]
    for i, r in enumerate(seq):
        end = r["ended"] if r.get("ended") is not None else model["now"]
        if r["requested"] <= e1 and end >= e0 and P["R"]:
            ui.update(focus="res", res_sel=i)
            press(ui, "noop", model, P)
            return True
    ui["note"] = ("nothing to select there", "dim")
    return True


def _readout_lines(info, model, g, caps, nw=11):
    """The readout as two groups of (priority, [(text, role)] parts), the lower the number the longer a
    line stays: the readings (one series a line, the peak against the RAM, away, no data), and what
    happened (incidents, reservations, events). nw: the width of the series' names."""
    mono = caps.color == "none"
    left, right = [], []
    for k, (name, lo, hi) in enumerate(info["readings"]):
        role = {"App": "app", "Compressed": "comp", "Wired": "wired", "Kernel": "wired", "Swap": "swap"}[name]
        a, b = "%.1f" % lo, "%.1f" % hi
        left.append((1 + k + (3 if name == "Swap" and hi == 0 else 0),
                     [(g["sw"] + " ", None if mono else role), (name.ljust(nw), "fg"),
                      ("%s GB" % (b if a == b else "%s to %s" % (a, b)), "fg")]))
    if info["readings"] and info.get("avail"):   # Linux (03 §3.9): what was available, in place of the peak
        a, b = "%.1f" % info["avail"][0], "%.1f" % info["avail"][1]
        left.append((5, [("available %s GB" % (b if a == b else "%s to %s" % (a, b)), "dim")] +
                     ([(" %s away" % g["mid"], "dim")] if info["away"] else [])))
    elif info["readings"]:
        ram = model.get("ram") or 0
        left.append((5, [("%s %.1f%s GB" % ("peak" if info["samples"] > 1 else "all four", info["peak"],
                                            " of %.0f" % ram if ram else ""),
                          "crit" if ram and info["peak"] > ram else "dim")] +
                     ([(" %s away" % g["mid"], "dim")] if info["away"] else [])))
    if info["no_data"]:
        left.append((2, [(info["no_data"], "dim")]))
    if not info["readings"] and not info["no_data"]:
        left.append((2, [("no readings here", "dim")]))
    for t in info["incidents"][:2]:
        right.append((1, [(g["dot"] + " ", "incident"), (t, "incident")]))
    for i, (r, color) in enumerate(info["reserved"]):
        right.append((3 + i, [(g["sw"] + " ", None if mono else color), (r, "fg")]))
    if info["more_reserved"]:
        right.append((9, [("+ %d more reserved" % info["more_reserved"], "faint")]))
    for i, (t, alarm) in enumerate(info["events"]):
        right.append((4 + i, [(g["mid"] + " ", "faint"), (t, "incident" if alarm else "fg")]))
    if info["more_events"]:
        right.append((10, [("+ %d more kinds of events" % info["more_events"], "faint")]))
    return left, right


def _fit_lines(lines, n):
    """At most n lines, the highest priorities giving way first (the last of equals first); the order kept."""
    lines = list(lines)
    while len(lines) > max(n, 0):
        worst = max(range(len(lines)), key=lambda i: (lines[i][0], i))
        del lines[worst]
    return [parts for _, parts in lines]


def _draw_parts(fr, x, y, w, parts, g, bg=KEEP):
    end = x + w
    for text, role in parts:
        if x >= end:
            break
        x = fr.put(x, y, fit(text, end - x, g), role, bg)
    return x


def _readings_count(info):
    return "%d readings in this column" % info["samples"] if info["samples"] > 1 else \
        "1 reading" if info["samples"] == 1 else "no reading"


def draw_inspect(fr, model, ui, P, caps, g):
    """The cursor on the plot and the strip, and the readout: docked where the lists are, so the chart,
    its time axis and the strip stay in view (from 72 columns in two columns: the readings, and what
    happened); a floating card on the side away from the cursor where the pane has no list area. The
    readout is hover_info's, the app's hover card."""
    info, col = inspect_info(model, ui, P)
    x0 = P["plot_x"]
    fr.flag(x0 + col, P["plot_y"], 1, P["plot_h"], REV)
    if P["S"]:
        fr.flag(x0 + col, P["strip_y"], 1, P["S"], REV)
    fr.put(x0 + col, P["axis_y"], g["up"], "accent", KEEP, BOLD)
    y0, rows, where = panel_area(P)
    lw = P["lw"]
    if where == "lists":
        fr.fill(1, y0 + 1, lw - 2, rows, " ", None, None)
        for yy in range(y0 + 1, y0 + 1 + rows):
            fr.put(0, yy, g["v"], "line")
            fr.put(lw - 1, yy, g["v"], "line")
        right = "%s %s %s" % (info["ago"], g["mid"], _readings_count(info))
        if tw(right) + tw(info["when"]) + 20 > lw:
            right = info["ago"]
        section(fr, 0, y0, lw, g, "Inspect %s %s" % (g["mid"], info["when"]) if lw >= 64 else info["when"], right)
        left, rest = _readout_lines(info, model, g, caps)
        if lw >= 72:
            lw_ = min(36, (lw - 4) // 2)
            for i, parts in enumerate(_fit_lines(left, rows)):
                _draw_parts(fr, 2, y0 + 1 + i, lw_, parts, g)
            for i, parts in enumerate(_fit_lines(rest, rows)):
                _draw_parts(fr, 2 + lw_ + 2, y0 + 1 + i, lw - 6 - lw_, parts, g)
        else:
            for i, parts in enumerate(_fit_lines(left + [(p + 0.5, x) for p, x in rest], rows)):
                _draw_parts(fr, 2, y0 + 1 + i, lw - 4, parts, g)
        return info
    left, rest = _readout_lines(info, model, g, caps, nw=11)
    right_side = col < P["plot_w"] // 2                 # the app's card changes sides at the middle
    side = (lw - 1) - (x0 + col + 2) if right_side else (x0 + col - 1) - 1
    cw = max(20, min(40, side))
    room = P["axis_y"] - P["plot_y"] + 1                # from the plot's top to the time axis: the strip stays
    body = _fit_lines([(0, [(_readings_count(info) + " %s " % g["mid"] + info["ago"], "dim")])] + left +
                      [(p + 0.5, x) for p, x in rest], room - 2)
    ch = len(body) + 2
    cx = x0 + col + 2 if right_side else x0 + col - 1 - cw
    cx, cy = max(1, min(cx, lw - 1 - cw)), P["plot_y"]
    fr.fill(cx, cy, cw, ch, " ", None, "bar")
    fr.box(cx, cy, cw, ch, g, "dim")
    fr.bg(cx, cy, cw, ch, "bar")
    fr.put(cx + 2, cy, " %s " % fit(info["when"], cw - 6, g), "fg", "bar", BOLD)
    for i, parts in enumerate(body):
        _draw_parts(fr, cx + 2, cy + 1 + i, cw - 4, parts, g, "bar")
    return info


# ------------------------------------------------------------------ the mouse (04 §3.10): buttons and the wheel, no motion
def span_hits(P, ui, g, w=None):
    """[(span key, first column, last column)] of the span selector in the chart's top edge."""
    x, w = 0, P["lw"] if w is None else w
    cx = x + 2
    if w >= 100:
        cx += tw(" Memory ") + 1
    labels = [(k, " %s " % (g["inf"] if k == "inf" else k)) for k in SPAN_ORDER]
    if cx + sum(len(lab) for _, lab in labels) > x + w - 2:
        labels = [(k, "%s%s%s" % (g["more_l"], lab.strip(), g["more_r"])) for k, lab in labels if k == ui["span"]]
    out = []
    for key, lab in labels:
        out.append((key, cx, cx + tw(lab) - 1))
        cx += tw(lab)
    return out


def mouse(ui, model, P, g, button, x, y):
    """A button pressed at cell (x, y), 0-based. Returns what the program must do beyond `ui`:
    ("span", key), ("card",) or None. Left button: a span in the chart's edge chooses it; the plot, the
    strip or the time axis inspects that column; a row of a list or a panel selects it, and a click
    on the selected row opens it; a list's caption moves into it. The wheel over the chart changes the
    span (up: shorter), over a list or a panel scrolls it."""
    wheel = button & 64
    if button & 32:                                  # motion: never asked for
        return None
    px, pw = P["plot_x"], P["plot_w"]
    in_chart_cols = px <= x < px + pw
    chart_rows = [P["box_y"], P["axis_y"]] + list(range(P["plot_y"], P["plot_y"] + P["plot_h"])) + \
        (list(range(P["strip_y"], P["strip_y"] + P["S"])) if P["S"] else [])
    if x >= P["lw"]:
        return None
    if wheel:
        up = button & 1 == 0
        if y in chart_rows or (y == P["cap_y"] and P["S"]):
            i = SPAN_ORDER.index(ui["span"]) + (1 if up else -1)
            if 0 <= i < len(SPAN_ORDER):
                return ("span", SPAN_ORDER[i])
            return None
        key = "up" if up else "down"
        if ui.get("panel"):
            press(ui, key, model, P)
        elif P["R"] and P["list_y"] <= y < P["list_y"] + P["R"]:
            ui["focus"] = "res"
            ui.setdefault("res_sel", 0)
            press(ui, key, model, P)
        elif P["I"] and P["inc_y"] <= y < P["inc_y"] + P["I"]:
            ui["focus"] = "inc"
            ui.setdefault("inc_sel", 0)
            press(ui, key, model, P)
        return None
    if button & 3 != 0:                              # the middle and right buttons do nothing
        return None
    if y == P["box_y"]:
        for key, a, b in span_hits(P, ui, g):
            if a <= x <= b:
                return ("span", key)
        return None
    if y in chart_rows and in_chart_cols:
        if ui.get("panel"):                          # the readout takes the panel's place
            press(ui, "esc", model, P)
        inspect_at(ui, model, P, x - px)
        return None
    ui.pop("inspect", None)
    if ui.get("panel"):
        y0, rows, _ = panel_area(P)
        if ui["panel"] in ("a", "s") and y0 < y <= y0 + rows:
            items = panel_items(model, ui["panel"])
            body, ncol, per = panel_page(P, model, ui["panel"])
            cw = (P["lw"] - 2) // ncol
            i = ui.get("panel_off", 0) + (y - y0 - 1) + body * min(ncol - 1, max(0, (x - 1) // max(cw, 1)))
            if (y - y0 - 1) < body and 0 <= i < len(items):
                again = ui.get("focus") == "panel" and ui.get("panel_sel") == i
                ui.update(focus="panel", panel_sel=i)
                return ("card",) if again else None
        return None
    if P["R"] and P["list_y"] <= y < P["list_y"] + P["R"]:
        rows = list_rows(model, P["R"], ui)[0]
        k = y - P["list_y"]
        if k < len(rows):
            row = rows[k]
            if row[0] == "res":
                again = ui.get("focus") == "res" and ui.get("res_sel") == row[2]
                ui.update(focus="res", res_sel=row[2])
                return ("card",) if again else None
            if row[0] == "other":                     # "On other resources": its words are all there is
                return None
            ui["focus"] = "res"                       # "n more": into the list, at the first not shown
            ui["res_sel"] = row[1] + k
            press(ui, "noop", model, P)
        return None
    if P["I"] and P["inc_y"] <= y < P["inc_y"] + P["I"]:
        off = min(ui.get("inc_off", 0), max(len(model["incidents"]) - P["I"], 0))
        i = off + y - P["inc_y"]
        if i < len(model["incidents"]):
            again = ui.get("focus") == "inc" and ui.get("inc_sel") == i
            ui.update(focus="inc", inc_sel=i, inc_off=off)
            return ("card",) if again else None
        return None
    for cap, want in ((P["cap_y"], "res"), (P["inc_cap_y"], "inc")):
        if cap is not None and y == cap:
            press(ui, "esc", model, P)
            press(ui, "down" if want == "res" else "up", model, P)
            if ui.get("focus") != want:
                press(ui, "space", model, P)
            return None
    return None


# ------------------------------------------------------------------ the frame
def keys_main(g, model):
    """The hints of the key line, most useful first. While pressure is not normal or an incident is
    open, `s sessions` moves up: "what is using the memory?" is the question then."""
    cur = model.get("cur") or {}
    hot = cur.get("pressure") not in (None, "Normal") or any(i["open"] for i in model["incidents"])
    apps = "groups" if (model.get("cur") or {}).get("linux") is not None else "apps"
    k = [("q", "quit"), ("?", "help"), ("a", apps)]
    if hot:
        k.append(("s", "sessions"))
    k += [(g["arrows"], "span"), (g["updown"], "select")]
    if not hot:
        k.append(("s", "sessions"))
    k += [("e", "events"), ("i", "inspect")]
    if not model.get("tabs"):
        return k
    sel = model.get("sel", 0)
    t, v = model["tabs"][sel], tab_views(model)[sel]
    on = model.get("engine") == "on"
    if several(model):
        k.insert(k.index((g["updown"], "select")) + 1, ("tab", "machine"))
    if t.get("local") or v["live"] or v["phase"] == "grace":
        return k + ([("+", "add")] if on else [])
    lead = [("q", "quit"), ("?", "help")]
    if v["attention"]:
        lead.append(("enter", "what happened"))
    elif v["retry"] and on:
        lead.append(("r", "retry now"))
    lead += [("x", "disconnect"), ("X", "forget")] if on else []
    rest = [x for x in k if x[0] not in ("q", "?")]
    return lead + [x for x in rest if x[0] == "tab"] + ([("+", "add")] if on else []) + [x for x in rest if x[0] != "tab"]


def keys_of(g, model, ui, P):
    """The key line of the mode the dashboard is in; every mode but the plain view starts with esc
    and where it leads."""
    if ui.get("inspect"):
        A = g["arrows"]
        return [("esc", "back"), (A, "move"), ("shift-" + A, "by 10"), ("home end", "oldest %s now" % g["mid"]),
                ("t", "span"), ("enter", "select"), ("q", "quit")]
    if ui.get("panel"):
        where = panel_area(P)[2]
        k = [("esc", where)]
        apps = "groups" if (model.get("cur") or {}).get("linux") is not None else "apps"
        k += [(p, {"a": apps, "s": "sessions", "e": "events"}[p]) for p in "ase" if p != ui["panel"]]
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
    if model.get("remote"):              # another machine: the machine line says how it is
        return None, "faint"
    if ui.get("readonly"):
        return ui["readonly"], "warntx"
    lg = model.get("logger")
    if lg == "off":
        return model.get("off_text") or "Logging is off", "warntx"
    if lg == "silent":
        return "Logger not reporting since %s" % hhmm(model.get("logger_t") or model["now"]), "warntx"
    if several(model):                   # the machine line says it
        return None, "faint"
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
    fr = Frame(W, H, caps.glyphs == "ascii", caps.glyphs == "cp437")
    lines = ["oomph top", "needs 40 x 10", "this is %d x %d" % (W, H)]
    for i, text in enumerate(lines):
        fr.put(max((W - len(text)) // 2, 0), max(H // 2 - 1, 0) + i, text, "fg" if i == 0 else "dim", None,
               BOLD if i == 0 else 0)
    return fr


def layout(model, W, H):
    """The row plan for this model at this size (its slow facts: reservations and incidents on record;
    with the resources on, how many small rows the selection asks for)."""
    return plan(W, H, has_res=bool(model["res"]), has_inc=bool(model["incidents"]), mline=several(model),
                spark=len(rv_others(model)))


def rv_shown(model):
    """(the resources shown, the focus) with the resources on, over the tiles this machine has."""
    rv = model.get("rv") or {}
    return selection_shown(rv.get("sel") or ["memory"], rv.get("focus"), model.get("avail") or available(None))


def rv_others(model):
    """The shown resources other than the focus, in tile order: the small rows under the plot."""
    if not model.get("rv"):
        return []
    shown, focus = rv_shown(model)
    return [r for r in shown if r != focus]


def render(model, W, H, caps, ui):
    """The whole frame: a pure function of the model, the size, the terminal's capabilities and the
    ui state ({"span": "24h"} and, while running, the selection, the panel, the dialog, a note).
    model: see oomph_top.load_model. The frame's `yhold` is what the loop keeps for the next one."""
    g = GLYPHS[caps.glyphs]
    if W < 40 or H < 10:
        return too_small(W, H, caps)
    fr = Frame(W, H, caps.glyphs == "ascii", caps.glyphs == "cp437")
    P = layout(model, W, H)
    if model.get("tabs"):
        machine_tabs(fr, model, caps, g)
        if P["mline"]:
            machine_line(fr, 1, model, caps, g)
    else:
        tab_bar(fr, model, caps, g)
    if P["stats"]:
        if model.get("rv"):
            draw_tiles(fr, 1, P["stats_y"], W - 2, model, g, caps, P["stats"])
        else:
            draw_stats(fr, 1, P["stats_y"], W - 2, model, g, P["stats"])
        if model.get("logger") == "silent" or model.get("stale"):   # readings that are not live: greyed
            fr.restyle(0, P["stats_y"], W, P["stats"], "off")
    draw_body(fr, P, model, ui, caps, g)
    if ui.get("inspect"):
        draw_inspect(fr, model, ui, P, caps, g)
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
    draw_footer(fr, H - 1, g, status, keys, srole,          # (a note just asked for is shown even so)
                must=("esc",) if keys[0][0] == "esc" else () if ui.get("note") else ("a",))
    if ov:
        fr.restyle(0, H - 1, W, 1, "off")
    return fr


def draw_overlay(fr, model, ui, ov, caps, g):
    kind = ov.get("kind")
    if kind == "help":
        return overlay_help(fr, caps, g, model, ui, ov)
    machine_dialogs = {"connect": overlay_connect, "pair": overlay_pair, "ssh": overlay_ssh, "ask": overlay_ask,
                       "name": overlay_name, "rename": overlay_name, "forget": overlay_forget,
                       "attention": overlay_attention, "list": overlay_list}
    if kind in machine_dialogs and (model.get("tabs") or kind == "connect"):
        return machine_dialogs[kind](fr, caps, g, model, ov)
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
    miss = False
    if model.get("missing"):
        f, _ = mapper(model["now"], model.get("first") or model["now"], SPANS[ui["span"]])
        miss = any(f(b) > 0 for a, b, k in model["missing"])
    if model.get("rv"):
        focus = rv_shown(model)[1]
        draw_chart_head(fr, 0, P["box_y"], lw, ui, caps, g, RES_WORDS[focus], miss, values=legend_values(model, focus))
        if focus == "memory":
            gridcols = draw_plot(fr, x0, P["plot_y"], pw, ph, model, ui, caps, g)
        elif focus == "net":
            gridcols = draw_netplot(fr, x0, P["plot_y"], pw, ph, model, ui, caps, g)
        else:
            gridcols = draw_rplot(fr, x0, P["plot_y"], pw, ph, model, ui, caps, g, focus)
        for i, r in enumerate(rv_others(model)[:P["spark_n"]]):
            draw_spark(fr, x0, P["spark_y"] + i, pw, model, ui, caps, g, r)
        if P["spark_n"]:            # the time axis goes under the small rows, which took the plot's label row
            now_, first = model["now"], model.get("first") or (model["pts"][0]["t"] if model["pts"] else model["now"])
            f_, _ = mapper(now_, first, SPANS[ui["span"]])
            for x, text in axis_labels(f_, pw, now_, log=SPANS[ui["span"]] is None):
                cx = min(max(int(round(x * pw)) - len(text) // 2, 0), pw - len(text))
                fr.put(x0 + cx, P["axis_y"], text, "dim")
    else:
        lx = (model.get("cur") or {}).get("linux")
        draw_chart_head(fr, 0, P["box_y"], lw, ui, caps, g, "Memory", miss, words=series_words(model.get("cur")),
                        away=lx is None or lx["desktop"])     # no one sits at a server (03 §3.9)
        gridcols = draw_plot(fr, x0, P["plot_y"], pw, ph, model, ui, caps, g)
    now = model["now"]
    rows, n_live, n_wait = list_rows(model, P["R"], ui)
    if P["cap_y"] is not None:
        live = [r for r in model["res"] if r.get("ended") is None]
        reserved = sum(r["segments"][-1][1] for r in live if r.get("granted") is not None)
        n24 = sum(1 for r in model["res"] if (r["ended"] if r.get("ended") is not None else now) >= now - 86400)
        summary = "%.1f GB reserved %s %d in the last 24 h" % (reserved, g["mid"], n24)
        if model.get("rv"):         # the shown resources' grants, summed (02 §3.7.7)
            shown = rv_shown(model)[0]
            summary = asc(caption_text(rv_split(live, shown)[0], shown, n24), fr).replace(" · ", " %s " % g["mid"])
        if model.get("stale"):           # another machine's, not connected: said once, as of when (01 §3.5)
            summary = "as of %s: %.1f GB reserved" % (hhmm(model.get("known") or now), reserved)
        room = lw - 2 - (24 if lw >= 64 else 14)
        if model.get("rv") and not model.get("stale"):     # too long beside the title: the last parts give way
            parts = summary.split(" %s " % g["mid"])
            while len(parts) > 1 and tw((" %s " % g["mid"]).join(parts)) + 4 > room:
                parts.pop()
            summary = (" %s " % g["mid"]).join(parts)
        elif tw(summary) + 4 > room:      # too long beside the title: the count gives way
            summary = summary.split(" %s " % g["mid"])[0]
        hidden = n_live - sum(1 for r in rows if r[0] == "res" and r[1].get("ended") is None)
        if hidden and not any(r[0] == "more" for r in rows):         # no list at all: the caption counts
            summary = "%d granted%s %s %s" % (n_live - n_wait, " %s %d waiting" % (g["mid"], n_wait) if n_wait else "",
                                             g["mid"], summary.split(" %s " % g["mid"])[0])
        section(fr, 0, P["cap_y"], lw, g, "Reserved by agents" if lw >= 64 else "Reserved", summary)
        if P["S"] and model.get("rv"):
            draw_bands(fr, x0, P["strip_y"], pw, P["S"], model, ui, caps, g, gridcols)
        elif P["S"]:
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
    if ui.get("panel") and not ui.get("inspect"):
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
