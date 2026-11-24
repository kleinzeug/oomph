#!/usr/bin/python3 -I
"""The full-screen half of `oomph top` (roadmap 04-tui §10, step T1): the input decoder, the writer
(replayed into a terminal model of its own and, where tmux is installed, into tmux, which shares no
code with it), the selection rules, the history kept as typed arrays, and the program itself in a
pseudo-terminal: keys, resizes, signals, suspend, a stalled terminal, a vanished one, read-only
mode, `--ssh` against a stand-in ssh, and what a quiet minute costs.

    tools/toptest.py            run everything (the self-test runs this); exit 1 on a failure
    tools/toptest.py --minute   only the budget: a minute of the real clock in a pseudo-terminal, installed
                                the way install.sh installs, on 14 days of data with a sample every 10 s
                                (CI runs this; the design's budget: 1 % of a core, 40 MB peak resident)

With CI set in the environment a missing tmux is a failure, not a skip (a skipped oracle would let
T1's exit criterion pass without the test having run). Every child runs under a timeout; nothing
here grows without bound.
"""
import base64
import fcntl
import gzip
import json
import os
import random
import re
import select
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unicodedata

os.environ["TZ"] = "Europe/Berlin"
time.tzset()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import oomph  # noqa: E402
import oomph_top as T  # noqa: E402
import oomph_view as V  # noqa: E402
import topfixture  # noqa: E402

FAILS = []
PY = "/usr/bin/python3" if os.path.exists("/usr/bin/python3") else sys.executable
CLI = os.path.join(ROOT, "daemon", "oomph.py")
NOW = topfixture.NOW
KEYS = {"up": b"\x1b[A", "down": b"\x1b[B", "right": b"\x1b[C", "left": b"\x1b[D", "enter": b"\r", "esc": b"\x1b",
        "space": b" ", "pgdn": b"\x1b[6~", "pgup": b"\x1b[5~", "home": b"\x1b[H", "end": b"\x1b[F", "ctrl-z": b"\x1a",
        "ctrl-l": b"\x0c", "ctrl-c": b"\x03"}


def check(ok, what):
    print("%s %s" % ("ok   " if ok else "FAIL ", what))
    if not ok:
        FAILS.append(what)


# ------------------------------------------------------------------ the decoder
def decode(chunks, text=False, gap=0.0, esc_wait=0.05, mouse=False, after=10.0):
    out, now = [], 0.0
    d = T.Decoder(out.append, lambda: text, esc_wait, mouse=lambda: mouse)
    for c in chunks:
        d.feed(c, now)
        now += gap
    d.tick(now + after)
    return out


def splits(data):
    for i in range(1, len(data)):
        yield [data[:i], data[i:]]
    yield [data[i:i + 1] for i in range(len(data))]


def keys_of(evs):
    return [e[1] for e in evs if e[0] == "key"]


def test_decoder():
    table = [(b"\x1b[A", ["up"]), (b"\x1bOA", ["up"]), (b"\x1b[B", ["down"]), (b"\x1b[C", ["right"]),
             (b"\x1b[D", ["left"]), (b"\x1b[1;2D", ["shift-left"]), (b"\x1b[5~", ["pgup"]), (b"\x1b[6~", ["pgdn"]),
             (b"\x1b[H", ["home"]), (b"\x1b[F", ["end"]), (b"\x1b[1~", ["home"]), (b"\x1b[4~", ["end"]),
             (b"\x1bOP", ["f1"]), (b"\x1b[11~", ["f1"]), (b"\r", ["enter"]), (b"\x03", ["ctrl-c"]),
             (b"\x1a", ["ctrl-z"]), (b"q", ["q"]), (b"\x1b", ["esc"]), (b"\x1b\x1b", ["esc", "esc"]),
             (b"\x1b[Z", ["shift-tab"]), ("é".encode(), ["é"])]
    bad = []
    for data, want in table:
        for chunks in [[data]] + list(splits(data)):
            got = keys_of(decode(chunks, gap=0.01))
            if got != want:
                bad.append((data, chunks, got))
    check(not bad, "decoder: every key in its forms, whole and cut at every byte (%s)" % bad[:2])
    bad = []
    for data, want in table[:12]:
        for chunks in splits(data):
            got = keys_of(decode(chunks, gap=0.2))       # a slow link: the tail comes after the ESC was reported
            if any(len(k) == 1 for k in got) or got[-1:] != want[-1:]:
                bad.append((data, chunks, got))
    check(not bad, "decoder: a sequence torn by a slow link is esc, then the key; never a letter from inside it (%s)"
          % bad[:2])
    ev = decode([b"\x1b[2;4R"]) + decode([b"\x1b[2;7R"]) + decode([b"\x1b[1;4R"])
    check([e for e in ev if e[0] == "reply"] == [("reply", "cpr", "2;4"), ("reply", "cpr", "2;7")] and not keys_of(ev),
          "decoder: the glyph probe's reports from row 2 are replies; from row 1 (a modified F3) nothing")
    long_csi = b"\x1b[" + b"1;" * 39 + b"1q"
    osc = b"\x1b]" + b"x" * 2400
    cases = [long_csi + b"j", osc + b"\x07j", osc + b"\x1b\\j", b"\x1bP" + b"y" * 2400 + b"\x1b\\j"]
    bad = [c[:12] for c in cases for chunks in ([c], [c[:5], c[5:600], c[600:]])
           if keys_of(decode(chunks, gap=0.01)) != ["j"]]
    check(not bad, "decoder: a CSI of 79 parameter bytes ending in q, an OSC and a DCS of 2.4 KB are swallowed whole; "
                   "the key after them arrives (%s)" % bad[:2])
    ev = decode([b"\x1b[200~hello\x1b[31m\x07 world\x1b[201~j"])
    big = decode([b"\x1b[200~" + b"a" * 100000 + b"\x1b[201~j"])
    check(ev[0] == ("paste", "hello[31m world") and keys_of(ev) == ["j"] and big[0] == ("paste-too-long",) and
          keys_of(big) == ["j"], "decoder: a paste is one event without control characters; 100 KB is dropped whole")
    torn = decode([b"\x1b[200~half a paste", b"q\x03"], gap=T.PASTE_WAIT + 0.5)
    slow = decode([b"\x1b[200~a", b"b", b"c\x1b[201~q"], gap=T.PASTE_WAIT - 0.5)
    check(torn == [("paste-too-long",), ("key", "q"), ("key", "ctrl-c")] and slow == [("paste", "abc"), ("key", "q")],
          "decoder: a paste whose end never comes is dropped after %.0f s without a byte; q and ctrl-c then work "
          "(%s %s)" % (T.PASTE_WAIT, torn, slow))
    x10 = b"\x1b[M" + bytes((32, 200, 155)) + b"j"
    bad = [ch for ch in [[x10]] + list(splits(x10)) if keys_of(decode(ch, gap=0.01, mouse=True)) != ["j"]]
    check(not bad, "decoder: an X10 mouse report (CSI M and three raw bytes, one above 127) yields no key")
    addr = b"[fe80::1%en0]:6674"
    bad = [ch for ch in [[addr]] + list(splits(addr)) for gap in (0.0, 0.2)
           if [e[1] for e in decode(ch, text=True, gap=gap)] != list(addr.decode())]
    check(not bad, "decoder: in a text field every character is text, however the bytes are spaced")
    rnd = random.Random(4)
    raised, printable = 0, 0
    for _ in range(2000):
        data = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 48)))
        try:
            cuts = sorted(rnd.sample(range(1, len(data)), min(3, len(data) - 1))) if len(data) > 2 else []
            decode([data[a:b] for a, b in zip([0] + cuts, cuts + [len(data)])], gap=rnd.choice((0.0, 0.03, 0.3)))
        except Exception:
            raised += 1
    for _ in range(1500):
        params = "".join(rnd.choice("0123456789;:<=>?") for _ in range(rnd.randrange(0, 200)))
        data = b"\x1b[" + params.encode() + bytes((rnd.randrange(0x40, 0x7f),))
        if rnd.random() < 0.3:
            data = (b"\x1b]" if rnd.random() < 0.5 else b"\x1bP") + bytes(rnd.randrange(32, 127) for _ in range(
                rnd.randrange(0, 3000))) + (b"\x07" if rnd.random() < 0.5 else b"\x1b\\")
        k = rnd.randrange(1, len(data))
        got = keys_of(decode([data[:k], data[k:]], gap=0.01))
        printable += any(len(x) == 1 for x in got)
    check(not raised and not printable, "decoder: 2,000 random byte strings never raise; 1,500 well-formed sequences "
                                        "(up to 200 parameter bytes, strings up to 3 KB), cut anywhere, never yield a "
                                        "printable key (%d raised, %d printable)" % (raised, printable))


# ------------------------------------------------------------------ the writer, and a terminal to check it
class MiniVT:
    """A small terminal: cursor addressing, SGR, erase display, the alternate screen, two-cell
    characters; strings (OSC, DCS) and private modes are swallowed. It shares no code with the
    writer but the width table."""

    def __init__(self, w, h):
        self.w, self.h, self.x, self.y, self.sgr = w, h, 0, 0, "\x1b[0m"
        self.main = self._blank()
        self.cells = self.main
        self.alt_seen = None

    def _blank(self):
        return [[(" ", "\x1b[0m") for _ in range(self.w)] for _ in range(self.h)]

    def _set(self, x, y, value):
        row = self.cells[y]
        if row[x][0] == "" and x > 0:
            row[x - 1] = (" ", row[x - 1][1])
        elif x + 1 < self.w and row[x + 1][0] == "":
            row[x + 1] = (" ", row[x + 1][1])
        row[x] = value

    def feed(self, data):
        i, n = 0, len(data)
        while i < n:
            ch = data[i]
            if ch == "\x1b" and i + 1 < n:
                nxt = data[i + 1]
                if nxt == "[":
                    j = i + 2
                    while j < n and not "@" <= data[j] <= "~":
                        j += 1
                    if j >= n:
                        return
                    arg, final = data[i + 2:j], data[j]
                    if final == "H":
                        r, c = (arg.split(";") + ["1", "1"])[:2]
                        self.y, self.x = int(r or 1) - 1, int(c or 1) - 1
                    elif final == "m":
                        self.sgr = "\x1b[%sm" % arg
                    elif final == "J" and arg == "2":
                        for row in self.cells:
                            row[:] = [(" ", "\x1b[0m")] * self.w
                    elif final in "hl" and arg == "?1049":
                        if final == "h":
                            self.cells = self._blank()
                        else:
                            self.alt_seen, self.cells = self.cells, self.main
                    i = j + 1
                    continue
                if nxt in "]P":
                    j = i + 2
                    while j < n and data[j] != "\x07" and not (data[j] == "\x1b" and j + 1 < n and data[j + 1] == "\\"):
                        j += 1
                    i = j + (1 if j < n and data[j] == "\x07" else 2)
                    continue
                i += 2
                continue
            if ch < " " or ch == "\x7f":
                i += 1
                continue
            cat = unicodedata.category(ch)
            if cat in ("Mn", "Me"):
                if 0 < self.x <= self.w and self.y < self.h:
                    k = self.x - 1 if self.cells[self.y][self.x - 1][0] != "" else self.x - 2
                    c0, s0 = self.cells[self.y][k]
                    self.cells[self.y][k] = (c0 + ch, s0)
                i += 1
                continue
            wide = V._in(ord(ch), V.WIDE2)
            if self.y < self.h and self.x + (1 if wide else 0) < self.w:
                self._set(self.x, self.y, (ch, self.sgr))
                if wide:
                    self._set(self.x + 1, self.y, ("", self.sgr))
            self.x += 2 if wide else 1
            i += 1

    def shows(self, frame, caps, cells=None):
        cells = cells or self.cells
        for y in range(frame.h):
            for x in range(frame.w):
                ch, sgr = cells[y][x]
                cell = frame.c[y][x]
                if cell[0] == "":
                    if ch != "":
                        return "row %d col %d: %r where the second half of a wide character belongs" % (y, x, ch)
                    continue
                want_ch, want_sgr = V.paint(cell, caps)
                if ch != want_ch or sgr != want_sgr:
                    return "row %d col %d: %r %r, want %r %r" % (y, x, ch, sgr, want_ch, want_sgr)
        return None


def golden_frames():
    base = tempfile.mkdtemp(prefix="oomph-toptest-")
    try:
        return topfixture.frames(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_writer(frames):
    caps = V.Caps("256", "unicode", "dark")
    seq = [frames[n][1] for n in ("80x24-default.golden", "80x24-selected.golden", "80x24-apps.golden",
                                  "80x24-help.golden", "80x24-reservation-card.golden", "80x24-incident-card.golden",
                                  "80x24-hostile.golden", "80x24-default.golden")]
    vt, prev, bad, sizes = MiniVT(80, 24), None, [], []
    for fr in seq:
        out = V.diff_ansi(prev, fr, caps)
        sizes.append(len(out.encode()))
        vt.feed(out)
        why = vt.shows(fr, caps)
        if why:
            bad.append(why)
        prev = fr
    check(not bad and V.diff_ansi(prev, prev, caps) == "",
          "writer: each change replayed into a terminal model shows the next frame; no change writes nothing (%s)"
          % (bad[:1] or "%s bytes" % sizes))
    shifted = V.Frame(80, 2)
    shifted.put(0, 0, "構築テスト ab 構築")
    other = V.Frame(80, 2)
    other.put(1, 0, "構築テスト ab 構築")
    vt = MiniVT(80, 2)
    vt.feed(V.diff_ansi(None, shifted, caps))
    vt.feed(V.diff_ansi(shifted, other, caps))
    check(vt.shows(other, caps) is None, "writer: two-cell characters shifted by one cell are rewritten whole")
    return seq


def tmux_oracle(frames):
    tmux = shutil.which("tmux")
    if not tmux:
        if os.environ.get("CI"):
            check(False, "tmux comparison: tmux is not installed (CI must install it)")
        else:
            print("skip  tmux comparison: tmux is not installed here")
        return
    names = ("80x24-default.golden", "160x48-wide.golden", "80x24-16.golden", "80x24-ascii.golden",
             "80x24-cells.golden", "80x24-help.golden", "80x24-hostile.golden", "60x16-apps.golden")
    sock = "oomph-toptest-%d" % os.getpid()
    tmp = tempfile.mkdtemp(prefix="oomph-tmux-")
    conf = os.path.join(tmp, "tmux.conf")
    with open(conf, "w") as f:
        f.write("set -g status off\n")  # no status line to take a row: the pane is the frame's size on every version
    bad = []
    try:
        for name in names:
            fr = frames[name][1]
            caps = V.Caps({"80x24-16.golden": "16"}.get(name, "256"),
                          {"80x24-ascii.golden": "ascii", "80x24-cells.golden": "cells"}.get(name, "unicode"), "dark")
            path = os.path.join(tmp, name + ".bin")
            with open(path, "wb") as f:
                f.write(V.diff_ansi(None, fr, caps).encode())
            loc = "en_US.UTF-8" if sys.platform == "darwin" else "C.UTF-8"
            env = dict(os.environ, LANG=loc, LC_ALL=loc)
            # the frame is painted only once the window has its size, which is not always what -x and -y
            # asked for: on Rocky 9 the pane came out a row short (1.9.4's CI)
            go = path + ".go"
            subprocess.run([tmux, "-L", sock, "-f", conf, "-u", "new-session", "-d", "-x", str(fr.w), "-y",
                            str(fr.h), "until [ -e %s ]; do sleep 0.05; done; cat %s; sleep 30"
                            % (shlex.quote(go), shlex.quote(path))],
                           env=env, timeout=20, check=True)
            subprocess.run([tmux, "-L", sock, "resize-window", "-x", str(fr.w), "-y", str(fr.h)],
                           capture_output=True, timeout=10, env=env)   # tmux 2.9+; older ones keep -x and -y
            open(go, "w").close()
            shown = ""
            for _ in range(50):
                time.sleep(0.1)
                shown = subprocess.run([tmux, "-L", sock, "capture-pane", "-p"], capture_output=True, text=True,
                                       timeout=10, env=env).stdout
                if shown.strip():
                    break
            time.sleep(0.2)
            shown = subprocess.run([tmux, "-L", sock, "capture-pane", "-p"], capture_output=True, text=True,
                                   timeout=10, env=env).stdout
            size = subprocess.run([tmux, "-L", sock, "display-message", "-p", "#{pane_width}x#{pane_height}"],
                                  capture_output=True, text=True, timeout=10, env=env).stdout.strip()
            subprocess.run([tmux, "-L", sock, "kill-server"], capture_output=True, timeout=10)
            want = ["".join(V.paint(c, caps)[0] for c in row if c[0] != "").rstrip() for row in fr.c]
            got = [r.rstrip() for r in shown.rstrip("\n").split("\n")]
            got += [""] * (len(want) - len(got))
            diff = [(i, w, g) for i, (w, g) in enumerate(zip(want, got)) if w != g]
            if diff:
                bad.append("%s row %d: want %r got %r (tmux pane %s)" % (name, diff[0][0], diff[0][1][:60],
                                                                        diff[0][2][:60], size))
    finally:
        subprocess.run([tmux, "-L", sock, "kill-server"], capture_output=True, timeout=10)
        shutil.rmtree(tmp, ignore_errors=True)
    check(not bad, "tmux comparison: %d frames painted into tmux read back as drawn (%s)" % (len(names), bad[:1]))


# ------------------------------------------------------------------ the selection, the lists, the panels
def test_space_key():
    """The space bar reaches the lists as "space": the decoder gives the character itself, the app's
    aliases name it. (1.9.5 shipped without the alias, so space never moved the focus.)"""
    keys = [T.KEY_ALIASES.get(k, k) for k in keys_of(decode([b" "]))]
    check(keys == ["space"], "space bar: the key the app acts on is %r" % keys)


def test_selection():
    base = tempfile.mkdtemp(prefix="oomph-toptest-sel-")
    try:
        log, led = topfixture.write_fixture(os.path.join(base, "d"), "default")
        oomph.LEDGER_DIR = led
        model = T.load_model("24h", NOW, log_dir=log, live=False)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    model.update(host="studio", os="macOS 27.2")
    caps = V.Caps("256", "unicode", "dark")
    seq = V.res_seq(model)[0]

    def marks(fr):
        return [(y, x) for y, row in enumerate(fr.c) for x, c in enumerate(row) if c[0] == "›" and c[1] == "accent"]
    bad = []
    for W, H in ((80, 24), (100, 40), (160, 48)):
        P = V.layout(model, W, H)
        ui = V.press({"span": "24h"}, "up", model, P)
        if not (ui.get("focus") == "inc" and ui.get("inc_sel") == 0):
            bad.append("%dx%d: up from the plain view" % (W, H))
        for n in (1, 2, 5, 20, len(seq) + 5):
            for tail in (("space", "home"), ("esc", "up")):
                ui = {"span": "24h"}
                for k in ["down"] * n + list(tail):
                    V.press(ui, k, model, P)
                if not (ui.get("focus") == "inc" and ui.get("inc_sel") == 0):
                    bad.append("%dx%d: %d x down, %s" % (W, H, n, " ".join(tail)))
        rnd = random.Random(W)
        ui = {"span": "24h"}
        for i in range(400):
            V.press(ui, rnd.choice(("up", "down", "pgup", "pgdn", "home", "end", "space", "esc", "down", "down")),
                    model, P)
            if i % 8 == 0:
                fr = V.render(model, W, H, caps, ui)
                m = marks(fr)
                if ui.get("focus") and len(m) != 1 or not ui.get("focus") and m:
                    bad.append("%dx%d after %d keys: %d highlighted rows" % (W, H, i, len(m)))
    P = V.layout(model, 60, 16)
    ui = V.press({"span": "24h"}, "up", model, P)
    if P["I"] or (ui.get("overlay") or {}).get("id") != model["incidents"][0]["id"]:
        bad.append("60x16: up does not open the newest incident's card")
    check(not bad, "selection: up reaches the newest incident from the plain view, and in two keys from anywhere in "
                   "the reservations; after 400 random keys one highlighted row, in the list with the focus (%s)"
                   % bad[:3])
    bad = []
    for W, H in ((80, 15), (80, 16), (40, 15), (40, 16), (130, 14)):
        P = V.layout(model, W, H)
        if P["R"] != 1:
            bad.append("%dx%d: the plan gives the list %d rows, not 1" % (W, H, P["R"]))
            continue
        ui = {"span": "24h"}
        unfocused = V.render(model, W, H, caps, ui).text()
        for n in range(1, len(seq) + 2):
            V.press(ui, "down", model, P)
            fr = V.render(model, W, H, caps, ui)
            m = marks(fr)
            rows = V.list_rows(model, 1, ui)[0]
            if len(m) != 1 or m[0][0] != P["list_y"] or rows[0][:3:2] != ("res", ui["res_sel"]) or \
                    rows[0][1] is not seq[ui["res_sel"]]:
                bad.append("%dx%d after %d x down: %d highlighted rows, not reservation %d" % (W, H, n, len(m),
                                                                                            ui["res_sel"]))
        if "granted" not in unfocused:
            bad.append("%dx%d: the single row does not count before it has the focus" % (W, H))
    check(not bad, "selection: a list of one row shows the selected reservation, and counts until it has the focus "
                   "(%s)" % bad[:3])
    bad = []
    for live in range(9):
        rs = []
        for i in range(live):
            granted = None if i % 3 == 0 else NOW - 100 * i
            rs.append(dict(key="k%d" % i, id="r%d" % i, purpose="p%d" % i, project=None, holder="session", pid=None,
                           requested=NOW - 100 * i - 50, granted=granted, ended=None, outcome=None, peak=0, used=0,
                           expires=None if granted is None else NOW + 60 * i, segments=[(NOW - 100 * i - 50, 1.0)]))
        m = dict(model, res=rs)
        for R in range(1, 9):
            rows, _, _ = V.list_rows(m, R)
            shown = [r[1] for r in rows if r[0] == "res"]
            hidden_wait = [r for r in rs if r["granted"] is None and r not in shown]
            if hidden_wait and any(r["granted"] is not None for r in shown):
                bad.append("R=%d live=%d" % (R, live))
    check(not bad, "the list rule: no waiting reservation is hidden while a granted one is shown (%s)" % bad[:3])
    bad = []
    for W in range(40, 121, 4):
        for H in (10, 16, 24):
            for ui in ({"span": "24h", "panel": "a"}, {"span": "1h", "panel": "s", "focus": "panel", "panel_sel": 1},
                       {"span": "6h", "panel": "e"}, {"span": "24h", "overlay": {"kind": "help", "page": 1}},
                       {"span": "24h", "overlay": {"kind": "inc", "id": model["incidents"][1]["id"]}},
                       {"span": "24h", "overlay": {"kind": "res", "key": seq[0]["key"]}}):
                try:
                    fr = V.render(model, W, H, caps, dict(ui))
                except Exception as e:
                    bad.append("%dx%d %s: %r" % (W, H, sorted(ui), e))
                    continue
                rows = fr.text().rstrip("\n").split("\n")
                if len(rows) != H or any(V.tw(r) != W for r in rows) or V.lint_pairing(fr):
                    bad.append("%dx%d %s: shape or colour rule" % (W, H, sorted(ui)))
                last = rows[-1]
                if ("panel" in ui or "overlay" in ui) and "esc" not in last and "esc" not in fr.text():
                    bad.append("%dx%d %s: no esc" % (W, H, sorted(ui)))
    check(not bad, "panels, help and cards render at every size from 40 x 10, rows exactly as wide as the frame, and "
                   "name esc (%s)" % bad[:2])


# ------------------------------------------------------------------ inspect and the mouse (T1b)
def test_inspect_mouse():
    base = tempfile.mkdtemp(prefix="oomph-toptest-insp-")
    try:
        log, led = topfixture.write_fixture(os.path.join(base, "d"), "default")
        oomph.LEDGER_DIR = led
        model = T.load_model("6h", NOW, log_dir=log, live=False)
    finally:
        shutil.rmtree(base, ignore_errors=True)
    model.update(host="studio", os="macOS 27.2")
    caps = V.Caps("256", "unicode", "dark")
    g = V.GLYPHS["unicode"]
    P = V.layout(model, 80, 24)
    W = P["plot_w"]
    ui = {"span": "6h"}
    V.inspect_at(ui, model, P, W - 1)
    cols = [V.inspect_geometry(model, ui, P)[4]]
    for k in ("left", "shift-left", "<", "home", "end", ">", "right", "shift-right"):
        V.inspect_key(ui, k, model, P)
        cols.append(V.inspect_geometry(model, ui, P)[4])
    check(cols == [W - 1, W - 2, W - 12, W - 22, 0, W - 1, W - 1, W - 1, W - 1],
          "inspect: ← → move a column, shift-← → and < > ten, home and end the oldest column and now; the cursor "
          "stays in the plot (%s)" % cols)
    inc = model["incidents"][0]                       # 10:29 on Friday: inside the 6 h view
    f, finv, first, _, _ = V.inspect_geometry(model, ui, P)
    c_inc = int(f(inc["start"]) * W)
    V.inspect_at(ui, model, P, c_inc)
    info, col = V.inspect_info(model, ui, P)
    t_kept = ui["inspect"]["t"]
    ui24 = dict(ui, span="24h")
    f24, _, _, _, c24 = V.inspect_geometry(model, ui24, P)
    i24, _ = V.inspect_info(model, ui24, P)
    check(col == c_inc and info["incidents"] and info["incidents"][0].startswith("incident 10:29") and
          i24["t0"] <= t_kept <= i24["t1"], "inspect: the column of an incident names it; at another span the cursor "
          "is on the column that holds the same time (%s, %s)" % (info["incidents"][:1], i24["when"]))
    fr = V.render(model, 80, 24, caps, dict(ui))
    text = fr.text()
    want = ["Inspect %s %s" % (g["mid"], info["when"])] + [r[0] for r in info["readings"]] + info["incidents"][:1]
    check(all(w[:30] in text for w in want) and text.rstrip("\n").split("\n")[-1].startswith(" esc back"),
          "inspect: the readout docked under the strip says what hover_info says (the app's hover card, held to it by "
          "the chart vectors); the key line starts with the way out")
    ui2 = dict(ui)
    V.inspect_key(ui2, "enter", model, P)
    sel = V.selected(model, ui2)
    ui3 = {"span": "6h"}
    V.inspect_at(ui3, model, P, 0)
    for _ in range(3):
        V.inspect_key(ui3, "right", model, P)
    i3, _ = V.inspect_info(model, ui3, P)
    V.inspect_key(ui3, "enter", model, P)
    check("inspect" not in ui2 and sel[0] == "inc" and sel[1]["id"] == inc["id"] and "inspect" not in ui3 and
          (ui3.get("focus") in ("inc", "res") or ui3.get("note")),
          "inspect: enter selects the incident under the cursor in its list and leaves inspect (%s)" % (sel[0],))
    bad = []
    rnd = random.Random(5)
    for Wd in range(40, 161, 8):
        for H in (10, 12, 16, 24, 40):
            for span in ("inf", "24h", "1h"):
                u = {"span": span}
                PP = V.layout(model, Wd, H)
                V.inspect_at(u, model, PP, rnd.randrange(PP["plot_w"]))
                try:
                    fr = V.render(dict(model), Wd, H, caps, u)
                except Exception as e:
                    bad.append("%dx%d %s: %r" % (Wd, H, span, e))
                    continue
                rows = fr.text().rstrip("\n").split("\n")
                if len(rows) != H or any(V.tw(r) != Wd for r in rows) or V.lint_pairing(fr):
                    bad.append("%dx%d %s: shape or colour rule" % (Wd, H, span))
                elif not rows[-1].startswith(" esc"):
                    bad.append("%dx%d %s: the key line does not start with esc" % (Wd, H, span))
    check(not bad, "inspect: the readout draws at every size from 40 x 10 (docked, or floating where there is no list "
                   "area), rows as wide as the frame (%s)" % bad[:3])
    # the mouse: what a press at a cell does
    P = V.layout(model, 80, 24)
    hits = V.span_hits(P, {"span": "6h"}, g)
    k1 = [h for h in hits if h[0] == "1h"][0]
    u = {"span": "6h"}
    acts = [V.mouse(u, model, P, g, 0, k1[1] + 1, P["box_y"]), V.mouse(u, model, P, g, 64, P["plot_x"] + 5, P["plot_y"]),
            V.mouse(u, model, P, g, 65, P["plot_x"] + 5, P["plot_y"])]
    V.mouse(u, model, P, g, 0, P["plot_x"] + 9, P["plot_y"] + 2)
    c_click = V.inspect_geometry(model, u, P)[4]
    V.mouse(u, model, P, g, 32, P["plot_x"] + 30, P["plot_y"] + 2)      # motion: never acted on
    V.mouse(u, model, P, g, 2, P["plot_x"] + 30, P["plot_y"] + 2)       # the right button: nothing
    c_after = V.inspect_geometry(model, u, P)[4]
    rows = V.list_rows(model, P["R"], {})[0]
    first = V.mouse(u, model, P, g, 0, 10, P["list_y"])
    in_res = u.get("focus") == "res" and u.get("res_sel") == rows[0][2] and "inspect" not in u
    again = V.mouse(u, model, P, g, 0, 10, P["list_y"])
    V.mouse(u, model, P, g, 0, 10, P["inc_y"] + 1)
    in_inc = (u.get("focus"), u.get("inc_sel"))
    V.mouse(u, model, P, g, 65, 10, P["list_y"] + 1)
    wheel = (u.get("focus"), u.get("res_sel"))
    u2 = {"span": "6h"}
    V.mouse(u2, model, P, g, 0, 10, P["inc_cap_y"])
    check(acts == [("span", "1h"), ("span", "1h"), ("span", "24h")] and c_click == 9 and c_after == 9 and first is None
          and in_res and again == ("card",) and in_inc == ("inc", 1) and wheel == ("res", 1) and u2.get("focus") == "inc",
          "mouse: a span in the chart's edge chooses it, the wheel over the chart changes it; a click in the plot "
          "inspects that column; motion and the right button do nothing; a row is selected, clicked again it opens; "
          "the wheel over a list scrolls it; a caption moves into its list (%s)" % [acts, c_click, c_after, first, again,
                                                                                    in_inc, wheel, u2.get("focus")])
    evs = []
    d = T.Decoder(evs.append, mouse=lambda: True)
    d.feed(b"\x1b[<0;12;8M\x1b[<0;12;8m\x1b[<65;3;4M", 0.0)
    check(evs == [("mouse", 0, 12, 8, True), ("mouse", 0, 12, 8, False), ("mouse", 65, 3, 4, True)],
          "mouse: SGR reports decode to presses and releases (%s)" % evs)


def test_pty_inspect(base):
    """i, the arrows and esc in a terminal; ctrl-o turns the mouse on and off, a click inspects; --mouse."""
    env, log, led = fixture_env(base)
    oomph.LEDGER_DIR = led
    model = T.load_model("24h", NOW, log_dir=log, live=False)
    P = V.layout(model, 80, 24)

    def screen(p):
        vt = MiniVT(80, 24)
        vt.feed(p.text())
        return "\n".join("".join(c[0] for c in row) for row in vt.cells)
    p = Pty(top(), env)
    try:
        p.pump(5, until=b"Logging every")
        p.send("i", "left", "left", wait=0.3)
        insp = "Inspect" in screen(p) and "esc back" in screen(p)
        p.send("esc", wait=0.3)
        back = "Inspect" not in screen(p) and "a apps" in screen(p)
        n1 = len(p.out)
        p.send(b"\x0f", wait=0.4)
        on = b"\x1b[?1000h\x1b[?1006h" in p.out[n1:] and "mouse on" in screen(p)
        p.send(b"\x1b[<0;%d;%dM\x1b[<0;%d;%dm" % ((P["plot_x"] + 11, P["plot_y"] + 2) * 2), wait=0.4)
        clicked = "Inspect" in screen(p)
        n3 = len(p.out)
        p.send(b"\x0f", wait=0.3)
        off = b"\x1b[?1000l\x1b[?1006l" in p.out[n3:]
        p.send("q", wait=0.1)
        rc = p.wait(5)
        restored = p.restored()
    finally:
        p.close()
    saved = json.load(open(os.path.join(env["OOMPH_STATE_DIR"], "top.json")))
    check(insp and back and on and clicked and off and rc == 0 and restored and saved.get("mouse") is False,
          "pty: i inspects and esc leaves; ctrl-o turns mouse reporting on (buttons and the wheel, SGR) and off; a "
          "click in the plot inspects that column; top.json remembers the mouse off (%s)"
          % [insp, back, on, clicked, off, rc, saved.get("mouse")])
    p = Pty(top("--mouse"), env)
    try:
        p.pump(5, until=b"Logging every")
        started = b"\x1b[?1000h\x1b[?1006h" in p.out
        p.send("q", wait=0.1)
        rc = p.wait(5)
        left = p.out.endswith(T.LEAVE.encode()) and b"\x1b[?1000l" in T.LEAVE.encode()
    finally:
        p.close()
    saved = json.load(open(os.path.join(env["OOMPH_STATE_DIR"], "top.json")))
    check(started and left and rc == 0 and saved.get("mouse") is True,
          "pty: --mouse turns reporting on from the start, the leave sequences turn it off, and it is remembered (%s)"
          % [started, left, rc, saved.get("mouse")])


# ------------------------------------------------------------------ history as typed arrays
def test_arrays():
    rnd = random.Random(7)
    now = NOW
    pts, t = [], now - 3 * 86400
    while t < now:
        t += rnd.choice((30, 30, 30, 31, 400, 3000)) if rnd.random() < 0.02 else 30
        pts.append(dict(t=float(t), wired=6.0 + rnd.random(), app=8.0 + rnd.random() * 4, comp=5.0 + rnd.random(),
                        swap=rnd.random() * (rnd.random() < 0.1), away=rnd.random() < 0.2, kills=int(rnd.random() < 0.01)))
    pts = pts[:3000] + pts[-3000:]
    import array
    cols = [array.array("d", [p[k] for p in pts]) for k in ("t", "wired", "app", "comp", "swap")] + \
        [bytearray(1 if p["away"] else 0 for p in pts), array.array("l", [p["kills"] for p in pts])]
    a, b = T.multires_cols(cols, now), V.multires(pts, now)
    check(a == b and T.gaps_cols(cols[0]) + [] == [g for g in V.find_gaps(pts, now) if g[1] != now],
          "history: the thinning over typed arrays is point for point the app's (%d points → %d)" % (len(pts), len(b)))
    d = tempfile.mkdtemp(prefix="oomph-toptest-hist-")
    try:
        day = time.strftime("%Y-%m-%d", time.localtime(now))
        path = os.path.join(d, "samples-%s.jsonl" % day)
        lines = [json.dumps({"t": now - 3000 + 30 * i, "app_gb": 1.0 + i, "wired_gb": 2.0, "compressed_gb": 0.5,
                             "swap_used_gb": 0.0, "jetsam_kills": 0, "away": {"idle_s": 0}}) + "\n" for i in range(60)]
        with open(path, "w") as f:
            f.write("".join(lines[:30]) + lines[30][:20])       # a line still being written
        h = T.History(d)
        h.refresh()
        n1 = len(h.days[day].t)
        with open(path, "a") as f:
            f.write(lines[30][20:] + "".join(lines[31:]))
        changed = h.refresh()
        whole = T.History(d)
        whole.refresh()
        same = list(h.days[day].t) == list(whole.days[day].t) and len(whole.days[day].t) == 60
    finally:
        shutil.rmtree(d, ignore_errors=True)
    check(n1 == 30 and changed and same, "history: today's file is read on from where it stopped, a half-written line "
                                         "whole the next time (%d, then %s)" % (n1, same))
    test_series()


HOSTILE_CHILD = r"""
import json, os, resource, sys
sys.path.insert(0, sys.argv[1])
import oomph_top as T
d, now = sys.argv[2], float(sys.argv[3])
pts, _ = T.load_points(d, now, now - 10 * 86400)
h = T.History(d)
h.refresh()
h.refresh()
rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({"points": sorted(p["t"] for p in pts), "days": {k: len(v.t) for k, v in h.days.items()},
                  "rss_mb": rss / (1 << 20 if sys.platform == "darwin" else 1 << 10)}))
"""


def test_hostile_days():
    """A day file the logger's account planted (on Linux /var/log/oomph is oomphd's, which `sudo oomph top`
    must not trust; 03 §12.3): a link out of the folder, a FIFO, a link to /dev/zero, a .gz that unpacks to
    one endless line and a line over LINE_MAX. load_points and History.refresh read none of them (only the
    good line after the long one), never hang and stay small."""
    now = NOW
    d = tempfile.mkdtemp(prefix="oomph-toptest-hostile-")
    try:
        day = [time.strftime("%Y-%m-%d", time.localtime(now - k * 86400)) for k in range(6)]
        outside = os.path.join(d, "outside.json")
        with open(outside, "w") as f:
            f.write(json.dumps({"t": now - 5 * 86400, "app_gb": 1.0}) + "\n")
        os.symlink(outside, os.path.join(d, "samples-%s.jsonl" % day[5]))
        os.mkfifo(os.path.join(d, "samples-%s.jsonl" % day[4]))
        os.symlink("/dev/zero", os.path.join(d, "samples-%s.jsonl" % day[3]))
        with gzip.open(os.path.join(d, "samples-%s.jsonl.gz" % day[2]), "wb", compresslevel=9) as f:
            chunk = b"a" * (1 << 20)
            for _ in range(T.DAY_CAP // len(chunk) + 64):       # past DAY_CAP, without a newline
                f.write(chunk)
        good = json.dumps({"t": now - 3600, "app_gb": 2.0, "wired_gb": 1.0}) + "\n"
        with open(os.path.join(d, "samples-%s.jsonl" % day[0]), "w") as f:
            f.write('{"t": %d, "pad": "%s"}\n' % (now - 7200, "x" * (T.LINE_MAX + 10)) + good)
        try:
            r = subprocess.run([sys.executable, "-I", "-c", HOSTILE_CHILD, os.path.join(ROOT, "daemon"), d, str(now)],
                               capture_output=True, text=True, timeout=60)
            o = json.loads(r.stdout or "{}")
        except (subprocess.TimeoutExpired, ValueError) as e:
            o = {"error": repr(e)}
    finally:
        shutil.rmtree(d, ignore_errors=True)
    days = o.get("days") or {}
    check(o.get("points") == [now - 3600] and days.get(day[0]) == 1 and not any(days.get(x) for x in day[1:])
          and o.get("rss_mb", 1e9) < 120,
          "history: a planted day file (a link out, a FIFO, /dev/zero, a .gz of one endless line, an overlong line) "
          "is not read, nothing hangs, and the reader stays small (%s)" % (o if "error" in o else
                                                                         "%.0f MB" % o.get("rss_mb", -1)))


def test_series():
    """History.series is load_points column by column: days in order, a day out of order, days that
    overlap and a sample in the future (the slow path raised on every typed array up to 1.11.0)."""
    rnd = random.Random(5)
    now = NOW
    keys = ("t", "wired", "app", "comp", "swap", "away", "kills")

    def sample(t):
        return {"t": t, "app_gb": rnd.random() * 9, "wired_gb": 2.0 + rnd.random(), "compressed_gb": rnd.random(),
                "swap_used_gb": 0.0, "jetsam_kills": rnd.randrange(2), "away": {"idle_s": rnd.choice((0, 9999))},
                "cpu": {"busy": rnd.random() * 8, "sys": 0.5}, "gpu": [{"util": 40.0, "mem_gb": 1.5}],
                "disk_free_gb": 100.0}

    def day_of(t):
        return time.strftime("%Y-%m-%d", time.localtime(t))

    results = []
    for case in ("ordered", "out of order", "overlap", "future"):
        d = tempfile.mkdtemp(prefix="oomph-toptest-series-")
        try:
            days = {}
            for k in range(3, -1, -1):
                ts = [now - k * 86400 - 3600 + 60 * i for i in range(40)]
                if case == "out of order" and k == 1:
                    rnd.shuffle(ts)
                if case == "overlap" and k == 1:
                    ts += [now - 2 * 86400 - 1800 + 60 * i for i in range(10)]
                if case == "future" and k == 0:
                    ts += [now + 7200, now + 30]
                days.setdefault(day_of(now - k * 86400), []).extend(ts)
            for day, ts in days.items():
                with open(os.path.join(d, "samples-%s.jsonl" % day), "w") as f:
                    f.write("".join(json.dumps(sample(t)) + "\n" for t in ts))
            for res in (False, True):
                for since in (now - 3600, now - 2 * 86400, now - 30 * 86400):
                    h = T.History(d, res)
                    h.refresh()
                    try:
                        cols, older = h.series(now, since)
                    except Exception as e:  # noqa: BLE001 -- reported as a failure below
                        results.append("%s: %r" % (case, e))
                        continue
                    pts, older2 = T.load_points(d, now, since, res)
                    want = [[p[k] for p in pts] for k in keys]
                    want[5] = [1 if a else 0 for a in want[5]]
                    if res:
                        want += [[float("nan") if p[k] is None else p[k] for p in pts] for k in V.RES_POINT]
                        want.append([1 if p["gfull"] else 0 for p in pts])
                    got = [list(c) for c in cols]
                    types = [getattr(c, "typecode", "b") for c in cols] == list("dddddbl" + "dddddb" * res) and \
                        isinstance(cols[5], bytearray)
                    if not (older == older2 and types and len(got) == len(want) and
                            all(repr(g) == repr(w) for g, w in zip(got, want))):
                        results.append("%s (res %s, since %d)" % (case, res, now - since))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    check(not results, "history: series() is load_points column by column, also for a day out of order, days that "
                       "overlap and a sample in the future (%s)" % (", ".join(results) or "4 cases x 6"))


# ------------------------------------------------------------------ in a pseudo-terminal
# A small session leader in the pseudo-terminal: it starts the program in its own (foreground) process
# group, waits for it, and reports the program's pid, its exit and whether the terminal's modes after it
# are the modes before it. (The terminal is taken from a session when its leader exits: the leader must
# outlive the program to look.)
# ------------------------------------------------------------------ machines (T2): the pure parts
def fake_tabs(n, now, states=None):
    """This machine and n others, with marks of every kind."""
    kinds = states or ["live", "offline", "attention", "live-warn", "connecting", "live-crit-inc"]
    tabs = [dict(mid="local", local=True, label="studio", cur=dict(pressure="Normal", t=now, interval=30, silent=False,
                                                                     incident=None), version="1.10.3", system="macOS 27.2")]
    for i in range(n):
        k = kinds[i % len(kinds)]
        st = {"state": "live", "updated": now, "pid": 1}
        cur = dict(pressure="Normal", t=now, interval=30, silent=False, incident=None)
        if k == "offline":
            st = {"state": "offline", "error": "timeout", "updated": now, "last_contact": now - 600, "next_try": now + 40}
        elif k == "attention":
            st = {"state": "needs_attention", "error": "identity_changed", "updated": now}
        elif k == "connecting":
            st = {"state": "connecting", "updated": now}
        elif k == "live-warn":
            cur["pressure"] = "Warning"
        elif k == "live-crit-inc":
            cur.update(pressure="Critical", incident="20261120-132412")
        tabs.append(dict(mid="m-%016x" % i, local=False, label="machine-number-%d" % (i + 1), addr="host%d.local" % i,
                         transport="tcp", status=st, pid_alive=True, cur=cur,
                         sync=dict(offset_s=0, have=[], gone=[], oldest=None, synced={}), known=now - 60,
                         opened=(now - 60, False), version="1.10.0", system="macOS 27.1"))
    return tabs


def test_resource_arrays():
    """The other resources (1.11.0) through the typed arrays: point for point view.multires's, the GPU's kind
    never averaged across its seam, and nothing of it while the switch is off."""
    rnd = random.Random(11)
    now = NOW
    pts, t = [], now - 2 * 86400
    while t < now:
        t += 30 if rnd.random() > 0.01 else 600
        full = t > now - 86400
        p = dict(t=float(t), wired=6.0, app=8.0 + rnd.random() * 4, comp=5.0, swap=0.0, away=False, kills=0,
                 cpu=None if rnd.random() < 0.05 else rnd.random() * 14, sys=rnd.random(), gpu=rnd.random() * 100,
                 gfull=full, gmem=rnd.random() * 20, disk=50 + rnd.random() * 10)
        pts.append(p)
    import array
    nan = float("nan")
    cols = [array.array("d", [p[k] for p in pts]) for k in ("t", "wired", "app", "comp", "swap")] + \
        [bytearray(0 for p in pts), array.array("l", [0 for p in pts])] + \
        [array.array("d", [nan if p[k] is None else p[k] for p in pts]) for k in V.RES_POINT] + \
        [bytearray(1 if p["gfull"] else 0 for p in pts)]
    a, b = T.multires_cols(cols, now), V.multires(pts, now)
    seam = [p for p in b if p["t"] > now - 86400 - 3000 and p["t"] < now - 86400 + 3000]
    check(a == b and all(isinstance(p["gfull"], bool) for p in b) and len(b) < len(pts),
          "resources: the thinning over typed arrays is point for point the view's, with cpu, gpu and disk (%d → %d)"
          % (len(pts), len(b)))
    agg = V.res_agg([dict(cpu=2.0, sys=0.5, gpu=90.0, gfull=False, gmem=3.0, disk=40.0),
                     dict(cpu=None, sys=None, gpu=30.0, gfull=True, gmem=5.0, disk=35.0),
                     dict(cpu=4.0, sys=1.5, gpu=10.0, gfull=True, gmem=None, disk=None)])
    check(agg == dict(cpu=3.0, sys=1.0, gpu=20.0, gfull=True, gmem=5.0, disk=35.0) and seam,
          "resources: a bucket keeps the rates' mean, the GPU's newest kind only, the most GPU memory, the least disk (%s)"
          % agg)
    plain = T._point({"t": 1.0, "app_gb": 1, "wired_gb": 1, "compressed_gb": 1, "swap_used_gb": 0, "cpu": {"busy": 3}})
    check("cpu" not in plain and T.History("/nonexistent").res is False and T.res_view({}) is None and
          T.res_view({"resourcesUI": "yes"}) is None,
          "resources: switched off unless top.json says \"resourcesUI\": true; no extra series are read then")
    check(T.res_view({"resourcesUI": True, "selection": ["disk", "nonsense", "cpu"], "focus": "disk"}) ==
          {"sel": ["cpu", "disk"], "focus": "disk"} and
          T.res_view({"resourcesUI": True, "selection": "memory", "focus": "gpu"}) == {"sel": ["memory"], "focus": "memory"},
          "resources: top.json's selection is read in tile order; anything else is Memory alone")


def test_pty_resources(base):
    """With the switch on: the tiles in place of the readings, m c g d and M C G D change what is shown,
    the last one is refused, and top.json remembers the selection apart from the app's."""
    log, led = topfixture.write_fixture(os.path.join(base, "fx"), "resources")
    env = {k: v for k, v in os.environ.items() if k not in ("COLORTERM", "SSH_CONNECTION", "NO_COLOR", "TERM_PROGRAM",
                                                             "COLORFGBG", "LC_ALL", "LC_CTYPE")}
    env.update(TERM="xterm-256color", LANG="en_US.UTF-8", OOMPH_DIR=log, OOMPH_LEDGER_DIR=led,
               OOMPH_STATE_DIR=os.path.join(base, "state"), TZ="Europe/Berlin")
    os.makedirs(env["OOMPH_STATE_DIR"], mode=0o700)
    with open(os.path.join(env["OOMPH_STATE_DIR"], "top.json"), "w") as f:
        json.dump({"v": 1, "resourcesUI": True}, f)

    def screen(p):
        vt = MiniVT(80, 32)
        vt.feed(p.text())
        return "\n".join("".join(c[0] for c in row) for row in vt.cells)
    p = Pty(top(), env, size=(80, 32))
    try:
        p.pump(5, until=b"Logging every")
        s0 = screen(p)
        tiles = "8.2 / 14 cores" in s0 and "45 GB free" in s0 and "Wired 7.2" in s0
        p.send("c", wait=0.4)
        s1 = screen(p)
        cpu = "System" in s1 and "Wired 7.2" not in s1
        p.send("c", wait=0.4)
        apps = "Top apps" in screen(p)
        p.send("esc", "M", "G", wait=0.5)
        s2 = screen(p)
        sparks = " Mem" in s2 and " GPU" in s2 and "System" in s2
        p.send("C", "G", "M", wait=0.5)
        refused = "can't be removed" in screen(p)
        p.send("q", wait=0.1)
        rc = p.wait(5)
    finally:
        p.close()
    saved = json.load(open(os.path.join(env["OOMPH_STATE_DIR"], "top.json")))
    check(tiles and cpu and apps and sparks and refused and rc == 0 and saved.get("selection") == ["memory"]
          and saved.get("focus") == "memory" and saved.get("resourcesUI") is True,
          "pty: with resourcesUI the tiles show the four resources; c gives the CPU the plot (again: its top apps); M G add "
          "rows under it; the last one shown can't be removed; top.json keeps the selection (%s)"
          % [tiles, cpu, apps, sparks, refused, rc, saved.get("selection"), saved.get("focus")])


def test_tab_ladder():
    """04 §3.7: at every width from 40 to 200 columns and with 1 to 13 machines, the first, a middle and the
    last selected: the selected tab with its label and its ×, the + and the capsule are there; a counter is a
    guillemet, a plus sign and a count; rows are as wide as the terminal."""
    caps = V.Caps("256", "unicode", "dark")
    g = V.GLYPHS["unicode"]
    bad = []
    for n in range(0, 13):
        for sel in sorted({0, n // 2, n}):
            for W in range(40, 201, 3):
                tabs = fake_tabs(n, NOW)
                m = dict(now=NOW, wall=NOW, brand="oomph", tabs=tabs, sel=sel, engine="on", cur=None, logger="ok")
                fr = V.Frame(W, 10)
                V.machine_tabs(fr, m, caps, g)
                row = "".join(c[0] for c in fr.c[0])
                lab = V.fit(tabs[sel]["label"], 2, g)[:1]
                hits = fr.tab_hits
                seltab = [h for h in hits if h[2] == "tab" and h[3] == sel]
                cap = V.tab_views(m)[sel]["capsule"][0] if sel else V.capsule(m)[0]
                why = None
                if not seltab:
                    why = "no selected tab"
                elif lab not in row[seltab[0][0]:seltab[0][1]]:
                    why = "the selected tab has no label"
                elif sel and g["close"] not in row[seltab[0][0]:seltab[0][1]]:
                    why = "no ×"
                elif not any(h[2] == "plus" for h in hits) or "+" not in row:
                    why = "no +"
                elif cap not in row:
                    why = "no capsule"
                elif len(fr.c[0]) != W:
                    why = "row width"
                for h in hits:
                    if h[2] == "more":
                        txt = row[h[0]:h[1]]
                        if not (("‹+" in txt and txt.index("‹+") == 0) if h[3] == "l" else txt.endswith("›")):
                            why = "a counter without its guillemet: %r" % txt
                        if not any(ch.isdigit() for ch in txt):
                            why = "a counter without its count: %r" % txt
                shown = {h[3] for h in hits if h[2] == "tab"}
                hidden = sum(int("".join(c for c in row[h[0]:h[1]] if c.isdigit())) for h in hits if h[2] == "more")
                if len(shown) + hidden != len(tabs):
                    why = "%d tabs shown and %d counted of %d" % (len(shown), hidden, len(tabs))
                if why:
                    bad.append("%d machines, %d selected, %d columns: %s (%r)" % (n + 1, sel + 1, W, why, row.rstrip()))
    check(not bad, "tab bar: 40 to 200 columns, 1 to 13 machines, first/middle/last selected: the selected tab with "
                   "label and ×, the +, the capsule and every machine shown or counted (%s)" % (bad[:2],))
    m = dict(now=NOW, wall=NOW, brand="oomph", tabs=fake_tabs(6, NOW), sel=2, engine="on", cur=None, logger="ok")
    fr = V.Frame(80, 2)
    V.machine_tabs(fr, m, caps, g)
    row = "".join(c[0] for c in fr.c[0])
    check(row.startswith(" oomph  1●  2●  3 machi… ⊘ ×  4▲  5◐  6↻  7◆!  +") and row.rstrip().endswith("Not connected  13:27"),
          "tab bar at 80 columns: labels cut alike, the marks by state and pressure, a red ! for an incident (%r)" % row)


def test_link_rows():
    """Every row of 04 §3.7's table: its capsule and its sentence from a status.json."""
    w = NOW
    cur = dict(pressure="Normal", t=w - 20, interval=30, silent=False, incident=None)
    rows = [
        ({"state": "live", "updated": w, "pid": 1}, cur, "Normal", "Logging every 30 s"),
        ({"state": "live", "updated": w, "pid": 1}, dict(cur, silent=True, t=w - 3600), "No readings",
         "Connected, but its logger stopped at 12:27"),
        ({"state": "catching_up", "updated": w, "pid": 1}, cur, "Normal", "Catching up: fetching missed history…"),
        ({"state": "offline", "error": "timeout", "updated": w, "last_contact": w - 1800, "next_try": w + 40}, cur,
         "Not connected", "No answer since 12:57 · next try in 40 s"),
        ({"state": "offline", "error": "refused", "updated": w}, cur, "Sharing is off there", "Last data 13:26"),
        ({"state": "offline", "error": "local_network_denied", "updated": w}, cur, "Blocked by macOS", "Last data 13:26"),
        ({"state": "needs_attention", "error": "identity_changed", "updated": w}, cur, "Key changed",
         "Its key changed · last data 13:26"),
        ({"state": "needs_attention", "error": "revoked", "updated": w}, cur, "Access revoked", "Access revoked · last data"),
        ({"state": "needs_attention", "error": "incompatible", "updated": w}, cur, "Too old", "talk to this one"),
        ({"state": "needs_attention", "error": "ssh", "updated": w}, cur, "SSH can't sign in", "SSH can't sign in · last"),
        ({"state": "pairing", "updated": w}, cur, "Pairing…", "Pairing…"),
        ({"state": "connecting", "updated": w}, cur, "Connecting…", "Last data 13:26"),
        ({"state": "live", "updated": w - 30, "pid": 1}, dict(cur, pressure="Warning"), "Not connected",
         "pressure was warning"),
    ]
    bad = []
    for st, c, cap, words in rows:
        t = dict(mid="m-0000000000000001", local=False, label="mac-mini", status=st, pid_alive=True, cur=c,
                 sync=dict(offset_s=0, have=[(w - 86400, w - 60)], gone=[], oldest=None,
                           synced={"ledger": True, "incidents": True}), known=w - 60,
                 opened=(w - 60, False), transport="tcp")
        v = V.link_view(t, w)
        s = V.machine_sentence(t, v, dict(now=w, wall=w, engine="on", tabs=[t]))
        if v["capsule"][0] != cap or words not in s:
            bad.append("%s/%s: %r %r" % (st["state"], st.get("error"), v["capsule"][0], s))
    t = dict(mid="m-0000000000000001", local=False, label="mac-mini", status={"state": "idle", "was": "live", "connect_ms": 400,
             "updated": w - 100}, pid_alive=False, cur=cur, sync={}, known=w - 100, opened=(w - 0.5, True), transport="tcp")
    grace = V.link_view(t, w)
    t["opened"] = (w - 2, True)
    conn = V.link_view(t, w)
    t["opened"] = (w - 9, True)
    after = V.link_view(t, w)
    ns = V.link_view(t, w, engine="off")
    check(not bad and grace["phase"] == "grace" and grace["dim"] and not grace["stale"] and
          conn["capsule"][0] == "Connecting…" and after["capsule"][0] == "Not connected" and
          ns["capsule"][0] == "Not syncing",
          "link: every row of 04 §3.7's table has its capsule and sentence; an opening is a grace (dimmed), then "
          "Connecting…, then Not connected at 8 s; --no-connect is Not syncing (%s)" % bad)
    crash = []
    for junk in ([], {}, 1e308, -1e308, 10 ** 400, "x", None, True):
        for st in ({"state": "offline", "error": junk, "last_contact": junk, "next_try": junk, "updated": junk},
                   {"state": junk, "error": "timeout", "updated": w, "last_contact": 1e308, "next_try": 1e308}):
            t = dict(mid="m-0000000000000001", local=False, label="mac-mini", status=st, pid_alive=True,
                     cur=dict(cur, t=junk), sync={}, known=junk, opened=(w - 60, False), transport="tcp")
            try:
                V.machine_sentence(t, V.link_view(t, w), dict(now=w, wall=w, engine="on", tabs=[t]))
            except Exception as e:
                crash.append("%s: %s" % (repr(st)[:120], e))
    check(not crash, "link: a status.json with lists, huge or odd values is drawn as not connected, not a crash (%s)"
          % crash[:2])


def test_mirror_gaps():
    """MachineStore.mirrorGaps in Python: inside coverage no data, outside not received, gone, not connected."""
    now = 10000.0
    nd, miss = V.mirror_gaps([(1000, 1600), (8000, 8500)], [(0, 5000), (6000, 9000)], [], 0, now, True)
    nd2, miss2 = V.mirror_gaps([], [(0, 5000)], [(-500, -100)], -500, now, False)
    nd3, miss3 = V.mirror_gaps([], [], [], None, now, True)
    nd4, miss4 = V.mirror_gaps([], [(0, now - 100)], [], 0, now, False)
    check(nd == [(1000, 1600), (8000, 8500)] and miss == [(5000, 6000, "not_received"), (9000, now, "not_connected")] and
          miss2 == [(-500, -100, "gone"), (-100, 0, "not_received"), (5000, now, "not_received")] and
          miss3 == [(now - 14 * 86400, now, "not_connected")] and miss4 == [],
          "not received: holes in the coverage map by kind; the youngest one while live only past a gap (%s %s %s %s)"
          % (miss, miss2, miss3, miss4))


def test_connect_rows():
    """04 §3.8: a complete address highlights "as typed" (round 1 sent 192.168.1.4 to a remembered .42); a
    beginning highlights the best match; nothing typed lists the Recents."""
    book = [{"mid": "m-1", "name": "build-box", "host": "build-box.local", "addrs": ["192.168.1.42"], "pinned": True},
            {"mid": "m-2", "name": "air", "host": "air.local", "addrs": [], "pinned": False, "last_connected": 5}]
    r1, s1 = V.connect_rows("192.168.1.4", book)
    r2, s2 = V.connect_rows("bui", book)
    r3, s3 = V.connect_rows("", book)
    r4, s4 = V.connect_rows("sam@atlas", book)
    check(r1[s1][0] == "typed" and r1[0][1]["mid"] == "m-1" and r2[s2][1]["mid"] == "m-1" and
          [r[1]["mid"] for r in r3] == ["m-2"] and s3 == 0 and r4[s4] == ("typed", "sam@atlas"),
          "connect: as typed for a complete address, the match for a beginning, Recents for nothing")
    msgs = [V.connect_message(c, "mac-mini.local") for c in ("refused", "timeout", "dns", "pair_failed", "too_many")]
    check(all(m and "this Mac" not in m.replace("Share this Mac", "") for m in msgs) and "mac-mini" in msgs[0] and
          "isn't oomph" in V.connect_message("not_oomph", "x.local") and
          "not installed" in V.connect_message("not_oomph", "sam@atlas", "oomph is not installed on atlas"),
          "connect: 01 §3.7's sentences, this Mac read as this computer")


# 04 §8's row expectations for what was a golden frame before the list closed: (what, mirror selected, width,
# height, span, glyphs, the dialog open, pinned machines more, {row: the row's text from its first column, or a
# piece of it}). The chart is in the goldens; these rows are the tab bar, the machine line, the dialogs and the keys.
MACHINE_ROWS = [
    ("tabs, this machine selected", "local", 80, 24, "24h", "unicode", None, 0, {
        0: " 1 studio ●  2 mac-m… ●  3 build… ⊘  4 gpu-b… ▲  5 rende… ↻  +    Normal  13:27",
        1: " ● studio · this machine · Logging every 30 s         oomph 1.10.0 · macOS 27.2",
        23: " q quit  ? help  a apps  ←→ span  ↑↓ select  tab machine  s sessions  e events"}),
    ("the attention card", "m-90a1b2c3d4e5f607", 80, 24, "24h", "unicode",
     {"kind": "attention", "mid": "m-90a1b2c3d4e5f607"}, 0, {
         0: " 1 studio ●  2 mac-m… ●  3 build… ⊘  4 gpu-b… ▲ ×  5 rende… ↻  +   Key changed",
         1: " ▲ gpu-box · Its key changed · last data yesterday 15:27           oomph 1.10.0",
         4: "╭─ gpu-box needs attention ─", 6: "│  Its key changed.  ",
         8: "│  gpu-box answers with a different key than the one pinned when   │",
         14: "│  Last data yesterday 15:27; what was received stays here.        │",
         18: "│  esc close  p pair again  X forget                               │", 23: " esc close"}),
    ("Connect, an address typed", "local", 80, 24, "24h", "unicode",
     {"kind": "connect", "text": "192.168.1.4", "sel": None}, 0, {
         4: "╭─ Connect to a machine ─", 6: "│  Address   192.168.1.4    ",
         8: "│    mac-mini   192.168.1.40 · macOS 27.1 · 64 GB           12:27  │",
         12: "│    air        192.168.1.47 · macOS 26.4 · 16…  Wed 18 Nov 13:27  │",
         13: "│  › + connect to “192.168.1.4” as typed                           │",
         18: "│  esc cancel  enter connect  tab complete  ↑↓ choose  ^D forget   │", 23: " esc close"}),
    ("the list of machines", "m-7f3a9c1e5b2d4a68", 80, 24, "24h", "unicode", {"kind": "list", "filter": "", "sel": 1}, 0, {
        0: " 1 studio ●  2 mac-m… ● ×  3 build… ⊘  4 gpu-b… ▲  5 rende… ↻  +        Normal",
        1: " ● mac-mini · Logging every 30 s                      oomph 1.10.0 · macOS 27.1",
        9: "│      1 ●  studio         this machine                       connected  │",
        10: "│  ›   2 ●  mac-mini       mac-mini.local                     connected  │",
        11: "│      3 ⊘  build-box      build-box.local                not connected  │",
        12: "│      4 ▲  gpu-box        gpu-box.loc…    needs attention: key changed  │",
        13: "│      5 ↻  render-01      sam@render-01                    catching up  │",
        16: "│  esc close  enter show  ↑↓ choose  type to filter                      │", 23: " esc close"}),
    ("twelve tabs in ASCII", "m-1b2c3d4e5f607182", 80, 24, "6h", "ascii", None, 8, {
        0: " 1*  2*  3 build~ o x  4^  5~  6o  7o  8o  9o  10o  o+3>  +      Not connected",
        1: " o build-box - No answer since 12:47 - next try in 40 s            oomph 1.10.0",
        4: "+- all  24h  6h  1h -------- #Wired #App #Compr. #Swap /no data :not received -+",
        6: "|                ::::::::::::::::::::!::::::::::::::::::::::::::::::::::::     |",
        12: "+- Reserved by agents ------------------------- as of 12:47: 12.0 GB reserved -+",
        18: "|  #  2.0G  pnpm check              webshop                     was using 0.3G |",
        23: " q quit  ? help  r retry now  x disconnect  X forget  tab machine  + add"}),
]


def test_linux_desktop_rows():
    """T3 (1.13.4): a Linux laptop whose only swap is zram, at 100x30 with the inspect readout, as rows (it was a
    golden frame; 04 §10 closes their list): the machine line says what is available, the tiles zram and Kernel,
    the legend the series it has (no Swap: no swap file, no swap total), the readout Kernel and available; no
    Mac word anywhere."""
    base = tempfile.mkdtemp(prefix="oomph-toptest-")
    try:
        fr = topfixture.frames(base, topfixture.ROW_FRAMES)["100x30-linux-desktop.ans"][1]
    finally:
        shutil.rmtree(base, ignore_errors=True)
    rows = fr.text().rstrip("\n").split("\n")
    legend = next((r for r in rows if "Memory" in r and "■" in r), "")
    want = (len(rows) == 30 and "avail" in rows[0] and "zram / size" in rows[2] and "Kernel" in rows[2] and
            "■Kernel ■App ■Compressed" in legend and "Swap" not in legend and
            any("Inspect" in r for r in rows) and any("■ Kernel" in r for r in rows) and
            any(r.startswith("│ available ") for r in rows) and
            not re.search(r"Wired|[Uu]nowned|jetsam|Activity Monitor", "\n".join(rows)))
    check(want, "Linux laptop with zram, 100x30, inspect: available, zram and Kernel, the legend without Swap, the "
                "readout in Linux words (%r)" % (rows[:3] if not want else legend.strip()[:60]))


def test_linux_server_rows():
    """T3 (1.13.4): a Linux server at 80x24 in 256 colours, as rows (04 §10 closes the list of goldens; the console
    frame of the same scenario is the golden): the machine line says avail, the tiles Available, Kernel, Swap / size
    and Stalled, the legend Kernel, App and Swap (no Compressed: no zram or zswap); no Mac word anywhere."""
    base = tempfile.mkdtemp(prefix="oomph-toptest-")
    try:
        fr = topfixture.frames(base, topfixture.ROW_FRAMES)["80x24-linux-server.ans"][1]
    finally:
        shutil.rmtree(base, ignore_errors=True)
    rows = fr.text().rstrip("\n").split("\n")
    legend = rows[3] if len(rows) > 3 else ""
    want = (len(rows) == 24 and "9.5G avail" in rows[0] and
            all(w in rows[2] for w in ("App memory", "Available", "Kernel", "RAM total", "Swap / size", "Stalled")) and
            "■Kernel ■App ■Swap" in legend and "Compressed" not in legend and "no data" in legend and
            any("Incidents" in r for r in rows) and
            not re.search(r"Wired|[Uu]nowned|jetsam|Activity Monitor|Compressed", "\n".join(rows)))
    check(want, "Linux server, 80x24: avail, Available, Kernel, Swap / size and Stalled, the legend without "
                "Compressed, no Mac word (%r)" % (rows[:4] if not want else legend.strip()[:60]))


def test_linux_live():
    """T3 (1.13.4): oomph top on Linux with no logger draws a live sample, which has no logger's machine block: the
    machine's own (oomph_linux.machine, read once) gives its words. A zram desktop then has Compressed in the
    legend and the tiles, zram as its only swap and Idle, as with a logger."""
    with open(os.path.join(ROOT, "tools", "vectors", "linux.json"), encoding="utf-8") as f:
        case = next(c for c in json.load(f)["inputs"]["tiles"] if c["case"] == "desktop, no idle time")
    s = dict(case["sample"], source="live")
    machine = s.pop("daemon")["machine"]
    saved = list(T._LIVE_MACHINE)
    try:
        T._LIVE_MACHINE[:] = [machine]
        c = T.readings(s)
        T._LIVE_MACHINE[:] = [None]                 # not on Linux, or not known: the defaults, never a crash
        bare = T.readings(s)
    finally:
        T._LIVE_MACHINE[:] = saved
    names = [n for n, _ in V.series_words(c)]
    labels = [x[1] for x in V.linux_tiles(c, V.GLYPHS["unicode"])]
    check(names == ["Kernel", "App", "Compressed"] and "Compressed" in labels and "zram / size" in labels and
          "Idle" in labels and "Available" not in labels and bare.get("linux") is not None,
          "Linux, no logger: a live zram desktop's legend has Compressed, its tiles Compressed, zram / size and "
          "Idle (%s; %s)" % (names, labels))


def test_machine_rows():
    """04 §8: the machine frames beyond the four goldens, as rows (from the same fixture and model)."""
    base = tempfile.mkdtemp(prefix="oomph-toptest-")
    led, log = oomph.LEDGER_DIR, oomph.LOG_DIR
    try:
        dirs = {}
        for what, mid, w, h, span, glyphs, ov, more, rows in MACHINE_ROWS:
            got = topfixture.machine_frame(base, dirs, mid, w, h, span, glyphs, ov, more).text().rstrip("\n").split("\n")
            bad = [(y, got[y].rstrip()) for y, want in sorted(rows.items())
                   if y >= len(got) or (want != got[y].rstrip() if not want.endswith(" ") and len(want) >= w - 4
                                        else want.strip() not in got[y])]
            check(not bad, "machine rows: %s (%s)" % (what, bad[:2]))
    finally:
        oomph.LEDGER_DIR, oomph.LOG_DIR = led, log
        shutil.rmtree(base, ignore_errors=True)


LAUNCHER = r"""
import json, os, resource, signal, subprocess, sys, termios, fcntl
os.setsid()
fcntl.ioctl(0, termios.TIOCSCTTY, 0)
signal.signal(signal.SIGHUP, signal.SIG_IGN)
before = termios.tcgetattr(0)
rep = int(sys.argv[1])
jobs = sys.argv[2] == "--jobs"
def pre():
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    if jobs:  # a process group of its own in the foreground, as a shell starts a job: ctrl-z can stop it
        os.setpgid(0, 0)
        signal.signal(signal.SIGTTOU, signal.SIG_IGN)
        os.tcsetpgrp(0, os.getpid())
        signal.signal(signal.SIGTTOU, signal.SIG_DFL)
p = subprocess.Popen(sys.argv[3:] if jobs else sys.argv[2:], pass_fds=(), restore_signals=True, preexec_fn=pre)
os.write(rep, (json.dumps({"pid": p.pid}) + "\n").encode())
rc = p.wait()
def modes(a):  # PENDIN is the kernel's own note that input is to be retyped: not a mode anybody set
    a = list(a)
    a[3] &= ~getattr(termios, "PENDIN", 0)
    return a
try:
    same = modes(termios.tcgetattr(0)) == modes(before)
except termios.error:
    same = None
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
os.write(rep, (json.dumps({"rc": rc, "same": same, "cpu": ru.ru_utime + ru.ru_stime, "rss": ru.ru_maxrss}) +
               "\n").encode())
"""


class Pty:
    """The program on a pseudo-terminal of our own, under LAUNCHER: in the session leader's process
    group (no job control, as under sshd), or with `jobs` in a foreground group of its own (as a shell
    runs it)."""

    def __init__(self, args, env, size=(80, 24), timeout=30, jobs=False):
        self.master, self.slave = os.openpty()
        self.size(*size)
        self.rep_r, rep_w = os.pipe()
        self.p = subprocess.Popen([PY, "-I", "-c", LAUNCHER, str(rep_w)] + (["--jobs"] if jobs else []) + args, stdin=self.slave, stdout=self.slave,
                                  stderr=self.slave, env=env, pass_fds=(rep_w,))
        os.close(rep_w)
        os.close(self.slave)
        self.slave = None
        self.out, self.report, self.buf = b"", {}, b""
        self.ru = None
        self.closed = False
        self.pid = None
        end = time.time() + 10
        while self.pid is None and time.time() < end:
            self._report(0.1)
            self.pid = self.report.get("pid")

    def _report(self, wait):
        r, _, _ = select.select([self.rep_r], [], [], wait)
        if r:
            d = os.read(self.rep_r, 4096)
            self.buf += d
            while b"\n" in self.buf:
                line, self.buf = self.buf.split(b"\n", 1)
                self.report.update(json.loads(line))

    def size(self, w, h):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", h, w, 0, 0))

    def pump(self, secs, until=None):
        end = time.time() + secs
        while time.time() < end and not self.closed:
            r, _, _ = select.select([self.master], [], [], 0.05)
            if r:
                try:
                    d = os.read(self.master, 65536)
                except OSError:
                    return
                if not d:
                    return
                self.out += d
                if until and until in self.out:
                    return

    def send(self, *keys, wait=0.25):
        for k in keys:
            os.write(self.master, KEYS.get(k, k.encode() if isinstance(k, str) else k))
            self.pump(wait)

    def wait(self, secs=5):
        """The program's exit code (negative: a signal), or None if it is still running after secs."""
        end = time.time() + secs
        while time.time() < end:
            self.pump(0.05)
            self._report(0.0)
            if "rc" in self.report:
                return self.report["rc"]
        return None

    def restored(self):
        return self.report.get("same")

    def kill(self):
        for pid in (self.pid, self.p.pid):
            try:
                if pid:
                    os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            pass

    def close(self):
        self.kill()
        for fd in ([] if self.closed else [self.master]) + [self.rep_r]:
            try:
                os.close(fd)
            except OSError:
                pass
        self.closed = True

    def text(self):
        return self.out.decode("utf-8", "replace")


def fixture_env(base, extra=None):
    log, led = topfixture.write_fixture(os.path.join(base, "fx"), "default")
    env = {k: v for k, v in os.environ.items() if k not in ("COLORTERM", "SSH_CONNECTION", "NO_COLOR", "TERM_PROGRAM",
                                                             "COLORFGBG", "LC_ALL", "LC_CTYPE")}
    env.update(TERM="xterm-256color", LANG="en_US.UTF-8", OOMPH_DIR=log, OOMPH_LEDGER_DIR=led,
               OOMPH_STATE_DIR=os.path.join(base, "state"), TZ="Europe/Berlin")
    env.update(extra or {})
    return env, log, led


def top(*args):
    return [PY, "-I", "-B", CLI, "top", "--now", str(int(NOW)), "--no-probe"] + list(args)


def test_pty(base):
    env, log, led = fixture_env(base)
    oomph.LEDGER_DIR = led
    model = T.load_model("24h", NOW, log_dir=log, live=False)
    model.update(host=T.host_name(), os=T.os_name())
    caps = V.Caps("256", "unicode", "dark")
    t0 = time.time()
    p = Pty(top(), env)
    try:
        p.pump(5, until=b"Logging every")
        first = time.time() - t0
        check(b"\x1b[?1049h" in p.out and b"Logging every" in p.out and first < 5,
              "pty: the first frame arrives (%.2f s; the budget is 0.3 s on the reference Mac, 1.5 s on a runner)" % first)
        p.send("right", "right", "a", "esc", "up", "enter", "esc", "?", "?", "esc")
        p.size(100, 30)
        p.pump(0.4)
        p.size(80, 24)
        p.pump(0.4)
        vt = MiniVT(80, 24)
        vt.feed(p.text())
        ui = {"span": "1h"}
        V.press(ui, "up", model, V.layout(model, 80, 24))
        m1 = T.load_model("1h", NOW, log_dir=log, live=False)
        m1.update(host=model["host"], os=model["os"])
        tabs = T.no_tabs_reason(None) is None and T.sync_module() is not None
        want = V.render(T.with_tabs(m1) if tabs else m1, 80, 24, caps, ui)   # (with machines: its own tab and the +, 04 §3.7)
        why = vt.shows(want, caps)
        p.send("q", wait=0.1)
        rc = p.wait(5)
        check(why is None, "pty: keys and two resizes end on the frame render() draws for that state (%s)" % why)
        check(rc == 0 and p.out.endswith(T.LEAVE.encode()) and p.restored() and b"Traceback" not in p.out,
              "pty: q leaves with exit 0, the leave sequences last and the terminal's modes as they were (rc %s)" % rc)
    finally:
        p.close()
    for sig in (signal.SIGTERM, signal.SIGHUP):
        p = Pty(top(), env)
        try:
            p.pump(5, until=b"Logging every")
            os.kill(p.pid, sig)
            rc = p.wait(5)
            check(rc == 0 and p.out.endswith(T.LEAVE.encode()) and p.restored(),
                  "pty: %s leaves with exit 0 and the terminal restored (rc %s)" % (signal.Signals(sig).name, rc))
        finally:
            p.close()
    p = Pty(top(), env, jobs=True)
    try:
        p.pump(5, until=b"Logging every")
        n0 = len(p.out)
        p.send("ctrl-z", wait=0.5)
        left = p.out.find(b"\x1b[?1049l", n0)
        stat = subprocess.run(["ps", "-o", "stat=", "-p", str(p.pid)], capture_output=True, text=True,
                              timeout=10).stdout.strip()
        stopped = left >= 0 and stat.startswith("T")
        os.kill(p.pid, signal.SIGCONT)
        p.pump(1.0)
        again = left >= 0 and b"\x1b[?1049h" in p.out[left:] and b"Logging every" in p.out[left:]
        quiet = b"can't suspend" not in p.out
        p.send("q", wait=0.1)
        rc = p.wait(5)
        check(stopped and again and quiet and rc == 0,
              "pty: in a job of its own ctrl-z restores the terminal and stops (ps: %r); on SIGCONT it repaints; "
              "q still quits (%s %s %s)" % (stat, again, quiet, rc))
    finally:
        p.close()
    p = Pty(top(), dict(env, SSH_CONNECTION="10.0.0.1 1 10.0.0.2 22"))
    try:
        p.pump(5, until=b"Logging every")
        n0 = len(p.out)
        p.send("ctrl-z", wait=0.5)
        told = b"can't suspend" in p.out[n0:] and b"enter ~ ctrl-z" in p.out[n0:]
        flash = b"\x1b[?1049l" in p.out[n0:]
        p.send("q", wait=0.1)
        rc = p.wait(5)
        check(told and not flash and rc == 0, "pty: as the session's leader (as under sshd) ctrl-z, which the kernel "
                                              "would discard, leaves the screen alone and names ssh's ~ ctrl-z "
                                              "(%s %s %s)" % (told, flash, rc))
    finally:
        p.close()
    p = Pty(top(), env, size=(300, 100))
    try:
        p.pump(5, until=b"Logging every")
        for _ in range(40):                          # repaints nobody reads: the writer blocks on a full terminal
            os.write(p.master, b"\x0c\x1b[C\x1b[D")
        time.sleep(1.0)
        t0 = time.time()
        os.kill(p.pid, signal.SIGTERM)
        rc = p.wait(3)
        check(rc is not None and time.time() - t0 < 2.0, "pty: SIGTERM while the program is blocked writing to a "
                                                          "terminal nobody reads: gone in %.2f s" % (time.time() - t0))
    finally:
        p.close()
    p = Pty(top(), env)
    try:
        p.pump(5, until=b"Logging every")
        os.close(p.master)
        p.closed = True
        t0 = time.time()
        rc = p.wait(3)
        check(rc == 0 and time.time() - t0 < 2.0, "pty: the terminal closed without a signal: the program leaves at once, "
                                                  "exit %s" % rc)
    finally:
        p.close()
    p = Pty(top("--some-later-option"), dict(env, SSH_CONNECTION="10.0.0.1 1 10.0.0.2 22"))
    try:
        p.pump(5, until=b"Logging every")
        p.send(b"\x1b[200~q\x1b[201~", wait=0.4)
        pasted = b"pasted text ignored" in p.out
        p.send("up", "y", wait=0.4)
        inc = model["incidents"][0]
        want = base64.b64encode(inc["dir"].encode()).decode()
        osc = ("\x1b]52;c;%s\x07" % want) in p.text()
        p.send("q", wait=0.1)
        rc = p.wait(5)
        check(pasted and osc and b"ignored: --some-later-option" in p.out and rc == 0,
              "pty: a paste with no field open runs nothing; over SSH y sends the path as OSC 52; an unknown option is "
              "named (%s %s)" % (pasted, osc))
    finally:
        p.close()
    for extra, what in (({"TERM": "dumb"}, "TERM=dumb"),):
        p = Pty(top(), dict(env, **extra))
        try:
            rc = p.wait(10)
            check(rc == 2 and b"--once" in p.out, "pty: %s exits 2 and points to --once (rc %s)" % (what, rc))
        finally:
            p.close()
    r = subprocess.run(top(), stdin=subprocess.DEVNULL, capture_output=True, text=True, env=env, timeout=30)
    check(r.returncode == 2 and "--once" in r.stderr, "without a terminal oomph top exits 2 and points to --once")


# ------------------------------------------------------------------ machines (T2) in the pty
FAKE_REMOTE = r'''
import json, os, sys
log = os.environ["FAKE_REMOTE_LOG"]
def rec(o):
    with open(log, "a") as f:
        f.write(json.dumps(o) + "\n")
def out(o):
    sys.stdout.write(json.dumps(o) + "\n")
    sys.stdout.flush()
args = sys.argv[1:]
rec({"argv": args, "pid": os.getpid()})
mdir = os.environ["OOMPH_MACHINES_DIR"]
def book(f=None):
    b = json.load(open(os.path.join(mdir, "machines.json")))
    if f is not None:
        f(b)
        json.dump(b, open(os.path.join(mdir, ".m.tmp"), "w"))
        os.rename(os.path.join(mdir, ".m.tmp"), os.path.join(mdir, "machines.json"))
    return b
if args[:1] == ["sync"]:
    out({"ev": "hello", "pid": os.getpid()})
    for line in sys.stdin:
        c = json.loads(line)
        rec({"cmd": c, "pid": os.getpid()})
        if c.get("cmd") == "forget" and c.get("id") == "m-00000000000000bb":     # the book was busy: it stays
            out({"ev": "failed", "cmd": "forget", "id": c["id"], "reason": "busy", "detail": "the book is busy"})
        elif c.get("cmd") == "forget":                                            # as the engine does: it goes
            gone = [e for e in book()["machines"] if e["mid"] == c["id"]]
            json.dump(gone, open(os.path.join(mdir, ".forgotten"), "w"))
            book(lambda b: b.update(machines=[e for e in b["machines"] if e["mid"] != c["id"]]))
        out({"ev": "machines"})
    rec({"eof": os.getpid()})
    sys.exit(0)
target = args[1]
if target == "gpu-box.local":           # the forgotten machine, added again: its own id again (01's Book.place)
    again = json.load(open(os.path.join(mdir, ".forgotten")))
    book(lambda b: b["machines"].extend(dict(e, pinned=True) for e in again))
    out({"ok": True, "machine": {"mid": again[0]["mid"], "name": "gpu-box"}, "new": False})
    sys.exit(0)
code = sys.stdin.readline().strip() if "--code" in args else None
rec({"code": code})
if target == "new.local" and code is None:
    out({"ok": False, "error": "needs_code", "fp": "sha256:" + "ab" * 32, "fp_short": "ABAB ABAB ABAB ABAB"})
    sys.exit(1)
if code == "AAAA-AAAA-AAAA":
    out({"ok": False, "error": "pair_failed", "detail": "the code was not accepted"})
    sys.exit(1)
if target == "new.local":
    out({"ev": "ask", "question": "identity", "detail": "same id", "known": {"mid": "m-1b2c3d4e5f607182", "label": "build-box"}})
    a = sys.stdin.readline().strip()
    rec({"answer": a})
    if a != "new":
        out({"ok": False, "error": "ask", "detail": "nothing added"})
        sys.exit(1)
mid = "m-00000000000000aa"
b = json.load(open(os.path.join(mdir, "machines.json")))
b["machines"].append({"mid": mid, "id": mid, "name": "new-box", "transport": "tcp", "host": "new-box.local", "port": 6674,
                      "pinned": True, "order": 50})
json.dump(b, open(os.path.join(mdir, ".m.tmp"), "w"))
os.rename(os.path.join(mdir, ".m.tmp"), os.path.join(mdir, "machines.json"))
out({"ok": True, "machine": {"mid": mid, "name": "new-box", "os_version": "macOS 27.2", "ram_gb": 64, "version": "1.10.3"},
     "new": target == "new.local"})
'''


def screen(p, w=80, h=24):
    vt = MiniVT(w, h)
    vt.feed(p.text())
    return "\n".join("".join(c[0] for c in row) for row in vt.cells)


def records(path):
    try:
        with open(path) as f:
            return [json.loads(x) for x in f if x.strip()]
    except OSError:
        return []


def wait_until(fn, secs, p=None):
    end = time.time() + secs
    while time.time() < end:
        if p is not None:
            p.pump(0.1)
        else:
            time.sleep(0.1)
        if fn():
            return True
    return False


def test_pty_machines(base):
    """04 §10.8 with a scripted sync child (01's commands recorded) and a scripted `remote add`: tabs from
    machines.json, switching, retry, disconnect and undo, rename, forget, connect with the pairing code (a
    wrong one, the identity question, the tab's name), ssh with its consent, a machine added by "the app",
    the machine list, the "what happened" card; ctrl-z quits the child and a resume starts one; q ends it."""
    os.makedirs(base)
    env, log, led = fixture_env(base)
    mdir = topfixture.write_machines(os.path.join(base, "m"), pid=os.getpid())
    fake = os.path.join(base, "fake_remote.py")
    with open(fake, "w") as f:
        f.write(FAKE_REMOTE)
    flog = os.path.join(base, "remote.log")
    env.update(OOMPH_MACHINES_DIR=mdir, OOMPH_TOP_REMOTE=json.dumps([PY, "-I", fake]), FAKE_REMOTE_LOG=flog)
    r1 = subprocess.run(top("--once", "--machine", "build-box", "--size", "80x24", "--format", "text"), env=env,
                        capture_output=True, text=True, timeout=30)
    r2 = subprocess.run(top("--once", "--machine", "nope", "--size", "80x24"), env=env, capture_output=True, text=True,
                        timeout=30)
    check(r1.returncode == 0 and "build-box · No answer since 12:47" in r1.stdout and r2.returncode == 2 and
          "no machine named nope" in r2.stderr,
          "machines: --once --machine NAME prints that tab's frame; an unknown name is refused (exit 2) (%s %s)"
          % (r1.returncode, r1.stderr[-200:] + r2.stderr[-200:]))
    p = Pty(top(), env, jobs=True)
    mini, build, gpu = "m-7f3a9c1e5b2d4a68", "m-1b2c3d4e5f607182", "m-90a1b2c3d4e5f607"

    def cmds(kind=None):
        return [r["cmd"] for r in records(flog) if "cmd" in r and (kind is None or r["cmd"].get("cmd") == kind)]
    try:
        p.pump(5, until=b"this machine")
        s0 = screen(p)
        watched = wait_until(lambda: any(c.get("cmd") == "watch" and set(c["ids"]) >= {mini, build, gpu} for c in cmds()), 5, p)
        check("1 studio" in s0.splitlines()[0] or " 1 " in s0.splitlines()[0] and "this machine" in s0 and watched,
              "machines: the tabs of machines.json after this one; the sync child is told to watch them all")
        p.send("3", wait=0.2)                     # the worker reads build-box's history first: on a slow runner
        wait_until(lambda: "build-box · No answer since 12:47" in screen(p) and "Not connected" in screen(p), 6, p)
        # (that is more than half a second; wait for the whole sentence, a frame can come in two reads)
        s3 = screen(p)
        focus = wait_until(lambda: any(c.get("cmd") == "watch" and c.get("focus") == build for c in cmds()), 3, p)
        p.send("r", wait=0.4)
        retried = any(c == {"cmd": "retry", "id": build} for c in cmds())
        check("build-box · No answer since 12:47" in s3 and "Not connected" in s3 and focus and retried,
              "machines: 3 shows build-box, not connected, its sentence; the child is told it is the focus; r retries")
        p.send("x", wait=0.5)
        sx = screen(p)
        p.send("u", wait=0.5)
        check(any(c == {"cmd": "unpin", "id": build} for c in cmds()) and "build-box disconnected · u undo" in sx and
              any(c == {"cmd": "pin", "id": build} for c in cmds()),
              "machines: x disconnects (unpin) and says so with u undo for 6 s; u pins it again")
        p.send("2", "R", "m", "i", "n", "i", "enter", wait=0.4)
        check(any(c == {"cmd": "rename", "id": mini, "label": "mini"} for c in cmds()),
              "machines: R asks for the tab's name (typing replaces the name shown) and renames it")
        p.send("4", "r", wait=0.5)
        no_retry = "r can't help: enter says why" in screen(p) and not any(c == {"cmd": "retry", "id": gpu} for c in cmds())
        p.send("enter", wait=0.6)
        card = screen(p)
        p.send("esc", "X", wait=0.5)
        forget_q = screen(p)
        p.send("y", wait=0.5)
        check("gpu-box needs attention" in card and "Its key changed." in card and "p pair again" in card and
              "Forget gpu-box?" in forget_q and any(c == {"cmd": "forget", "id": gpu} for c in cmds()) and no_retry,
              "machines: r where retrying can't help says so (no retry); enter on a tab that needs attention shows "
              "what happened; X asks, y forgets (%s)" % no_retry)
        def watched_now():
            w = cmds("watch")
            return w[-1] if w else {}
        gone = wait_until(lambda: gpu not in watched_now().get("ids", []) and "gpu-box · " not in screen(p), 4, p)
        p.send("+", wait=0.3)
        for ch in "gpu-box.local":
            os.write(p.master, ch.encode())
        p.pump(0.3)
        p.send("enter", wait=0.3)
        back = wait_until(lambda: watched_now().get("focus") == gpu and "gpu-box · " in screen(p), 6, p)
        check(gone and back, "machines: a machine forgotten and added again in the same run is a tab again, and "
                             "shown (%s %s)" % (gone, back))
        p.send("+", wait=0.4)
        for ch in "new.local":
            os.write(p.master, ch.encode())
        p.pump(0.3)
        p.send("enter", wait=0.2)
        pair_up = wait_until(lambda: "Pair with new.local" in screen(p), 6, p)
        sp = screen(p)
        for ch in "aaaa-aaaa-aaaa":
            os.write(p.master, ch.encode())
        p.pump(0.3)
        p.send("enter", wait=0.2)
        wrong = wait_until(lambda: "wasn't accepted" in screen(p), 6, p)
        p.send(b"\x15", wait=0.2)                    # ctrl-u: the field empty again
        os.write(p.master, b"\x1b[200~k7qf-2m9x-d4tr\x1b[201~")   # a paste fills it
        p.pump(0.3)
        p.send("enter", wait=0.2)
        asked = wait_until(lambda: "Same machine as build-box?" in screen(p), 6, p)
        p.send("enter", wait=0.2)
        named = wait_until(lambda: "Paired with new-box" in screen(p), 6, p)
        for ch in "box":
            os.write(p.master, ch.encode())
        p.pump(0.3)
        p.send("enter", wait=0.6)
        recs = records(flog)
        adds = [r["argv"] for r in recs if "argv" in r and r["argv"][:1] == ["add"]]
        codes = [r["code"] for r in recs if "code" in r]
        newtab = wait_until(lambda: "new-" in screen(p).splitlines()[0], 4, p)
        check(pair_up and "ABAB ABAB ABAB ABAB" in sp and "sudo oomph share pair" in sp and wrong and asked and named and
              any(r.get("answer") == "new" for r in recs) and
              all("K7QF" not in " ".join(a) and "AAAA" not in " ".join(a) for a in adds) and
              ["--code", "-", "--fp", "sha256:" + "ab" * 32] == adds[-1][-4:] and codes[-1] == "K7QF-2M9X-D4TR" and
              any(c == {"cmd": "rename", "id": "m-00000000000000aa", "label": "box"} for c in cmds()) and newtab,
              "machines: + to a new machine asks for its code with the key; a wrong code is said in the dialog; a "
              "paste fills the code; the identity question answers new; the tab's name renames it; the code goes on "
              "stdin, never in an argument (%s %s %s %s %s %s %s)" % (pair_up, wrong, asked, named, codes[-1:], newtab,
                                                                      "ABAB ABAB ABAB ABAB" in sp))
        p.send("+", wait=0.3)
        for ch in "sam@atlas":
            os.write(p.master, ch.encode())
        p.pump(0.3)
        p.send("enter", wait=0.4)
        consent = screen(p)
        p.send("enter", wait=0.2)
        closed = wait_until(lambda: "Connect to" not in screen(p), 6, p)
        adds = [r["argv"] for r in records(flog) if "argv" in r and r["argv"][:1] == ["add"]]
        check("ssh -l sam -- atlas oomph serve --stdio" in consent and "Whoever can sign in to atlas as sam" in consent and
              closed and adds[-1][:2] == ["add", "sam@atlas"],
              "machines: ssh needs no code; the dialog shows the command and the consent, enter connects")
        b = json.load(open(os.path.join(mdir, "machines.json")))
        b["machines"].append({"mid": "m-00000000000000bb", "name": "from-the-app", "transport": "tcp",
                              "host": "from-the-app.local", "port": 6674, "pinned": True, "order": 60})
        json.dump(b, open(os.path.join(mdir, ".x"), "w"))
        os.rename(os.path.join(mdir, ".x"), os.path.join(mdir, "machines.json"))
        p.send("0", wait=0.3)
        for ch in "from":
            os.write(p.master, ch.encode())
        appeared = wait_until(lambda: "from-the-app" in screen(p), 4, p)
        p.send("enter", wait=0.5)
        shown = "from-the-app · " in screen(p)
        check(appeared and shown, "machines: a machine added by the app appears; 0 lists every machine, typing filters, "
                                  "enter shows it")
        p.send("X", wait=0.4)
        p.send("y", wait=0.2)
        failed = wait_until(lambda: "forget failed: the book is busy" in screen(p), 4, p)
        p.pump(1.5)                                  # (the worker's next models: a hidden tab would be gone by now)
        kept = wait_until(lambda: "m-00000000000000bb" in watched_now().get("ids", []), 4, p)
        check(failed and kept, "machines: a forget the engine could not do is said, and the tab comes back (%s %s)"
                               % (failed, kept))
        n_sync = len([r for r in records(flog) if r.get("argv", [None])[:1] == ["sync"]])
        p.send("ctrl-z", wait=0.6)
        quitted = wait_until(lambda: len([r for r in records(flog) if "eof" in r]) >= 1, 3)
        os.kill(p.pid, signal.SIGCONT)
        again = wait_until(lambda: len([r for r in records(flog) if r.get("argv", [None])[:1] == ["sync"]]) > n_sync, 6, p)
        check(quitted and again, "machines: ctrl-z ends the sync child (the end of its input: the lock is free for the "
                                 "app at once); after fg a new one runs (%s %s)" % (quitted, again))
        p.send("q", wait=0.2)
        rc = p.wait(5)
        ended = wait_until(lambda: len([r for r in records(flog) if "eof" in r]) >= 2, 3)
        check(rc == 0 and ended and p.restored() and b"Traceback" not in p.out,
              "machines: q leaves (exit 0) and the sync child gets the end of its input (rc %s)" % rc)
    finally:
        p.close()
    p = Pty(top("--no-connect"), env)
    try:
        p.pump(5, until=b"this machine")
        p.send("3", wait=0.2)
        wait_until(lambda: "Not syncing (--no-connect)" in screen(p), 6, p)   # (build-box's history read first)
        s = screen(p)
        n0 = len(records(flog))
        p.send("+", wait=0.4)
        s2 = screen(p)
        p.send("q", wait=0.1)
        rc = p.wait(5)
        check("Not syncing" in s and "--no-connect" in s and "--no-connect: nothing is added" in s2 and
              not [r for r in records(flog)[n0:] if "argv" in r] and rc == 0,
              "--no-connect: no child; the tabs say Not syncing (--no-connect); + says why it adds nothing")
    finally:
        p.close()
    app = T.App.__new__(T.App)                     # a thirteenth machine: 01's sentence
    tabs = fake_tabs(12, NOW)
    app.model, app.ui, app.sync, app.M, app.note_until, app.dirty = dict(tabs=tabs, sel=0), {}, object(), object(), 0, False
    app.mid, app.undo = "local", None
    app.key_machines("+", dict(tabs=tabs, sel=0, now=NOW, wall=NOW, engine="on"))
    check("overlay" not in app.ui and "Twelve machines are connected" in app.ui.get("note", ("",))[0],
          "machines: + with twelve other machines says 01's sentence and opens nothing")
    tabs = fake_tabs(3, NOW)                       # a click on row 0: a tab is shown, the + opens Connect
    m = dict(tabs=tabs, sel=0, now=NOW, wall=NOW, engine="on", brand="oomph", cur=None, logger="ok")
    app.model, app.ui, app.size, app.caps, app.src = m, {}, (80, 24), V.Caps("256", "unicode", "dark"), T.Source("/nonexistent", None)
    app.model_now = lambda: m
    fr = V.Frame(80, 1)
    V.machine_tabs(fr, m, app.caps, V.GLYPHS["unicode"])
    hit = {h[2] + str(h[3]): h[0] for h in fr.tab_hits}
    app.click(0, hit["tab2"], 0)
    picked = app.mid
    app.click(0, hit["plusNone"], 0)
    check(picked == tabs[2]["mid"] and app.ui.get("overlay", {}).get("kind") == "connect",
          "machines: with the mouse on, a click on a tab shows it and a click on + opens Connect")


def test_viewer(base):
    """T3 (1.13.4): this machine as a viewer, on a Mac and on Linux alike, with nothing but the defaults (no
    switch, no OOMPH_STATE_DIR, no OOMPH_MACHINES_DIR): `oomph remote add` over a stand-in ssh that runs
    `oomph serve --stdio` on a Mac's logs (the fixture, its machine block saying macos), the mirror in the state
    folder (on Linux the XDG state folder, $XDG_STATE_HOME/oomph/machines), the Mac's frame in its own words from
    `oomph top --once --machine studio`, and its tab in the full-screen program."""
    os.makedirs(base)
    env, log, led = fixture_env(base)
    env.pop("OOMPH_STATE_DIR", None)
    home, xdg = os.path.join(base, "home"), os.path.join(base, "xdg")
    os.makedirs(home)
    with open(os.path.join(log, "current.json")) as f:
        cur = json.load(f)
    cur["daemon"] = dict(cur["daemon"], machine={"id": "m-5d1e0c2b3a495867", "name": "studio", "os": "macos",
                                                 "os_version": "27.2", "kind": "desktop", "arch": "arm64"})
    with open(os.path.join(log, "current.json"), "w") as f:
        json.dump(cur, f)
    fake = os.path.join(base, "fakessh")
    with open(fake, "w") as f:
        f.write("#!%s -I\nimport os, sys\nos.execv(%r, [%r, '-I', '-B', %r, 'serve', '--stdio'])\n" % (PY, PY, PY, CLI))
    os.chmod(fake, 0o755)
    env.update(HOME=home, XDG_STATE_HOME=xdg, OOMPH_SSH=fake,   # (top.json is found by the password database's
               OOMPH_TOP_CONFIG=os.path.join(base, "top.json"))  # home: kept here, never the owner's real one)
    env.pop("OOMPH_MACHINES_DIR", None)
    r = subprocess.run([PY, "-I", "-B", CLI, "remote", "add", "sam@studio", "--name", "mac-studio", "--json"],
                       env=env, capture_output=True, text=True, timeout=60)
    try:
        m = json.loads(r.stdout)["machine"]
    except (ValueError, KeyError):
        check(False, "viewer: remote add over the stand-in ssh (%s %s)" % (r.stdout[-300:], r.stderr[-300:]))
        return
    where = os.path.join(xdg, "oomph") if sys.platform != "darwin" else os.path.join(home, "Library", "Application Support",
                                                                                   "oomph")
    mirror = os.path.join(where, "machines", m["mid"])
    check(m.get("os") == "macos" and os.path.isfile(os.path.join(mirror, "log", "current.json")) and
          os.path.isfile(os.path.join(where, "machines", "machines.json")),
          "viewer: remote add keeps the Mac and its first mirror in this system's state folder (%s)"
          % os.path.relpath(where, base))
    r = subprocess.run([PY, "-I", "-B", CLI, "top", "--once", "--machine", "mac-studio", "--size", "100x30", "--format", "text",
                        "--no-probe"], env=env, capture_output=True, text=True, timeout=60)
    first = r.stdout.splitlines()[:3]
    check(r.returncode == 0 and "mac-studio" in r.stdout and "Wired" in r.stdout and "Compressed" in r.stdout and
          "Kernel" not in r.stdout and "mac-studio" in (first[0] if first else ""),
          "viewer: oomph top --once --machine studio draws the Mac's mirror in a Mac's words (%s %s)"
          % (r.returncode, (r.stderr or r.stdout)[-300:]))
    p = Pty([PY, "-I", "-B", CLI, "top", "--no-probe", "--no-connect"], env)
    try:
        p.pump(8, until=b"mac-studio")
        top_row = screen(p, 80, 24).splitlines()[0]
        p.send("q", wait=0.2)
        rc = p.wait(5)
    finally:
        p.close()
    check("mac-studio" in top_row and rc == 0,
          "viewer: the full-screen program has the Mac as a tab (%r, rc %s)" % (top_row, rc))


def _lock_free(path):
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except BlockingIOError:
        return False
    finally:
        os.close(fd)                    # (closing drops a lock taken here at once)


def _logger_stand_in(log, stop):
    """A logger for the served fixture: a sample appended to today's file every second (at most ten
    minutes), so the coverage map grows while the test runs and a hole in it would show."""
    with open(os.path.join(log, "current.json")) as f:
        last = {k: v for k, v in json.load(f).items() if k not in ("groups", "claude", "top", "daemon", "procs")}
    for _ in range(600):
        if stop.wait(1.0):
            return
        now = time.time()
        with open(os.path.join(log, "samples-%s.jsonl" % time.strftime("%Y-%m-%d", time.localtime(now))), "a") as f:
            f.write(json.dumps(dict(last, t=now), separators=(",", ":")) + "\n")


def _ppid(pid):
    r = subprocess.run(["ps", "-o", "ppid=", "-p", str(pid)], capture_output=True, text=True, timeout=10)
    return int(r.stdout.strip() or 0)


def test_pty_engine(base):
    """04 §8's T2 exit criterion with 01's real engine: a machine over a stand-in ssh (it runs `oomph serve
    --stdio` on a fixture). While "the app's" engine holds engine.lock the dashboard's child follows; when
    that engine is killed, the dashboard's child takes the lock and the tab is live again with no hole left
    in the coverage map; ctrl-z frees the lock at once; after fg a new child runs; a dashboard stopped
    with SIGSTOP leaves its engine's status.json fresh. Then engine_handover: quitting the dashboard leaves
    the app's engine live, and X in the dashboard while the app's engine holds the lock forgets it in both."""
    os.makedirs(base)
    env, log, led = fixture_env(base)
    mdir = os.path.join(base, "machines")
    fake = os.path.join(base, "fakessh")
    with open(fake, "w") as f:
        f.write("#!%s -I\nimport os, sys\nos.execv(%r, [%r, '-I', '-B', %r, 'serve', '--stdio'])\n" % (PY, PY, PY, CLI))
    os.chmod(fake, 0o755)
    env.update(OOMPH_MACHINES_DIR=mdir, OOMPH_SSH=fake)
    r = subprocess.run([PY, "-I", "-B", CLI, "remote", "add", "sam@atlas", "--name", "atlas", "--no-mirror", "--json"],
                       env=env, capture_output=True, text=True, timeout=60)
    try:
        mid = json.loads(r.stdout)["machine"]["mid"]
    except (ValueError, KeyError):
        check(False, "engine: remote add over the stand-in ssh (%s %s)" % (r.stdout[-300:], r.stderr[-300:]))
        return
    status = os.path.join(mdir, mid, "status.json")

    def st():
        try:
            with open(status) as f:
                return json.load(f)
        except (OSError, ValueError):
            return {}
    stop = threading.Event()
    threading.Thread(target=_logger_stand_in, args=(log, stop), daemon=True).start()
    app = subprocess.Popen([PY, "-I", "-B", CLI, "remote", "sync", "--json"], stdin=subprocess.PIPE,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
    app.stdin.write((json.dumps({"cmd": "watch", "ids": [mid]}) + "\n").encode())
    app.stdin.flush()
    p = None
    try:
        live_app = wait_until(lambda: st().get("state") in ("live", "catching_up") and _ppid(st().get("pid") or 1) == app.pid, 30)
        p = Pty([PY, "-I", "-B", CLI, "top", "--no-probe"], env, jobs=True)
        p.pump(5, until=b"this machine")
        viewers = os.path.join(mdir, "viewers")
        follows = wait_until(lambda: any(n != "%d.json" % app.pid for n in os.listdir(viewers)), 10, p)
        p.send("2", wait=0.5)
        shown = wait_until(lambda: "atlas · " in screen(p) and "Not connected" not in screen(p).splitlines()[0], 10, p)
        app.kill()
        app.wait()
        t0 = time.time()
        took = wait_until(lambda: st().get("state") in ("live", "catching_up") and
                          _ppid(st().get("pid") or 1) not in (0, 1, app.pid) and time.time() - st().get("updated", 0) < 10, 20, p)
        took_s = time.time() - t0
        check(live_app and follows and shown and took,
              "engine: the dashboard's child follows the app's engine (a viewer file), the tab shows the machine; "
              "when that engine dies the dashboard's child takes over and the tab is live again (%.1f s; %s %s %s)"
              % (took_s, live_app, follows, shown))
        sync_json = os.path.join(mdir, mid, "sync.json")

        def whole():
            """The coverage map has no hole from before the kill up to the dashboard's child's own samples."""
            try:
                with open(sync_json) as f:
                    have = json.load(f).get("have") or []
            except (OSError, ValueError):
                return False
            return any(a <= t0 - 60 and b >= t0 + 5 for a, b in have)
        check(wait_until(whole, 30, p), "engine: after the take-over no hole is left in the chart across the kill "
                                        "(sync.json's coverage spans it)")
        lock = os.path.join(mdir, "engine.lock")
        p.send("ctrl-z", wait=0.3)
        freed = wait_until(lambda: _lock_free(lock), 5)
        os.kill(p.pid, signal.SIGCONT)
        again = wait_until(lambda: not _lock_free(lock), 10, p)
        fresh = wait_until(lambda: st().get("state") in ("live", "catching_up") and time.time() - st().get("updated", 0) < 5, 15, p)
        os.kill(p.pid, signal.SIGSTOP)              # 04 §10: stopped where ctrl-z cannot be caught
        try:
            u0, end, kept = st().get("updated") or 0, time.time() + 15, False
            while time.time() < end and not kept:
                time.sleep(0.3)
                kept = (st().get("updated") or 0) > u0 + 3 and _ppid(st().get("pid") or 1) not in (0, 1)
        finally:
            os.kill(p.pid, signal.SIGCONT)
        check(fresh and kept, "engine: with the dashboard stopped (SIGSTOP) its engine keeps status.json fresh (%s %s)"
              % (fresh, kept))
        p.send("q", wait=0.2)
        rc = p.wait(5)
        check(freed and again and rc == 0, "engine: ctrl-z frees engine.lock within seconds (suspended is not watching); "
                                           "after fg the dashboard's new child holds it again; q (%s %s %s)" % (freed, again, rc))
    finally:
        if p is not None:
            p.close()
        if app.poll() is None:
            app.kill()
            app.wait()
        stop.set()
        end = time.time() + 10           # the children leave by themselves (the end of their input): wait for that
        while time.time() < end and not _lock_free(os.path.join(mdir, "engine.lock")):
            time.sleep(0.2)
    engine_full_pipe(base, env, mid, st)
    engine_handover(base, env, mid, st)


def engine_handover(base, env, mid, st):
    """04 §8's T2 criteria with the app: the dashboard's child is the engine and the app's follows; q in
    the dashboard leaves the app's engine live (it takes the lock, status.json stays fresh under it). Then,
    the app's engine holding the lock, X and y in a dashboard forget the machine in both: machines.json
    loses it and the dashboard's tab goes."""
    mdir = env["OOMPH_MACHINES_DIR"]
    book = os.path.join(mdir, "machines.json")

    def listed():
        try:
            with open(book) as f:
                return any(e.get("mid") == mid for e in json.load(f).get("machines") or [])
        except (OSError, ValueError):
            return True
    lock = os.path.join(mdir, "engine.lock")
    p = Pty([PY, "-I", "-B", CLI, "top", "--no-probe"], env, jobs=True)
    app = None
    try:
        p.pump(5, until=b"this machine")
        p.send("2", wait=0.5)
        mine = wait_until(lambda: st().get("state") in ("live", "catching_up") and
                          _ppid(st().get("pid") or 1) not in (0, 1), 30, p)
        top_child = _ppid(st().get("pid") or 1)
        app = subprocess.Popen([PY, "-I", "-B", CLI, "remote", "sync", "--json"], stdin=subprocess.PIPE,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env)
        app.stdin.write((json.dumps({"cmd": "watch", "ids": [mid]}) + "\n").encode())
        app.stdin.flush()
        viewers = os.path.join(mdir, "viewers")
        follows = wait_until(lambda: os.path.exists(os.path.join(viewers, "%d.json" % app.pid)), 10, p)
        p.send("q", wait=0.2)
        rc = p.wait(5)
        p.close()
        kept = wait_until(lambda: _ppid(st().get("pid") or 1) == app.pid and time.time() - st().get("updated", 0) < 5, 20)
        check(mine and top_child != app.pid and follows and rc == 0 and kept,
              "engine: q in the dashboard (its child the engine) leaves the app's tabs live: the app's engine takes "
              "the lock and status.json stays fresh under it (%s %s %s %s)" % (mine, follows, rc, kept))
        p = Pty([PY, "-I", "-B", CLI, "top", "--no-probe"], env, jobs=True)
        p.pump(5, until=b"this machine")
        p.send("2", wait=0.5)
        tab = wait_until(lambda: "atlas · " in screen(p), 10, p)
        p.send("X", wait=0.4)
        asked = "Forget" in screen(p) or "forget" in screen(p)
        p.send("y", wait=0.3)
        gone = wait_until(lambda: not listed(), 20, p)
        app_engine = not _lock_free(lock) and app.poll() is None
        untabbed = wait_until(lambda: "atlas" not in screen(p).splitlines()[0], 10, p)
        p.send("q", wait=0.2)
        rc = p.wait(5)
        check(tab and asked and gone and untabbed and app_engine and rc == 0,
              "engine: X and y in the dashboard while the app's engine holds engine.lock forget the machine in both "
              "(machines.json loses it, the tab goes) (%s %s %s %s %s %s)" % (tab, asked, gone, untabbed, app_engine, rc))
    finally:
        p.close()
        if app is not None and app.poll() is None:
            app.stdin.close()
            try:
                app.wait(10)
            except subprocess.TimeoutExpired:
                app.kill()
                app.wait()
        end = time.time() + 10
        while time.time() < end and not _lock_free(lock):
            time.sleep(0.2)


def engine_full_pipe(base, env, mid, st):
    """A reader that stopped reading (a dashboard held up by its terminal, or stopped): the engine's
    stdout pipe is full from the start. It must not wait in a write while it holds engine.lock: the
    machine goes live under it and its status.json keeps being rewritten; whole lines only reach the
    pipe; the end of its input still ends it."""
    fifo = os.path.join(base, "events")
    os.mkfifo(fifo, 0o600)
    rfd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    wfd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
    filled = 0
    try:
        while filled < 1 << 20:
            filled += os.write(wfd, b"{}\n")
    except BlockingIOError:
        pass
    os.close(wfd)
    out = os.open(fifo, os.O_WRONLY)          # (a description of its own, blocking, as a pipe's would be)
    eng = subprocess.Popen([PY, "-I", "-B", CLI, "remote", "sync", "--json"], stdin=subprocess.PIPE, stdout=out,
                           stderr=subprocess.DEVNULL, env=env)
    os.close(out)
    try:
        eng.stdin.write((json.dumps({"cmd": "watch", "ids": [mid]}) + "\n").encode())
        eng.stdin.flush()
        live = wait_until(lambda: st().get("state") in ("live", "catching_up") and _ppid(st().get("pid") or 1) == eng.pid, 30)
        u0 = st().get("updated") or 0
        on = wait_until(lambda: (st().get("updated") or 0) > u0 + 4 and _ppid(st().get("pid") or 1) == eng.pid, 15)
        eng.stdin.close()
        try:
            rc = eng.wait(10)
        except subprocess.TimeoutExpired:
            rc = None
        data = b""
        try:
            while len(data) < 4 << 20:
                b = os.read(rfd, 65536)
                if not b:
                    break
                data += b
        except BlockingIOError:
            pass
        lines = data.split(b"\n")
        whole = lines[-1] == b"" and all(isinstance(oomph.loads_untrusted(x), dict) for x in lines[:-1])
        check(filled > 0 and live and on and rc == 0 and whole,
              "engine: with its output pipe full (%d bytes) it still keeps the machine live and status.json fresh, "
              "drops whole lines only, and ends at the end of its input (%s %s %s %s)" % (filled, live, on, rc, whole))
    finally:
        if eng.poll() is None:
            eng.kill()
            eng.wait()
        os.close(rfd)
        end = time.time() + 10
        while time.time() < end and not _lock_free(os.path.join(env["OOMPH_MACHINES_DIR"], "engine.lock")):
            time.sleep(0.2)


def test_machines_units(base):
    """The tabs' parts without a terminal: the sync child's events read on a thread of their own (a
    child that writes 1 MB ends although nobody calls events()); a forgotten machine that comes back
    in machines.json is a tab again; another tab's feed goes a minute after it was left; a forget while
    the worker reads that tab is no crash; a start on this machine for what it has to say keeps the
    remembered tab; a connect row gone meanwhile."""
    os.makedirs(base)
    woke = []
    sc = T.SyncChild([PY, "-I", "-c", "import sys\nfor i in range(20000): sys.stdout.write('{\"ev\": \"changed\", "
                                       "\"id\": \"m-%016x\", \"what\": [\"samples\"]}\\n' % i)\n"
                                       "sys.stdout.write('{\"ev\": \"failed\", \"cmd\": \"forget\", \"id\": \"x\"}\\n')"],
                     woke.append)
    sc.start(0.0)
    try:
        ended = wait_until(lambda: sc.p.poll() is not None, 15)
        time.sleep(0.2)
        evs = sc.events()
    finally:
        sc.close()
    check(ended and woke and [e.get("cmd") for e in evs] == ["forget"] and any(woke),
          "machines: the sync child's output is read off the terminal's loop (a 1 MB burst ends unread by it); a "
          "failure is kept for a note (%s %d %s)" % (ended, len(woke), evs))
    mdir = topfixture.write_machines(os.path.join(base, "m"), pid=os.getpid())
    S = T.sync_module()
    M = T.Machines(mdir, S)
    M.refresh(NOW)
    gpu = "m-90a1b2c3d4e5f607"
    M.hide(gpu)
    M.refresh(NOW)
    hidden = gpu not in [e["mid"] for e in M.tabs()]
    M.hide(gpu, time.monotonic() - T.HIDE_S - 1)
    M.refresh(NOW)
    late = gpu in [e["mid"] for e in M.tabs()] and gpu not in M.hidden
    M.hide(gpu)
    path = os.path.join(mdir, "machines.json")
    b = json.load(open(path))
    keep = [e for e in b["machines"] if e["mid"] == gpu]
    json.dump(dict(b, machines=[e for e in b["machines"] if e["mid"] != gpu]), open(path + ".t", "w"))
    os.rename(path + ".t", path)
    M.refresh(NOW)
    json.dump(dict(b, machines=[e for e in b["machines"] if e["mid"] != gpu] + keep), open(path + ".t", "w"))
    os.rename(path + ".t", path)
    M.refresh(NOW)
    check(hidden and late and gpu in [e["mid"] for e in M.tabs()] and not M.hidden,
          "machines: a forgotten machine is no tab; a forget machines.json never shows in HIDE_S is undone; gone "
          "from machines.json and back, it is a tab again (%s %s)" % (hidden, late))
    keep_s = T.FEED_KEEP_S
    try:
        T.FEED_KEEP_S = 0.05
        src = T.Source("/nonexistent", lambda m: None, clock=lambda: NOW, machines=M)
        build = "m-1b2c3d4e5f607182"
        src.mid = build
        src.step()
        had = build in src.feeds
        src.mid = "local"
        src.step()
        kept = build in src.feeds
        time.sleep(0.1)
        src.step()
        check(had and kept and build not in src.feeds and "local" in src.feeds,
              "machines: another tab's feed (its history) is dropped a while after its tab was left (04 §4.6)")
    finally:
        T.FEED_KEEP_S = keep_s
    posted, step = [], T.Feed.step
    try:                                # the loop's y lands while the worker reads that tab's history
        T.Feed.step = lambda self, *a: (M.hide(build), step(self, *a))[1]
        src = T.Source("/nonexistent", posted.append, clock=lambda: NOW, machines=M)
        src.mid = build
        src.step()
    finally:
        T.Feed.step = step
        M.unhide(build)
    try:
        m = T.at(posted[-1], NOW)
        err = None
    except Exception as e:
        m, err = None, repr(e)
    check(m is not None and m["tabs"][m["sel"]]["mid"] == m["tab_mid"] == build,
          "machines: a forget sent while the worker reads that tab draws its last frame, no crash (%s)" % err)
    cur = T._current
    try:
        T._current = lambda d: {"t": time.time(), "pressure": 4}
        hot = T.start_tab(M, build, None)
        T._current = lambda d: {"t": time.time(), "pressure": 1}
        calm = T.start_tab(M, build, None)
        T._current = lambda d: {"t": time.time(), "pressure": 2}
        warn = T.start_tab(M, build, None)
        T._current = lambda d: {"t": time.time(), "pressure": 1, "daemon": {"interval": 30, "incident": "20261120-1"}}
        inc = T.start_tab(M, build, None)
    finally:
        T._current = cur
    check(hot == ("local", True) and inc == ("local", True) and calm == (build, False) and warn == (build, False),
          "machines: critical pressure or an open incident starts on this machine, marked so the remembered tab is "
          "kept; warning does not (D9, as the app's localHasSay) (%s %s %s %s)" % (hot, inc, calm, warn))
    app = T.App.__new__(T.App)
    app.ui = {"overlay": {"kind": "connect", "text": "", "sel": 3}}
    e = {"mid": "m-00000000000000cc", "name": "old-box", "host": "old-box.local", "transport": "tcp", "port": 6674,
         "pinned": False}
    app.key_machine_dialog("tab", app.ui["overlay"], {"book": [e]})
    check(app.ui["overlay"].get("text") == "old-box" and app.ui["overlay"].get("sel") is None,
          "machines: a Connect row that went meanwhile (the Recents shrank) is no crash; the highlight is on the last")
    app = T.App.__new__(T.App)
    app.ui, app.sync, app.M, app.mid, app.dirty = {"overlay": {"kind": "forget", "mid": build, "label": "build-box"}}, None, M, \
        "local", False
    app.key_machine_dialog("y", app.ui["overlay"], {})
    check(not M.is_hidden(build) and "overlay" not in app.ui and "--no-connect" in app.ui.get("note", ("",))[0],
          "machines: a forget that could not be sent (--no-connect) hides no tab and says why")


def test_bell_settings_nologger(base):
    app = T.App.__new__(T.App)                     # the bell's rule alone, without a terminal
    app.bell, app.pending, app.open_ids, app.pressure, app.bell_at, app.first_model = True, "", set(), None, -1e9, True
    calm = {"incidents": [], "cur": {"pressure": "Normal"}}
    opened = {"incidents": [{"id": "20261120-132412", "open": True}], "cur": {"pressure": "Warning"}}
    critical = {"incidents": [{"id": "20261120-132412", "open": True}], "cur": {"pressure": "Critical"}}
    rings = []
    for m in (opened, calm, opened, critical, calm):
        app.attention(m)
        rings.append(app.pending.count("\x07"))
        app.pending = ""
    check(rings == [0, 0, 1, 0, 0], "--bell: one BEL when an incident opens (not for one open at the start), and "
                                    "not again within 15 minutes (%s)" % rings)
    env, log, _ = fixture_env(base)
    p = Pty(top(), env)
    try:
        p.pump(5, until=b"Logging every")
        p.send("right", "q", wait=0.3)
        p.wait(5)
    finally:
        p.close()
    saved = json.load(open(os.path.join(env["OOMPH_STATE_DIR"], "top.json")))
    mode = os.stat(os.path.join(env["OOMPH_STATE_DIR"], "top.json")).st_mode & 0o777
    p = Pty(top(), env)
    try:
        p.pump(5, until=b"Logging every")
        vt = MiniVT(80, 24)
        vt.feed(p.text())
        head = "".join(c[0] for c in vt.cells[3])
        p.send("q", wait=0.1)
        p.wait(5)
    finally:
        p.close()
    check(saved.get("span") == "6h" and saved.get("v") == 1 and mode == 0o600 and " 6h " in head,
          "settings: the span is remembered in top.json (600) and the next start opens on it (%s)" % saved)
    cfg = os.path.join(env["OOMPH_STATE_DIR"], "top.json")
    seen = []
    for args in (["--glyphs", "cells"], [], ["--glyphs", "unicode", "--theme", "light", "--from-ssh", "--bell"],
                 ["--glyphs", "auto"]):
        p = Pty(top(*args), env)
        try:
            p.pump(5, until=b"Logging every")
            p.send("?", wait=0.4)
            vt = MiniVT(80, 24)
            vt.feed(p.text())
            screen = "\n".join("".join(c[0] for c in row) for row in vt.cells)
            p.send("esc", "q", wait=0.1)
            p.wait(5)
        finally:
            p.close()
        line = re.search(r"detected: [^│]*", screen)
        saved = json.load(open(cfg))
        seen.append(((line.group(0).strip() if line else None), saved.get("glyphs"), saved.get("bell")))
    ok = ("cells glyphs" in (seen[0][0] or "") and seen[0][1] == "cells" and "cells glyphs" in (seen[1][0] or "") and
          "unicode glyphs" in (seen[2][0] or "") and seen[2][1] == "cells" and seen[2][2] is not True and
          "unicode glyphs" in (seen[3][0] or "") and seen[3][1] is None and "theme" not in json.load(open(cfg)))
    check(ok, "settings: --glyphs cells is remembered and the next plain start's help names it; choices passed by "
              "--ssh (the bell too) are not remembered; --glyphs auto forgets (%s)" % seen)
    empty = os.path.join(base, "nolog")
    os.makedirs(empty)
    p = Pty(top(), dict(env, OOMPH_DIR=empty))
    try:
        p.pump(8, until=b"\x1b[?2026l")
        p.pump(1.0)
        txt = p.text()
        p.send("q", wait=0.1)
        rc = p.wait(5)
    finally:
        p.close()
    check(rc == 0 and "Logging is off" in txt and "Traceback" not in txt,
          "no logger: the dashboard measures by itself (where it can) and says how to start logging (rc %s)" % rc)


def test_budget(base):
    env, log, led = fixture_env(base)
    # a minute later nothing on screen counts seconds: a quiet dashboard draws every 10 s, writes nothing new
    p = Pty([PY, "-I", "-B", CLI, "top", "--now", str(int(NOW + 120)), "--no-probe"], env)
    try:
        p.pump(5, until=b"Logging every")
        p.pump(0.8)
        n = len(p.out)
        p.pump(11.0)
        quiet = len(p.out) - n
        p.send("q", wait=0.1)
        rc = p.wait(5)
        cpu = p.report.get("cpu", -1)
        rss = p.report.get("rss", -1) / ((1 << 20) if sys.platform == "darwin" else 1024.0)
    finally:
        p.close()
    print("      budget: start, 12 s idle, quit: %.2f s of CPU in all, peak resident %.1f MB, %d bytes written "
          "while idle" % (cpu, rss, quiet))
    check(rc == 0 and quiet == 0 and 0 <= cpu < 2.0 and 0 < rss < 56,
          "budget: a quiet dashboard writes nothing (%d bytes in 11 s) and stays small (%.2f s CPU with start-up, "
          "%.0f MB peak from the checkout, under 56 MB with or without bytecode; --minute holds the 40 MB of an "
          "install)" % (quiet, cpu, rss))


# ------------------------------------------------------------------ read-only, --ssh
def test_readonly_ssh(base):
    os.makedirs(base, exist_ok=True)
    check(T.readonly_reason("/nonexistent/x", euid=0) == "Running as root: read-only, settings not saved" and
          T.readonly_reason("/usr", euid=os.geteuid() + 1 if os.geteuid() else 12345) is not None and
          T.readonly_reason("/usr/no/such/oomph", euid=os.geteuid() + 1 if os.geteuid() else 12345) is not None and
          T.readonly_reason(os.path.join(base, "no-home", "x", "oomph"), euid=os.geteuid(),
                            home=os.path.join(base, "no-home")) is not None and
          T.readonly_reason(os.path.join(base, ".local", "state", "oomph"), euid=os.geteuid()) is None and
          T.readonly_reason(base, euid=os.geteuid()) is None,
          "read-only: as root, in someone else's folder (or below one), or without a home; not in one's own, even "
          "where ~/.local/state does not exist yet")
    fake = os.path.join(base, "bin")
    os.makedirs(fake, exist_ok=True)
    rec = os.path.join(base, "ssh-argv.json")
    with open(os.path.join(fake, "ssh"), "w") as f:     # a stand-in: says how it was called, exits as told
        f.write("#!%s -I\nimport json, os, sys\njson.dump(sys.argv[1:], open(%r, 'w'))\n"
                "sys.exit(int(os.environ.get('FAKE_SSH_RC', '0')))\n" % (PY, rec))
    os.chmod(os.path.join(fake, "ssh"), 0o755)
    env, _, _ = fixture_env(base)
    env["PATH"] = fake + os.pathsep + env.get("PATH", "")
    for rc_in, want_rc, want in ((122, 127, "linux/install.sh"), (121, 127, "build-app.sh"), (124, 127, "older than 1.9.0"),
                                 (0, 0, None), (255, 255, None)):
        if os.path.exists(rec):
            os.unlink(rec)
        p = Pty([PY, "-I", "-B", CLI, "top", "--ssh", "sam@build-box", "--no-probe", "--span", "6h"],
                dict(env, FAKE_SSH_RC=str(rc_in)))
        try:
            rc = p.wait(15)
            argv = json.load(open(rec)) if os.path.exists(rec) else []
            ok = (rc == want_rc and argv[:2] == ["-t", "-o"] and "--" in argv and argv[argv.index("--") + 1] ==
                  "sam@build-box" and "ServerAliveInterval=5" in argv and "RemoteCommand=none" in argv and
                  "ClearAllForwardings=yes" in argv and "--span 6h" in argv[-1] and "--from-ssh" in argv[-1] and "--no-bell" in argv[-1] and
                  argv[-1].startswith("exec /bin/sh -c '"))
            if want:
                ok = ok and b"oomph is not installed on build-box" in p.out if rc_in != 124 else ok
                ok = ok and want.encode() in p.out
            if rc_in == 255:
                ok = ok and T.SSH_LEAVE.encode() in p.out      # the far side could not restore: we do
            elif want:
                ok = ok and T.SSH_LEAVE.encode() not in p.out
            check(ok, "--ssh: ssh exits %d → oomph top exits %s%s" % (rc_in, rc, " and names the install" if want else ""))
        finally:
            p.close()
    remote = T.ssh_command("h", None, ["--span", "24h"])[-1].replace("/usr/local/bin/oomph", "/nonexistent/oomph")
    shells = [s for s in ("/bin/sh", "/bin/csh", "/bin/tcsh", "/bin/zsh", "/bin/bash") if os.path.exists(s)]
    want = {"Darwin": 121, "Linux": 122}.get(os.uname().sysname, 123)
    got = {s: subprocess.run([s, "-c", remote], env={"PATH": "/usr/bin:/bin", "HOME": base}, capture_output=True,
                             timeout=20).returncode for s in shells}
    check(all(v == want for v in got.values()), "--ssh: the far side's command parses in %s and says which system "
                                                "lacks oomph (%s)" % (", ".join(shells), got))
    far = os.path.join(base, "far")
    os.makedirs(far, exist_ok=True)
    for help_text, want, what in (("usage: oomph top [--once] [--span inf|24h|6h|1h]", 124, "an older oomph"),
                                  ("usage: oomph top [--span inf|24h|6h|1h] [--ssh [USER@]HOST]", 7, "this oomph")):
        with open(os.path.join(far, "oomph"), "w") as f:      # a stand-in: its help, or a run that exits 7
            f.write("#!/bin/sh\ncase \"$2\" in --help) echo '%s';; *) exit 7;; esac\n" % help_text)
        os.chmod(os.path.join(far, "oomph"), 0o755)
        got = {s: subprocess.run([s, "-c", remote], env={"PATH": far + ":/usr/bin:/bin", "HOME": base},
                                 capture_output=True, timeout=20).returncode for s in shells}
        check(all(v == want for v in got.values()), "--ssh: on the far side %s %s (%s)" % (
            what, "exits %d (too old)" % want if want == 124 else "is started", got))
    mine = os.path.join(base, ".local", "bin")        # linux/install.sh's: not on a non-interactive ssh's PATH
    os.makedirs(mine, exist_ok=True)
    shutil.copy(os.path.join(far, "oomph"), os.path.join(mine, "oomph"))
    got = {s: subprocess.run([s, "-c", remote], env={"PATH": "/usr/bin:/bin", "HOME": base}, capture_output=True,
                             timeout=20).returncode for s in shells}
    check(all(v == 7 for v in got.values()), "--ssh: on the far side an oomph in ~/.local/bin (linux/install.sh) is "
                                             "started (%s)" % got)
    shutil.rmtree(os.path.join(base, ".local", "bin"))
    if os.path.exists(rec):
        os.unlink(rec)
    for args in (["--ssh", "-oProxyCommand=x"], ["--ssh", "x@-y"], ["--ssh", "build-box", "--once"]):
        p = Pty([PY, "-I", "-B", CLI, "top", "--no-probe"] + args, env)
        try:
            rc = p.wait(10)
            check(rc == 2 and not os.path.exists(rec), "--ssh %s: refused with exit 2, ssh not started (rc %s)"
                  % (" ".join(args[1:]), rc))
        finally:
            p.close()
    con = {"TERM": "linux", "LANG": "C.UTF-8"}
    check(T.detect_glyphs("auto", con) == "cp437" and T.far_glyphs("auto", con) == "unicode" and
          T.far_glyphs("cp437", con, "cp437") == "cp437" and T.far_glyphs("cp437", con) == "unicode" and
          T.far_glyphs("auto", {"TERM": "xterm", "LANG": "C"}) == "ascii",
          "--ssh from a Linux console asks the far side for unicode (an oomph before 1.13.4 refuses cp437), and "
          "for cp437 only when typed on the command line, not when top.json remembers it")
    r = subprocess.run([PY, "-I", "-B", CLI, "top", "--once", "--from-ssh", "--glyphs", "braille", "--size", "40x10",
                        "--format", "text"], env=env, capture_output=True, text=True, timeout=30)
    r2 = subprocess.run([PY, "-I", "-B", CLI, "top", "--once", "--glyphs", "braille", "--size", "40x10"], env=env,
                        capture_output=True, text=True, timeout=30)
    check(r.returncode == 0 and r2.returncode == 2, "a far side takes a newer viewer's --glyphs as auto; typed here, "
                                                    "an unknown --glyphs still exits 2 (rc %s, %s)" % (r.returncode, r2.returncode))
    p = Pty([PY, "-I", "-B", CLI, "top", "--no-probe", "--ssh", "build-box"],
            dict(env, OOMPH_STATE_DIR="/usr/oomph-not-ours", FAKE_SSH_RC="0"))
    try:
        rc = p.wait(15)
        check(rc == 0 and os.path.exists(rec), "--ssh: a settings folder that is not this user's makes the run "
                                               "read-only here, and the far side still starts (rc %s)" % rc)
    finally:
        p.close()


CRASH = r"""
import sys
sys.path.insert(0, sys.argv[1])
import oomph_top as T
how = sys.argv[2]
def boom(*a, **k):
    raise RuntimeError("crash test: " + how)
if how in ("loop", "readonly"):
    T.App.loop = boom
if how == "readonly":
    T.readonly_reason = lambda *a, **k: "Read-only: the crash test"
if how == "render":
    T.view.render = boom
sys.exit(T.cmd_top(sys.argv[3:]))
"""


def test_crash(base):
    """The terminal comes back on an exception too: the loop raising, and render() raising (which only
    costs that frame)."""
    for how in ("loop", "readonly", "render"):
        state = os.path.join(base, how)
        env, _, _ = fixture_env(os.path.join(base, "fx-" + how), {"OOMPH_STATE_DIR": state})
        p = Pty([PY, "-I", "-B", "-c", CRASH, os.path.join(ROOT, "daemon"), how, "--now", str(int(NOW)), "--no-probe"],
                env)
        try:
            p.pump(5, until=b"\x1b[?2026l")
            if how == "render":
                p.pump(5, until=b"can't draw this frame")
                p.send("q", wait=0.1)
            rc = p.wait(10)
        finally:
            p.close()
        crash = os.path.join(state, "top-crash.log")
        logged = open(crash).read() if os.path.exists(crash) else ""
        left = p.out.rfind(T.LEAVE.encode())
        if how == "render":
            ok = (rc == 0 and p.restored() and p.out.endswith(T.LEAVE.encode()) and b"can't draw this frame" in p.out
                  and "crash test: render" in logged)
            what = "render() raising costs that frame only: it says so, the details go to top-crash.log, q leaves"
        else:
            ok = (rc == 1 and p.restored() and left >= 0 and b"Traceback" in p.out[left:] and
                  b"crash test" in p.out[left:] and b"Traceback" not in p.out[:left] and
                  (("crash test: loop" in logged) if how == "loop" else not os.path.exists(crash)))
            what = ("the loop raising: exit 1, the terminal restored, then the traceback on stderr and in "
                    "top-crash.log" if how == "loop" else "the same in read-only mode: no top-crash.log written")
        check(ok, "crash: %s (rc %s, restored %s, log %d bytes)" % (what, rc, p.restored(), len(logged)))


def test_children(base):
    """o and y: a report writer runs to its end however long it takes, also after q; one at a time; a
    failed one says so; a clipboard tool still has its 3 s."""
    os.makedirs(base, exist_ok=True)
    app = T.App.__new__(T.App)
    app.children, app.ui, app.readonly, app.note_until, app.dirty, app.pending = [], {"span": "inf"}, None, 0.0, False, ""
    out = os.path.join(base, "report.html")
    app.me = [PY, "-I", "-c", "import sys, time; time.sleep(4); open(sys.argv[1], 'w').write('a report')", out]
    app.local_desktop = lambda: True
    if sys.platform == "darwin":
        app.report(None)                             # o: the report of the span on screen, through `me`
        app.report(None)                             # o again while it is written
        second = app.ui.get("note", ("",))[0]
    else:
        app.spawn(app.me + ["html"], "report", "oomph html")
        second = "a report is still being written…"
    app.reap(time.monotonic() + 3.5)                 # past the deadline a clipboard tool has
    running = len(app.children) == 1 and app.children[0][0].poll() is None
    app.leave_children()                             # q
    end = time.time() + 8
    while not os.path.exists(out) and time.time() < end:
        time.sleep(0.1)
    check(running and os.path.exists(out) and second == "a report is still being written…",
          "o: a report writer that takes 4 s is not killed after 3 s nor by q; a second o meanwhile only says so "
          "(%s %s %r)" % (running, os.path.exists(out), second))
    app.spawn([PY, "-I", "-c", "import sys; sys.exit(3)"], "report", "oomph html")
    t0 = time.time()
    while app.children[0][0].poll() is None and time.time() < t0 + 5:
        time.sleep(0.05)
    app.reap(time.monotonic())
    failed = app.ui.get("note")
    app.spawn([PY, "-I", "-c", "import time; time.sleep(20)"], "copy", "/some/path")
    app.reap(time.monotonic() + 3.5)
    check(not app.children and "report failed (oomph html: exit 3)" in str(failed) and
          "\x1b]52;c;" in app.pending, "o: a report writer that fails says so; y: a clipboard tool that hangs is "
                                       "stopped after 3 s and OSC 52 sent instead (%s)" % (failed,))


def budget_fixture(base):
    """The budget's data (04 §4.9): 14 days at a 30 s interval ending at the real clock, each line
    carrying a process list as a real sample does (about 1.5 KB), today's file plain, the rest .gz, and
    events.jsonl and .1 past the MB of each that top reads, of all kinds.
    Returns (env, log directory, a function that appends one sample now, as the logger would)."""
    env, log, _ = fixture_env(base)
    for n in os.listdir(log):
        if n.startswith("samples-"):
            os.unlink(os.path.join(log, n))
    shift = time.time() - NOW
    top = [{"pid": 400 + i, "ppid": 1, "name": "process number %d" % i, "uid": 501, "mb": 900 - 30 * i,
            "rss_mb": 950 - 30 * i, "g": "Group %d" % (i % 7), "s": None} for i in range(16)]
    groups = [{"name": n, "mb": int(gb * 1024), "n": k} for n, gb, k in topfixture.GROUPS]

    def line(p):
        return json.dumps(dict(p, top=top, groups=groups, procs=742), separators=(",", ":")) + "\n"
    by_day = {}
    for p in topfixture.synth(start=NOW - 14 * 86400 + 30):
        p["t"] += shift
        by_day.setdefault(time.strftime("%Y-%m-%d", time.localtime(p["t"])), []).append(p)
    today = time.strftime("%Y-%m-%d")
    last = None
    for day, ps in sorted(by_day.items()):
        text = "".join(line(p) for p in ps).encode()
        if day == today:
            with open(os.path.join(log, "samples-%s.jsonl" % day), "wb") as f:
                f.write(text)
        else:
            with gzip.GzipFile(os.path.join(log, "samples-%s.jsonl.gz" % day), "wb", compresslevel=1, mtime=0) as f:
                f.write(text)
        last = ps[-1]
    cur = json.load(open(os.path.join(log, "current.json")))
    ev = os.path.join(log, "events.jsonl")
    with open(ev) as f:
        kept = f.read()
    kinds = [lambda i: dict(kind="pressure_change", old=1 + (i % 2), new=2 - (i % 2)),
             lambda i: dict(kind="sleep_gap", seconds=600 + 37 * i % 30000),
             lambda i: dict(kind="jetsam", kills=1 + i % 3, top={"process number %d" % (i % 9): 1 + i % 3}),
             lambda i: dict(kind="thermal", old=i % 3, new=(i + 1) % 3, busy=11.5),
             lambda i: dict(kind="volume", pool="vol:%d" % (i % 5), mount="/Volumes/Disk %d" % (i % 5),
                            name="Disk %d" % (i % 5), what=("mounted", "unmounted")[i % 2]),
             lambda i: dict(kind="cpu_saturated", busy=13.1, n=14, minutes=10 + i % 50, top={"cargo": 9}),
             lambda i: dict(kind="notified", title="Memory pressure high", event="pressure")]
    i = 0
    for name, t0 in (("events.jsonl.1", time.time() - 14 * 86400), ("events.jsonl", time.time() - 7 * 86400)):
        with open(os.path.join(log, name), "w") as f:      # a long-running install's: the newest MB of each read
            while f.tell() < (1 << 20) + 4096:
                i += 1
                e = dict(kinds[i % len(kinds)](i), t=t0 + 25 * i % (6 * 86400), iso="2026-11-20T10:00:00+0100")
                f.write(json.dumps(e) + "\n")
            if name == "events.jsonl":
                f.write(kept)

    def append():
        p = dict(last, t=time.time())
        with open(os.path.join(log, "samples-%s.jsonl" % time.strftime("%Y-%m-%d")), "a") as f:
            f.write(line(p))
        tmp = os.path.join(log, ".current.json")
        with open(tmp, "w") as f:
            json.dump(dict(cur, **p), f)
        os.replace(tmp, os.path.join(log, "current.json"))
    append()
    return env, log, append


def cpu_of(pid):
    """CPU seconds a running process has used so far (ps: portable, to the hundredth on macOS)."""
    try:
        out = subprocess.run(["ps", "-o", "time=", "-p", str(pid)], capture_output=True, text=True,
                             timeout=10).stdout.strip()
        days, _, hms = out.rpartition("-")
        secs = 0.0
        for part in hms.split(":"):
            secs = secs * 60 + float(part)
        return secs + 86400 * int(days or 0)
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def minute():
    """A minute of `oomph top` as installed (a copy compiled with compileall, as install.sh does,
    started without -B) at 160 x 48 on 14 days of data, the span ∞, a sample appended every 10 s
    (three times the logger's rate): what a pane costs all day. The budget (04 §4.9): under 1 % of a core, under 40 MB peak resident."""
    base = tempfile.mkdtemp(prefix="oomph-toptest-minute-")
    try:
        inst = os.path.join(base, "libexec")
        os.makedirs(inst)
        for n in os.listdir(os.path.join(ROOT, "daemon")):
            if n.endswith(".py"):
                shutil.copy(os.path.join(ROOT, "daemon", n), inst)
        subprocess.run([PY, "-I", "-m", "compileall", "-q", inst], check=True, capture_output=True, timeout=120)
        env, _, append = budget_fixture(base)
        p = Pty([PY, "-I", os.path.join(inst, "oomph.py"), "top", "--no-probe", "--span", "inf"], env, size=(160, 48),
                timeout=120)
        try:
            p.pump(10, until=b"\x1b[?2026l")
            c0, settled = cpu_of(p.pid), time.time() + 30        # the 14 days load on the worker: wait for it
            while time.time() < settled:
                p.pump(1.0)
                c1 = cpu_of(p.pid)
                if c0 is not None and c1 is not None and c1 - c0 < 0.05:
                    break
                c0 = c1
            start, t0 = cpu_of(p.pid), time.time()
            while time.time() < t0 + 60:
                p.pump(10.0)
                append()
            used = cpu_of(p.pid) - start if start is not None else -1
            p.send("q", wait=0.1)
            rc = p.wait(5)
            rss = p.report.get("rss", 0) / ((1 << 20) if sys.platform == "darwin" else 1024.0)
            drew = b"Logging every" in p.out and b"Traceback" not in p.out
        finally:
            p.close()
    finally:
        shutil.rmtree(base, ignore_errors=True)
    pct = used / 60 * 100
    print("      a minute at 160 x 48, 14 days, a sample every 10 s, installed with bytecode: %.2f s of CPU after "
          "start-up (%.2f %% of a core), peak resident %.1f MB" % (used, pct, rss))
    # a shared, virtualised CI runner gets a margin: over 1 % there is a warning in the log, over 1.5 % a failure
    limit = 1.5 if os.environ.get("CI") else 1.0
    if limit > 1.0 and pct >= 1.0:
        print("warn  budget: %.2f %% of a core is over the design's 1 %% (within this runner's margin of %.1f %%)"
              % (pct, limit))
    check(rc == 0 and drew and 0 <= pct < limit and 0 < rss < 40,
          "budget: a minute of the dashboard costs under %.1f %% of a core (%.2f %%) and stays under 40 MB peak "
          "resident (%.1f MB)" % (limit, pct, rss))
    return 1 if FAILS else 0


def main():
    if "--minute" in sys.argv:
        return minute()
    t0 = time.time()
    test_decoder()
    frames = golden_frames()
    test_writer(frames)
    tmux_oracle(frames)
    test_space_key()
    test_selection()
    test_inspect_mouse()
    test_arrays()
    test_hostile_days()
    test_resource_arrays()
    test_tab_ladder()
    test_link_rows()
    test_mirror_gaps()
    test_connect_rows()
    test_machine_rows()
    test_linux_desktop_rows()
    test_linux_server_rows()
    test_linux_live()
    base = tempfile.mkdtemp(prefix="oomph-toptest-")
    try:
        test_pty(os.path.join(base, "pty"))
        test_bell_settings_nologger(os.path.join(base, "settings"))
        test_pty_inspect(os.path.join(base, "inspect"))
        test_pty_resources(os.path.join(base, "resources"))
        test_budget(os.path.join(base, "budget"))
        test_readonly_ssh(os.path.join(base, "ssh"))
        test_crash(os.path.join(base, "crash"))
        test_children(os.path.join(base, "children"))
        test_machines_units(os.path.join(base, "units"))
        test_pty_machines(os.path.join(base, "machines"))
        test_viewer(os.path.join(base, "viewer"))
        test_pty_engine(os.path.join(base, "engine"))
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("toptest: %s in %.0f s" % ("all passed" if not FAILS else "%d FAILED" % len(FAILS), time.time() - t0))
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
