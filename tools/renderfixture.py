#!/usr/bin/python3 -I
"""The app's renders, made to repeat themselves (roadmap 02 §8; 1.10.6): a fixture directory, and the
check that two renders of it are byte-identical. A render reads this Mac's clock and asks the process
table whether a lease's holder lives; `--now T` and `--no-liveness` take both from the fixture, and
`--fixture DIR` reads DIR/log, DIR/ledger and DIR/machines instead of this Mac's folders.

    tools/renderfixture.py DIR          write the fixture into DIR and print the command that draws it
    tools/renderfixture.py --app EXE    check EXE (oomph.app/Contents/MacOS/oomph): every state below is
                                        drawn twice and must come out byte for byte the same; a render an hour
                                        later must differ (the clock is honoured), and so must one without
                                        --no-liveness (the fixture's holders are not alive)

The data is tools/topfixture.py's invented week ("default"), its live leases held by a process that cannot
exist. CI runs the check after building the app; the TimeAxis refactor (M5) is held to it before and after.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import topfixture  # noqa: E402

NOW = int(topfixture.NOW)
DEAD_PID = 99999999  # above every system's pid limit: kill(pid, 0) says ESRCH
# (--ai state, extra arguments): the plain popup, the ∞ range, both tooltips, dark, and the machines switch on
STATES = [("", []), ("log", []), ("hover:300", []), ("rhover:420:30", []), ("", ["--dark"]),
          ("", ["-machinesUI", "YES"])]
DEFAULTS = ["-aiOn", "NO", "-machinesUI", "NO", "-openedAgo", "0"]  # never this Mac's own settings


def write(d):
    """The fixture: topfixture's default machine; its live leases' holder is DEAD_PID."""
    log, led = topfixture.write_fixture(d, "default")
    os.makedirs(os.path.join(d, "machines"))
    p = os.path.join(led, "ledger.json")
    with open(p) as f:
        ledger = json.load(f)
    for lease in ledger["leases"]:
        lease["holder"]["pid"] = DEAD_PID
    with open(p, "w") as f:
        json.dump(ledger, f)
    return d


def render(exe, fx, out, ai="", extra=(), now=NOW, live=False):
    """One render into `out`: (exit code, the PNG's bytes or None, stderr)."""
    cmd = [exe, "--render-popup", out, "--fixture", fx, "--now", str(now)] + ([] if live else ["--no-liveness"])
    cmd += (["--ai", ai] if ai else []) + DEFAULTS + list(extra)  # after DEFAULTS: the last value of a key wins
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return -1, None, "timed out"
    data = open(out, "rb").read() if os.path.exists(out) and os.path.getsize(out) > 0 else None
    return r.returncode, data, r.stderr.strip()


def check(exe):
    bad = []

    def ok(cond, what):
        print(("ok    " if cond else "FAIL  ") + what)
        if not cond:
            bad.append(what)

    base = tempfile.mkdtemp(prefix="oomph-renderfixture-")
    try:
        fx = write(os.path.join(base, "fx"))
        first = {}
        for i, (ai, extra) in enumerate(STATES):
            name = (ai or "plain") + "".join(" " + x for x in extra)
            a = render(exe, fx, os.path.join(base, "%d-a.png" % i), ai, extra)
            b = render(exe, fx, os.path.join(base, "%d-b.png" % i), ai, extra)
            first[i] = a[1]
            ok(a[0] == 0 and a[1] is not None and a[1] == b[1],
               "render %s: drawn twice, byte-identical (%s)" % (
                   name, "%d bytes" % len(a[1]) if a[1] and a[1] == b[1] else a[2] or b[2] or "they differ"))
        ok(first[0] is not None and first[len(STATES) - 1] not in (None, first[0]),
           "render with the machines switch on: a different picture from the plain one (the switch took)")
        later = render(exe, fx, os.path.join(base, "later.png"), now=NOW + 3600)
        ok(later[1] is not None and first[0] is not None and later[1] != first[0],
           "render an hour later by --now: a different picture (the clock comes from --now)")
        live = render(exe, fx, os.path.join(base, "live.png"), live=True)
        ok(live[1] is not None and first[0] is not None and live[1] != first[0],
           "render without --no-liveness: a different picture (the fixture's holders are not alive)")
        nolog = render(exe, os.path.join(base, "nothing"), os.path.join(base, "nolog.png"))
        ok(nolog[0] == 2 and nolog[1] is None, "--fixture without a log folder: refused (exit %s)" % nolog[0])
        badnow = render(exe, fx, os.path.join(base, "badnow.png"), now="soon")
        ok(badnow[0] == 2 and badnow[1] is None, "--now that is not a time: refused (exit %s)" % badnow[0])
    finally:
        shutil.rmtree(base, ignore_errors=True)
    print("renderfixture: %s" % ("renders repeat themselves" if not bad else "%d problem(s)" % len(bad)))
    return 1 if bad else 0


def main(argv):
    if "--app" in argv and argv.index("--app") + 1 < len(argv):
        return check(argv[argv.index("--app") + 1])
    if len(argv) == 1 and not argv[0].startswith("-"):
        d = write(argv[0])
        print("renderfixture: %s (now = %d)\n  oomph.app/Contents/MacOS/oomph --render-popup out.png --fixture %s "
              "--now %d --no-liveness %s" % (d, NOW, d, NOW, " ".join(DEFAULTS)))
        return 0
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
