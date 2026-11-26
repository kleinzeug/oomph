#!/usr/bin/python3 -I
"""H0 as real root: no process running as root opens anything inside the shared ledger
directory, to read or to write, by any route, and root never waits on it. Used by CI.

  sudo /usr/bin/python3 -I -B tools/roottest.py   as root (CI has passwordless sudo)
  /usr/bin/python3 -I -B tools/roottest.py        not root: a dry run — this process pretends
                                                  to be root, its children run as you

Copies daemon/ into a root-owned 0755 directory (the unprivileged children must read it),
points OOMPH_DIR and OOMPH_LEDGER_DIR at temporary directories, and runs the daemon's
sampling and `oomph reserve` / `reservations` / `release` / `top` / `doctor` / `serve --stdio` against a planted symbolic link, a
FIFO, endless and sparse files, a held lock, malformed leases, a hard link and a directory
replaced by a link. An audit hook records every file this (root) process opens, renames,
removes or creates: anything inside the ledger directories fails the test, as does a changed
link target, an operation past its deadline, or a sample that waited for the ledger.
"""
import base64
import hashlib
import io
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from contextlib import redirect_stderr, redirect_stdout

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REAL = os.geteuid() == 0
USER = int(os.environ.get("SUDO_UID") or 0) if REAL else os.getuid()  # whom root's ledger children run as
NOBODY = pwd.getpwnam("nobody").pw_uid


def ps_uid(pid):
    """The effective uid of `pid` as ps shows it, as pwd gives it (ps prints nobody as -2), or None."""
    out = subprocess.run(["/bin/ps", "-o", "uid=", "-p", str(pid)], capture_output=True, text=True, timeout=10).stdout
    try:
        return int(out.strip()) & 0xffffffff
    except ValueError:
        return None


base = tempfile.mkdtemp(prefix="oomph-roottest-")
os.chmod(base, 0o755)
code, ledgers, victims = (os.path.join(base, x) for x in ("code", "ledgers", "victims"))
for d in (code, ledgers, victims):
    os.mkdir(d)
    os.chmod(d, 0o755)
for f in ("oomph.py", "oomphd.py", "oomph_darwin.py", "oomph_linux.py", "oomph_ioreport.py", "oomph_top.py", "oomph_view.py",
          "oomph_net.py", "oomph_sync.py", "oomph_remote.py", "oomph_gpu.py"):
    shutil.copy(os.path.join(ROOT, "daemon", f), code)
    os.chmod(os.path.join(code, f), 0o644)
os.environ["OOMPH_DIR"] = os.path.join(base, "logs")
os.environ["OOMPH_LEDGER_DIR"] = os.path.join(ledgers, "unused")
os.environ["OOMPH_IOREPORT"] = "0"  # the daemon's samples start no IOReport helper here; section 12 starts one itself
sys.path.insert(0, code)

import oomph  # noqa: E402
import oomphd  # noqa: E402

if not REAL:  # pretend: the code takes its root paths, the children simply run as us
    os.geteuid = lambda: 0
    oomph._drop_to = lambda user, group: {}
print("H0 root test, " + ("as root (ledger children as uid %s, the daemon's as nobody)" % (USER or "nobody") if REAL
                           else "DRY RUN as uid %d (pretending to be root; all children run as you)" % os.getuid()))
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


# --- the audit hook: what this process touches
watching = [False]
hits = []
PREFIXES = (ledgers, os.path.realpath(ledgers))
EVENTS = {"open", "os.rename", "os.remove", "os.rmdir", "os.mkdir", "os.chmod", "os.chown", "os.link", "os.symlink",
          "os.truncate", "os.utime", "os.listdir", "os.scandir", "os.chflags", "shutil.rmtree", "shutil.copyfile"}


def hook(event, args):
    if watching[0] and event in EVENTS:
        for a in args[:2] if event in ("os.rename", "os.link", "os.symlink") else args[:1]:
            if isinstance(a, bytes):
                a = a.decode("utf-8", "replace")
            if isinstance(a, str) and (a.startswith(PREFIXES) or not a.startswith("/")):
                hits.append("%s %s (thread %s)" % (event, a, threading.current_thread().name))


sys.addaudithook(hook)


class Watch:
    """Within: the code under test, as root. Outside: the harness."""

    def __enter__(self):
        del hits[:]
        watching[0] = True

    def __exit__(self, *a):
        watching[0] = False
        return False


fake = dict(oomph.live_sample(with_procs=False), ram_gb=36.0, app_gb=20.0, wired_gb=4.0, compressed_gb=2.0,
            pressure=1, disk_free_gb=60.0, swap_used_gb=0.0, swap_total_gb=0.0)
oomph._sample_override = lambda: dict(fake)


def as_user(cmd, **kw):
    """A process of the user whose ledger root writes on behalf of (planted things, holders)."""
    if REAL and USER:
        kw.update(user=USER, group=pwd.getpwuid(USER).pw_gid, extra_groups=[])
    return subprocess.Popen(cmd, **kw)


def case(name):
    """A fresh ledger directory, 0777 like /Users/Shared/oomph."""
    p = os.path.join(ledgers, name)
    os.mkdir(p)
    os.chmod(p, 0o777)
    oomph.LEDGER_DIR = p
    return p


def victim(name, text, owner=None, mode=0o600):
    p = os.path.join(victims, name)
    open(p, "w").write(text)
    os.chmod(p, mode)
    if REAL:
        os.chown(p, owner if owner is not None else 0, -1)
    return p


def digest(p):
    st = os.lstat(p)
    return hashlib.sha256(open(p, "rb").read()).hexdigest(), st.st_size, st.st_mtime_ns, st.st_nlink


def cli(*args):
    out, err = io.StringIO(), io.StringIO()
    t = time.time()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            rc = oomph.main(list(args))
        except Exception as e:  # noqa: B902 — a traceback is a failure, recorded as such
            rc, err = "raised %r" % e, io.StringIO(repr(e))
    return rc, out.getvalue(), err.getvalue(), time.time() - t


d = oomphd.Daemon()
d.notify = lambda *a: None
d.ledger.FORCE_EVERY = 0  # a child every sample: deterministic
d.ledger.ERROR_EVERY = 0  # every error an event
d.ledger.start()


def tick(timeout=15):
    """One sample (timed: it must not wait), then wait for the ledger thread's child."""
    n = d.ledger.runs
    t = time.time()
    try:
        s = d.sample()
    except Exception as e:  # noqa: B902
        s = {"raised": repr(e)}
    dt = time.time() - t
    end = time.time() + timeout
    while d.ledger.runs == n and time.time() < end:
        time.sleep(0.05)
    return s, dt, d.ledger.runs > n


def _events():
    p = os.path.join(os.environ["OOMPH_DIR"], "events.jsonl")
    return [json.loads(x) for x in open(p)] if os.path.exists(p) else []


def mark():
    """Where the daemon's event log is now."""
    return len(_events())


def events(since, where=None):
    """daemon_error events logged after mark `since`."""
    return [e for e in _events()[since:] if e["kind"] == "daemon_error" and (where is None or e.get("where") == where)]


def no_hits(what):
    check(not hits, "%s: root opened nothing in the ledger directory%s" % (what, "" if not hits else " — " + "; ".join(hits[:5])))


# 0. the fence
case("fence")
with Watch():
    refused = []
    for name, fn in (("read_ledger", oomph.read_ledger), ("read_history", oomph.read_history),
                     ("Ledger", lambda: oomph.Ledger().__enter__())):
        try:
            fn()
        except oomph.LedgerError:
            refused.append(name)
check(len(refused) == 3, "fence: read_ledger, read_history and Ledger refuse root (%s)" % refused)
# root's own per-user ledger on Linux is the one place root works in place (03 §7.5): never a
# shared, group-writable or env-given folder, and never on a Mac
plat, envd = sys.platform, os.environ.pop("OOMPH_LEDGER_DIR")
try:
    inplace = [oomph._root_in_place()]
    sys.platform = "linux"
    inplace.append(oomph._root_in_place())          # the 0777 folder of case(), not the default path
    os.environ["OOMPH_LEDGER_DIR"] = oomph.LEDGER_DIR
    inplace.append(oomph._root_in_place())          # named by the environment
finally:
    sys.platform = plat
    os.environ["OOMPH_LEDGER_DIR"] = envd
check(inplace == [False, False, False], "fence: root never works in place on a Mac, nor in a shared or env-given "
                                        "folder on Linux (%s)" % inplace)
no_hits("fence")

# 1. the plain path: root reserves through a child as the invoking user
p = case("plain")
with Watch():
    r1 = cli("reserve", "1G", "--for", "roottest plain", "--json")
    r2 = cli("reservations", "--json")
    tick()
    s, dt, ran = tick()
    rid = json.loads(r1[1] or "{}").get("id", "r0")
    r5 = cli("top", "--once", "--color", "never", "--size", "100x30")
    r6 = cli("doctor", "--json")
    r3 = cli("release", rid, "--json")
st = os.lstat(os.path.join(p, "ledger.json")) if os.path.lexists(os.path.join(p, "ledger.json")) else None
check(r1[0] == 0 and r2[0] == 0 and r3[0] == 0 and json.loads(r3[1] or "{}").get("released"),
      "plain: `oomph reserve`, `reservations`, `release` as root work (%s)" % [r1[0], r2[0], r3[0], r1[2][-200:]])
check(st and stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o666 and (not REAL or not USER or st.st_uid == USER),
      "plain: ledger.json written 0666 by uid %s, not by root" % (st and st.st_uid))
check([x["id"] for x in s.get("leases", [])] == [rid] and ran and dt < 2,
      "plain: the sample (%.2f s) carries the reservation, from the daemon's child" % dt)
check(r5[0] == 0 and "roottest plain" in r5[1] and len(r5[1].splitlines()) == 30,
      "plain: `oomph top --once` as root shows the reservation, read by a child (%s)" % [r5[0], r5[2][-200:]])
dc = {c["id"]: c for c in (json.loads(r6[1]) if r6[1].startswith("{") else {}).get("checks", [])}
check(r6[0] in (0, 1, 2) and dc.get("ledger", {}).get("level") == "ok" and "1 live reservation" in dc["ledger"]["text"]
      and dc.get("claude", {}).get("level") == "note",
      "plain: `oomph doctor` as root counts the reservation through a child, skips the Claude files (%s)"
      % [r6[0], dc.get("ledger"), r6[2][-200:]])
no_hits("plain")

# 1b. cores (1.12.0): a vector request as root, decided and measured in the child; the logger's pools
p = case("cores")
oomph._sample_override = lambda: dict(fake, cpu={"n": 14, "busy": 0.0})  # the grant, whatever the runner's cores
try:
    with Watch():
        tick()
        rc_ = cli("reserve", "--cpu", "2", "--for", "roottest cores", "--json")
        tick()
        s, dt, ran = tick()
        got = json.loads(rc_[1] or "{}")
        rr = cli("release", got.get("id", "r0"), "--json")
finally:
    oomph._sample_override = lambda: dict(fake)
cur = json.load(open(os.path.join(os.environ["OOMPH_DIR"], "current.json")))
check(rc_[0] == 0 and (got.get("run_with") or {}).get("cpu_cores") == 2 and rr[0] == 0
      and [x.get("cpu") for x in s.get("leases", [])] == [2],
      "cores: `oomph reserve --cpu 2` as root is granted through a child, the sample carries its cores (%s)"
      % [rc_[0], got.get("run_with"), rc_[2][-200:]])
check(sys.platform != "darwin" or ((cur.get("pools") or {}).get("cpu") or {}).get("cap") == cur["cpu"]["n"],
      "cores: the logger as root writes pools.cpu into current.json (%s)" % (cur.get("pools") or {}).get("cpu"))
no_hits("cores")

# 1c. disk space (1.12.1): the path is resolved to its pool in the child, as the user; root opens nothing in the ledger
p = case("disk")
with Watch():
    tick()
    rd_ = cli("reserve", "--disk", "1G@" + base, "--for", "roottest disk", "--json")
    tick()
    s, dt, ran = tick()
    got = json.loads(rd_[1] or "{}")
    if got.get("id"):
        cli("release", got["id"], "--json")
granted = got.get("status") == "granted" and (got.get("asked") or {}).get("disk") == "data" and \
    [(x.get("disk"), x.get("disk_pool")) for x in s.get("leases", [])] == [(1.0, "data")]
short = got.get("status") == "refused" and "can be reserved there" in got.get("advice", "")  # a runner's full disk
check(rd_[0] in (0, 75) and (granted or short),
      "disk: `oomph reserve --disk 1G@PATH` as root names the system's pool, decided in a child; the sample carries it "
      "(%s)" % [rd_[0], got.get("status"), got.get("asked"), rd_[2][-200:]])
no_hits("disk")

# 2. symbolic links planted at ledger.json and reservations.jsonl, to files only root may read and write
p = case("symlink")
secret = victim("root-ledger", json.dumps({"seq": 7, "history": [], "leases": [
    {"id": "r7", "state": "granted", "gb": 1, "purpose": "SECRET-ROOT-ONLY", "holder": {"pid": 1, "start": None},
     "requested": time.time(), "seen": time.time(), "granted": time.time()}]}))
rootlog = victim("root-log", "# root only\n")
before = (digest(secret), digest(rootlog))
os.symlink(secret, os.path.join(p, "ledger.json"))
os.symlink(rootlog, os.path.join(p, "reservations.jsonl"))
with Watch():
    r0 = cli("doctor", "--json")
    s, dt, ran = tick()
    r1 = cli("reserve", "1G", "--for", "roottest symlink", "--json")
    r2 = cli("reservations", "--json")
    r3 = cli("release", json.loads(r1[1] or "{}").get("id", "r0"), "--json")
    r4 = cli("status")
    r5 = cli("top", "--once", "--color", "never", "--size", "100x30")
check("SECRET" not in json.dumps(s) + r1[1] + r2[1] + r3[1] + r4[1] + r5[1] and r5[0] == 0 and (digest(secret), digest(rootlog)) == before,
      "symlink: nothing read or written through the planted links (rc %s)" % [r1[0], r2[0], r3[0], r4[0]])
check(all(stat.S_ISREG(os.lstat(os.path.join(p, f)).st_mode) for f in ("ledger.json", "reservations.jsonl")),
      "symlink: fresh files took the names")
dc = {c["id"]: c for c in (json.loads(r0[1]) if r0[1].startswith("{") else {}).get("checks", [])}
check(r0[0] in (1, 2) and dc.get("ledger", {}).get("level") == "warn" and "SECRET" not in r0[1],
      "symlink: `oomph doctor` as root reports the planted link (%s)" % [r0[0], dc.get("ledger"), r0[2][-200:]])
no_hits("symlink")

# 3. FIFOs, endless and sparse files
p = case("fifo")
for f in ("ledger.json", "reservations.jsonl"):
    os.mkfifo(os.path.join(p, f), 0o666)
with Watch():
    s, dt_s, ran = tick()
    r1 = cli("reserve", "1G", "--for", "roottest fifo", "--json")
    r3 = cli("release", json.loads(r1[1] or "{}").get("id", "r0"))
    r5 = cli("top", "--once", "--color", "never")
check(dt_s < 2 and ran and r1[0] == 0 and r3[0] == 0 and r5[0] == 0 and r1[3] + r3[3] + r5[3] < 30,
      "FIFO: the sample took %.2f s, reserve %.1f s, release %.1f s, top %.1f s; nothing hung"
      % (dt_s, r1[3], r3[3], r5[3]))
no_hits("FIFO")
p = case("fifo-lock")
os.mkfifo(os.path.join(p, "ledger.lock"), 0o666)
with Watch():
    r1 = cli("reserve", "1G", "--for", "roottest fifo lock")
    s, dt_s, ran = tick()
check(r1[0] == 1 and "not a regular file" in r1[2] and r1[3] < 10 and dt_s < 2,
      "FIFO as the lock: refused cleanly in %.1f s (%s)" % (r1[3], r1[2].strip()[:80]))
no_hits("FIFO lock")
p = case("endless")
os.symlink("/dev/zero", os.path.join(p, "ledger.json"))
os.symlink("/dev/urandom", os.path.join(p, "reservations.jsonl"))
with Watch():
    s, dt_s, ran = tick()
    r1 = cli("reserve", "1G", "--for", "roottest endless", "--json")
    r3 = cli("release", json.loads(r1[1] or "{}").get("id", "r0"))
check(dt_s < 2 and r1[0] == 0 and r3[0] == 0 and r1[3] + r3[3] < 20,
      "endless (/dev/zero, /dev/urandom): reserve %.1f s, release %.1f s" % (r1[3], r3[3]))
no_hits("endless")
p = case("sparse")
for f in ("ledger.json", "reservations.jsonl"):
    with open(os.path.join(p, f), "wb") as fh:
        fh.truncate(1 << 30)
    os.chmod(os.path.join(p, f), 0o666)
    if REAL and USER:
        os.chown(os.path.join(p, f), USER, -1)
with Watch():
    s, dt_s, ran = tick()
    r1 = cli("reserve", "1G", "--for", "roottest sparse", "--json")
    r3 = cli("release", json.loads(r1[1] or "{}").get("id", "r0"))
check(dt_s < 2 and r1[0] == 0 and r3[0] == 0 and r1[3] + r3[3] < 20 and
      os.lstat(os.path.join(p, "reservations.jsonl")).st_size < 1 << 20,
      "1 GB sparse files: reserve %.1f s, release %.1f s, replaced by small ones" % (r1[3], r3[3]))
no_hits("sparse")

# 4. a held lock: `oomph reserve` says busy, the sampler doesn't wait
p = case("lock")
open(os.path.join(p, "ledger.lock"), "w").close()
os.chmod(os.path.join(p, "ledger.lock"), 0o666)
holder = as_user([sys.executable, "-I", "-c", "import fcntl, os, sys, time\nfd = os.open(sys.argv[1], os.O_RDONLY)\n"
                  "fcntl.flock(fd, fcntl.LOCK_EX)\nprint('held', flush=True)\ntime.sleep(120)",
                  os.path.join(p, "ledger.lock")], stdout=subprocess.PIPE, text=True)
holder.stdout.readline()
open(os.path.join(p, "ledger.json"), "w").write(json.dumps({"seq": 1, "history": [], "leases": [
    {"id": "r1", "state": "granted", "gb": 1, "purpose": "held", "holder": {"pid": holder.pid, "start": None},
     "requested": time.time(), "seen": time.time(), "granted": time.time()}]}))
os.chmod(os.path.join(p, "ledger.json"), 0o666)
t0 = mark()
with Watch():
    r1 = cli("reserve", "1G", "--for", "roottest lock")
    samples = [tick() for _ in range(3)]
check(r1[0] == 75 and "busy" in r1[2] and r1[3] < oomph.LOCK_WAIT_S + 8,
      "held lock: `oomph reserve` as root exits 75 after %.1f s (%s)" % (r1[3], r1[2].strip()[:70]))
check(max(x[1] for x in samples) < 2 and all(x[2] for x in samples) and
      [b["id"] for b in samples[-1][0].get("leases", [])] == ["r1"],
      "held lock: samples took %s s; the snapshot still arrives" % ", ".join("%.2f" % x[1] for x in samples))
check(any("busy" in e.get("error", "") for e in events(t0, "ledger")), "held lock: a daemon_error (ledger) says busy")
holder.kill()
holder.wait()
no_hits("held lock")

# 5. malformed leases: every sample used to raise
p = case("malformed")
sleeper = as_user(["/bin/sleep", "120"])
open(os.path.join(p, "ledger.json"), "w").write(json.dumps({"seq": "x", "history": [{"id": 3}], "leases": [
    {"id": "r1"}, {"id": "r2", "state": "granted", "gb": [], "holder": {}},
    {"id": "r3", "state": "queued", "gb": 1, "purpose": "valid", "holder": {"pid": sleeper.pid, "start": None},
     "requested": time.time(), "seen": time.time()}]}))
os.chmod(os.path.join(p, "ledger.json"), 0o666)
t0 = mark()
with Watch():
    a = tick()
    b = tick()
    r1 = cli("reserve", "1G", "--for", "roottest malformed", "--json")
    r2 = cli("reservations", "--history", "--json")
errs = events(t0, "loop") + events(t0, "ledger")
check("raised" not in a[0] and "raised" not in b[0] and not errs,
      "malformed leases: samples don't raise, no daemon_error %s" % [e.get("error") for e in errs])
check([x["id"] for x in b[0].get("leases", [])] == ["r3"], "malformed leases: the sample carries the valid one only")
check(r1[0] in (0, 75) and r2[0] == 0, "malformed leases: `oomph reserve` / `reservations --history` work (%s)"
      % [r1[0], r2[0], r1[2][-100:]])
sleeper.kill()
sleeper.wait()
no_hits("malformed")

# 6. hard links to the invoking user's own file (their ~/.zshrc): no write through them, by construction
p = case("hardlink")
zshrc = victim("zshrc", "export PATH=/usr/bin\n", owner=USER, mode=0o644)
before = digest(zshrc)
os.link(zshrc, os.path.join(p, "reservations.jsonl"))
os.link(zshrc, os.path.join(p, "ledger.json"))
with Watch():
    r1 = cli("reserve", "1G", "--for", "roottest hardlink", "--json")
    r3 = cli("release", json.loads(r1[1] or "{}").get("id", "r0"))
    s, dt_s, ran = tick()
check(r1[0] == 0 and r3[0] == 0 and digest(zshrc) == before and os.lstat(zshrc).st_nlink == 1,
      "hard link: the user's file is unchanged, the names now hold fresh files")
recs = open(os.path.join(p, "reservations.jsonl")).read()
check("roottest hardlink" in recs, "hard link: the history record went to the fresh log")
no_hits("hard link")

# 7. the directory itself replaced by a link (to a directory root and the children could write)
target = os.path.join(victims, "elsewhere")
os.mkdir(target)
os.chmod(target, 0o777)
p = os.path.join(ledgers, "dirlink")
os.symlink(target, p)
oomph.LEDGER_DIR = p
t0 = mark()
with Watch():
    r1 = cli("reserve", "1G", "--for", "roottest dirlink")
    s, dt_s, ran = tick()
check(r1[0] == 1 and "not a plain directory" in r1[2] and os.listdir(target) == [] and dt_s < 2 and "raised" not in s,
      "directory replaced by a link: refused (%s), nothing created behind it" % r1[2].strip()[:70])
check(any("not a plain directory" in e.get("error", "") for e in events(t0, "ledger")),
      "directory replaced by a link: the daemon reports it")
no_hits("dir link")

# 8. a dead holder's reservation still ends within one sample
p = case("dead")
sleeper = as_user(["/bin/sleep", "120"])
with Watch():
    x = oomph.reserve(0.5, "roottest dies", {"pid": sleeper.pid, "start": None, "kind": "session", "project": "/"})
    sleeper.kill()
    sleeper.wait()
    t_kill = time.time()
    s, dt_s, ran = tick()
    h = oomph.reservation_history(3600)
end = next((r for r in h["reservations"] if r["id"] == x.get("id")), {})
check(x.get("status") == "granted" and end.get("outcome") == "holder_gone" and ran and
      time.time() - t_kill < oomphd.INTERVAL, "dead holder: retired within one sample (%s)" % end.get("outcome"))
st = os.lstat(os.path.join(p, "ledger.json"))
check(not REAL or st.st_uid == NOBODY, "dead holder: the daemon's child wrote as nobody (uid %d)" % st.st_uid)
no_hits("dead holder")

# 9. the root-owned configuration file: read only when root's and nobody else's
cfgd = os.path.join(base, "config")
os.mkdir(cfgd)
os.chmod(cfgd, 0o755)
cfg = os.path.join(cfgd, "config.json")
open(cfg, "w").write('{"ioreport": true}')
os.chmod(cfg, 0o644)
check(oomph.read_config(cfg) == ({"ioreport": True} if REAL else {}),
      "config: %s" % ("root's file is read" if REAL else "a file root doesn't own is ignored"))
if REAL:
    cases = []
    os.chmod(cfg, 0o664)
    cases.append(oomph.read_config(cfg))  # group-writable
    os.chmod(cfg, 0o644)
    os.chown(cfg, USER or NOBODY, -1)
    cases.append(oomph.read_config(cfg))  # someone else's
    os.chown(cfg, 0, -1)
    os.chmod(cfgd, 0o777)
    cases.append(oomph.read_config(cfg))  # in a folder others can write
    os.chmod(cfgd, 0o755)
    os.rename(cfg, cfg + ".real")
    os.symlink(cfg + ".real", cfg)
    cases.append(oomph.read_config(cfg))  # a link
    os.remove(cfg)
    os.mkfifo(cfg, 0o644)
    t = time.time()
    cases.append(oomph.read_config(cfg))  # a FIFO
    check(cases == [{}] * 5 and time.time() - t < 2,
          "config: ignored when group-writable, someone else's, in a folder others can write, a link or a FIFO")

# 11. `oomph serve --stdio` as root gives up root for good before it reads anything, and what is
#     planted in the ledger directory (a link to root's file, a FIFO) is absent to it, without a wait
p = case("serve")
v = victim("serve-ledger.json", json.dumps({"seq": 1, "leases": [{"id": "r1", "state": "granted", "gb": 1.0,
                                                                   "purpose": "root's secret", "requested": time.time(),
                                                                   "granted": time.time(), "holder": {"pid": 1}}]}),
           mode=0o644)  # readable by all: only not following the link keeps it out of the answer
os.symlink(v, os.path.join(p, "ledger.json"))
os.mkfifo(os.path.join(p, "reservations.jsonl"), 0o666)
srv = subprocess.Popen([sys.executable, "-I", "-B", os.path.join(code, "oomph.py"), "serve", "--stdio"],
                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=dict(os.environ, OOMPH_LEDGER_DIR=p))
t = time.time()
answers = []
try:
    for i, m in enumerate(("hello", "ledger", "reservations")):
        srv.stdin.write((json.dumps({"jsonrpc": "2.0", "id": i, "method": m, "params": {"proto": [1, 1]}}) + "\n").encode())
        srv.stdin.flush()
        answers.append(json.loads(srv.stdout.readline() or "{}"))
        if i == 0:
            uid = ps_uid(srv.pid)
finally:
    srv.stdin.close()
    srv.wait(10)
    srv.stdout.close()
want = (USER or NOBODY) if REAL else os.getuid()
snap = json.loads(zlib.decompress(base64.b64decode(answers[1].get("result", {}).get("data", ""))) or b"{}") \
    if len(answers) > 1 and "result" in answers[1] else {}
check(uid == want and snap.get("leases") == [] and answers[2].get("result", {}).get("n") == 0 and time.time() - t < 10,
      "serve --stdio as root runs as uid %s (want %s); a link to root's file and a FIFO are absent (%.1f s)"
      % (uid, want, time.time() - t))

# 12. the IOReport helper (1.9.3): its private library never loads into a process running as root. The
#     helper refuses root, the logger starts it as nobody, and the logger's own process has not loaded it.
if sys.platform == "darwin":
    P = oomph.plat()
    cmd = P.ioreport_helper()
    r = subprocess.run(cmd, input=b"\n", capture_output=True, timeout=30)
    if REAL:
        check(r.returncode == 3 and not r.stdout, "IOReport: the helper refuses to run as root (exit %s)" % r.returncode)
    # where this Mac has no usable table (Intel, CI's VMs) the helper is started anyway, with the table of 02 A.4:
    # who it runs as and what this process loads do not depend on the table
    table = P.gpu_dvfs_mhz()
    real_table = oomphd.dvfs_usable(table)
    fs = oomphd.FullSpeed(cmd, table if real_table else [0.0, 338.0, 618.0, 796.0, 832.0, 924.0, 952.0, 1056.0, 1064.0,
                                                         1182.0, 1182.0, 1312.0, 1242.0, 1380.0],
                          os.path.join(os.environ["OOMPH_DIR"], "ioreport.json"), P.boot_id())
    fs.figure(None)
    uid = ps_uid(fs.proc.pid) if fs.proc else None
    time.sleep(0.5)
    t1 = P.uptime_s()
    fs.figure(None)
    time.sleep(0.5)
    fig = fs.figure(P.uptime_s() - t1)
    fs.close()
    import ctypes  # noqa: E402
    dyld = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
    dyld._dyld_get_image_name.restype = ctypes.c_char_p
    loaded = [dyld._dyld_get_image_name(i) or b"" for i in range(dyld._dyld_image_count())]
    want = NOBODY if REAL else os.getuid()
    check(uid == want and not any(b"IOReport" in x for x in loaded) and fs.state["crashes"] == 0 and
          (fig is not None if real_table else True) and fs.status() in ("on", "unavailable"),
          "IOReport: the logger starts the helper as uid %s (want %s) and never loads the library itself; %s"
          % (uid, want, "a reading of %.1f %% at full speed" % fig[0] if fig else
             "no reading: this Mac has %s" % ("no channel" if fs.status() == "unavailable" else
                                               "no usable GPU frequency table" if not real_table else fs.status())))

# 10. install.sh as root into a throwaway prefix: everything root's, the old layout migrated
#     (the real one, with launchd, runs in CI's "Install over 1.8.4" step)
#     As root, a prefix someone else could change is refused: root's install follows no one's directory.
if REAL:
    loose = os.path.join(base, "loose")
    os.mkdir(loose)
    os.chmod(loose, 0o777)
    r = subprocess.run(["/bin/bash", os.path.join(ROOT, "install.sh")], capture_output=True, text=True, timeout=60,
                       env=dict(os.environ, OOMPH_INSTALL_ROOT=loose))
    r2 = subprocess.run(["/bin/bash", os.path.join(ROOT, "uninstall.sh")], capture_output=True, text=True,
                        timeout=60, env=dict(os.environ, OOMPH_INSTALL_ROOT=loose))
    check(r.returncode == 1 and r2.returncode == 1 and os.listdir(loose) == [],
          "install.sh/uninstall.sh as root refuse a prefix others can write")
# root's all the way up (TMPDIR may be the sudoer's): a fresh folder in /private/tmp
pfx = tempfile.mkdtemp(prefix="oomph-prefix-", dir="/private/tmp") if REAL else os.path.join(base, "prefix")
lx = os.path.join(pfx, "usr", "local", "libexec")
os.makedirs(os.path.join(lx, "oomph"))
shutil.copy(os.path.join(ROOT, "daemon", "oomph.py"), os.path.join(lx, "oomph"))
r = subprocess.run(["/bin/bash", os.path.join(ROOT, "install.sh")], capture_output=True, text=True, timeout=120,
                   env=dict(os.environ, OOMPH_INSTALL_ROOT=pfx))
target = os.readlink(os.path.join(lx, "oomph")) if os.path.islink(os.path.join(lx, "oomph")) else ""
paths = [os.path.join(dp, x) for dp, dn, fn in os.walk(os.path.join(lx, target)) for x in dn + fn] if target else []
bad = [x for x in paths + [os.path.join(lx, "oomph"), os.path.join(lx, target)]
       if os.lstat(x).st_uid != os.getuid() or stat.S_IMODE(os.lstat(x).st_mode) & 0o022]
check(r.returncode == 0 and target.startswith("oomph-") and paths and not bad and
      len([x for x in os.listdir(lx) if x.startswith("oomph-")]) == 2,
      "install.sh: a complete version directory behind the link, owned by uid %d and writable by nobody else%s"
      % (os.getuid(), " — " + (r.stderr.strip()[-200:] or str(bad[:3])) if r.returncode or bad else ""))
r = subprocess.run(["/bin/bash", os.path.join(ROOT, "uninstall.sh")], capture_output=True, text=True, timeout=60,
                   env=dict(os.environ, OOMPH_INSTALL_ROOT=pfx))
check(r.returncode == 0 and os.listdir(lx) == [], "uninstall.sh: every version and the link removed")
if REAL:
    shutil.rmtree(pfx, ignore_errors=True)

if not REAL:
    print("dry run: real root, user switching and the file owners are checked only under sudo")
shutil.rmtree(base, ignore_errors=True)
print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed"))
sys.exit(1 if failures else 0)
