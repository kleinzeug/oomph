#!/usr/bin/python3 -I
"""Linux for agents (1.9.4, step L1; roadmap 03 §15): the Linux backend, the CLI on it, and the
exit codes agents rely on. Three parts:

  fixtures  on any system: daemon/oomph_linux.py on recorded machines (tools/linuxfixture.py) — the
            memory classes and their identity, the level and its three invariants (table-driven:
            a grant used as declared never changes the level; headroom alone never reads critical;
            a container at its own limit is not the machine), PSI off (RHEL 9), cgroup scope,
            process names and groups; then the CLI as it runs on Linux (check, status, doctor,
            reservations, a refused oversize request) on those machines, with no macOS word.
  live      on the system this runs on, Mac or Linux, with the same table of exit codes: check,
            reserve, amend, release, run, hook, doctor, wait, mcp, usage errors, and two sessions
            taking turns (a request queued behind another, granted when it is released; two
            `oomph run` in a row). On a Mac this is the macOS backend: the exit codes match.
  linux     on Linux only: a real measurement (a child that writes 200 MB raises its tree's
            footprint by that much), cgroup scope when this runs in a limited container (the CI's
            2 GB one), `oomph top --once`, setup-claude, and linux/install.sh into a scratch HOME.

  logger    on any system: the Linux logger (1.13.0) on recorded machines and captured journal lines.
  system    on Linux: linux/install.sh --system into a folder, and its uninstall.

  root      on Linux as root without sudo, only when named (it writes root's home): root's own
            ledger used in place, a shared one through a child as nobody, install.sh as root.
  service   on Linux as root with systemd, only when named (CI): the logger installed as a service.

Run: python3 -I -B tools/linuxtest.py [fixtures|logger|live|linux|system|root|service ...]. Exit 0 when every check
passes. OOMPH_LINUXTEST_STRICT=1 (CI) turns every skipped part into a failure.
Ad-hoc memory is bounded: the one allocation is 200 MB, every child has a timeout.
"""
import glob
import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DAEMON = os.path.join(ROOT, "daemon")
OOMPH = os.path.join(DAEMON, "oomph.py")
TMP = tempfile.mkdtemp(prefix="oomph-linuxtest-")
sys.path[:0] = [DAEMON, os.path.join(ROOT, "tools")]
import linuxfixture  # noqa: E402

LINUX = sys.platform.startswith("linux")
STRICT = os.environ.get("OOMPH_LINUXTEST_STRICT") == "1"  # CI: a part that cannot run here fails instead of skipping
MAC_WORDS = re.compile(r"\b(jetsam|Mac|macOS|Activity Monitor|unowned|wired|Wired)\b")
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)
    return cond


def skip(what):
    """A part this machine cannot run: a note, or under OOMPH_LINUXTEST_STRICT a failure."""
    if STRICT:
        check(False, "not run (strict): " + what)
    else:
        print("skip  " + what)


def env(**kw):
    """A clean environment: a log folder with no logger, a ledger and state of this test's own,
    no claude on the PATH (setup-claude must not touch the real ~/.claude.json)."""
    e = {k: v for k, v in os.environ.items() if not k.startswith(("OOMPH_", "XDG_"))}
    e.update(OOMPH_DIR=os.path.join(TMP, "logs"), OOMPH_LEDGER_DIR=os.path.join(TMP, "ledger"),
             OOMPH_STATE_DIR=os.path.join(TMP, "state"), PATH="/usr/bin:/bin", COLUMNS="80")
    e.update(kw)
    return {k: v for k, v in e.items() if v is not None}


def cli(*args, stdin=None, timeout=60, **kw):
    """`oomph ARGS` as a process: (exit code, stdout, stderr)."""
    r = subprocess.run([sys.executable, "-I", "-B", OOMPH] + list(args), input=stdin, capture_output=True, text=True,
                       timeout=timeout, env=env(**kw))
    return r.returncode, r.stdout, r.stderr


# A Linux CLI on a recorded machine, on any system: sys.platform says linux, OOMPH_SYSROOT the tree.
AS_LINUX = r"""
import sys
sys.platform = "linux"
sys.path.insert(0, sys.argv[1])
import oomph
sys.exit(oomph.main(sys.argv[2:]) or 0)
"""


def fx_cli(scenario, *args, timeout=60, **kw):
    root = os.path.join(TMP, "fx", scenario)
    if not os.path.isdir(root):
        linuxfixture.build(root, scenario)
    r = subprocess.run([sys.executable, "-I", "-B", "-c", AS_LINUX, DAEMON] + list(args), capture_output=True, text=True,
                       timeout=timeout, env=env(**dict(dict(OOMPH_SYSROOT=root, OOMPH_LEDGER_DIR=os.path.join(TMP, "fxl", scenario),
                                                            XDG_STATE_HOME=os.path.join(TMP, "xdg")), **kw)))
    return r.returncode, r.stdout, r.stderr


def backend(scenario):
    """oomph_linux on a recorded machine, in this process."""
    root = os.path.join(TMP, "fx", scenario)
    if not os.path.isdir(root):
        linuxfixture.build(root, scenario)
    os.environ["OOMPH_SYSROOT"] = root
    import oomph_linux
    return importlib.reload(oomph_linux)


# ======================================================================= fixtures
def part_fixtures():
    import oomph
    for name, (_fn, want) in linuxfixture.SCENARIOS.items():
        L = backend(name)
        s = dict(L.system_memory(), os="linux")
        v = oomph.verdict(s)
        got = {"pressure": s["pressure"], "ram_gb": s["ram_gb"], "level": v["level"], "margin_gb": s["linux"]["margin_gb"],
               "psi": "psi" in s, "scope": (s.get("scope") or {}).get("kind"), "by": (s.get("scope") or {}).get("by"),
               "compressed_gb": s["compressed_gb"], "swap_total_gb": s["swap_total_gb"], "swap_used_gb": s["swap_used_gb"],
               "free_gb": s["free_gb"], "limit": bool((s.get("psi") or {}).get("limit")),
               "host_pressure": (s.get("scope") or {}).get("host_pressure")}
        ident = round(s["wired_gb"] + s["app_gb"] + s["compressed_gb"] + s["cached_gb"] + s["free_gb"], 1)
        got["identity"] = abs(ident - s["ram_gb"]) <= 0.1
        bad = {k: (got.get(k), w) for k, w in want.items() if got.get(k) != w}
        words = " ".join(v["reasons"] + v.get("notes", []) + [v["advice"]])
        check(not bad and not MAC_WORDS.search(words), "fixture %s: level %s (%s), %.1f GB, margin %.2f%s%s" % (
            name, v["level"], s["pressure"], s["ram_gb"], s["linux"]["margin_gb"],
            "; " + v["reasons"][0][:90] if v["reasons"] else "", "; MISMATCH %s" % bad if bad else ""))
        if name == "container-thrash-roomy-host":
            check(s["psi"]["limit"]["cgroups"] == ["docker:a3f9c1a7"] and s["psi"]["mem_some"] == 0.0,
                  "a container thrashing at its own limit: the machine's stall time is 0, and psi.limit names it")

    # a root caller's child as nobody where no group is named nobody (Debian, Ubuntu: nogroup)
    import grp
    import pwd

    def no_group(name):
        raise KeyError("getgrnam(): name not found: %r" % name)
    real, grp.getgrnam = grp.getgrnam, no_group
    try:
        ids = oomph._ids("nobody", "nobody")
    except Exception as e:  # noqa: BLE001 - the check reports it
        ids = repr(e)
    finally:
        grp.getgrnam = real
    pw = pwd.getpwnam("nobody")
    check(ids == (pw.pw_uid, pw.pw_gid) and oomph._ids(5, 7) == (5, 7),
          "a child as nobody without a group named nobody: nobody's own group, numerically (%s)" % (ids,))

    # the backend contract (oomph_darwin's names), and what a process is called and grouped under
    L = backend("ubuntu-server-idle")
    contract = ("OS", "machine", "system_memory", "away_state", "collect_procs", "proc_cwd", "group_key", "is_agent",
                "ownership", "uptime_s", "notify", "dump_syslog", "group_of", "scope", "boot_id")
    check(all(hasattr(L, n) for n in contract) and L.OS == "linux", "backend contract: oomph_linux has every member")
    procs = L.collect_procs()
    names = {p["pid"]: (p["name"], L.group_of(p), L.is_agent(p), p["path"]) for p in procs.values()}
    want = {1600: ("claude", "claude", True, ""), 1700: ("node", "node", True, ""),
            1610: ("java", "java", False, "/usr/bin/java"), 900: ("postgres", "postgresql@16-main", False,
                                                                   "/usr/lib/postgresql/16/bin/postgres"),
            2001: ("nginx", "docker:a3f9c1a7 (nginx)", False, ""), 2002: ("nginx", "docker:a3f9c1a7 (nginx)", False, ""),
            2101: ("postgres", "podman:devdb", False, ""), 2200: ("gnome-terminal-server", "org.gnome.Terminal", False,
                                                                  "/usr/libexec/gnome-terminal-server"),
            2300: ("a) (b", "a) (b", False, ""), 812: ("sshd", "ssh", False, ""),
            2310: ("x?]0;pwn?", "ev?[2Jil", False, "")}  # no control character reaches a terminal
    bad = {k: (names.get(k), w) for k, w in want.items() if names.get(k) != w}
    check(not bad and 2 not in procs, "processes: names from comm and argv (never exe), groups by container, unit and "
                                      "app scope, agents by name and by node's argv; kernel threads left out%s"
                                      % (": %s" % bad if bad else ""))
    p = procs[1610]
    check(p["fp"] == 5200 * 1024 * 1024 and p["rss"] == 5300 * 1024 * 1024 and p["start"] == 2610 and p["uid"] == 1000,
          "footprint is RssAnon + VmSwap, rss VmRSS, start in ticks since boot")
    check(sorted(L.collect_procs(only={1610})) == [1, 812, 1500, 1600, 1610],
          "collect_procs(only=…): the process and its ancestors, without a full scan")
    m = L.machine()
    check(re.fullmatch(r"m-[0-9a-f]{16}", m["id"] or "") and m["id_from"] == "machine-id" and m["os"] == "linux" and
          m["os_version"] == "Ubuntu 24.04.3 LTS" and m["measures"]["psi"] is True and m["measures"]["cgroup"] == "v2",
          "machine: id from /etc/machine-id, distribution, measures (psi, cgroup v2)")
    check(L.boot_id() == "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" and L.machine()["measures"]["all_procs"] is True,
          "boot id; all processes visible (no hidepid)")
    L = backend("rhel9-nopsi")
    check(L.machine()["measures"]["psi"] is False and "psi" not in L.system_memory(), "RHEL 9: PSI off is measured as off")
    L = backend("container-2g")
    sc = L.system_memory()["scope"]
    check(sc["kind"] == "cgroup" and sc["id"] == "/" and sc["limit_gb"] == 2.0 and sc["host_ram_gb"] == 16.0 and
          L.machine()["kind"] == "container" and L.machine()["virt"] == "docker" and L.machine()["id"] is None,
          "a docker container with its own cgroup namespace: scope cgroup, 2 GB, the host's 16 GB beside it; no machine id")

    # the three invariants (03 §5.3, §15.2), table-driven over pure functions
    L = backend("ubuntu-server-idle")
    viol, n = [], 0
    for ram in (2, 4, 8, 16, 32, 64, 128, 256, 512):
        for swap_frac in (0, 0.1, 0.5, 1.0):
            for left in (1.0, 0.55, 0.5, 0.09):
                swap = ram * swap_frac
                for avail in [L.margin(ram) + k * ram / 20.0 for k in range(0, 20)]:
                    if avail > ram:
                        continue
                    n += 1
                    grant = avail - L.margin(ram)      # the largest admissible request
                    sw_free = max(0.0, swap * left - grant)  # the worst case: all of it pushed other pages into swap
                    after = L.level(0.0, 0.0, avail - grant, ram, L.swap_left(swap, sw_free, ram))
                    if after != 1:
                        viol.append(("grant", ram, swap_frac, left, round(avail, 2), after))
                    for some in (None, 0.0):
                        if L.level(some, some, avail, ram, L.swap_left(swap, swap * left, ram)) == 4 or \
                                L.level(some, some, avail * 0.01, ram, 0.0) == 4:
                            viol.append(("headroom", ram, swap_frac, left, round(avail, 2)))
                    big = L.oversize_limit(avail, swap * left, ram)
                    if big and avail + swap * left - big < L.bounds(ram)[1] - 1e-9:
                        viol.append(("oversize", ram, swap_frac, left, round(avail, 2), big))
    check(not viol, "invariants over %d cells: a grant used as declared leaves the level normal; headroom alone never "
                    "reads critical; the largest lone grant leaves the lower bound%s" % (n, ": %s" % viol[:3] if viol else ""))

    # zram's free capacity is room only by what compressing saves: its pages stay in RAM
    zv = [(kf, zf, r) for kf in (0.0, 2.0, 8.0) for zf in (0.0, 1.0, 8.0) for r in (None, 0.5, 1.0, 2.1, 9.0)
          if L.swap_room(kf, zf, r) > max(0.0, kf - min(zf, kf)) + min(zf, kf) * (2 / 3.0) + 1e-9 or L.swap_room(kf, zf, r) > kf]
    L = backend("zram-desktop")
    lx = L.system_memory()["linux"]
    check(not zv and lx["swap_room_gb"] < lx["kswap_free_gb"] and
          lx["oversize_gb"] <= lx["avail_gb"] + lx["swap_room_gb"] - lx["floor_gb"] + 1e-9,
          "zram desktop: free zram counts by what compression saves (%.2f of %.2f GB free), and the largest lone grant "
          "(%.2f GB) leaves the lower bound%s" % (lx["swap_room_gb"], lx["kswap_free_gb"], lx["oversize_gb"],
                                                 ": %s" % zv[:3] if zv else ""))

    # the CLI as it runs on Linux, on recorded machines
    rc, out, err = fx_cli("ubuntu-server-idle", "check")
    check(rc == 0 and out.startswith("oomph: OK — 14.4G available of 16G · pressure normal · swap 0.0/3.0G") and
          "disk" not in out.splitlines()[0] and not MAC_WORDS.search(out),
          "check on Linux: \"available\", no disk, exit 0: %s" % (out.splitlines() or [err[-200:]])[0])
    for scen, code in (("server-noswap-93pct", 1), ("rhel9-nopsi", 1), ("pain-critical", 2), ("zram-desktop", 1),
                       ("container-2g", 0)):
        rc, out, err = fx_cli(scen, "check")
        check(rc == code and not MAC_WORDS.search(out), "check on %s: exit %d (%s)" % (
            scen, rc, (re.findall(r"why: (.*)", out) or [(out.splitlines() or [err[-120:]])[0]])[0][:100]))
    rc, out, _ = fx_cli("rhel9-nopsi", "check")
    check("PSI is off" in out and "CRITICAL" not in out, "RHEL 9 without PSI: tight, never critical, and says why")
    rc, out, _ = fx_cli("container-2g", "check", "--json")
    v = json.loads(out) if rc == 0 else {}
    c = v.get("coordination") or {}
    check(v.get("scope", {}).get("kind") == "cgroup" and v.get("ram_gb") == 2.0 and c.get("ledger", {}).get("kind") == "user"
          and c.get("grantable_gb") == c.get("available_gb") and v.get("available_gb") == v.get("free_gb"),
          "check --json in a container: scope, the limit as RAM, ledger kind user, grantable_gb")
    rc, out, err = fx_cli("ubuntu-server-idle", "status")
    check(rc == 0 and out.startswith("not logged: a live reading") and "stalled    memory some" in out and
          "available" in out and "top groups:" in out and not MAC_WORDS.search(out),
          "status without a logger: a live reading under a banner, exit 0, Linux words")
    rc, out, _ = fx_cli("rhel9-nopsi", "doctor")
    check(rc == 0 and "psi=1" in out and "grubby" in out and "Rocky Linux 9.9" in out,
          "doctor on RHEL 9 without PSI: a note with psi=1, exit 0")
    rc, out, _ = fx_cli("ubuntu-server-idle", "doctor", "--json")
    d = json.loads(out) if out.strip() else {}
    ids = [x["id"] for x in d.get("checks", [])]
    check(rc == d.get("exit") == 0 and {"memory", "pressure", "processes", "groups", "swap", "scope", "logger",
                                         "ledger"} <= set(ids) and d["ledger"]["kind"] == "user",
          "doctor --json on Linux: %s" % " ".join(ids))
    sec = os.path.join(TMP, "alert.secret")
    with open(sec, "w") as f:
        f.write("NTFY_URL=x\n")
    os.chmod(sec, 0o644)
    os.symlink(sec, sec + ".link")
    r = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys, json; sys.path.insert(0, sys.argv[1]); import oomph; "
                        "print(json.dumps([oomph._secret_bad(p) for p in sys.argv[2:]]))", DAEMON, sec, sec + ".link",
                        sec + ".missing"], capture_output=True, text=True, timeout=60, env=env())
    sb = json.loads(r.stdout or "[]")
    check(len(sb) == 3 and ("uid" in (sb[0] or "") or "others" in (sb[0] or "")) and "regular" in (sb[1] or "") and sb[2] is None,
          "doctor names an alert.secret that is not root's alone (another owner, a link): %s" % sb)
    rc, out, _ = fx_cli("ubuntu-server-idle", "reservations")
    check(rc == 0 and "left to grant" in out and "ledger:" in out and "yours only" in out,
          "reservations: \"available − reserved − margin = left to grant\", and whose ledger")
    rc, out, _ = fx_cli("vm-32g-noswap", "reserve", "8G", "--for", "too big", "--json")
    st = json.loads(out) if out.strip() else {}
    check(rc == 75 and st.get("status") == "refused" and "Ask for at most 6.8 GB" in st.get("advice", ""),
          "alone, but beyond what RAM and swap hold less the lower bound: refused with the arithmetic, exit 75 (%s)"
          % st.get("advice", "")[:150])
    rc, out, _ = fx_cli("container-2g", "reserve", "1.9G", "--for", "beyond the limit", "--json")
    st = json.loads(out) if out.strip() else {}
    check(rc == 75 and "in a cgroup limited to 2 GB" in st.get("advice", ""), "beyond 90 %% of a container's limit: "
          "refused, in the container's words (%s)" % st.get("advice", "")[:100])
    rc, out, _ = fx_cli("container-2g", "reserve", "1.5G", "--for", "too big here", "--json")
    st = json.loads(out) if out.strip() else {}
    nums = [float(x) for x in re.findall(r"([\d.]+) GB must stay free", st.get("advice", ""))]
    check(rc == 75 and st.get("status") == "refused" and "no swap" in st.get("advice", "") and nums and nums[0] < 2.0
          and not MAC_WORDS.search(st.get("advice", "")),
          "in a 2 GB container without swap: refused with the container's figures (%s)" % st.get("advice", "")[:160])
    fx_cli("container-2g", "release", "all")
    rc, out, _ = fx_cli("vm-32g-noswap", "reserve", "6.8G", "--for", "just fits", "--json")
    st = json.loads(out) if out.strip() else {}
    check(rc == 0 and st.get("status") == "granted", "the largest request that fits alone (6.8 GB) is granted")
    fx_cli("vm-32g-noswap", "release", "all")
    rc, out, _ = fx_cli("ubuntu-server-idle", "reserve", "13G", "--for", "lone", "--json")
    st = json.loads(out) if out.strip() else {}
    check(rc == 0 and st.get("status") == "granted" and "keeps free" in (st.get("note") or ""),
          "a lone request above what is left to grant but within RAM and swap: granted with a note")
    fx_cli("ubuntu-server-idle", "release", "all")
    led = json.load(open(os.path.join(TMP, "fxl", "ubuntu-server-idle", "ledger.json")))
    check(led.get("boot") == "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0" and led["leases"] == [],
          "the ledger records the boot it was written in")
    # a ledger from before the last boot: its leases end at the boot
    led["boot"] = "11111111-2222-3333-4444-555555555555"
    led["leases"] = [{"id": "r90", "state": "granted", "gb": 1.0, "purpose": "before the reboot", "requested": time.time() - 900,
                      "granted": time.time() - 900, "seen": time.time() - 900, "holder": {"pid": 1600, "start": 2600,
                                                                                          "kind": "session"}}]
    json.dump(led, open(os.path.join(TMP, "fxl", "ubuntu-server-idle", "ledger.json"), "w"))
    rc, out, _ = fx_cli("ubuntu-server-idle", "reservations", "--json")
    c = json.loads(out) if out.strip() else {}
    check(rc == 0 and not c.get("mine") and not c.get("others") and any(
        h["id"] == "r90" and h["outcome"] == "holder_gone" for h in c.get("history", [])),
          "a lease of an earlier boot ends as holder_gone, though its holder's pid lives again")
    # the per-user ledger at its default path: used only while it is this user's own, mode 700
    pu = dict(OOMPH_LEDGER_DIR=None, OOMPH_STATE_DIR=os.path.join(TMP, "state-pu"))
    rc, out, _ = fx_cli("ubuntu-server-idle", "reservations", "--json", **pu)
    dflt = ((json.loads(out) if out.strip() else {}).get("ledger") or {}).get("path") or ""
    made = dflt.startswith(TMP + "/")
    if made:
        os.makedirs(dflt, 0o755, exist_ok=True)    # (reading the reservations made it already, 0700)
        os.chmod(dflt, 0o755)
    rc1, out1, err1 = fx_cli("ubuntu-server-idle", "reserve", "1G", "--for", "loose folder", "--json", **pu)
    if made:
        os.chmod(dflt, 0o700)
    rc2, out2, _ = fx_cli("ubuntu-server-idle", "reserve", "1G", "--for", "own folder", "--json", **pu)
    fx_cli("ubuntu-server-idle", "release", "all", **pu)
    wrote = "loose folder" in (open(os.path.join(dflt, "ledger.json")).read()
                               if os.path.exists(os.path.join(dflt, "ledger.json")) else "")
    check(made and rc1 == 1 and "mode 700" in err1 and not wrote and rc2 == 0,
          "a per-user ledger folder others can reach (0755) is refused, nothing written; at 0700 it is used (%s %s)"
          % (dflt[len(TMP):], (err1 or out1).strip()[-160:]))


    # the hook's state: a folder of this user's own, never the shared /tmp itself; a planted or
    # future-dated state is ignored (it would silence the warnings)
    saved = {k: os.environ.pop(k, None) for k in ("XDG_RUNTIME_DIR", "TMPDIR")}
    os.environ["TMPDIR"] = os.path.join(TMP, "hooktmp")
    os.makedirs(os.environ["TMPDIR"], 0o777)
    try:
        d = oomph._hook_dir()
        p = os.path.join(d or TMP, "oomph-hook-1.json")
        with open(p, "w") as f:
            json.dump({"level": "tight", "t": 1e12}, f)
        future = oomph._hook_load(p)
        oomph._hook_save(p, "tight")
        own = oomph._hook_load(p).get("level")
        os.chmod(d, 0o755)
        loose = oomph._hook_dir()
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    check(d == os.path.join(TMP, "hooktmp", "oomph-%d" % os.getuid()) and future == {} and own == "tight" and loose is None,
          "the hook's state: in oomph-<uid> (0700) in $TMPDIR, a state from the future ignored, a folder others "
          "can read refused")


# ======================================================================= logger
# The Linux logger (1.13.0, step L2), on recorded machines: runs on any system.
AS_LINUX_DAEMON = r"""
import json, os, sys, time
sys.platform = "linux"
sys.path[:0] = [sys.argv[1], sys.argv[2]]
import oomphd, oomph, linuxfixture
P = oomph.plat()
d = oomphd.Daemon()
d.kills = P.KillWatcher(oomphd.STATE_DIR, trigger=d.trigger, storm=d.cgroup_storm, event=d.event)
d.kills.fresh = False
s1 = d.sample(); d.evaluate(s1)
lines = linuxfixture.journal_lines(time.time() - 5)
os.makedirs(oomphd.STATE_DIR, exist_ok=True)
for i in (9, 10, 11, 14):             # an OOM report with its machine-wide kill, then a hostile name
    d.kills.feed(lines[i])
s2 = d.sample(); d.evaluate(s2)
d.cgroup_storm("docker:a3f9c1a7 (nginx)", 6, "/system.slice/docker-x.scope")
s3 = d.sample(); d.evaluate(s3)
inc = dict(d.incident)
d.resource_events(s3, time.time(), [{"id": "data", "watch": True, "free_gb": 1.4, "level": "critical", "low_gb": 2.0,
                                     "crit_gb": 1.0, "mount": "/", "name": "/"}], False)
d.close_incident(time.time())
qt = time.mktime(time.strptime(d.quiet["id"], "%Y%m%d-%H%M%S"))
d.open_incident(qt, [{"kind": "oom", "desc": "OOM killer killed x (1 GB)", "t": qt}])
twin = d.incident["id"]
d.incident = None
T = time.time() + 7200                # a long incident the hooks heard of, rolled over: its next part closes it
d.last_notify = 0
d.open_incident(T, [{"kind": "oom", "desc": "OOM killer killed y (2 GB)", "t": T}])
first = d.incident["id"]
d.rolled = (first, T + 10, 5, T, d.incident if d.incident.get("alerted") else None)
d.close_incident(T + 10, rolled=True)
d.open_incident(T + 12, [{"kind": "pressure", "desc": "pressure critical", "t": T + 12}])
second = d.incident["id"]
d.close_incident(T + 20)
print(json.dumps({"s2": {k: s2.get(k) for k in ("jetsam_kills", "cgroup_kills", "killed", "incident", "cpu", "io", "gpu",
                                                "disks")},
                  "incident": inc, "quiet": d.quiet, "measures": d.machine.get("measures"), "twin": twin,
                  "rolled": [first, second],
                  "quiet_kept": json.load(open(os.path.join(oomphd.LOG_DIR, "incidents", d.quiet["id"], "incident.json"))).get("quiet")}))
"""


# root (euid 0, no SUDO_UID) on a Linux machine whose machine ledger exists: the ledger call runs as nobody
AS_ROOT_SHARED = r"""
import json, os, sys
sys.platform = "linux"
sys.path.insert(0, sys.argv[1])
import oomph
oomph.PATHS_HERE["shared_ledger"] = sys.argv[2]
out = {"default": oomph._ledger_default()}
os.geteuid = lambda: 0
oomph.LEDGER_DIR = out["default"]
calls = []
oomph._drop_to = lambda u, g: {}
oomph.run_bounded = lambda cmd, data, cap, timeout, **kw: (calls.append(oomph._child_user()[0]), (0, b'{"ok": 1}', ""))[1]
res = oomph._call_as_user("ledger_snapshot", [], {}, False)
out["shared"] = [calls[-1] if calls else None, res]
oomph.LEDGER_DIR = oomph._path("ledger")
try:
    oomph._call_as_user("ledger_snapshot", [], {}, False)
except oomph.LedgerError as e:
    out["own"] = str(e)
print(json.dumps(out))
"""


def part_logger():
    """The Linux logger on recorded machines (1.13.0, roadmap 03 §5.5, §5.6, §5.13, §11.2, Appendix C.3):
    the kill watcher on lines the fact spike captured (a group kill counts its victim once, the class from
    the line's prefix, earlyoom once, a hostile name cleaned, the cursor of a handled line, the lost-record
    check, the counter without a journal, a first start that does not count the past, resuming after a
    restart), the journal child, syslog.txt's OOM excerpt, CPU, disks, I/O and NVIDIA cards (recorded from
    a real machine with two RTX 4090) through the logger's Meter, then the logger itself: a kill opens an
    incident headlined by it, the sample and events.jsonl name the victim, an alert record runs a hook with
    safe variables once, storms of containers make one quiet incident, `incidents` hides it, `serve --stdio`
    answers for the machine, and the units carry their hardening."""
    import oomph_linux
    L = backend("epyc-nvidia")
    root = os.environ["OOMPH_SYSROOT"]
    lines = linuxfixture.journal_lines(time.time() - 30)

    # --- the kill watcher, line by line
    st = os.path.join(TMP, "kw-state")
    os.makedirs(st)
    trig, storms = [], []
    w = L.KillWatcher(st, trigger=lambda k, m: trig.append((k, m)), storm=lambda *a: storms.append(a))
    w.fresh, w.mode = False, "journal"      # (as with a journal it reads: the lines are fed here instead)
    for line in lines[:9]:
        w.feed(line)
    r = w.flush(1, L.collect_procs())
    check(r["cgroup"] == 3 and r["kills"] == 0 and r["ooms"] == 1 and sorted(v["pid"] for v in r["victims"]) == [2888, 2893, 2894],
          "a group kill (C.3 row 9: four kill lines for three processes): three victims at a cgroup's limit, one OOM, "
          "nothing machine-wide (%s)" % {k: r[k] for k in ("kills", "cgroup", "ooms")})
    check(not trig, "kills at a cgroup's own limit open no incident")
    for line in lines[9:14]:
        w.feed(line)
    r = w.flush(1)
    by = r["by"]
    check(by == {"kernel": 1, "earlyoom": 1} and r["kills"] == 2 and [k for k, _ in trig] == ["oom", "oomd"],
          "a machine-wide kill and earlyoom's SIGTERM with its escalation: two victims, each counted once (%s)" % by)
    head = [m for _, m in trig]
    check(head[0] == "OOM killer killed python3 (1.7 GB)" and all(len(x) <= 44 for x in head) and
          head[1] == "earlyoom killed python3 (1.6 GB)", "headlines of at most 44 characters: %s" % head)
    w.feed(lines[14])
    w.feed(lines[14])
    r = w.flush(1)
    v = r["victims"][0] if r["victims"] else {}
    check(len(r["victims"]) == 1 and "\x1b" not in v.get("name", "") and v.get("name", "").isprintable() and
          len(trig[-1][1]) <= 44 and v.get("mb") == 2000,
          "a hostile name (escape sequences, parentheses) is cleaned, its repeated line not counted again: %r" % v.get("name"))
    w.feed(lines[15])
    r = w.flush(1)
    check(r["cgroup"] == 1 and r["victims"][0]["constraint"] == "memcg",
          "a kill line whose report header was rate-limited away: classed by its own prefix (a cgroup's limit)")
    last = json.loads(lines[15])["__CURSOR"]
    saved = json.load(open(os.path.join(st, "state.json")))
    check(w.cursor == last and saved["cursor"] == last and saved["boot"] == L.boot_id(),
          "the stored cursor is the last entry the watcher read with its own filter (C.3 row 13)")
    # the lost-record check against the kernel's counter (/proc/vmstat oom_kill)
    vm = os.path.join(root, "proc", "vmstat")
    base = saved["oom_kill"]
    with open(vm, "w") as f:
        f.write("pswpin 0\npswpout 0\noom_kill %d\n" % (base + 2))
    r1 = w.flush(1)
    r1b = w.flush(1)                        # a sample later: journald may only be slow
    w.pending = (w.pending[0], w.pending[1] - w.LOST_S)
    r2 = w.flush(2)
    check("unknown" not in r1["by"] and "unknown" not in r1b["by"] and r2["by"].get("unknown") == 2 and r2["kills"] == 2,
          "two kills the journal did not show: noted once missing for 30 s, as machine-wide at warning (%s, %s)"
          % (r1["by"], r2["by"]))
    # a kill whose line comes late (journald behind under pressure): counted once, by name, never also as unknown
    base2 = w.base + w.acc
    with open(vm, "w") as f:
        f.write("pswpin 0\npswpout 0\noom_kill %d\n" % (base2 + 1))
    late = [x for x in linuxfixture.journal_lines(time.time() - 3) if '"Out of memory: Killed process' in x
            or "Out of memory: Killed process" in json.loads(x).get("MESSAGE", "")][:1]
    r1 = w.flush(1)
    w.seen.clear()                          # (the same line was read before: here it is a new kill)
    for line in late:
        w.feed(line)
    r2 = w.flush(1)
    if w.pending:
        w.pending = (w.pending[0], w.pending[1] - w.LOST_S)
    r3 = w.flush(1)
    check(late and "unknown" not in r1["by"] and r2["by"].get("kernel") == 1 and "unknown" not in r2["by"] and
          "unknown" not in r3["by"], "a kill line that arrives a sample after the counter moved: one named victim, no "
                                      "unknown one (%s, %s, %s)" % (r1["by"], r2["by"], r3["by"]))
    for i in range(300):                    # old-style "Kill process" lines that never get their "Killed" line
        w.handle("Out of memory: Kill process %d (x) score 900 or sacrifice child" % (90000 + i), "", time.time() + i * 2)
    check(len(w.old) <= 2, "a kernel's \"Kill process\" line without its \"Killed process\" line is not kept (%d kept)"
          % len(w.old))
    w.old.clear()
    with open(vm, "w") as f:
        f.write("pswpin 0\npswpout 0\noom_kill %d\n" % (w.base + w.acc))
    w.flush(1)
    base = w.base + w.acc - 2
    with open(vm, "w") as f:
        f.write("pswpin 0\npswpout 0\noom_kill %d\n" % (base + 6))
    for line in linuxfixture.journal_lines(time.time() - 20)[3:9]:  # the group kill again: 4 lines, counter +4
        w.feed(line.replace('"i=36', '"i=46'))
    r1, r2 = w.flush(1), w.flush(1)
    check("unknown" not in r1["by"] and "unknown" not in r2["by"],
          "a group kill's repeated line is in the kernel's count too: no phantom unknown kill (C.3 row 9)")
    # a restart: the cursor and the counter go on where they were
    w2 = L.KillWatcher(st)
    check(w2.cursor == w.cursor and not w2.fresh and w2.base == base + 6 and "--after-cursor=" + w.cursor in w2.command(),
          "after a restart the watcher resumes after the stored cursor, from the stored counter")
    # a first start reads this boot from its beginning and counts nothing that happened before it
    st3 = os.path.join(TMP, "kw-first")
    os.makedirs(st3)
    w3 = L.KillWatcher(st3)
    w3.mode = "journal"
    first = w3.command()
    for line in linuxfixture.journal_lines(time.time() - 3600):
        w3.feed(line)
    r = w3.flush(1)
    check(w3.fresh and "-b" in first and "--no-tail" in first and not r["victims"] and w3.cursor and
          "--after-cursor=" + w3.cursor in w3.command(),
          "the first start ever: this boot's journal from its start (-b), its past not counted, the cursor kept")
    # a wall clock stepped back after the first start (NTP correcting an RTC ahead, at boot): a kill after the start
    # still counts, told by its monotonic time of this boot; one from before the start does not
    ws = []
    for k, dm in (("after", 1.0), ("before", -3600.0)):
        sk = os.path.join(TMP, "kw-step-" + k)
        os.makedirs(sk)
        wk = L.KillWatcher(sk)
        wk.mode, wk.boot = "journal", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0"
        for line in linuxfixture.journal_lines(time.time() - 3600, mono=wk.started_m + dm):
            wk.feed(line)
        ws.append((wk.fresh, len(wk.flush(1)["victims"])))
    check(not ws[0][0] and ws[0][1] > 0 and ws[1][0] and ws[1][1] == 0,
          "the first start with the wall clock stepped back an hour: kills after the start are named (by the journal's "
          "monotonic time), those before it are not (%s)" % ws)
    # without a journal: the counter, classed by the level
    os.rename(os.path.join(root, "run", "systemd"), os.path.join(root, "run", "systemd-off"))
    try:
        w4 = L.KillWatcher(None)
        with open(vm, "w") as f:
            f.write("pswpin 0\npswpout 0\noom_kill %d\n" % (base + 9))
        r = w4.flush(1)
    finally:
        os.rename(os.path.join(root, "run", "systemd-off"), os.path.join(root, "run", "systemd"))
    check(w4.mode == "count" and r["cgroup"] == 3 and r["kills"] == 0 and r["by"] == {"unknown": 3},
          "no journal (no systemd, or not in its group): kills counted from the kernel's counter, at a cgroup's limit "
          "while the level is normal")

    # --- the journal child: what it is run with, and where it resumes
    fake = os.path.join(root, "usr", "bin", "journalctl")
    jl = os.path.join(TMP, "journal.jsonl")
    with open(jl, "w") as f:
        f.write("\n".join(lines[8:12]) + "\n")
    with open(fake, "w") as f:
        f.write("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> '%s.argv'\nc=$(printf '%%s\\n' \"$@\" | sed -n 's/^--after-cursor=//p')\n"
                "if [ -n \"$c\" ]; then awk -v c=\"$c\" 'f; index($0, c) {f=1}' '%s'; else cat '%s'; fi\n" % (jl, jl, jl))
    os.chmod(fake, 0o755)
    st5 = os.path.join(TMP, "kw-child")
    os.makedirs(st5)
    with open(os.path.join(st5, "state.json"), "w") as f:
        json.dump({"boot": L.boot_id(), "cursor": json.loads(lines[8])["__CURSOR"], "oom_kill": base + 9}, f)
    t5 = []
    w5 = L.KillWatcher(st5, trigger=lambda k, m: t5.append(k))
    w5.RETRY_S = 0.2
    w5.start()
    deadline = time.time() + 20
    while time.time() < deadline and len(open(jl + ".argv").read().splitlines() if os.path.exists(jl + ".argv") else ()) < 3:
        time.sleep(0.1)
    w5.stop()
    argv = open(jl + ".argv").read().splitlines() if os.path.exists(jl + ".argv") else []
    r = w5.flush(1)
    check(w5.mode == "journal" and len(argv) >= 3 and "-f -q --no-pager -o json --after-cursor=%s" % json.loads(lines[8])["__CURSOR"]
          in argv[0] and "--after-cursor=%s" % json.loads(lines[11])["__CURSOR"] in argv[1] and
          "_TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service + _SYSTEMD_UNIT=earlyoom.service" in argv[0] and
          r["kills"] == 1 and t5 == ["oom"],
          "journalctl -f -o json with the stored cursor and the killers' filter; when it ends, again after the last line "
          "read, and nothing is counted twice (%d runs, %d kills)" % (len(argv), r["kills"]))
    os.remove(fake)

    # --- syslog.txt: the OOM evidence, nothing else of the kernel log
    ents = [json.loads(x) for x in lines]
    ents.insert(0, {"MESSAGE": "usb 1-1: new high-speed USB device number 3 using xhci_hcd", "_TRANSPORT": "kernel",
                    "__REALTIME_TIMESTAMP": ents[0]["__REALTIME_TIMESTAMP"]})
    ents.insert(10, {"MESSAGE": "EXT4-fs (sda1): mounted filesystem", "_TRANSPORT": "kernel",
                     "__REALTIME_TIMESTAMP": ents[9]["__REALTIME_TIMESTAMP"]})
    ents.append({"MESSAGE": "audit: type=1400 apparmor=DENIED operation=open", "_TRANSPORT": "kernel",
                 "__REALTIME_TIMESTAMP": ents[-1]["__REALTIME_TIMESTAMP"]})
    ex = L.oom_excerpt(ents)
    ents.insert(3, {"MESSAGE": "[   2888]     0  2888    54950    11460   167936        0           500 python3",
                    "_TRANSPORT": "kernel", "__REALTIME_TIMESTAMP": ents[2]["__REALTIME_TIMESTAMP"]})
    ex = L.oom_excerpt(ents)
    check("invoked oom-killer" in ex and "memory: usage 98304kB" in ex and "Tasks state" not in ex and "[   2888]" not in ex,
          "syslog.txt keeps a report's memory summary, not the table of every task (pids, accounts and names hidepid hides)")
    check("invoked oom-killer" in ex and ex.count("Killed process") == 7 and "usb 1-1" not in ex
          and "apparmor" not in ex and "EXT4-fs" not in ex and "earlyoom: sending SIGTERM" in ex and "\x1b" not in ex,
          "syslog.txt: each OOM report and the killers' lines, no other kernel line, no escape sequence (%d lines)"
          % ex.count("\n"))

    # --- NVIDIA cards through nvidia-smi, as recorded on a machine with two RTX 4090
    nv = linuxfixture.NVIDIA
    cards = L.parse_nvidia_gpus(open(os.path.join(nv, "query-gpu.csv")).read())
    pm = L.parse_nvidia_pmon(open(os.path.join(nv, "pmon.txt")).read())
    apps = L.parse_nvidia_apps(open(os.path.join(nv, "compute-apps.csv")).read())
    check(len(cards) == 2 and cards[0]["name"] == "NVIDIA GeForce RTX 4090" and cards[0]["total_mb"] == 24564 and
          cards[0]["used_mb"] == 396 and cards[0]["util"] == 0 and pm == {0: {48211: {"mb": 386.0}}} and
          apps == {cards[0]["uuid"]: {48211: 386.0}},
          "nvidia-smi's recorded answers: two cards, 386 MB of process 48211 on card 0, no utilisation measured")
    check(L.parse_nvidia_gpus("0, GPU-x, A, [N/A], [Not Supported], 7\nnonsense\n")[0]["util"] is None and
          L.parse_nvidia_pmon("no header\n0 1 C 5 5\n") is None,
          "nvidia-smi's [N/A] is no figure, and output without pmon's header is not read")
    check(L.gpu_cards()[0]["procs"] == {48211: {"mb": 386.0}}, "gpu_cards() on the recorded machine")

    # --- CPU, I/O, disks and the cards through the logger's Meter: two readings with work in between
    import oomphd
    importlib.reload(oomphd)
    os.environ.pop("OOMPH_SYSROOT")
    bz = os.path.join(TMP, "fx", "epyc-busy")
    linuxfixture.build(bz, "epyc-nvidia")
    linuxfixture.nvidia(bz, busy=True)
    os.environ["OOMPH_SYSROOT"] = bz
    L = importlib.reload(oomph_linux)
    m = oomphd.Meter(L)
    m.read(L.collect_procs(), 251.0, up=1000.0)
    linuxfixture._cpu(bz, busy=150)                # 150 ticks a core more in 2 s: 0.75 of each of 4 cores
    linuxfixture._w(bz, "/proc/1610/stat", linuxfixture.stat(1610, "java", 1600, 2610).replace(" 5 3 0 0 ", " 205 3 0 0 "))
    with open(os.path.join(bz, "proc", "diskstats")) as f:
        ds = f.read().replace("sda 100 0 2048000", "sda 100 0 2068480")   # +10 MB read from sda
    with open(os.path.join(bz, "proc", "diskstats"), "w") as f:
        f.write(ds)
    procs = L.collect_procs()
    out, use = m.read(procs, 251.0, up=1002.0)
    g = out.get("gpu") or [{}, {}]
    check(out["cpu"]["n"] == 4 and abs(out["cpu"]["busy"] - 3.0) < 0.05 and abs(use[1610]["cpu"] - 1.0) < 0.05,
          "cores from /proc/stat: %.2f of 4 busy; java's own time from its stat file: %.2f cores"
          % (out["cpu"].get("busy", -1), use.get(1610, {}).get("cpu", -1)))
    check(abs(out["io"]["r_mb_s"] - 5.0) < 0.01 and out["io"]["w_mb_s"] == 0,
          "I/O from /proc/diskstats: every disk once (no partition, loop or device-mapper twice): %s" % out["io"])
    check(len(g) == 2 and g[0]["util"] == 87 and g[0]["mem_gb"] == 18.0 and g[0]["mem_limit_gb"] == 24.0 and
          g[0]["src"] == "nvidia-smi" and not g[0]["unified"] and g[1]["procs"] == [{"pid": 1610, "name": "java", "mb": 2048,
                                                                                     "util": 12.0}]
          and use[1610]["gpu"] == 12.0 and _gpu_line(g[0]).startswith("busy 87 % of the time · 18.0 of 24 GB"),
          "NVIDIA per card (busy, memory used of the card's) and per process (memory, SM share, the name from "
          "the process table): %s" % _gpu_line(g[0]))
    linuxfixture.nvidia(bz, busy=True, pmon=False)
    L._nv["off_until"] = 0
    c = L.gpu_cards()
    check(c[0]["procs"] == {48211: {"mb": 386.0}}, "a driver without pmon: memory per process from the compute apps")
    pools, rows = L.disk_pools(L.mounts())
    why = {r["mount"]: (r["cls"], r["why"]) for r in rows}
    check([p["id"] for p in pools] == ["data", "vol:5e1f0c2a-9d3b-4c47-8e21-0a1b2c3d4e5f"] and pools[0]["watch"] and
          pools[1]["name"] == "scratch" and why["/media/ada/STICK"] == ("ignored", "removable media") and
          why["/srv/share"][1] == "network file system" and why["/snap/core22/1380"][0] == "ignored" and
          why["/boot/efi"][1] == "part of the system",
          "disks from mountinfo: / is the system's pool (its read-only view in a sandbox does not make it read-only), "
          "a second disk listed by its file system's UUID, a USB stick, NFS, a snap and /boot ignored")
    check(L.linux_floors(30) == (2.0, 1.0) and L.linux_floors(1800) == (20.0, 5.0),
          "the system pool's floors scale with it: a 30 GB disk is low below 2 GB, not 20")

    # --- the logger itself, on the recorded machine
    logs = os.path.join(TMP, "logger-logs")
    e = env(OOMPH_SYSROOT=bz, OOMPH_DIR=logs, OOMPH_DAEMON_DIR=os.path.join(TMP, "logger-state"),
            OOMPH_LEDGER_DIR=os.path.join(TMP, "logger-ledger"), XDG_STATE_HOME=os.path.join(TMP, "xdg"))
    p = subprocess.run([sys.executable, "-I", "-B", "-c", AS_LINUX_DAEMON, DAEMON, os.path.join(ROOT, "tools")],
                       capture_output=True, text=True, timeout=60, env=e)
    got = json.loads(p.stdout) if p.returncode == 0 and p.stdout.strip() else {}
    if not check(got, "the logger samples a recorded Linux machine%s" % ("" if got else ": " + p.stderr[-600:])):
        return
    inc, s2 = got["incident"], got["s2"]
    head = (inc.get("reasons") or [{}])[0]
    check(head.get("kind") == "oom" and head["desc"] == "OOM killer killed python3 (1.7 GB)" and inc.get("opened_by") == "oom",
          "a machine-wide kill opens an incident at once, headlined by it: %r" % head.get("desc"))
    check(s2["jetsam_kills"] == 2 and s2["cgroup_kills"] == 0 and [k.get("name") for k in s2.get("killed") or ()] ==
          ["x?]0;pwn?) (b", "python3"],
          "the sample counts the machine's kills and names the biggest (killed: %s)" % s2.get("killed"))
    ev = [json.loads(x) for x in open(os.path.join(logs, "events.jsonl"))]
    ok = [x for x in ev if x["kind"] == "oom_kill"]
    check(ok and ok[0]["kills"] == 2 and ok[0]["by"] == {"kernel": 2} and {v["name"] for v in ok[0]["victims"]} ==
          {"python3", "x?]0;pwn?) (b"} and any(x["kind"] == "notified" for x in ev),
          "events.jsonl: one oom_kill event per sample naming each victim, and the notification (a journal line)")
    check("<2>oomph: Memory incident: OOM killer killed python3" in p.stderr,
          "the incident reaches the journal at priority critical (<2> on the logger's stderr)")
    check("<2>oomph: Memory incident: OOM killer killed x (1 GB) — papertrail: oomph incident %s" % got["twin"] in p.stderr
          and not os.path.exists(os.path.join(logs, "alerts", "%s.open.json" % got["twin"])),
          "an incident opened within the notification's cool-down: no notification or hook, its journal line still")
    a, b = got["rolled"]
    cl = json.load(open(os.path.join(logs, "alerts", "%s.close.json" % b))) if os.path.exists(
        os.path.join(logs, "alerts", "%s.close.json" % b)) else {}
    check(os.path.exists(os.path.join(logs, "alerts", "%s.open.json" % a)) and cl.get("continues") == a and
          not os.path.exists(os.path.join(logs, "alerts", "%s.close.json" % a)) and
          not os.path.exists(os.path.join(logs, "alerts", "%s.open.json" % b)),
          "an incident rolled over: the hooks hear of its open, and of the close of the part that ends it (continues %s)"
          % cl.get("continues"))
    check(s2["cpu"] and s2["cpu"]["n"] == 4 and isinstance(s2.get("gpu"), list) and len(s2["gpu"]) == 2 and
          [d["id"] for d in s2.get("disks") or []][:1] == ["data"],
          "the sample carries cpu, gpu (2 cards) and disks blocks on Linux")
    ms = got["measures"]
    check(ms.get("kills") == "count" and ms.get("gpu") == "nvidia-smi" and ms.get("cpu") == "proc-stat",
          "machine.measures says how kills, CPU and the GPU are read here: %s" % {k: ms.get(k) for k in ("kills", "gpu", "cpu")})
    q = got["quiet"] or {}
    check(q.get("quiet") is True and q.get("cgroups", [{}])[0].get("name") == "docker:a3f9c1a7 (nginx)" and
          q.get("reasons", [{}])[0].get("desc") == "docker:a3f9c1a7 (nginx): 6 OOMs at its limit" and q["id"] != inc["id"],
          "a container OOMing five times in ten minutes: one quiet incident, headlined by it")
    check(got["twin"] != q["id"] and got["quiet_kept"] is True,
          "an incident that opens in the second a quiet one did takes the next second; the quiet one keeps its folder")
    al = os.path.join(logs, "alerts")
    recs = sorted(x for x in os.listdir(al) if x.endswith(".json") and x.startswith(inc["id"]))
    check(recs == ["%s.close.json" % inc["id"], "%s.open.json" % inc["id"]] and os.path.isfile(os.path.join(al, ".beat")),
          "alert records for the incident's open and close (none for the quiet one), and the beat: %s" % recs)
    hooks = os.path.join(TMP, "alert.d")
    os.mkdir(hooks, 0o755)
    got_f = os.path.join(TMP, "hook.out")
    with open(os.path.join(hooks, "50-test"), "w") as f:
        f.write("#!/bin/sh\nprintf '%%s|%%s|%%s|%%s\\n' \"$OOMPH_EVENT\" \"$OOMPH_INCIDENT\" \"$OOMPH_LEVEL\" \"$OOMPH_MESSAGE\" >> '%s'\n"
                "cat >> '%s.json'; echo >> '%s.json'\n" % (got_f, got_f, got_f))
    os.chmod(os.path.join(hooks, "50-test"), 0o755)
    for bad, mode in (("60-writable", 0o777), ("README.md", 0o755)):
        with open(os.path.join(hooks, bad), "w") as f:
            f.write("#!/bin/sh\necho ran >> '%s.bad'\n" % got_f)
        os.chmod(os.path.join(hooks, bad), mode)
    rc0, _, err0 = fx_cli("epyc-nvidia", "alert", "--run-hooks", OOMPH_DIR=logs, OOMPH_ALERT_D=hooks)
    check(rc0 == 2 and "only oomph-alert.service" in err0 and not os.path.exists(got_f),
          "oomph alert --run-hooks outside the unit (no STATE_DIRECTORY): refused, nothing replayed")
    ae = dict(OOMPH_DIR=logs, OOMPH_ALERT_D=hooks, STATE_DIRECTORY=os.path.join(TMP, "alert-state"))
    rc1, _, err1 = fx_cli("epyc-nvidia", "alert", "--run-hooks", **ae)
    rc2, _, _ = fx_cli("epyc-nvidia", "alert", "--run-hooks", **ae)
    said = open(got_f).read().splitlines() if os.path.exists(got_f) else []
    js = [json.loads(x) for x in open(got_f + ".json").read().split("\n") if x.strip()] if os.path.exists(got_f + ".json") else []
    check(rc1 == 0 and rc2 == 0 and [x.split("|")[0] for x in said if x.split("|")[1] == inc["id"]] == ["open", "close"] and
          all(re.fullmatch(r"[A-Za-z0-9 .,:;()/%+@_?|-]*", x) for x in said) and js and js[0]["incident"] == inc["id"]
          and not os.path.exists(got_f + ".bad"),
          "oomph alert --run-hooks: each record to the hook once (a second run finds nothing new), variables in the safe "
          "alphabet, the record as JSON on stdin; a hook others may write and a README never run%s"
          % ("" if said else ": " + err1[-300:]))
    rc, out, _ = fx_cli("epyc-nvidia", "alert", "--test", OOMPH_ALERT_D=hooks)
    check(rc == 0 and "50-test" in out and "60-writable" not in out, "oomph alert --test runs the hooks with a test record")
    priv = os.path.join(hooks, "70-private")
    with open(priv, "w") as f:
        f.write("#!/bin/sh\necho ran >> '%s.private'\n" % got_f)
    os.chmod(priv, 0o700)
    rc, out, _ = fx_cli("epyc-nvidia", "alert", "--test", OOMPH_ALERT_D=hooks)
    check(rc == 1 and "70-private" in out and "not run" in out and not os.path.exists(got_f + ".private"),
          "a hook only its owner may read (0700) is not run and is named: the unit's throwaway account could not run it")
    os.remove(priv)
    r = subprocess.run([sys.executable, "-I", "-B", "-c", "import sys; sys.platform = 'darwin'; sys.path.insert(0, sys.argv[1]); "
                        "import oomph; sys.exit(oomph.cmd_alert(['--test']))", DAEMON], capture_output=True, text=True,
                       timeout=60, env=env())
    check(r.returncode == 2 and "Linux only" in r.stderr, "oomph alert on a Mac: Linux only")
    ev2 = [json.loads(x) for x in open(os.path.join(logs, "events.jsonl"))]
    low = [x for x in ev2 if x["kind"] == "disk_low" and x.get("pool") == "data"]
    check(low and low[0].get("level") == "critical" and "<4>oomph: Disk space low: Only 1 GB free on /." in p.stderr,
          "Linux: the system disk below its floor gives disk_low and a journal warning, without the Mac's swap words")
    rc, out, _ = fx_cli("epyc-nvidia", "incidents", OOMPH_DIR=logs)
    rc2, out2, _ = fx_cli("epyc-nvidia", "incidents", "--all", OOMPH_DIR=logs)
    check(rc == 0 and inc["id"] in out and q["id"] not in out and "+ 1 quiet one" in out and q["id"] in out2 and
          "quiet" in out2 and "\x1b" not in out + out2,
          "oomph incidents leaves the quiet incident out and counts it; --all lists it")
    only_q = os.path.join(TMP, "logs-only-quiet")
    shutil.copytree(os.path.join(logs, "incidents", q["id"]), os.path.join(only_q, "incidents", q["id"]))
    rc, out, _ = fx_cli("epyc-nvidia", "incidents", OOMPH_DIR=only_q)
    check(rc == 0 and "no incidents recorded" in out and "+ 1 quiet one" in out and q["id"] not in out,
          "oomph incidents with only a quiet incident: none recorded, + 1 quiet one (the words CI's root job looks for): "
          "%s" % out.strip())
    rc, out, _ = fx_cli("epyc-nvidia", "report", OOMPH_DIR=logs)
    check(rc == 0 and "OOM kills: 2 of the machine" in out and not MAC_WORDS.search(out),
          "oomph report on Linux: the kills in Linux words%s" % ("" if rc == 0 else ": " + out[-200:]))
    rc, out, _ = fx_cli("epyc-nvidia", "check", OOMPH_DIR=logs)
    check("busy 87 % of the time" in out or "busy 0 % of the time" in out, "check shows the NVIDIA cards")
    hello = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1]}}) + "\n"
    r = subprocess.run([sys.executable, "-I", "-B", "-c", AS_LINUX, DAEMON, "serve", "--stdio"], input=hello,
                       capture_output=True, text=True, timeout=60, env=env(OOMPH_SYSROOT=bz, OOMPH_DIR=logs))
    mm = ((json.loads(r.stdout.splitlines()[0]) if r.stdout.strip() else {}).get("result") or {}).get("machine") or {}
    r2 = subprocess.run([sys.executable, "-I", "-B", "-c", AS_LINUX, DAEMON, "serve", "--stdio"], input=hello,
                        capture_output=True, text=True, timeout=60, env=env(OOMPH_SYSROOT=bz, OOMPH_DIR=os.path.join(TMP, "none")))
    m2 = ((json.loads(r2.stdout.splitlines()[0]) if r2.stdout.strip() else {}).get("result") or {}).get("machine") or {}
    check(mm.get("os") == "linux" and mm.get("logs") == "ok" and (mm.get("measures") or {}).get("kills") == "count" and
          m2.get("logs") == "absent" and m2.get("os") == "linux",
          "oomph serve --stdio answers for a Linux machine: os linux, logs ok (absent without a logger), what it measures")
    ask = hello + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "incidents", "params": {"after": ""}}) + "\n"
    r = subprocess.run([sys.executable, "-I", "-B", "-c", AS_LINUX, DAEMON, "serve", "--stdio"], input=ask,
                       capture_output=True, text=True, timeout=60, env=env(OOMPH_SYSROOT=bz, OOMPH_DIR=logs))
    import oomph
    import oomph_net
    import oomph_top
    res = next((x.get("result") for x in map(json.loads, r.stdout.splitlines()) if x.get("id") == 2), None) or {}
    rows = [json.loads(x) for x in oomph_net.unpack(res.get("data")) if x.strip()] if res.get("data") else []
    qrow = next((x for x in rows if x.get("id") == q["id"]), {})
    mirror = os.path.join(TMP, "mirror-log")
    for x in rows:
        os.makedirs(os.path.join(mirror, "incidents", x["id"]))
        with open(os.path.join(mirror, "incidents", x["id"], "incident.json"), "w") as f:
            json.dump(x, f)
    shown, _ = oomph_top.load_incidents(mirror, time.time())
    check(qrow.get("quiet") is True and qrow.get("open") is True and (qrow.get("cgroups") or [{}])[0].get("name") ==
          "docker:a3f9c1a7 (nginx)" and inc["id"] in [i["id"] for i in shown] and
          q["id"] not in [i["id"] for i in shown],
          "serve --stdio sends the quiet incident with its flag and cgroups; through a mirror, oomph top leaves it out "
          "(no open incident of it, no badge): %s" % [(x.get("id"), x.get("quiet"), x.get("open")) for x in rows])
    check(oomph_top.chart_event({"t": 1, "kind": "oom_kill", "kills": 0, "cgroup": 3, "top": {"nginx": 3}}).alarming is False
          and oomph_top.chart_event({"t": 1, "kind": "oom_kill", "kills": 1, "cgroup": 3}).alarming is True and
          oomph_top.chart_event({"t": 1, "kind": "oom_kill", "kills": 2}).alarming is True and
          oomph.calm_event({"kind": "incident_open", "quiet": True}) and not oomph.calm_event({"kind": "incident_open"}),
          "kills only at a container's own limit and a quiet incident are no alarm in oomph top or the report")
    xdg = os.path.join(TMP, "runtime")
    os.mkdir(xdg, 0o700)
    rc, out, err = fx_cli("epyc-nvidia", "incident", "latest", "--html", OOMPH_DIR=logs, XDG_RUNTIME_DIR=xdg, TMPDIR="/tmp",
                          DISPLAY=None, WAYLAND_DISPLAY=None)
    rp = out.strip().splitlines()[-1] if out.strip() else ""
    check(rc == 0 and rp.startswith(os.path.join(xdg, "oomph") + "/oomph-2") and os.path.isfile(rp) and
          oct(os.stat(rp).st_mode & 0o777) == "0o600" and oct(os.stat(os.path.dirname(rp)).st_mode & 0o777) == "0o700"
          and "Traceback" not in err,
          "oomph incident latest --html on Linux: exit 0, the report in $XDG_RUNTIME_DIR/oomph (0700), never /tmp, "
          "nothing opened without a desktop: %s%s" % (rp, err[-300:]))
    st_dir = os.path.join(TMP, "html-state")
    rc, out, err = fx_cli("epyc-nvidia", "html", "--last", "1h", "--open", OOMPH_DIR=logs, XDG_RUNTIME_DIR=None,
                          TMPDIR="/tmp", OOMPH_STATE_DIR=st_dir, DISPLAY=None)
    rp = out.strip().splitlines()[-1] if out.strip() else ""
    check(rc == 0 and rp.startswith(os.path.join(st_dir, "reports", "oomph-report-")) and os.path.isfile(rp) and
          "Traceback" not in err, "oomph html --open without a runtime folder: the state folder's reports/, exit 0: %s%s"
          % (rp, err[-300:]))
    # bounded reads of the logger's files: an overlong line skipped, a linked incident folder not followed
    lim = dict(oomph.LIMITS)
    try:
        oomph.LIMITS.update(log_line=1000, log_file=5000)
        big = os.path.join(TMP, "big.jsonl")
        with open(big, "w") as f:
            f.write('{"a": 1}\n' + "x" * 3000 + '\n{"b": 2}\n' + "y" * 9000 + "\n")
        got_lines = list(oomph._read_lines(big))
    finally:
        oomph.LIMITS.clear()
        oomph.LIMITS.update(lim)
    lk = os.path.join(TMP, "linked-logs")
    os.makedirs(os.path.join(lk, "incidents", "20250101-000000"))
    os.makedirs(os.path.join(TMP, "elsewhere"))
    with open(os.path.join(TMP, "elsewhere", "incident.json"), "w") as f:
        json.dump({"id": "20250102-000000", "start": 1}, f)
    with open(os.path.join(lk, "incidents", "20250101-000000", "incident.json"), "w") as f:
        json.dump({"id": "20250101-000000", "start": 1}, f)
    os.symlink(os.path.join(TMP, "elsewhere"), os.path.join(lk, "incidents", "20250102-000000"))
    saved_log, oomph.LOG_DIR = oomph.LOG_DIR, lk
    try:
        listed = [i["id"] for i in oomph.list_incidents()]
    finally:
        oomph.LOG_DIR = saved_log
    check(got_lines == ['{"a": 1}\n', '{"b": 2}\n'] and listed == ["20250101-000000"],
          "the logger's files as root reads them: a line past the limit skipped, the total unpacked bounded, an "
          "incident folder that is a link not followed (%s, %s)" % (got_lines, listed))

    # --- the alert runner stops before a hook that could outlast the unit, and goes on where it stopped
    slow = os.path.join(TMP, "alert-slow.d")
    os.mkdir(slow, 0o755)
    ran_f = os.path.join(TMP, "slow.out")
    for n in ("10-a", "20-b"):
        with open(os.path.join(slow, n), "w") as f:
            f.write("#!/bin/sh\nsleep 2\necho %s-$OOMPH_INCIDENT >> '%s'\n" % (n, ran_f))
        os.chmod(os.path.join(slow, n), 0o755)
    run_short = ("import sys; sys.platform = 'linux'; sys.path.insert(0, sys.argv[1]); import oomph; "
                 "oomph.ALERT_HOOK_S, oomph.ALERT_RUN_S = 3, 4; sys.exit(oomph.cmd_alert(['--run-hooks']))")
    se = dict(OOMPH_DIR=logs, OOMPH_ALERT_D=slow, STATE_DIRECTORY=os.path.join(TMP, "alert-slow-state"))
    r1 = subprocess.run([sys.executable, "-I", "-B", "-c", run_short, DAEMON], capture_output=True, text=True, timeout=60,
                        env=env(**se))
    first = open(ran_f).read().split() if os.path.exists(ran_f) else []
    cur1 = json.load(open(os.path.join(TMP, "alert-slow-state", "cursor.json")))
    r2 = subprocess.run([sys.executable, "-I", "-B", "-c", run_short, DAEMON], capture_output=True, text=True, timeout=60,
                        env=env(**se))
    second = open(ran_f).read().split() if os.path.exists(ran_f) else []
    check(r1.returncode == 0 and r2.returncode == 0 and first == ["10-a-" + inc["id"]] and
          (cur1.get("part") or {}).get("done") == ["10-a"] and second[:2] == ["10-a-" + inc["id"], "20-b-" + inc["id"]]
          and second.count("10-a-" + inc["id"]) == 1,
          "oomph alert --run-hooks: a hook that could pass the unit's time is not started; the next start runs the "
          "record's other hooks, not again the ones that ran (%s, then %s)" % (first, second))

    # --- the kill watcher where its journal cursor is lost: this boot read again, nothing counted twice
    fake = os.path.join(bz, "usr", "bin", "journalctl")
    jl6 = os.path.join(TMP, "journal6.jsonl")
    old_lines = linuxfixture.journal_lines(time.time() - 3600)
    with open(jl6, "w") as f:
        f.write("\n".join(old_lines[9:12]) + "\n")
    with open(fake, "w") as f:
        f.write("#!/bin/sh\nprintf '%%s\\n' \"$*\" >> '%s.argv'\ncase \"$*\" in *--after-cursor=*) exit 1 ;; esac\n"
                "cat '%s'\n" % (jl6, jl6))
    os.chmod(fake, 0o755)
    st6 = os.path.join(TMP, "kw-lost")
    os.makedirs(st6)
    with open(os.path.join(st6, "state.json"), "w") as f:
        json.dump({"boot": L.boot_id(), "cursor": json.loads(old_lines[8])["__CURSOR"], "oom_kill": 0}, f)
    t6 = []
    w6 = L.KillWatcher(st6, trigger=lambda k, m: t6.append(k))
    w6.RETRY_S = 0.2
    w6.start()
    deadline = time.time() + 20
    while time.time() < deadline and len(open(jl6 + ".argv").read().splitlines() if os.path.exists(jl6 + ".argv") else ()) < 3:
        time.sleep(0.1)
    w6.stop()
    argv6 = open(jl6 + ".argv").read().splitlines() if os.path.exists(jl6 + ".argv") else []
    r6 = w6.flush(1)
    os.remove(fake)
    check(len(argv6) >= 2 and "--after-cursor=" in argv6[0] and "-b --no-tail" in argv6[1] and w6.fresh and
          not r6["victims"] and not t6,
          "a stored cursor the journal no longer takes: this boot read again from its start, and its old kills "
          "neither counted again nor alerted (%d runs, %d victims)" % (len(argv6), len(r6["victims"])))

    # --- hidepid: another account's victim is only a size, syslog.txt is the logger's group's alone (03 §5.6)
    hp = os.path.join(TMP, "fx", "epyc-hidepid")
    linuxfixture.build(hp, "epyc-nvidia")
    mi = os.path.join(hp, "proc", "self", "mountinfo")
    with open(mi) as f:
        text = f.read().replace("- proc proc rw\n", "- proc proc rw,hidepid=invisible\n", 1)
    with open(mi, "w") as f:
        f.write(text)
    os.environ["OOMPH_SYSROOT"] = hp
    H = importlib.reload(oomph_linux)
    try:
        trig7 = []
        w7 = H.KillWatcher(None, trigger=lambda k, m: trig7.append(m))
        w7.fresh = False
        for line in linuxfixture.journal_lines(time.time() - 5)[9:12]:
            w7.feed(line)
        r7 = w7.flush(1)
        v7 = r7["victims"][0] if r7["victims"] else {}
        inc_d = os.path.join(TMP, "hp-incident")
        os.mkdir(inc_d)
        os.umask(0o022)
        H.dump_syslog(inc_d, None)
        mode = oct(os.stat(os.path.join(inc_d, "syslog.txt")).st_mode & 0o777)
    finally:
        os.environ["OOMPH_SYSROOT"] = bz
        importlib.reload(oomph_linux)
    check(w7.hide and v7.get("name") == "?" and not {"pid", "uid", "cg"} & set(v7) and v7.get("mb") == 1729 and
          r7["kills"] == 1 and trig7 == ["OOM killer killed ? (1.7 GB)"] and list(r7["top"]) == ["?"] and mode == "0o640",
          "under hidepid another account's victim is named \"?\" (no pid, account or cgroup; its size and count kept), "
          "and syslog.txt is 0640: %s, %s, %s" % (v7, trig7, mode))

    # --- root without sudo (`su -`, a root agent) on a machine with the logger: the machine's ledger, through nobody
    shared = os.path.join(TMP, "machine-ledger")
    os.mkdir(shared)
    os.chmod(shared, 0o777)
    r = subprocess.run([sys.executable, "-I", "-B", "-c", AS_ROOT_SHARED, DAEMON, shared], capture_output=True, text=True,
                       timeout=60, env=env(OOMPH_LEDGER_DIR=None, SUDO_UID=None, SUDO_USER=None, SUDO_GID=None,
                                           XDG_STATE_HOME=os.path.join(TMP, "xdg-root")))
    got = json.loads(r.stdout) if r.returncode == 0 and r.stdout.strip() else {}
    check(got.get("default") == shared and got.get("shared") == ["nobody", 1] and "used only where nobody" in
          (got.get("own") or ""), "root without sudo: the machine's ledger, once it exists, through a child as nobody; "
                                  "root's own per-user one still only in place (%s)" % (got or r.stderr[-300:]))

    # --- the units: what the design and the spike ask of them (03 Appendix A, C.3 rows 14 to 16, 28)
    svc = open(os.path.join(ROOT, "linux", "oomphd.service")).read()
    alert = open(os.path.join(ROOT, "linux", "oomph-alert.service")).read()
    need = ("\nCapabilityBoundingSet=\n", "\nAmbientCapabilities=\n", "\nNoNewPrivileges=yes", "\nPrivateNetwork=yes",
            "\nRestrictAddressFamilies=AF_UNIX\n", "\nIPAddressDeny=any", "\nProtectSystem=strict", "\nPrivateDevices=yes",
            "\nMemoryDenyWriteExecute=yes", "\nUser=oomphd", "ptrace", "\nMemoryMax=")
    check(all(x in svc for x in need) and "ExecStart=@PY@ -I -B /usr/local/libexec/oomph/oomphd.py" in svc and
          "CAP_" not in svc and "\nProtectHome=read-only" in svc and "\nStartLimitBurst=" in svc,
          "oomphd.service: no capability, no network, no devices, its three folders writable, /home read-only (a "
          "separate /home disk stays visible), a start limit")
    check("LoadCredential=alert:/etc/oomph/alert.secret" in alert and "TemporaryFileSystem=/dev/shm" in
          open(os.path.join(ROOT, "linux", "oomphd-nvidia.conf")).read(),
          "the hooks' secrets reach them as a credential; the NVIDIA drop-in shares no /dev/shm with the host")
    check(all(x in alert for x in ("\nDynamicUser=yes", "\nCapabilityBoundingSet=\n", "\nNoNewPrivileges=yes",
                                   "\nProtectSystem=strict", "\nPrivateDevices=yes", "\nProtectProc=invisible",
                                   "\nSystemCallFilter=@system-service")) and "alert --run-hooks" in alert,
          "oomph-alert.service: a throwaway account, no capability, the logger's hardening where it fits")
    analyze = shutil.which("systemd-analyze") if LINUX else None
    if analyze:
        ver = subprocess.run([analyze, "--version"], capture_output=True, text=True, timeout=30).stdout
        mv = re.search(r"systemd (\d+)", ver)
        if mv and int(mv.group(1)) >= 252:
            nvc = open(os.path.join(ROOT, "linux", "oomphd-nvidia.conf")).read()
            for name, text in (("oomphd.service", svc), ("oomph-alert.service", alert), ("oomphd.service", svc + nvc)):
                d = tempfile.mkdtemp(dir=TMP)
                f = os.path.join(d, name)
                with open(f, "w") as h:
                    h.write(text.replace("@PY@", "/usr/bin/python3"))
                r = subprocess.run([analyze, "security", "--offline=true", "--no-pager", f], capture_output=True,
                                   text=True, timeout=60)
                mx = re.search(r"Overall exposure level for \S+: ([\d.]+)", r.stdout + r.stderr)
                check(mx and float(mx.group(1)) <= 2.5, "systemd-analyze security %s%s: exposure %s (at most 2.5)"
                      % (name, " with 20-nvidia.conf" if text.endswith(nvc) else "",
                         mx.group(1) if mx else "?: " + (r.stdout + r.stderr)[-200:]))
        else:
            print("info  systemd-analyze %s: security --offline needs 252 or newer" % (mv.group(1) if mv else "?"))
    else:
        print("info  no systemd-analyze here: the units' exposure is measured on Linux with systemd 252 or newer")


def _gpu_line(g):
    import oomph
    return oomph._gpu_text(g)


def part_system():
    """linux/install.sh --system into a folder (OOMPH_INSTALL_ROOT: the files only, no account, no systemd), and
    linux/uninstall.sh --system --purge: the code side by side, the units with this Python, the folders with
    their modes (the ledger every account's, without the sticky bit), the NVIDIA drop-in where nvidia-smi is,
    --no-journal; nothing left after the purge. The real install, as root with systemd, is CI's."""
    if not LINUX:
        skip("linux/install.sh --system: needs Linux")
        return
    pfx = os.path.join(TMP, "sysroot")
    os.makedirs(os.path.join(pfx, "usr", "bin"))
    smi = os.path.join(pfx, "usr", "bin", "nvidia-smi")
    with open(smi, "w") as f:
        f.write("#!/bin/sh\n")
    os.chmod(smi, 0o755)
    e = env(OOMPH_INSTALL_ROOT=pfx)
    r = subprocess.run([os.path.join(ROOT, "linux", "install.sh"), "--system"], capture_output=True, text=True,
                       timeout=120, env=e)
    unit = os.path.join(pfx, "etc", "systemd", "system", "oomphd.service")
    u = open(unit).read() if os.path.exists(unit) else ""
    lib = os.path.join(pfx, "usr", "local", "libexec", "oomph")
    led = os.path.join(pfx, "var", "lib", "oomph", "ledger")
    mode = lambda p: oct(os.stat(p).st_mode & 0o7777) if os.path.exists(p) else None  # noqa: E731
    check(r.returncode == 0 and os.path.islink(lib) and os.path.isfile(os.path.join(lib, "oomphd.py")) and
          os.path.realpath(os.path.join(pfx, "usr", "local", "bin", "oomph")) == os.path.realpath(os.path.join(lib, "oomph.py"))
          and re.search(r"(?m)^ExecStart=/\S*python3\S* -I -B /usr/local/libexec/oomph/oomphd.py$", u)
          and "@PY@" not in u and "SupplementaryGroups=systemd-journal" in u and
          mode(led) == "0o777" and mode(os.path.join(pfx, "var", "lib", "oomph", "daemon")) == "0o700" and
          mode(os.path.join(pfx, "var", "log", "oomph")) == "0o755" and
          os.path.isfile(os.path.join(pfx, "etc", "systemd", "system", "oomphd.service.d", "20-nvidia.conf")) and
          os.path.isfile(os.path.join(pfx, "etc", "systemd", "system", "oomph-alert.path")) and
          os.path.isfile(os.path.join(lib, "alert.d.examples", "10-ntfy")) and
          not os.path.exists(os.path.join(pfx, "var", "log", "oomph", "alerts")) and
          mode(os.path.join(pfx, "etc", "oomph", "alert.secret")) == "0o600",
          "linux/install.sh --system (into a folder): code, command, units with this Python, folders and modes, the NVIDIA "
          "drop-in%s" % ("" if r.returncode == 0 else ": " + (r.stdout + r.stderr)[-300:]))
    os.remove(smi)
    r = subprocess.run([os.path.join(ROOT, "linux", "install.sh"), "--system", "--no-journal"], capture_output=True,
                       text=True, timeout=120, env=e)
    u = open(unit).read() if os.path.exists(unit) else ""
    check(r.returncode == 0 and "\nSupplementaryGroups=" not in u and
          not os.path.exists(os.path.join(pfx, "etc", "systemd", "system", "oomphd.service.d")),
          "--no-journal leaves the journal group out; without nvidia-smi the drop-in goes")
    r = subprocess.run([os.path.join(ROOT, "linux", "install.sh"), "--no-journal"], capture_output=True, text=True,
                       timeout=60, env=e)
    check(r.returncode == 2, "--no-journal without --system is a usage error")
    r = subprocess.run([os.path.join(ROOT, "linux", "uninstall.sh"), "--system", "--purge"], capture_output=True,
                       text=True, timeout=60, env=e)
    left = [os.path.join(dp, f) for dp, dn, fn in os.walk(pfx) for f in fn + dn]
    check(r.returncode == 0 and not left or set(left) <= {os.path.join(pfx, x) for x in (
        "usr", "usr/bin", "usr/local", "usr/local/bin", "usr/local/libexec", "etc", "etc/systemd", "etc/systemd/system",
        "var", "var/lib", "var/log")}, "linux/uninstall.sh --system --purge leaves nothing of oomph%s"
          % ("" if r.returncode == 0 else ": " + r.stderr[-200:]))


# ======================================================================= live
def part_live():
    rc, out, err = cli("check", "--json")
    v = json.loads(out) if out.strip() else {}
    check(rc == v.get("exit_code") and rc in (0, 1, 2), "check --json: exit %s = its exit_code (%s)" % (rc, v.get("level")))
    rc2, out2, _ = cli("check")
    check(rc2 == rc and out2.startswith("oomph: "), "check: the same exit code as --json")
    for args in (("reserve",), ("reserve", "1G", "--bogus"), ("reserve", "lots"), ("run",), ("run", "--reserve", "1G"),
                 ("amend", "r1"), ("release",)):
        r = cli(*args)
        check(r[0] == 2, "usage error: oomph %s → exit %d" % (" ".join(args), r[0]))
    if v.get("level") != "ok":
        skip("the ledger part: memory here is %s, so requests would queue (needs ok)" % v.get("level"))
        return
    G = (v.get("coordination") or {}).get("grantable_gb") or (v.get("coordination") or {}).get("available_gb") or 0
    holders = [subprocess.Popen(["sleep", "300"]) for _ in range(2)]
    try:
        rc, out, _ = cli("reserve", "0.05G", "--for", "tiny", "--json")
        st = json.loads(out)
        check(rc == 0 and st["status"] == "granted", "reserve a little: granted, exit 0")
        rc, out, _ = cli("amend", st["id"], "--gb", "0.03G")
        check(rc == 0, "amend (shrink): exit 0")
        rc, out, _ = cli("amend", "r9999", "--gb", "0.03G")
        check(rc == 75, "amend an unknown reservation: exit 75")
        rc, out, _ = cli("release", st["id"])
        check(rc == 0 and "released" in out, "release: exit 0")
        rc, out, _ = cli("release", st["id"])
        check(rc == 1, "release it again: nothing to release, exit 1")
        if G < 0.5:
            skip("taking turns: only %.1f GB left to grant here" % G)
            return
        a = "%.2fG" % (0.6 * G)
        rc, out, _ = cli("reserve", a, "--for", "session A", "--pid", str(holders[0].pid), "--json")
        A = json.loads(out)
        rc2, out2, _ = cli("reserve", a, "--for", "session B", "--pid", str(holders[1].pid), "--json")
        B = json.loads(out2)
        check(rc == 0 and A["status"] == "granted" and rc2 == 75 and B["status"] == "queued" and
              [x["id"] for x in B.get("ahead", [])] == [A["id"]],
              "two sessions: A (%s) granted, exit 0; B queued behind A, exit 75" % a)
        rc, out, _ = cli("run", "--reserve", a, "--wait", "1s", "--", "true")
        check(rc == 75 and "not started" in _, "oomph run that is never granted within --wait: nothing runs, exit 75")
        rc, out, _ = cli("release", A["id"])
        check(rc == 0 and B["id"] in out, "A releases: exit 0, and B is granted (%s)" % out.strip().splitlines()[-1][:60])
        rc, out, _ = cli("reserve", a, "--ticket", B["id"], "--pid", str(holders[1].pid), "--json")
        check(rc == 0 and json.loads(out)["status"] == "granted", "B polls with its ticket: granted, exit 0")
        cli("release", B["id"])
        # two `oomph run` in a row: the second waits for the first and runs after it
        t0 = time.time()
        first = subprocess.Popen([sys.executable, "-I", "-B", OOMPH, "run", "--reserve", a, "--for", "run 1", "--",
                                  "sleep", "3"], env=env(), stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        for _ in range(100):
            if json.loads(cli("reservations", "--json")[1]).get("others"):
                break
            time.sleep(0.1)
        rc, out, err = cli("run", "--reserve", a, "--for", "run 2", "--wait", "60s", "--", "sh", "-c", "exit 3", timeout=90)
        t2 = time.time() - t0
        first.wait(60)
        check(first.returncode == 0 and rc == 3 and t2 >= 2.5 and "waiting for" in err,
              "two oomph run in a row: the second waits (%.1f s) and then runs; its exit code is the command's (3)" % t2)
        rc, _, _ = cli("run", "--reserve", "0.05G", "--", "/nonexistent/command")
        check(rc == 127, "oomph run of a command that does not exist: exit 127")
    finally:
        for h in holders:
            h.kill()
            h.wait()
    rc, out, err = cli("hook", stdin="{}")
    check(rc == 0 and not err, "hook while memory is ok: silent, exit 0")
    rc, out, _ = cli("wait", "--timeout", "2s")
    check(rc == 0, "wait while memory is ok: exit 0")
    rc, out, _ = cli("doctor", "--json")
    d = json.loads(out) if out.strip() else {}
    check(rc == d.get("exit") and rc in (0, 1), "doctor: exit %s (%s)" % (rc, ", ".join(
        "%s %s" % (x["level"], x["id"]) for x in d.get("checks", []) if x["level"] != "ok")))
    rc, out, _ = cli("session", "--pid", str(os.getpid()))
    check(rc in (0, 1), "session: exit %d" % rc)
    rc, out, _ = cli("reservations", "--json")
    c = json.loads(out) if out.strip() else {}
    check(rc == 0 and "ledger" in c and "grantable_gb" in c and c["ledger"]["path"] == os.path.join(TMP, "ledger"),
          "reservations --json: ledger %s, grantable_gb" % c.get("ledger", {}).get("kind"))
    # the MCP server
    reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "memory_check", "arguments": {}}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "reserve_memory", "arguments": {"gb": 0.05, "purpose": "mcp test", "wait_s": 0}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "release_memory", "arguments": {"id": "all"}}}]
    rc, out, err = cli("mcp", stdin="".join(json.dumps(r) + "\n" for r in reqs), timeout=60)
    res = {m.get("id"): m for m in map(json.loads, out.splitlines())}
    tools = (res.get(2, {}).get("result") or {}).get("tools") or []
    body = lambda i: json.loads(res[i]["result"]["content"][0]["text"]) if i in res and not res[i]["result"].get("isError") else {}
    here = "this machine" if LINUX else "this Mac"
    check(rc == 0 and len(tools) >= 10 and all(here in t["description"] for t in tools if t["name"] == "memory_check") and
          body(3).get("level") in ("ok", "tight", "critical") and body(4).get("status") == "granted" and
          body(5).get("released"), "mcp: initialize, tools/list (\"%s\"), memory_check, reserve_memory, release_memory" % here)


# ======================================================================= linux
CHILD = r"""
import sys, time
sys.stdout.write("up\n"); sys.stdout.flush()
sys.stdin.readline()
b = bytearray(200 << 20)
for i in range(0, len(b), 4096):
    b[i] = 1
sys.stdout.write("ready\n"); sys.stdout.flush()
time.sleep(30)
"""


def part_linux():
    os.environ.pop("OOMPH_SYSROOT", None)
    import oomph_linux as L
    L = importlib.reload(L)
    p = subprocess.Popen([sys.executable, "-I", "-c", CHILD], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        p.stdout.readline()                      # up: measured before it allocates
        before = (L.collect_procs(only={p.pid}).get(p.pid) or {}).get("fp", 0)
        p.stdin.write("go\n")
        p.stdin.flush()
        p.stdout.readline()                      # ready: 200 MB written
        after = (L.collect_procs(only={p.pid}).get(p.pid) or {}).get("fp", 0)
    finally:
        p.kill()
        p.wait()
    grew = (after - before) / (1 << 20)
    check(180 <= grew <= 220, "a child that writes 200 MB raises its footprint (RssAnon + VmSwap) by %.0f MB" % grew)
    s = L.system_memory()
    ident = round(s["wired_gb"] + s["app_gb"] + s["compressed_gb"] + s["cached_gb"] + s["free_gb"], 1)
    check(abs(ident - s["ram_gb"]) <= 0.2 or s.get("scope"), "this machine: %.1f GB, available %.1f, level %s, psi %s, "
          "scope %s; the classes add up (%.1f)" % (s["ram_gb"], s["linux"]["avail_gb"], s["pressure"], "psi" in s,
                                                    (s.get("scope") or {}).get("kind", "host"), ident))
    t0 = time.time()
    n = len(L.collect_procs())
    scan = (time.time() - t0) * 1000
    t0 = time.time()
    rc, _, _ = cli("hook", stdin="{}")
    hook = (time.time() - t0) * 1000
    print("info  a full scan of %d processes: %.0f ms; a hook call, Python's start included: %.0f ms" % (n, scan, hook))
    try:
        lim = int(open("/sys/fs/cgroup/memory.max").read().strip())
    except (OSError, ValueError):
        lim = None
    if lim:
        rc, out, _ = cli("check", "--json")
        v = json.loads(out)
        check(v.get("scope", {}).get("kind") == "cgroup" and abs(v["ram_gb"] - lim / (1 << 30)) < 0.05,
              "in a container limited to %.1f GB: check speaks about the container (%s)" % (
                  lim / (1 << 30), out.strip()[:0] or (v.get("scope") or {})))
    else:
        print("info  not in a limited container: the cgroup-scope check runs in the CI's 2 GB container")
    rc, out, err = cli("top", "--once", "--size", "80x24", "--glyphs", "ascii", timeout=120)
    check(rc == 0 and len(out.split("\n")[:-1]) == 24, "oomph top --once on Linux: one 80x24 frame from the live source%s"
          % ("" if rc == 0 else ": " + err[-300:]))
    home = os.path.join(TMP, "home")
    os.makedirs(home)
    rc, out, _ = cli("setup-claude", HOME=home)
    skill = os.path.join(home, ".claude", "skills", "oomph", "SKILL.md")
    check(rc == 0 and os.path.isfile(skill) and "claude mcp add" in out, "setup-claude without claude on the PATH: the "
          "skill is installed, and the line to register the MCP server is printed")
    rc, out, _ = cli("setup-claude", "--remove", HOME=home)
    check(rc == 0 and not os.path.exists(skill), "setup-claude --remove")
    # linux/install.sh into a scratch home: no root, ~/.local, the skill; uninstall leaves nothing
    home2 = os.path.join(TMP, "home2")
    os.makedirs(home2)
    e = env(HOME=home2)
    e.pop("OOMPH_LEDGER_DIR")
    r = subprocess.run([os.path.join(ROOT, "linux", "install.sh")], capture_output=True, text=True, timeout=120, env=e)
    exe = os.path.join(home2, ".local", "bin", "oomph")
    ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30, env=e).stdout.strip() \
        if os.path.exists(exe) else ""
    chk = subprocess.run([exe, "check"], capture_output=True, text=True, timeout=60, env=e) if ver else None
    check(r.returncode == 0 and ver and ver != "dev" and chk and chk.returncode in (0, 1, 2) and
          os.path.isfile(os.path.join(home2, ".claude", "skills", "oomph", "SKILL.md")) is False,
          "linux/install.sh: ~/.local/bin/oomph %s runs (check exit %s); the skill waits for Claude Code%s"
          % (ver, chk and chk.returncode, "" if r.returncode == 0 else ": " + (r.stdout + r.stderr)[-300:]))
    r2 = subprocess.run([os.path.join(ROOT, "linux", "install.sh")], capture_output=True, text=True, timeout=120, env=e)
    check(r2.returncode == 0 and os.path.realpath(exe).startswith(os.path.join(home2, ".local", "lib")),
          "linux/install.sh again: still one link into ~/.local/lib")
    r = subprocess.run([os.path.join(ROOT, "linux", "uninstall.sh")], capture_output=True, text=True, timeout=60, env=e)
    left = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.join(home2, ".local")) for f in fn + dn
            if "oomph" in f and "/state/" not in dp + "/" and not f.startswith("state")]
    check(r.returncode == 0 and not os.path.lexists(exe) and not left,
          "linux/uninstall.sh removes the link and the code, keeps the ledger%s" % (": left %s" % left[:3] if left else ""))


# ======================================================================= root
def part_root():
    """As root on Linux without sudo (a root agent in a container; CI's 2 GB one): root's own
    per-user ledger in ~/.local/state is used in place (03 §7.5), with the Mac's exit codes;
    a shared or env-given folder still goes through a child as nobody; a ledger folder others
    could reach is refused with a reason; linux/install.sh installs into root's own ~/.local and
    refuses a sudo user's. Run only when asked for (it writes root's home)."""
    if not LINUX or os.geteuid() != 0:
        skip("the root part: needs Linux and root")
        return
    import pwd
    home = pwd.getpwuid(0).pw_dir
    e = env(HOME=home, OOMPH_LEDGER_DIR=None, OOMPH_STATE_DIR=None, SUDO_UID=None, SUDO_USER=None, SUDO_GID=None)
    run = lambda *a, stdin=None, **kw: subprocess.run([sys.executable, "-I", "-B", OOMPH] + list(a), input=stdin,
                                                      capture_output=True, text=True, timeout=60, env=dict(e, **kw))
    r = run("reserve", "0.05G", "--for", "root in a container", "--json")
    st = json.loads(r.stdout) if r.stdout.strip() else {}
    led = (json.loads(run("reservations", "--json").stdout or "{}").get("ledger") or {})
    check(r.returncode == 0 and st.get("status") == "granted" and led.get("kind") == "user" and
          led.get("path", "").startswith(os.path.join(home, ".local", "state", "oomph", "ledger") + "/"),
          "root without sudo: reserve is granted, exit 0, in root's own ledger %s%s"
          % (led.get("path"), "" if r.returncode == 0 else ": " + r.stderr[-200:]))
    path = led.get("path") or ""
    r2 = run("release", st.get("id") or "r0")
    check(r2.returncode == 0, "root: release, exit 0")
    r = run("run", "--reserve", "0.05G", "--", "true")
    check(r.returncode == 0, "root: oomph run --reserve 0.05G -- true, exit 0%s"
          % ("" if r.returncode == 0 else ": " + r.stderr[-200:]))
    r = run("run", "--reserve", "0.05G", "--", "sh", "-c", "exit 3")
    check(r.returncode == 3, "root: oomph run passes the command's exit code (3)")
    r = run("check", "--json")
    v = json.loads(r.stdout) if r.stdout.strip() else {}
    check(r.returncode == v.get("exit_code") and not (v.get("coordination") or {}).get("error"),
          "root: check --json has no coordination error")
    reqs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
             "params": {"name": "reserve_memory", "arguments": {"gb": 0.05, "purpose": "mcp as root", "wait_s": 0}}},
            {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "release_memory", "arguments": {"id": "all"}}}]
    r = run("mcp", stdin="".join(json.dumps(x) + "\n" for x in reqs))
    res = {m.get("id"): m for m in map(json.loads, r.stdout.splitlines())}
    body = (res.get(4) or {}).get("result") or {}
    check(body.get("content") and not body.get("isError") and json.loads(body["content"][0]["text"]).get("status") ==
          "granted", "root: MCP reserve_memory is granted%s" % ("" if body else ": " + r.stderr[-200:]))
    owner = [os.lstat(os.path.join(path, f)).st_uid for f in ("ledger.json",) if os.path.exists(os.path.join(path, f))]
    check(owner == [0] and os.stat(path).st_mode & 0o777 == 0o700, "root's ledger: written in place by root, folder 0700")
    # a folder others could reach: refused with the reason, nothing written
    os.chmod(path, 0o750)
    try:
        r = run("reserve", "0.05G", "--for", "group-readable", "--json")
    finally:
        os.chmod(path, 0o700)
    check(r.returncode == 1 and "nobody else can reach" in r.stderr, "root's ledger folder readable by its group: "
          "refused (exit 1), not used in place: %s" % r.stderr.strip()[-120:])
    # a shared folder (the environment names it): through a child as nobody, never in place
    shared = os.path.join(TMP, "shared")
    os.chmod(TMP, 0o755)
    os.mkdir(shared)
    os.chmod(shared, 0o777)
    r = run("reserve", "0.05G", "--for", "shared as root", "--json", OOMPH_LEDGER_DIR=shared)
    st = os.lstat(os.path.join(shared, "ledger.json")) if os.path.exists(os.path.join(shared, "ledger.json")) else None
    check(st is not None and st.st_uid == pwd.getpwnam("nobody").pw_uid,
          "a shared ledger named by OOMPH_LEDGER_DIR: root's operation ran as nobody (exit %d), not in place" % r.returncode)
    # linux/install.sh as root: into root's own ~/.local; never for a sudo user, never another HOME
    ie = dict(e, PATH="/usr/bin:/bin")
    r = subprocess.run([os.path.join(ROOT, "linux", "install.sh"), "--no-claude"], capture_output=True, text=True,
                       timeout=120, env=ie)
    exe = os.path.join(home, ".local", "bin", "oomph")
    c = subprocess.run([exe, "reserve", "0.05G", "--for", "installed", "--json"], capture_output=True, text=True,
                       timeout=60, env=ie) if r.returncode == 0 else None
    check(r.returncode == 0 and c is not None and c.returncode == 0, "linux/install.sh as root (HOME %s): installs, and "
          "the installed oomph reserves, exit %s%s" % (home, c and c.returncode, "" if r.returncode == 0 else ": " + r.stderr[-200:]))
    if os.environ.get("OOMPH_LINUXTEST_GIT") == "1":     # CI's checkout, which git must accept from root too
        ver = subprocess.run([exe, "version"], capture_output=True, text=True, timeout=30, env=ie).stdout.strip() \
            if r.returncode == 0 else ""
        check(ver and "nogit" not in ver and ver != "dev", "linux/install.sh as root stamps the checkout's version (%s)" % ver)
    if c:
        subprocess.run([exe, "release", "all"], capture_output=True, timeout=60, env=ie)
    r3 = subprocess.run([os.path.join(ROOT, "linux", "install.sh")], capture_output=True, text=True, timeout=60,
                        env=dict(ie, SUDO_UID="1000", SUDO_USER="someone"))
    r4 = subprocess.run([os.path.join(ROOT, "linux", "install.sh")], capture_output=True, text=True, timeout=60,
                        env=dict(ie, HOME=TMP))
    check(r3.returncode == 1 and "sudo" in r3.stderr and r4.returncode == 1 and "HOME" in r4.stderr,
          "linux/install.sh as root refuses a sudo user's run and a HOME other than root's")
    r = subprocess.run([os.path.join(ROOT, "linux", "uninstall.sh")], capture_output=True, text=True, timeout=60, env=ie)
    check(r.returncode == 0 and not os.path.lexists(exe), "linux/uninstall.sh as root removes it")


# ======================================================================= service (CI, as root)
KILL_ME = "x = b'x' * (400 << 20)"  # writes 400 MB: a scope limited to 64 MB is OOM-killed at once


# What a unit's process must not be able to do (03 §12.3: "the claim is checked, not asserted"): run under the
# unit's own settings by systemd-run, each attempt's outcome, "ok" or the exception's name.
SANDBOX_PROBE = r"""
import json, os, socket
r = {}
def t(name, f):
    try:
        f()
        r[name] = "ok"
    except Exception as e:
        r[name] = type(e).__name__
def w(p):
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    os.unlink(p)
t("exe", lambda: os.readlink("/proc/1/exe"))
t("mem", lambda: open("/proc/1/mem", "rb").close())
t("inet", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close())
t("etc", lambda: w("/etc/oomph-sandbox-probe"))
t("ledger", lambda: w("/var/lib/oomph/ledger/oomph-sandbox-probe"))
t("logs", lambda: w("/var/log/oomph/oomph-sandbox-probe"))
print(json.dumps(r))
"""
PROBE_SKIP = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "Type", "Restart", "RestartSec",
              "StateDirectory", "LoadCredential", "SetCredential", "TimeoutStartSec", "TimeoutSec", "RemainAfterExit")


def _sandbox_probe(sh, unit):
    """SANDBOX_PROBE run with `unit`'s [Service] settings as installed (with drop-ins, from `systemctl cat`), by
    the unit's own Python: {attempt: outcome}, or {"error": what systemd-run said}."""
    props, section, py = [], None, None
    for line in sh(["systemctl", "cat", "--no-pager", unit]).stdout.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Service]" and "=" in line and not line.startswith(("#", ";")) and not line.endswith("\\"):
            k, v = line.split("=", 1)
            if k.strip() == "ExecStart" and v.split():
                py = v.split()[0].lstrip("@-:+!")
            if k.strip() not in PROBE_SKIP:
                props += ["-p", line]
    r = sh(["systemd-run", "--quiet", "--wait", "--pipe", "--collect"] + props +
           [py or "/usr/bin/python3", "-I", "-B", "-c", SANDBOX_PROBE], timeout=60)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": (r.stdout + r.stderr)[-300:]}


def part_service():
    """The Linux logger installed for real (1.13.0; roadmap 03 §15.5, C.3 rows 9 to 16): as root on a
    machine with systemd, in CI only (the Ubuntu runner is thrown away afterwards). linux/install.sh --system
    starts the service; it runs as oomphd with no capability (CapEff, CapBnd 0, NoNewPrivs, a seccomp filter),
    rates at most 2.5 in systemd-analyze security, reads kills from the journal; a process killed at its
    cgroup's limit is named in events.jsonl within one sample of its journal line, a slice whose processes keep hitting its limit
    makes one quiet incident, an alert record runs a hook through oomph-alert.path, two accounts reserve in the
    one ledger /var/lib/oomph/ledger, serve --stdio answers, and uninstall --system --purge leaves nothing."""
    if not (LINUX and os.geteuid() == 0 and os.path.isdir("/run/systemd/system") and shutil.which("systemctl")):
        skip("the service part: needs Linux, root and systemd (CI)")
        return
    import pwd
    sh = lambda cmd, timeout=120: subprocess.run(cmd, shell=isinstance(cmd, str), capture_output=True, text=True,  # noqa: E731
                                                 timeout=timeout)
    user = os.environ.get("SUDO_USER") or ""
    as_user = (lambda *a, **kw: subprocess.run(["runuser", "-u", user, "--"] + list(a), capture_output=True, text=True,
                                               timeout=kw.get("timeout", 60), input=kw.get("input"))) if user else None
    e = dict(os.environ, PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin")
    r = subprocess.run([os.path.join(ROOT, "linux", "install.sh"), "--system"], capture_output=True, text=True, timeout=300,
                       env={k: v for k, v in e.items() if k not in ("SUDO_UID", "SUDO_USER", "SUDO_GID")})
    print(r.stdout.rstrip())
    ok = check(r.returncode == 0 and sh("systemctl is-active oomphd").stdout.strip() == "active",
               "linux/install.sh --system: the service oomphd is active and wrote its first sample%s"
               % ("" if r.returncode == 0 else ": " + (r.stdout + r.stderr)[-500:]))
    if not ok:
        print(sh("journalctl -u oomphd -n 40 --no-pager").stdout)
        return
    try:
        _service_checks(sh, as_user, user)
    finally:
        print(sh("journalctl -u oomphd -n 15 --no-pager").stdout)
        r = sh([os.path.join(ROOT, "linux", "uninstall.sh"), "--system", "--purge"])
        left = [p for p in ("/etc/systemd/system/oomphd.service", "/usr/local/bin/oomph", "/usr/local/libexec/oomph",
                            "/var/log/oomph", "/var/lib/oomph", "/etc/oomph") if os.path.lexists(p)]
        try:
            pwd.getpwnam("oomphd")
            left.append("the account oomphd")
        except KeyError:
            pass
        check(r.returncode == 0 and not left and sh("pgrep -u oomphd").stdout.strip() == "" if not left else False,
              "linux/uninstall.sh --system --purge: the service, the code, the logs, the ledger and the account are gone%s"
              % (": left %s" % left if left else ""))


def _service_checks(sh, as_user, user):
    pid = sh("systemctl show -p MainPID --value oomphd").stdout.strip()
    st = dict(l.split(":", 1) for l in open("/proc/%s/status" % pid).read().splitlines() if ":" in l)
    owner = sh("ps -o user= -p %s" % pid).stdout.strip()
    check(owner == "oomphd" and int(st["CapEff"].strip(), 16) == 0 and int(st["CapBnd"].strip(), 16) == 0 and
          st["NoNewPrivs"].strip() == "1" and st["Seccomp"].strip() == "2",
          "the logger runs as %s: CapEff %s, CapBnd %s, NoNewPrivs %s, Seccomp %s" % (
              owner, st["CapEff"].strip(), st["CapBnd"].strip(), st["NoNewPrivs"].strip(), st["Seccomp"].strip()))
    props = sh("systemctl show oomphd -p PrivateNetwork -p RestrictAddressFamilies -p PrivateDevices -p ProtectSystem").stdout
    check("PrivateNetwork=yes" in props and "RestrictAddressFamilies=AF_UNIX" in props and "PrivateDevices=yes" in props
          and "ProtectSystem=strict" in props, "no network, no devices, a read-only system: %s" % props.split())
    for unit in ("oomphd.service", "oomph-alert.service"):
        r = sh(["systemd-analyze", "security", "--no-pager", unit])
        m = re.search(r"Overall exposure level for \S+: ([\d.]+)", r.stdout + r.stderr)
        check(m and float(m.group(1)) <= 2.5, "systemd-analyze security %s: %s (at most 2.5)" % (unit, m.group(1) if m else
                                                                                                  (r.stdout + r.stderr)[-300:]))
    pr = _sandbox_probe(sh, "oomphd.service")
    check(all(pr.get(k) not in (None, "ok") for k in ("exe", "mem", "inet", "etc")),
          "under oomphd.service's settings root's exe link, /proc/1/mem, an AF_INET socket and a file in /etc are all "
          "refused: %s" % pr)
    pr = _sandbox_probe(sh, "oomph-alert.service")
    check(all(pr.get(k) not in (None, "ok") for k in ("etc", "ledger", "logs")),
          "under oomph-alert.service's settings the hooks can write neither the ledger, the logs nor /etc: %s" % pr)
    cur = json.load(open("/var/log/oomph/current.json"))
    d = cur.get("daemon") or {}
    ms = (d.get("machine") or {}).get("measures") or {}
    check(d.get("user") == "oomphd" and ms.get("kills") == "journal" and d.get("root") is False and cur.get("os") == "linux"
          and isinstance(cur.get("cpu"), dict) and isinstance(cur.get("disks"), list),
          "current.json: the logger as oomphd, kills from the journal, cpu and disks recorded (%s)" % ms.get("kills"))
    # a kill at a cgroup's own limit, named
    t0 = time.time()
    r = sh(["systemd-run", "--scope", "-q", "-p", "MemoryMax=64M", "-p", "MemorySwapMax=0", "python3", "-c", KILL_ME])
    check(r.returncode in (137, -9), "a scope limited to 64 MB is OOM-killed (exit %s)" % r.returncode)
    found = None
    while time.time() - t0 < 75 and not found:
        time.sleep(3)
        for line in open("/var/log/oomph/events.jsonl"):
            ev = json.loads(line)
            if ev.get("kind") == "oom_kill" and ev.get("t", 0) >= t0 - 1 and \
                    any(v.get("name") == "python3" and v.get("by") == "cgroup" for v in ev.get("victims") or ()):
                found = ev
    vt = min((v.get("t", 0) for v in (found or {}).get("victims") or () if v.get("name") == "python3"), default=0)
    check(found and vt >= t0 - 1 and found["t"] - vt <= 35, "events.jsonl names the victim (python3, at a cgroup's "
          "limit) within one sample (30 s, and 5 for the sample itself) of its line in the journal: %s, %.0f s after"
          % (found and {k: found[k] for k in ("by", "top", "ooms")}, found["t"] - vt if found else -1))
    inc = [json.load(open(f)) for f in glob.glob("/var/log/oomph/incidents/*/incident.json")]
    check(not [i for i in inc if not i.get("quiet")], "a kill at a cgroup's own limit opens no incident of the machine")
    # five OOMs of one slice: a quiet incident
    sh(["systemd-run", "--scope", "-q", "--slice=oomphci.slice", "true"])
    sh(["systemctl", "set-property", "--runtime", "oomphci.slice", "MemoryMax=64M", "MemorySwapMax=0"])
    t1 = time.time()
    for _ in range(5):
        sh(["systemd-run", "--scope", "-q", "--slice=oomphci.slice", "python3", "-c", KILL_ME])
    quiet = None
    while time.time() - t1 < 80 and not quiet:
        time.sleep(3)
        for f in glob.glob("/var/log/oomph/incidents/*/incident.json"):
            i = json.load(open(f))
            if i.get("quiet") and any("oomphci" in (c.get("name") or "") for c in i.get("cgroups") or ()):
                quiet = i
    check(quiet, "five OOMs of one slice in a minute: one quiet incident naming it (%s)"
          % (quiet and quiet["reasons"][0]["desc"]))
    if as_user:
        r = as_user("/usr/local/bin/oomph", "incidents")
        check(r.returncode == 0 and "quiet one" in r.stdout, "oomph incidents (as %s) counts it as quiet: %s"
              % (user, r.stdout.strip().splitlines()[-1:] if r.stdout.strip() else r.stderr[-200:]))
    # an alert record runs a hook, through oomph-alert.path
    os.makedirs("/etc/oomph/alert.d", exist_ok=True)
    check(oct(os.stat("/etc/oomph/alert.secret").st_mode & 0o777) == "0o600" and
          os.path.isdir("/var/log/oomph/alerts") and os.stat("/var/log/oomph/alerts").st_uid == pwd.getpwnam("oomphd").pw_uid,
          "the hooks' secrets file is root's (0600); alerts/ is the logger's, made by the logger")
    with open("/etc/oomph/alert.secret", "w") as f:
        f.write("CI_SECRET=s3cret-ci\n")
    with open("/etc/oomph/alert.d/50-ci", "w") as f:   # it works only with the secret the unit hands it, in its sandbox
        f.write("#!/bin/sh\n[ \"$(sed -n 's/^CI_SECRET=//p' \"$CREDENTIALS_DIRECTORY/alert\")\" = s3cret-ci ] || exit 3\n"
                "[ -e /proc/meminfo ] && exit 4\n"     # (ProcSubset=pid: `alert --test` too runs it as the unit does)
                "echo \"ci hook: $OOMPH_EVENT $OOMPH_INCIDENT\"\n")
    os.chmod("/etc/oomph/alert.d/50-ci", 0o755)
    with open("/etc/oomph/alert.d/60-private", "w") as f:
        f.write("#!/bin/sh\nexit 0\n")
    os.chmod("/etc/oomph/alert.d/60-private", 0o700)
    r = sh("systemctl enable --now oomph-alert.path")
    rec = {"v": 1, "event": "open", "incident": "20991231-000000", "t": time.time(), "level": "critical", "host": "ci",
           "title": "Memory incident on ci", "message": "a test record"}
    tmp = "/var/log/oomph/alerts/.20991231-000000.tmp"
    with open(tmp, "w") as f:
        json.dump(rec, f)
    os.chmod(tmp, 0o644)
    os.replace(tmp, "/var/log/oomph/alerts/20991231-000000.open.json")
    ran = ""
    for _ in range(20):
        time.sleep(1)
        ran = sh("journalctl -u oomph-alert.service --no-pager -o cat").stdout
        if "open 50-ci: 0" in ran:
            break
    check(r.returncode == 0 and "open 50-ci: 0" in ran and "60-private" not in ran, "an alert record starts "
          "oomph-alert.service, which runs the hook as a throwaway account, with the secret as its credential (a 0700 "
          "hook is left out): %s" % (ran.strip().splitlines()[-2:] if ran.strip() else r.stderr[-200:]))
    r = sh(["/usr/local/bin/oomph", "alert", "--test"])
    check(r.returncode == 1 and re.search(r"50-ci\s+ok", r.stdout) and "throwaway account" in r.stdout and
          re.search(r"60-private\s+not run", r.stdout), "sudo oomph alert --test runs it as the unit does (the secret "
                                                       "read, in the unit's sandbox, ok) and names the 0700 hook it could not run: %s"
          % (r.stdout + r.stderr)[-400:])
    os.remove("/etc/oomph/alert.d/60-private")
    # the machine's ledger: two accounts, one queue
    if as_user:
        sh("id ocitest || useradd -m ocitest")
        r1 = as_user("/usr/local/bin/oomph", "reserve", "0.1G", "--for", "ci one", "--json")
        r2 = subprocess.run(["runuser", "-u", "ocitest", "--", "/usr/local/bin/oomph", "reserve", "0.1G", "--for", "ci two",
                             "--json"], capture_output=True, text=True, timeout=60)
        r3 = as_user("/usr/local/bin/oomph", "reservations", "--json")
        res = json.loads(r3.stdout) if r3.stdout.strip() else {}
        led = res.get("ledger") or {}
        users = {x.get("user") for x in (res.get("mine") or []) + (res.get("others") or []) if isinstance(x, dict)}
        check(r1.returncode == 0 and r2.returncode == 0 and led.get("path") == "/var/lib/oomph/ledger" and
              led.get("kind") == "shared" and {user, "ocitest"} <= users,
              "two accounts reserve in the machine's ledger %s (%s): %s" % (led.get("path"), led.get("members"), sorted(
                  u for u in users if u)) + ("" if r2.returncode == 0 else ": " + r2.stderr[-200:]))
        r4 = sh(["env", "-u", "SUDO_UID", "-u", "SUDO_USER", "-u", "SUDO_GID", "/usr/local/bin/oomph", "reserve", "0.1G",
                 "--for", "ci root", "--json"])
        got = json.loads(r4.stdout) if r4.stdout.strip().startswith("{") else {}
        r5 = as_user("/usr/local/bin/oomph", "reservations", "--json")
        res = json.loads(r5.stdout) if r5.stdout.strip() else {}
        check(r4.returncode == 0 and got.get("status") == "granted" and
              any(x.get("purpose") == "ci root" for x in (res.get("others") or []) + (res.get("mine") or [])),
              "root without sudo (su -, a root agent) reserves in the machine's ledger, through a child as nobody: %s"
              % (r4.stdout + r4.stderr)[-300:])
        hello = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1]}}) + "\n"
        r = as_user("/usr/local/bin/oomph", "serve", "--stdio", input=hello)
        m = ((json.loads(r.stdout.splitlines()[0]) if r.stdout.strip() else {}).get("result") or {}).get("machine") or {}
        check(m.get("os") == "linux" and m.get("logs") == "ok" and m.get("logger"), "oomph serve --stdio as %s: a Linux "
              "machine with its logs (logger %s)" % (user, m.get("logger")))
        r = as_user("/usr/local/bin/oomph", "doctor", "--json")
        dj = json.loads(r.stdout) if r.stdout.strip() else {}
        lv = {c["id"]: c["level"] for c in dj.get("checks") or ()}
        check(lv.get("logger") == "ok" and lv.get("kills") == "ok" and lv.get("access") == "note",
              "oomph doctor: the logger running, kills named, who may use the ledger (%s)" % lv)


if __name__ == "__main__":
    parts = sys.argv[1:] or ["fixtures", "logger", "live"] + (["linux", "system"] if LINUX else [])
    try:
        for part in parts:
            print("--- %s" % part)
            {"fixtures": part_fixtures, "logger": part_logger, "live": part_live, "linux": part_linux, "system": part_system,
             "root": part_root, "service": part_service}[part]()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed"))
    sys.exit(1 if failures else 0)
