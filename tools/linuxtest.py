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

  root      on Linux as root without sudo, only when named (it writes root's home): root's own
            ledger used in place, a shared one through a child as nobody, install.sh as root.

Run: python3 -I -B tools/linuxtest.py [fixtures|live|linux|root ...]. Exit 0 when every check
passes. OOMPH_LINUXTEST_STRICT=1 (CI) turns every skipped part into a failure.
Ad-hoc memory is bounded: the one allocation is 200 MB, every child has a timeout.
"""
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


if __name__ == "__main__":
    parts = sys.argv[1:] or ["fixtures", "live"] + (["linux"] if LINUX else [])
    try:
        for part in parts:
            print("--- %s" % part)
            {"fixtures": part_fixtures, "live": part_live, "linux": part_linux, "root": part_root}[part]()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
    print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all checks passed"))
    sys.exit(1 if failures else 0)
