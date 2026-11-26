#!/usr/bin/python3 -I
"""Tests of the network reservations of 1.15 (roadmap NET-concept §12, step N2): the parsers of --net, --net-up and
--net-rate, the pools net.down and net.up at 8, 40, 194 and 1000 Mbit/s, elastic grants (two volume pulls side by side,
a third waits; an exact range waits), refusals, a network without a figure granted unmanaged, the switch
net_reservations off (exit 75, both texts), the network changing under a grant, `over` (rate and volume) and `idle`
from the logger's bytes per process, Σ used never above what the connections moved, the totals-only path (the Linux
service), the ETA and run_with, `oomph run`'s environment, placeholders and limiter flags, amend, the MCP arguments,
the logger's pools in current.json and the history records. Unprivileged and portable (no traffic: the sample's net
block and the bytes per process are made up); a ledger of its own. tools/selftest.py runs it.

    /usr/bin/python3 -I -B tools/netrestest.py
"""
import contextlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="oomph-netrestest-")
os.environ.update(OOMPH_DIR=TMP, OOMPH_LEDGER_DIR=os.path.join(TMP, "ledger"), OOMPH_STATE_DIR=os.path.join(TMP, "state"))
for k in ("OOMPH_NET_RESERVATIONS", "OOMPH_GPU_RESERVATIONS"):
    os.environ[k] = "0"   # off whatever the root-owned config.json says (an owner trying the switch by hand, D-N19)
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import oomph  # noqa: E402

T = oomph._T()  # the network's code (daemon/oomph_traffic.py), bound to oomph
if sys.platform != "darwin":  # the ledger's process table, as tools/selftest.py has it on Linux
    import fixtureplat  # noqa: E402
    oomph._plat = fixtureplat
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


A, B, C = "rmac:00:00:5e:00:53:01", "rmac:00:00:5e:00:53:02", "rmac:00:00:5e:00:53:03"   # three made-up routers
BASE = dict(ram_gb=64.0, app_gb=10.0, wired_gb=4.0, compressed_gb=0.0, pressure=1, disk_free_gb=600.0,
            swap_used_gb=0.0, swap_total_gb=0.0, os="macos", cpu={"n": 14, "busy": 0.0})
state = {"net": {"if": "en0", "vpn": False, "network": A, "src": "flows", "down_mbps": 0.0, "up_mbps": 0.0}}


def sample():
    s = dict(BASE, t=time.time())
    if state["net"] is not None:
        s["net"] = dict(state["net"])
    if state.get("pools"):
        s["pools"] = json.loads(json.dumps(state["pools"]))
    return s


def on_net(key, **kw):
    state["net"] = dict({"if": "en0", "vpn": False, "network": key, "src": "flows", "down_mbps": 0.0, "up_mbps": 0.0},
                        **kw)


def on(v=True):
    if v:
        os.environ["OOMPH_NET_RESERVATIONS"] = "1"
    else:
        os.environ["OOMPH_NET_RESERVATIONS"] = "0"


def setnet(key, down, up):
    r = T.networks_edit("set", key, {"down": down, "up": up, "source": "set"})
    assert r.get("ok"), r


oomph._sample_override = sample
sleepers = [subprocess.Popen(["/bin/sleep", "120"]) for _ in range(5)]
H = [{"pid": x.pid, "start": None, "kind": "session", "project": "/tmp/n-%d" % i} for i, x in enumerate(sleepers)]
lease = lambda rid: next((x for x in oomph.read_ledger()["leases"] if x["id"] == rid), {})  # noqa: E731
part = lambda rid, k="net": (lease(rid).get("res") or {}).get(k) or {}  # noqa: E731


def clear():
    """Every lease ends (those of `oomph reserve` from here are held by this test's parent)."""
    for r in oomph.read_ledger()["leases"]:
        oomph.release(r["id"])


def raises(f, *a):
    try:
        f(*a)
    except (ValueError, oomph.UsageError) as e:
        return str(e)
    return None


try:
    # --- the parsers (12.12)
    check(T.parse_net_rate("200M") == ((200, 100), None) and T.parse_net_rate("100M..200M/10M..20M") == ((200, 100), (20, 10))
          and T.parse_net_rate("/20M") == (None, (20, 10)) and T.parse_net_rate("200Mbit/s/20Mbit/s") == ((200, 100), (20, 10))
          and T.parse_net_rate("400M..400M") == ((400, 400), None) and T.parse_net_rate("2.5") == ((2.5, 1.3), None),
          "--net-rate: a rate (elastic from half), a range, DOWN/UP, upload only, Mbit/s spelt out, an exact range")
    bad = {x: raises(T.parse_net_rate, x) for x in ("1G", "25MB/s", "500k", "200M..100M", "0M", "lots", "1/2/3")}
    check(all(bad.values()) and "use 1000M" in bad["1G"] and "200M" in bad["25MB/s"] and "start at 1M" in bad["500k"]
          and "lowest" in bad["200M..100M"],
          "--net-rate refuses with the reason: 1G is ambiguous, MB/s is bytes, k is too small, a range backwards (%s)"
          % {k: (v or "")[:30] for k, v in bad.items()})
    o = T.net_opts({"--net": "1.5T", "--net-up": "5G", "--net-rate": "150M"})
    check(o == {"net_gb": 1500.0, "net_up_gb": 5.0, "net_mbps": 150, "net_min_mbps": 75}
          and "megabits or megabytes" in (raises(T.net_opts, {"--net": "500M"}) or "")
          and T.net_opts({"--net": "0"}, zero=True) == {"net_gb": 0.0} and raises(T.net_opts, {"--net": "0"}),
          "--net and --net-up take GB (T = 1000 G), 500M is refused; amend's --net 0 drops the part (%s)" % o)

    # --- the pools at 8, 40, 194 and 1000 Mbit/s (12.8): the household keeps max(10, 25 %) down, max(5, 30 %) up
    nv = {}
    for i, (k, d, u) in enumerate(((A, 8, 4), (B, 40, 10), (C, 194, 48))):
        setnet(k, d, u)
    setnet("rmac:00:00:5e:00:53:04", 1000, 500)
    for k in (A, B, C, "rmac:00:00:5e:00:53:04"):
        on_net(k)
        nv[k] = T.net_view(sample(), [], time.time())
    P = lambda k, p: nv[k]["pools"].get(p)  # noqa: E731
    check(not nv[A]["pools"] and nv[A]["why"] == {"net.down": "slow", "net.up": "slow"}
          and P(B, "net.down")["margin"] == 10 and P(B, "net.down")["room"] == 30 and P(B, "net.up")["room"] == 5
          and P(C, "net.down")["margin"] == 48.5 and P(C, "net.up")["margin"] == 14.4
          and P(C, "net.down")["room"] == 145.5 and P("rmac:00:00:5e:00:53:04", "net.down")["room"] == 750
          and P("rmac:00:00:5e:00:53:04", "net.up")["room"] == 350,
          "the pools: 8 Mbit/s is too slow to share; 40/10 shares 30/5; 194/48 keeps 48.5/14.4; 1000/500 shares 750/350")
    on_net(C)

    # --- the switch (12.11): off by default, refused before anything is written, with how to switch it on
    on(False)
    off = oomph.reserve(0, "a pull", H[0], net_gb=40)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = oomph.cmd_reserve(["--net", "40G", "--for", "x", "--json"])
        rc_run = oomph.cmd_run(["--net-rate", "100M", "--", "/usr/bin/true"])
    plain = T.net_switch_text("oomph: REFUSED — ")
    paste = [x.strip() for x in plain.splitlines() if "net_reservations" in x and ("sudo" in x or x.strip() == oomph.CONFIG_FILE)]
    check(off["status"] == "refused" and off.get("switch") == "net_reservations" and "switched off" in off["advice"]
          and oomph.CONFIG_FILE in off["advice"] and "OOMPH_NET_RESERVATIONS=1" in off["advice"]
          and rc == 75 and json.loads(out.getvalue())["switch"] == "net_reservations" and rc_run == 75
          and "not started" in err.getvalue() and not oomph.read_ledger()["leases"],
          "switched off: reserve, the CLI and oomph run are refused (exit 75) with how to switch it on; nothing written")
    check(paste and (paste[0] == oomph.CONFIG_FILE or paste[0].startswith("sudo mkdir")),
          "switched off, in a terminal: what is to be pasted stands on a line of its own (%r)" % (paste[:1],))
    mc = oomph._mcp_call("reserve_memory", {"purpose": "mcp", "net_gb": 4, "wait_s": 0})
    mem = oomph.reserve(1, "memory as usual", H[0])
    check(mc["status"] == "refused" and mc.get("switch") == "net_reservations" and mem["status"] == "granted",
          "switched off: the MCP tool is refused the same way; memory is reserved as usual")
    on()
    os.environ["OOMPH_NET_RESERVATIONS"] = "0"
    check(not oomph.net_reservations_on(), "the switch: OOMPH_NET_RESERVATIONS=0 is off")
    on()
    check(oomph.net_reservations_on(), "the switch: OOMPH_NET_RESERVATIONS=1 is on for one command")
    clear()

    # --- elastic, shared (D-N12; 12.10): two volume pulls side by side, a third waits; memory passes it
    a = oomph.reserve(0, "pull a", H[0], net_gb=40)
    b = oomph.reserve(0, "pull b", H[1], net_gb=40)
    c = oomph.reserve(0, "pull c", H[2], net_gb=40)
    m = oomph.reserve(1, "memory meanwhile", H[3])
    check(a["status"] == b["status"] == "granted" and a["granted"]["net_mbps"] == 72 and part(b["id"])["got"] == 72
          and part(a["id"])["min"] == 36 and part(a["id"])["network"] == C
          and c["status"] == "queued" and c.get("waiting_on") == ["net.down"] and "at least 36 Mbit/s down" in c["advice"]
          and m["status"] == "granted",
          "two 40 GB pulls on 194 Mbit/s get 72 each (half the 145.5 that can be shared), a third waits for net.down, "
          "memory passes it (%s)" % [a.get("granted"), c.get("waiting_on")])
    check(a["run_with"] == {"net_mbps": 72, "limit": 9000000, "eta_s": 4444} and isinstance(a["run_with"]["limit"], int)
          and a["advice"].startswith("Run at 72 Mbit/s (curl --limit-rate 9000000; oomph run adds it): 40 GB at 72 "
                                     "Mbit/s ≈ 74 min."),
          "run_with in integers (bytes per second: curl reads M as MiB) and the ETA in words (%s)" % a["advice"][:90])
    oomph.release(a["id"])
    c2 = oomph.reserve(0, "pull c", H[2], ticket=c["id"])
    check(c2["status"] == "granted" and c2["granted"]["net_mbps"] == 72, "the third pull is granted once one ends")
    clear()

    # an exact range waits for its turn; a minimum above what the line can share is refused
    x1 = oomph.reserve(0, "big", H[0], net_mbps=100)
    x2 = oomph.reserve(0, "exact", H[1], net_mbps=100, net_min_mbps=100)
    x3 = oomph.reserve(0, "elastic", H[2], net_mbps=100)
    never = oomph.reserve(0, "never", H[3], net_mbps=200, net_min_mbps=200)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = oomph.cmd_reserve(["--net-rate", "200M..200M", "--for", "never"])
    check(x1["granted"]["net_mbps"] == 100 and x2["status"] == "queued" and "exactly 100" in x2["advice"]
          and x3["status"] == "queued" and x3.get("waiting_on") == ["net.down"]
          and never["status"] == "refused" and "145.5 Mbit/s to share" in never["advice"]
          and "can never be granted" in never["advice"] and rc == 75 and "never be granted" in " ".join(out.getvalue().split()),
          "an exact range waits for its turn (100..100 with 45.5 left), an elastic one behind it waits too (first come); "
          "200..200 on a line that shares 145.5 is refused (exit 75)")
    clear()
    # what is idle sizes an elastic grant (the logger's others), and the note says why less
    state["pools"] = {"t": time.time(), "net.down": {"network": C, "cap": 194.0, "margin": 48.5, "reserved": 0,
                                                     "busy": 100.0, "others": 100.0}}
    e1 = oomph.reserve(0, "elastic", H[0], net_mbps=80)
    state["pools"] = None
    state["net"] = {"if": "en0", "network": C, "src": "id"}   # read now, without a window: no rates (no logger)
    e2 = oomph.reserve(0, "no logger", H[1], net_mbps=20)
    on_net(C)
    check(e1["granted"]["net_mbps"] == 45 and "holds no reservation" in (e1.get("note") or "")
          and e2["granted"]["net_mbps"] == 20 and "not measured right now" in (e2.get("note") or ""),
          "elastic: 80 asked with 100 of 194 busy elsewhere gets the 45 idle (at least 40); without the logger's "
          "pools the line's load is not measured, idle = room (%s)" % [e1.get("note"), e2.get("note")])
    clear()

    # --- a network without a figure (D-N14), a line too slow to share, offline: unmanaged, exit 0
    on_net("gw:192.0.2.1/24")
    u = oomph.reserve(0, "unknown", H[0], net_gb=40, net_mbps=100)
    up_ = dict(part(u["id"]))
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = oomph.cmd_reserve(["--net", "4G", "--for", "unknown too"])
    oomph.release(u["id"])   # its answer leaves the machine: the ledger's own record keeps the key
    rec = [h for h in oomph.read_ledger()["history"] if h["id"] == u["id"]][-1]
    on_net(A)
    slow = oomph.reserve(0, "slow", H[1], net_gb=1)
    state["net"] = {"if": None}
    offline = oomph.reserve(0, "offline", H[2], net_gb=1)
    on_net(C)
    check(u["status"] == "granted" and up_.get("unmanaged") is True and "got" not in up_
          and up_["network"] == "gw:192.0.2.1/24" and up_["gb"] == 40
          and "capacity is unknown: oomph net" in (u.get("note") or "")
          and u["run_with"] == {"net_mbps": 0, "limit": 0, "net_unmanaged": True} and rc == 0
          and slow["status"] == "granted" and "too slow to share" in (slow.get("note") or "")
          and offline["status"] == "granted" and "offline" in (offline.get("note") or ""),
          "unknown network: granted unmanaged (exit 0), no rate handed on (0: no limit), the volume kept, the note "
          "says how to measure it; a line too slow to share and offline likewise")
    check(rec["res"].get("net_gb") == 40 and "net" not in rec["res"] and rec["res"].get("net_network") == "gw:192.0.2.1/24",
          "an unmanaged part's record: its volume and network, no rate (%s)" % rec.get("res"))
    clear()

    # --- the network changes under a grant (§11 Q1): granted again on the new one, as far as room goes; unknown:
    # unmanaged; and back
    setnet(B, 40, 10)
    g1 = oomph.reserve(0, "moving", H[0], net_gb=40, net_up_gb=2)
    g2 = oomph.reserve(0, "moving too", H[1], net_mbps=50)
    on_net(B)
    oomph.coordination(H[0]["pid"])
    p1, p2, q1 = part(g1["id"]), part(g2["id"]), part(g1["id"], "net_up")
    note1 = lease(g1["id"]).get("note") or ""
    on_net("gw:198.51.100.1/24")
    oomph.coordination(H[0]["pid"])
    p3 = part(g1["id"])
    on_net(C)
    oomph.coordination(H[0]["pid"])
    p4 = part(g1["id"])
    check(p1["network"] == B and p1["got"] == 30 and p2["got"] == 1 and q1["got"] == 5 and p1["gb"] == 40
          and "network changed: now 30 Mbit/s down" in note1
          and p3.get("unmanaged") is True and "got" not in p3 and p3["network"] == "gw:198.51.100.1/24"
          and p4["network"] == C and p4["got"] == 72 and not p4.get("unmanaged"),
          "a laptop moves: on a 40/10 line the grants get 30 and 1 (room, no minimum, at least 1), upload 5; on an "
          "unknown network unmanaged; back home 72 again (%s)" % [p1.get("got"), p2.get("got"), q1.get("got"), note1[:40]])
    clear()

    # a moment offline (a laptop waking, roaming) neither starts a queued exact range unmanaged nor lets it skip its turn
    on_net(C)
    procs0 = oomph.plat().collect_procs()
    o1 = oomph.reserve(0, "holds 100", H[0], net_mbps=100)
    o2 = oomph.reserve(0, "exactly 100", H[1], net_mbps=100, net_min_mbps=100)
    state["net"] = {"if": None}
    oomph.refresh_ledger(sample(), procs0)
    off_state, off_part = lease(o2["id"]).get("state"), dict(part(o2["id"]))
    on_net(C)
    oomph.refresh_ledger(sample(), procs0)
    on_state = lease(o2["id"]).get("state")
    oomph.release(o1["id"])
    o2b = part(o2["id"])
    check(o1["granted"]["net_mbps"] == 100 and o2["status"] == "queued" and off_state == on_state == "queued"
          and not off_part.get("unmanaged") and lease(o2["id"]).get("state") == "granted" and o2b.get("got") == 100,
          "an offline sample keeps a queued 100..100 waiting (not granted unmanaged, no limit); back online it still "
          "waits its turn, and gets exactly 100 once the line is free (%s)" % [off_state, on_state, o2b.get("got")])
    clear()

    # a queued volume alone asks half of the line it is on now; a move onto a full line says so
    on_net(C)
    w1 = oomph.reserve(0, "pull 1", H[0], net_gb=40)
    w2 = oomph.reserve(0, "pull 2", H[1], net_gb=40)
    w3 = oomph.reserve(0, "pull 3", H[2], net_gb=10)
    w3a = dict(part(w3["id"]))
    on_net(B)
    oomph.coordination(H[0]["pid"])
    w3b, n2 = dict(part(w3["id"])), lease(w2["id"]).get("note") or ""
    oomph.release(w1["id"])
    oomph.release(w2["id"])
    w3c = part(w3["id"])
    check(w3["status"] == "queued" and w3a["ask"] == 72 and w3a["min"] == 36 and w3a.get("network") == C
          and w3b["ask"] == 15 and w3b["min"] == 8 and w3b.get("network") == B
          and "fully reserved" in n2 and part(w2["id"]) == {} and w3c.get("got") == 15,
          "a queued --net 10G made on 194/48 (72, at least 36) asks half of a 40/10 line once moved there (15, at "
          "least 8) and is granted there; the grant pushed onto the full line is told so (%s)" % [w3b, n2[:70]])
    clear()
    on_net(C)

    # the network is read before the ledger's lock, never while it is held
    held, seen = [0], []
    enter0, exit0, ident0 = oomph.Ledger.__enter__, oomph.Ledger.__exit__, T._ident_live

    def enter(self):
        held[0] += 1
        return enter0(self)

    def leave(self, *a):
        held[0] -= 1
        return exit0(self, *a)
    oomph.Ledger.__enter__, oomph.Ledger.__exit__ = enter, leave
    T._ident_live = lambda P=None: (seen.append(held[0]), ({"if": "en0", "gw": "192.0.2.1"}, C))[1]
    try:
        lk = oomph.reserve(0, "locked?", H[0], net_mbps=10)
        state["net"] = None   # no logger: the network is read live
        oomph.amend(lk["id"], net_gb=2)
        oomph.coordination(H[0]["pid"])
        oomph.release(lk["id"])
    finally:
        oomph.Ledger.__enter__, oomph.Ledger.__exit__, T._ident_live = enter0, exit0, ident0
        on_net(C)
    check(len(seen) >= 3 and not any(seen),
          "without the logger the network is read before the ledger's lock (amend, coordination, release), never "
          "while it is held (%s)" % seen)
    clear()

    # --- what grants use (12.4): the logger's bytes per process, in grant order, Σ used ≤ what was moved
    me = os.getpid()
    procs = oomph.plat().collect_procs()
    h0 = {"pid": me, "start": procs.get(me, {}).get("start"), "kind": "session", "project": "/tmp/n"}
    r1 = oomph.reserve(0, "watched", h0, net_mbps=40, net_gb=1)
    r2 = oomph.reserve(0, "the same tree", h0, net_mbps=40)

    def tick(ni=0, no=0, dt=10.0, complete=True, down=None, up=None, now=None, extra=None):
        pr = oomph.plat().collect_procs()
        if me in pr:
            pr[me].update(ni=ni, no=no)
        for pid, b in (extra or {}).items():
            if pid in pr:
                pr[pid].update(ni=b[0], no=b[1])
        s = sample()
        s["net"].update(down_mbps=down if down is not None else ni * 8 / dt / 1e6,
                        up_mbps=up if up is not None else no * 8 / dt / 1e6)
        with oomph.Ledger() as L:
            oomph._evaluate(L, s, pr, now or time.time(), rated=True, net={"dt": dt, "complete": complete})
    t0 = time.time()
    for dt_ in (0, 10, 700):   # 60 Mbit/s for 10 s: 75 MB, shared in grant order (§4.1, as memory and cores)
        tick(ni=int(60e6 / 8 * 10), now=t0 + dt_)
    a1, a2 = part(r1["id"]), part(r2["id"])
    tick(ni=int(100e6 / 8 * 10))
    tick(ni=int(100e6 / 8 * 10))
    c1, c2 = part(r1["id"]), part(r2["id"])
    check(a1["used"] == 40 and a2["used"] == 20 and a1["moved"] == 0.15 and a2["moved"] == 0.075
          and "flag" not in a1 and "flag" not in a2 and c1["used"] == 40 and c2["used"] == 60 and "flag" not in c1
          and c2.get("flag") == "over",
          "two 40 Mbit/s grants on one tree at 60 Mbit/s: 40 and 20, neither `over` nor (after ten minutes) `idle`; "
          "at 100 the last takes the rest (60) and is the one `over` (%s)"
          % [a1.get("used"), a2.get("used"), a2.get("flag"), c1.get("used"), c2.get("used"), c2.get("flag")])
    clear()
    r1 = oomph.reserve(0, "watched", h0, net_mbps=40, net_gb=1)
    tick(ni=int(60e6 / 8 * 10))   # alone on its tree: it takes all its tree moved
    a1 = part(r1["id"])
    tick(ni=int(60e6 / 8 * 10))
    b1 = part(r1["id"])
    check(a1["used"] == 60 and a1["moved"] == 0.075 and "flag" not in a1 and b1.get("flag") == "over"
          and b1["peak"] == 60 and abs(b1["avg"] - 60) < 0.01,
          "a grant alone on its tree takes its traffic (60 Mbit/s, 0.075 GB); over 1.25 × 40 twice in a row is `over` "
          "(%s)" % [a1.get("used"), b1.get("flag")])
    st = oomph.reserve(0, "watched", h0, ticket=r1["id"])
    check("Your processes move 60 Mbit/s" in st["advice"] and st.get("flags", {}).get("net") == "over"
          and "--limit-rate 5000000" in st["advice"] and "0.15 of 1 GB moved, ≈ 2 min left at 60 Mbit/s" in st["advice"]
          and st["run_with"]["eta_s"] == 113,
          "the holder is told: move less (curl --limit-rate 5000000) or amend; the ETA at the last minute's mean "
          "(%s)" % st["advice"][:160])
    for _ in range(14):
        tick(ni=int(60e6 / 8 * 10))
    v1 = part(r1["id"])
    check(v1["moved"] > 1 and v1.get("flag") == "over" and oomph._t(v1.get("vol_t")),
          "more than its volume moved (%.3f of 1 GB): `over` stays, since it first did" % v1["moved"])
    tick(ni=0, complete=False, down=30.0)   # nettop backs off: totals alone
    v2 = part(r1["id"])
    tick(ni=int(60e6 / 8 * 10))
    v3 = part(r1["id"])
    check(v2.get("flag") == "over" and v2.get("over_t") == v1["vol_t"] and v3.get("flag") == "over"
          and v3.get("over_t") == v1["vol_t"],
          "a grant over its volume stays `over`, since the same time, through a sample of totals alone (%s)"
          % [v2.get("flag"), v2.get("over_t"), v1.get("vol_t")])
    clear()
    i1 = oomph.reserve(0, "idle", h0, net_mbps=40)
    t0 = time.time()
    tick(ni=0, now=t0)
    tick(ni=0, now=t0 + 700)
    f_idle = part(i1["id"]).get("flag")
    tick(ni=0, now=t0 + 710, complete=False, down=0.0)
    f_tot = part(i1["id"]).get("flag")
    tick(ni=0, now=t0 + 720, complete=False, down=30.0)
    tot = part(i1["id"])
    check(f_idle == "idle" and f_tot is None and tot["used"] == 30 and "low_t" not in tot,
          "under 10 %% of its rate for ten minutes is `idle`; from the line's totals alone (the Linux service) the "
          "grant is charged the line's rate up to what it got, and never called idle (%s)" % [f_idle, f_tot, tot.get("used")])
    clear()
    # totals alone hold the LAN too: the volume is an estimate there, never `over`; an unmanaged part gets what is left
    tv = oomph.reserve(0, "tiny volume", h0, net_mbps=40, net_gb=0.01)
    tick(complete=False, down=40.0)
    tv1 = part(tv["id"])
    clear()
    on_net("gw:192.0.2.1/24")
    tu = oomph.reserve(0, "unmanaged", h0, net_gb=40)
    tick(complete=False, down=30.0)
    tu1 = part(tu["id"])
    on_net(C)
    check(tv1["moved"] == 0.05 and "flag" not in tv1 and tu1.get("unmanaged") is True and tu1["used"] == 30
          and tu1["moved"] == 0.0375,
          "from the totals (LAN included) a grant's volume is an estimate: 0.05 of 0.01 GB moved is not `over`; an "
          "unmanaged part is charged what the managed ones leave (%s)" % [tv1.get("flag"), tu1.get("used")])
    clear()
    # Σ used never exceeds what the processes moved (randomized: grants on overlapping trees, as for disk)
    rnd, worst = random.Random(7), 0.0
    kids = [subprocess.Popen(["/bin/sleep", "60"]) for _ in range(3)]
    try:
        for trial in range(12):
            hs = [dict(h0, pid=rnd.choice([me] + [k.pid for k in kids])) for _ in range(rnd.randint(1, 4))]
            ids = [oomph.reserve(0, "r%d" % j, hh, net_mbps=rnd.choice([5, 10, 20]))["id"] for j, hh in enumerate(hs)]
            ext = {k.pid: (rnd.randint(0, 10 ** 7), rnd.randint(0, 10 ** 6)) for k in kids}
            mine = (rnd.randint(0, 10 ** 7), rnd.randint(0, 10 ** 6))
            tick(ni=mine[0], no=mine[1], extra=ext)
            moved = (mine[0] + sum(x[0] for x in ext.values())) * 8 / 10.0 / 1e6
            used = sum(part(i).get("used", 0) for i in ids)
            worst = max(worst, used - moved)
            clear()
    finally:
        for k in kids:
            k.kill()
            k.wait()
    check(worst <= 0.01 * 12, "Σ used over the grants never exceeds what the processes moved (12 random ledgers; "
          "worst excess %.3f Mbit/s, rounding)" % worst)

    # --- amend (02 §6.4 per part): a volume always applies, a rate shrinks, grows only into room, 0 drops
    on_net(C)
    am = oomph.reserve(0, "amend me", H[0], net_gb=10, net_mbps=100)
    big = oomph.reserve(0, "the rest", H[1], net_mbps=45)
    s1 = oomph.amend(am["id"], net_mbps=50)
    s2 = oomph.amend(am["id"], net_mbps=150)
    s3 = oomph.amend(am["id"], net_gb=80)
    on(False)
    s4 = oomph.amend(am["id"], net_mbps=60)
    s5 = oomph.amend(am["id"], net_mbps=40)
    on()
    s6 = oomph.amend(am["id"], net_up_gb=2)
    s7 = oomph.amend(big["id"], net_gb=0)
    s8 = oomph.amend(am["id"], net_gb=0, gb=1)
    check(s1["changed"].get("net") == [100, 50] and s2["status"] == "refused" and "only 50.5 Mbit/s" in s2["advice"]
          and s3["changed"].get("net_gb") == [10, 80] and s4["status"] == "refused" and s4.get("switch") == "net_reservations"
          and s5["changed"].get("net") == [50, 40] and s6["status"] == "refused" and "holds no upload part" in s6["advice"]
          and s7["status"] == "refused" and "release it instead" in s7["advice"]
          and s8["status"] == "granted" and "net" not in (lease(am["id"]).get("res") or {}),
          "amend: a rate shrinks, grows only into room; a volume always applies; switched off it may shrink, not grow; "
          "no part is added; --net 0 drops it (not the last part) (%s)" % [s2["advice"][:60], s6["advice"][:40]])
    z = oomph.amend(big["id"], net_gb=0, net_mbps=10)
    check(z["status"] == "refused" and "means nothing" in z["advice"]
          and "takes no rate" in (raises(T.net_opts, {"--net": "0", "--net-rate": "10M"}, True) or ""),
          "amend --net 0 with a download rate is refused, not half applied (%s)" % z["advice"][:60])
    clear()

    # --- oomph run: the environment, {net}, {net_limit} and the limiter flags (12.14)
    st = {"id": "r9", "run_with": {"net_mbps": 150, "limit": 18750000, "net_up_mbps": 20, "up_limit": 2500000},
          "asked": {"net_gb": 40.0, "net_up_gb": 5.0}}
    env = oomph.run_env(st, {"OOMPH_NET_MBPS": "999"})
    check(env["OOMPH_NET_MBPS"] == "150" and env["OOMPH_NET_LIMIT"] == "18750000" and env["OOMPH_NET_UP_MBPS"] == "20"
          and env["OOMPH_NET_UP_LIMIT"] == "2500000" and env["OOMPH_NET_GB"] == "40" and env["OOMPH_NET_UP_GB"] == "5",
          "oomph run's environment: OOMPH_NET_MBPS, _LIMIT (bytes per second), _UP_…, _GB, replacing what was set")
    nested = oomph.run_env({"id": "r10", "run_with": {"net_up_mbps": 5, "up_limit": 625000}, "asked": {"net_up_gb": 5.0}},
                           {"OOMPH_NET_MBPS": "100", "OOMPH_NET_LIMIT": "12500000", "OOMPH_NET_GB": "4"})
    mem_only = oomph.run_env({"id": "r11", "run_with": {}}, {"OOMPH_NET_MBPS": "100"})
    check(not {"OOMPH_NET_MBPS", "OOMPH_NET_LIMIT", "OOMPH_NET_GB"} & set(nested) and nested["OOMPH_NET_UP_MBPS"] == "5"
          and mem_only.get("OOMPH_NET_MBPS") == "100",
          "a nested oomph run --net-up inside a --net-rate one inherits no download rate; one without a network part "
          "leaves the outer one's as they are")
    cj = {"pools": {"net.down": {"network": C, "cap": 194.0, "margin": 48.5, "reserved": 100},
                    "net.up": {"network": C, "cap": 48.0, "margin": 14.4, "reserved": 0}}}
    tail_on = T.status_tail(cj)
    on(False)
    tail_off = T.status_tail(cj)
    on()
    check(tail_on == " · 45.5/33.6 Mbit/s left to reserve" and tail_off == "" and T.status_tail({}) == "",
          "oomph status' network line ends as oomph resources' does, from the logger's pools; with the switch off it "
          "says nothing of it (oomph resources does, as for the GPU: N2-6) (%r, %r)" % (tail_on, tail_off))
    cases = [(["curl", "-O", "u"], ["curl", "--limit-rate", "18750000", "-O", "u"]),
             (["/usr/bin/wget", "u"], ["/usr/bin/wget", "--limit-rate=18750000", "u"]),
             (["rsync", "-a", "x", "y"], ["rsync", "--bwlimit=18310", "-a", "x", "y"]),
             (["aria2c", "u"], ["aria2c", "--max-overall-download-limit=18750000", "u"]),
             (["curl", "--limit-rate", "1M", "u"], None), (["wget", "--limit-rate=1m", "u"], None),
             (["aria2c", "--max-download-limit=1M", "u"], None), (["rsync", "--bwlimit=100", "x", "y"], None),
             (["env", "curl", "u"], None), (["sudo", "curl", "u"], None), (["sh", "-c", "curl u"], None),
             (["nice", "wget", "u"], None), (["xargs", "curl"], None), (["time", "curl", "u"], None),
             (["python3", "get.py", "{net}", "--bps={net_limit}"], ["python3", "get.py", "150", "--bps=18750000"])]
    bad = []
    for cmd, want in cases:
        added = []
        got = oomph.run_argv(cmd, st, added)
        if got != (want or cmd) or bool(added) != (want is not None and want[1:2] != cmd[1:2] and "{net}" not in cmd):
            bad.append((cmd, got, added))
    up_only = oomph.run_argv(["curl", "u"], {"run_with": {"net_up_mbps": 20, "up_limit": 2500000}})
    um = oomph.run_argv(["curl", "{net}", "{net_limit}"], {"run_with": {"net_mbps": 0, "limit": 0, "net_unmanaged": True}})
    check(not bad and up_only == ["curl", "--limit-rate", "2500000", "u"] and um == ["curl", "0", "0"],
          "oomph run's limiter flags: curl, wget, rsync (KiB/s), aria2c as the first word, never when one is set (either "
          "spelling) or behind env, sudo, sh -c, nice, xargs, time; the up rate where only that is granted; {net} and "
          "{net_limit}, 0 unmanaged (%s)" % bad[:2])
    fake = os.path.join(TMP, "bin")
    os.makedirs(fake)
    with open(os.path.join(fake, "curl"), "w") as f:
        f.write("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s/argv\nenv > %s/env\n" % (TMP, TMP))
    os.chmod(os.path.join(fake, "curl"), 0o755)
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = oomph.cmd_run(["--net", "4G", "--net-rate", "100M", "--", os.path.join(fake, "curl"), "-s", "u"])
    argv = open(os.path.join(TMP, "argv")).read().split()
    envd = dict(x.split("=", 1) for x in open(os.path.join(TMP, "env")).read().splitlines() if "=" in x)
    check(rc == 0 and argv == ["--limit-rate", "12500000", "-s", "u"] and envd.get("OOMPH_NET_MBPS") == "100"
          and envd.get("OOMPH_NET_GB") == "4" and "added --limit-rate 12500000 (100 Mbit/s)" in err.getvalue()
          and "↓ 100 Mbit/s" in err.getvalue(),
          "oomph run --net 4G --net-rate 100M -- curl: granted 100, curl gets --limit-rate 12500000 and the "
          "environment; stderr says what was added and what moved (%s)" % err.getvalue().strip().splitlines()[-1:])
    clear()

    # --- MCP (12.12, 12.13)
    def tool_err(name, a):
        try:
            oomph._mcp_args(name, a)
        except oomph.ToolArgError as e:
            return str(e)
        return None
    errs = [tool_err("reserve_memory", {"purpose": "x", "net_mbps": "200M"}),
            tool_err("reserve_memory", {"purpose": "x", "net_mbps": "25MB/s"}),
            tool_err("reserve_memory", {"purpose": "x", "net_min_mbps": 50}),
            tool_err("reserve_memory", {"purpose": "x", "net_mbps": 50, "net_min_mbps": 60}),
            tool_err("reserve_memory", {"purpose": "x", "net_gb": 0}),
            tool_err("reserve_memory", {"purpose": "x", "net_mbps": 0.5})]
    sch = {t["name"]: t["inputSchema"]["properties"] for t in oomph.MCP_TOOLS}
    check(all(errs) and "takes a number" in errs[0] and "200M" in errs[1] and "comes with net_mbps" in errs[2]
          and "not above" in errs[3] and tool_err("update_reservation", {"id": "r1", "net_gb": 0}) is None
          and all(k in sch["reserve_memory"] and k in sch["update_reservation"] for k in T._NET_KW)
          and "net" in sch["reservation_history"]["resource"]["enum"],
          "MCP: net_gb, net_up_gb, net_mbps, net_min_mbps, net_up_mbps, net_up_min_mbps in both tools' schemas; numbers "
          "only (a string refused with the parser's words); a minimum with its rate (%s)" % [e[:40] for e in errs[:2]])
    mc = oomph._mcp_call("reserve_memory", {"purpose": "mcp pull", "net_gb": 4, "net_up_mbps": 10, "wait_s": 0})
    co = oomph._mcp_call("reservations", {})
    chk = oomph.checked_verdict(mine=H[0]["pid"], network=True)
    blob = json.dumps(mc) + json.dumps(co) + json.dumps(chk)
    check(mc["status"] == "granted" and mc["run_with"].get("net_up_mbps") == 10 and mc["run_with"].get("up_limit") == 1250000
          and co["net"]["down"]["reserved"] == 72 and str(co["net"]["id"] or "net-").startswith("net-")
          and chk["network"]["room"] == [73.5, 23.6] and chk["network"]["reservable"] is True and A[5:] not in blob
          and C[5:] not in blob,
          "MCP: reserve_memory grants the line; reservations and memory_check say what can still be reserved, the "
          "network by its public id only (none where the system has no id to salt it with) (%s)" % [co["net"].get("id"), chk["network"].get("room")])
    on(False)
    nw_off = oomph.network_info(sample(), {})
    on()
    check(nw_off["reservable"] is False and nw_off.get("reservable_off") == "net_reservations"
          and "reservable: off (net_reservations)" in T.resources_tail({"network": nw_off})
          and "left to reserve" in T.resources_tail({"network": chk["network"]}),
          "the network object and `oomph resources` say the line is reservable, or that the switch is off")
    oomph.release(mc["id"])
    hist = oomph._mcp_call("reservation_history", {"resource": "net"})
    check(hist["reservations"] and all(set(x["res"]) & {"net", "net_gb", "net_up"} for x in hist["reservations"])
          and C[5:] not in json.dumps(hist) and all(str(x["res"].get("net_network") or "net-").startswith("net-")
                                                     for x in hist["reservations"]),
          "reservation_history: resource net, the network's key replaced by its public id")
    clear()
    # nothing that leaves the machine names the network's key (N1 decision B), current.json's pools included
    state["pools"] = dict(T.pool_blocks({"if": "en0", "network": C, "src": "flows", "down_mbps": 10.0, "up_mbps": 1.0},
                                        {"asked": C, "key": C, "entry": {"down": 194.0, "up": 48.0}}, [], {}),
                          t=time.time())
    sample0, oomph.sample = oomph.sample, lambda *a, **k: sample()   # memory_status, status --json: current.json
    rv = oomph._mcp_call("reserve_memory", {"purpose": "leak?", "net_gb": 4, "wait_s": 0})
    answers = [rv, oomph._mcp_call("update_reservation", {"id": rv["id"], "net_gb": 5}),
               oomph._mcp_call("memory_status", {}), oomph._mcp_call("memory_check", {}),
               oomph._mcp_call("reservations", {})]
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        oomph.cmd_status_json()
        oomph.cmd_release([rv["id"], "--json"])
    answers.append(out.getvalue())
    rv2 = oomph._mcp_call("reserve_memory", {"purpose": "leak? 2", "net_gb": 4, "wait_s": 0})
    answers += [rv2, oomph._mcp_call("release_memory", {"id": rv2["id"]}),
                oomph._mcp_call("reservation_history", {}), oomph.public_sample(dict(sample(), net={"network": "gw:x"}))]
    oomph.sample = sample0
    blob = json.dumps(answers)
    msp = answers[2].get("pools") or {}
    check(rv["status"] == "granted" and answers[2]["network"]["room"] == [73.5, 33.6] and "rmac:" not in blob
          and msp.get("net.down", {}).get("cap") == 194.0 and "network" in msp["net.up"]
          and str(msp["net.up"]["network"] or "net-").startswith("net-")
          and "gw:" not in blob and C[5:] not in blob and str(answers[-3]["released"][0]["res"].get("net_network")
                                                             or "net-").startswith("net-"),
          "memory_status (room from the pools less the grants: %s), status --json, memory_check, reservations, "
          "reserve_memory, update_reservation, release_memory, oomph release --json and reservation_history name "
          "the network by its public id only, current.json's pools net.down and net.up included"
          % answers[2]["network"].get("room"))
    state["pools"] = None
    clear()

    # --- the ledger: parts this code reads, and those it does not; the records (12.9)
    q = {"id": "r90", "state": "queued", "gb": 0.01, "purpose": "x", "holder": {"pid": H[0]["pid"]}, "requested": 1e9, "v": 2}
    V = oomph._valid_lease
    good = V(dict(q, res={"net": {"ask": 100, "min": 50, "gb": 40}}))
    um = V(dict(q, res={"net": {"gb": 40, "unmanaged": True, "network": "gw:x"}}))
    badp = [V(dict(q, res={"net": {"ask": 0.5}})), V(dict(q, res={"net": {"ask": 100, "min": 200}})),
            V(dict(q, res={"net": {"gb": 40}})), V(dict(q, res={"net": "lots"})),
            V(dict(q, res={"net": {"ask": 10, "min": 0}})), V(dict(q, res={"net": {"unmanaged": True}}))]
    planted = V(dict(q, res={"net": {"ask": 10, "network": "../../etc x", "eta": "soon", "moved": -1, "metered": 1}}))
    gm = V(dict(q, res={"net": {"ask": 100, "min": 50, "gb": 40, "metered": True}}))
    umm = V(dict(q, res={"net": {"gb": 40, "unmanaged": True, "network": "gw:x", "metered": True}}))
    check(oomph.weighable(good) and oomph.lease_need(good) == {"net.down": (50, 100)}
          and oomph.weighable(um) and oomph.lease_need(um) == {}
          and oomph.lease_need(gm) == {"net.down": (50, 100), "net.quota": (40, 40)}
          and oomph.weighable(umm) and oomph.lease_need(umm) == {"net.quota": (40, 40)}
          and not any(oomph.weighable(x) for x in badp)
          and not {"network", "eta", "moved", "metered"} & set(planted["res"]["net"]),
          "the ledger: a rate part asks net.down from its minimum; an unmanaged part asks no rate pool and is weighable; "
          "on a metered network (`metered`) both ask net.quota for their volume (N3), elsewhere not; a part this code "
          "cannot read is not; a planted network, eta, moved or metered is dropped")
    rec = oomph._valid_finished({"id": "r91", "gb": 0, "requested": 1e9, "event": "end", "key": "k",
                                 "res": {"net": 150, "net_up": 20, "net_gb": 40, "net_up_gb": 5, "net_network": C},
                                 "peak": {"net": 188, "net_gb": 39.8}}, log=True)
    check(rec["res"] == {"net": 150, "net_up": 20, "net_gb": 40, "net_up_gb": 5, "net_network": C}
          and rec["peak"] == {"net": 188, "net_gb": 39.8} and T.net_rec_text(rec) == "150 Mbit/s down, 39.8 of 40 GB "
          "moved, 20 Mbit/s up, 0 of 5 GB moved" and T.net_rec_text(rec, short=True) == "150Md40Gn 20Mu5Gu",
          "a history record keeps the rates, the volumes, the network and what was moved (%s)" % T.net_rec_text(rec))

    # --- the logger's pools (12.5, 12.8): current.json's net.down and net.up
    prev = {}
    blk = {"if": "en0", "network": C, "src": "flows", "down_mbps": 180.0, "up_mbps": 2.0}
    ans = {"asked": C, "key": C, "entry": {"down": 194.0, "up": 48.0}}
    ls = [{"state": "granted", "net": 72, "net_used": 70.0}, {"state": "granted", "net": 72, "net_used": 100.0},
          {"state": "queued", "net": 72}, {"state": "granted", "gb": 1.0}]
    p1 = T.pool_blocks(blk, ans, ls, prev)
    p2 = T.pool_blocks(dict(blk, down_mbps=190.0), ans, ls, prev)
    p3 = T.pool_blocks(dict(blk, down_mbps=190.0), ans, ls, prev)
    p4 = T.pool_blocks(dict(blk, network=B), {"asked": B, "key": B, "entry": {"down": 8.0}}, ls, prev)
    p5 = T.pool_blocks(dict(blk, network=A), ans, ls, prev)
    check(p1["net.down"] == {"network": C, "cap": 194.0, "margin": 48.5, "reserved": 144, "busy": 180.0, "others": 38.0}
          and p2["net.down"]["others"] == 43.0 and "level" not in p2["net.down"] and p3["net.down"]["level"] == "busy"
          and p1["net.up"]["margin"] == 14.4 and p4 == {} and p5 == {},
          "the logger's pools: cap and margin from the child's answer about this network, reserved from the snapshot, "
          "others = busy − Σ min(used, got) smoothed; busy after three samples at 90 %%; none on a slow line, none "
          "from an answer about another network (%s)" % p1.get("net.down"))
    br = {"id": "r5", "state": "granted", "gb": 0.0, "purpose": "p", "project": None, "net": 150, "net_used": 143.2,
          "net_gb": 40.0, "net_moved": 12.3, "net_up": 20, "network": C}
    sl = oomph.sample_leases([br])
    check(sl[0].get("net") == 150 and sl[0].get("net_moved") == 12.3 and "network" not in sl[0]
          and "↓150 Mbit/s 12.3/40G, ↑20 Mbit/s" in oomph._fmt_brief(dict(br, for_min=3)),
          "a sample's leases carry the line's numbers, never the network; a reservation row says them")
    fl = oomph._fmt_brief(dict(br, for_min=3, flags={"net": "over", "net_up": "idle"}))
    check("over on the download, idle on the upload, " in fl and "on net" not in fl,
          "a reservation row names a flagged part of the line in words (%s)" % fl)
finally:
    for x in sleepers:
        x.kill()
        x.wait()
    shutil.rmtree(TMP, ignore_errors=True)

print("\nFAILED (%d)" % len(failures) if failures else "\nall network reservation checks passed")
sys.exit(1 if failures else 0)
