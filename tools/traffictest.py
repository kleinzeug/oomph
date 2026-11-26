#!/usr/bin/python3 -I
"""Tests of internet traffic's measuring (NET step N1, roadmap NET-concept §12): nettop's and ss's rows parsed as
untrusted input (tools/fixtures/net, hostile rows too), LAN or internet, the deltas from sample to sample and what
they add up to (Σ per process ≤ the flows ≤ the total), the network's identity, networks.json (its sanitizer, its
writer under the ledger lock, its limits), `oomph net` and its subcommands, `net test` against a stand-in
networkQuality, `oomph ps --net`, the network line of check, status and resources, the report's peaks, and what
of it travels to another machine. Unprivileged and portable (the machines are fixtures; the Mac's live readings
run where there is a Mac); a ledger of its own. tools/selftest.py runs it.

    /usr/bin/python3 -I -B tools/traffictest.py
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
TMP = tempfile.mkdtemp(prefix="oomph-traffictest-")
os.environ.update(OOMPH_DIR=os.path.join(TMP, "log"), OOMPH_LEDGER_DIR=os.path.join(TMP, "ledger"),
                  OOMPH_STATE_DIR=os.path.join(TMP, "state"))
for k in ("OOMPH_NETTOP_FIXTURE", "OOMPH_SS_FIXTURE", "OOMPH_NETWORKQUALITY"):
    os.environ.pop(k, None)
os.makedirs(os.environ["OOMPH_DIR"])
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import oomph  # noqa: E402
import oomph_linux  # noqa: E402  (its readers take OOMPH_SYSROOT's place through ROOT)

T = oomph._T()
FX = os.path.join(ROOT, "tools", "fixtures", "net")
MAC = sys.platform == "darwin"
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


def fx(name, mode="rb"):
    with open(os.path.join(FX, name), mode) as f:
        return f.read()


def run(fn, *a):
    """(exit status, stdout, stderr) of a command function called in this process."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = fn(*a)
        except SystemExit as e:
            rc = e.code
    return rc, out.getvalue(), err.getvalue()


P = lambda pid, name, uid=501: {"pid": pid, "ppid": 1, "uid": uid, "name": name, "start": 1, "fp": 0, "rss": 0,  # noqa: E731
                                "path": "/usr/bin/" + name}
PROCS = {361: P(361, "remoted", 0), 4101: P(4101, "curl"), 4102: P(4102, "networkQuality"),
         4103: P(4103, "mDNSResponder", 65), 4104: P(4104, "idea"), 4105: P(4105, "rapportd"), 4106: P(4106, "Safari")}
ONLINK = T.onlink_nets(["192.168.178.0/24", "2001:db8:0:1::/64", "fd00:db8:1::/64"])

try:
    # --- LAN or internet (12.3): one case per range
    cases = {"10.1.2.3": True, "172.16.0.1": True, "172.31.255.1": True, "172.32.0.1": False, "192.168.1.1": True,
             "169.254.3.4": True, "127.0.0.1": True, "0.1.2.3": True, "224.0.0.251": True, "239.1.1.1": True,
             "255.255.255.255": True, "::1": True, "fe80::1": True, "fe80::1%en16": True, "fc00::1": True,
             "fd00:db8:1::5": True, "ff02::fb": True, "::ffff:192.168.178.30": True, "::ffff:203.0.113.7": False,
             "100.64.1.2": False, "100.127.255.254": False, "203.0.113.7": False, "2001:db8:ffff::2": False,
             "2001:db8:0:1::99": True, "8.8.8.8": False, "not-an-address": None, "": None}
    bad = {a: T.is_lan(a, ONLINK) for a, want in cases.items() if T.is_lan(a, ONLINK) is not want}
    check(not bad and T.is_lan("2001:db8:0:1::99") is False,
          "LAN or internet: private, link-local, loopback, multicast, ULA, mapped private v4 and the interface's own "
          "prefixes are LAN; CGNAT (100.64/10) and public addresses are internet; the on-link global v6 only with its "
          "prefix %s" % (bad or ""))

    # --- nettop's rows (12.1, mac-1)
    rows, why = T.nettop_flows(fx("nettop-J.csv"), PROCS, ONLINK, "en16", "utun3")
    by = {}
    for r in rows:
        by.setdefault(r[0], []).append(r)
    inet = sorted((r[0], r[4], r[5]) for r in rows if not r[3] and r[2] == "phys")
    check(why is None and len(rows) == 10 and inet == [(4101, 50000000, 200000), (4102, 1000, 500),
                                                       (4102, 30000000, 4000000), (4104, 542, 9813),
                                                       (4104, 7000000, 999)]
          and sum(1 for r in rows if r[3]) == 4 and [r for r in rows if r[2] == "tun"] == [
              (4106, rows[-1][1], "tun", False, 80000, 400)] and None in by,
          "nettop: 10 flows on the egress (en16) and the tunnel (utun3); internet ones by process (curl, both of "
          "networkQuality's incl. QUIC, idea's two incl. CGNAT); 4 LAN (SMB, link-local, an on-link global v6, a mapped "
          "private v4); Wi-Fi (en0), the listener, unconnected UDP and other interfaces left out; kernel_task (pid 0, "
          "not a process of the table) is nobody's")
    rows2, why2 = T.nettop_flows(fx("nettop-J-reordered.csv"), PROCS, ONLINK, "en16", "utun3")
    check(why2 is None and sorted(rows2, key=repr) == sorted(rows, key=repr), "nettop: columns found by the header's names (-J may "
          "change their order): the same flows")
    check(T.nettop_flows(b"time,,interface,state,bytes_in\nx.1,,,1,\n", PROCS)[1] == "columns" and
          T.nettop_flows(b"", PROCS)[1] == "columns" and T.nettop_flows(None, PROCS)[1] == "missing" and
          T.nettop_flows(b"x" * (T.FLOWS_CAP + 1), PROCS)[1] == "cap",
          "nettop: a header without bytes_out, no output, no nettop and more than 4 MB give no flows")
    many = ",interface,state,bytes_in,bytes_out,\n" + "".join(
        "tcp4 192.168.178.42:%d<->203.0.113.9:443,en16,Established,1,1,\n" % (i % 60000) for i in range(T.FLOWS_ROWS + 5))
    check(T.nettop_flows(many.encode(), PROCS, (), "en16")[1] == "cap", "nettop: more than 20 000 rows is a capped "
          "sample (totals only)")
    hp = dict(PROCS)
    hp.update({4201: P(4201, "evil,name"), 4202: P(4202, "a<->b"), 4203: P(4203, "tcp6 ::.1<->::")})
    hr, hw = T.nettop_flows(fx("nettop-hostile.csv"), hp, ONLINK, "en16")
    got = sorted(((r[0], r[4]) for r in hr), key=repr)
    check(hw is None and got == [(4201, 1000), (4202, 2000), (4203, 3000), (None, 2500), (None, 9000)],
          "nettop, hostile names: a comma or <-> in a name, a name that reads as a flow (a process of the table, no "
          "interface) stay processes, one not in the table owning nothing; a 31-digit counter, a 600-character line, a missing column, a negative counter "
          "and a remote that is no address are dropped; a process not in the table owns nothing (%s)" % got)

    # --- ss's rows (12.2, epyc-1…3)
    sp = {5101: P(5101, "appd", 1001), 5102: P(5102, "curl", 1001), 5103: P(5103, "pip", 1001),
          5104: P(5104, "bytes_received:9", 1001), 5105: P(5105, "faker", 0), 5106: P(5106, "evil", 1001),
          5107: P(5107, "evil", 1001), 5108: P(5108, "x", 1001), 5109: P(5109, "ino:1 sk:1 <->", 1001),
          5110: P(5110, "docker-proxy", 0), 4242: P(4242, "victim", 1001)}
    SON = T.onlink_nets(["192.168.178.0/24", "2001:db8:0:1::/64"])
    SEG = {"if": "enp1s0f0", "tun": None, "addrs": ["192.168.178.30", "2001:db8:0:1::11", "fe80::200:5eff:fe00:5304"]}
    sr, sw = T.ss_flows(fx("ss-tinpeHO.txt"), sp, SON, SEG)
    sset = sorted(((r[0], r[3], r[4], r[5]) for r in sr), key=repr)
    check(sw is None and sset == sorted([(5101, True, 1300, 2500000), (5102, False, 50000000, 1201),
                                         (5103, False, 20000000, 3000), (None, True, 4000, 90000),
                                         (None, False, 3000, 700000), (5104, False, 10, 10), (None, False, 5000, 500),
                                         (None, False, 12, 0), (5106, False, 0, 0), (5107, False, 200, 100),
                                         (5108, False, 1, 1), (5109, False, 7, 7)], key=repr) and
          all(r[2] == "phys" for r in sr),
          "ss: LISTEN skipped; IPv6 in brackets, a scoped link-local (LAN), a mapped public v4 (internet); in bytes_received, "
          "out bytes_acked (not bytes_sent), a missing one 0; a name imitating bytes_received: does not count; a pid whose "
          "process has another owner than the socket (uid) is nobody's; another user's socket has no pid; loopback, a "
          "docker bridge's and the tunnel's sockets are not the egress device's (%s)" % sset)
    check(len({r[1] for r in sr}) == len(sr) and hash(("sk", "1b690")) in {r[1] for r in sr} and
          sum(1 for r in sr if r[1] == hash(("sk", "1b690"))) == 1,
          "ss: each socket its own key (the cookie sk:); a cookie a cgroup path imitates is no socket's")
    check(T.ss_flows(fx("ss-tinpeHO.txt"), sp, SON, {"if": "enp1s0f0"})[1] == "addrs" and
          T.ss_flows(fx("ss-tinpeHO.txt"), sp, SON, dict(SEG, tun="wg0"))[1] == "addrs",
          "ss: without the device's (or the tunnel's) own addresses nothing is attributed (totals only)")
    vr, vw = T.ss_flows(fx("ss-tinpeHO.txt"), sp, SON, dict(SEG, tun="wg0", tun_addrs=["10.8.0.2"]))
    check(vw is None and [(r[0], r[2], r[4]) for r in vr if r[2] == "tun"] == [(5102, "tun", 3000000)] and
          len([r for r in vr if r[2] == "phys"]) == len(sr),
          "ss under a VPN (wg0): the tunnel's socket is the tunnel's, by its local address")

    # --- deltas, totals, attribution (12.4)
    def nt(**flows):
        """nettop's CSV with one process per flow name: name=(pid, remote, bytes in, bytes out)."""
        out = [",interface,state,bytes_in,bytes_out,"]
        for name, (pid, remote, bi, bo) in flows.items():
            out.append("%s.%d,,,%d,%d," % (name, pid, bi, bo))
            out.append("tcp4 192.168.178.42:%d<->%s,en16,Established,%d,%d," % (40000 + pid % 1000, remote, bi, bo))
        return ("\n".join(out) + "\n").encode()

    EG = {"if": "en16", "tun": None, "gw": "192.168.178.1", "subnet": "192.168.178.0/24"}
    tp = {1: P(1, "a"), 2: P(2, "b"), 3: P(3, "c"), 9: P(9, "nas")}

    def step(tr, mono, data, wire, complete=True, gap=False):
        f, w = T.nettop_flows(data, tp, ONLINK, "en16") if data is not None else (None, "timeout")
        return tr.step(mono, 1795600000 + mono, EG, wire, f if complete else None, complete and w is None, tp,
                       "rmac:00:00:5e:00:53:03", gap)

    tr = T.Traffic()
    b0, per0, dt0 = step(tr, 0, nt(a=(1, "203.0.113.1:443", 1000, 100)), (10 ** 9, 10 ** 8))
    b1, per1, dt1 = step(tr, 10, nt(a=(1, "203.0.113.1:443", 1000 + 12500000, 100), b=(2, "203.0.113.2:443", 2500000, 0)),
                         (10 ** 9 + 16200000, 10 ** 8 + 2000))
    check(b0["src"] == "if" and "down_mbps" not in b0 and per0 == {} and b1["src"] == "flows" and
          per1 == {1: [12500000, 0], 2: [2500000, 0]} and b1["down_mbps"] == 12.0 and dt1 == 10,
          "deltas: the first sample is a baseline (no rates, totals only); then each flow's growth, and a flow new "
          "since a complete sample in full: 15 MB in 10 s = 12.0 Mbit/s (the flows' sum; the wire's 16.2 MB / 1.08 = "
          "15 MB says the same)")
    b2, per2, _ = step(tr, 20, nt(a=(1, "203.0.113.1:443", 500, 100)), (10 ** 9 + 16200000 + 540, 10 ** 8 + 2000))
    check(per2 == {1: [500, 0]}, "deltas: a counter that went down is a new connection on the same addresses: its whole "
          "count")
    step(tr, 30, None, (10 ** 9 + 2 * 10 ** 7, 10 ** 8 + 3000), complete=False)
    b4, per4, _ = step(tr, 40, nt(c=(3, "203.0.113.3:443", 9000000, 0)), (10 ** 9 + 3 * 10 ** 7, 10 ** 8 + 4000))
    b5, per5, _ = step(tr, 50, nt(c=(3, "203.0.113.3:443", 9000000 + 1000, 0)), (10 ** 9 + 3 * 10 ** 7 + 1080, 10 ** 8 + 4000))
    check(per4 == {} and b4["src"] == "if" and per5 == {3: [1000, 0]} and b5["src"] == "flows",
          "deltas: after a timed-out sample every flow is a baseline, counted from the next sample on")
    b6, per6, dt6 = step(tr, 250, nt(c=(3, "203.0.113.3:443", 9000000 + 5000, 0)), (10 ** 9 + 4 * 10 ** 7, 10 ** 8 + 4000))
    b7, per7, _ = step(tr, 260, nt(c=(3, "203.0.113.3:443", 9000000 + 6000, 0)), (10 ** 9 + 4 * 10 ** 7 + 1080, 10 ** 8 + 4000),
                       gap=True)
    check(per6 == {} and dt6 is None and "down_mbps" not in b6 and per7 == {} and "down_mbps" not in b7,
          "deltas: no rates over more than 120 s, nor across a gap the logger reports")
    tl = T.Traffic()
    step(tl, 0, nt(a=(1, "203.0.113.1:443", 0, 0), n=(9, "192.168.178.50:445", 0, 0)), (0, 0))
    bl, perl, _ = step(tl, 10, nt(a=(1, "203.0.113.1:443", 1000000, 0), n=(9, "192.168.178.50:445", 50000000, 0)),
                       (round(50000000 * 1.08) + 1161000, 1500000))
    check(perl == {1: [1000000, 0]} and bl["lan_mbps"] == 40.0 and bl["down_mbps"] == 0.86 and bl["up_mbps"] == 0,
          "the LAN: a NAS's 50 MB are lan_mbps, never internet; the interface's bytes less the LAN's wire bytes (× 1.08, "
          "and its ACKs the other way), by 1.08, are the internet's payload when more than the flows (%s)" % {
              k: bl.get(k) for k in ("down_mbps", "up_mbps", "lan_mbps")})
    # a backup to a NAS alone: 1.1 GB up in 10 s, 8 % wire overhead, 2 % of ACKs coming back
    tn = T.Traffic()
    step(tn, 0, nt(n=(9, "192.168.178.50:445", 0, 0)), (10 ** 9, 10 ** 9))
    bn, pern, _ = step(tn, 10, nt(n=(9, "192.168.178.50:445", 0, 1100000000)),
                       (10 ** 9 + 22000000, 10 ** 9 + round(1100000000 * 1.08)))
    check(bn["up_mbps"] <= 1 and bn["down_mbps"] <= 1 and pern == {} and bn["in_gb"] == 0 and bn["out_gb"] == 0 and
          bn["lan_mbps"] == 880.0,
          "the LAN at the wire's scale: a NAS backup of 1.1 GB with its overhead and ACKs reads no internet either way "
          "and adds nothing to the day's GB (%s)" % {k: bn.get(k) for k in ("down_mbps", "up_mbps", "in_gb", "out_gb")})

    # a randomized check: Σ per process ≤ the flows ≤ the total, whatever the counters do
    rnd, worst = random.Random(7), []
    tr = T.Traffic()
    flows = {i: [i % 4 + 1, "203.0.113.%d:443" % i if i % 3 else "192.168.178.%d:445" % (i + 2), 0, 0] for i in range(12)}
    wire = [0, 0]
    for k in range(60):
        for f in flows.values():
            if rnd.random() < 0.1:
                f[2], f[3] = rnd.randrange(0, 10 ** 6), rnd.randrange(0, 10 ** 5)   # reused tuple: counters restart
            else:
                f[2] += rnd.randrange(0, 10 ** 7)
                f[3] += rnd.randrange(0, 10 ** 6)
        wire[0] += rnd.randrange(0, 3 * 10 ** 8)
        wire[1] += rnd.randrange(0, 3 * 10 ** 7)
        out = [",interface,state,bytes_in,bytes_out,"]
        for i, (pid, remote, bi, bo) in flows.items():
            if rnd.random() < 0.9:
                out.append("p.%d,,,0,0," % pid)
                out.append("tcp4 192.168.178.42:%d<->%s,en16,Established,%d,%d," % (30000 + i, remote, bi, bo))
        b, per, dt = step(tr, 10 * k, ("\n".join(out) + "\n").encode(), tuple(wire),
                          complete=rnd.random() > 0.05, gap=rnd.random() < 0.03)
        if dt:
            sd, su = sum(x[0] for x in per.values()) * 8 / dt / 1e6, sum(x[1] for x in per.values()) * 8 / dt / 1e6
            if sd > b["down_mbps"] + 0.01 or su > b["up_mbps"] + 0.01:
                worst.append((k, round(sd, 2), b["down_mbps"]))
    check(not worst, "the sum per process never exceeds the internet total, over 60 random samples with restarts, "
          "timeouts and gaps %s" % worst[:3])

    # the probe's saturated line (mac-3): flows 195.6 against a wire of 211.6 Mbit/s over 2 s
    tq = T.Traffic()
    step(tq, 0, nt(q=(1, "203.0.113.1:443", 0, 0)), (0, 0))
    bq, _, _ = step(tq, 2, nt(q=(1, "203.0.113.1:443", 48900000, 10450000)), (52900000, 11075000))
    check(bq["down_mbps"] == 195.6 and bq["up_mbps"] == 41.8,
          "a saturated line: 195.6 Mbit/s of flows against 211.6 on the wire, less the upload's ACKs, reads the flows' "
          "195.6 (the wire's payload alone 194.9), the uplink the flows' 41.8 (%s)" % {
              k: bq.get(k) for k in ("down_mbps", "up_mbps")})
    check(bq["in_gb"] == 0.049 and bq["out_gb"] == 0.01 and bq["network"] == "rmac:00:00:5e:00:53:03",
          "the day's internet bytes on this network: in_gb, out_gb (%s, %s)" % (bq.get("in_gb"), bq.get("out_gb")))

    # a flow far bigger than what the interface moved (a planted or misread counter) is cut to it, per process alike
    tc = T.Traffic()
    step(tc, 0, nt(z=(3, "203.0.113.4:443", 0, 0)), (10 ** 6, 10 ** 6), complete=True)
    bc, perc, dtc = step(tc, 10, nt(z=(3, "203.0.113.4:443", 0, 0), a=(1, "203.0.113.1:443", 10 ** 12, 0)),
                         (10 ** 6 + 1000, 10 ** 6))
    check(bc["down_mbps"] < 1.0 and perc[1][0] <= 1000 * T.WIRE_CAP_X + T.WIRE_CAP_B and "in_gb" in bc and
          bc["in_gb"] < 0.01,
          "a new flow of 1 TB against 1000 bytes on the wire reads at most the wire (%s Mbit/s, %s bytes)" % (
              bc["down_mbps"], perc.get(1)))
    td = T.Traffic()
    dup = ("p.1,,,0,0,\ntcp4 192.168.178.42:1<->203.0.113.1:443,en16,Established,%d,0,\n"
           "tcp4 192.168.178.42:1<->203.0.113.1:443,en16,Established,%d,0,\n")
    step(td, 0, (",interface,state,bytes_in,bytes_out,\n" + dup % (0, 0)).encode(), None)
    bd, perd, _ = step(td, 10, (",interface,state,bytes_in,bytes_out,\n" + dup % (1000, 900000)).encode(), None)
    check(perd == {1: [1000, 0]}, "two rows under one key: the first counts (%s)" % perd)
    # nettop's own pid keys a flow: a process started between the process table and nettop is not counted twice
    tk, tp_late = T.Traffic(), {k: v for k, v in tp.items() if k != 2}
    late = lambda bi: nt(a=(1, "203.0.113.1:443", 0, 0), b=(2, "203.0.113.2:443", bi, 0))  # noqa: E731
    tk.step(0, 1795600000, EG, None, T.nettop_flows(late(0), tp, ONLINK, "en16")[0][:1], True, tp, None)
    f1 = T.nettop_flows(late(5000), tp_late, ONLINK, "en16")[0]
    _, pk1, _ = tk.step(10, 1795600010, EG, None, f1, True, tp_late, None)
    _, pk2, _ = tk.step(20, 1795600020, EG, None, T.nettop_flows(late(6000), tp, ONLINK, "en16")[0], True, tp, None)
    check(2 not in pk1 and pk2.get(2) == [1000, 0],
          "a process new to the table keeps its flow's key: the bytes counted unattributed are not counted again (%s)" % pk2)

    # Linux (ss): loopback, a docker bridge and a LAN NAS are not the internet; the wire less the LAN's own
    lsp = {7: P(7, "curl", 1001), 8: P(8, "postgres", 1001), 9: P(9, "docker-proxy", 0)}
    LEG = {"if": "eth0", "tun": None, "gw": "192.168.178.1", "subnet": "192.168.178.0/24", "addrs": ["192.168.178.30"]}

    def ssl(curl, lo, nas, dock):
        return ("ESTAB 0 0 192.168.178.30:40000 203.0.113.7:443 users:((\"curl\",pid=7,fd=5)) uid:1001 ino:1 sk:a1 <-> "
                "bytes_acked:1 bytes_received:%d\n"
                "ESTAB 0 0 127.0.0.1:5432 127.0.0.1:40001 users:((\"postgres\",pid=8,fd=5)) uid:1001 ino:2 sk:a2 <-> "
                "bytes_acked:%d bytes_received:1\n"
                "ESTAB 0 0 127.0.0.1:40001 127.0.0.1:5432 ino:3 sk:a3 <-> bytes_acked:1 bytes_received:%d\n"
                "ESTAB 0 0 192.168.178.30:40002 192.168.178.50:445 ino:4 sk:a4 <-> bytes_acked:1 bytes_received:%d\n"
                "ESTAB 0 0 172.17.0.1:40003 172.17.0.2:80 users:((\"docker-proxy\",pid=9,fd=5)) ino:5 sk:a5 <-> "
                "bytes_acked:1 bytes_received:%d\n" % (curl, lo, lo, nas, dock)).encode()

    tlx = T.Traffic()
    on_l = T.onlink_nets(["192.168.178.0/24"])
    tlx.step(0, 1795600000, LEG, (10 ** 9, 10 ** 8), T.ss_flows(ssl(0, 0, 0, 0), lsp, on_l, LEG)[0], True, lsp, None)
    fl = T.ss_flows(ssl(10 ** 8, 2 * 10 ** 9, 5 * 10 ** 7, 3 * 10 ** 9), lsp, on_l, LEG)[0]
    blx, plx, _ = tlx.step(30, 1795600030, LEG, (10 ** 9 + round(4.5 * 10 ** 8 * 1.08), 10 ** 8 + 1000), fl, True, lsp,
                           None)
    check(abs(blx["down_mbps"] - 106.67) < 0.01 and blx["lan_mbps"] == 13.33 and plx == {7: [10 ** 8, 0]} and
          blx["src"] == "flows",
          "Linux: 2 GB over loopback and 3 GB over a docker bridge are not the device's; 400 MB of internet read "
          "(wire − the NAS's 50 MB × 1.08) / 1.08 = 106.7 Mbit/s, curl's 100 MB attributed (%s)" % {
              k: blx.get(k) for k in ("down_mbps", "lan_mbps")})
    VEG = dict(LEG, tun="wg0", tun_addrs=["10.8.0.2"])
    lsp[10] = P(10, "git", 1001)
    vpn_ss = lambda n, corp: ("ESTAB 0 0 10.8.0.2:40000 203.0.113.7:443 users:((\"curl\",pid=7,fd=5)) uid:1001 ino:1 "  # noqa: E731
                              "sk:b1 <-> bytes_acked:1 bytes_received:%d\n"
                              "ESTAB 0 0 10.8.0.2:40001 10.20.0.5:22 users:((\"git\",pid=10,fd=5)) uid:1001 ino:2 "
                              "sk:b2 <-> bytes_acked:1 bytes_received:%d\n"
                              % (n, corp)).encode()
    tvx = T.Traffic()
    tvx.step(0, 1795600000, VEG, (0, 0), T.ss_flows(vpn_ss(0, 0), lsp, on_l, VEG)[0], True, lsp, None)
    bvx, pvx, _ = tvx.step(10, 1795600010, VEG, (11 * 10 ** 6, 10 ** 5), T.ss_flows(vpn_ss(10 ** 7, 10 ** 6), lsp, on_l,
                                                                                         VEG)[0], True, lsp, None)
    check(pvx == {7: [10 ** 7, 0], 10: [10 ** 6, 0]} and bvx["vpn"] is True and bvx["lan_mbps"] == 0 and
          bvx["down_mbps"] == 8.8,
          "Linux under WireGuard: the tunnel's flows attributed (curl), a corporate 10.x host's through the tunnel too "
          "(git): it is internet, not the physical device's LAN (%s, %s)" % (
              {k: bvx.get(k) for k in ("down_mbps", "lan_mbps")}, pvx))
    tpx = T.Traffic()   # the same flow on the physical device, no VPN: the LAN's
    tpx.step(0, 1795600000, LEG, (0, 0), T.ss_flows(vpn_ss(0, 0).replace(b"10.8.0.2", b"192.168.178.30"), lsp,
                                                     T.onlink_nets(["10.20.0.0/24"]), LEG)[0], True, lsp, None)
    bpx, ppx, _ = tpx.step(10, 1795600010, LEG, (11 * 10 ** 6, 10 ** 5), T.ss_flows(
        vpn_ss(10 ** 7, 10 ** 6).replace(b"10.8.0.2", b"192.168.178.30"), lsp, T.onlink_nets(["10.20.0.0/24"]), LEG)[0],
        True, lsp, None)
    check(ppx == {7: [10 ** 7, 0]} and bpx["lan_mbps"] == 0.8,
          "without a VPN the same 10.x host on the physical device is the LAN's: not attributed (%s, %s)" % (bpx, ppx))
    # a pure download reads (almost) no upload: the ACKs it causes are not upload payload
    tax = T.Traffic()
    tax.step(0, 1795600000, LEG, (0, 0), [], True, lsp, None)
    bax, _, _ = tax.step(10, 1795600010, LEG, (round(10 ** 8 * T.WIRE_X), round(10 ** 8 * T.ACK_X)), [], True, lsp,
                         None)
    check(bax["down_mbps"] == 80.0 and bax["up_mbps"] == 0,
          "a download of 100 MB in 10 s (its wire bytes and its ACKs the other way) reads 80 Mbit/s down, 0 up (%s)"
          % {k: bax.get(k) for k in ("down_mbps", "up_mbps")})
    # an accepted socket keeps its listener's owner (root): sshd's session child serving scp is still attributed
    sshp = {11: P(11, "sshd", 1001)}
    acc = (b'ESTAB 0 0 192.168.178.30:22 203.0.113.9:50000 users:(("sshd",pid=11,fd=4)) ino:9 sk:c1 <-> '
           b'bytes_acked:5000 bytes_received:10\n'
           b'ESTAB 0 0 192.168.178.30:22 203.0.113.9:50001 users:(("sshd",pid=11,fd=4)) uid:1002 ino:9 sk:c2 <-> '
           b'bytes_acked:5000 bytes_received:10\n')
    check([r[0] for r in T.ss_flows(acc, sshp, on_l, LEG)[0]] == [11, None],
          "ss: a root-owned (accepted) socket keeps its process (sshd's session child); another user's uid does not")

    # --- the Sampler, with a stand-in backend: VPN, backoff, names
    class FakeNet:
        NET_FLOWS = "nettop"

        def __init__(self):
            self.eg = dict(EG, onlink=["192.168.178.0/24"])
            self.wire, self.data, self.why, self.calls = (0, 0), nt(a=(1, "203.0.113.1:443", 0, 0)), None, 0
            self.mac, self.mac6 = "0:0:5e:0:53:3", None

        def net_route(self):
            return dict(self.eg)

        def net_bytes(self, ifname):
            return self.wire

        def net_flows(self, tun=None):
            self.calls += 1
            self.tun_asked = tun
            return (self.data, None) if self.why is None else (None, self.why)

        def host_secret(self):
            return "0123456789abcdef0123456789abcdef"

        def router_mac(self, gw, ifname):
            return self.mac

        def router_mac6(self, ifname):
            return self.mac6

    fk = FakeNet()
    sm = T.Sampler(fk)
    sm.read(tp, now=1795600000)
    fk.why = "timeout"
    blk, _, _ = sm.read(tp, now=1795600010)
    calls = fk.calls
    blk2, _, _ = sm.read(tp, now=1795600020)
    check(blk["src"] == "if" and sm.status == "too many connections" and fk.calls == calls and sm.backoff == 300 and
          blk2["src"] == "if", "the cost guard: a nettop that timed out makes the sample totals only and is not run "
          "again for 5 minutes (daemon.net: too many connections)")
    sm.off_until, fk.why = 0, "columns"
    sm.read(tp, now=1795600025)
    st_cols = sm.status
    fk.why = None
    sm.read(tp, now=1795600030)
    fk.why = "exit 1"
    sm.read(tp, now=1795600027)
    st_exit = sm.status
    check(st_exit == "nettop failed (exit 1)", "a nettop (or ss) that exits non-zero is named, not read (%s)" % st_exit)
    fk.why = None
    sm.read(tp, now=1795600028)
    check(st_cols == "nettop failed (columns)" and sm.status is None and sm.backoff == 0,
          "the cost guard: a nettop that fails otherwise after the pause names that (%s); one that answers again "
          "clears it" % st_cols)
    fk.eg = dict(EG, tun="utun4", onlink=["192.168.178.0/24"])
    fk.data = (",interface,state,bytes_in,bytes_out,\nb.2,,,0,0,\n"
               "tcp4 10.8.0.2:5000<->203.0.113.9:443,utun4,Established,100000,0,\n"
               "vpnclient.3,,,0,0,\ntcp4 192.168.178.42:5001<->198.51.100.1:51820,en16,Established,120000,0,\n").encode()
    sm.read(tp, now=1795600040)
    fk.data = fk.data.replace(b",100000,", b",1100000,").replace(b",120000,", b",1200000,")
    bv, pv, dv = sm.read(tp, now=1795600050)
    check(bv["vpn"] is True and bv["tun"] == "utun4" and bv["if"] == "en16" and pv == {2: [1000000, 0]} and
          fk.tun_asked == "utun4",
          "a VPN: the physical interface's counters and identity, the tunnel's flows attributed (nettop asked for "
          "every interface: -t external leaves utun out), the VPN client's outer flow on en16 not (the same bytes "
          "twice)")

    # --- identity (12.6)
    idt, eg1 = T.Identity(), dict(EG)
    fk.mac = "0:0:5e:0:53:3"
    a1 = idt.get(fk, eg1, 0)
    fk.mac = None
    a2 = idt.get(fk, eg1, 10 ** 6)
    fk.mac6 = "00:00:5e:00:53:03"
    i2 = T.Identity()
    b6_ = i2.get(fk, eg1, 0)
    fk.mac6 = None
    i3 = T.Identity()
    c1 = i3.get(fk, eg1, 0)
    fk.mac = "00:00:5e:00:53:07"
    c2 = i3.get(fk, eg1, 300)
    c3 = i3.get(fk, eg1, 700)
    c4 = i3.get(fk, dict(eg1, gw="192.168.1.1", subnet="192.168.1.0/24"), 800)
    check(a1 == "rmac:00:00:5e:00:53:03" and a2 == a1 and b6_ == a1 and c1 == "gw:192.168.178.1/24" and c2 == c1 and
          c3 == "rmac:00:00:5e:00:53:07" and c4 == "rmac:00:00:5e:00:53:07",
          "identity: the router's MAC zero-padded (arp prints 0:0:5e:0:53:3) and sticky while interface, gateway and "
          "subnet stay; else the IPv6 router's (NDP); else gw:<gateway>/<prefix>, asked again after 10 minutes")
    # another router behind the same interface, gateway and subnet (two FRITZ!Boxes): found at the next re-read or
    # after a gap; a cache miss keeps the router found
    i8 = T.Identity()
    fk.mac, fk.mac6 = "00:00:5e:00:53:03", None
    h1 = i8.get(fk, eg1, 0)
    fk.mac = "00:00:5e:00:53:09"
    h2 = i8.get(fk, eg1, 300)
    h3 = i8.get(fk, eg1, 700)
    fk.mac = None
    h4 = i8.get(fk, eg1, 1400)
    fk.mac = "00:00:5e:00:53:03"
    h5 = i8.get(fk, eg1, 1500, gap=True)
    i9 = T.Identity()
    fk.mac = None
    i9.get(fk, eg1, 0)
    i9.adopt("rmac:00:00:5e:00:53:03", "gw:192.168.178.1/24", {"gw": "192.168.178.1", "subnet": "192.168.178.0/24"})
    fk.mac = "00:00:5e:00:53:0a"
    h6 = i9.get(fk, eg1, 700)
    check(h1 == "rmac:00:00:5e:00:53:03" and h2 == h1 and h3 == "rmac:00:00:5e:00:53:09" and h4 == h3 and h5 == h1 and
          h6 == "rmac:00:00:5e:00:53:0a" and not i9.taken,
          "identity: another router on the same interface, gateway and subnet is found after 10 minutes or after a "
          "gap (sleep), an adopted key gives way to the MAC found; a cache miss keeps the router (%s)" % [
              h1, h2, h3, h4, h5, h6])
    check(T.norm_mac("(incomplete)") is None and T.norm_mac("0:0:0:0:0:0") is None and T.norm_mac("ff:ff:ff:ff:ff:ff")
          is None and T.norm_mac("3C:A6:2F:1:2:3") == "3c:a6:2f:01:02:03",
          "identity: an incomplete, all-zero or broadcast entry is no MAC")
    nets_r = {"rmac:00:00:5e:00:53:03": {"gw": "192.168.178.1", "subnet": "192.168.178.0/24", "down": 100.0}}
    nets_g = {"gw:192.168.178.1/24": {"down": 100.0}}
    check(T.resolve(nets_r, "gw:192.168.178.1/24", "192.168.178.1", "192.168.178.0/24") == "rmac:00:00:5e:00:53:03" and
          T.resolve(nets_r, "gw:192.168.1.1/24", "192.168.1.1", "192.168.1.0/24") == "gw:192.168.1.1/24" and
          T.resolve(nets_g, "rmac:00:00:5e:00:53:03", "192.168.178.1", "192.168.178.0/24") == "rmac:00:00:5e:00:53:03" and
          T.resolve(nets_g, "rmac:00:00:5e:00:53:99", "192.168.178.1", "192.168.178.0/24") == "rmac:00:00:5e:00:53:99",
          "identity: a gw: key takes the rmac entry of its gateway and subnet (a cache miss makes no new network); an "
          "rmac key never takes a gw: entry (every FRITZ!Box is 192.168.178.1/24: another router would take it)")
    G = "gw:192.168.178.1/24"
    i4 = T.Identity()
    i4.get(fk if setattr(fk, "mac", None) is None else fk, eg1, 0)
    i4.adopt("rmac:00:00:5e:00:53:03", "gw:192.168.1.1/24")          # an answer about another network
    other_ = i4.id
    i4.adopt("rmac:00:00:5e:00:53:03", G, {"gw": "192.168.1.1", "subnet": "192.168.1.0/24", "down": 5.0})
    wrong_gw = i4.id
    i4.adopt("rmac:00:00:5e:00:53:03", G, {"gw": "192.168.178.1", "subnet": "192.168.178.0/24", "down": 5.0})
    fk.mac = "00:00:5e:00:53:03"
    i5 = T.Identity()
    r5_ = i5.get(fk, eg1, 0)
    i5.adopt(G, "rmac:00:00:5e:00:53:03")
    r6_ = i5.get(fk, eg1, 5000)
    r7_ = i5.get(fk, dict(eg1, gw="192.168.1.1", subnet="192.168.1.0/24"), 5010)
    i5.adopt("../x", r7_)
    check(other_ == G and wrong_gw == G and i4.id == "rmac:00:00:5e:00:53:03" and r5_ == "rmac:00:00:5e:00:53:03" and
          r6_ == "rmac:00:00:5e:00:53:03" and r7_ == "rmac:00:00:5e:00:53:03" and i5.id == r7_,
          "identity: a gw: identity takes over the rmac key the ledger child names for it (sticky until interface, "
          "gateway or subnet change); not an answer about another network, nor an entry of another gateway; an rmac "
          "identity takes no gw: key; never a key that is not one")
    # after a move, an answer about the network left (a failed or slow child) does not rename the new one
    fk.mac = None
    i6 = T.Identity()
    ga = i6.get(fk, eg1, 0)
    ans_a = {"asked": ga, "key": "rmac:00:00:5e:00:53:03", "entry": {"gw": "192.168.178.1", "subnet": "192.168.178.0/24"}}
    egb = dict(eg1, gw="172.20.0.1", subnet="172.20.0.0/16", **{"if": "en0"})
    gb = i6.get(fk, egb, 30)
    i6.adopt(ans_a["key"], ans_a["asked"], ans_a["entry"])
    egc = dict(eg1, gw="10.0.0.1", subnet="10.0.0.0/24")
    i7 = T.Identity()
    i7.get(fk, eg1, 0)
    i7.get(fk, egc, 30)
    i7.adopt("rmac:00:00:5e:00:53:03", "gw:192.168.178.1/24", ans_a["entry"])
    check(i6.id == gb and i7.id == "gw:10.0.0.1/24",
          "identity: after a move (another interface, gateway or subnet) the child's answer about the network left is "
          "not taken over (%s, %s)" % (i6.id, i7.id))
    # two routers sending router advertisements (the FRITZ!Box and a HomePod as a Thread border router): only the
    # IPv4 gateway's ARP entry moves an rmac identity; the IPv6 default router's names a network none names yet
    ia = T.Identity()
    fk.mac, fk.mac6 = "00:00:5e:00:53:03", "00:00:5e:00:53:0b"
    k1 = ia.get(fk, eg1, 0)
    fk.mac = None
    k2 = ia.get(fk, eg1, 700)
    fk.mac = "00:00:5e:00:53:03"
    k3 = ia.get(fk, eg1, 1400)
    fk.mac = None
    k4 = ia.get(fk, eg1, 2100, gap=True)
    ib = T.Identity()
    k5 = ib.get(fk, eg1, 0)
    fk.mac = "00:00:5e:00:53:03"
    k6 = ib.get(fk, eg1, 700)
    check(k1 == k2 == k3 == k4 == "rmac:00:00:5e:00:53:03" and k5 == "rmac:00:00:5e:00:53:0b" and k6 == k1,
          "identity: an ARP miss with another IPv6 router keeps the gateway's MAC (no flip at each re-read); NDP "
          "names a network only while no router is known, the gateway's ARP entry then takes over (%s)" % [
              k1, k2, k3, k4, k5, k6])
    # none found (IPv6 only, point to point): not asked again every sample
    class CountNet(FakeNet):
        def router_mac6(self, ifname):
            self.n6 = getattr(self, "n6", 0) + 1
            return None
    cn = CountNet()
    cn.mac = None
    ic = T.Identity()
    eg0 = dict(eg1, gw=None, subnet=None)
    n0 = [ic.get(cn, eg0, t) for t in (0, 30, 60, 590)]
    asked = cn.n6
    ic.get(cn, eg0, 700)
    check(n0 == [None] * 4 and asked == 1 and cn.n6 == 2,
          "identity: none found is kept for 10 minutes like one found (one ndp or ip -6 neigh, not one per sample)")
    # the IPv6 default router's entry, not the router with the most entries (macOS: route -inet6 + ndp -an)
    ndp = (b"Neighbor                                Linklayer Address  Netif Expire    St Flgs Prbs\n"
           b"2001:db8:0:1::b1                        0:0:5e:0:53:b      en16 23h59m58s S  R\n"
           b"fd00:db8:1::b2                          0:0:5e:0:53:b      en16 23h59m58s S  R\n"
           b"fe80::200:5eff:fe00:530b%en16           0:0:5e:0:53:b      en16 8s        R  R\n"
           b"fe80::200:5eff:fe00:5303%en16           0:0:5e:0:53:3      en16 8s        R  R\n"
           b"fe80::200:5eff:fe00:5303%en0            0:0:5e:0:53:9      en0  8s        R  R\n")
    rt6 = b"   route to: ::\ndestination: ::\n       mask: default\n    gateway: fe80::200:5eff:fe00:5303%en16\n" \
          b"  interface: en16\n"
    if MAC:
        import oomph_darwin as D6
        real_rc = D6.run_capped
        argv6 = []
        nobody6 = {}
        D6.run_capped = lambda cmd, *a, **k: (argv6.append(cmd), nobody6.__setitem__(cmd[0], bool(k.get("as_nobody"))),
                                              rt6 if "route" in cmd[0] else ndp)[2]
        try:
            m6 = D6.router_mac6("en16")
            D6.run_capped = lambda cmd, *a, **k: b"" if "route" in cmd[0] else ndp
            m6none = D6.router_mac6("en16")
            arp4 = b"? (192.168.178.1) at 0:0:5e:0:53:3 on en16 ifscope [ethernet]\n"
            D6.run_capped = lambda cmd, *a, **k: (nobody6.__setitem__(cmd[0], bool(k.get("as_nobody"))), arp4)[1]
            m4 = D6.router_mac("192.168.178.1", "en16")
        finally:
            D6.run_capped = real_rc
        # macOS 26/27 shows a caller other than root no neighbour entry (arp: "no entry"; ndp: only its own
        # addresses, with 2:0:0:0:0:0): arp and ndp run as the logger's root, route as nobody
        check(T.norm_mac(m4) == "00:00:5e:00:53:03" and nobody6 == {"/sbin/route": True, "/usr/sbin/ndp": False,
                                                                     "/usr/sbin/arp": False} and
              T.norm_mac("2:0:0:0:0:0") is None,
              "macOS: arp and ndp run as the logger's root (current macOS hides the neighbour caches from anyone "
              "else), route as nobody; 02:00:00:00:00:00 (the MAC macOS shows instead) is no router (%s)" % nobody6)
        D6.run_capped = lambda cmd, *a, **k: (b"" if cmd[3] == "1.1.1.1" else
                                              b"  interface: en16\n    gateway: fe80::200:5eff:fe00:5303%en16\n"
                                              if "-inet6" in cmd else b"")
        try:
            v6only = D6.net_route()
        finally:
            D6.run_capped = real_rc
        dn = T.doctor_line({"daemon": {"net": "too many connections"}})
        check(dn[1] == "note" and "too many connections" in dn[2] and T.doctor_line({"daemon": {}})[1] == "ok",
              "doctor on macOS: the logger's totals-only state (too many connections, nettop failing) is a note, not "
              "ok (%s)" % (dn,))
        check(v6only and v6only["if"] == "en16" and v6only["gw"] is None and v6only["tun"] is None,
              "macOS: IPv6 only (no IPv4 route) is online: the IPv6 route's interface, no IPv4 gateway (%s)" % v6only)
        check(T.norm_mac(m6) == "00:00:5e:00:53:03" and m6none is None and
              argv6[0] == ["/sbin/route", "-n", "get", "-inet6", "-ifscope", "en16", "default"],
              "macOS: the IPv6 router is the default route's (route -n get -inet6 -ifscope), its entry in ndp -an on "
              "that interface; not the router with the most entries (%s)" % m6)
    lrc, lip, lnd = oomph_linux.run_capped, oomph_linux._ip, oomph_linux._netdir
    lr6 = (b"default via fe80::200:5eff:fe00:530b dev enp1s0f0 proto ra metric 1024 expires 1454sec pref medium\n"
           b"default via fe80::200:5eff:fe00:5303 dev enp1s0f0 proto ra metric 100 expires 1454sec pref medium\n")
    ln6 = (b"fe80::200:5eff:fe00:530b lladdr 00:00:5e:00:53:0b router REACHABLE\n"
           b"2001:db8:0:1::b1 lladdr 00:00:5e:00:53:0b router STALE\n"
           b"fe80::200:5eff:fe00:5303 lladdr 00:00:5e:00:53:03 router STALE\n")
    oomph_linux._ip, oomph_linux._netdir = (lambda: "/sbin/ip"), (lambda: "/proc/net")
    oomph_linux.run_capped = lambda cmd, *a, **k: lr6 if "route" in cmd else ln6
    try:
        lm6 = oomph_linux.router_mac6("enp1s0f0")
        bad = [oomph_linux._ifname_ok(x) for x in (".", "..", "a/b", "", None, "enp1s0f0", "wg0", "br-1.2")]
    finally:
        oomph_linux.run_capped, oomph_linux._ip, oomph_linux._netdir = lrc, lip, lnd
    check(lm6 == "00:00:5e:00:53:03" and bad == [False] * 5 + [True] * 3,
          "Linux: the IPv6 router is the lowest-metric default's (ip -6 route), its entry in ip -6 neigh, not the "
          "first router listed; a device name for a /sys path is never '.', '..' or has a '/' (%s)" % lm6)
    lwhy = []
    lpart = oomph_linux.run_capped(["/bin/sh", "-c", "echo partial; exit 3"], 1 << 20, 5, as_root=True, why=lwhy)
    check(lpart is None and lwhy == ["exit 3"],
          "Linux: an ss that exits non-zero (an iproute2 refusing -e or -O, a security policy) says so: 'ss failed "
          "(exit 3)', not missing (%s)" % lwhy)
    # a VPN coming up on an existing utun is a baseline: the tunnel's flows, never listed before, are not new
    tv = T.Traffic()
    VEG_ = dict(EG, tun="utun4")
    f0 = [(1, 101, "phys", False, 5000, 0)]
    f1 = [(1, 101, "phys", False, 6000, 0), (2, 202, "tun", False, 9 * 10 ** 8, 0)]
    f2 = [(1, 101, "phys", False, 7000, 0), (2, 202, "tun", False, 9 * 10 ** 8 + 1000, 0)]
    tv.step(0, 1795600000, EG, (10 ** 9, 10 ** 8), f0, True, tp, "rmac:00:00:5e:00:53:03")
    bt1, pt1, _ = tv.step(10, 1795600010, VEG_, (10 ** 9 + 2 * 10 ** 9, 10 ** 8), f1, True, tp, "rmac:00:00:5e:00:53:03")
    bt2, pt2, _ = tv.step(20, 1795600020, VEG_, (10 ** 9 + 2 * 10 ** 9 + 1080, 10 ** 8), f2, True, tp,
                          "rmac:00:00:5e:00:53:03")
    check(pt1 == {} and "down_mbps" not in bt1 and pt2 == {2: [1000, 0]},
          "deltas: a tunnel that comes (or goes, or moves) is a baseline like another interface: its long-lived flows "
          "are not counted whole (%s)" % pt1)
    # the day's counters: marked where an interval held the LAN's traffic, carried over when the identity is adopted
    sa = T.Sampler(fk)
    sa.traffic.day["gw:192.168.178.1/24"] = [T._date(1795600000), 5e9, 1e9, True]
    sa.ident.tup, sa.ident.id, sa.ident.at = (EG["if"], EG["gw"], EG["subnet"]), "gw:192.168.178.1/24", 1795600000
    sa.adopt("rmac:00:00:5e:00:53:03", "gw:192.168.178.1/24", {"gw": "192.168.178.1", "subnet": "192.168.178.0/24"})
    sg = T.Sampler(fk)   # the identity itself moves from gw: to rmac: (the ARP entry found at a later re-read)
    sg.traffic.day["gw:192.168.178.1/24"] = [T._date(1795600000), 4e9, 1e9, False]
    sg.ident.tup, sg.ident.id, sg.ident.at = (fk.eg["if"], fk.eg["gw"], fk.eg["subnet"]), "gw:192.168.178.1/24", \
        1795600000
    fk_mac, fk.mac = fk.mac, "0:0:5e:0:53:3"
    sg.read(tp, now=1795600000 + T.IDENT_S + 1)
    fk.mac = fk_mac
    check(sg.ident.id == "rmac:00:00:5e:00:53:03" and "gw:192.168.178.1/24" not in sg.traffic.day and
          sg.traffic.day.get("rmac:00:00:5e:00:53:03", [0, 0])[1] >= 4e9,
          "the day's counters: carried along when the identity finds the router's MAC later (gw: to rmac:, same "
          "interface, gateway and subnet)")
    so = T.Sampler(fk)   # an answer that arrives after the network went offline changes nothing, raises nothing
    so.ident.tup, so.ident.id, so.ident.at = (EG["if"], EG["gw"], EG["subnet"]), "gw:192.168.178.1/24", 1795600000
    fk_eg, fk.eg = fk.eg, {}
    so.read(tp, now=1795600000)
    fk.eg = fk_eg
    so.ident.id = "gw:192.168.178.1/24"   # even with the identity left from before
    so.adopt("rmac:00:00:5e:00:53:03", "gw:192.168.178.1/24", {"gw": "192.168.178.1", "subnet": "192.168.178.0/24"})
    check(so.ident.tup is None and so.ident.id == "gw:192.168.178.1/24",
          "the child's late answer about the network before going offline adopts nothing (and raises nothing)")
    td = T.Traffic()
    td.step(0, 1795600000, EG, (10 ** 9, 10 ** 8), None, False, tp, "rmac:00:00:5e:00:53:05")
    bd, _, _ = td.step(10, 1795600010, EG, (10 ** 9 + 10 ** 6, 10 ** 8), None, False, tp, "rmac:00:00:5e:00:53:05")
    check(sa.ident.id == "rmac:00:00:5e:00:53:03" and sa.traffic.day.get("rmac:00:00:5e:00:53:03", [0, 0])[1] == 5e9
          and "gw:192.168.178.1/24" not in sa.traffic.day and bd.get("day_src") == "if" and bd["in_gb"] > 0,
          "the day's counters: carried to the key networks.json keeps (a gw: identity adopting its rmac key); a day "
          "with intervals of totals only says so (day_src: if, the LAN's traffic in them)")

    check(T.onlink_nets(["0.0.0.0/0", "10.0.0.0/7", "::/0", "2001:db8::/31", "192.168.178.0/24", "2001:db8:0:1::/64",
                         "bogus"]) == T.onlink_nets(["192.168.178.0/24", "2001:db8:0:1::/64"]),
          "on-link prefixes: none wider than /8 (IPv4) or /32 (IPv6): a /0 would make the internet LAN")

    # --- the Linux backend on a recorded server (12.2)
    lroot = os.path.join(TMP, "sysroot")
    shutil.copytree(os.path.join(FX, "linux"), lroot)
    oomph_linux.ROOT = lroot
    try:
        le = oomph_linux.net_route()
        lb = oomph_linux.net_bytes("enp1s0f0")
        lm = oomph_linux.router_mac("192.168.178.1", "enp1s0f0")
        check(le == {"if": "enp1s0f0", "tun": None, "gw": "192.168.178.1", "subnet": "192.168.178.0/24",
                     "onlink": ["192.168.178.0/24", "2001:db8:0:1::11/64", "fd00:db8:1:0:200:5eff:fe00:5304/64"],
                     "addrs": ["fe80::200:5eff:fe00:5304", "2001:db8:0:1::11", "fd00:db8:1:0:200:5eff:fe00:5304"]}
              and lb == (98765432100, 12345678900) and T.norm_mac(lm) == "00:00:5e:00:53:13" and
              oomph_linux.net_flows() == (None, "missing"),
              "Linux: the egress from /proc/net/route (no ip for a recorded machine), its subnet and global IPv6 "
              "prefixes, the counters from /proc/net/dev, the router's MAC from /proc/net/arp; ss is not run for one")
        rt = os.path.join(lroot, "proc", "net", "route")
        with open(rt) as f:
            rlines = f.read().splitlines(True)
        with open(rt, "w") as f:  # a link-local route (NetworkManager, avahi) listed before the LAN's /24
            f.write("".join(rlines[:2] + ["enp1s0f0\t0000FEA9\t00000000\t0001\t0\t0\t1000\t0000FFFF\t0\t0\t0\n",
                                           "enp1s0f0\t01B2A8C0\t00000000\t0005\t0\t0\t100\tFFFFFFFF\t0\t0\t0\n"] +
                            rlines[2:]))
        arp = os.path.join(lroot, "proc", "net", "arp")
        with open(arp) as f:
            atext = f.read()
        with open(arp, "w") as f:  # a static gateway entry: complete and permanent (0x6)
            f.write(atext.replace("192.168.178.1    0x1         0x2 ", "192.168.178.1    0x1         0x6 "))
        check(oomph_linux.net_route()["subnet"] == "192.168.178.0/24" and
              T.norm_mac(oomph_linux.router_mac("192.168.178.1", "enp1s0f0")) == "00:00:5e:00:53:13" and
              oomph_linux.router_mac("192.168.178.62", "enp1s0f0") is None,
              "Linux: the subnet is the on-link route that holds the gateway (not a 169.254/16 one before it, not "
              "DHCP's host route to the gateway, as on the Epyc); a "
              "permanent ARP entry of the gateway counts, an incomplete one does not")
        with open(os.path.join(lroot, "proc", "net", "if_inet6"), "a") as f:
            f.write("fd000db8000200000000000000000002 07 40 00 80 wg0\n")
        with open(rt, "a") as f:
            f.write("wg0\t00000000\t00000000\t0001\t0\t0\t50\t00000000\t0\t0\t0\n")
        lv = oomph_linux.net_route()
        check(lv and lv["if"] == "enp1s0f0" and lv["tun"] == "wg0" and lv["gw"] == "192.168.178.1" and
              lv["tun_addrs"] == ["fd00:db8:2::2"],
              "Linux: a WireGuard default (type 65534) is a VPN over the physical device's default; the tunnel's addresses")
        pr = os.path.join(TMP, "sysroot-ppp")
        os.makedirs(os.path.join(pr, "proc", "net"))
        os.makedirs(os.path.join(pr, "sys", "class", "net", "ppp0"))
        with open(os.path.join(pr, "proc", "net", "route"), "w") as f:
            f.write(rlines[0] + "ppp0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\t0\t0\t0\n")
        with open(os.path.join(pr, "proc", "net", "dev"), "w") as f:
            f.write("h1\nh2\n    lo: 1 0 0 0 0 0 0 0 1 0 0 0 0 0 0 0\n  ppp0: 5000 9 0 0 0 0 0 0 700 9 0 0 0 0 0 0\n")
        with open(os.path.join(pr, "sys", "class", "net", "ppp0", "type"), "w") as f:
            f.write("512\n")
        oomph_linux.ROOT = pr
        lp = oomph_linux.net_route()
        check(lp and lp["if"] == "ppp0" and lp["tun"] is None and oomph_linux.net_bytes("ppp0") == (5000, 700),
              "Linux: PPPoE dialled on the machine itself (ppp0 the only default) is the line, not a VPN, not offline")
        v6r = os.path.join(TMP, "sysroot-v6")   # IPv6 only: no IPv4 default, the RA's default in ipv6_route
        os.makedirs(os.path.join(v6r, "proc", "net"))
        with open(os.path.join(v6r, "proc", "net", "route"), "w") as f:
            f.write(rlines[0])
        with open(os.path.join(v6r, "proc", "net", "ipv6_route"), "w") as f:
            f.write("00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                    "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"
                    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
                    "fe8000000000000002005efffe005303 00000400 00000001 00000000 00450003 enp1s0f0\n")
        with open(os.path.join(v6r, "proc", "net", "if_inet6"), "w") as f:
            f.write("20010db8000000010000000000000011 02 40 00 00 enp1s0f0\n")
        oomph_linux.ROOT = v6r
        l6 = oomph_linux.net_route()
        check(l6 and l6["if"] == "enp1s0f0" and l6["gw"] is None and l6["subnet"] is None and
              "2001:db8:0:1::11/64" in l6["onlink"],
              "Linux: IPv6 only (no IPv4 default) is online: the device of ipv6_route's default (not lo's unreachable "
              "one), no IPv4 gateway (%s)" % l6)
        ns = os.path.join(TMP, "sysroot-ns")
        os.makedirs(os.path.join(ns, "proc", "1"))
        shutil.copytree(os.path.join(FX, "linux", "proc", "net"), os.path.join(ns, "proc", "1", "net"))
        os.makedirs(os.path.join(ns, "proc", "net"))
        with open(os.path.join(ns, "proc", "net", "dev"), "w") as f:
            f.write(fx("linux/proc/net/dev", "r").split("enp1s0f0:")[0].rstrip(" ") + "\n")
        oomph_linux.ROOT = ns
        check(oomph_linux._netdir() == "/proc/1/net" and oomph_linux.net_bytes("enp1s0f0") == lb and
              (oomph_linux.net_route() or {}).get("if") == "enp1s0f0",
              "Linux, the service oomphd (PrivateNetwork: its /proc/net shows lo alone): the host's figures from /proc/1/net")
    finally:
        oomph_linux.ROOT = ""

    # --- networks.json (12.7)
    now = time.time()
    good = {"label": "home", "gw": "192.168.178.1", "subnet": "192.168.178.0/24", "down": 250.04, "up": 40.0,
            "source": "test", "set_by": "alice", "set": now - 60,
            "test": {"down": 262.1, "up": 41.7, "rpm": 812, "base_rtt": 9.0, "tool": "networkQuality", "t": now - 60},
            "metered": {"cap_gb": 20, "period": "month", "from_day": 14}, "later": "kept", "nested": {"x": 1}}
    v = T.valid_entry(good, now)
    check(v and v["down"] == 250.0 and v["later"] == "kept" and "nested" not in v and v["metered"]["from_day"] == 14,
          "networks.json: an entry keeps its known fields (figures to one decimal) and a later writer's scalars")
    bad_e = T.valid_entry(dict(good, label="ho\x1bme", gw="not-an-address", subnet="1.2.3.4", down=0.1, up=1e9,
                               source="guess", set_by="x y", set=now + 10 ** 6,
                               test={"rpm": -1, "tool": "speedtest"},
                               metered={"cap_gb": 20, "period": "month", "from_day": 32}), now)
    check(bad_e == {"metered": {"cap_gb": 20, "period": "month"}, "later": "kept"},
          "networks.json: each field that fails its limit is dropped (control characters in a label, an address, a "
          "CIDR, figures 0.5–100 000, the source, who, a time in the future, the test's, a day 1–31) %s" % bad_e)
    planted = {"rmac:00:00:5e:00:53:66": dict(good, set=now + 3600), "rmac:00:00:5e:00:53:03": dict(good, set=now - 60)}
    pv_, _ = T.valid_networks({"v": 1, "networks": planted}, now)
    check("set" not in pv_["rmac:00:00:5e:00:53:66"] and T.valid_entry(dict(good, set=now + 120), now)["set"] == now + 120
          and T.resolve(pv_, "gw:192.168.178.1/24", "192.168.178.1", "192.168.178.0/24") == "rmac:00:00:5e:00:53:03",
          "networks.json: a time more than 5 minutes ahead is dropped, so a planted entry of this gateway and subnet does "
          "not outrank the one set last")
    check(T.valid_entry({"down": 0.2}, now) is None and T.valid_entry({"label": "x" * 33}, now) is None and
          T.valid_key("rmac:00:00:5e:00:53:03") and T.valid_key("gw:192.168.178.1/24") and
          T.valid_key("gw:fe80::1/64") and not T.valid_key("gw:192.168.178.1/33") and not T.valid_key("rmac:0:0:5e:0:53:3")
          and not T.valid_key("rmac:00:00:5e:00:53:03:00") and not T.valid_key("../x") and not T.valid_key("gw:" + "1" * 80),
          "networks.json: an entry with nothing left is dropped; keys are rmac: and six two-digit pairs, or gw: an "
          "address /0–32 (/0–128 for IPv6), at most 80 characters")
    many_n = {"rmac:00:00:5e:00:%02x:%02x" % (i // 256, i % 256): {"down": 10.0 + i} for i in range(65)}
    vn, vb = T.valid_networks({"v": 1, "networks": dict(many_n, **{"rmac:bad": {"down": 1.0}})}, now)
    dup, db_ = T.valid_networks({"v": 1, "networks": {"rmac:00:00:5e:00:53:01": {"label": "Home", "down": 5.0},
                                                      "rmac:00:00:5e:00:53:02": {"label": "home", "down": 6.0}}}, now)
    check(len(vn) == 64 and vb == 2 and list(dup.values())[1].get("label") is None and db_ == 0 and
          T.valid_networks({"v": 2, "networks": {}}, now) == ({}, 1) and T.valid_networks(None, now) == ({}, 0),
          "networks.json: at most 64 entries (the 65th and an unreadable key counted), labels unique ignoring case, "
          "another version unreadable")

    # the writer, under the ledger lock (D-N10), and what is planted in the folder
    led = os.environ["OOMPH_LEDGER_DIR"]
    os.makedirs(led)
    os.chmod(led, 0o777)
    K = "rmac:00:00:5e:00:53:03"
    r1 = T.networks_edit("set", K, {"down": 176.4, "up": 42.3, "source": "test", "gw": "192.168.178.1",
                                    "subnet": "192.168.178.0/24",
                                    "test": {"down": 176.4, "up": 42.3, "rpm": 1100, "tool": "networkQuality"}})
    r2 = T.networks_edit("name", K, {"label": "home"})
    r3 = T.networks_edit("set", K, {"down": 250.0, "up": None, "source": "set"})
    st = os.stat(os.path.join(led, "networks.json"))
    rn = T.read_networks()["networks"]
    check(r1.get("ok") and r2.get("ok") and r3.get("ok") and rn[K]["down"] == 250.0 and rn[K]["up"] == 42.3 and
          rn[K]["label"] == "home" and rn[K]["prev"]["down"] == 176.4 and rn[K]["prev"]["source"] == "test" and
          "test" not in rn[K] and rn[K]["set_by"] and st.st_mode & 0o777 == 0o666 and
          not [n for n in os.listdir(led) if n.endswith(".tmp")],
          "networks.json written under the ledger lock by a new file renamed over the old (0666): a figure by "
          "hand replaces a test's (kept as prev), the other side stays, the label and who set it")
    r4 = T.networks_edit("name", "rmac:00:00:5e:00:53:04", {"label": "HOME"})
    r5 = T.networks_edit("forget", "rmac:00:00:5e:00:53:09")
    check(r4.get("code") == 2 and r5.get("code") == 1 and T.networks_edit("set", "../evil", {"down": 1}).get("code") == 2
          and T.networks_edit("set", "../evil", {"down": 1}).get("error") == "not a network: ../evil",
          "networks.json: a label in use (ignoring case) is refused (exit 2), forgetting what is not there says so, "
          "a key that is not one is refused")
    os.rename(os.path.join(led, "networks.json"), os.path.join(TMP, "networks.saved"))
    secret = os.path.join(TMP, "secret.json")
    with open(secret, "w") as f:
        json.dump({"v": 1, "networks": {K: {"down": 999.0}}}, f)
    os.chmod(secret, 0o666)
    os.symlink(secret, os.path.join(led, "networks.json"))
    via_link = T.read_networks()["networks"]
    os.unlink(os.path.join(led, "networks.json"))
    with open(os.path.join(led, "networks.json"), "w") as f:
        f.write(json.dumps({"v": 1, "networks": {K: {"down": 5.0, "label": "x" * 20}}}) + " " * (65 << 10))
    os.chmod(os.path.join(led, "networks.json"), 0o666)
    too_big = T.read_networks()["networks"]
    os.unlink(os.path.join(led, "networks.json"))
    os.rename(os.path.join(TMP, "networks.saved"), os.path.join(led, "networks.json"))
    check(via_link == {} and too_big == {} and T.read_networks()["networks"][K]["down"] == 250.0,
          "networks.json: a symbolic link planted in its place reads as none, so does a file over 64 KB")
    real_time, t0 = time.time, time.time() + 1
    try:   # each filler a second after K and the one before: the order is the clock's, not the machine's speed
        for i in range(70):
            time.time = lambda i=i: t0 + i
            T.networks_edit("set", "rmac:00:00:5e:01:00:%02x" % i, {"down": 10.0, "up": 1.0})
    finally:
        time.time = real_time
    nn = T.read_networks()
    check(len(nn["networks"]) == 64 and K not in nn["networks"] and "rmac:00:00:5e:01:00:45" in nn["networks"] and
          "rmac:00:00:5e:01:00:05" not in nn["networks"] and "rmac:00:00:5e:01:00:06" in nn["networks"],
          "networks.json: a write past 64 entries drops the one set longest ago")
    tie = {"rmac:00:00:5e:00:53:%02x" % i: {"down": 10.0, "set": round(now - 86400)} for i in range(63)}
    tie["rmac:00:00:5e:00:53:7f"] = {"down": 10.0, "label": "kept", "set": round(now - 86400)}
    with open(os.path.join(led, "networks.json"), "w") as f:
        json.dump({"v": 1, "networks": tie}, f)
    os.chmod(os.path.join(led, "networks.json"), 0o666)
    T.networks_edit("set", "rmac:00:00:5e:00:53:fe", {"down": 20.0})
    nt_ = T.read_networks()["networks"]
    check(len(nt_) == 64 and "rmac:00:00:5e:00:53:7f" in nt_ and "rmac:00:00:5e:00:53:fe" in nt_ and
          "rmac:00:00:5e:00:53:00" not in nt_,
          "networks.json: of entries set at the same time, one without a label goes first, never by the keys' order")
    saved_ = open(os.path.join(led, "networks.json")).read()
    with open(os.path.join(led, "networks.json"), "w") as f:   # a later oomph's file
        json.dump({"v": 2, "networks": {"ssid:abc": {"down": 5.0}}}, f)
    r_v2 = T.networks_edit("set", K, {"down": 9.0})
    v2_left = json.load(open(os.path.join(led, "networks.json")))
    with open(os.path.join(led, "networks.json"), "w") as f:   # v1 with a later kind of key
        json.dump({"v": 1, "networks": {"ssid:abc": {"down": 5.0, "x": [1]}, K: {"down": 5.0}}}, f)
    r_f = T.networks_edit("set", K, {"down": 9.0})
    f_left = json.load(open(os.path.join(led, "networks.json")))
    with open(os.path.join(led, "networks.json"), "w") as f:
        f.write(saved_)
    os.chmod(os.path.join(led, "networks.json"), 0o666)
    check(r_v2.get("code") == 1 and "newer oomph" in r_v2.get("error", "") and v2_left["v"] == 2 and
          r_f.get("ok") and f_left["networks"]["ssid:abc"] == {"down": 5.0, "x": [1]} and
          f_left["networks"][K]["down"] == 9.0 and "ssid:abc" not in T.valid_networks(f_left)[0],
          "networks.json: a later version's file is never rewritten as v1 (refused, exit 1), and a later kind of key's "
          "entries are carried through as they are (never read)")
    NJ = os.path.join(led, "networks.json")
    broken = {"over 64 KB": json.dumps({"v": 1, "networks": {K: {"down": 5.0}}}) + " " * (65 << 10),
              "broken JSON": '{"v": 1, "networks": {"%s": {"down": 5.0}' % K,
              "past loads_untrusted": json.dumps({"v": 1, "networks": {"rmac:00:00:5e:00:%02x:%02x" % (i // 256, i % 256):
                                                                       {"down": 1.0} for i in range(300)}}),
              "networks not an object": '{"v": 1, "networks": []}'}
    kept_ = {}
    for why_, text_ in broken.items():
        with open(NJ, "w") as f:
            f.write(text_)
        os.chmod(NJ, 0o666)
        rb_ = T.networks_edit("set", K, {"down": 9.0})
        kept_[why_] = (rb_.get("code"), "remove it to start over" in rb_.get("error", ""), open(NJ).read() == text_)
    check(all(x == (1, True, True) for x in kept_.values()),
          "networks.json it cannot read (over 64 KB, broken, past the parser's limits, odd) is never replaced unread: "
          "refused (exit 1) with where it is and that removing it starts over; the file unchanged %s" % kept_)
    fill_ = {"zz:%03d" % i: {"blob": "x" * 900} for i in range(70)}   # a later kind of key, near 64 KB
    with open(NJ, "w") as f:
        json.dump({"v": 1, "networks": dict(fill_, **{K: {"down": 5.0}})}, f)
    os.chmod(NJ, 0o666)
    r_fill = T.networks_edit("set", "rmac:00:00:5e:00:53:44", {"down": 9.0})
    fl_ = json.load(open(NJ))["networks"]
    check(r_fill.get("ok") and fl_["rmac:00:00:5e:00:53:44"]["down"] == 9.0 and K in fl_ and
          0 < sum(1 for k in fl_ if k.startswith("zz:")) < 70 and os.path.getsize(NJ) <= T.LIMITS["networks"] and
          "remove the file to start over" in r_v2.get("error", ""),
          "networks.json: a later kind of key's entries planted to fill the file give way (biggest first) instead of "
          "blocking every write; a later version's file is refused with how to start over")
    with open(NJ, "w") as f:
        json.dump({"v": 1, "networks": {K: {"down": 5.0, "label": "home"}}}, f)
    os.chmod(NJ, 0o666)
    lbl = {x: T.networks_edit("name", "rmac:00:00:5e:00:53:45", {"label": x}).get("code") for x in
           ("this", "This", "gw:10.0.0.1/24", "rmac:00:00:5e:00:53:01", "net-1a2b3c", "NET-x", "ho\u200bme",
            "home\u00ad", "\u2060", "ho\u0301me", "Ｈｏｍｅ", "café", "the office")}
    look = T.valid_networks({"v": 1, "networks": {"rmac:00:00:5e:00:53:01": {"label": "home", "down": 5.0},
                                                  "rmac:00:00:5e:00:53:02": {"label": "ho\u0301me", "down": 6.0},
                                                  "rmac:00:00:5e:00:53:03": {"label": "ho\u200bme", "down": 6.0},
                                                  "rmac:00:00:5e:00:53:04": {"label": "this", "down": 6.0}}}, now)[0]
    check(lbl == {"this": 2, "This": 2, "gw:10.0.0.1/24": 2, "rmac:00:00:5e:00:53:01": 2, "net-1a2b3c": 2, "NET-x": 2,
                  "ho\u200bme": 2, "home\u00ad": 2, "\u2060": 2, "ho\u0301me": 2, "Ｈｏｍｅ": 2, "café": None,
                  "the office": None} and
          [e.get("label") for e in look.values()] == ["home", None, None, None],
          "labels: not `this`, a key or a net-… id (NETWORK reads those first), no invisible characters (zero-width, "
          "soft hyphen, word joiner), and a look-alike of another (a combining mark, full-width letters) is the same "
          "label; another user's file is read the same way %s" % lbl)
    with open(os.path.join(led, "networks.json"), "w") as f:   # the commands' tests start from a short file again
        json.dump({"v": 1, "networks": {k: v for k, v in nn["networks"].items() if not k.startswith("rmac:00:00:5e:01:")}},
                  f)
    os.chmod(os.path.join(led, "networks.json"), 0o666)

    # --- the commands, on a stand-in backend
    class FakePlat(FakeNet):
        OS = "macos"

        def collect_procs(self):
            return dict(tp)

        def group_key(self, path, name):
            return name

    fp = FakePlat()
    fp.mac = "00:00:5e:00:53:07"
    real_plat = oomph._plat
    oomph._plat = fp
    try:
        HK = "rmac:00:00:5e:00:53:07"
        rc, out, err = run(T.cmd_net, ["set", "250/40"])
        rc2, out2, _ = run(T.cmd_net, ["name", "home"])
        rc3, out3, _ = run(T.cmd_net, ["set", "/48", "home"])
        rc4, out4, _ = run(T.cmd_net, ["list", "--json"])
        lj = json.loads(out4)
        check(rc == 0 and rc2 == 0 and rc3 == 0 and lj["current"] == HK and lj["networks"][HK]["down"] == 250.0 and
              lj["networks"][HK]["up"] == 48.0 and lj["networks"][HK]["gw"] == "192.168.178.1" and
              "stored for %s: 250 ↓ / 40 ↑ Mbit/s, set" % T.public_id(HK) in out and HK not in out + out2 + out3 and
              "home" in out2 and HK in out4,
              "oomph net set 250/40 (this network), name home, set /48 home (a label names it; the other side kept), "
              "list --json with the current one; set and name echo the label or the id, never the router's MAC")
        bad_rc = [run(T.cmd_net, a)[0] for a in (["set", "1G"], ["set", "25MB/s"], ["set", "500k"], ["set", "x/"],
                                                  ["name"], ["forget"], ["set", "100", "nowhere"], ["bogus", "--x"])]
        check(bad_rc == [2, 2, 2, 2, 2, 2, 1, 2], "oomph net: what it cannot read is refused with the reason (exit 2): "
              "1G, MB/s, k, no figure, no label, forget without a network; an unknown network exits 1 (%s)" % bad_rc)
        e1 = [str(x) for x in (T.parse_rate("200M"), T.parse_rate("200Mbit/s"), T.parse_rate("12.5mbps"),
                               T.parse_volume("40G"), T.parse_volume("1.5T"), T.parse_volume("0.5"))]
        errs = []
        for f_, x in ((T.parse_rate, "1G"), (T.parse_rate, "25MB/s"), (T.parse_rate, "500k"), (T.parse_rate, "200MiB/s"),
                      (T.parse_rate, "0.5M"), (T.parse_volume, "500M"), (T.parse_volume, "0.001G"),
                      (T.parse_rate, "1Gbit"), (T.parse_rate, "500kbit")):
            try:
                f_(x)
                errs.append("took %s" % x)
            except ValueError as e:
                errs.append(str(e))
        check(e1 == ["200.0", "200.0", "12.5", "40.0", "1500.0", "0.5"] and "use 1000M" in errs[0] and
              "200M" in errs[1] and "1M" in errs[2] and "megabits per second" in errs[3] and "1M to" in errs[4] and
              "0.5G" in errs[5] and "0.01G" in errs[6] and "use 1000M" in errs[7] and "1M" in errs[8],
              "the parsers of 12.12: rates in Mbit/s (M, Mbit/s, Mbps), volumes in GB (G, T = 1000 G); 1G, MB/s, k, "
              "MiB/s and 500M refused with what to write instead (%s)" % errs)

        # oomph net, ps --net and the lines, from a logger's current sample
        cur = {"t": time.time(), "iso": "2026-11-26T03:00:00+01:00", "os": "macos", "ram_gb": 36.0, "app_gb": 10.0,
               "wired_gb": 2.0, "compressed_gb": 1.0, "cached_gb": 4.0, "free_gb": 19.0, "free_pct": 50, "pressure": 1,
               "swap_used_gb": 0.0, "swap_total_gb": 0.0, "swapfiles": 0, "disk_free_gb": 200.0, "cpu": {"n": 14, "busy": 1},
               "net": {"if": "en16", "vpn": False, "network": HK, "src": "flows", "flows": 40, "down_mbps": 212.4,
                       "up_mbps": 8.1, "lan_mbps": 0.1, "in_gb": 41.2, "out_gb": 3.1},
               "net_names": [{"name": "curl", "down": 195.4, "up": 0.2, "n": 1}],
               "top_net": [{"pid": 4101, "name": "curl", "uid": os.getuid(), "down": 195.4, "up": 0.2}],
               "daemon": {"pid": 1, "version": oomph.VERSION, "interval": 30}}
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(cur, f)
        rc, out, _ = run(T.cmd_net, [])
        rcj, outj, _ = run(T.cmd_net, ["--json"])
        nj = json.loads(outj)
        check(rc == 0 and "home (%s) on en16" % T.public_id(HK) in out and HK not in out and
              "250 ↓ / 48 ↑ Mbit/s, set" in out and
              "↓ 212 ↑ 8.1 Mbit/s · busiest: curl 196" in out and nj["network"] == HK and nj["source"] == "daemon" and
              nj["now"]["down_mbps"] == 212.4,
              "oomph net: the network and its label (its id, not the router's MAC: an agent reads it too), the line's "
              "figure with who set it when, now and the busiest")
        rc, out, _ = run(oomph.cmd_ps, ["--net"])
        rcj, outj, _ = run(oomph.cmd_ps, ["--net", "--json"])
        check(rc == 0 and "curl" in out and "195.40" in out and "↓Mbit/s" in out and
              json.loads(outj)["rows"][0]["pid"] == 4101 and run(oomph.cmd_ps, ["--net", "--cpu"])[0] == 2,
              "oomph ps --net: PID NAME ↓ ↑ USER from the logger's attribution; one resource at a time")
        cur_if = dict(cur, top_net=[], net=dict(cur["net"], src="if"))
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(cur_if, f)
        check("totals only here" in run(oomph.cmd_ps, ["--net"])[1], "oomph ps --net: totals only where no process is named")
        line = T.resource_line(cur, samples=[])
        info = T.network_info(cur, samples=[])
        check(line == ("net", "↓212 ↑8.1 of 250/48 Mbit/s (home)") and info["id"] == T.public_id(HK) and
              info["id"].startswith("net-") and len(info["id"]) == 14 and info["cap"] == [250.0, 48.0]
              and info["label"] == "home" and info["stale"] is False and info["room"] is None,
              "the network line of check, status and resources, and the network object of check --json and the MCP "
              "answers (%s)" % (line,))
        check(T.resource_line(dict(cur, net={"if": None}), samples=[])[1] == "offline" and
              "older than 1.15" in T.resource_line({"cpu": {}}, samples=[])[1] and
              T.resource_line(dict(cur, net=dict(cur["net"], network="gw:10.0.0.1/8")), samples=[])[1].endswith(
                  "· line not tested"),
              "the network line: offline, a logger before 1.15, a line not tested (no command: agents read it, and a "
              "speed test is a person's to start)")
        rmk = "rmac:00:00:5e:00:53:77"
        T.networks_edit("set", rmk, {"down": 250.0})
        bare = {k: v for k, v in cur["net"].items() if k != "network"}
        ln_un = [T.resource_line(dict(cur, net=dict(bare, network=n)), samples=[])[1]
                 for n in ("rmac:00:00:5e:00:53:66", "gw:203.0.113.1/24", rmk)]
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(dict(cur, t=time.time(), net=dict(bare, network="rmac:00:00:5e:00:53:66")), f)
        unnamed = dict(cur, t=time.time(), disks=[], net=dict(bare, network="rmac:00:00:5e:00:53:66"))
        oomph._sample_override = lambda: json.loads(json.dumps(unnamed))
        try:
            texts = [run(oomph.cmd_check, [])[1], run(oomph.cmd_check, ["--json"])[1], run(oomph.cmd_status)[1],
                     run(oomph.cmd_resources, [])[1], run(oomph.cmd_resources, ["--json"])[1]]
        finally:
            oomph._sample_override = None
        T.networks_edit("forget", rmk)
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(cur_if, f)
        check(not any("rmac:" in x or "gw:" in x for x in ln_un + texts) and "unnamed network" in ln_un[0] and
              "of 250/? Mbit/s" in ln_un[2] and "not tested" not in ln_un[2] and
              all("unnamed network" in x for x in texts[:1] + texts[2:4]),
              "the network line never shows a key (a router's MAC, a public gateway: SKILL.md has agents run oomph "
              "check): check, status, resources, text and --json; a figure of one side (net set 250/) is a figure "
              "(%s)" % ([ln_un] + [x[-300:] for x in texts if "unnamed network" not in x][:1]))
        hot = [{"net": dict(cur["net"], down_mbps=x)} for x in (280.0, 290.0, 300.0)]
        sth = T.stale(T.read_networks()["networks"][HK], hot, HK)
        sat = [{"net": dict(cur["net"], down_mbps=x)} for x in (260.0, 270.0, 275.0)]
        check(sth == {"dir": "down", "seen": 290.0, "cap": 250.0, "source": "set"} and
              T.stale_text(sth) == "seen 290 Mbit/s, more than the 250 set: oomph net test" and
              T.stale(T.read_networks()["networks"][HK], sat, HK) is None and
              "seen 290" in T.resource_line(cur, samples=hot)[1] and "net test" not in T.resource_line(cur, samples=hot)[1]
              and T.stale_text(sth, cmd=False) == "seen 290 Mbit/s, more than the 250 set",
              "the stale hint: three samples above 1.1 × the figure (payload against payload); a saturated line is "
              "not; check, status and resources name no command")
        tot = [{"net": dict(cur["net"], src="if", down_mbps=940.0)} for _ in range(3)]
        check(T.stale(T.read_networks()["networks"][HK], tot, HK) is None and
              "totals, LAN included" in T.resource_line(dict(cur, net=tot[0]["net"]), samples=tot)[1] and
              "seen" not in T.resource_line(dict(cur, net=tot[0]["net"]), samples=tot)[1],
              "the stale hint: totals alone (the Linux service, nettop pausing: the LAN's traffic in them) never say "
              "the line is faster than its figure; the line says they include the LAN")
        # the network's key never leaves in an answer for a model's provider
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(dict(cur, t=time.time()), f)
        leaks = {}
        for what, fn in (("memory_status", lambda: oomph._mcp_call("memory_status", {})),
                         ("memory_check", lambda: oomph._mcp_call("memory_check", {})),
                         ("status --json", lambda: json.loads(run(oomph.cmd_status_json)[1])),
                         ("full_sample", lambda: oomph.full_sample(cur))):
            try:
                leaks[what] = "rmac:" in json.dumps(fn())
            except Exception as x:  # noqa: B902
                leaks[what] = repr(x)[:120]
        ms_ = oomph._mcp_call("memory_status", {})
        check(leaks == {"memory_status": False, "memory_check": False, "status --json": False, "full_sample": False}
              and ms_["net"]["network"] == T.public_id(HK) and ms_["network"]["label"] == "home" and
              T.read_networks()["networks"].get(HK) and
              json.loads(run(T.cmd_net, ["--json"])[1])["network"] == HK,
              "the router's MAC stays home: memory_status, memory_check, status --json and the full sample a viewer gets "
              "name the network by a salted hash and its label; oomph net --json by its key (%s)" % leaks)
        # a figure stored as gw: while the router's MAC was missing: oomph net points at it once the MAC is known
        T.networks_edit("set", "gw:192.168.178.1/24", {"down": 77.0, "up": 7.0})
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(dict(cur, t=time.time(), net=dict(cur["net"], network="rmac:00:00:5e:00:53:44")), f)
        rco, outo, _ = run(T.cmd_net, [])
        T.networks_edit("forget", "gw:192.168.178.1/24")
        gid_ = T.public_id("gw:192.168.178.1/24")
        check(rco == 0 and "stored as %s" % gid_ in outo and "net set again" in outo and "gw:" not in outo and
              T._target(gid_, {"gw:192.168.178.1/24": {"down": 1.0}})[0] == "gw:192.168.178.1/24" and
              "oomph net forget NETWORK" in T.NET_USAGE,
              "oomph net: a figure stored under gw: before the router's MAC was known is pointed at, not lost silently")
    finally:
        oomph._plat = real_plat

    # --- net test against a stand-in networkQuality (12.13)
    nq = os.path.join(TMP, "networkQuality")
    with open(nq, "w") as f:
        f.write("#!/bin/sh\ntouch '%s'\ncat '%s'\n" % (os.path.join(TMP, "nq-ran"), os.path.join(FX, "networkQuality-s.json")))
    os.chmod(nq, 0o755)
    other = os.path.join(TMP, "networkQuality-wifi")
    with open(other, "w") as f:
        f.write("#!/bin/sh\nsed 's/\"en16\"/\"en0\"/' '%s'\n" % os.path.join(FX, "networkQuality-s.json"))
    os.chmod(other, 0o755)
    os.environ["OOMPH_NETWORKQUALITY"] = nq
    fp2 = FakePlat()
    fp2.mac = "00:00:5e:00:53:20"
    oomph._plat = fp2
    real_stdin = sys.stdin
    sys.stdin = io.StringIO("")   # no terminal, whatever runs the test
    try:
        os.unlink(os.path.join(os.environ["OOMPH_DIR"], "current.json"))
        rc, out, err = run(T.cmd_net, ["test", "--json"])
        check(rc == 1 and out == "" and "--yes" not in err and "terminal" in err and
              not os.path.exists(os.path.join(TMP, "nq-ran")),
              "net test without a terminal and without --yes refuses before networkQuality runs (an agent following "
              "the 'oomph net test' hint moves no few hundred MB over the shared line), and shows no way round it "
              "(%r)" % err)
        sys.stdin = tty = io.StringIO("n\n")
        tty.isatty = lambda: True
        rc, out, err = run(T.cmd_net, ["test", "--json"])
        j = json.loads(out)
        sys.stdin = io.StringIO("")
        rcy, outy, _ = run(T.cmd_net, ["test", "--yes", "--json"])
        jy = json.loads(outy)
        e2 = T.read_networks()["networks"].get("rmac:00:00:5e:00:53:20") or {}
        check(rc == 0 and j["stored"] is False and j["result"]["down"] == 176.4 and j["result"]["up"] == 42.3 and
              rcy == 0 and jy["stored"] is True and e2.get("down") == 176.4 and e2.get("source") == "test" and
              e2.get("test", {}).get("rpm") == 1100 and e2.get("test", {}).get("tool") == "networkQuality",
              "net test: networkQuality -c -s read (176.4 ↓ / 42.3 ↑, 1100 RPM); in a terminal without --yes nothing "
              "is stored (--json asks nothing), with --yes it is, as a test")
        os.environ["OOMPH_NETWORKQUALITY"] = other
        rcw, outw, _ = run(T.cmd_net, ["test", "--yes", "--json"])
        jw = json.loads(outw)
        check(rcw == 1 and jw["stored"] is False and "en0" in jw["refused"],
              "net test: a result measured over another interface than this network's is not stored (exit 1)")
        T.networks_edit("set", "rmac:00:00:5e:00:53:20", {"down": 10.0, "up": 10.0})
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(dict(cur, t=time.time(), net=dict(cur["net"], network="rmac:00:00:5e:00:53:20", down_mbps=5.0)), f)
        os.environ["OOMPH_NETWORKQUALITY"] = nq
        sys.stdin = tty = io.StringIO("n\n")
        tty.isatty = lambda: True
        rcb, _, errb = run(T.cmd_net, ["test"])
        sys.stdin = io.StringIO("")
        check(rcb == 1 and "busy" in errb and "--yes" in errb,
              "net test: a line busy with more than 10 % of its figure needs --yes (the result would read low)")
        rcb2, outb2, _ = run(T.cmd_net, ["test", "--yes", "--json"])
        check(rcb2 == 0 and json.loads(outb2)["stored"] is True and
              T.read_networks()["networks"]["rmac:00:00:5e:00:53:20"]["down"] == 176.4,
              "net test --yes on a busy line tests and stores (12.13: --yes stores) (%s)" % outb2)
        # the router's MAC not in the cache now: `this` (set, name, test) is the logger's network where it has the
        # same gateway and subnet, not where the logger's sample names another network (one interval after a move)
        T.networks_edit("set", "rmac:00:00:5e:00:53:21", {"down": 30.0, "up": 3.0, "gw": "10.0.0.1",
                                                          "subnet": "10.0.0.0/24"})
        nets_now = T.read_networks()["networks"]
        fp2.mac = None
        same = T._target(None, nets_now)[0]
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(dict(cur, t=time.time(), net=dict(cur["net"], network="rmac:00:00:5e:00:53:21")), f)
        moved = T._target(None, nets_now)[0]
        fp2.mac = "00:00:5e:00:53:22"
        moved2 = T._target(None, nets_now)[0]
        check(same == "rmac:00:00:5e:00:53:20" and moved == "rmac:00:00:5e:00:53:20" and moved2 == "rmac:00:00:5e:00:53:22",
              "net this: the logger's network while it has this gateway and subnet; not the network a sample from "
              "before a move names (another gateway's: the live gw: key resolved, or the live MAC) (%s, %s, %s)" % (same, moved, moved2))
        os.unlink(os.path.join(os.environ["OOMPH_DIR"], "current.json"))
        fp2.mac = None
        T.networks_edit("forget", "rmac:00:00:5e:00:53:20")
        with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
            json.dump(dict(cur, t=time.time(), net=dict(cur["net"], network="rmac:00:00:5e:00:53:20", down_mbps=0.1)), f)
        rct, outt, _ = run(T.cmd_net, ["test", "--yes", "--json"])
        nt_keys = sorted(k for k in T.read_networks()["networks"] if k == "rmac:00:00:5e:00:53:20" or k.startswith("gw:"))
        check(rct == 0 and json.loads(outt)["network"] == "rmac:00:00:5e:00:53:20" and
              nt_keys == ["rmac:00:00:5e:00:53:20"],
              "net test keys its result as the logger names this network (the router's MAC not in the cache now): "
              "no gw: entry another router on 192.168.178.1/24 would match (%s)" % nt_keys)
        os.unlink(os.path.join(os.environ["OOMPH_DIR"], "current.json"))
        # the router's MAC missing when the test starts, there when it ends (its own traffic filled the cache)
        class Fill(FakePlat):
            def router_mac(self, gw, ifname):
                return self.macs.pop(0) if self.macs else "00:00:5e:00:53:41"
        fp3 = Fill()
        fp3.macs, fp3.eg = [None], dict(EG, gw="10.41.0.1", subnet="10.41.0.0/24", onlink=["10.41.0.0/24"])
        oomph._plat = fp3
        rcf, outf, _ = run(T.cmd_net, ["test", "--yes", "--json"])
        jf = json.loads(outf)
        nf = T.read_networks()["networks"]
        check(rcf == 0 and jf["stored"] is True and jf["network"] == "rmac:00:00:5e:00:53:41" and
              nf.get("rmac:00:00:5e:00:53:41", {}).get("down") == 176.4 and "gw:10.41.0.1/24" not in nf,
              "net test: the router's MAC found during the test (gw: before, rmac: after, same gateway and subnet) is "
              "the same network: stored under the rmac key (%s)" % jf)
        T.networks_edit("forget", "rmac:00:00:5e:00:53:41")
    finally:
        oomph._plat = real_plat
        sys.stdin = real_stdin
        os.environ.pop("OOMPH_NETWORKQUALITY", None)

    # --- the logger child's answer about this network (12.7), read back by root's rules
    ans = T.child_entry({"network": "gw:192.168.178.1/24", "gw": "192.168.178.1", "subnet": "192.168.178.0/24"})
    T.networks_edit("set", "rmac:00:00:5e:00:53:30", {"down": 50.0, "up": 5.0, "gw": "10.9.0.1", "subnet": "10.9.0.0/16"})
    ans2 = T.child_entry({"network": "gw:10.9.0.1/16", "gw": "10.9.0.1", "subnet": "10.9.0.0/16"})
    ans3 = T.child_entry({"network": "gw:10.7.0.1/16", "gw": "10.7.0.1", "subnet": "10.7.0.0/16"})
    T.networks_edit("set", "rmac:00:00:5e:00:53:31", {"down": 60.0, "up": 6.0, "gw": "10.8.0.1", "subnet": "10.8.0.0/16"})
    pad = json.load(open(os.path.join(led, "networks.json")))
    pad["networks"]["rmac:00:00:5e:00:53:31"].update({"pad%02d" % i: "y" * 200 for i in range(16)})
    with open(os.path.join(led, "networks.json"), "w") as f:
        json.dump(pad, f)
    ans4 = T.child_entry({"network": "gw:10.8.0.1/16", "gw": "10.8.0.1", "subnet": "10.8.0.0/16"})
    T.networks_edit("forget", "rmac:00:00:5e:00:53:31")
    check(ans4 and ans4["key"] == "rmac:00:00:5e:00:53:31" and T.answer_entry(ans4) and
          not any(k.startswith("pad") for k in ans4["entry"]),
          "the child's answer carries only what the logger reads: an entry padded with 16 unknown fields of 200 "
          "characters is still adopted")
    check(ans and ans["key"] == "rmac:00:00:5e:00:53:20" and ans2 and ans2["key"] == "rmac:00:00:5e:00:53:30" and T.answer_entry(ans2) == ans2 and
          ans3 is None and T.answer_entry({"key": "../x", "entry": {"down": 5}}) is None and
          T.answer_entry({"key": "rmac:00:00:5e:00:53:30", "entry": {"down": 5, "label": "x" * 3000}}) is None,
          "the ledger child names this network's entry (a gw: identity finds the rmac entry of its gateway and subnet, "
          "the one set last of two); the logger reads that answer through the sanitizer again, at most 2 KB")
    with open(os.path.join(os.environ["OOMPH_DIR"], "current.json"), "w") as f:
        json.dump(dict(cur, t=time.time()), f)
    lt_ans = {}
    oomph.ledger_tick(dict(cur, pools=None), {}, nets={4101: [1000, 20]},
                      net={"network": "gw:10.9.0.1/16", "gw": "10.9.0.1", "subnet": "10.9.0.0/16"}, answer=lt_ans)
    check((lt_ans.get("network") or {}).get("key") == "rmac:00:00:5e:00:53:30",
          "the logger's tick: the child (another process) answers with this network's entry")

    # --- what travels (01 §4.2): the rates, never the day's GB (old mirrors refuse *_gb above 16 x RAM)
    import oomph_sync  # noqa: E402
    big = dict(cur, ram_gb=8.0, net=dict(cur["net"], in_gb=900.0, out_gb=300.0))
    sl, fu = oomph.slim_sample(big), oomph.full_sample(dict(big, daemon=dict(cur["daemon"], net="too many connections")))
    check(sl["net"] == {"src": "flows", "vpn": False, "down_mbps": 212.4, "up_mbps": 8.1, "lan_mbps": 0.1} and
          "net_names" not in sl and "top_net" not in sl and "network" not in fu["net"] and fu["net"]["if"] == "en16" and
          "in_gb" not in fu["net"] and
          fu["net_names"][0]["name"] == "curl" and fu["top_net"][0]["pid"] == 4101 and
          fu["daemon"]["net"] == "too many connections" and oomph_sync.gb_ok(sl, 8.0) and oomph_sync.gb_ok(fu, 8.0) and
          not oomph_sync.gb_ok(big, 8.0),
          "the wire: a slim sample carries the rates; the current one also the interface, names and top_net (never the "
          "network's key); "
          "the day's GB stay home (a day's 900 GB on an 8 GB machine would make 1.9–1.14 mirrors drop the row)")

    ing = oomph_sync.Ingest({"now": time.time(), "ram_gb": 8.0})
    got_ = ing.row(json.dumps(dict(sl, t=time.time() - 60)), "samples")
    check(got_ and got_[1].get("net") == sl["net"] and not any(ing.dropped.values()),
          "a viewer's mirror takes the slim sample's net block in (ingest's checks pass)")

    # --- the report: the peaks and who moved most then
    samples = [dict(cur, t=1795600000 + 30 * i, iso="2026-11-26T03:%02d:00+01:00" % i,
                    net=dict(cur["net"], down_mbps=10.0 * i, up_mbps=50.0 - i),
                    net_names=[{"name": "curl", "down": 9.0 * i, "up": 0.1, "n": 1}]) for i in range(5)]
    summ = oomph.summarize(samples, [])
    lines = oomph.resource_summary_lines(summ)
    check(summ["max_net_down_mbps"] == 40.0 and summ["max_net_up_mbps"] == 50.0 and
          any(x.startswith("internet, peak: ↓ 40.0 Mbit/s at 03:04 (curl 36.0) · ↑ 50.0 Mbit/s at 03:00") for x in lines),
          "oomph report, other resources: the internet's peaks down and up with the busiest names then %s" % lines[-1:])
    odd = T.report_line({"max_net_down_mbps": 40.0, "max_net_down_at": "2026-11-26T03:04:00+01:00",
                         "names_net_down_at_peak": [{"name": "curl", "down": "x"}, {"name": 5, "down": 3.0}]})
    check(odd == "internet, peak: ↓ 40.0 Mbit/s at 03:04 (curl 0.0, 5 3.0)",
          "the report: an odd row of a damaged log costs its figure, not the report (%s)" % odd)
    tot = [dict(x, net=dict(x["net"], src="if", down_mbps=d, up_mbps=3.0), net_names=[]) for x, d in
           zip(samples[:2], (940.0, 12.0))]
    st_ = oomph.summarize(tot, [])
    lt_ = oomph.resource_summary_lines(st_)
    sm_ = oomph.summarize(tot + [dict(samples[3], net=dict(samples[3]["net"], src="flows"))], [])
    lm_ = oomph.resource_summary_lines(sm_)
    check(st_.get("max_net_down_mbps") is None and not any(x.startswith("internet") for x in lt_) and
          "network (interface totals, LAN included), peak: ↓ 940.0 Mbit/s at 03:00 · ↑ 3.0 Mbit/s at 03:00" in lt_ and
          sm_["max_net_down_mbps"] == 30.0 and
          any(x.startswith("internet, peak: ↓ 30.0 Mbit/s at 03:03 (curl 27.0)") for x in lm_) and
          not any(x.startswith("network (interface") for x in lm_),
          "the report: totals-only samples (a Linux service logger, nettop backing off: the LAN included) give no "
          "internet peak, only a line saying what they are; one per-connection sample in the window gives the internet's "
          "peak from those alone %s %s" % (lt_[-1:], lm_[-1:]))
    check(oomph.summarize([{k: v for k, v in x.items() if k not in ("net", "net_names")} for x in samples], [])
          .get("max_net_down_mbps") is None, "the report: samples before 1.15 have no internet line")

    # --- the live readings on this Mac (nothing is sent: nettop lists, the routing table is asked)
    if MAC:
        import oomph_darwin as D
        eg = D.net_route()
        got = D.net_flows()
        rows_live, why_live = T.nettop_flows(got[0], oomph.plat().collect_procs(), T.onlink_nets((eg or {}).get("onlink")),
                                             (eg or {}).get("if"), (eg or {}).get("tun"))
        nb = D.net_bytes(eg["if"]) if eg else None
        check(eg is None or (eg["if"] and nb and nb[0] > 0 and got[1] is None and why_live is None and
                             isinstance(rows_live, list)),
              "this Mac, live: the egress (%s), its 64-bit counters, nettop's flows parsed (%s rows)" % (
                  (eg or {}).get("if"), len(rows_live or [])))
        ifc = subprocess.run(["/sbin/ifconfig", eg["if"]], capture_output=True, text=True, timeout=10).stdout if eg else ""
        mine = [a.split("/")[0] for a in D.if_addrs().get((eg or {}).get("if"), [])]
        check(eg is None or all(a.split("%")[0] in ifc for a in mine if not a.startswith("fe80")),
              "this Mac, live: getifaddrs' addresses are ifconfig's")
finally:
    shutil.rmtree(TMP, ignore_errors=True)

print("\nFAILED (%d)" % len(failures) if failures else "\nall internet traffic checks passed")
sys.exit(1 if failures else 0)
