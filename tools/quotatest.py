#!/usr/bin/python3 -I
"""Tests of the metered networks of 1.15 (roadmap NET-concept §3, §12.8, §12.10, §12.17, D-N13, D-N20; step N3): the
periods (a month from the 31st in February, a week from Monday or Sunday, a day, the changes to and from summer time),
the logger's day counters (netdays.json: across a restart, the 62-day and 64-network trims, written at most once a
minute and at the stop, a hostile file), net.quota in current.json, quota admission (all or nothing, the refusal with
what is left, a request waiting on net.quota, first come first served, what grants have still to move, a network
without a figure, the counters read without the logger), amend, `oomph net metered`, the network line, check --json
and memory_check, the hook's line once per session and period, and the capsule. Unprivileged and portable (no
traffic: the samples and counters are made up); a ledger and a log folder of its own. tools/selftest.py runs it.

    /usr/bin/python3 -I -B tools/quotatest.py
"""
import contextlib
import datetime
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

os.environ["TZ"] = "Europe/Berlin"   # the periods' summer time cases are this zone's
time.tzset()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="oomph-quotatest-")
os.environ.update(OOMPH_DIR=os.path.join(TMP, "log"), OOMPH_LEDGER_DIR=os.path.join(TMP, "ledger"),
                  OOMPH_STATE_DIR=os.path.join(TMP, "state"), TMPDIR=os.path.join(TMP, "tmp"))
for k in ("OOMPH_NET_RESERVATIONS", "OOMPH_GPU_RESERVATIONS", "XDG_RUNTIME_DIR"):
    os.environ.pop(k, None)
for d in ("log", "tmp"):
    os.makedirs(os.path.join(TMP, d))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import oomph  # noqa: E402

T = oomph._T()
if sys.platform != "darwin":  # the ledger's process table, as tools/selftest.py has it on Linux
    import fixtureplat  # noqa: E402
    oomph._plat = fixtureplat
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


D = datetime.date
A, B, C = "rmac:00:00:5e:00:53:01", "rmac:00:00:5e:00:53:02", "rmac:00:00:5e:00:53:03"   # three made-up routers
LOG = os.environ["OOMPH_DIR"]


def at(y, m, d, h=12):
    return time.mktime((y, m, d, h, 0, 0, 0, 0, -1))


def per(p, now, fd=None):
    return T.period(dict({"period": p}, **({"from_day": fd} if fd else {})), now)


def hours(a, b):
    return round((T.local_midnight(b) - T.local_midnight(a)) / 3600.0, 3)


BASE = dict(ram_gb=64.0, app_gb=10.0, wired_gb=4.0, compressed_gb=0.0, pressure=1, disk_free_gb=600.0,
            swap_used_gb=0.0, swap_total_gb=0.0, os="macos", cpu={"n": 14, "busy": 0.0})
state = {"net": {"if": "en0", "vpn": False, "network": C, "src": "flows", "down_mbps": 0.0, "up_mbps": 0.0}, "pools": None}


def sample():
    s = dict(BASE, t=time.time())
    if state["net"] is not None:
        s["net"] = dict(state["net"])
    if state.get("pools"):
        s["pools"] = json.loads(json.dumps(state["pools"]))
    return s


def quota(key, used, cap=20.0, m=None, label=None, now=None):
    """current.json's pools with the logger's net.quota of a metered network."""
    m = m or {"cap_gb": cap, "period": "month", "from_day": 14}
    q = T.quota_pool(m, key, used, 0.0, now or time.time())
    q = {k: q[k] for k in ("network", "cap", "margin", "used", "from", "to", "period")}
    if label:
        q["label"] = label
    return {"t": time.time(), "net.quota": q}


def clear():
    for r in oomph.read_ledger()["leases"]:
        oomph.release(r["id"])


def cli(f, args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = f(args)
    return rc, out.getvalue(), err.getvalue()


def part(rid, k="net"):
    r = next((x for x in oomph.read_ledger()["leases"] if x["id"] == rid), {})
    return (r.get("res") or {}).get(k) or {}


oomph._sample_override = sample
sleepers = [subprocess.Popen(["/bin/sleep", "120"]) for _ in range(5)]
H = [{"pid": x.pid, "start": None, "kind": "session", "project": "/tmp/q-%d" % i} for i, x in enumerate(sleepers)]

try:
    # --- the periods (12.8): by calendar dates, a month without the day from its last
    check(per("month", at(2027, 2, 15), 31) == (D(2027, 1, 31), D(2027, 2, 28))
          and per("month", at(2027, 2, 28), 31) == (D(2027, 2, 28), D(2027, 3, 31))
          and per("month", at(2027, 3, 30), 31) == (D(2027, 2, 28), D(2027, 3, 31))
          and per("month", at(2027, 3, 31), 31) == (D(2027, 3, 31), D(2027, 4, 30))
          and per("month", at(2028, 2, 29), 31) == (D(2028, 2, 29), D(2028, 3, 31))
          and per("month", at(2028, 2, 28), 30) == (D(2028, 1, 30), D(2028, 2, 29)),
          "a month from the 31st: February's period begins on its last day (28th, 29th in a leap year), March's on "
          "the 31st")
    check(per("month", at(2026, 11, 26), 14) == (D(2026, 11, 14), D(2026, 12, 14))
          and per("month", at(2026, 11, 13), 14) == (D(2026, 10, 14), D(2026, 11, 14))
          and per("month", at(2026, 1, 5), 14) == (D(2025, 12, 14), D(2026, 1, 14))
          and per("month", at(2026, 11, 14, 0), 14) == (D(2026, 11, 14), D(2026, 12, 14))
          and per("month", at(2026, 12, 31)) == (D(2026, 12, 1), D(2027, 1, 1)),
          "a month from the 14th: before and after it, across the year's end, from midnight on; by default from the 1st")
    check(per("week", at(2026, 11, 26)) == (D(2026, 11, 23), D(2026, 11, 30))
          and per("week", at(2026, 11, 23, 0)) == (D(2026, 11, 23), D(2026, 11, 30))
          and per("week", at(2026, 11, 26), 7) == (D(2026, 11, 22), D(2026, 11, 29))
          and per("week", at(2026, 11, 26), 4) == (D(2026, 11, 26), D(2026, 12, 3))
          and per("day", at(2026, 11, 26, 23)) == (D(2026, 11, 26), D(2026, 11, 27)),
          "a week from Monday (the default), from Sunday (7), from Thursday on a Thursday; a day from midnight")
    check(hours(*per("day", at(2027, 3, 28))) == 23 and hours(*per("day", at(2026, 10, 25))) == 25
          and hours(*per("week", at(2027, 3, 28))) == 7 * 24 - 1
          and time.localtime(T.local_midnight(D(2027, 3, 29)))[3:5] == (0, 0)
          and time.localtime(T.local_midnight(D(2026, 10, 26)))[3:5] == (0, 0),
          "summer time: the day it begins has 23 hours, the day it ends 25; each period still begins at local midnight")

    # --- the parsers of `oomph net metered`
    bad = {}
    for x in ("20G", "20G/year", "500M/month", "0.05G/month", "lots/month", "200000G/month"):
        try:
            T.parse_cap(x)
        except ValueError as e:
            bad[x] = str(e)
    fr = {}
    for x, p in (("32", "month"), ("0", "month"), ("8", "week"), ("1", "day"), ("x", "week")):
        try:
            T.parse_from(x, p)
        except ValueError as e:
            fr[x + p] = str(e)
    check(T.parse_cap("20G/month") == (20.0, "month") and T.parse_cap("1.5T/week") == (1500.0, "week")
          and T.parse_cap("5/day") == (5.0, "day") and len(bad) == 6 and "per period" in bad["20G"]
          and "megabits or megabytes" in bad["500M/month"] and len(fr) == 5 and "no --from" in fr["1day"]
          and T.parse_from("sunday", "week") == 7 and T.parse_from("Mon", "week") == 1 and T.parse_from("31", "month") == 31,
          "--cap VOLUME/PERIOD and --from: a period is required, M refused; a month's day 1–31, a week's 1–7 or its "
          "name, a day takes none (%s)" % sorted(bad))

    # --- the day counters (12.8): netdays.json in the logger's folder
    path = os.path.join(LOG, "netdays.json")
    nd = T.NetDays(path)
    for i in range(70):
        nd.add(A, (D(2026, 11, 26) - datetime.timedelta(days=i)).isoformat(), 1e9, 0.5e9)
    for i in range(65):
        nd.add("gw:10.%d.0.1/24" % i, "2026-%02d-%02d" % (1 + i // 28, 1 + i % 28), 1e6, 0)
    check(len(nd.days[A]) == 62 and min(nd.days[A]) == "2026-09-26" and len(nd.days) == 64 and A in nd.days
          and "gw:10.0.0.1/24" not in nd.days and "gw:10.1.0.1/24" not in nd.days
          and nd.used(A, "2026-11-14", "2026-11-26") == 13 * 1.5e9 and nd.get(A, "2026-11-26") == (1e9, 0.5e9),
          "the counters keep 62 dates per network and 64 networks (the one seen longest ago goes)")
    nd.add("not a key", "2026-11-26", 1, 1)
    nd.add(B, "2026-02-30", 1, 1)
    check("not a key" not in nd.days and B not in nd.days, "a key or a date that is none is not counted")
    check(nd.due(100.0) and not nd.written(100.0) and not nd.due(130.0) and (nd.add(A, "2026-11-26", 1, 1) or True)
          and not nd.due(159.0) and nd.due(160.0) and nd.due(130.0, force=True),
          "written at once the first time, then at most once a minute, and at the stop (force)")
    with open(path, "w") as f:
        f.write(nd.dumps())
    back = T.NetDays(path).load()
    check(back.days.keys() == nd.days.keys() and abs(back.used(A, "2026-11-14", "2026-11-26") - 13 * 1.5e9 - 2) < 1e3,
          "netdays.json read back at the logger's start holds what was counted (a restart goes on counting)")
    tr = T.Traffic(back)
    eg = {"if": "en0"}
    now = time.time()
    today = datetime.date.fromtimestamp(now).isoformat()
    back.days.setdefault(C, {})[today] = [2.5e9, 0.5e9]
    b1 = tr.step(1000.0, now, eg, (0, 0), [], True, {}, C)[0]
    tr.step(1010.0, now + 1, eg, (int(1.08e9), 0), [], True, {}, C)
    b2 = tr.step(1020.0, now + 2, eg, (int(1.08e9), 0), [], True, {}, C)[0]
    check(b1.get("in_gb") == 2.5 and b1.get("out_gb") == 0.5 and 3.4 < b2.get("in_gb", 0) < 3.6
          and 3.4e9 < back.get(C, today)[0] < 3.6e9,
          "after a restart the day's in_gb goes on from the counters, and what the next samples move is added (%s, %s)"
          % (b1.get("in_gb"), b2.get("in_gb")))
    fresh = T.NetDays()
    tr = T.Traffic(fresh)
    tr.day["gw:192.168.178.1/24"] = [today, 1e9, 0.0, False]
    fresh.add("gw:192.168.178.1/24", today, 1e9, 0.0)
    fresh.add("gw:192.168.178.1/24", "2026-01-01", 7e9, 0.0)
    fresh.add(B, today, 2e9, 0.0)
    tr.rename("gw:192.168.178.1/24", B)
    check(fresh.get(B, today) == (3e9, 0.0) and fresh.get("gw:192.168.178.1/24", "2026-01-01") == (7e9, 0.0)
          and fresh.get("gw:192.168.178.1/24", today) is None,
          "the router found later: the day's counts move to its key, older days of the gateway stay (another router's?)")
    for name, text in (("version", '{"v": 2, "days": {}}'), ("key", '{"v": 1, "days": {"x": {"2026-11-26": [1, 1]}}}'),
                       ("date", '{"v": 1, "days": {"%s": {"2026-13-01": [1, 1]}}}' % A),
                       ("negative", '{"v": 1, "days": {"%s": {"2026-11-26": [-1, 1]}}}' % A),
                       ("string", '{"v": 1, "days": {"%s": {"2026-11-26": ["1", 1]}}}' % A),
                       ("three", '{"v": 1, "days": {"%s": {"2026-11-26": [1, 1, 2]}}}' % A),
                       ("flag", '{"v": 1, "days": {"%s": {"2026-11-26": [1, 1, true]}}}' % A),
                       ("four", '{"v": 1, "days": {"%s": {"2026-11-26": [1, 1, 1, 1]}}}' % A),
                       ("future", '{"v": 1, "days": {"%s": {"%s": [1, 1]}}}' % (
                           A, (datetime.date.today() + datetime.timedelta(days=2)).isoformat())),
                       ("huge", '{"v": 1, "days": {"%s": {"2026-11-26": [1e7, 1]}}}' % A),
                       ("big", '{"v": 1, "days": {}, "pad": "%s"}' % ("x" * (300 << 10))), ("broken", '{"v": 1, "da')):
        with open(path, "w") as f:
            f.write(text)
        got = T.NetDays(path).load().days
        check(got == {}, "a hostile netdays.json counts nothing: %s" % name)
    os.remove(path)
    os.symlink(os.path.join(TMP, "elsewhere.json"), path)
    with open(os.path.join(TMP, "elsewhere.json"), "w") as f:
        f.write('{"v": 1, "days": {"%s": {"2026-11-26": [5, 5]}}}' % A)
    check(T.NetDays(path).load().days == {} and T.read_netdays() == {}, "netdays.json as a symbolic link is not read")
    os.remove(path)

    # the logger writes it into its own folder, at most once a minute and at its stop
    import oomphd  # noqa: E402
    dmn = oomphd.Daemon()
    dmn.net_days = T.NetDays(path)
    dmn.net_days.add(C, today, 1e9, 0)
    dmn.save_net_days()
    st1 = os.stat(path)
    dmn.net_days.add(C, today, 1e9, 0)
    dmn.save_net_days()
    mid = T.read_netdays()
    dmn.save_net_days(force=True)
    end = T.read_netdays()
    check(oct(st1.st_mode & 0o777) == "0o644" and mid[C][today][0] == 1e9 and end[C][today][0] == 2e9,
          "the logger: netdays.json 0644 in its folder, not again within the minute, at once at its stop")
    os.remove(path)

    # --- net.quota in current.json (12.5): the logger's, from the child's answer about this network and its counters
    bk = T.NetDays()
    m14 = {"cap_gb": 20.0, "period": "month", "from_day": 14}
    a14, b14 = T.period(m14, now)
    bk.add(C, today, 3e9, 1e9)
    bk.add(C, a14.isoformat(), 2e9, 0)
    bk.add(C, (a14 - datetime.timedelta(days=1)).isoformat(), 50e9, 0)
    ans = {"asked": C, "key": C, "entry": {"label": "phone", "metered": dict(m14, set_by="x", set=1.0)}}
    ls = [{"state": "granted", "net_gb": 4.0, "net_moved": 1.5}, {"state": "granted", "net_up_gb": 1.0},
          {"state": "queued", "net_gb": 9.0}, {"state": "granted", "net_gb": 2.0, "net_moved": 3.0}]
    blk = {"if": "en0", "network": C, "src": "flows", "down_mbps": 1.0, "up_mbps": 0.1}
    pb = T.pool_blocks(blk, ans, ls, {}, bk, now)
    q = pb.get("net.quota") or {}
    check(q.get("network") == C and q.get("cap") == 20.0 and q.get("margin") == 2.0 and q.get("used") == 6.0
          and "reserved" not in q and q.get("from") == T.local_midnight(a14) and q.get("to") == T.local_midnight(b14)
          and q.get("label") == "phone" and q.get("period") == "month" and "net.down" not in pb and "lan" not in q,
          "current.json's net.quota: used this period from the counters (the day before it not), the label, no "
          "`reserved` (the snapshot does not say which network a grant is on); on a metered network without a figure no "
          "rate pools (%s)" % q)
    bk.add(C, today, 0.5e9, 0, True)
    q2 = T.pool_blocks(blk, ans, ls, {}, bk, now).get("net.quota") or {}
    bk.add(C, (a14 - datetime.timedelta(days=1)).isoformat(), 1e9, 0, True)
    bk2 = T.NetDays(path)
    bk2.add(C, (a14 - datetime.timedelta(days=1)).isoformat(), 1e9, 0, True)
    check(q2.get("lan") is True and q2.get("used") == 6.5 and T.valid_netdays(json.loads(bk.dumps()))[C][today][2]
          and T.quota_block(ans, blk, bk2, now) is not None and "lan" not in T.quota_block(ans, blk, bk2, now),
          "a day counted from totals only (the LAN's traffic in it) marks net.quota `lan` while it is in the period, and "
          "netdays.json keeps the mark")
    check(T.pool_blocks(blk, {"asked": A, "key": A, "entry": ans["entry"]}, ls, {}, bk, now) == {}
          and T.pool_blocks(blk, {"asked": C, "key": C, "entry": {"down": 100.0}}, ls, {}, bk, now).get("net.quota") is None
          and T.pool_blocks(dict(blk, **{"if": None}), ans, ls, {}, bk, now) == {},
          "no net.quota from an answer about another network, on a network not metered, or offline")

    # --- quota admission (12.10): all or nothing, against cap − margin − used − what grants have still to move
    os.environ["OOMPH_NET_RESERVATIONS"] = "1"
    assert T.networks_edit("set", C, {"down": 194.0, "up": 48.0, "source": "set"}).get("ok")
    assert T.networks_edit("metered", C, {"cap_gb": 20.0, "period": "month", "from_day": 14}).get("ok")
    state["pools"] = quota(C, 12.4)
    ref = oomph.reserve(0, "too much", H[0], net_gb=10)
    rc, out, _ = cli(oomph.cmd_reserve, ["--net", "10G", "--for", "too much", "--json"])
    resets = b14.strftime("%-d %b")
    check(ref["status"] == "refused" and "12.4 of 20 GB used this period" in ref["advice"]
          and "it resets on %s" % resets in ref["advice"] and "5.6 GB can be reserved" in ref["advice"]
          and rc == 75 and json.loads(out)["status"] == "refused" and not oomph.read_ledger()["leases"],
          "10 GB on a 20 GB cap with 12.4 used is refused at once (exit 75): what was used, when it resets, what can be "
          "reserved (%s)" % ref["advice"][:120])
    g1 = oomph.reserve(0, "4 GB", H[0], net_gb=4)
    w1 = oomph.reserve(0, "3 GB", H[1], net_gb=3)
    w2 = oomph.reserve(0, "1 GB after it", H[2], net_gb=1)
    mm = oomph.reserve(1, "memory meanwhile", H[3])
    check(g1["status"] == "granted" and "this network is metered" in (g1.get("note") or "")
          and g1["available"].get("net_quota_gb") == 1.6
          and w1["status"] == "queued" and w1.get("waiting_on") == ["net.quota"]
          and "you asked to move 3 GB, and 1.6 GB" in w1["advice"]
          and w2["status"] == "queued" and "net.quota" in w2.get("waiting_on", []) and mm["status"] == "granted",
          "4 GB granted in full (1.6 left); 3 GB waits on net.quota with the reason; 1 GB behind it waits too (first come, "
          "first served); memory passes (%s)" % [g1.get("note"), w1.get("waiting_on"), w2.get("waiting_on")])
    with oomph.Ledger() as L:   # the logger counted 3 of the 4 GB: its outstanding volume is 1 GB now
        x = next(r for r in L["leases"] if r["id"] == g1["id"])
        x["res"]["net"]["moved"] = 3.0
    state["pools"] = quota(C, 15.4)
    w1b = oomph.reserve(0, "3 GB", H[1], ticket=w1["id"])
    w2b = oomph.reserve(0, "1 GB after it", H[2], ticket=w2["id"])
    rc_w, out_w, _ = cli(oomph.cmd_reserve, ["--ticket", w1["id"], "--for", "3 GB", "--json"])
    why = w1b.get("advice") or w1b.get("note") or ""
    check(w1b["status"] == "refused" and "15.4 of 20 GB used this period" in why and "2.6 GB can be reserved" in why
          and w2b["status"] == "granted" and w2b["available"].get("net_quota_gb") == 0.6
          and not any(r["id"] == w1["id"] for r in oomph.read_ledger()["leases"])
          and rc_w == 75 and json.loads(out_w)["status"] == "refused",
          "what a grant has moved is in `used` (15.4) and no longer outstanding: the queued 3 GB can never fit this "
          "period (2.6 GB, whatever is released) and is refused with the reason, so it holds nobody up until the reset "
          "(the ticket's poll exits 75); the 1 GB behind it is granted, 0.6 GB left (%s)"
          % [w1b.get("status"), why[:90], w2b.get("status"), w2b.get("available"), rc_w])
    oomph.release(g1["id"])
    am = oomph.amend(w2["id"], net_gb=3)
    am_ok = oomph.amend(w2["id"], net_gb=2.0)
    am_down = oomph.amend(w2["id"], net_gb=0.5)
    check(am["status"] == "refused" and "this network is metered" in am["advice"] and "1.6 GB of its cap" in am["advice"]
          and part(w2["id"]).get("gb") == 0.5 and am_ok.get("changed", {}).get("net_gb") == [1.0, 2.0]
          and am_down.get("changed", {}).get("net_gb") == [2.0, 0.5],
          "amend: growing a granted volume by more than is left is refused with the reason; by less, and shrinking, "
          "apply (%s)" % am["advice"][:100])
    clear()
    both = oomph.reserve(0, "both ways", H[0], net_gb=3, net_up_gb=3)
    check(both["status"] == "refused" and "6 GB" in both["advice"], "download and upload volumes count together (6 > 5.6)")
    clear()
    state["pools"] = quota(C, 12.4)
    two = oomph.reserve(0, "both ways, small", H[0], net_gb=1, net_up_gb=1)   # 3.6 GB left to reserve
    am2 = oomph.amend(two["id"], net_gb=3, net_up_gb=3)
    kept = (part(two["id"]).get("gb"), part(two["id"], "net_up").get("gb"))
    am3 = oomph.amend(two["id"], net_gb=2.5, net_up_gb=2)
    check(two["status"] == "granted" and am2["status"] == "refused" and "upload" in am2["advice"]
          and kept == (1.0, 1.0)
          and am3.get("changed", {}).get("net_gb") == [1.0, 2.5] and am3["changed"].get("net_up_gb") == [1.0, 2.0],
          "amend: both directions grow out of one room (3.6 GB): 2 + 2 more refused at the upload, nothing changed; "
          "1.5 + 1 more applies (%s)" % am2.get("advice", "")[:90])
    clear()
    qa = oomph.reserve(0, "4 GB", H[0], net_gb=4)
    qb = oomph.reserve(0, "3 GB queued", H[1], net_gb=3)
    qc = oomph.amend(qb["id"], net_gb=6)
    kept = part(qb["id"]).get("gb")
    qd = oomph.amend(qb["id"], net_gb=5)
    check(qa["status"] == "granted" and qb["status"] == "queued" and qc["status"] == "refused"
          and "can be reserved" in qc["advice"] and "5.6 GB" in qc["advice"] and kept == 3.0
          and qd.get("changed", {}).get("net_gb") == [3.0, 5.0] and qd["status"] == "queued",
          "amend: a queued request grown past what this period can ever grant (5.6 GB) is refused, nothing changed; "
          "grown within it, it waits at the back (%s)" % qc.get("advice", "")[:90])
    clear()

    # a metered network without a figure: the volume unmanaged at once, and charged against the quota all the same
    assert T.networks_edit("metered", B, {"cap_gb": 10.0, "period": "week"}).get("ok")
    state["net"] = {"if": "en0", "vpn": False, "network": B, "src": "flows", "down_mbps": 0.0, "up_mbps": 0.0}
    state["pools"] = quota(B, 2.0, cap=10.0, m={"cap_gb": 10.0, "period": "week"})
    u1 = oomph.reserve(0, "hotspot pull", H[0], net_gb=5)
    u2 = oomph.reserve(0, "another", H[1], net_gb=3)
    check(u1["status"] == "granted" and u1["run_with"].get("net_unmanaged") and part(u1["id"]).get("unmanaged")
          and u2["status"] == "queued" and u2.get("waiting_on") == ["net.quota"],
          "a metered network without a figure: 5 GB granted unmanaged (no rate); 3 GB more waits on net.quota (2 left)")
    clear()

    # a volume weighs net.quota only on a metered network: elsewhere it neither waits behind nor holds up anyone's
    D4 = "rmac:00:00:5e:00:53:04"   # no entry: unknown, not metered
    state["net"] = {"if": "en0", "vpn": False, "network": D4, "src": "flows", "down_mbps": 0.0, "up_mbps": 0.0}
    state["pools"] = None
    later = oomph.reserve(1, "a later writer's", H[4])
    with oomph.Ledger() as L:   # a lease of a resource this code does not know: it holds every pool it weighs
        x = next(r for r in L["leases"] if r["id"] == later["id"])
        x["state"], x["res"] = "queued", dict(x.get("res") or {}, tpu={"ask": 1})
    un = oomph.reserve(0, "unknown network", H[0], net_gb=4)
    check(un["status"] == "granted" and "metered" not in part(un["id"]) and part(un["id"]).get("unmanaged")
          and "net.quota" not in oomph.lease_need(next(r for r in oomph.read_ledger()["leases"] if r["id"] == un["id"])),
          "an unmanaged volume on an unknown network that is not metered asks no pool: granted at once past an "
          "unweighable lease (%s)" % un.get("waiting_on"))
    clear()
    state["net"] = {"if": "en0", "vpn": False, "network": C, "src": "flows", "down_mbps": 0.0, "up_mbps": 0.0}
    state["pools"] = quota(C, 12.4)
    big = oomph.reserve(0, "the line and 4 GB", H[0], net_gb=4, net_mbps=140, net_min_mbps=140)
    fa = oomph.reserve(0, "a turn and 3 GB", H[1], net_gb=3, net_mbps=100, net_min_mbps=100)
    fb = oomph.reserve(0, "1 GB up after it", H[2], net_up_gb=1)
    check(big["status"] == "granted" and fa["status"] == "queued" and {"net.down", "net.quota"} <= set(fa["waiting_on"])
          and part(fa["id"]).get("metered") is True and fb["status"] == "queued"
          and "net.quota" in fb.get("waiting_on", []),
          "first come, first served on net.quota: a request waiting for a turn at the line and short of the cap holds "
          "the cap up too, so an upload volume behind it waits (%s, %s)" % (fa.get("waiting_on"), fb.get("waiting_on")))
    clear()
    mem = oomph.reserve(1, "memory", H[3])
    mq = oomph.reserve(55, "memory and a volume", H[1], net_gb=1)
    gv = oomph.reserve(0, "a volume", H[0], net_gb=1)
    ga = oomph.amend(gv["id"], net_gb=2)
    check(mem["status"] == "granted" and mq["status"] == "queued" and mq.get("waiting_on") == ["ram"]
          and gv["status"] == "granted" and ga.get("changed", {}).get("net_gb") == [1.0, 2.0],
          "amend: a granted volume grows while the only queued volume request waits for memory, not for the cap (%s)"
          % ga.get("advice", ga.get("changed")))
    clear()
    nd3 = T.NetDays()
    real = D.today()
    for i in range(62):
        nd3.add(A, (real - datetime.timedelta(days=i)).isoformat(), 1e9, 0)
    nd3.days[A][(real + datetime.timedelta(days=40)).isoformat()] = [5e9, 0.0, False]   # a clock set forward, then back
    nd3.add(A, real.isoformat(), 1e9, 0)
    nd3.add(A, (real + datetime.timedelta(days=1)).isoformat(), 1e9, 0)
    check(len(nd3.days[A]) == 62 and max(nd3.days[A]) == (real + datetime.timedelta(days=1)).isoformat()
          and (real - datetime.timedelta(days=60)).isoformat() in nd3.days[A],
          "a date after tomorrow is trimmed before the period's real dates")

    # without the logger: `used` from its day counters (what it counted until it stopped)
    state["net"] = {"if": "en0", "vpn": False, "network": C, "src": "id"}
    state["pools"] = None
    nd2 = T.NetDays(path)
    nd2.add(C, a14.isoformat(), 10e9, 0)
    nd2.add(C, (a14 - datetime.timedelta(days=1)).isoformat(), 50e9, 0)
    with open(path, "w") as f:
        f.write(nd2.dumps())
    n9 = oomph.reserve(0, "9", H[0], net_gb=9)
    n7 = oomph.reserve(0, "7", H[0], net_gb=7)
    check(n9["status"] == "refused" and "10 of 20 GB used" in n9["advice"] and n7["status"] == "granted",
          "no logger: what its counters hold this period is used (10 GB; the day before the period not): 9 GB refused, "
          "7 GB granted (%s)" % n9["advice"][:80])
    clear()
    G = "gw:192.0.2.1/24"   # counted under the gateway's key before the router's was adopted (as quota_block adds)
    nd2.add(G, a14.isoformat(), 3e9, 0)
    with open(path, "w") as f:
        f.write(nd2.dumps())
    nets = T.read_networks()["networks"]
    qv = T.quota_view(dict(sample(), net=dict(state["net"], network=G)), C, nets[C], [], time.time())
    check(qv and qv["used"] == 13.0 and not qv["counted"],
          "no logger: the sample's own key's days count too (10 + 3 GB, as the logger's quota_block) (%s)"
          % (qv or {}).get("used"))
    os.remove(path)
    state["net"] = {"if": "en0", "vpn": False, "network": C, "src": "flows", "down_mbps": 3.0, "up_mbps": 0.2}

    # --- what readers say: the network line, check --json, memory_check, oomph net (12.13)
    state["pools"] = quota(C, 12.4, label="phone")
    rl = T.resource_line(sample(), samples=[])[1]
    state["pools"] = quota(C, 18.2, label="phone")
    s_low = sample()
    rl_low = T.resource_line(s_low, samples=[])[1]
    ni = T.network_info(s_low, samples=[])
    mc = oomph._mcp_call("memory_check", {})
    check("metered: 12.4 of 20 GB used this period, resets %s" % resets in rl
          and "metered: ▲ 1.8 of 20 GB left until %s" % resets in rl_low
          and ni["metered"] == {"left_gb": 1.8, "resets": b14.isoformat(), "cap_gb": 20.0, "used_gb": 18.2,
                                "period": "month", "low": True}
          and (mc.get("network") or {}).get("metered", {}).get("low") is True and mc["level"] == "ok",
          "the network line says what is used and when it resets, under 10 %% what is left first; check --json and "
          "memory_check carry `metered` (low), and memory's level stays its own (%s | %s)" % (rl[-70:], rl_low[-50:]))
    with open(os.path.join(LOG, "current.json"), "w") as f:
        json.dump(dict(sample(), source=None, daemon={"version": oomph.VERSION}), f)
    rc_s, out_s, _ = cli(T.cmd_net, [])
    out_s = " ".join(out_s.split())
    rc_j, out_j, _ = cli(T.cmd_net, ["--json"])
    mj = json.loads(out_j).get("metered") or {}
    check(rc_s == 0 and "quota" in out_s and "1.8 of 20 GB left until" in out_s and "a month from the 14th" in out_s
          and "GB can be reserved" in out_s and "the logger" not in out_s and "LAN" not in out_s
          and rc_j == 0 and mj.get("low") is True and mj.get("used") == 18.2 and mj.get("counted") is True,
          "oomph net: a quota line (left, from when, the rule, what can be reserved); --json with `metered`")
    del os.environ["OOMPH_NET_RESERVATIONS"]   # switched off (the default): the cap is shown, no reservable GB
    rc_o, out_o, _ = cli(T.cmd_net, [])
    out_o = " ".join(out_o.split())
    mjo = json.loads(cli(T.cmd_net, ["--json"])[1]).get("metered") or {}
    ms = oomph._mcp_call("memory_status", {})
    nwo = ms.get("network") or {}
    mco = oomph._mcp_call("memory_check", {}).get("network") or {}
    check(rc_o == 0 and "1.8 of 20 GB left until" in out_o and "can be reserved" not in out_o
          and "reservable: off (net_reservations)" in out_o and "room" not in mjo and "reserved" not in mjo
          and mjo.get("reservable_off") == "net_reservations" and mjo.get("low") is True
          and "available_gb" not in (nwo.get("metered") or {}) and nwo.get("reservable_off") == "net_reservations"
          and (nwo.get("metered") or {}).get("low") is True and "available_gb" not in (mco.get("metered") or {})
          and mco.get("reservable_off") == "net_reservations",
          "net_reservations off: oomph net, --json, memory_status and memory_check show the cap but offer nothing to "
          "reserve (%s | %s)" % (out_o[-90:], nwo.get("metered")))
    os.environ["OOMPH_NET_RESERVATIONS"] = "1"
    os.remove(os.path.join(LOG, "current.json"))

    # --- the hook (12.17): silent about the network, except under 10 % left: once per session and period
    def hook():
        old = sys.stdin
        sys.stdin = io.StringIO("{}")
        try:
            return cli(oomph.cmd_hook, [])
        finally:
            sys.stdin = old
    state["pools"] = quota(C, 12.4, label="phone")
    h0 = hook()
    state["pools"] = quota(C, 18.2, label="phone")
    h1 = hook()
    h2 = hook()
    check(h0 == (0, "", "") and h1[0] == 2
          and h1[2].strip() == "oomph: the metered network phone has 1.8 of 20 GB left until %s (oomph net)" % resets
          and h2 == (0, "", ""),
          "the hook: silent with 7.6 GB left; under 10 %% one line, exit 2; the next call silent (%r)" % h1[2].strip())
    state["pools"] = quota(B, 9.5, cap=10.0, m={"cap_gb": 10.0, "period": "week"})
    h3 = hook()
    h4 = hook()
    BASE["pressure"] = 2
    state["pools"] = quota(C, 18.2, label="phone")
    h5 = hook()
    BASE["pressure"] = 1
    check(h3[0] == 2 and "this metered network has 0.5 of 10 GB left" in h3[2] and h4 == (0, "", "")
          and h5[0] == 2 and "TIGHT" in h5[2] and "phone" not in h5[2],
          "the hook: another network (or period) is said once too; memory tight is said as before, the network not "
          "again (%r)" % h5[2][:60])
    state["pools"] = quota(A, 19.0, label="other")   # memory recovers on the call that first says this network
    h6 = hook()
    BASE["pressure"] = 2
    h7 = hook()
    BASE["pressure"] = 1
    check(h6[0] == 2 and "other" in h6[2] and "TIGHT" not in h6[2] and h7[0] == 2 and "TIGHT" in h7[2],
          "the hook: memory ok again on a network-only call is saved as ok, so tight within 10 minutes is said again "
          "(%r)" % h7[2][:60])

    # --- the capsule (12.15): amber "Network 1.8 GB left", after memory and disk
    c_low = oomph.capsule(dict(sample(), pools=quota(C, 18.2)))
    c_ok = oomph.capsule(dict(sample(), pools=quota(C, 18.0)))
    c_mem = oomph.capsule(dict(sample(), pressure=2, pools=quota(C, 18.2)))
    c_disk = oomph.capsule(dict(sample(), disk_free_gb=14.0, pools=quota(C, 25.0)))
    c_zero = oomph.capsule(dict(sample(), pools=quota(C, 25.0)))
    check(c_low == {"text": "Network 1.8 GB left", "level": 1, "memory": 0, "disk": 0, "network": 1}
          and c_ok["network"] == 0 and c_ok["text"] == "Normal" and c_mem["text"] == "Memory tight"
          and c_mem["network"] == 1 and c_disk["text"].startswith("Disk") and c_zero["text"] == "Network 0.0 GB left"
          and oomph.verdict(dict(sample(), pools=quota(C, 18.2)))["level"] == "ok",
          "the capsule: under 10 %% amber with what is left; exactly 10 %% not; memory and disk come first; over the "
          "cap 0.0; the verdict's level is memory's alone (%s)" % c_low)

    # --- `oomph net metered` (12.13): stored for every user, shown in net list
    rc1, o1, _ = cli(T.cmd_net, ["metered", "--cap", "5G/week", "--from", "sunday", A])
    e1 = T.read_networks()["networks"].get(A, {}).get("metered") or {}
    rc2, o2, _ = cli(T.cmd_net, ["list"])
    rc3, o3, _ = cli(T.cmd_net, ["metered", "--off", A])
    rc4, o4, _ = cli(T.cmd_net, ["metered", "--off", A])
    errs = [cli(T.cmd_net, a)[0] for a in (["metered"], ["metered", "--cap", "20G", A], ["metered", "--off", "--cap",
                                                                                        "1G/day", A],
                                           ["metered", "--cap", "1G/day", "--from", "3", A],
                                           ["metered", "--cap", "1G/month", "--from", "32", A],
                                           ["metered", "--off", "--from", "3", A])]
    check(rc1 == 0 and "is metered now: 5 GB a week from Sunday" in o1 and e1.get("from_day") == 7
          and e1.get("period") == "week" and e1.get("cap_gb") == 5.0 and e1.get("set_by") and rc2 == 0
          and "metered: 5 GB a week from Sunday" in o2 and rc3 == 0 and "is not metered now" in o3
          and A not in T.read_networks()["networks"] and rc4 == 0 and "was not metered" in o4 and errs == [2] * 6,
          "oomph net metered: --cap and --from stored with who set it, net list shows it, --off removes it (and the "
          "entry with nothing else), usage errors exit 2 (%s)" % errs)
    rc5, o5, _ = cli(T.cmd_net, ["metered", "--cap", "20G/month", "--from", "14", C, "--json"])
    check(rc5 == 0 and json.loads(o5)["entry"]["down"] == 194.0 and json.loads(o5)["entry"]["metered"]["from_day"] == 14,
          "a figure stays when a cap is set (--json)")
    v_e = T.valid_entry({"metered": {"cap_gb": 20, "period": "week", "from_day": 9}, "down": 5.0})
    v_y = T.valid_entry({"metered": {"cap_gb": 20, "period": "year"}, "down": 5.0})
    check(v_e["metered"] == {"cap_gb": 20.0, "period": "week"} and "metered" not in v_y,
          "the sanitizer: a week's day 9 is dropped, a period it does not know drops the cap")
finally:
    for x in sleepers:
        x.kill()
        x.wait()
    shutil.rmtree(TMP, ignore_errors=True)

print("\nFAILED (%d)" % len(failures) if failures else "\nall metered network checks passed")
sys.exit(1 if failures else 0)
