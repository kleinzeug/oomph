#!/usr/bin/python3 -I
"""oomph — inspect the memory papertrail written by oomphd.

  oomph status
  oomph report [--last 2h | --since ISO [--until ISO]]
  oomph incidents
  oomph incident <id|latest> [--html]
  oomph html [--last 6h | --since ISO [--until ISO]] [-o FILE] [--open]

for agents and scripts (work without the daemon too — they measure live):
  oomph check [--json]              verdict ok / tight / critical + advice; exit 0 / 1 / 2
  oomph session [--json] [--pid N]  memory of the Claude session this runs in (its whole process tree)
  oomph wait [--timeout 10m] [--free 4G]   block until memory is ok again; exit 1 on timeout
  oomph status --json               the latest full sample
  oomph hook                        Claude Code PostToolUse hook: silent when ok, warns when tight
  oomph mcp                         MCP server over stdio (tools: memory_check, my_session, ...)
  oomph setup-claude [--hook] [--remove]   install the skill + register the MCP server for Claude Code
"""
import datetime
import glob
import gzip
import html as _html
import json
import os
import re
import subprocess
import sys
import time

VERSION = "1.1.0"
LOG_DIR = os.environ.get("OOMPH_DIR", "/Library/Logs/oomph")

# What the daemon streams from the unified log. On macOS 27 memory kills show up as
# launchd exits with OS_REASON_JETSAM and as ReportSystemMemory batch lines
# "Process X [pid] killed by jetsam reason low-swap"; idle-exit kills are excluded.
LOG_PREDICATE = (
    '(process == "launchd" AND eventMessage CONTAINS "OS_REASON_JETSAM")'
    ' OR (process == "ReportSystemMemory" AND eventMessage CONTAINS "killed by jetsam")'
    ' OR ((process == "loginwindow" OR process == "UserNotificationCenter")'
    ' AND eventMessage CONTAINS[c] "application memory")'
)

PRESSURE = {0: "?", 1: "normal", 2: "WARN", 4: "CRITICAL"}
AWAY_IDLE_S = 300


# ------------------------------------------------------------------ loading
def _day_range(since, until):
    d = datetime.date.fromtimestamp(since)
    end = datetime.date.fromtimestamp(until)
    while d <= end:
        yield d.isoformat()
        d += datetime.timedelta(days=1)


def _read_lines(path):
    opener = gzip.open if path.endswith(".gz") else open
    try:
        with opener(path, "rt") as f:
            for line in f:
                yield line
    except (OSError, EOFError):
        return


def load_samples(since, until):
    out = []
    for day in _day_range(since, until):
        for path in (os.path.join(LOG_DIR, "samples-%s.jsonl.gz" % day),
                     os.path.join(LOG_DIR, "samples-%s.jsonl" % day)):
            if not os.path.exists(path):
                continue
            for line in _read_lines(path):
                try:
                    s = json.loads(line)
                except ValueError:
                    continue
                if since <= s.get("t", 0) <= until:
                    out.append(s)
    out.sort(key=lambda s: s["t"])
    return out


def load_events(since, until):
    out = []
    for path in (os.path.join(LOG_DIR, "events.jsonl.1"), os.path.join(LOG_DIR, "events.jsonl")):
        if os.path.exists(path):
            for line in _read_lines(path):
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                if since <= e.get("t", 0) <= until:
                    out.append(e)
    out.sort(key=lambda e: e["t"])
    return out


def is_away(s):
    a = s.get("away") or {}
    return bool((a.get("idle_s") or 0) >= AWAY_IDLE_S or a.get("locked") or a.get("display_on") is False)


# ---------------------------------------------------------------- summarize
def _risers(samples, key, limit=10):
    first, peak, peak_t, last = {}, {}, {}, {}
    for s in samples:
        for p in s.get(key) or []:
            k = p["name"] if key == "groups" else "%s [%s]" % (p["name"], p["pid"])
            first.setdefault(k, p["mb"])
            last[k] = p["mb"]
            if p["mb"] > peak.get(k, -1):
                peak[k], peak_t[k] = p["mb"], s["t"]
    rows = [{"name": k, "first_mb": first[k], "peak_mb": peak[k], "last_mb": last[k],
             "rise_mb": peak[k] - first[k], "peak_iso": _hm(peak_t[k])} for k in peak]
    rows.sort(key=lambda r: (r["rise_mb"], r["peak_mb"]), reverse=True)
    return rows[:limit]


def _hm(t):
    return datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")


def summarize(samples, events):
    if not samples:
        return {"samples": 0}
    peak = max(samples, key=lambda s: (s.get("pressure", 0), s.get("swap_used_gb", 0),
                                       s.get("app_gb", 0) + s.get("compressed_gb", 0)))
    onset = next((s for s in samples if s.get("pressure", 0) >= 2 or s.get("jetsam_kills")), None)
    kills = sum(s.get("jetsam_kills", 0) for s in samples)
    reasons = {}
    killed = {}
    for e in events:
        if e.get("kind") == "jetsam":
            for r, n in (e.get("reasons") or {}).items():
                reasons[r] = reasons.get(r, 0) + n
            for k, n in (e.get("top") or {}).items():
                killed[k] = killed.get(k, 0) + n
    away = sum(1 for s in samples if is_away(s))
    return {
        "samples": len(samples),
        "from": samples[0]["iso"], "to": samples[-1]["iso"],
        "peak_pressure": PRESSURE.get(peak.get("pressure", 0), peak.get("pressure")),
        "peak_at": peak["iso"],
        "max_swap_used_gb": max(s.get("swap_used_gb", 0) for s in samples),
        "max_swap_total_gb": max(s.get("swap_total_gb", 0) for s in samples),
        "min_disk_free_gb": min(s.get("disk_free_gb", 0) for s in samples),
        "max_app_plus_compressed_gb": round(max(s.get("app_gb", 0) + s.get("compressed_gb", 0) for s in samples), 1),
        "ram_gb": samples[-1].get("ram_gb"),
        "jetsam_kills": kills,
        "jetsam_reasons": reasons,
        "most_killed": dict(sorted(killed.items(), key=lambda kv: -kv[1])[:10]),
        "away_fraction": round(away / len(samples), 2),
        "onset": None if not onset else {
            "at": onset["iso"], "pressure": PRESSURE.get(onset.get("pressure", 0)),
            "idle_s": (onset.get("away") or {}).get("idle_s"),
            "display_on": (onset.get("away") or {}).get("display_on"),
            "locked": (onset.get("away") or {}).get("locked"),
            "swap_used_gb": onset.get("swap_used_gb"), "disk_free_gb": onset.get("disk_free_gb")},
        "top_at_peak": (peak.get("top") or [])[:10],
        "groups_at_peak": (peak.get("groups") or [])[:10],
        "claude_at_peak": peak.get("claude") or [],
        "group_risers": _risers(samples, "groups"),
        "process_risers": _risers(samples, "top"),
    }


# --------------------------------------------------------------------- HTML
CSS = """
:root{--bg:#fbfbfa;--fg:#1d1d1f;--muted:#6e6e73;--grid:#e3e3e0;--card:#fff;--line:#d9d9d6;
--c-wired:#8e8e93;--c-app:#3b82c4;--c-comp:#e0a030;--c-swap:#d0503c;--c-ram:#1d1d1f;--away:rgba(110,110,115,.12);
--k1:#3b82c4;--k2:#d0503c;--k3:#2f9e6e;--k4:#9b59b6;--k5:#e0a030;--bad:#d0503c}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#161618;--fg:#ececee;--muted:#9a9aa0;--grid:#2c2c30;--card:#1e1e21;--line:#34343a;
--c-wired:#6e6e74;--c-app:#5b9fe0;--c-comp:#e8b450;--c-swap:#ef6b56;--c-ram:#ececee;--away:rgba(160,160,170,.12);
--k1:#5b9fe0;--k2:#ef6b56;--k3:#45c08b;--k4:#b57edc;--k5:#e8b450;--bad:#ef6b56}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.kpi .v{font-size:20px;font-weight:600;font-variant-numeric:tabular-nums}.kpi .l{color:var(--muted);font-size:12px}
.bad{color:var(--bad)}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:12px}td.n{text-align:right}.scroll{overflow-x:auto}svg{width:100%;height:auto;display:block}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin-top:6px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
"""


def _e(x):
    return _html.escape(str(x))


def _scale(v, lo, hi, a, b):
    return a if hi == lo else a + (v - lo) * (b - a) / (hi - lo)


def _svg_chart(samples, series, stacked, events=(), ymax=None, unit="GB", refline=None, height=220, bars=None):
    W, H, L, R, T, B = 960, height, 48, 10, 10, 26
    if not samples:
        return "<p class=sub>No samples.</p>"
    t0, t1 = samples[0]["t"], samples[-1]["t"]
    if t1 == t0:
        t1 = t0 + 1
    xs = [_scale(s["t"], t0, t1, L, W - R) for s in samples]
    vals = [[f(s) or 0 for s in samples] for _, f, _ in series]
    if stacked:
        cum = [0.0] * len(samples)
        tops = []
        for v in vals:
            cum = [c + x for c, x in zip(cum, v)]
            tops.append(cum[:])
        top_max = max(max(t) for t in tops)
    else:
        top_max = max((max(v) for v in vals), default=1)
    ymax = ymax or max(top_max, refline or 0) * 1.08 or 1
    y = lambda v: _scale(v, 0, ymax, H - B, T)  # noqa: E731
    out = ['<svg viewBox="0 0 %d %d" role="img">' % (W, H)]
    # away shading
    i = 0
    while i < len(samples):
        if is_away(samples[i]):
            j = i
            while j + 1 < len(samples) and is_away(samples[j + 1]):
                j += 1
            x0, x1 = xs[i], xs[j] if j > i else xs[i] + 2
            out.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="var(--away)"/>' % (x0, T, max(x1 - x0, 2), H - B - T))
            i = j + 1
        else:
            i += 1
    # grid
    step = _nice_step(ymax)
    v = 0
    while v <= ymax:
        yy = y(v)
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--grid)"/>' % (L, W - R, yy, yy))
        out.append('<text x="%d" y="%.1f" font-size="11" fill="var(--muted)" text-anchor="end">%s</text>' % (L - 6, yy + 4, _fmt(v)))
        v += step
    # x labels
    n = 6
    for k in range(n + 1):
        tt = t0 + (t1 - t0) * k / n
        xx = _scale(tt, t0, t1, L, W - R)
        out.append('<text x="%.1f" y="%d" font-size="11" fill="var(--muted)" text-anchor="middle">%s</text>'
                   % (xx, H - 8, datetime.datetime.fromtimestamp(tt).strftime("%H:%M:%S" if t1 - t0 < 900 else ("%H:%M" if t1 - t0 < 86400 else "%a %H:%M"))))
    if stacked:
        prev = [H - B] * len(samples)
        for (label, _, color), tp in zip(series, tops):
            pts = " ".join("%.1f,%.1f" % (x, y(v)) for x, v in zip(xs, tp))
            back = " ".join("%.1f,%.1f" % (x, p) for x, p in reversed(list(zip(xs, prev))))
            out.append('<polygon points="%s %s" fill="%s" fill-opacity=".75" stroke="%s" stroke-width="1"/>' % (pts, back, color, color))
            prev = [y(v) for v in tp]
    else:
        for (label, _, color), v in zip(series, vals):
            pts = " ".join("%.1f,%.1f" % (x, y(vv)) for x, vv in zip(xs, v))
            out.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="1.8"/>' % (pts, color))
    if bars:
        f, color = bars
        bmax = max((f(s) or 0) for s in samples) or 1
        for s, xx in zip(samples, xs):
            bv = f(s) or 0
            if bv:
                h = max(2, 30 * bv / bmax)
                out.append('<rect x="%.1f" y="%.1f" width="2" height="%.1f" fill="%s" opacity=".8"/>' % (xx - 1, H - B - h, h, color))
    if refline:
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--c-ram)" stroke-dasharray="5 4"/>' % (L, W - R, y(refline), y(refline)))
        out.append('<text x="%d" y="%.1f" font-size="11" fill="var(--fg)" text-anchor="end">RAM %s %s</text>' % (W - R - 4, y(refline) - 4, _fmt(refline), unit))
    for e in events:
        if t0 <= e["t"] <= t1:
            xx = _scale(e["t"], t0, t1, L, W - R)
            out.append('<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" stroke="var(--bad)" stroke-width="1.5"><title>%s</title></line>'
                       % (xx, xx, T, H - B, _e(e.get("iso", "") + " " + e.get("kind", ""))))
    out.append("</svg>")
    leg = "".join('<span><i class=sw style="background:%s"></i>%s</span>' % (c, _e(l)) for l, _, c in series)
    leg += '<span><i class=sw style="background:var(--away)"></i>away (idle ≥5 min / locked / display off)</span>'
    return "".join(out) + '<div class=legend>%s</div>' % leg


def _nice_step(m):
    for s in (0.5, 1, 2, 4, 5, 8, 10, 20, 25, 50, 100, 200, 500, 1000, 2000, 5000):
        if m / s <= 6:
            return s
    return m / 5


def _fmt(v):
    return ("%.1f" % v).rstrip("0").rstrip(".") if isinstance(v, float) else str(v)


def _table(rows, cols):
    if not rows:
        return "<p class=sub>none</p>"
    h = "".join("<th>%s</th>" % _e(c[0]) for c in cols)
    body = ""
    for r in rows:
        body += "<tr>" + "".join('<td class="%s">%s</td>' % ("n" if c[2] else "", _e(c[1](r))) for c in cols) + "</tr>"
    return '<div class=scroll><table><tr>%s</tr>%s</table></div>' % (h, body)


def render_html(samples, events, title, incident=None):
    summ = summarize(samples, events)
    marks = [e for e in events if e.get("kind") in ("incident_open", "pressure_change") and
             (e.get("kind") == "incident_open" or e.get("new", 0) >= 4)]
    mem_series = [("wired", lambda s: s.get("wired_gb"), "var(--c-wired)"),
                  ("app memory", lambda s: s.get("app_gb"), "var(--c-app)"),
                  ("compressed", lambda s: s.get("compressed_gb"), "var(--c-comp)"),
                  ("swap used", lambda s: s.get("swap_used_gb"), "var(--c-swap)")]
    ram = samples[-1].get("ram_gb") if samples else None
    # top-5 app groups by peak
    peaks = {}
    for s in samples:
        for g in s.get("groups") or []:
            peaks[g["name"]] = max(peaks.get(g["name"], 0), g["mb"])
    top5 = [k for k, _ in sorted(peaks.items(), key=lambda kv: -kv[1])[:5]]
    colors = ["var(--k1)", "var(--k2)", "var(--k3)", "var(--k4)", "var(--k5)"]

    def gval(name):
        return lambda s: next((g["mb"] / 1024 for g in s.get("groups") or [] if g["name"] == name), 0)
    grp_series = [(n, gval(n), c) for n, c in zip(top5, colors)]
    disk_series = [("free disk GB", lambda s: s.get("disk_free_gb"), "var(--k3)"),
                   ("swap total GB", lambda s: s.get("swap_total_gb"), "var(--c-swap)")]

    k = []
    if summ.get("samples"):
        o = summ.get("onset") or {}
        k = [("Peak pressure", summ["peak_pressure"], summ["peak_pressure"] in ("WARN", "CRITICAL")),
             ("Max swap used", "%.1f GB" % summ["max_swap_used_gb"], False),
             ("Min free disk", "%.0f GB" % summ["min_disk_free_gb"], summ["min_disk_free_gb"] < 20),
             ("Jetsam kills", summ["jetsam_kills"], summ["jetsam_kills"] > 0),
             ("Away during window", "%d%%" % round(100 * summ["away_fraction"]), False),
             ("Idle at onset", ("%d min" % (o["idle_s"] // 60)) if o.get("idle_s") is not None else "–", False)]
    kpis = "".join('<div class="card kpi"><div class="v %s">%s</div><div class=l>%s</div></div>'
                   % ("bad" if bad else "", _e(v), _e(l)) for l, v, bad in k)
    reasons_html = ""
    if incident:
        reasons_html = "<h2>Triggers</h2>" + _table(incident.get("reasons", []), [
            ("time", lambda r: _hm(r["t"]), False), ("kind", lambda r: r["kind"], False), ("detail", lambda r: r["desc"], False)])
    cl = summ.get("claude_at_peak") or []
    ev_rows = [e for e in events if e.get("kind") not in ("notified",)][-200:]
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
        "<title>%s</title><style>%s</style></head><body><main>" % (_e(title), CSS),
        "<h1>%s</h1><p class=sub>%s → %s · %d samples · generated %s by oomph %s</p>" % (
            _e(title), _e(summ.get("from", "")), _e(summ.get("to", "")), summ.get("samples", 0),
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), VERSION),
        '<div class=kpis>%s</div>' % kpis,
        reasons_html,
        "<h2>System memory (stacked) vs. RAM</h2><div class=card>%s</div>" % _svg_chart(
            samples, mem_series, True, marks, refline=ram,
            bars=(lambda s: s.get("jetsam_kills"), "var(--bad)")),
        "<h2>Top 5 apps / process groups (GB)</h2><div class=card>%s</div>" % _svg_chart(samples, grp_series, False, marks),
        "<h2>Free disk and swap size (GB)</h2><div class=card>%s</div>" % _svg_chart(samples, disk_series, False, marks, height=160),
        "<h2>Biggest risers — apps</h2><div class=card>%s</div>" % _table(summ.get("group_risers", []), [
            ("app / group", lambda r: r["name"], False), ("first MB", lambda r: r["first_mb"], True),
            ("peak MB", lambda r: r["peak_mb"], True), ("rise MB", lambda r: r["rise_mb"], True), ("peak at", lambda r: r["peak_iso"], False)]),
        "<h2>Biggest risers — processes</h2><div class=card>%s</div>" % _table(summ.get("process_risers", []), [
            ("process", lambda r: r["name"], False), ("first MB", lambda r: r["first_mb"], True),
            ("peak MB", lambda r: r["peak_mb"], True), ("rise MB", lambda r: r["rise_mb"], True), ("peak at", lambda r: r["peak_iso"], False)]),
        "<h2>Claude sessions at peak (%s)</h2><div class=card>%s</div>" % (_e(summ.get("peak_at", "")), _table(cl, [
            ("pid", lambda r: r["pid"], True), ("project", lambda r: r.get("cwd") or "?", False),
            ("total MB", lambda r: r["mb"], True), ("procs", lambda r: r["n"], True),
            ("biggest child", lambda r: ("%s (%s MB)" % (r["biggest"]["name"], r["biggest"]["mb"])) if r.get("biggest") else "", False)])),
        "<h2>Top processes at peak</h2><div class=card>%s</div>" % _table(summ.get("top_at_peak", []), [
            ("pid", lambda r: r["pid"], True), ("name", lambda r: r["name"], False), ("MB", lambda r: r["mb"], True)]),
        "<h2>Most-killed by jetsam</h2><div class=card>%s<p class=sub>reasons: %s</p></div>" % (
            _table([{"n": k2, "c": v2} for k2, v2 in (summ.get("most_killed") or {}).items()],
                   [("service", lambda r: r["n"], False), ("kills", lambda r: r["c"], True)]),
            _e(", ".join("%s × %d" % kv for kv in (summ.get("jetsam_reasons") or {}).items()) or "–")),
        "<h2>Events</h2><div class=card>%s</div>" % _table(ev_rows, [
            ("time", lambda e: e.get("iso", "")[11:19], False), ("kind", lambda e: e.get("kind"), False),
            ("detail", lambda e: _event_detail(e), False)]),
        "</main></body></html>",
    ]
    return "".join(parts)


def _event_detail(e):
    skip = {"t", "iso", "kind"}
    return ", ".join("%s=%s" % (k, json.dumps(v) if isinstance(v, (dict, list)) else v)
                     for k, v in e.items() if k not in skip)[:300]


# ---------------------------------------------------------------------- CLI
def parse_dur(s):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)([smhd])", s.strip())
    if not m:
        raise SystemExit("bad duration: %s (use e.g. 30m, 2h, 1d)" % s)
    return float(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def parse_time(s):
    return datetime.datetime.fromisoformat(s).timestamp()


def window(args, default="2h"):
    until = time.time()
    since = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--last":
            since = until - parse_dur(args[i + 1]); i += 1
        elif a == "--since":
            since = parse_time(args[i + 1]); i += 1
        elif a == "--until":
            until = parse_time(args[i + 1]); i += 1
        i += 1
    if since is None:
        since = until - parse_dur(default)
    return since, until


def cmd_status():
    p = os.path.join(LOG_DIR, "current.json")
    if not os.path.exists(p):
        print("oomph: no data in %s — daemon not installed or not running" % LOG_DIR)
        return 1
    c = json.load(open(p))
    age = time.time() - c["t"]
    d = c.get("daemon", {})
    alive = age < 3 * (d.get("interval") or 30) + 10
    a = c.get("away") or {}
    print("daemon     %s (pid %s, v%s, sample %ds ago, interval %ss%s)" % (
        "running" if alive else "NOT RUNNING", d.get("pid"), d.get("version"), age, d.get("interval"),
        ", root" if d.get("root") else ", NOT root"))
    print("pressure   %s   free %s%%" % (PRESSURE.get(c["pressure"], c["pressure"]), c.get("free_pct")))
    print("memory     RAM %.0f GB · app %.1f · wired %.1f · compressed %.1f · cached %.1f · free %.1f GB" % (
        c["ram_gb"], c["app_gb"], c["wired_gb"], c["compressed_gb"], c["cached_gb"], c["free_gb"]))
    print("swap       %.1f / %.1f GB used (%d swapfiles)" % (c["swap_used_gb"], c["swap_total_gb"], c["swapfiles"]))
    print("disk       %.0f GB free" % c["disk_free_gb"])
    print("you        idle %ss · display %s · %s · sleep held by %s" % (
        a.get("idle_s"), "on" if a.get("display_on") else "off", "locked" if a.get("locked") else "unlocked",
        ", ".join(a.get("sleep_preventers") or []) or "nobody"))
    if d.get("incident"):
        print("INCIDENT   open: %s" % d["incident"])
    print("\ntop apps:")
    for g in (c.get("groups") or [])[:8]:
        print("  %6.1f GB  %s (%d)" % (g["mb"] / 1024, g["name"], g["n"]))
    if c.get("claude"):
        print("\nclaude sessions:")
        for s in c["claude"]:
            print("  %6.1f GB  pid %-6s %s" % (s["mb"] / 1024, s["pid"], s.get("cwd")))
    return 0


def cmd_report(args):
    since, until = window(args)
    samples = load_samples(since, until)
    events = load_events(since, until)
    if not samples:
        print("no samples in window")
        return 1
    span = samples[-1]["t"] - samples[0]["t"]
    bucket = max(60, int(span / 36 // 60 * 60) or 60)
    print("%-8s %-8s %6s %6s %6s %6s %5s %4s  %s" % ("time", "pressure", "app", "compr", "swap", "disk", "kills", "away", "biggest app"))
    cur, rows = None, []
    for s in samples:
        b = int(s["t"] // bucket)
        if b != cur:
            rows.append([])
            cur = b
        rows[-1].append(s)
    for r in rows:
        worst = max(r, key=lambda s: (s.get("pressure", 0), s.get("swap_used_gb", 0)))
        g = (worst.get("groups") or [{}])[0]
        print("%-8s %-8s %6.1f %6.1f %6.1f %6.0f %5d %4s  %s %.1fG" % (
            datetime.datetime.fromtimestamp(r[0]["t"]).strftime("%H:%M"), PRESSURE.get(worst.get("pressure", 0)),
            worst["app_gb"], worst["compressed_gb"], worst["swap_used_gb"], worst["disk_free_gb"],
            sum(s.get("jetsam_kills", 0) for s in r), "yes" if any(is_away(s) for s in r) else "",
            g.get("name", ""), g.get("mb", 0) / 1024))
    summ = summarize(samples, events)
    print("\nbiggest risers (apps):")
    for x in summ["group_risers"][:8]:
        print("  +%6d MB  %-40s peak %d MB at %s" % (x["rise_mb"], x["name"][:40], x["peak_mb"], x["peak_iso"]))
    print("\nbiggest risers (processes):")
    for x in summ["process_risers"][:8]:
        print("  +%6d MB  %-40s peak %d MB at %s" % (x["rise_mb"], x["name"][:40], x["peak_mb"], x["peak_iso"]))
    notable = [e for e in events if e.get("kind") not in ("jetsam", "notified")]
    if summ["jetsam_kills"]:
        print("\njetsam kills: %d   reasons: %s" % (summ["jetsam_kills"], summ["jetsam_reasons"]))
    if notable:
        print("\nevents:")
        for e in notable[-30:]:
            print("  %s  %-16s %s" % (e["iso"][11:19], e["kind"], _event_detail(e)[:110]))
    return 0


def list_incidents():
    out = []
    for f in sorted(glob.glob(os.path.join(LOG_DIR, "incidents", "*", "incident.json"))):
        try:
            inc = json.load(open(f))
        except Exception:
            continue
        inc["dir"] = os.path.dirname(f)
        out.append(inc)
    return out


def cmd_incidents():
    incs = list_incidents()
    if not incs:
        print("no incidents recorded")
    for i in incs:
        dur = ("%dm" % ((i.get("end", time.time()) - i["start"]) // 60))
        s = i.get("summary") or {}
        print("%s  %-5s %s  swap %.1fG  disk %sG  kills %s  %s" % (
            i["id"], dur, "OPEN " if i.get("open") else "     ", s.get("max_swap_used_gb", 0),
            s.get("min_disk_free_gb", "?"), s.get("jetsam_kills", "?"), i["reasons"][0]["desc"][:70]))
    return 0


def cmd_incident(args):
    incs = list_incidents()
    if not incs:
        print("no incidents recorded")
        return 1
    ident = args[0] if args else "latest"
    inc = incs[-1] if ident == "latest" else next((i for i in incs if i["id"] == ident), None)
    if not inc:
        print("no such incident: %s" % ident)
        return 1
    if "--html" in args:
        p = os.path.join(inc["dir"], "report.html")
        if not os.path.exists(p):
            p = os.path.join(os.environ.get("TMPDIR", "/tmp"), "oomph-%s.html" % inc["id"])
            s = load_samples(inc["start"] - 900, inc.get("end", time.time()))
            e = load_events(inc["start"] - 900, inc.get("end", time.time()))
            open(p, "w").write(render_html(s, e, "Memory incident %s (open)" % inc["id"], inc))
        subprocess.run(["/usr/bin/open", p])
        print(p)
        return 0
    print(json.dumps(inc, indent=1))
    return 0


def cmd_html(args):
    since, until = window(args, "6h")
    out = None
    if "-o" in args:
        out = args[args.index("-o") + 1]
    out = out or os.path.join(os.environ.get("TMPDIR", "/tmp"), "oomph-report.html")
    s = load_samples(since, until)
    e = load_events(since, until)
    open(out, "w").write(render_html(s, e, "Memory report"))
    print(out)
    if "--open" in args:
        subprocess.run(["/usr/bin/open", out])
    return 0


# ------------------------------------------------------------- agent protocol
HERE = os.path.dirname(os.path.realpath(__file__))
SKILL_URL = "https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md"
LEVELS = ("ok", "tight", "critical")
_oomphd = None


def _daemon_module():
    global _oomphd
    if _oomphd is None:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import oomphd as m  # noqa
        _oomphd = m
    return _oomphd


def _daemon_sample(max_age=45):
    """The daemon's latest sample if it is fresh, else None."""
    try:
        c = json.load(open(os.path.join(LOG_DIR, "current.json")))
        if time.time() - c["t"] <= max_age:
            c["source"] = "daemon"
            return c
    except Exception:
        pass
    return None


def live_sample(with_procs=True):
    d = _daemon_module()
    s = {"t": round(time.time(), 1), "iso": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
         "source": "live"}
    s.update(d.system_memory())
    s["away"] = {k: v for k, v in d.away_state().items() if k in ("idle_s", "display_on", "locked", "sleep_preventers")}
    if with_procs:
        top, groups, sessions = d.summarize_procs(d.collect_procs())
        s["top"], s["groups"], s["claude"] = top, groups, sessions
    return s


def sample(with_procs=True):
    return _daemon_sample() or live_sample(with_procs)


def free_physical_gb(s):
    """Activity Monitor's figure: Physical Memory - (App Memory + Wired + Compressed)."""
    return round(max(0.0, s["ram_gb"] - s["app_gb"] - s["wired_gb"] - s["compressed_gb"]), 1)


ADVICE = {
    "ok": "Memory is fine. Go ahead; check again before the next memory-heavy step "
          "(big builds, test suites, containers, parallel jobs or sub-agents).",
    "tight": "Memory is tight. Don't start memory-heavy work in parallel: lower build/test parallelism (-j1/-j2), "
             "start no new containers, VMs, browsers or sub-agents, and stop processes this session started and no "
             "longer needs. Run `oomph check` again before the next heavy step.",
    "critical": "Memory is critical. Start nothing heavy. Stop or pause memory-heavy processes this session started "
                "(see `oomph session`), then `oomph wait` until it recovers, and tell the user what you did. "
                "If disk space is the problem, ask the user to free some — swap cannot grow on a full disk.",
}


def verdict(s):
    ram = s.get("ram_gb") or 0
    free = free_physical_gb(s)
    disk = s.get("disk_free_gb", 999)
    swap_full = s.get("swap_total_gb", 0) > 0 and s.get("swap_used_gb", 0) >= 0.9 * s["swap_total_gb"]
    level, reasons = 0, []

    def bump(lv, why):
        nonlocal level
        level = max(level, lv)
        reasons.append(why)

    p = s.get("pressure", 1)
    if p >= 4:
        bump(2, "macOS memory pressure is CRITICAL")
    elif p >= 2:
        bump(1, "macOS memory pressure is WARNING")
    if disk < 5:
        bump(2, "only %.0f GB disk free — swap cannot grow" % disk)
    elif disk < 20:
        bump(1, "only %.0f GB disk free — swap may not be able to grow" % disk)
    if swap_full and disk < 20:
        bump(2, "swap is full (%.1f/%.1f GB) and the disk is too full to add more" % (s["swap_used_gb"], s["swap_total_gb"]))
    if ram and free < 0.05 * ram:
        bump(1, "only %.1f GB physical memory free" % free)
    if s.get("jetsam_kills"):
        bump(1, "macOS just killed %d processes for memory" % s["jetsam_kills"])
    lv = LEVELS[level]
    return {
        "level": lv, "exit_code": level, "reasons": reasons, "advice": ADVICE[lv],
        "free_gb": free, "ram_gb": ram, "pressure": PRESSURE.get(p, p),
        "swap_used_gb": s.get("swap_used_gb"), "swap_total_gb": s.get("swap_total_gb"),
        "disk_free_gb": disk, "source": s.get("source", "daemon"), "at": s.get("iso"),
    }


def verdict_line(v):
    line = "oomph: %s — %.1fG free of %.0fG · pressure %s · swap %.1f/%.1fG · disk %.0fG free" % (
        v["level"].upper(), v["free_gb"], v["ram_gb"], v["pressure"], v["swap_used_gb"] or 0,
        v["swap_total_gb"] or 0, v["disk_free_gb"])
    if v["reasons"]:
        line += "\n  why: " + "; ".join(v["reasons"])
    return line + "\n  advice: " + v["advice"]


def find_session(pid=None):
    """The Claude Code session (outermost `claude` process) that `pid` (default: our parent) runs in."""
    d = _daemon_module()
    procs = d.collect_procs()
    cur = pid or os.getppid()
    root, hops = None, 0
    while cur in procs and hops < 64:
        if procs[cur]["name"] == "claude":
            root = cur  # keep walking: the outermost claude is the session
        cur, hops = procs[cur]["ppid"], hops + 1
    if root is None:
        return None
    children = {}
    for p in procs.values():
        children.setdefault(p["ppid"], []).append(p["pid"])
    stack, members = [root], []
    while stack:
        x = stack.pop()
        members.append(x)
        stack.extend(children.get(x, []))
    mem = [procs[m] for m in members if m in procs]
    mem.sort(key=lambda p: p["fp"], reverse=True)
    total = sum(p["fp"] for p in mem)
    MBf = 1024 * 1024
    return {
        "pid": root, "cwd": d.proc_cwd(root), "total_mb": round(total / MBf), "processes": len(mem),
        "own_mb": round(procs[root]["fp"] / MBf),
        "biggest": [{"pid": p["pid"], "name": p["name"], "mb": round(p["fp"] / MBf)}
                    for p in mem if p["pid"] != root][:8],
    }


def cmd_check(args):
    v = verdict(sample(with_procs=False))
    print(json.dumps(v) if "--json" in args else verdict_line(v))
    return v["exit_code"]


def cmd_session(args):
    pid = int(args[args.index("--pid") + 1]) if "--pid" in args else None
    ses = find_session(pid)
    if "--json" in args:
        print(json.dumps(ses))
        return 0 if ses else 1
    if not ses:
        print("oomph: not running inside a Claude Code session (no `claude` ancestor process)")
        return 1
    print("session  pid %s · %s" % (ses["pid"], ses["cwd"]))
    print("memory   %.1f GB in %d processes (claude itself %.1f GB)" % (
        ses["total_mb"] / 1024, ses["processes"], ses["own_mb"] / 1024))
    for b in ses["biggest"]:
        print("  %7d MB  %-30s pid %s" % (b["mb"], b["name"][:30], b["pid"]))
    return 0


def _parse_gb(x):
    x = x.strip().upper().rstrip("B")
    return float(x[:-1]) if x.endswith("G") else float(x)


def wait_for_memory(timeout_s=600, min_free_gb=0.0, quiet=False):
    start = time.time()
    last = None
    while True:
        v = verdict(live_sample(with_procs=False))
        ok = v["level"] == "ok" and v["free_gb"] >= min_free_gb
        if ok:
            return True, v, round(time.time() - start)
        if not quiet and (last is None or time.time() - last > 60):
            last = time.time()
            print("oomph: waiting — %s, %.1fG free" % (v["level"], v["free_gb"]), flush=True)
        if time.time() - start >= timeout_s:
            return False, v, round(time.time() - start)
        time.sleep(5)


def cmd_wait(args):
    timeout = parse_dur(args[args.index("--timeout") + 1]) if "--timeout" in args else 600
    need = _parse_gb(args[args.index("--free") + 1]) if "--free" in args else 0.0
    ok, v, waited = wait_for_memory(timeout, need)
    print(("oomph: ok after %ds" if ok else "oomph: still %s after %ds — giving up") % (
        (waited,) if ok else (v["level"], waited)))
    if not ok:
        print(verdict_line(v))
    return 0 if ok else 1


def cmd_status_json():
    print(json.dumps(sample()))
    return 0


def cmd_hook(args):
    """PostToolUse hook. Silent (exit 0) when memory is ok. When tight/critical, prints a short
    warning to stderr and exits 2, which Claude Code shows to the model. Warns again only when
    the level changes or after 10 minutes."""
    try:
        sys.stdin.read()  # the hook payload; not needed
    except Exception:
        pass
    v = verdict(sample(with_procs=False))
    state = os.path.join(os.environ.get("TMPDIR", "/tmp"), "oomph-hook-%d.json" % os.getppid())
    try:
        prev = json.load(open(state))
    except Exception:
        prev = {}
    if v["level"] == "ok":
        if prev.get("level") not in (None, "ok"):
            json.dump({"level": "ok", "t": time.time()}, open(state, "w"))
        return 0
    if prev.get("level") == v["level"] and time.time() - prev.get("t", 0) < 600:
        return 0
    json.dump({"level": v["level"], "t": time.time()}, open(state, "w"))
    sys.stderr.write(verdict_line(v) + "\n")
    return 2


# ------------------------------------------------------------------- MCP
MCP_TOOLS = [
    {"name": "memory_check",
     "description": "Verdict on this Mac's memory right now: level ok / tight / critical, the reasons, free physical "
                    "memory, pressure, swap and free disk, plus advice on what to do. Call it before memory-heavy "
                    "work (builds, test suites, containers, parallel jobs, sub-agents) and periodically in long runs.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "my_session",
     "description": "Memory used by the Claude Code session this server belongs to: its whole process tree, total, "
                    "and the biggest child processes (pid, name, MB). Use it to find what to stop when memory is tight.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "memory_status",
     "description": "The full latest sample: system memory breakdown, swap, disk, idle state, top processes, top apps "
                    "and all Claude sessions.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "wait_for_memory",
     "description": "Block until memory is back to ok (and optionally at least min_free_gb free), polling every 5 s, "
                    "up to timeout_s (max 300). Returns whether it recovered and the final verdict.",
     "inputSchema": {"type": "object", "properties": {
         "timeout_s": {"type": "integer", "minimum": 5, "maximum": 300, "default": 120},
         "min_free_gb": {"type": "number", "minimum": 0, "default": 0}}}},
    {"name": "incidents",
     "description": "Recorded memory incidents (needs the oomph daemon): id, start, triggers, peak swap, minimum free "
                    "disk, jetsam kills. Use after unexplained process deaths or an 'out of application memory' dialog.",
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}}}},
    {"name": "incident",
     "description": "Full summary of one incident ('latest' or an id): timeline facts, biggest risers, processes and "
                    "Claude sessions at the peak, most-killed services, and the path of its HTML report.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string", "default": "latest"}}}},
]


def _mcp_call(name, a):
    if name == "memory_check":
        return verdict(sample(with_procs=False))
    if name == "my_session":
        return find_session() or {"error": "this MCP server is not running under a Claude Code session"}
    if name == "memory_status":
        return sample()
    if name == "wait_for_memory":
        ok, v, waited = wait_for_memory(min(int(a.get("timeout_s", 120)), 300), float(a.get("min_free_gb", 0)), quiet=True)
        return {"recovered": ok, "waited_s": waited, "verdict": v}
    if name == "incidents":
        incs = list_incidents()[-int(a.get("limit", 10)):]
        return [{"id": i["id"], "start": i.get("start_iso"), "end": i.get("end_iso"), "open": i.get("open"),
                 "triggers": [r["desc"] for r in i.get("reasons", [])][:5],
                 "max_swap_used_gb": (i.get("summary") or {}).get("max_swap_used_gb"),
                 "min_disk_free_gb": (i.get("summary") or {}).get("min_disk_free_gb"),
                 "jetsam_kills": (i.get("summary") or {}).get("jetsam_kills")} for i in reversed(incs)]
    if name == "incident":
        incs = list_incidents()
        ident = a.get("id", "latest")
        inc = (incs[-1] if incs else None) if ident == "latest" else next((i for i in incs if i["id"] == ident), None)
        if not inc:
            return {"error": "no such incident (is the oomph daemon installed?)"}
        out = dict(inc)
        out["report_html"] = os.path.join(inc["dir"], "report.html")
        return out
    raise KeyError(name)


def cmd_mcp():
    """Minimal MCP server (JSON-RPC 2.0, newline-delimited over stdio)."""
    def send(msg):
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except ValueError:
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        rid, method, params = req.get("id"), req.get("method"), req.get("params") or {}
        if rid is None:
            continue  # notification (e.g. notifications/initialized)
        try:
            if method == "initialize":
                result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                          "capabilities": {"tools": {}},
                          "serverInfo": {"name": "oomph", "version": VERSION},
                          "instructions": "oomph reports this Mac's memory, swap and disk. Call memory_check before "
                                          "memory-heavy work and back off when it says tight or critical."}
            elif method == "ping":
                result = {}
            elif method == "tools/list":
                result = {"tools": MCP_TOOLS}
            elif method == "tools/call":
                try:
                    data = _mcp_call(params.get("name"), params.get("arguments") or {})
                    result = {"content": [{"type": "text", "text": json.dumps(data, indent=1)}], "isError": False}
                except KeyError:
                    send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown tool"}})
                    continue
                except Exception as e:
                    result = {"content": [{"type": "text", "text": "oomph error: %r" % e}], "isError": True}
            else:
                send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}})
                continue
            send({"jsonrpc": "2.0", "id": rid, "result": result})
        except Exception as e:
            send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": repr(e)}})
    return 0


# ------------------------------------------------------------ claude setup
def _skill_source():
    for p in (os.path.join(HERE, "skills", "oomph", "SKILL.md"),                 # installed / app bundle
              os.path.join(os.path.dirname(HERE), "skills", "oomph", "SKILL.md")):  # repo checkout
        if os.path.exists(p):
            return p
    return None


def cmd_setup_claude(args):
    import shutil
    home = os.path.expanduser("~")
    dest_dir = os.path.join(home, ".claude", "skills", "oomph")
    settings = os.path.join(home, ".claude", "settings.json")
    me = "/usr/local/bin/oomph" if os.path.exists("/usr/local/bin/oomph") else os.path.realpath(__file__)
    claude = shutil.which("claude")
    hook_cmd = me + " hook"

    def edit_settings(add):
        try:
            cfg = json.load(open(settings))
        except FileNotFoundError:
            cfg = {}
        hooks = cfg.setdefault("hooks", {})
        post = [h for h in hooks.get("PostToolUse", [])
                if not any(x.get("command", "").endswith(" hook") and "oomph" in x.get("command", "")
                           for x in h.get("hooks", []))]
        if add:
            post.append({"matcher": "Bash", "hooks": [{"type": "command", "command": hook_cmd, "timeout": 10}]})
        if post:
            hooks["PostToolUse"] = post
        else:
            hooks.pop("PostToolUse", None)
        if not hooks:
            cfg.pop("hooks", None)
        if os.path.exists(settings):
            shutil.copy(settings, settings + ".oomph-backup")
        os.makedirs(os.path.dirname(settings), exist_ok=True)
        with open(settings, "w") as f:
            json.dump(cfg, f, indent=2)
            f.write("\n")

    if "--remove" in args:
        shutil.rmtree(dest_dir, ignore_errors=True)
        print("removed skill   %s" % dest_dir)
        if claude:
            subprocess.run([claude, "mcp", "remove", "oomph", "--scope", "user"], capture_output=True)
            print("removed MCP     oomph (user scope)")
        edit_settings(False)
        print("removed hook    (if it was installed) from %s" % settings)
        return 0

    src = _skill_source()
    if not src:
        print("oomph: SKILL.md not found next to this script; get it from %s" % SKILL_URL)
        return 1
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy(src, os.path.join(dest_dir, "SKILL.md"))
    print("installed skill %s/SKILL.md" % dest_dir)
    if claude:
        subprocess.run([claude, "mcp", "remove", "oomph", "--scope", "user"], capture_output=True)
        r = subprocess.run([claude, "mcp", "add", "--scope", "user", "oomph", "--", me, "mcp"],
                           capture_output=True, text=True)
        print(("registered MCP  oomph → %s mcp (user scope)" % me) if r.returncode == 0 else
              ("MCP registration failed: %s" % (r.stderr or r.stdout).strip()))
    else:
        print("claude CLI not found; register the MCP server yourself:\n  claude mcp add --scope user oomph -- %s mcp" % me)
    if "--hook" in args:
        edit_settings(True)
        print("added hook      PostToolUse(Bash) → %s  (backup: %s.oomph-backup)" % (hook_cmd, settings))
    print("\nNew Claude Code sessions are oom-aware now. Already-running sessions: tell them to use the oomph skill.")
    return 0


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__.strip())
        return 0
    c, rest = argv[0], argv[1:]
    if c == "status":
        return cmd_status_json() if "--json" in rest else cmd_status()
    if c == "check":
        return cmd_check(rest)
    if c == "session":
        return cmd_session(rest)
    if c == "wait":
        return cmd_wait(rest)
    if c == "hook":
        return cmd_hook(rest)
    if c == "mcp":
        return cmd_mcp()
    if c == "setup-claude":
        return cmd_setup_claude(rest)
    if c == "report":
        return cmd_report(rest)
    if c == "incidents":
        return cmd_incidents()
    if c == "incident":
        return cmd_incident(rest)
    if c == "html":
        return cmd_html(rest)
    if c == "version":
        print(VERSION)
        return 0
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
