#!/usr/bin/python3 -I
"""oomph — inspect the memory papertrail written by oomphd.

  oomph status
  oomph report [--last 2h | --since ISO [--until ISO]]
  oomph incidents
  oomph incident <id|latest> [--html]
  oomph html [--last 24h | --since ISO [--until ISO]] [-o FILE] [--open]
  oomph upgrade tools|check|log|build [--json]   upgrade from GitHub (each commit on main is a release)
  oomph ai-report [--provider claude|openai|ollama] [--model M] [--base-url URL] [--last 24h] [--open]
                                     a model investigates the logs and writes an analysis on top of the
                                     report (token in OOMPH_AI_TOKEN / ANTHROPIC_API_KEY / OPENAI_API_KEY)
  oomph ai-check --provider P [--model M] [--base-url URL]   does the provider accept the token
                                     (OOMPH_AI_TOKEN) and know the model? one cheap request, no tokens

for agents and scripts (work without the daemon too — they measure live):
  oomph check [--json]              verdict ok / tight / critical + advice; exit 0 / 1 / 2
  oomph session [--json] [--pid N]  memory of the Claude session this runs in (its whole process tree)
  oomph wait [--timeout 10m] [--free 4G]   block until memory is ok again; exit 1 on timeout
  oomph status --json               the latest full sample

coordinating memory between sessions (a shared first-come-first-served ledger):
  oomph run --reserve 6G [--for "what"] [--wait 30m] -- <cmd…>   wait for a grant, run, release; records the peak
  oomph reserve <6G> --for "what" [--wait 10m] [--ttl 30m] [--ticket rN] [--json]   exit 0 granted, 75 not (yet)
  oomph amend <id> [--gb 3G] [--ttl 20m] [--for "what"] [--json]   change a reservation: shrinking applies at
                                    once; growing a grant only if it fits now with nobody queued (else refused:
                                    reserve the extra separately); --ttl counts from now; exit 0 ok, 75 refused
  oomph release <id | all>          give a reservation back (all = this session's)
  oomph reservations [--json]       who holds / waits for how much, and past peaks
  oomph reservations --history [--last 24h] [--json]   past reservations (14 days are kept): spans, edits,
                                    reserved vs peak, how each ended
  oomph hook                        Claude Code PostToolUse hook: silent when ok, warns when tight
  oomph mcp                         MCP server over stdio (memory_check, reserve_memory, release_memory, ...)
  oomph setup-claude [--hook] [--remove]   install the skill + register the MCP server for Claude Code
"""
import datetime
import functools
import glob
import gzip
import html as _html
import json
import math
import os
import pwd
import re
import secrets
import select
import stat
import subprocess
import sys
import threading
import time

VERSION = "dev"  # stamped by build-app.sh / install.sh from `git describe` (tools/version.sh)
COMMIT = ""      # the git commit the stamped copy was built from
HARDENING = 1    # H0 (1.8.4): root never opens the shared ledger directory; `oomph share on` requires it


def _checkout_version():
    """Running straight from a git checkout: derive the version like tools/version.sh."""
    root = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    if not os.path.isdir(os.path.join(root, ".git")):
        return "0.0.0-nogit", ""
    try:
        d = subprocess.run(["git", "-C", root, "describe", "--tags", "--match", "v*", "--always", "--dirty",
                            "--first-parent"], capture_output=True, text=True, timeout=5).stdout.strip()
        c = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return "0.0.0-nogit", ""
    if not d:
        return "0.0.0-nogit", c
    return (d[1:] if d.startswith("v") else "0.0.0-g" + d), c


if VERSION == "dev":
    VERSION, COMMIT = _checkout_version()
LOG_DIR = os.environ.get("OOMPH_DIR", "/Library/Logs/oomph")

# What the daemon reads from the unified log. On macOS 27 memory kills show up as
# launchd exits with OS_REASON_JETSAM and as ReportSystemMemory batch lines
# "Process X [pid] killed by jetsam reason low-swap"; idle-exit kills are excluded.
# `log stream` never delivers launchd's lines (`log show` does), so the daemon polls
# JETSAM_EXIT_PREDICATE with `log show` and streams the rest.
JETSAM_EXIT_PREDICATE = '(process == "launchd" AND eventMessage CONTAINS "OS_REASON_JETSAM")'
LOG_PREDICATE = (
    JETSAM_EXIT_PREDICATE +
    ' OR (process == "ReportSystemMemory" AND eventMessage CONTAINS "killed by jetsam")'
    ' OR ((process == "loginwindow" OR process == "UserNotificationCenter")'
    ' AND eventMessage CONTAINS[c] "application memory")'
)

PRESSURE = {0: "?", 1: "normal", 2: "WARN", 4: "CRITICAL"}
AWAY_IDLE_S = 300


def unowned_limit_gb(ram_gb):
    """Memory no process owns, above which something outside the process list (a GPU or
    driver leak, typically) holds it. Normally a few GB; only a restart frees a real leak."""
    return max(16.0, 0.4 * (ram_gb or 0))


def unowned_gb(s):
    """App memory plus the uncompressed size of everything in the compressor, minus what all
    processes' footprints account for. Older samples lack procs_gb: fall back to the top
    groups (an overestimate by a few GB)."""
    if "compressor_logical_gb" not in s:
        return None
    if "unowned_gb" in s:
        return s["unowned_gb"]
    owned = s.get("procs_gb")
    if owned is None:
        if not s.get("groups"):
            return None
        owned = sum(g["mb"] for g in s["groups"]) / 1024
    return round(max(0.0, s.get("app_gb", 0) + s["compressor_logical_gb"] - owned), 1)


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
    first, peak, peak_t, last, info = {}, {}, {}, {}, {}
    for s in samples:
        for p in s.get(key) or []:
            k = p["name"] if key == "groups" else "%s [%s]" % (p["name"], p["pid"])
            first.setdefault(k, p["mb"])
            last[k] = p["mb"]
            info[k] = p
            if p["mb"] > peak.get(k, -1):
                peak[k], peak_t[k] = p["mb"], s["t"]
    rows = [{"name": k, "first_mb": first[k], "peak_mb": peak[k], "last_mb": last[k],
             "rise_mb": peak[k] - first[k], "peak_iso": _hm(peak_t[k])} for k in peak]
    if key != "groups":
        for r in rows:
            p = info[r["name"]]
            r.update(pid=p["pid"], proc=p["name"], ppid=p.get("ppid"), uid=p.get("uid"))
    rows.sort(key=lambda r: (r["rise_mb"], r["peak_mb"]), reverse=True)
    return rows[:limit] if limit else rows


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
    unowned = [u for u in (unowned_gb(s) for s in samples) if u is not None]
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
        "max_unowned_gb": max(unowned) if unowned else None,
        "max_stall_s": max([s.get("stall", 0) for s in samples] +
                           [e.get("seconds", 0) for e in events if e.get("kind") == "stall"]),
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
--k1:#3b82c4;--k2:#d0503c;--k3:#2f9e6e;--k4:#9b59b6;--k5:#e0a030;--k6:#a1a1a6;--bad:#d0503c;--crit:rgba(208,80,60,.10);
--hl:rgba(59,130,196,.22);--hov:rgba(59,130,196,.09);--seg:#ececea;--seg-on:#fff;--input:#fff}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#161618;--fg:#ececee;--muted:#9a9aa0;--grid:#2c2c30;--card:#1e1e21;--line:#34343a;
--c-wired:#6e6e74;--c-app:#5b9fe0;--c-comp:#e8b450;--c-swap:#ef6b56;--c-ram:#ececee;--away:rgba(160,160,170,.12);
--k1:#5b9fe0;--k2:#ef6b56;--k3:#45c08b;--k4:#b57edc;--k5:#e8b450;--k6:#6e6e74;--bad:#ef6b56;--crit:rgba(239,107,86,.13);
--hl:rgba(91,159,224,.28);--hov:rgba(91,159,224,.11);--seg:#2a2a2e;--seg-on:#3a3a40;--input:#1a1a1d}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}
.sub{color:var(--muted);margin:0 0 16px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:10px 0}
.kpis{display:grid;grid-auto-flow:column;grid-auto-columns:minmax(0,1fr);gap:8px}.kpis .card{margin:0;padding:10px 12px;min-width:0}
.kpi .v{font-size:18px;font-weight:600;font-variant-numeric:tabular-nums;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.kpi .l{color:var(--muted);font-size:11.5px;line-height:1.3}
@media (max-width:760px){.kpis{grid-auto-flow:row;grid-template-columns:repeat(2,minmax(0,1fr))}.kpis .kpi:last-child:nth-child(odd){grid-column:span 2}}
.hrow.top{margin:0 0 2px}.hrow h1{margin:0;flex:1 1 auto}.seg.big button{font-size:13px;padding:3px 14px}
.bad{color:var(--bad)}table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
th{color:var(--muted);font-weight:500;font-size:12px;white-space:nowrap}td.n,th.n{text-align:right}.scroll{overflow-x:auto}svg{width:100%;height:auto;display:block}
th.pid,td.pid{width:96px;min-width:96px;max-width:96px;white-space:nowrap;text-align:right;padding-right:14px}
td.pid .more{color:var(--muted);font-size:11px}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted);margin-top:6px}.sw{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:4px;vertical-align:-1px}
code{font:12px ui-monospace,SFMono-Regular,Menlo,monospace}
.hrow{display:flex;align-items:baseline;flex-wrap:wrap;gap:6px 12px;margin:28px 0 8px}.hrow h2{margin:0;flex:1 1 auto}
.ctl{display:flex;align-items:baseline;flex-wrap:wrap;justify-content:flex-end;gap:6px 10px;font-size:12px;color:var(--muted)}
.seg{display:inline-flex;background:var(--seg);border-radius:999px;padding:2px}
.seg button{font:inherit;font-size:12px;border:0;background:none;color:var(--muted);padding:2px 12px;border-radius:999px;cursor:pointer}
.seg button.on{background:var(--seg-on);color:var(--fg);box-shadow:0 1px 2px rgba(0,0,0,.12)}
tr[data-k]{cursor:pointer}tr.hov>td{background:var(--hov)}tr.hl>td{background:var(--hl)}
.caret{display:inline-block;width:14px;color:var(--muted);cursor:pointer;user-select:none}
.node{color:var(--muted)}.agg{color:var(--muted);font-style:italic}
.morebar{margin-top:8px;font-size:12px}.linkbtn,.morebar a,.morebar button{color:var(--k1);background:none;border:0;padding:0;font:inherit;cursor:pointer;text-decoration:none}
.cnt{color:var(--muted);font-weight:400;font-size:12px;margin-left:6px}
.search{position:relative;display:inline-block}
.search input{font:inherit;font-size:12px;width:170px;padding:3px 22px 3px 8px;border:1px solid var(--line);border-radius:999px;background:var(--input);color:var(--fg)}
.search button{position:absolute;right:4px;top:50%;transform:translateY(-50%);border:0;background:var(--muted);color:var(--card);width:14px;height:14px;border-radius:50%;font-size:10px;line-height:14px;padding:0;cursor:pointer;display:none}
.search.has button{display:block}
input[type=datetime-local]{font:inherit;font-size:12px;padding:2px 6px;border:1px solid var(--line);border-radius:6px;background:var(--input);color:var(--fg)}
input[type=datetime-local]:disabled{opacity:.45}
.toggle{display:inline-flex;align-items:center;gap:6px;cursor:pointer}.toggle input{display:none}
.toggle .tr{width:26px;height:15px;border-radius:999px;background:var(--line);position:relative;transition:background .15s;align-self:center}
.toggle .tr:after{content:"";position:absolute;left:2px;top:2px;width:11px;height:11px;border-radius:50%;background:#fff;transition:left .15s;box-shadow:0 1px 1px rgba(0,0,0,.2)}
.toggle input:checked+.tr{background:var(--k3)}.toggle input:checked+.tr:after{left:13px}
td.kind{white-space:nowrap}td.time{white-space:nowrap;color:var(--muted)}
"""

BAD_KINDS = ("incident_open", "stall", "unowned_memory", "jetsam", "disk_low", "daemon_error", "log")


def _e(x):
    return _html.escape(str(x))


def _scale(v, lo, hi, a, b):
    return a if hi == lo else a + (v - lo) * (b - a) / (hi - lo)


NO_DATA_S = 300
_chart_n = 0


def _critical_spans(samples, gap=120):
    """Stretches of CRITICAL pressure; flips back within `gap` seconds are bridged so a
    flapping hour reads as one band."""
    spans = []
    for s in samples:
        if s.get("pressure", 0) >= 4:
            if spans and s["t"] - spans[-1][1] <= gap:
                spans[-1][1] = s["t"]
            else:
                spans.append([s["t"], s["t"]])
    return spans


def _svg_chart(samples, series, stacked, marks=(), bands=(), ymax=None, unit="GB", refline=None,
               height=220, bars=None, t0=None, t1=None):
    W, H, L, R, T, B = 960, height, 48, 10, 10, 26
    if not samples:
        return "<p class=sub>No samples.</p>"
    t0 = samples[0]["t"] if t0 is None else min(t0, samples[0]["t"])
    t1 = samples[-1]["t"] if t1 is None else max(t1, samples[-1]["t"])
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
    X = lambda t: _scale(t, t0, t1, L, W - R)  # noqa: E731
    # runs of samples without a hole (asleep, frozen, logger down) longer than NO_DATA_S
    segs, a = [], 0
    for i in range(1, len(samples) + 1):
        if i == len(samples) or samples[i]["t"] - samples[i - 1]["t"] > NO_DATA_S:
            segs.append((a, i))
            a = i
    global _chart_n
    _chart_n += 1
    pat = "nd%d" % _chart_n
    out = ['<svg viewBox="0 0 %d %d" role="img"><defs><pattern id="%s" width="6" height="6" patternUnits="userSpaceOnUse" '
           'patternTransform="rotate(45)"><line x1="0" y1="0" x2="0" y2="6" stroke="var(--grid)" stroke-width="2"/></pattern></defs>'
           % (W, H, pat)]
    holes = [(samples[e1 - 1]["t"], samples[b0]["t"]) for (_, e1), (b0, _) in zip(segs, segs[1:])]
    if samples[0]["t"] - t0 > NO_DATA_S:
        holes.insert(0, (t0, samples[0]["t"]))
    if t1 - samples[-1]["t"] > NO_DATA_S:
        holes.append((samples[-1]["t"], t1))
    for ha, hb in holes:
        xa, xb = X(ha), X(hb)
        out.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="url(#%s)"><title>no data %s–%s</title></rect>'
                   % (xa, T, xb - xa, H - B - T, pat, _hm(ha), _hm(hb)))
        if xb - xa > 70:
            out.append('<text x="%.1f" y="%d" font-size="11" fill="var(--muted)" text-anchor="middle">no data</text>'
                       % ((xa + xb) / 2, T + 16))
    # background layer: away shading, critical-pressure bands, incident marks, grid
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
    for a, b in bands:
        if b >= t0 and a <= t1:
            xa, xb = X(max(a, t0)), X(min(b, t1))
            out.append('<rect x="%.1f" y="%d" width="%.1f" height="%d" fill="var(--crit)"><title>CRITICAL pressure %s–%s</title></rect>'
                       % (xa, T, max(xb - xa, 2), H - B - T, _hm(a), _hm(b)))
    step = _nice_step(ymax)
    v = 0
    while v <= ymax:
        yy = y(v)
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--grid)"/>' % (L, W - R, yy, yy))
        out.append('<text x="%d" y="%.1f" font-size="11" fill="var(--muted)" text-anchor="end">%s</text>' % (L - 6, yy + 4, _fmt(v)))
        v += step
    for m in marks:
        if t0 <= m["t"] <= t1:
            xx = X(m["t"])
            out.append('<line x1="%.1f" x2="%.1f" y1="%d" y2="%d" stroke="var(--bad)" stroke-width="1" stroke-dasharray="3 3" opacity=".7"><title>%s</title></line>'
                       % (xx, xx, T, H - B, _e(m["label"])))
    n = 6
    for k in range(n + 1):
        tt = t0 + (t1 - t0) * k / n
        out.append('<text x="%.1f" y="%d" font-size="11" fill="var(--muted)" text-anchor="%s">%s</text>'
                   % (X(tt), H - 8, "start" if k == 0 else ("end" if k == n else "middle"), datetime.datetime.fromtimestamp(tt).strftime("%H:%M:%S" if t1 - t0 < 900 else ("%H:%M" if t1 - t0 < 86400 else "%a %H:%M"))))
    # data layer
    if stacked:
        prev = [H - B] * len(samples)
        for (label, _, color), tp in zip(series, tops):
            for a, b in segs:
                pts = " ".join("%.1f,%.1f" % (x, y(v)) for x, v in zip(xs[a:b], tp[a:b]))
                back = " ".join("%.1f,%.1f" % (x, p) for x, p in reversed(list(zip(xs[a:b], prev[a:b]))))
                out.append('<polygon points="%s %s" fill="%s" fill-opacity=".75" stroke="%s" stroke-width="1"><title>%s</title></polygon>'
                           % (pts, back, color, color, _e(label)))
            prev = [y(v) for v in tp]
    else:
        for (label, _, color), v in zip(series, vals):
            for a, b in segs:
                pts = " ".join("%.1f,%.1f" % (x, y(vv)) for x, vv in zip(xs[a:b], v[a:b]))
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
    out.append("</svg>")
    leg = "".join('<span><i class=sw style="background:%s"></i>%s</span>' % (c, _e(l)) for l, _, c in series)
    leg += '<span><i class=sw style="background:var(--away)"></i>away (idle ≥5 min / locked / display off)</span>'
    if any(b >= t0 and a <= t1 for a, b in bands):
        leg += '<span><i class=sw style="background:var(--crit);outline:1px solid var(--bad)"></i>critical pressure</span>'
    if any(t0 <= m["t"] <= t1 for m in marks):
        leg += '<span><i class=sw style="background:none;border-left:1px dashed var(--bad);border-radius:0"></i>incident start / end</span>'
    return "".join(out) + '<div class=legend>%s</div>' % leg


def _nice_step(m):
    for s in (0.5, 1, 2, 4, 5, 8, 10, 20, 25, 50, 100, 200, 500, 1000, 2000, 5000):
        if m / s <= 6:
            return s
    return m / 5


def _fmt(v):
    return ("%.1f" % v).rstrip("0").rstrip(".") if isinstance(v, float) else str(v)


def _table(rows, cols, attrs=None):
    """cols: (title, value_fn, numeric[, css_class]); attrs(row) -> extra <tr> attributes."""
    if not rows:
        return "<p class=sub>none</p>"

    def cls(c):
        return " ".join(x for x in (("n" if c[2] else ""), (c[3] if len(c) > 3 else "")) if x)
    h = "".join('<th class="%s">%s</th>' % (cls(c), _e(c[0])) for c in cols)
    body = ""
    for r in rows:
        a = attrs(r) if attrs else ""
        body += "<tr%s>" % a + "".join('<td class="%s">%s</td>' % (cls(c), _e(c[1](r))) for c in cols) + "</tr>"
    return '<div class=scroll><table><tr>%s</tr>%s</table></div>' % (h, body)


def _row_attrs(key, pids=(), app=None):
    a = ' data-k="%s" data-pids="%s"' % (_e(key), " ".join(str(p) for p in pids if p))
    if app:
        a += ' data-app="%s"' % _e(app)
    return a


def _guess_group(name, groups):
    """The app group a process belongs to, for samples recorded before processes carried it."""
    if name in groups:
        return name
    for g in groups:
        if name.startswith(g + " "):
            return g
    return None


VIEW_SPANS = (("24h", 86400), ("6h", 6 * 3600), ("1h", 3600))


def _dur_label(sec):
    if sec >= 2 * 86400:
        return "%dd" % round(sec / 86400)
    if sec >= 3600:
        return "%dh" % round(sec / 3600)
    return "%dm" % max(1, round(sec / 60))


def report_views(since, until):
    """The report's time views (key, label, from, to): the whole window when it isn't one of
    24h / 6h / 1h, then each of those that fits, all ending at `until`."""
    full = until - since
    views = [(k, k, until - sec, until) for k, sec in VIEW_SPANS if sec <= full + 60]
    if not any(abs(full - sec) <= 60 for _, sec in VIEW_SPANS):
        views.insert(0 if full > 86400 else len(views), ("all", _dur_label(full), since, until))
    return views


def _downsample(samples, n=1200):
    """At most ~n samples for drawing: per time bucket keep the one using the most memory
    (spikes survive) and add up the bucket's jetsam kills."""
    if len(samples) <= n:
        return samples
    t0, t1 = samples[0]["t"], samples[-1]["t"]
    w = (t1 - t0) / n or 1

    def load(s):
        return s.get("app_gb", 0) + s.get("compressed_gb", 0) + s.get("swap_used_gb", 0)
    out, cur, key, kills = [], None, None, 0
    for s in samples:
        b = int((s["t"] - t0) / w)
        if b != key:
            if cur is not None:
                out.append(dict(cur, jetsam_kills=kills))
            key, cur, kills = b, s, 0
        elif load(s) > load(cur):
            cur = s
        kills += s.get("jetsam_kills", 0)
    out.append(dict(cur, jetsam_kills=kills))
    return out


def _report_meta(samples):
    """pid -> name/parent/owner/app/session over the whole report, owner names, session projects."""
    meta, sessions = {}, {}
    for s in samples:
        names = {g["name"] for g in s.get("groups") or []}
        for p in s.get("top") or []:
            meta[p["pid"]] = {"n": p["name"], "pp": p.get("ppid"), "u": p.get("uid"),
                              "g": p.get("g") or _guess_group(p["name"], names), "s": p.get("s"), "pn": p.get("pn")}
        for c in s.get("claude") or []:
            sessions[c["pid"]] = c.get("cwd") or ""
            meta.setdefault(c["pid"], {"n": "claude"})
            b = c.get("biggest")
            if b:
                meta.setdefault(b["pid"], {"n": b["name"]})
                meta[b["pid"]].setdefault("s", c["pid"])
    users = {}
    for m in meta.values():
        u = m.get("u")
        if u is not None and u not in users:
            try:
                users[u] = pwd.getpwuid(u).pw_name
            except (KeyError, TypeError):
                users[u] = "uid %s" % u
    return meta, users, sessions


def _risers_data(samples, meta):
    app_pids = {}
    for s in samples:
        for p in s.get("top") or []:
            g = (meta.get(p["pid"]) or {}).get("g")
            if g:
                d = app_pids.setdefault(g, {})
                d[p["pid"]] = max(d.get(p["pid"], 0), p["mb"])
    procs = [{"pid": r["pid"], "name": r["proc"], "first": r["first_mb"], "peak": r["peak_mb"],
              "rise": r["rise_mb"], "at": r["peak_iso"], "ppid": r.get("ppid"), "uid": r.get("uid")}
             for r in _risers(samples, "top", limit=None)]
    apps = []
    for r in _risers(samples, "groups", limit=None):
        pids = sorted(app_pids.get(r["name"], {}).items(), key=lambda kv: -kv[1])
        apps.append({"name": r["name"], "first": r["first_mb"], "peak": r["peak_mb"], "rise": r["rise_mb"],
                     "at": r["peak_iso"], "pids": [[p, mb] for p, mb in pids]})
    return procs, apps


def _when(t):
    return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def _view_html(samples, events, meta, key, t0, t1):
    """One time view: (sub line + KPIs + charts, sessions + top processes + kills)."""
    cls = "v v-%s" % key
    sub = '<p class="sub %s">%s → %s · %d samples</p>' % (cls, _when(t0), _when(t1), len(samples))
    if not samples:
        return (sub + '<div class="card %s"><p class=sub>No samples in this window.</p></div>' % cls, "")
    summ = summarize(samples, events)
    marks = [{"t": e["t"], "label": "%s %s %s" % (e.get("iso", "")[11:19], e["kind"].replace("_", " "), e.get("id", ""))}
             for e in events if e.get("kind") in ("incident_open", "incident_close")]
    bands = _critical_spans(samples)
    draw = _downsample(samples)
    mem_series = [("wired", lambda s: s.get("wired_gb"), "var(--c-wired)"),
                  ("app memory", lambda s: s.get("app_gb"), "var(--c-app)"),
                  ("compressed", lambda s: s.get("compressed_gb"), "var(--c-comp)"),
                  ("swap used", lambda s: s.get("swap_used_gb"), "var(--c-swap)")]
    ram = samples[-1].get("ram_gb")
    peaks = {}
    for s in samples:
        for g in s.get("groups") or []:
            peaks[g["name"]] = max(peaks.get(g["name"], 0), g["mb"])
    top5 = [k for k, _ in sorted(peaks.items(), key=lambda kv: -kv[1])[:5]]
    colors = ["var(--k1)", "var(--k2)", "var(--k3)", "var(--k4)", "var(--k5)"]

    def gval(name):
        return lambda s: next((g["mb"] / 1024 for g in s.get("groups") or [] if g["name"] == name), 0)

    def rest(s):
        return sum(g["mb"] for g in s.get("groups") or [] if g["name"] not in top5) / 1024
    grp_series = [(n, gval(n), c) for n, c in zip(top5, colors)]
    if len(peaks) > len(top5):
        grp_series.append(("other recorded apps", rest, "var(--k6)"))
    disk_series = [("free disk GB", lambda s: s.get("disk_free_gb"), "var(--k3)"),
                   ("swap total GB", lambda s: s.get("swap_total_gb"), "var(--c-swap)")]
    o = summ.get("onset") or {}
    k = [("Peak pressure", summ["peak_pressure"], summ["peak_pressure"] in ("WARN", "CRITICAL")),
         ("Max swap used", "%.1f GB" % summ["max_swap_used_gb"], False),
         ("Min free disk", "%.0f GB" % summ["min_disk_free_gb"], summ["min_disk_free_gb"] < 20),
         ("Jetsam kills", summ["jetsam_kills"], summ["jetsam_kills"] > 0),
         ("Max unowned memory", "%.0f GB" % summ["max_unowned_gb"] if summ.get("max_unowned_gb") is not None else "–",
          (summ.get("max_unowned_gb") or 0) >= unowned_limit_gb(summ.get("ram_gb"))),
         ("Away during window", "%d%%" % round(100 * summ["away_fraction"]), False),
         ("Idle at onset", ("%d min" % (o["idle_s"] // 60)) if o.get("idle_s") is not None else "–", False)]
    if summ.get("max_stall_s"):
        k.append(("Longest stall (awake)", "%d s" % summ["max_stall_s"], summ["max_stall_s"] >= 60))
    kpis = "".join('<div class="card kpi"><div class="v %s">%s</div><div class=l>%s</div></div>'
                   % ("bad" if bad else "", _e(v), _e(l)) for l, v, bad in k)
    rng = dict(t0=t0, t1=t1)
    head = "".join([
        sub,
        '<div class="kpis %s">%s</div>' % (cls, kpis),
        '<div class="%s"><h2>System memory (stacked) vs. RAM</h2><div class=card>%s</div>' % (cls, _svg_chart(
            draw, mem_series, True, marks, bands, refline=ram, bars=(lambda s: s.get("jetsam_kills"), "var(--bad)"), **rng)),
        "<h2>Top 5 apps / process groups (GB, stacked)</h2><div class=card>%s</div>" % _svg_chart(
            draw, grp_series, True, marks, bands, **rng),
        "<h2>Free disk and swap size (GB)</h2><div class=card>%s</div></div>" % _svg_chart(
            draw, disk_series, False, marks, bands, height=160, **rng),
    ])

    def sess_pids(c):
        return [c["pid"]] + [p for p, m in meta.items() if m.get("s") == c["pid"]] + \
               ([c["biggest"]["pid"]] if c.get("biggest") else [])
    tail = "".join([
        '<div class="%s"><h2>Claude sessions at peak (%s)</h2><div class=card>%s</div>' % (
            cls, _e(summ.get("peak_at", "")[11:19]), _table(summ.get("claude_at_peak") or [], [
                ("pid", lambda r: r["pid"], True, "pid"), ("project", lambda r: r.get("cwd") or "?", False),
                ("total MB", lambda r: r["mb"], True), ("procs", lambda r: r["n"], True),
                ("biggest child", lambda r: ("%s [%s] (%s MB)" % (r["biggest"]["name"], r["biggest"]["pid"], r["biggest"]["mb"]))
                 if r.get("biggest") else "", False)],
                attrs=lambda r: _row_attrs("s:%s" % r["pid"], sess_pids(r)))),
        "<h2>Top processes at peak</h2><div class=card>%s</div>" % _table(summ.get("top_at_peak", []), [
            ("pid", lambda r: r["pid"], True, "pid"), ("name", lambda r: r["name"], False), ("MB", lambda r: r["mb"], True)],
            attrs=lambda r: _row_attrs("p:%s" % r["pid"], [r["pid"]], (meta.get(r["pid"]) or {}).get("g"))),
        "<h2>Most-killed by jetsam</h2><div class=card>%s<p class=sub>reasons: %s</p></div></div>" % (
            _table([{"n": k2, "c": v2} for k2, v2 in (summ.get("most_killed") or {}).items()],
                   [("service", lambda r: r["n"], False), ("kills", lambda r: r["c"], True)]),
            _e(", ".join("%s × %d" % kv for kv in (summ.get("jetsam_reasons") or {}).items()) or "–")),
    ])
    return head, tail


def render_html(samples, events, title, incident=None, views=None, extra_css="", intro_html=""):
    """A self-contained report. `views` are the (key, label, from, to) windows the page can
    switch between (default: 24h / 6h / 1h ending at the last sample); the first is shown."""
    if views is None:
        views = report_views(samples[0]["t"], samples[-1]["t"]) if samples else [("all", "–", 0, 0)]
    meta, users, sessions = _report_meta(samples)
    heads, tails, vdata = [], [], {}
    for key, label, a, b in views:
        vs = [s for s in samples if a <= s["t"] <= b]
        ve = [e for e in events if a <= e["t"] <= b]
        h, t = _view_html(vs, ve, meta, key, a, b)
        heads.append(h)
        tails.append(t)
        procs, apps = _risers_data(vs, meta)
        vdata[key] = {"procs": procs, "apps": apps, "range": [a, b]}
    evs = [{"t": e["t"], "iso": e.get("iso", ""), "kind": e.get("kind", ""), "d": _event_detail(e),
            "bad": e.get("kind") in BAD_KINDS}
           for e in reversed(collapse_pressure_events([e for e in events if e.get("kind") != "notified"]))]
    data = {"meta": meta, "users": users, "sessions": sessions, "events": evs, "views": vdata}
    first = views[0][0]
    view_css = "".join('body:not([data-view="%s"]) .v-%s{display:none!important}' % (k, k) for k, *_ in views)
    pill = ""
    if len(views) > 1:
        pill = '<div class="seg big" data-for=view>%s</div>' % "".join(
            '<button data-view="%s"%s>%s</button>' % (k, " class=on" if k == first else "", _e(lab)) for k, lab, *_ in views)
    reasons_html = ""
    if incident:
        reasons_html = "<h2>Triggers</h2>" + _table(incident.get("reasons", []), [
            ("time", lambda r: _hm(r["t"]), False), ("kind", lambda r: r["kind"], False), ("detail", lambda r: r["desc"], False)])

    def seg(target):
        return ('<div class=seg data-for="%s"><button class=on data-mode=list>List</button>'
                '<button data-mode=tree>Tree</button></div>' % target)
    blob = json.dumps(data, separators=(",", ":")).replace("</", "<\\/")
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>",
        "<title>%s</title><style>%s%s%s</style></head><body data-view=\"%s\"><main>" % (_e(title), CSS, view_css, extra_css, first),
        '<div class="hrow top"><h1>%s</h1><div class=ctl>%s</div></div>' % (_e(title), pill),
        intro_html,
        "".join(heads[:1]) + "".join(heads[1:]),
        reasons_html,
        '<div class=hrow><h2>Biggest risers — apps</h2><div class=ctl>%s</div></div>'
        '<div class=card><div id=r-apps></div></div>' % seg("r-apps"),
        '<div class=hrow><h2>Biggest risers — processes</h2><div class=ctl>%s</div></div>'
        '<div class=card><div id=r-procs></div></div>' % seg("r-procs"),
        "".join(tails),
        '<div class=hrow><h2>Events<span class=cnt id=ev-cnt></span></h2><div class=ctl>'
        '<label class=toggle title="Filter by time"><input type=checkbox id=ev-time><span class=tr></span>time</label>'
        '<input type=datetime-local step=1 id=ev-from disabled aria-label="from"> – '
        '<input type=datetime-local step=1 id=ev-to disabled aria-label="to">'
        '<span class=search id=ev-search><input type=text id=ev-q placeholder="Filter events" aria-label="Filter events">'
        '<button id=ev-x type=button aria-label="Clear filter">✕</button></span></div></div>'
        '<div class=card><div id=ev></div></div>',
        '<script type="application/json" id=oomph-data>%s</script><script>%s</script>' % (blob, REPORT_JS),
        '<p class=sub style="margin-top:24px">generated %s by oomph %s</p>' % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), VERSION),
        "</main></body></html>",
    ]
    return "".join(parts)


def incident_html(inc):
    """An incident's report: the incident itself (from 15 min before it opened), plus the
    24h / 6h / 1h before it settled (its last trigger, plus the time it takes to close)."""
    start = inc["start"]
    end = inc.get("end") or time.time()
    anchor = end if inc.get("open") else min(end, inc.get("last_trigger", end) + 180)
    lo = min(start - 900, anchor - 86400)
    samples, events = load_samples(lo, end), load_events(lo, end)
    views = [("incident", "Incident", start - 900, end)] + [(k, k, anchor - sec, anchor) for k, sec in VIEW_SPANS]
    title = "Memory incident %s%s" % (inc["id"], " (open)" if inc.get("open") else "")
    return render_html(samples, events, title, inc, views)


REPORT_JS = r"""
(function(){
const D = JSON.parse(document.getElementById('oomph-data').textContent);
const esc = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const N = 10, PAGE = 50;
const meta = D.meta || {}, users = D.users || {}, sessions = D.sessions || {};
const base = p => (p || '').split('/').filter(Boolean).pop() || p;
const owner = u => u == null ? 'unknown owner' : (users[u] || ('uid ' + u));
const label = (pid, name) => sessions[pid] != null ? 'claude · ' + base(sessions[pid]) : name;
let view = document.body.dataset.view;
const V = () => (D.views || {})[view] || {procs: [], apps: [], range: null};
const onView = [];
let procByPid = new Map(), pidApp = {};
function refreshMaps(){
  procByPid = new Map(V().procs.map(r => [r.pid, r]));
  pidApp = {}; V().apps.forEach(a => a.pids.forEach(p => pidApp[p[0]] = a.name));
}
refreshMaps();
const viewSeg = document.querySelector('.seg[data-for=view]');
if (viewSeg) viewSeg.addEventListener('click', e => {
  const b = e.target.closest('button[data-view]'); if (!b || b.dataset.view === view) return;
  view = document.body.dataset.view = b.dataset.view;
  viewSeg.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
  refreshMaps(); onView.forEach(f => f()); paint();
});

/* ---------- highlighting: click toggles, hover previews ---------- */
const sel = new Set(); let hover = null;
function keyOf(tr){ return {pids: (tr.dataset.pids || '').split(' ').filter(Boolean), app: tr.dataset.app || null, k: tr.dataset.k}; }
function sets(keys){
  const P = new Set(), A = new Set();
  for (const k of keys) {
    const tr = document.querySelector('tr[data-k="' + CSS.escape(k) + '"]');
    if (!tr) continue;
    const o = keyOf(tr);
    o.pids.forEach(p => P.add(p));
    if (k.startsWith('a:')) A.add(k.slice(2));
  }
  return [P, A];
}
function paint(){
  const [SP, SA] = sets(sel), [HP, HA] = hover ? sets([hover]) : [new Set(), new Set()];
  document.querySelectorAll('tr[data-k]').forEach(tr => {
    const o = keyOf(tr);
    const m = (P, A) => o.pids.some(p => P.has(p)) || (!!o.app && A.has(o.app)) ;
    tr.classList.toggle('hl', sel.has(o.k) || m(SP, SA));
    tr.classList.toggle('hov', !!hover && (hover === o.k || m(HP, HA)));
  });
}
document.addEventListener('click', e => {
  if (e.target.closest('.caret')) return;
  const tr = e.target.closest('tr[data-k]'); if (!tr) return;
  const k = tr.dataset.k; sel.has(k) ? sel.delete(k) : sel.add(k); paint();
});
document.addEventListener('mouseover', e => {
  const tr = e.target.closest('tr[data-k]'); const k = tr ? tr.dataset.k : null;
  if (k !== hover) { hover = k; paint(); }
});

/* ---------- risers: list or tree, top 10 or all ---------- */
function attrs(key, pids, app){
  return ' data-k="' + esc(key) + '" data-pids="' + esc((pids || []).join(' ')) + '"' + (app ? ' data-app="' + esc(app) + '"' : '');
}
function pidCell(pids){
  if (!pids || !pids.length) return '<td class=pid></td>';
  const more = pids.length > 1 ? ' <span class=more>+' + (pids.length - 1) + '</span>' : '';
  return '<td class=pid title="' + esc(pids.join(', ')) + '">' + esc(pids[0]) + more + '</td>';
}
function nums(r, agg){
  if (r) return '<td class=n>' + esc(r.first ?? '') + '</td><td class=n>' + esc(r.peak ?? '') + '</td><td class=n>' + esc(r.rise ?? '') + '</td><td>' + esc(r.at ?? '') + '</td>';
  if (agg) return '<td class=n></td><td class=n></td><td class="n agg" title="sum of the rises below">Σ ' + esc(agg) + '</td><td></td>';
  return '<td></td><td></td><td></td><td></td>';
}
const HEAD = (first) => '<tr><th class="pid">pid</th><th>' + first + '</th><th class=n>first MB</th><th class=n>peak MB</th><th class=n>rise MB</th><th>peak at</th></tr>';
const appPids = a => a.pids.map(p => String(p[0]));

function node(key, o){ return Object.assign({key: key, kids: new Map()}, o || {}); }
function put(root, steps){ let cur = root; for (const st of steps) { if (!cur.kids.has(st.key)) cur.kids.set(st.key, node(st.key, st)); cur = cur.kids.get(st.key); } return cur; }
// agg: what the direct children add up to (a child with its own row counts once, not again via its kids)
function finish(n){ let s = 0, mx = -1e9; for (const c of n.kids.values()) { finish(c); s += c.own; mx = Math.max(mx, c.max); }
  const own = n.row && n.row.rise != null ? n.row.rise : null;
  n.agg = n.kids.size ? s : null; n.own = own != null ? own : s; n.max = Math.max(mx, own == null ? -1e9 : own); }

function procTree(rows){
  const root = node('root'), byPid = new Map(rows.map(r => [r.pid, r]));
  for (const r of rows) {
    const m = meta[r.pid] || {}, chain = [], seen = new Set([r.pid]);
    const pp = r.ppid != null ? r.ppid : m.pp;
    let p = pp, guard = 0;
    while (p && p > 1 && !seen.has(p) && guard++ < 16) {
      seen.add(p);
      const pm = meta[p];
      chain.unshift({pid: p, name: pm ? pm.n : ((p === pp && m.pn) || 'pid ' + p)});
      if (!pm || pm.pp == null) break;
      p = pm.pp;
    }
    if (m.s && m.s !== r.pid && !chain.some(c => c.pid === m.s)) chain.unshift({pid: m.s, name: 'claude'});
    const uid = r.uid != null ? r.uid : m.u;
    const steps = [{key: 'u:' + uid, label: owner(uid), owner: true}]
      .concat(chain.map(c => ({key: 'p:' + c.pid, pid: c.pid, label: label(c.pid, c.name), pids: [String(c.pid)], app: (meta[c.pid] || {}).g})))
      .concat([{key: 'p:' + r.pid, pid: r.pid, label: label(r.pid, r.name), pids: [String(r.pid)], app: m.g || pidApp[r.pid]}]);
    put(root, steps).row = r;
  }
  (function walk(n){ if (!n.row && n.pid && byPid.has(n.pid)) n.row = byPid.get(n.pid); n.kids.forEach(walk); })(root);
  finish(root); return root;
}
function appTree(rows){
  const root = node('root');
  for (const a of rows) {
    const uids = a.pids.map(p => (meta[p[0]] || {}).u).filter(u => u != null);
    const uid = uids.length ? uids.sort((x, y) => uids.filter(v => v === y).length - uids.filter(v => v === x).length)[0] : null;
    const an = put(root, [{key: 'u:' + uid, label: owner(uid), owner: true},
                         {key: 'a:' + a.name, label: a.name, pids: appPids(a), app: a.name}]);
    an.row = a;
    for (const [pid, mb] of a.pids) {
      const pr = procByPid.get(pid);
      const c = put(an, [{key: 'p:' + pid, pid: pid, label: label(pid, (meta[pid] || {}).n || ('pid ' + pid)), pids: [String(pid)], app: a.name}]);
      c.row = pr || {peak: mb};
    }
  }
  finish(root); return root;
}
const KIDS = 10;
function treeRows(root, collapsed, opened, showAll){
  const out = [];
  (function walk(n, depth){
    const all = [...n.kids.values()].sort((a, b) => b.max - a.max);
    const kids = showAll.has(n.key) ? all : all.slice(0, KIDS);
    for (const c of kids) {
      // apps start folded (their processes can number in the hundreds); everything else open
      const has = c.kids.size > 0, closed = c.key.startsWith('a:') ? !opened.has(c.key) : collapsed.has(c.key);
      const caret = has ? '<span class=caret data-key="' + esc(c.key) + '">' + (closed ? '▸' : '▾') + '</span>' : '<span class=caret></span>';
      const name = '<td style="padding-left:' + (8 + depth * 16) + 'px">' + caret + (c.owner ? '<span class=node>' + esc(c.label) + '</span>' : esc(c.label)) + '</td>';
      const a = c.pids ? attrs(c.key, c.pids, c.app) : '';
      out.push('<tr' + a + '>' + (c.pid ? pidCell([c.pid]) : (c.pids ? pidCell(c.pids) : '<td class=pid></td>')) + name + nums(c.row, c.agg) + '</tr>');
      if (has && !closed) walk(c, depth + 1);
    }
    if (all.length > kids.length)
      out.push('<tr><td class=pid></td><td colspan=5 style="padding-left:' + (22 + depth * 16) + 'px"><button type=button class=linkbtn data-all="' +
               esc(n.key) + '">… ' + (all.length - kids.length) + ' more</button></td></tr>');
  })(root, 0);
  return out.join('');
}
function riser(id, kind){
  const el = document.getElementById(id); if (!el) return;
  onView.push(() => { st.all = false; st.showAll.clear(); render(); });
  const st = {mode: 'list', all: false, collapsed: new Set(), opened: new Set(), showAll: new Set()};
  const segEl = document.querySelector('.seg[data-for="' + id + '"]');
  function render(){
    const rows = V()[kind];
    if (!rows.length) { el.innerHTML = '<p class=sub>none</p>'; return; }
    const vis = st.all ? rows : rows.slice(0, N);
    let body;
    if (st.mode === 'tree') body = treeRows(kind === 'apps' ? appTree(vis) : procTree(vis), st.collapsed, st.opened, st.showAll);
    else body = vis.map(r => kind === 'apps'
      ? '<tr' + attrs('a:' + r.name, appPids(r), r.name) + '>' + pidCell(appPids(r)) + '<td>' + esc(r.name) + '</td>' + nums(r) + '</tr>'
      : '<tr' + attrs('p:' + r.pid, [String(r.pid)], (meta[r.pid] || {}).g || pidApp[r.pid]) + '>' + pidCell([r.pid]) + '<td>' + esc(label(r.pid, r.name)) + '</td>' + nums(r) + '</tr>').join('');
    let more = '';
    if (rows.length > N) more = '<div class=morebar><button type=button data-more>' + (st.all ? 'fewer' : 'more — all ' + rows.length + ' entries') + '</button></div>';
    el.innerHTML = '<div class=scroll><table>' + HEAD(kind === 'apps' ? 'app / group' : 'process') + body + '</table></div>' + more;
    paint();
  }
  el.addEventListener('click', e => {
    const c = e.target.closest('.caret[data-key]');
    if (c) { const k = c.dataset.key, set = k.startsWith('a:') ? st.opened : st.collapsed;
             set.has(k) ? set.delete(k) : set.add(k); render(); return; }
    const m = e.target.closest('[data-all]');
    if (m) { st.showAll.add(m.dataset.all); render(); return; }
    if (e.target.closest('[data-more]')) { st.all = !st.all; render(); }
  });
  if (segEl) segEl.addEventListener('click', e => {
    const b = e.target.closest('button[data-mode]'); if (!b) return;
    st.mode = b.dataset.mode;
    segEl.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
    render();
  });
  render();
}
riser('r-apps', 'apps');
riser('r-procs', 'procs');

/* ---------- events: newest first, live text + time filter, paged ---------- */
(function(){
  const el = document.getElementById('ev'); if (!el) return;
  const evs = D.events || [], q = document.getElementById('ev-q'), x = document.getElementById('ev-x'),
        box = document.getElementById('ev-search'), on = document.getElementById('ev-time'),
        from = document.getElementById('ev-from'), to = document.getElementById('ev-to'), cnt = document.getElementById('ev-cnt');
  const pad = n => String(n).padStart(2, '0');
  const local = t => { const d = new Date(t * 1000); return d.getFullYear() + '-' + pad(d.getMonth() + 1) + '-' + pad(d.getDate()) + 'T' + pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); };
  let shown = PAGE, multiDay = false, inView = evs;
  function setRange(){
    const r = V().range || [evs.length ? evs[evs.length - 1].t : 0, evs.length ? evs[0].t : 0];
    from.value = local(Math.floor(r[0])); to.value = local(Math.ceil(r[1]));
    multiDay = local(r[0]).slice(0, 10) !== local(r[1]).slice(0, 10);
    inView = evs.filter(e => e.t >= r[0] && e.t <= r[1]);
  }
  setRange();
  onView.push(() => { setRange(); shown = PAGE; render(); });
  function filtered(){
    const terms = q.value.toLowerCase().split(/\s+/).filter(Boolean);
    const a = on.checked && from.value ? new Date(from.value).getTime() / 1000 : -Infinity;
    const b = on.checked && to.value ? new Date(to.value).getTime() / 1000 : Infinity;
    return inView.filter(e => e.t >= a && e.t <= b &&
      terms.every(w => (e.iso + ' ' + e.kind + ' ' + e.d).toLowerCase().includes(w)));
  }
  function render(){
    const f = filtered(), vis = f.slice(0, shown);
    cnt.textContent = f.length === inView.length ? inView.length + ' total' : f.length + ' of ' + inView.length;
    box.classList.toggle('has', !!q.value);
    if (!f.length) { el.innerHTML = '<p class=sub>' + (inView.length ? 'No events match the filter.' : 'none') + '</p>'; return; }
    const rows = vis.map(e => '<tr><td class=time>' + esc(multiDay ? e.iso.slice(5, 10) + ' ' + e.iso.slice(11, 19) : e.iso.slice(11, 19)) +
      '</td><td class="kind' + (e.bad ? ' bad' : '') + '">' + esc(e.kind) + '</td><td>' + esc(e.d) + '</td></tr>').join('');
    const left = f.length - vis.length;
    el.innerHTML = '<div class=scroll><table><tr><th>time</th><th>kind</th><th>detail</th></tr>' + rows + '</table></div>' +
      (left > 0 ? '<div class=morebar><button type=button data-more>more — next ' + Math.min(PAGE, left) + ' of ' + left + ' older</button></div>' : '');
  }
  const reset = () => { shown = PAGE; render(); };
  q.addEventListener('input', reset);
  x.addEventListener('click', () => { q.value = ''; q.focus(); reset(); });
  on.addEventListener('change', () => { from.disabled = to.disabled = !on.checked; reset(); });
  from.addEventListener('input', reset); to.addEventListener('input', reset);
  el.addEventListener('click', e => { if (e.target.closest('[data-more]')) { shown += PAGE; render(); } });
  render();
})();
})();
"""


FLAP_GAP_S = 120


def collapse_pressure_events(events):
    """Merge runs of pressure_change events less than FLAP_GAP_S apart into one
    pressure_flapping row (older logs record every flip; the daemon now batches them)."""
    out, run = [], []

    def flush():
        if len(run) == 1:
            out.append(run[0])
        elif run:
            levels = sorted({run[0]["old"]} | {e["new"] for e in run})
            out.append({"t": run[0]["t"], "iso": run[0]["iso"], "kind": "pressure_flapping",
                        "flips": len(run), "levels": [PRESSURE.get(x, x) for x in levels],
                        "until": run[-1]["iso"][11:19], "now": PRESSURE.get(run[-1]["new"], run[-1]["new"]),
                        "swap_used_gb": run[-1].get("swap_used_gb")})
        run.clear()
    for e in events:
        if e.get("kind") == "pressure_change" and "old" in e:
            if run and e["t"] - run[-1]["t"] > FLAP_GAP_S:
                flush()
            run.append(e)
            continue
        flush()
        out.append(e)
    flush()
    return out


def _event_detail(e):
    if e.get("kind") == "pressure_change" and "old" in e:
        e = dict(e, old=PRESSURE.get(e["old"], e["old"]), new=PRESSURE.get(e["new"], e["new"]))
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
    u = unowned_gb(c)
    if u is not None:
        print("unowned    %.1f GB held outside any process%s" % (
            u, "  <- LEAK? only a restart frees it" if u >= unowned_limit_gb(c["ram_gb"]) else ""))
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
    try:
        leases = ledger_snapshot()
    except LedgerError:
        leases = []
    if leases:
        print("\nreservations (oomph reservations for details):")
        for b in leases:
            print("  " + _fmt_brief(b))
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
        # Render fresh rather than opening the report.html saved at close: that one is a
        # snapshot in whatever report design the daemon had back then.
        p = os.path.join(os.environ.get("TMPDIR", "/tmp"), "oomph-%s.html" % inc["id"])
        open(p, "w").write(incident_html(inc))
        subprocess.run(["/usr/bin/open", p])
        print(p)
        return 0
    print(json.dumps(inc, indent=1))
    return 0


def cmd_html(args):
    since, until = window(args, "24h")
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
        procs = d.collect_procs()
        top, groups, sessions = d.summarize_procs(procs)
        s["top"], s["groups"], s["claude"] = top, groups, sessions
        s.update(d.ownership(s, procs))
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
    u = s.get("unowned_gb")
    if u is not None and ram and u >= unowned_limit_gb(ram):
        bump(1, "%.0f GB of memory is held outside any process (likely a GPU or driver leak) "
                "and won't come back until the Mac restarts" % u)
    lv = LEVELS[level]
    return {
        "level": lv, "exit_code": level, "reasons": reasons, "advice": ADVICE[lv],
        "free_gb": free, "ram_gb": ram, "pressure": PRESSURE.get(p, p),
        "swap_used_gb": s.get("swap_used_gb"), "swap_total_gb": s.get("swap_total_gb"),
        "disk_free_gb": disk, "unowned_gb": s.get("unowned_gb"), "source": s.get("source", "daemon"), "at": s.get("iso"),
    }


def verdict_line(v):
    line = "oomph: %s — %.1fG free of %.0fG · pressure %s · swap %.1f/%.1fG · disk %.0fG free" % (
        v["level"].upper(), v["free_gb"], v["ram_gb"], v["pressure"], v["swap_used_gb"] or 0,
        v["swap_total_gb"] or 0, v["disk_free_gb"])
    if v["reasons"]:
        line += "\n  why: " + "; ".join(v["reasons"])
    c = v.get("coordination") or {}
    if c.get("others") or c.get("mine"):
        g = [o for o in c["others"] if o["state"] == "granted"]
        q = [o for o in c["others"] if o["state"] == "queued"]
        line += ("\n  reservations: others hold %d (%.1fG not yet used), %d waiting · yours %d · %.1fG available to you"
                 % (len(g), c["reserved_by_others_gb"], len(q), len(c["mine"]), c["available_to_me_gb"]))
    return line + "\n  advice: " + v["advice"]


def _session_root(procs, pid):
    """pid of the outermost `claude` process above `pid`, or None."""
    cur, root, hops = pid, None, 0
    while cur in procs and hops < 64:
        if procs[cur]["name"] == "claude":
            root = cur  # keep walking: the outermost claude is the session
        cur, hops = procs[cur]["ppid"], hops + 1
    return root


def find_session(pid=None):
    """The Claude Code session (outermost `claude` process) that `pid` (default: our parent) runs in."""
    d = _daemon_module()
    procs = d.collect_procs()
    root = _session_root(procs, pid or os.getppid())
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


def checked_verdict(mine=None):
    """verdict() plus what other sessions have reserved or are waiting for."""
    s = _sample_override() if _sample_override else sample(with_procs=False)
    v = verdict(s)
    try:
        coordination_verdict(v, coordination(mine if mine is not None else holder_for()["pid"], s))
    except Exception as e:  # the ledger is a bonus; never let it break a check
        v["coordination"] = {"error": repr(e)}
    return v


def cmd_check(args):
    v = checked_verdict()
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
    x = str(x).strip().upper().rstrip("B")
    if x.endswith("M"):
        return float(x[:-1]) / 1024
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


# ------------------------------------------------------ coordination ledger
# Sessions announce memory-heavy work before starting it ("reserve 6G for the gradle build").
# Requests queue first-come-first-served in one shared ledger; a request is granted when it
# fits into free memory minus what earlier grants have not yet used, minus a safety margin.
# So concurrent heavy steps from different sessions run side by side when there's room, and
# one after another when there isn't. Advisory: oomph never stops or kills anything.
LEDGER_DIR = os.environ.get("OOMPH_LEDGER_DIR", "/Users/Shared/oomph")
QUEUE_STALE_S = 180          # a queued request lapses if its owner hasn't polled for this long
DEFAULT_TTL_S = 30 * 60      # session-held grants expire unless released or extended
MAX_TTL_S = 8 * 3600
POLL_S = 2
HISTORY_KEEP = 100           # finished reservations kept in ledger.json (the log keeps 14 days)
HISTORY_FILE = "reservations.jsonl"  # one record per edit and per finished reservation
HISTORY_DAYS = 14
_sample_override = None      # tests: a function returning the sample to decide on


def margin_gb(ram):
    """Memory kept free on top of all reservations."""
    return max(1.5, 0.05 * (ram or 0))


# ----- the shared directory (H0)
# LEDGER_DIR is world-writable (dir 0777, files 0666): every session and user on this Mac
# shares it, so anything in it may have been planted — a symbolic or hard link to someone
# else's file, a FIFO, a device, an endless or sparse file, JSON with huge numbers or deep
# nesting. Everybody's file handling goes through the few functions below, and nothing
# running as root comes here at all: a root caller runs its ledger operation in a child as
# the invoking user (or nobody), and the root daemon only ever sees what such a child
# printed, rebuilt from typed, capped fields.
LIMITS = {                   # the one table of limits for what is read from the directory
    "ledger": 4 << 20,       # ledger.json: bytes; a bigger one is treated as absent
    "history": 8 << 20,      # reservations.jsonl: readers take its newest 8 MB, writers keep it below
    "child": 1 << 20,        # a root caller's unprivileged child: bytes of answer
    "tick": 64 << 10,        # the daemon's child (refresh + snapshot): bytes of answer
    "leases": 16 << 10,      # the leases block of a sample: bytes in all ...
    "leases_n": 64,          # ... entries ...
    "str": 200,              # ... and characters per string
    "digits": 30,            # an integer longer than this is not JSON oomph wrote (int() is quadratic)
    "keys": 256,             # keys per JSON object
    "depth": 32,             # nesting (newer Pythons parse far deeper than the recursion limit)
}
LOCK_WAIT_S = 5.0            # interactive callers: a holder keeps the lock for milliseconds, so 5 s
                             # only runs out when it is stuck or hostile, yet survives a swapped-out
                             # holder on a Mac under pressure
LOCK_WAIT_TICK_S = 1.0       # the daemon's child: it runs again next sample anyway
CHILD_TIMEOUT_S = 20         # a root caller's child (lock wait included)
TICK_TIMEOUT_S = 5           # the daemon's child
PY = "/usr/bin/python3"
_lock_wait = LOCK_WAIT_S
_held = None                 # the Ledger whose lock this process holds (the history log is written under it)
_given = None                # (sample, procs) a root parent measured for its unprivileged child
_RID = re.compile(r"r\d{1,15}")


class LedgerError(Exception):
    """The shared ledger can't be used safely right now (refused, busy, or its child failed)."""


class LedgerBusy(LedgerError):
    """The ledger lock wasn't free within the deadline."""


def _not_root(what):
    """The fence: whatever path leads here, a process running as root stops."""
    if os.geteuid() == 0:
        raise LedgerError("%s as root refused: root never opens the shared ledger directory" % what)


def read_bounded(name, cap, dir_fd=None, tail=False):
    """The bytes of a regular file with a single link, read without following a symbolic link,
    without blocking on a FIFO and never more than `cap` of them; None for anything else (missing,
    a link, a FIFO, a device, a directory, a hard-linked file, or bigger than `cap`). With `tail`
    a bigger file gives its last whole lines within `cap` instead."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            return None
        cut = st.st_size > cap
        if cut:
            if not tail:
                return None
            os.lseek(fd, st.st_size - cap, os.SEEK_SET)
        parts, n = [], 0
        while n <= cap:
            b = os.read(fd, min(1 << 16, cap + 1 - n))
            if not b:
                break
            parts.append(b)
            n += len(b)
        data = b"".join(parts)
        if len(data) > cap:  # it grew while we read
            if not tail:
                return None
            data, cut = data[-cap:], True
        if cut:  # the first line is a fragment
            data = data[data.find(b"\n") + 1:] if b"\n" in data else b""
        return data
    except OSError:
        return None
    finally:
        os.close(fd)


def _parse_int(s):
    if len(s) > LIMITS["digits"]:
        raise ValueError("integer too long")
    return int(s)


def _parse_float(s):
    f = float(s)
    if not math.isfinite(f):
        raise ValueError("number out of range")
    return f


def _no_constant(s):
    raise ValueError("%s is not JSON" % s)


def _object(pairs):
    if len(pairs) > LIMITS["keys"]:
        raise ValueError("too many keys")
    return dict(pairs)


def loads_untrusted(data):
    """JSON from the shared directory (or from a child that read it), or None if it isn't JSON
    oomph could have written: no integers over LIMITS["digits"] digits, no NaN or Infinity, at
    most LIMITS["keys"] keys per object, no nesting deeper than LIMITS["depth"]."""
    if data is None:
        return None
    try:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
        v = json.loads(data, parse_int=_parse_int, parse_float=_parse_float, parse_constant=_no_constant,
                       object_pairs_hook=_object)
    except (ValueError, RecursionError, TypeError, MemoryError):
        return None
    return v if _depth_ok(v) else None


def _depth_ok(v):
    """No container nested deeper than LIMITS["depth"] (iterative: the value may be very deep)."""
    stack = [(v, 0)]
    while stack:
        x, d = stack.pop()
        if isinstance(x, (dict, list)):
            if d >= LIMITS["depth"]:
                return False
            stack.extend((y, d + 1) for y in (x.values() if isinstance(x, dict) else x))
    return True


def _num(x, lo=-1e15, hi=1e15):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and lo <= x <= hi


def _t(x):
    """A unix time oomph could have written (datetime can't take just any float)."""
    return _num(x, 0, 1e11)


def _pid(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 < x < 2 ** 31


def _segments(x):
    segs = [{"t": s["t"], "gb": s["gb"]} for s in (x if isinstance(x, list) else [])
            if isinstance(s, dict) and _t(s.get("t")) and _num(s.get("gb"), 0, 1e6)]
    return segs or None


def _typed(src, out, times=(), nums=(), strs=()):
    """Optional fields: kept unchanged when they have their type (or are None), else dropped.
    Nothing is cut here: this is the read-modify-write path, and a view limit must not reach it."""
    for k in times + nums + strs:
        if k in src and not (src[k] is None or (_t(src[k]) if k in times else _num(src[k]) if k in nums
                                                 else isinstance(src[k], str))):
            out.pop(k, None)
    return out


def _valid_lease(r):
    """A live lease as oomph writes it, with the types the code relies on, or None."""
    if not isinstance(r, dict):
        return None
    h = r.get("holder")
    if not (isinstance(r.get("id"), str) and _RID.fullmatch(r["id"]) and r.get("state") in ("queued", "granted")
            and _num(r.get("gb"), 0, 1e6) and r["gb"] > 0 and isinstance(r.get("purpose"), str)
            and isinstance(h, dict) and _pid(h.get("pid")) and _t(r.get("requested"))):
        return None
    if r["state"] == "granted" and not _t(r.get("granted")):
        return None
    out = dict(r)
    start = h.get("start")
    out["holder"] = dict(h, start=start if isinstance(start, int) and not isinstance(start, bool) else None,
                         kind=h["kind"] if isinstance(h.get("kind"), str) else None)
    out["seen"] = r["seen"] if _t(r.get("seen")) else r["requested"]
    _typed(r, out, times=("granted", "expires"), nums=("ttl", "peak_gb", "used_gb", "baseline_gb"),
           strs=("project", "key", "note"))
    if "watch" in r and not (r["watch"] is None or _pid(r["watch"])):
        out["watch"] = None
    if "segments" in r:
        segs = _segments(r["segments"])
        if segs:
            out["segments"] = segs
        else:
            out.pop("segments")
    return out


def _valid_finished(h, log=False):
    """A finished reservation (ledger.json's history) or, with `log`, a record of the history log,
    with the types the code relies on, or None."""
    if not (isinstance(h, dict) and isinstance(h.get("id"), str) and _RID.fullmatch(h["id"])
            and _num(h.get("gb"), 0, 1e6) and _t(h.get("requested"))):
        return None
    if not log and not (_t(h.get("ended")) and isinstance(h.get("outcome"), str)):
        return None
    out = dict(h, purpose=h["purpose"] if isinstance(h.get("purpose"), str) else "?")
    _typed(h, out, times=("granted", "ended", "t", "expires"), nums=("peak_gb", "held_s", "waited_s"),
           strs=("project", "holder", "outcome", "event"))
    if not isinstance(out.get("key"), str):
        out.pop("key", None)
    if "segments" in h:
        segs = _segments(h["segments"])
        if segs:
            out["segments"] = segs
        else:
            out.pop("segments")
    return out


def _valid_ledger(L):
    """The ledger with every lease and history entry checked field by field. One that doesn't
    fit was never written by oomph and is dropped — and with it the KeyError or TypeError it
    would cause in every reader. None if it isn't a ledger at all."""
    if not isinstance(L, dict) or not isinstance(L.get("leases"), list):
        return None
    out = dict(L)
    out["leases"] = [x for x in map(_valid_lease, L["leases"]) if x]
    out["history"] = [x for x in map(_valid_finished, L.get("history") if isinstance(L.get("history"), list) else [])
                      if x][-HISTORY_KEEP:]
    seq = L.get("seq")
    out["seq"] = max([seq if isinstance(seq, int) and not isinstance(seq, bool) and seq >= 0 else 0] +
                     [int(x["id"][1:]) for x in out["leases"] + out["history"]])
    st = L.get("state")
    out["state"] = {k: v for k, v in st.items() if _num(v) or (k == "level" and v in LEVELS)} \
        if isinstance(st, dict) else {}
    if "history_pruned" in L and not _num(L["history_pruned"]):
        out.pop("history_pruned")
    return out


def _ledger_dir(create=False):
    """A descriptor of LEDGER_DIR, opened without following a symbolic link (anyone who could
    replace the directory by a link would otherwise choose where everything goes); every file
    in it is opened relative to it. None if it doesn't exist and `create` is false."""
    _not_root("opening %s" % LEDGER_DIR)
    if create and not os.path.lexists(LEDGER_DIR):
        old = os.umask(0)
        try:  # shared by every session (and user) on this Mac
            os.makedirs(LEDGER_DIR, mode=0o777, exist_ok=True)
        except OSError:
            pass  # the open below says what is wrong
        finally:
            os.umask(old)
    try:
        return os.open(LEDGER_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if create:
            raise LedgerError("can't create %s" % LEDGER_DIR)
        return None
    except OSError as e:
        raise LedgerError("%s is not a plain directory (%s)" % (LEDGER_DIR, e.strerror))


def _replace(dfd, name, data):
    """Write `name` in the ledger directory without opening any file that is already there: a
    temporary file with a random name, created exclusively (a link or file planted under that
    name makes it fail instead of being written through), made 0666 on its descriptor, then
    renamed over `name` — which replaces whatever had the name, link or not."""
    tmp = "%s.%s.tmp" % (name, secrets.token_hex(8))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
    try:
        try:
            os.fchmod(fd, 0o666)  # shared by every user
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    except BaseException:
        try:
            os.unlink(tmp, dir_fd=dfd)
        except OSError:
            pass
        raise


def _lock(dfd, wait):
    """Take the ledger lock: ledger.lock opened read-only (flock needs no more), never through
    a link, never blocking on a FIFO, a regular file; polled until `wait` runs out, then
    LedgerBusy rather than a hang."""
    import fcntl
    old = os.umask(0)
    try:
        fd = os.open("ledger.lock", os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o666,
                     dir_fd=dfd)
    except OSError as e:
        raise LedgerError("can't open the ledger lock (%s)" % e.strerror)
    finally:
        os.umask(old)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise LedgerError("%s/ledger.lock is not a regular file" % LEDGER_DIR)
        deadline = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return fd
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise LedgerBusy("the reservation ledger is busy: its lock has been held for over %g s "
                                     "(%s/ledger.lock); try again" % (wait, LEDGER_DIR))
                time.sleep(0.05)
    except BaseException:
        os.close(fd)
        raise


class Ledger:
    """`with Ledger() as L:` — exclusive, read-modify-write access to the shared ledger."""

    def __init__(self, wait=None):
        self.wait = _lock_wait if wait is None else wait

    def __enter__(self):
        global _held
        _not_root("writing the ledger")
        self.dir = LEDGER_DIR
        self.dfd = _ledger_dir(create=True)
        try:
            self.fd = _lock(self.dfd, self.wait)
            try:
                self.data = _read_ledger_at(self.dfd)
            except BaseException:
                os.close(self.fd)
                raise
        except BaseException:
            os.close(self.dfd)
            raise
        _held = self
        return self.data

    def __exit__(self, et, e, tb):
        global _held
        try:
            if et is None:
                try:
                    _replace(self.dfd, "ledger.json", json.dumps(self.data, indent=1).encode())
                except OSError as x:
                    raise LedgerError("can't write %s/ledger.json (%s)" % (self.dir, x.strerror or x))
        finally:
            _held = None
            os.close(self.fd)  # closing it releases the lock
            os.close(self.dfd)
        return False


def _read_ledger_at(dfd):
    L = _valid_ledger(loads_untrusted(read_bounded("ledger.json", LIMITS["ledger"], dfd)))
    if L is None:
        # a fresh (or lost) ledger: continue the numbering of the history log, so ids don't repeat
        L = {"seq": _history_max_seq(dfd), "leases": [], "history": []}
    return L


def read_ledger():
    _not_root("reading the ledger")
    try:
        dfd = _ledger_dir()
    except LedgerError:
        dfd = None  # replaced by a link: nothing to read
    if dfd is None:
        return {"seq": 0, "leases": [], "history": []}
    try:
        return _read_ledger_at(dfd)
    finally:
        os.close(dfd)


# ----- the reservation history log (LEDGER_DIR/reservations.jsonl)
# One JSON object per line, written under the ledger lock:
#   {"event": "edit" | "end", "t": when written, "key": "r12@1795172655", "id": "r12", "purpose", "project",
#    "holder": "session" | "process" | "run", "gb": current GB, "segments": [{"t", "gb"}, …] (only once edited),
#    "requested", "granted", "peak_gb", and for "end": "ended", "outcome"; for "edit": "change", "expires"}
# The last record per key wins. `key` stays unique across ledger resets: it carries the request time.
def _history_path():
    return os.path.join(LEDGER_DIR, HISTORY_FILE)


def _key(r):
    return r.get("key") or "%s@%d" % (r["id"], int(r.get("requested") or 0))


def _history_max_seq(dfd=None):
    best = 0
    for rec in read_history(dfd=dfd):
        best = max(best, int(rec["id"][1:]))
    return best


def _rec_time(rec):
    t = rec.get("ended") or rec.get("t") or 0
    return t if _num(t) else 0


def read_history(since=None, dfd=None):
    """Records of the history log, oldest first (optionally only those that end after `since`):
    its newest LIMITS["history"] bytes, every record checked like a lease."""
    _not_root("reading the history log")
    own = dfd is None
    if own:
        try:
            dfd = _ledger_dir()
        except LedgerError:
            return []
        if dfd is None:
            return []
    try:
        data = read_bounded(HISTORY_FILE, LIMITS["history"], dfd, tail=True)
    finally:
        if own:
            os.close(dfd)
    out = []
    for line in (data or b"").splitlines():
        rec = _valid_finished(loads_untrusted(line), log=True)
        if rec and (since is None or _rec_time(rec) >= since):
            rec["key"] = _key(rec)
            out.append(rec)
    return out


def _record(r, event, t, **extra):
    h = r.get("holder")  # a live lease's holder, or a finished one's holder kind
    rec = {"event": event, "t": round(t, 1), "key": _key(r), "id": r["id"], "purpose": r["purpose"],
           "project": r.get("project"), "holder": h.get("kind") if isinstance(h, dict) else h,
           "gb": r["gb"], "requested": r["requested"], "granted": r.get("granted"),
           "peak_gb": round(r.get("peak_gb", 0) or 0, 2)}
    if len(r.get("segments") or []) > 1:
        rec["segments"] = r["segments"]
    rec.update(extra)
    return rec


def _append_history(L, recs, now):
    """Add records to the log, under the ledger lock. No writer opens the log's existing name for
    writing: a hard link planted there would turn an append into a write to another user's
    file, and no open flag can refuse a hard link. So every write reads the log (its newest
    LIMITS["history"] bytes, a file with a single link only), keeps the records of the last
    HISTORY_DAYS, adds the new ones, drops the oldest beyond LIMITS["history"] bytes and renames
    a fresh file over the name. The format stays one record per line: readers, and 1.8.1–1.8.3
    writers (which append under the same lock), work on it unchanged. A new log is seeded with
    the ledger's own short history."""
    _not_root("writing the history log")
    if _held is None:
        raise LedgerError("the history log is written under the ledger lock only")
    dfd = _held.dfd
    data = read_bounded(HISTORY_FILE, LIMITS["history"], dfd, tail=True)
    cutoff = now - HISTORY_DAYS * 86400
    lines = []
    for line in (data or b"").splitlines():
        rec = loads_untrusted(line)
        if isinstance(rec, dict) and _rec_time(rec) >= cutoff:
            lines.append(line)  # carried through unchanged
    if data is None:  # no log yet (or something other than a log had its name)
        keys = {x["key"] for x in recs}
        lines += [json.dumps(dict(_record(h, "end", h["ended"]), ended=h["ended"], outcome=h["outcome"],
                                  backfilled=True)).encode()
                  for h in L["history"] if h.get("key") not in keys]
    lines += [json.dumps(rec).encode() for rec in recs]
    keep, size = [], 0
    for line in reversed(lines):  # newest first, within the size limit
        size += len(line) + 1
        if size > LIMITS["history"]:
            break
        keep.append(line)
    _replace(dfd, HISTORY_FILE, b"".join(x + b"\n" for x in reversed(keep)))


def _alive(procs, pid, start):
    p = procs.get(pid)
    if p is not None:
        return start is None or p["start"] == start
    try:
        os.kill(pid, 0)
        return True  # exists, just not visible to us
    except PermissionError:
        return True
    except OSError:
        return False


def _children(procs):
    ch = {}
    for p in procs.values():
        ch.setdefault(p["ppid"], []).append(p["pid"])
    return ch


def _tree_gb(procs, children, root):
    stack, seen, tot = [root], set(), 0
    while stack:
        x = stack.pop()
        if x in seen or x not in procs:
            continue
        seen.add(x)
        tot += procs[x]["fp"]
        stack.extend(children.get(x, []))
    return tot / (1024 ** 3)


def _retire(L, r, outcome, now):
    """Move a lease into the history, ending it when it really ended: an expired grant at its
    expiry, a lapsed request when its owner stopped polling, anything else now."""
    end = now
    if outcome == "expired" and r.get("expires"):
        end = min(now, r["expires"])
    elif outcome == "lapsed":
        end = min(now, r["seen"] + QUEUE_STALE_S)
    end = round(max(end, r.get("granted") or r["requested"]), 1)
    h = {"id": r["id"], "key": _key(r), "purpose": r["purpose"], "project": r.get("project"), "gb": r["gb"],
         "holder": (r.get("holder") or {}).get("kind"),
         "peak_gb": round(r.get("peak_gb", 0), 2), "outcome": outcome,
         "requested": r["requested"], "granted": r.get("granted"), "ended": end,
         "waited_s": round((r.get("granted") or end) - r["requested"]),
         "held_s": round(end - r["granted"]) if r.get("granted") else 0}
    if len(r.get("segments") or []) > 1:
        h["segments"] = r["segments"]
    L["history"].append(h)
    L["history"] = L["history"][-HISTORY_KEEP:]
    try:
        _append_history(L, [_record(r, "end", now, ended=end, outcome=outcome)], now)
    except OSError:
        pass  # the log is a record, not the ledger: never let it block coordination


def _evaluate(L, s, procs, now):
    """Drop dead, expired and abandoned entries, account for what grants already use, then grant
    queued requests strictly in arrival order while they fit."""
    keep = []
    for r in L["leases"]:
        h, why = r["holder"], None
        if not _alive(procs, h["pid"], h.get("start")):
            why = "holder_gone"
        elif r["state"] == "granted" and r.get("expires") and now > r["expires"]:
            why = "expired"
        elif r["state"] == "queued" and now - r["seen"] > QUEUE_STALE_S:
            why = "lapsed"
        if why:
            _retire(L, r, why, now)
        else:
            keep.append(r)
    L["leases"] = keep

    # Memory a grant's processes have added since it was granted counts against the grant, so
    # it isn't counted twice (once as used, once as reserved). Grants watching the same process
    # tree share its growth in grant order.
    children = _children(procs)
    groups = {}
    for r in L["leases"]:
        if r["state"] == "granted":
            groups.setdefault(r.get("watch"), []).append(r)
    for w, rs in groups.items():
        rs.sort(key=lambda r: r["granted"])
        grown = 0.0 if w is None or w not in procs else max(0.0, _tree_gb(procs, children, w) - rs[0].get("baseline_gb", 0))
        for i, r in enumerate(rs):
            share = grown if i == len(rs) - 1 else min(r["gb"], grown)
            grown -= share
            r["used_gb"] = round(min(r["gb"], share), 2)
            r["peak_gb"] = round(max(r.get("peak_gb", 0), share), 2)

    v = verdict(s)
    ram = s.get("ram_gb") or 0
    free = free_physical_gb(s)
    outstanding = sum(r["gb"] - r.get("used_gb", 0) for r in L["leases"] if r["state"] == "granted")
    avail = free - outstanding - margin_gb(ram)
    for r in [x for x in L["leases"] if x["state"] == "queued"]:
        if v["level"] == "critical":
            break
        alone = not any(x["state"] == "granted" for x in L["leases"])
        if r["gb"] <= avail or (alone and v["level"] == "ok"):
            if r["gb"] > avail:
                r["note"] = ("larger than the %.1f GB available now; granted because no other work is reserved — "
                             "expect swapping" % max(0.0, avail))
            r["state"], r["granted"] = "granted", round(now, 1)
            r["expires"] = round(now + r["ttl"], 1) if r.get("ttl") else None
            w = r.get("watch")
            r["baseline_gb"] = round(_tree_gb(procs, children, w), 3) if w in procs else 0.0
            r["used_gb"], r["peak_gb"] = 0.0, 0.0
            same = [x for x in L["leases"] if x is not r and x["state"] == "granted" and x.get("watch") == w]
            if same:  # share the first grant's baseline (see above)
                r["baseline_gb"] = min(x.get("baseline_gb", 0) for x in same)
            avail -= r["gb"]
            outstanding += r["gb"]
        else:
            break
    L["state"] = {"t": round(now, 1), "level": v["level"], "free_gb": free, "margin_gb": round(margin_gb(ram), 1),
                  "reserved_gb": round(outstanding, 1), "available_gb": round(avail, 1)}


# ----- root callers: the ledger operation runs in a child as the invoking user (H0)
_LEDGER_CALLS = {}


def _child_user():
    """Whom a root caller's ledger operation runs as: the user who ran sudo, else nobody."""
    try:
        uid, gid = int(os.environ.get("SUDO_UID") or 0), int(os.environ.get("SUDO_GID") or 0)
    except ValueError:
        uid = gid = 0
    if uid > 0:
        try:
            gid = gid if gid > 0 else pwd.getpwuid(uid).pw_gid
        except KeyError:
            gid = 0
        if gid > 0:
            return uid, gid
    return "nobody", "nobody"


def _drop_to(user, group):
    """subprocess arguments that run a child as user:group without root's other groups, when we
    are root; none when we aren't (the child then simply is us)."""
    return {"user": user, "group": group, "extra_groups": []} if os.geteuid() == 0 else {}


def run_bounded(cmd, data, cap, timeout, **kw):
    """Run `cmd` (in /, with a minimal environment) with `data` on its stdin and read at most
    `cap` bytes of its stdout, and the last few KB of its stderr, within `timeout` seconds. A
    child that takes longer or says more is killed; either way it is reaped. Returns (exit
    status, stdout, stderr text); raises LedgerError on a timeout or an overflow."""
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
                         env={"PATH": "/usr/bin:/bin", "OOMPH_LEDGER_DIR": LEDGER_DIR}, **kw)

    def feed():
        try:
            p.stdin.write(data)
        except (OSError, ValueError):
            pass  # it died or stopped reading
        try:
            p.stdin.close()
        except (OSError, ValueError):
            pass
    feeder = threading.Thread(target=feed, daemon=True)
    feeder.start()
    out_fd, err_fd = p.stdout.fileno(), p.stderr.fileno()
    out, err, n, fail = [], b"", 0, None
    deadline = time.monotonic() + timeout
    fds = [out_fd, err_fd]
    try:
        while fds and not fail:
            left = deadline - time.monotonic()
            if left <= 0:
                fail = "timed out after %g s" % timeout
                break
            for fd in select.select(fds, [], [], left)[0]:
                b = os.read(fd, 1 << 16)
                if not b:
                    fds.remove(fd)
                elif fd == out_fd:
                    out.append(b)
                    n += len(b)
                    if n > cap:
                        fail = "answered more than %d bytes" % cap
                else:
                    err = (err + b)[-4096:]
        if not fail:
            try:
                p.wait(max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                fail = "timed out after %g s" % timeout
    finally:
        if p.returncode is None:
            p.kill()
            p.wait()
        feeder.join(2)
        p.stdout.close()
        p.stderr.close()
    if fail:
        raise LedgerError("%s %s" % (" ".join(cmd[-2:]), fail))
    return p.returncode, b"".join(out), err.decode("utf-8", "replace")


def _unprivileged(inputs=False):
    """Ledger operations never run as root. Called as root (`sudo oomph reserve …`, a root
    agent's MCP server, the bookkeeping of `sudo oomph run`), the operation runs in a child as
    the user who ran sudo, else as nobody: `oomph _ledger-call <name>` gets the arguments as
    JSON on stdin — with `inputs` also the sample and process table, which only root measures
    whole — and answers with JSON on stdout, at most LIMITS["child"] bytes, within
    CHILD_TIMEOUT_S. Not root: a plain call."""
    def wrap(fn):
        _LEDGER_CALLS[fn.__name__] = fn

        @functools.wraps(fn)
        def call(*args, **kw):
            if os.geteuid() != 0:
                return fn(*args, **kw)
            return _call_as_user(fn.__name__, args, kw, inputs)
        return call
    return wrap


def _enc(x):  # a process table is keyed by int pid; JSON would make the keys strings
    if isinstance(x, dict) and x and all(isinstance(k, int) for k in x):
        return {"__by_int__": [[k, v] for k, v in x.items()]}
    return x


def _dec(x):
    if isinstance(x, dict) and list(x) == ["__by_int__"]:
        return {int(k): v for k, v in x["__by_int__"]}
    return x


def _call_as_user(name, args, kw, inputs):
    d = {"args": [_enc(a) for a in args], "kw": {k: _enc(v) for k, v in kw.items()}}
    if inputs:
        s, procs, _ = _decide_inputs()
        d["s"], d["procs"] = s, list(procs.values())
    user, group = _child_user()
    rc, out, err = run_bounded([PY, "-I", "-B", os.path.realpath(__file__), "_ledger-call", name],
                               json.dumps(d, default=str).encode(), LIMITS["child"], CHILD_TIMEOUT_S,
                               **_drop_to(user, group))
    res = loads_untrusted(out)
    if not isinstance(res, dict) or not ("ok" in res or "error" in res):
        raise LedgerError("the ledger operation (run as %s) failed: %s"
                          % (user, (err.strip().splitlines() or ["exit status %s" % rc])[-1][:300]))
    if "error" in res:
        raise (LedgerBusy if res.get("busy") else LedgerError)(str(res["error"])[:500])
    return res["ok"]


def _cmd_ledger_call(name):
    """Internal: the unprivileged half of a root caller's ledger operation (see _unprivileged)."""
    global _given
    if os.geteuid() == 0:
        print("oomph: _ledger-call refuses to run as root", file=sys.stderr)
        return 1
    fn = _LEDGER_CALLS.get(name)
    if fn is None:
        print("oomph: _ledger-call: no ledger operation %r" % name, file=sys.stderr)
        return 2
    d = json.loads(sys.stdin.read())
    if "s" in d:
        _given = (d["s"], {p["pid"]: p for p in d["procs"]})
    try:
        out = {"ok": fn(*[_dec(a) for a in d["args"]], **{k: _dec(v) for k, v in d["kw"].items()})}
    except LedgerBusy as e:
        out = {"error": str(e), "busy": True}
    except LedgerError as e:
        out = {"error": str(e)}
    except Exception as e:
        out = {"error": "%s: %s" % (type(e).__name__, e)}
    sys.stdout.write(json.dumps(out))
    return 0


def _decide_inputs(s=None):
    if _given:  # an unprivileged child: root measured them
        return s or _given[0], _given[1], time.time()
    s = s or (_sample_override() if _sample_override else live_sample(with_procs=False))
    return s, _daemon_module().collect_procs(), time.time()


def _brief(r, now):
    b = {"id": r["id"], "state": r["state"], "gb": r["gb"], "purpose": r["purpose"],
         "project": os.path.basename(r.get("project") or "") or None, "holder_pid": r["holder"]["pid"]}
    if r["state"] == "granted":
        b.update(used_gb=r.get("used_gb", 0), for_min=round((now - r["granted"]) / 60, 1))
        if r.get("expires"):
            b["expires_in_min"] = round((r["expires"] - now) / 60, 1)
    else:
        b["waiting_min"] = round((now - r["requested"]) / 60, 1)
    return b


def _status(L, rid, now):
    st = L.get("state", {})
    r = next((x for x in L["leases"] if x["id"] == rid), None)
    if r is None:
        h = next((x for x in reversed(L["history"]) if x["id"] == rid), None)
        return {"status": "gone", "id": rid, "outcome": h and h["outcome"],
                "advice": "This reservation no longer exists (%s). Request a new one if you still need it."
                          % (h["outcome"] if h else "unknown id")}
    out = {"status": r["state"], "id": r["id"], "gb": r["gb"], "purpose": r["purpose"],
           "available_gb": st.get("available_gb"), "reserved_gb": st.get("reserved_gb"),
           "free_gb": st.get("free_gb"), "level": st.get("level")}
    if r["state"] == "granted":
        out["expires_in_min"] = round((r["expires"] - now) / 60, 1) if r.get("expires") else None
        if r.get("note"):
            out["note"] = r["note"]
        out["advice"] = ("Granted: start the work now. Release it (release_memory / `oomph release %s`) as soon as the "
                         "memory-heavy part is over%s." % (r["id"], "" if not r.get("expires") else
                                                           "; it expires in %d min unless extended" % round((r["expires"] - now) / 60)))
    else:
        queued = [x for x in L["leases"] if x["state"] == "queued"]
        pos = [x["id"] for x in queued].index(r["id"]) + 1
        out["position"] = pos
        out["ahead"] = [_brief(x, now) for x in L["leases"]
                        if x["state"] == "granted" or (x["state"] == "queued" and x["id"] in [q["id"] for q in queued[:pos - 1]])]
        why = ("memory is critical" if st.get("level") == "critical" else
               "%d request(s) are ahead of you" % (pos - 1) if pos > 1 else
               "only %.1f GB is available for new reservations" % max(0.0, st.get("available_gb") or 0))
        out["advice"] = ("Queued #%d (%s). Don't start this work yet. Ask again with the same ticket (%s) within %d s to "
                         "keep your place — meanwhile do light work or wait." % (pos, why, r["id"], QUEUE_STALE_S))
    return out


def holder_for(pid=None, kind=None):
    """Who owns a reservation made from here: the Claude session we run in, else our parent process."""
    d = _daemon_module()
    procs = d.collect_procs()
    start_pid = pid or os.getppid()
    root = _session_root(procs, start_pid)
    hp = root or start_pid
    return {"pid": hp, "start": procs.get(hp, {}).get("start"), "kind": kind or ("session" if root else "process"),
            "project": d.proc_cwd(hp)}


@_unprivileged(inputs=True)
def reserve(gb, purpose, holder, ttl_s=DEFAULT_TTL_S, ticket=None, watch="holder"):
    """Request (or re-poll with `ticket`) a reservation. Returns its status dict."""
    s, procs, now = _decide_inputs()
    with Ledger() as L:
        r = next((x for x in L["leases"] if x["id"] == ticket), None) if ticket else None
        if ticket and r is None:
            return _status(L, ticket, now)
        if r is None:
            ram = s.get("ram_gb") or 0
            if gb <= 0 or (ram and gb > 0.9 * ram):
                return {"status": "refused", "gb": gb,
                        "advice": "Can't reserve %.1f GB on a Mac with %.0f GB RAM. Split the work or lower its "
                                  "parallelism." % (gb, ram)}
            L["seq"] += 1
            r = {"id": "r%d" % L["seq"], "state": "queued", "gb": round(gb, 2), "purpose": (purpose or "?")[:80],
                 "project": holder.get("project"), "holder": {k: holder.get(k) for k in ("pid", "start", "kind")},
                 "watch": holder["pid"] if watch == "holder" else watch,
                 "ttl": None if ttl_s is None else min(max(60, ttl_s), MAX_TTL_S),
                 "requested": round(now, 1), "seen": round(now, 1),
                 "segments": [{"t": round(now, 1), "gb": round(gb, 2)}]}
            r["key"] = _key(r)
            L["leases"].append(r)
        else:
            r["seen"] = round(now, 1)
            if r["state"] == "granted" and r.get("expires") and ttl_s:  # re-asking extends a grant
                r["expires"] = round(now + min(max(60, ttl_s), MAX_TTL_S), 1)
        _evaluate(L, s, procs, now)
        return _status(L, r["id"], now)


def acquire(gb, purpose, holder, ttl_s=DEFAULT_TTL_S, wait_s=0, ticket=None, watch="holder", progress=None):
    st = reserve(gb, purpose, holder, ttl_s, ticket, watch)
    t0 = time.time()
    while st["status"] == "queued" and time.time() - t0 < wait_s:
        if progress:
            progress(st)
        time.sleep(min(POLL_S, max(0.1, wait_s - (time.time() - t0))))
        st = reserve(gb, purpose, holder, ttl_s, st["id"], watch)
    return st


@_unprivileged(inputs=True)
def release(rid, holder_pid=None, outcome="released"):
    """Release one reservation, or with rid='all' every one held by `holder_pid`."""
    s, procs, now = _decide_inputs()
    with Ledger() as L:
        gone = [r for r in L["leases"] if r["id"] == rid or (rid == "all" and r["holder"]["pid"] == holder_pid)]
        _evaluate(L, s, procs, now)  # final usage figures, before removing
        gone = [r for r in L["leases"] if r["id"] in {g["id"] for g in gone}]
        for r in gone:
            _retire(L, r, outcome if r["state"] == "granted" else "cancelled", now)
        L["leases"] = [r for r in L["leases"] if r not in gone]
        _evaluate(L, s, procs, now)  # hand the memory to whoever is next
        return {"released": [h for h in L["history"] if h["id"] in {g["id"] for g in gone}],
                "available_gb": L["state"]["available_gb"],
                "next_granted": [r["id"] for r in L["leases"] if r["state"] == "granted" and r.get("granted") == round(now, 1)]}


@_unprivileged(inputs=True)
def amend(rid, gb=None, ttl_s=None, purpose=None):
    """Change a reservation in place: its size, its time to live (from now) or its purpose.
    Shrinking applies at once and hands the room to whoever waits. Growing a grant applies only
    when the extra memory would be granted to a new request right now (it fits, and nobody is
    queued); otherwise it is refused, with advice to reserve the extra separately, which queues
    fairly. Growing a queued request moves it to the back of the queue. Every applied change is
    written to the history log, and a new size starts a new segment of the reservation's span."""
    s, procs, now = _decide_inputs()
    with Ledger() as L:
        _evaluate(L, s, procs, now)
        r = next((x for x in L["leases"] if x["id"] == rid), None)
        if r is None:
            return _status(L, rid, now)
        ram = s.get("ram_gb") or 0
        change, refused = {}, None
        if gb is not None and round(gb, 2) != r["gb"]:
            gb = round(gb, 2)
            if gb <= 0 or (ram and gb > 0.9 * ram):
                refused = ("Can't reserve %.1f GB on a Mac with %.0f GB RAM. Release the reservation instead "
                           "(release_memory / `oomph release %s`) if the work is done." % (gb, ram, rid))
            elif gb > r["gb"] and r["state"] == "granted":
                extra, st = gb - r["gb"], L["state"]
                waiting = [x for x in L["leases"] if x["state"] == "queued"]
                if waiting or extra > st["available_gb"] or st["level"] == "critical":
                    why = ("%d request(s) are queued and come first" % len(waiting) if waiting else
                           "memory is critical" if st["level"] == "critical" else
                           "only %.1f GB is available" % max(0.0, st["available_gb"]))
                    refused = ("Can't grow %s from %.1f to %.1f GB now: %s. Keep the %.1f GB grant and reserve the "
                               "extra %.1f GB separately (reserve_memory gb=%.1f / `oomph reserve %.1fG --for \"…\"`): "
                               "it queues fairly and is granted when it fits." % (
                                   rid, r["gb"], gb, why, r["gb"], extra, extra, extra))
            if refused is None:
                change["gb"] = [r["gb"], gb]
                if gb > r["gb"] and r["state"] == "queued":  # a bigger request takes a new place in line
                    L["leases"].remove(r)
                    L["leases"].append(r)
                    change["requeued"] = True
                r["gb"] = gb
                r.setdefault("segments", [{"t": r.get("granted") or r["requested"], "gb": change["gb"][0]}])
                if r["segments"][-1]["t"] >= round(now, 1):
                    r["segments"][-1]["gb"] = gb
                else:
                    r["segments"].append({"t": round(now, 1), "gb": gb})
        if refused is None and ttl_s:
            ttl = min(max(60, ttl_s), MAX_TTL_S)
            r["ttl"] = ttl
            if r["state"] == "granted":
                change["expires_in_min"] = [round((r["expires"] - now) / 60, 1) if r.get("expires") else None,
                                            round(ttl / 60, 1)]
                r["expires"] = round(now + ttl, 1)
            else:
                change["ttl_min"] = round(ttl / 60, 1)
        if refused is None and purpose and purpose[:80] != r["purpose"]:
            change["purpose"] = [r["purpose"], purpose[:80]]
            r["purpose"] = purpose[:80]
        r["seen"] = round(now, 1)
        if change:
            _evaluate(L, s, procs, now)  # a smaller grant may let the next request go
            try:
                _append_history(L, [_record(r, "edit", now, change=change, expires=r.get("expires"))], now)
            except OSError:
                pass
        out = _status(L, rid, now)
        if refused:
            out.update(status="refused", id=rid, gb=r["gb"], requested_gb=gb, advice=refused, keeps=r["state"])
        else:
            out["changed"] = change
        return out


@_unprivileged(inputs=True)
def set_watch(rid, pid):
    """Point a grant at the process tree that does the work (`oomph run`'s child)."""
    s, procs, now = _decide_inputs()
    with Ledger() as L:
        for r in L["leases"]:
            if r["id"] == rid:
                r["watch"], r["baseline_gb"] = pid, 0.0
        _evaluate(L, s, procs, now)


@_unprivileged(inputs=True)
def coordination(mine=None, s=None):
    """Current reservations (refreshed), seen from session `mine`: what others hold or wait for."""
    s, procs, now = _decide_inputs(s)
    with Ledger() as L:
        _evaluate(L, s, procs, now)
        st = L["state"]
        others = [r for r in L["leases"] if r["holder"]["pid"] != mine]
        own = [r for r in L["leases"] if r["holder"]["pid"] == mine]
        others_out = sum(r["gb"] - r.get("used_gb", 0) for r in others if r["state"] == "granted")
        return {
            "free_gb": st["free_gb"], "margin_gb": st["margin_gb"], "reserved_gb": st["reserved_gb"],
            "available_gb": st["available_gb"],
            "reserved_by_others_gb": round(others_out, 1),
            "available_to_me_gb": round(st["free_gb"] - others_out - st["margin_gb"], 1),
            "others": [_brief(r, now) for r in others], "mine": [_brief(r, now) for r in own],
            "history": [dict(h, project=os.path.basename(h.get("project") or "") or None)
                        for h in L["history"][-15:]][::-1],
        }


def _span(rec, now):
    """A history record or live lease as a span for agents: when, how big, how it ended."""
    def iso(t):
        return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds") if t else None
    start = rec.get("granted") or rec["requested"]
    end = rec.get("ended")
    out = {"id": rec["id"], "key": _key(rec), "purpose": rec["purpose"],
           "project": os.path.basename(rec.get("project") or "") or None, "holder": rec.get("holder"),
           "gb": rec["gb"], "peak_gb": rec.get("peak_gb", 0), "requested": iso(rec["requested"]),
           "granted": iso(rec.get("granted")), "ended": iso(end),
           "outcome": rec.get("outcome") or ("active" if rec.get("granted") else "queued"),
           "waited_min": round(((rec.get("granted") or end or now) - rec["requested"]) / 60, 1),
           "held_min": round(((end or now) - start) / 60, 1) if rec.get("granted") else 0}
    if len(rec.get("segments") or []) > 1:
        out["gb_changes"] = [{"at": iso(x["t"]), "gb": x["gb"]} for x in rec["segments"]]
    return out


@_unprivileged()
def reservation_history(since_s=24 * 3600, limit=50):
    """Finished reservations from the history log (last `since_s` seconds) plus the live ones,
    newest first: what each reserved, what it really used at its peak, and how it ended."""
    now = time.time()
    last = {}
    for rec in read_history(now - since_s):
        if rec.get("event") == "end" or last.get(rec["key"], {}).get("event") != "end":
            last[rec["key"]] = rec
    for h in read_ledger()["history"]:  # finished before the log existed
        if h.get("ended", 0) >= now - since_s:
            last.setdefault(_key(h), h)
    L = read_ledger()
    live = [dict(r, holder=r["holder"].get("kind")) for r in L["leases"]]
    for r in live:
        last.pop(_key(r), None)
    done = [x for x in last.values() if x.get("ended")]
    spans = [_span(r, now) for r in live] + sorted((_span(x, now) for x in done), key=lambda x: x["ended"], reverse=True)
    return {"since": datetime.datetime.fromtimestamp(now - since_s).astimezone().isoformat(timespec="seconds"),
            "active": len(live), "finished": len(done), "reservations": spans[:limit],
            "log": _history_path()}


@_unprivileged()
def refresh_ledger(s, procs):
    """The daemon's tick: retire leases whose holder died or that expired, close to when it
    happened, and keep the usage figures current. Skips the lock when nothing is reserved."""
    if not read_ledger()["leases"]:
        return
    with Ledger() as L:
        _evaluate(L, s, procs, time.time())


def ledger_tick(s, procs, timeout=TICK_TIMEOUT_S):
    """The daemon's ledger work for one sample: refresh_ledger, then the snapshot of live
    reservations for the sample, both in a child — as nobody when the daemon is root (root
    never opens anything in the shared directory, to read or to write), as the same user when
    it isn't. Its answer is at most LIMITS["tick"] bytes of JSON, read within `timeout`, and the
    sample's block is rebuilt from it field by field (sample_leases). Returns (leases, error
    or None). The daemon calls this from a thread of its own: the sampler never waits on it."""
    payload = json.dumps({"s": s, "procs": list(procs.values())}, default=str).encode()
    rc, out, err = run_bounded([PY, "-I", "-B", os.path.realpath(__file__), "_ledger-refresh"], payload,
                               LIMITS["tick"], timeout, **_drop_to("nobody", "nobody"))
    d = loads_untrusted(out)
    if rc != 0 or not isinstance(d, dict):
        raise LedgerError("ledger refresh failed: %s" % (err.strip().splitlines() or ["exit status %s" % rc])[-1][:300])
    e = d.get("error")
    return sample_leases(d.get("leases")), (e[:300] if isinstance(e, str) else None)


def _cmd_ledger_refresh():
    """Internal: the unprivileged half of ledger_tick (sample + procs on stdin, snapshot on stdout)."""
    global _lock_wait
    if os.geteuid() == 0:
        print("oomph: _ledger-refresh refuses to run as root", file=sys.stderr)
        return 1
    _lock_wait = LOCK_WAIT_TICK_S  # busy now: it runs again next sample
    d = json.load(sys.stdin)
    procs = {p["pid"]: p for p in d["procs"]}
    out = {}
    try:
        fd = _ledger_dir()  # readers see a directory replaced by a link as empty; the daemon should hear of it
        if fd is not None:
            os.close(fd)
        refresh_ledger(d["s"], procs)
    except Exception as e:  # the snapshot is still worth having
        out["error"] = "%s: %s" % (type(e).__name__, e) if not isinstance(e, LedgerError) else str(e)
    out["leases"] = sample_leases(ledger_snapshot(procs))
    sys.stdout.write(json.dumps(out))
    return 0


@_unprivileged()
def ledger_snapshot(procs=None):
    """Compact read-only view of live reservations, for the daemon's samples (no lock, no write)."""
    try:
        L = read_ledger()
    except Exception:
        return []
    now = time.time()
    out = []
    for r in L["leases"]:
        if procs is not None and not _alive(procs, r["holder"]["pid"], r["holder"].get("start")):
            continue
        if r["state"] == "granted" and r.get("expires") and now > r["expires"]:
            continue
        if r["state"] == "queued" and now - r["seen"] > QUEUE_STALE_S:
            continue
        b = _brief(r, now)
        b.pop("holder_pid", None)
        out.append(b)
    return out


SAMPLE_LEASE_NUMS = ("used_gb", "for_min", "expires_in_min", "waiting_min")


def sample_leases(x):
    """The leases block of a sample, rebuilt from typed fields only — what root republishes can't
    be bigger, deeper or differently shaped than this, whatever the shared directory held: at
    most LIMITS["leases_n"] entries of id, state, gb, purpose, project and the numbers of
    SAMPLE_LEASE_NUMS, strings cut to LIMITS["str"], LIMITS["leases"] bytes in all. A malformed
    entry is skipped, never raised."""
    out, size, n = [], 2, LIMITS["str"]
    for b in x if isinstance(x, list) else []:
        if len(out) >= LIMITS["leases_n"]:
            break
        if not (isinstance(b, dict) and isinstance(b.get("id"), str) and b.get("state") in ("queued", "granted")
                and _num(b.get("gb"), 0, 1e6)):
            continue
        e = {"id": b["id"][:n], "state": b["state"], "gb": b["gb"],
             "purpose": b["purpose"][:n] if isinstance(b.get("purpose"), str) else "?",
             "project": b["project"][:n] if isinstance(b.get("project"), str) else None}
        e.update((k, b[k]) for k in SAMPLE_LEASE_NUMS if _num(b.get(k)))
        size += len(json.dumps(e)) + 1
        if size > LIMITS["leases"]:
            break
        out.append(e)
    return out


def coordination_verdict(v, c):
    """Fold others' reservations into a check verdict."""
    v["coordination"] = c
    if c["others"] and c["available_to_me_gb"] < 0 and v["level"] == "ok":
        v["level"], v["exit_code"] = "tight", 1
        v["advice"] = ADVICE["tight"]
    if c["others"] and c["available_to_me_gb"] < 0:
        v["reasons"].append("%.1f GB is reserved by other sessions for work they have started or are about to start"
                            % c["reserved_by_others_gb"])
    if any(o["state"] == "queued" for o in c["others"]):
        v["advice"] += (" Other sessions are queued for memory — reserve before your next heavy step "
                        "(reserve_memory / `oomph run --reserve`) so you take your turn instead of competing.")
    return v


def _fmt_brief(b):
    tail = ("using %.1fG, %.0f min" % (b.get("used_gb", 0), b["for_min"]) if b["state"] == "granted"
            else "waiting %.0f min" % b["waiting_min"])
    return "%-5s %-7s %5.1fG  %-28s %-14s %s" % (b["id"], b["state"], b["gb"], b["purpose"][:28],
                                                (b.get("project") or "")[:14], tail)


def _opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def cmd_reserve(args):
    pos = [a for i, a in enumerate(args) if not a.startswith("--") and (i == 0 or args[i - 1] not in
                                                                        ("--for", "--wait", "--ttl", "--ticket", "--pid"))]
    ticket = _opt(args, "--ticket")
    if not pos and not ticket:
        print("usage: oomph reserve <size, e.g. 6G> --for \"what\" [--wait 10m] [--ttl 30m] [--ticket rN] [--json]")
        return 2
    gb = _parse_gb(pos[0]) if pos else 0
    holder = holder_for(int(_opt(args, "--pid")) if "--pid" in args else None)
    st = acquire(gb, _opt(args, "--for", "unspecified"), holder, parse_dur(_opt(args, "--ttl", "30m")),
                 parse_dur(_opt(args, "--wait", "0s")), ticket)
    if "--json" in args:
        print(json.dumps(st))
    else:
        print("oomph: %s %s — %s" % (st["status"].upper(), st.get("id", ""), st["advice"]))
        for b in st.get("ahead") or []:
            print("  ahead: " + _fmt_brief(b))
        if st.get("note"):
            print("  note: " + st["note"])
    return 0 if st["status"] == "granted" else 75


def cmd_release(args):
    if not args or args[0].startswith("--"):
        print("usage: oomph release <id | all>   (all = every reservation held by this session)")
        return 2
    res = release(args[0], holder_for()["pid"] if args[0] == "all" else None)
    if "--json" in args:
        print(json.dumps(res))
        return 0
    if not res["released"]:
        print("oomph: nothing to release")
        return 1
    for h in res["released"]:
        print("oomph: released %s (%s) — reserved %.1fG, peak %.1fG, held %ds" % (
            h["id"], h["purpose"], h["gb"], h["peak_gb"], h["held_s"]))
    if res["next_granted"]:
        print("oomph: now granted to " + ", ".join(res["next_granted"]))
    return 0


def cmd_amend(args):
    rid = args[0] if args and not args[0].startswith("--") else None
    if not rid or not any(o in args for o in ("--gb", "--ttl", "--for")):
        print("usage: oomph amend <id> [--gb 3G] [--ttl 20m] [--for \"what\"] [--json]")
        return 2
    st = amend(rid, _parse_gb(_opt(args, "--gb")) if "--gb" in args else None,
               parse_dur(_opt(args, "--ttl")) if "--ttl" in args else None, _opt(args, "--for"))
    if "--json" in args:
        print(json.dumps(st))
    else:
        ch = st.get("changed") or {}
        what = ", ".join(("%.1fG → %.1fG" % tuple(v)) if k == "gb" else
                         ("expires in %.0f min" % v[1]) if k == "expires_in_min" else
                         ("ttl %.0f min" % v) if k == "ttl_min" else
                         ("for \"%s\"" % v[1]) if k == "purpose" else "back of the queue"
                         for k, v in ch.items())
        print("oomph: %s %s%s — %s" % (st["status"].upper(), st.get("id", rid), " (%s)" % what if what else "",
                                       st["advice"]))
    return 75 if st["status"] in ("refused", "gone") else 0


def cmd_reservation_history(args):
    h = reservation_history(parse_dur(_opt(args, "--last", "24h")), limit=int(_opt(args, "--limit", "50")))
    if "--json" in args:
        print(json.dumps(h))
        return 0
    print("%d active, %d finished since %s  (log: %s)" % (h["active"], h["finished"], h["since"][:16], h["log"]))
    for x in h["reservations"]:
        when = (x["granted"] or x["requested"])[5:16].replace("T", " ")
        end = (x["ended"] or "now")[11:16] if x["ended"] else "now"
        gbs = " → ".join("%.1fG" % c["gb"] for c in x.get("gb_changes", [])) or "%.1fG" % x["gb"]
        print("  %-6s %s–%-5s %-13s peak %4.1fG  %-26s %-14s %s" % (
            x["id"], when, end, gbs, x["peak_gb"], x["purpose"][:26], (x["project"] or "")[:14], x["outcome"]))
    return 0


def cmd_reservations(args):
    if "--history" in args:
        return cmd_reservation_history(args)
    c = coordination(holder_for()["pid"])
    if "--json" in args:
        print(json.dumps(c))
        return 0
    print("free %.1fG − reserved %.1fG − margin %.1fG = %.1fG available for new reservations" % (
        c["free_gb"], c["reserved_gb"], c["margin_gb"], c["available_gb"]))
    rows = [("me", b) for b in c["mine"]] + [("", b) for b in c["others"]]
    if rows:
        print("\nactive:")
        for who, b in sorted(rows, key=lambda x: (x[1]["state"] != "granted", x[1]["id"])):
            print("  %-3s %s" % (who, _fmt_brief(b)))
    else:
        print("\nno active reservations")
    if c["history"]:
        print("\nrecent (reserved → peak actually added):")
        for h in c["history"][:10]:
            print("  %-5s %5.1fG → %4.1fG  %-28s %-14s %-11s held %s" % (
                h["id"], h["gb"], h["peak_gb"], h["purpose"][:28], (h.get("project") or "")[:14], h["outcome"],
                "%dm%02ds" % divmod(h["held_s"], 60)))
    return 0


def cmd_run(args):
    if "--" not in args or "--reserve" not in args:
        print("usage: oomph run --reserve 6G [--for \"what\"] [--wait 30m] -- <command> [args…]")
        return 2
    i = args.index("--")
    opts, cmd = args[:i], args[i + 1:]
    if not cmd:
        print("oomph run: no command given")
        return 2
    import signal
    gb = _parse_gb(_opt(opts, "--reserve"))
    purpose = _opt(opts, "--for") or " ".join(os.path.basename(c) if j == 0 else c for j, c in enumerate(cmd[:3]))
    wait_s = parse_dur(_opt(opts, "--wait", "30m"))
    ses = holder_for()
    me = {"pid": os.getpid(), "start": _daemon_module().collect_procs().get(os.getpid(), {}).get("start"),
          "kind": "run", "project": ses["project"] if ses["kind"] == "session" else os.getcwd()}
    last = [0.0]

    def progress(st):
        if time.time() - last[0] >= 30:
            last[0] = time.time()
            ahead = ", ".join("%s %.1fG %s (%s)" % (b["id"], b["gb"], b["purpose"], b.get("project") or "?")
                              for b in st.get("ahead", [])[:3])
            sys.stderr.write("oomph: waiting for %.1fG — queued #%s, %.1fG available%s\n" % (
                gb, st.get("position"), st.get("available_gb") or 0, "; ahead: " + ahead if ahead else ""))
            sys.stderr.flush()

    st = acquire(gb, purpose, me, None, wait_s, watch=None, progress=progress)
    if st["status"] != "granted":
        if st["status"] == "queued":
            _quietly(release, st["id"])
        sys.stderr.write("oomph: not started — %s\n" % (
            "still queued after %ds (%s)" % (wait_s, st["advice"]) if st["status"] == "queued" else st["advice"]))
        return 75
    if st.get("note"):
        sys.stderr.write("oomph: note — %s\n" % st["note"])
    t0 = time.time()
    try:
        child = subprocess.Popen(cmd)
    except OSError as e:
        _quietly(release, st["id"])
        sys.stderr.write("oomph run: %s\n" % e)
        return 127
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, lambda n, f: child.send_signal(n))
    rc = None
    try:
        _quietly(set_watch, st["id"], child.pid)
        while rc is None:
            try:
                rc = child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _quietly(coordination)  # refresh: records this run's peak, hands spare room to others
    except KeyboardInterrupt:
        rc = child.wait()  # the child got the same SIGINT
    finally:
        res = _quietly(release, st["id"]) or {"released": []}  # else it ends when this process does
    h = (res["released"] or [{}])[0]
    sys.stderr.write("oomph: %s — reserved %.1fG, peak %.1fG, %ds\n" % (
        st["id"], gb, h.get("peak_gb", 0), time.time() - t0))
    return rc if rc >= 0 else 128 - rc


def _quietly(fn, *a):
    """Bookkeeping that mustn't stop `oomph run` (its command runs regardless): a ledger error
    is reported, not raised."""
    try:
        return fn(*a)
    except LedgerError as e:
        sys.stderr.write("oomph: %s\n" % e)
        return None


def cmd_hook(args):
    """PostToolUse hook. Silent (exit 0) when memory is ok. When tight/critical, prints a short
    warning to stderr and exits 2, which Claude Code shows to the model. Warns again only when
    the level changes or after 10 minutes."""
    try:
        sys.stdin.read()  # the hook payload; not needed
    except Exception:
        pass
    v = checked_verdict()
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
    {"name": "reserve_memory",
     "description": "Coordinate memory with other Claude sessions on this Mac. Before memory-heavy work (builds, test "
                    "suites, containers, browsers, sub-agents, data jobs) reserve its estimated PEAK extra memory. "
                    "Requests queue first-come-first-served and are granted when they fit next to what others have "
                    "reserved, so heavy steps run side by side when there's room and one after another when there "
                    "isn't. Returns status granted (start now), queued (do NOT start yet; call again with ticket=id "
                    "within 180 s to keep your place, and see who is ahead) or refused. Calling again with the ticket "
                    "of a granted reservation extends it. Change its size, ttl or purpose with update_reservation, "
                    "and release it with release_memory when the heavy part is over.",
     "inputSchema": {"type": "object", "required": ["gb", "purpose"], "properties": {
         "gb": {"type": "number", "exclusiveMinimum": 0, "description": "estimated peak extra memory in GB"},
         "purpose": {"type": "string", "description": "short label, e.g. 'gradle assembleDebug' — reuse the same "
                                                       "label for the same work so its measured peak can guide estimates"},
         "wait_s": {"type": "integer", "minimum": 0, "maximum": 300, "default": 120,
                    "description": "how long to wait for a grant within this call"},
         "ttl_min": {"type": "integer", "minimum": 1, "maximum": 480, "default": 30,
                     "description": "auto-expiry of the grant if it isn't released or extended"},
         "ticket": {"type": "string", "description": "id from an earlier queued/granted response"}}}},
    {"name": "release_memory",
     "description": "Release a reservation (id) — or 'all' of this session's — as soon as the memory-heavy work has "
                    "finished, so queued sessions can go. Returns the peak memory the work actually added.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {"id": {"type": "string"}}}},
    {"name": "update_reservation",
     "description": "Change a reservation (granted or queued) in place: a new size in GB, a new time to live "
                    "(counted from now: shorter or longer), or a new purpose. Shrink as soon as the heaviest part is "
                    "over, so others can start. Shrinking applies at once. Growing a granted reservation applies only "
                    "if the extra memory fits right now and nobody is queued; otherwise it is refused (status refused, "
                    "nothing changes, your grant stays) and you should reserve the extra separately with "
                    "reserve_memory, which queues fairly. Growing a queued request moves it to the back of the queue. "
                    "To end a reservation use release_memory.",
     "inputSchema": {"type": "object", "required": ["id"], "properties": {
         "id": {"type": "string", "description": "the reservation's id, e.g. r12"},
         "gb": {"type": "number", "exclusiveMinimum": 0, "description": "new size in GB"},
         "ttl_min": {"type": "integer", "minimum": 1, "maximum": 480, "description": "expire this many minutes from now"},
         "purpose": {"type": "string", "description": "new short label"}}}},
    {"name": "reservations",
     "description": "All current reservations on this Mac (yours and other sessions': granted and queued, with "
                    "purpose, project and memory actually used), the memory available for new ones, and recent "
                    "finished reservations with the peak each really needed — use those peaks to estimate.",
     "inputSchema": {"type": "object", "properties": {}}},
    {"name": "reservation_history",
     "description": "Past reservations on this Mac (14 days are kept, also of sessions that are gone): each one's "
                    "span (requested, granted, ended), GB reserved and its changes over time, the peak memory the "
                    "work really added, and how it ended (released, expired, holder_gone, lapsed, cancelled). Use "
                    "it to estimate what to reserve for work done before.",
     "inputSchema": {"type": "object", "properties": {
         "hours": {"type": "number", "minimum": 0.1, "maximum": 336, "default": 24},
         "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
         "purpose": {"type": "string", "description": "only reservations whose purpose contains this text"}}}},
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
        return checked_verdict()
    if name == "reserve_memory":
        ttl = min(max(int(a.get("ttl_min", 30)), 1), 480) * 60
        return acquire(float(a["gb"]), str(a.get("purpose", "unspecified")), holder_for(), ttl,
                       min(max(int(a.get("wait_s", 120)), 0), 300), a.get("ticket"))
    if name == "release_memory":
        rid = str(a.get("id", ""))
        return release(rid, holder_for()["pid"] if rid == "all" else None)
    if name == "update_reservation":
        return amend(str(a["id"]), float(a["gb"]) if a.get("gb") is not None else None,
                     min(max(int(a["ttl_min"]), 1), 480) * 60 if a.get("ttl_min") else None,
                     str(a["purpose"]) if a.get("purpose") else None)
    if name == "reservations":
        return coordination(holder_for()["pid"])
    if name == "reservation_history":
        h = reservation_history(min(max(float(a.get("hours", 24)), 0.1), 336) * 3600, 500)
        if a.get("purpose"):
            h["reservations"] = [x for x in h["reservations"] if str(a["purpose"]).lower() in x["purpose"].lower()]
        h["reservations"] = h["reservations"][:int(a.get("limit", 50))]
        return h
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
                          "instructions": "oomph reports this Mac's memory, swap and disk, and coordinates memory between "
                                          "Claude sessions and other agents. Before memory-heavy work call "
                                          "reserve_memory with the work's estimated peak (reservation_history shows "
                                          "what similar work really needed); start only when granted. Shrink or "
                                          "extend it with update_reservation as the work changes, and "
                                          "release_memory when done. Call memory_check periodically and back off "
                                          "when it says tight or critical."}
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
                except LedgerError as e:  # busy, or refused: say so plainly
                    result = {"content": [{"type": "text", "text": "oomph: %s" % e}], "isError": True}
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
    try:
        return _main(argv)
    except LedgerError as e:  # the ledger is busy, or something planted in its directory was refused
        sys.stderr.write("oomph: %s\n" % e)
        return 75 if isinstance(e, LedgerBusy) else 1


def _main(argv):
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
    if c == "reserve":
        return cmd_reserve(rest)
    if c == "release":
        return cmd_release(rest)
    if c == "amend":
        return cmd_amend(rest)
    if c == "reservations":
        return cmd_reservations(rest)
    if c == "run":
        return cmd_run(rest)
    if c == "upgrade":
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import oomph_upgrade
        return oomph_upgrade.cmd_upgrade(rest)
    if c == "ai-check":
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import oomph_ai
        return oomph_ai.cmd_ai_check(rest)
    if c == "ai-report":
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        import oomph_ai
        return oomph_ai.cmd_ai_report(rest)
    if c == "hook":
        return cmd_hook(rest)
    if c == "mcp":
        return cmd_mcp()
    if c == "_ledger-refresh":
        return _cmd_ledger_refresh()
    if c == "_ledger-call":
        return _cmd_ledger_call(rest[0] if rest else "")
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
        print(json.dumps({"version": VERSION, "commit": COMMIT, "hardening": HARDENING}) if "--json" in rest
              else VERSION)
        return 0
    print(__doc__.strip())
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
