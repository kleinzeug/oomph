"""oomph AI report: a model investigates oomph's logs with read-only tools and writes an analysis.

    oomph ai-report [--provider claude|openai|ollama] [--model M] [--base-url URL]
                    [--last 24h] [-o FILE] [--open]

The access token comes from the environment (OOMPH_AI_TOKEN, or ANTHROPIC_API_KEY /
OPENAI_API_KEY), never from the command line, so it doesn't show up in `ps`. Progress is
printed as one JSON object per line ({"progress": ...}, then {"done": path} or
{"error": ...}) for the menu-bar app; the report is the normal HTML report with the
analysis on top. Standard library only, like the rest of oomph: the Claude, OpenAI and
Ollama APIs are called over plain HTTPS/HTTP.
"""
import datetime
import html
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

import oomph

MAX_ROUNDS = 12          # tool-calling rounds before the model must write
TOOL_OUT_CHARS = 14000   # cap on one tool result
DEFAULT_MODELS = {"claude": "claude-opus-5-5", "openai": "gpt-5-codex", "ollama": ""}
PROVIDER_NAMES = {"claude": "Claude", "openai": "OpenAI", "ollama": "Ollama"}


class AIError(Exception):
    pass


def emit(**kw):
    print(json.dumps(kw), flush=True)


# ------------------------------------------------------------------ time helpers
def _parse_t(v, default, now):
    """ISO time ('2026-11-19T03:40', local if no zone), or relative ('-90m', '-6h')."""
    if v in (None, ""):
        return default
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    m = re.fullmatch(r"-(\d+(?:\.\d+)?)([smhd])", s)
    if m:
        return now - float(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    try:
        return datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        raise AIError("can't read time %r — use ISO like 2026-11-19T03:40 or relative like -6h" % s)


def _hm(t):
    return datetime.datetime.fromtimestamp(t).strftime("%m-%d %H:%M")


def _iso(t):
    return datetime.datetime.fromtimestamp(t).astimezone().isoformat(timespec="seconds")


# ------------------------------------------------------------------ the tools
class Logs:
    """Read-only views of oomph's samples, events, incidents and ledger for one window."""

    def __init__(self, since, until):
        self.since, self.until = since, until
        self.now = time.time()
        self._cache = {}

    def samples(self, a, b):
        key = ("s", int(a), int(b))
        if key not in self._cache:
            self._cache[key] = oomph.load_samples(a, b)
        return self._cache[key]

    def window(self, args):
        a = _parse_t(args.get("since"), self.since, self.now)
        b = _parse_t(args.get("until"), self.until, self.now)
        if b <= a:
            raise AIError("'until' must be after 'since'")
        return a, b

    # --- tools
    def overview(self, args):
        a, b = self.window(args)
        s, e = self.samples(a, b), oomph.load_events(a, b)
        if not s:
            return {"window": [_iso(a), _iso(b)], "samples": 0, "note": "no samples in this window"}
        summ = oomph.summarize(s, e)
        for k in ("top_at_peak", "groups_at_peak"):
            summ[k] = summ.get(k, [])[:8]
        summ["group_risers"] = summ.get("group_risers", [])[:8]
        summ["process_risers"] = summ.get("process_risers", [])[:10]
        summ["gaps"] = [{"from": _hm(x["t"]), "to": _hm(y["t"]), "minutes": round((y["t"] - x["t"]) / 60)}
                        for x, y in zip(s, s[1:]) if y["t"] - x["t"] > oomph.NO_DATA_S][:10]
        return summ

    def timeline(self, args):
        a, b = self.window(args)
        step = max(1, int(args.get("step_minutes") or 10)) * 60
        s = self.samples(a, b)
        rows, bucket, key = [], [], None

        def flush():
            if not bucket:
                return
            w = max(bucket, key=lambda x: (x.get("pressure", 0), x.get("app_gb", 0) + x.get("compressed_gb", 0)))
            g = (w.get("groups") or [{}])[0]
            rows.append({"t": _hm(bucket[0]["t"]), "pressure": oomph.PRESSURE.get(w.get("pressure"), w.get("pressure")),
                         "app": w.get("app_gb"), "wired": w.get("wired_gb"), "compressed": w.get("compressed_gb"),
                         "compressor_logical": w.get("compressor_logical_gb"), "swap": w.get("swap_used_gb"),
                         "swap_size": w.get("swap_total_gb"), "free_disk": w.get("disk_free_gb"),
                         "unowned": oomph.unowned_gb(w), "kills": sum(x.get("jetsam_kills", 0) for x in bucket),
                         "away": any(oomph.is_away(x) for x in bucket), "stall_s": max(x.get("stall", 0) for x in bucket),
                         "top_app": "%s %.1fG" % (g.get("name", "?"), (g.get("mb") or 0) / 1024)})
        for x in s:
            k = int((x["t"] - a) // step)
            if k != key:
                flush()
                bucket, key = [], k
            bucket.append(x)
        flush()
        return {"step_minutes": step // 60, "rows": rows[:200], "note": "each row is the worst sample of its step"}

    def top_at(self, args):
        t = _parse_t(args.get("time"), self.until, self.now)
        s = self.samples(t - 900, t + 900) or self.samples(t - 7200, t + 7200)
        if not s:
            return {"note": "no sample near %s" % _iso(t)}
        x = min(s, key=lambda y: abs(y["t"] - t))
        return {"sample_at": x["iso"], "pressure": oomph.PRESSURE.get(x.get("pressure")),
                "top_processes": (x.get("top") or [])[:15], "top_apps": (x.get("groups") or [])[:10],
                "claude_sessions": x.get("claude") or [], "gone_since_previous": x.get("gone") or [],
                "unowned_gb": oomph.unowned_gb(x)}

    def process_history(self, args):
        a, b = self.window(args)
        name = (args.get("name") or "").lower()
        pid = args.get("pid")
        if not name and pid is None:
            raise AIError("give a process name (substring) or a pid")
        per = {}
        for x in self.samples(a, b):
            for p in x.get("top") or []:
                if (pid is not None and p["pid"] == int(pid)) or (name and name in p["name"].lower()):
                    d = per.setdefault(p["pid"], {"pid": p["pid"], "name": p["name"], "ppid": p.get("ppid"),
                                                  "parent": p.get("pn"), "app": p.get("g"), "session": p.get("s"),
                                                  "uid": p.get("uid"), "series": []})
                    d["series"].append((x["t"], p["mb"]))
        out = []
        for d in sorted(per.values(), key=lambda d: -max(m for _, m in d["series"])):
            ser = d.pop("series")
            peak = max(ser, key=lambda v: v[1])
            stride = max(1, len(ser) // 30)
            d.update(first_seen=_hm(ser[0][0]), last_seen=_hm(ser[-1][0]), first_mb=ser[0][1],
                     peak_mb=peak[1], peak_at=_hm(peak[0]), last_mb=ser[-1][1],
                     series=[[_hm(t), m] for t, m in ser[::stride]])
            out.append(d)
        return {"matches": len(out), "processes": out[:12],
                "note": "only processes among the 25 biggest of a sample are recorded"}

    def events(self, args):
        a, b = self.window(args)
        ev = oomph.collapse_pressure_events([e for e in oomph.load_events(a, b) if e.get("kind") != "notified"])
        kind, q = args.get("kind"), (args.get("contains") or "").lower()
        if kind:
            ev = [e for e in ev if e.get("kind") == kind]
        if q:
            ev = [e for e in ev if q in json.dumps(e).lower()]
        lim = min(int(args.get("limit") or 80), 300)
        counts = {}
        for e in ev:
            counts[e["kind"]] = counts.get(e["kind"], 0) + 1
        return {"count": len(ev), "by_kind": counts,
                "events": [dict({k: v for k, v in e.items() if k not in ("t",)}) for e in ev[-lim:]]}

    def incidents(self, args):
        out = []
        for i in oomph.list_incidents():
            s = i.get("summary") or {}
            out.append({"id": i["id"], "start": i.get("start_iso"), "end": i.get("end_iso"), "open": i.get("open"),
                        "reasons": [r.get("desc") for r in i.get("reasons", [])][:6],
                        "peak_pressure": s.get("peak_pressure"), "max_swap_used_gb": s.get("max_swap_used_gb"),
                        "min_disk_free_gb": s.get("min_disk_free_gb"), "jetsam_kills": s.get("jetsam_kills")})
        return {"incidents": out[-20:]}

    def incident(self, args):
        iid = args.get("id")
        inc = next((i for i in oomph.list_incidents() if i["id"] == iid), None)
        if not inc:
            raise AIError("no incident %r" % iid)
        inc = dict(inc)
        inc.pop("dir", None)
        return inc

    def syslog(self, args):
        iid = args.get("id")
        inc = next((i for i in oomph.list_incidents() if i["id"] == iid), None)
        if not inc:
            raise AIError("no incident %r" % iid)
        p = os.path.join(inc["dir"], "syslog.txt")
        if not os.path.exists(p):
            return {"note": "no syslog.txt for this incident"}
        lines = open(p, errors="replace").read().splitlines()
        killed = {}
        for ln in lines:
            m = re.search(r"\[[^\]]*?/([^\s/\]]+) \[\d+\]:\] exited .*OS_REASON_JETSAM", ln)
            if m:
                killed[m.group(1)] = killed.get(m.group(1), 0) + 1
        q = (args.get("contains") or "").lower()
        hits = [ln for ln in lines if q in ln.lower()] if q else lines
        lim = min(int(args.get("limit") or 40), 200)
        return {"lines": len(lines), "jetsam_exits": sum(killed.values()),
                "most_killed": dict(sorted(killed.items(), key=lambda kv: -kv[1])[:15]),
                "matching": len(hits), "sample": hits[:lim]}

    def current_status(self, args):
        v = oomph.checked_verdict()
        return {"verdict": v, "reservations": oomph.ledger_snapshot()}

    def claude_sessions(self, args):
        a, b = self.window(args)
        per = {}
        for x in self.samples(a, b):
            for c in x.get("claude") or []:
                d = per.setdefault(c["pid"], {"pid": c["pid"], "project": c.get("cwd"), "peak_mb": 0,
                                              "first_seen": _hm(x["t"]), "children": {}})
                d["last_seen"] = _hm(x["t"])
                if c["mb"] > d["peak_mb"]:
                    d["peak_mb"], d["peak_at"], d["procs_at_peak"] = c["mb"], _hm(x["t"]), c.get("n")
                bg = c.get("biggest")
                if bg:
                    d["children"][bg["name"]] = max(d["children"].get(bg["name"], 0), bg["mb"])
            for p in x.get("top") or []:
                if p.get("s") in per:
                    ch = per[p["s"]]["children"]
                    ch[p["name"]] = max(ch.get(p["name"], 0), p["mb"])
        out = sorted(per.values(), key=lambda d: -d["peak_mb"])
        for d in out:
            d["biggest_children_mb"] = dict(sorted(d.pop("children").items(), key=lambda kv: -kv[1])[:8])
        return {"sessions": out[:15]}


TOOLS = [
    ("overview", "Summary of a time window: peak pressure, swap, free disk, jetsam kills, unowned memory "
                 "(memory no process owns — a leak sign), away share, onset, biggest risers, gaps without data.",
     {"since": "str", "until": "str"}),
    ("timeline", "Memory over time in steps (worst sample per step): pressure, app/wired/compressed GB, "
                 "compressor logical size, swap, free disk, unowned GB, kills, away, stalls, top app.",
     {"since": "str", "until": "str", "step_minutes": "int"}),
    ("top_at", "Biggest processes, apps and Claude sessions at the sample nearest a time, plus processes "
               "≥300 MB that had just disappeared.", {"time": "str"}),
    ("process_history", "Footprint over time of processes matching a name substring or a pid: parent, app, "
                        "Claude session, first/peak/last MB, series.",
     {"name": "str", "pid": "int", "since": "str", "until": "str"}),
    ("events", "Logged events (pressure changes, flapping, jetsam kills, stalls, sleep gaps, unowned memory, "
               "incidents, daemon restarts), optionally filtered by kind or text.",
     {"since": "str", "until": "str", "kind": "str", "contains": "str", "limit": "int"}),
    ("incidents", "All recorded incidents with their triggers and summary numbers.", {}),
    ("incident", "One incident's full record (triggers, summary, top processes at peak).", {"id": "str"}),
    ("syslog", "The system-log excerpt saved when an incident opened: jetsam exits per service, matching lines.",
     {"id": "str", "contains": "str", "limit": "int"}),
    ("current_status", "Memory right now: oomph's verdict (ok/tight/critical with reasons) and reservations.", {}),
    ("claude_sessions", "Claude Code sessions seen in a window: project, peak memory, biggest child processes.",
     {"since": "str", "until": "str"}),
]
ARG_DOC = {"since": "start, ISO local time (2026-11-19T03:40) or relative (-6h); default: report start",
           "until": "end, ISO or relative; default: report end", "step_minutes": "step size, default 10",
           "time": "ISO local time or relative", "name": "case-insensitive substring of the process name",
           "pid": "process id", "kind": "event kind, e.g. jetsam, stall, pressure_flapping, incident_open",
           "contains": "text to search for", "limit": "max rows", "id": "incident id like 20261119-035310"}


def tool_schema(params):
    props = {k: {"type": "integer" if t == "int" else "string", "description": ARG_DOC[k]} for k, t in params.items()}
    req = ["id"] if "id" in params else []
    return {"type": "object", "properties": props, "required": req}


def describe(name, args):
    a = args or {}
    span = ""
    if a.get("since") or a.get("until"):
        span = " %s–%s" % (str(a.get("since") or "start")[-8:], str(a.get("until") or "end")[-8:])
    return {"overview": "Summarizing" + (span or " the window"),
            "timeline": "Reading the timeline" + span,
            "top_at": "Looking at the biggest processes at %s" % str(a.get("time", "the end"))[-8:],
            "process_history": "Tracing %s" % (a.get("name") or "pid %s" % a.get("pid")),
            "events": "Reading events" + (" (%s)" % a["kind"] if a.get("kind") else "") + span,
            "incidents": "Listing incidents", "incident": "Reading incident %s" % a.get("id"),
            "syslog": "Reading the system log of %s" % a.get("id"),
            "current_status": "Checking memory right now",
            "claude_sessions": "Looking at Claude sessions" + span}.get(name, name)


def run_tool(logs, name, args):
    fn = getattr(logs, name, None) if name in {t[0] for t in TOOLS} else None
    if not fn:
        return json.dumps({"error": "unknown tool %s" % name}), True
    try:
        out = json.dumps(fn(args or {}), default=str, separators=(",", ":"))
    except AIError as e:
        return json.dumps({"error": str(e)}), True
    except Exception as e:  # a bad argument must not end the investigation
        return json.dumps({"error": "%s: %s" % (type(e).__name__, e)}), True
    if len(out) > TOOL_OUT_CHARS:
        out = out[:TOOL_OUT_CHARS] + '... [truncated — narrow the window or filter]'
    return out, False


# ------------------------------------------------------------------ prompts
SYSTEM = """You are a memory forensics analyst for a Mac. oomph, a memory monitor, has logged this Mac's \
memory every 5–30 seconds (pressure level, app/wired/compressed memory, the compressor's logical size, swap, free \
disk, the 25 biggest processes with parent, app and Claude Code session, jetsam kills, away state) plus events and \
incidents. Investigate the report window with the tools and explain to the Mac's owner what went on with memory.

How macOS memory works, briefly: app memory is compressed before it is swapped; swap lives on the startup disk and \
can only grow while there is free disk; macOS pressure goes normal -> WARN -> CRITICAL; under shortage jetsam kills \
processes. A footprint counts a process's compressed and swapped pages at full size. "Unowned memory" is app memory \
plus the compressor's logical size minus all footprints: normally a few GB; a large, lasting value is memory held \
outside every process (e.g. a GPU or driver leak) that only a restart frees. Gaps without samples mean the Mac \
slept, froze, or the logger was down; "stall" events mean the Mac was awake but too starved to run the logger.

Work like an investigator: start from the briefing, form hypotheses, then check them with the tools (timeline \
around the critical stretch, the processes that rose, their parents and Claude sessions, events, incident syslog). \
Prefer a few targeted calls over many broad ones. Quote concrete times, process names, pids and numbers. Separate \
what the data shows from what you infer, and say what the data can't tell. If nothing notable happened, say so \
briefly instead of inventing a problem.

Write the final report in Markdown with exactly these sections:
## Verdict
(2–3 sentences: what happened and how serious it was)
## Timeline
(a short bulleted timeline with times)
## Root cause
## Evidence
(bullets with the numbers that support it)
## Who was involved
(apps, processes, Claude sessions/projects)
## Risk right now
## Recommendations
(concrete, specific to the processes and projects found; most important first)

Keep it under about 900 words. Use local times as HH:MM (with the date when it spans days)."""


def briefing(logs):
    ov = logs.overview({})
    incs = [i for i in logs.incidents({})["incidents"]
            if (i.get("end") or "9") >= _iso(logs.since)[:19] and (i.get("start") or "") <= _iso(logs.until)]
    ev = logs.events({"limit": 0})
    return ("Report window: %s to %s (local time; the Mac's clock says now is %s).\n\n"
            "Overview of the window:\n%s\n\nIncidents in or overlapping the window:\n%s\n\n"
            "Event counts by kind: %s\n\nInvestigate, then write the report."
            % (_iso(logs.since), _iso(logs.until), _iso(logs.now),
               json.dumps(ov, default=str), json.dumps(incs, default=str), json.dumps(ev["by_kind"])))


FINAL_NUDGE = "Tool budget used up. Write the final report now from what you have found."


# ------------------------------------------------------------------ HTTP
def http_json(url, body, headers, timeout=600, method="POST"):
    data = json.dumps(body).encode() if body is not None else None
    h = {"content-type": "application/json", "user-agent": "oomph/%s" % oomph.VERSION}
    h.update(headers)
    for attempt in range(4):
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
            retry = e.code in (408, 409, 429, 500, 502, 503, 504, 529)
            if retry and attempt < 3:
                wait = float(e.headers.get("retry-after") or (2 ** attempt * 3))
                emit(progress="Provider busy (%d), retrying in %ds" % (e.code, wait))
                time.sleep(min(wait, 60))
                continue
            try:
                j = json.loads(raw)
                msg = (j.get("error") or {}).get("message") if isinstance(j.get("error"), dict) else j.get("error")
            except ValueError:
                msg = None
            raise AIError("%s returned %d: %s" % (url.split("/")[2], e.code, (msg or raw or e.reason)[:400]))
        except urllib.error.URLError as e:
            if attempt < 2:
                time.sleep(3)
                continue
            raise AIError("can't reach %s: %s" % (url.split("/")[2], e.reason))
    raise AIError("no response from %s" % url)


# ------------------------------------------------------------------ providers
class Claude:
    """Messages API with client tools. The full assistant content (thinking blocks included) is
    sent back unchanged every turn; the final turn uses tool_choice none."""
    URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, token, model, base_url=None):
        if not token:
            raise AIError("no Claude API key")
        self.model = model or DEFAULT_MODELS["claude"]
        self.url = (base_url.rstrip("/") + "/v1/messages") if base_url else self.URL
        betas = ["server-side-fallback-2026-07-01"]  # on a refusal, re-run on a fallback model
        self.headers = {"anthropic-version": "2026-10-21"}
        if token.startswith("sk-ant-oat"):  # OAuth access token
            self.headers["authorization"] = "Bearer " + token
            betas.append("oauth-2025-04-20")
        else:
            self.headers["x-api-key"] = token
        self.headers["anthropic-beta"] = ",".join(betas)
        self.tools = [{"name": n, "description": d, "input_schema": tool_schema(p)} for n, d, p in TOOLS]
        self.messages = []

    def start(self, system, user):
        self.system = system
        self.messages = [{"role": "user", "content": user}]

    def turn(self, final=False):
        body = {"model": self.model, "max_tokens": 16000, "system": self.system, "messages": self.messages,
                "tools": self.tools, "tool_choice": {"type": "none" if final else "auto"},
                "thinking": {"type": "adaptive"}, "output_config": {"effort": "high"}, "fallbacks": "default"}
        r = http_json(self.url, body, self.headers)
        if r.get("stop_reason") == "refusal":
            d = r.get("stop_details") or {}
            raise AIError("Claude declined (%s)" % (d.get("category") or d.get("explanation") or "refusal"))
        content = r.get("content") or []
        self.messages.append({"role": "assistant", "content": content})
        calls = [(b["id"], b["name"], b.get("input") or {}) for b in content if b.get("type") == "tool_use"]
        text = "\n".join(b.get("text", "") for b in content if b.get("type") == "text").strip()
        if r.get("stop_reason") == "max_tokens" and not calls:
            text += "\n\n*(The model ran out of output tokens here.)*"
        return text, calls

    def results(self, outs, nudge=None):
        blocks = [{"type": "tool_result", "tool_use_id": cid, "content": out, "is_error": err} for cid, out, err in outs]
        if nudge:
            blocks.append({"type": "text", "text": nudge})
        self.messages.append({"role": "user", "content": blocks})


class OpenAI:
    """Responses API with function tools, chained by previous_response_id."""
    URL = "https://api.openai.com/v1/responses"

    def __init__(self, token, model, base_url=None):
        if not token:
            raise AIError("no OpenAI API key")
        self.model = model or DEFAULT_MODELS["openai"]
        self.url = (base_url.rstrip("/") + "/responses") if base_url else self.URL
        self.headers = {"authorization": "Bearer " + token}
        self.tools = [{"type": "function", "name": n, "description": d, "parameters": tool_schema(p)} for n, d, p in TOOLS]
        self.prev, self.pending = None, None

    def start(self, system, user):
        self.system = system
        self.pending = [{"role": "user", "content": user}]

    def turn(self, final=False):
        body = {"model": self.model, "instructions": self.system, "input": self.pending, "tools": self.tools,
                "tool_choice": "none" if final else "auto"}
        if self.prev:
            body["previous_response_id"] = self.prev
        r = http_json(self.url, body, self.headers)
        self.prev = r.get("id")
        calls, texts = [], []
        for item in r.get("output") or []:
            if item.get("type") == "function_call":
                try:
                    args = json.loads(item.get("arguments") or "{}")
                except ValueError:
                    args = {}
                calls.append((item.get("call_id"), item.get("name"), args))
            elif item.get("type") == "message":
                texts += [c.get("text", "") for c in item.get("content") or [] if c.get("type") in ("output_text", "text")]
        return "\n".join(texts).strip(), calls

    def results(self, outs, nudge=None):
        self.pending = [{"type": "function_call_output", "call_id": cid, "output": out} for cid, out, _ in outs]
        if nudge:
            self.pending.append({"role": "user", "content": nudge})


class Ollama:
    """Local /api/chat with tools; models without tool support get one pass with a fuller briefing."""

    def __init__(self, token, model, base_url=None):
        self.base = (base_url or "http://localhost:11434").rstrip("/")
        self.headers = {"authorization": "Bearer " + token} if token else {}
        if not model:
            tags = http_json(self.base + "/api/tags", None, self.headers, timeout=10, method="GET")
            names = [m.get("name") for m in tags.get("models") or []]
            if not names:
                raise AIError("Ollama at %s has no models — pull one first (ollama pull qwen3)" % self.base)
            model = names[0]
        self.model = model
        self.tools = [{"type": "function", "function": {"name": n, "description": d, "parameters": tool_schema(p)}}
                      for n, d, p in TOOLS]
        self.use_tools = True

    def start(self, system, user):
        self.messages = [{"role": "system", "content": system}, {"role": "user", "content": user}]

    def turn(self, final=False):
        body = {"model": self.model, "messages": self.messages, "stream": False, "options": {"num_ctx": 32768}}
        if self.use_tools and not final:
            body["tools"] = self.tools
        try:
            r = http_json(self.base + "/api/chat", body, self.headers, timeout=900)
        except AIError as e:
            if self.use_tools and "tool" in str(e).lower():
                self.use_tools = False  # this model can't call tools: answer from the briefing
                emit(progress="%s can't use tools — analysing the briefing only" % self.model)
                return self.turn(final=True)
            raise
        msg = r.get("message") or {}
        self.messages.append(msg)
        calls = [(str(i), c["function"]["name"], c["function"].get("arguments") or {})
                 for i, c in enumerate(msg.get("tool_calls") or [])]
        return (msg.get("content") or "").strip(), calls

    def results(self, outs, nudge=None):
        for cid, out, _ in outs:
            self.messages.append({"role": "tool", "content": out, "tool_name": self._names.get(cid, "")})
        if nudge:
            self.messages.append({"role": "user", "content": nudge})

    _names = {}


PROVIDERS = {"claude": Claude, "openai": OpenAI, "ollama": Ollama}


# ------------------------------------------------------------------ the loop
def investigate(provider, logs):
    """Run the tool loop; returns (markdown, [(tool, args)])."""
    provider.start(SYSTEM, briefing(logs))
    log, text = [], ""
    for rnd in range(MAX_ROUNDS + 1):
        final = rnd == MAX_ROUNDS
        emit(progress=("Writing the report" if final else
                       "Asking %s (step %d)" % (getattr(provider, "model", "the model"), rnd + 1)), step=rnd + 1)
        text, calls = provider.turn(final=final)
        if not calls:
            break
        outs = []
        if isinstance(provider, Ollama):
            provider._names = {cid: name for cid, name, _ in calls}
        for cid, name, args in calls:
            emit(progress=describe(name, args), step=rnd + 1, tool=name)
            out, err = run_tool(logs, name, args)
            log.append((name, args))
            outs.append((cid, out, err))
        provider.results(outs, FINAL_NUDGE if rnd == MAX_ROUNDS - 1 else None)
    if not text:
        raise AIError("the model returned no report")
    return text, log


# ------------------------------------------------------------------ Markdown -> HTML
def _inline(s):
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
    s = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<em>\1</em>", s)
    return s


def md_to_html(md):
    out, para, lst, code, table = [], [], None, None, []

    def flush_para():
        if para:
            out.append("<p>%s</p>" % _inline(" ".join(para)))
            para.clear()

    def flush_list():
        nonlocal lst
        if lst:
            out.append("<%s>%s</%s>" % (lst[0], "".join("<li>%s</li>" % _inline(i) for i in lst[1]), lst[0]))
            lst = None

    def flush_table():
        if table:
            rows = [r for r in table if not re.fullmatch(r"\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?", r)]
            cells = [[c.strip() for c in r.strip().strip("|").split("|")] for r in rows]
            if cells:
                h = "".join("<th>%s</th>" % _inline(c) for c in cells[0])
                b = "".join("<tr>%s</tr>" % "".join("<td>%s</td>" % _inline(c) for c in r) for r in cells[1:])
                out.append("<div class=scroll><table><tr>%s</tr>%s</table></div>" % (h, b))
            table.clear()
    for line in md.splitlines():
        if code is not None:
            if line.strip().startswith("```"):
                out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(code)))
                code = None
            else:
                code.append(line)
            continue
        st = line.strip()
        if st.startswith("```"):
            flush_para(), flush_list(), flush_table()
            code = []
            continue
        if st.startswith("|"):
            flush_para(), flush_list()
            table.append(st)
            continue
        flush_table()
        m = re.match(r"(#{1,4})\s+(.*)", st)
        if m:
            flush_para(), flush_list()
            lvl = min(len(m.group(1)) + 1, 4)
            out.append("<h%d>%s</h%d>" % (lvl, _inline(m.group(2)), lvl))
            continue
        m = re.match(r"([-*+]|\d+[.)])\s+(.*)", st)
        if m:
            flush_para()
            kind = "ol" if m.group(1)[0].isdigit() else "ul"
            if not lst or lst[0] != kind:
                flush_list()
                lst = (kind, [])
            lst[1].append(m.group(2))
            continue
        if not st:
            flush_para(), flush_list()
            continue
        if lst and line.startswith("  "):
            lst[1][-1] += " " + st
            continue
        flush_list()
        para.append(st)
    if code is not None:
        out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(code)))
    flush_para(), flush_list(), flush_table()
    return "\n".join(out)


def ai_section(md, provider_key, model, log, seconds):
    steps = "".join("<li><code>%s(%s)</code></li>" % (html.escape(n), html.escape(
        ", ".join("%s=%s" % (k, json.dumps(v)) for k, v in (a or {}).items()))) for n, a in log)
    return ('<section class="card ai"><div class=ai-head><span class=ai-star>✦</span> AI analysis'
            '<span class=ai-meta>%s · %s · %d tool calls · %ds</span></div>%s'
            '<details><summary>How it was investigated</summary><ol>%s</ol>'
            '<p class=sub>Written by a language model from oomph\'s logs; check it against the charts and '
            'tables below.</p></details></section>'
            % (PROVIDER_NAMES.get(provider_key, provider_key), html.escape(model), len(log), seconds,
               md_to_html(md), steps))


AI_CSS = """
.ai{border-color:transparent;background:linear-gradient(var(--card),var(--card)) padding-box,
linear-gradient(135deg,#8b5cf6,#3b82f6 55%,#06b6d4) border-box;border:1.5px solid transparent;padding:16px 20px;margin:14px 0 18px}
.ai-head{font-weight:600;font-size:15px;display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}
.ai-star{background:linear-gradient(135deg,#8b5cf6,#3b82f6);-webkit-background-clip:text;background-clip:text;color:transparent}
.ai-meta{color:var(--muted);font-weight:400;font-size:12px;margin-left:auto}
.ai h2{font-size:15px;margin:18px 0 6px}.ai h3,.ai h4{font-size:14px;margin:14px 0 4px}
.ai p,.ai li{line-height:1.55}.ai ul,.ai ol{padding-left:22px;margin:6px 0}.ai li{margin:2px 0}
.ai pre{background:var(--seg);padding:8px 10px;border-radius:6px;overflow-x:auto}
.ai details{margin-top:14px;font-size:12px;color:var(--muted)}.ai details code{font-size:11.5px}
"""


# ------------------------------------------------------------------ CLI
def _opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


def cmd_ai_report(args):
    pk = (_opt(args, "--provider") or "claude").lower()
    if pk not in PROVIDERS:
        emit(error="unknown provider %s (claude, openai or ollama)" % pk)
        return 2
    token = os.environ.get("OOMPH_AI_TOKEN") or os.environ.get(
        {"claude": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY", "ollama": "OLLAMA_API_KEY"}[pk]) or ""
    since, until = oomph.window(args, "24h")
    out = _opt(args, "-o") or os.path.join(os.environ.get("TMPDIR", "/tmp"), "oomph-ai-report.html")
    t0 = time.time()
    try:
        emit(progress="Reading %s of logs" % oomph._dur_label(until - since))
        logs = Logs(since, until)
        samples, events = logs.samples(since, until), oomph.load_events(since, until)
        if not samples:
            raise AIError("no samples in the last %s — is the logger running?" % oomph._dur_label(until - since))
        prov = PROVIDERS[pk](token, _opt(args, "--model"), _opt(args, "--base-url"))
        md, log = investigate(prov, logs)
        emit(progress="Building the report")
        sec = ai_section(md, pk, prov.model, log, round(time.time() - t0))
        page = oomph.render_html(samples, events, "Memory report", extra_css=AI_CSS, intro_html=sec)
        with open(out, "w") as f:
            f.write(page)
    except AIError as e:
        emit(error=str(e))
        return 3
    except KeyboardInterrupt:
        emit(error="aborted")
        return 130
    emit(done=out, seconds=round(time.time() - t0), tool_calls=len(log))
    if "--open" in args:
        subprocess.run(["/usr/bin/open", out])
    return 0


if __name__ == "__main__":
    sys.exit(cmd_ai_report(sys.argv[1:]))
