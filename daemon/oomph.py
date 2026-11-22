#!/usr/bin/python3 -I
"""oomph — inspect the memory papertrail written by oomphd.

  oomph status
  oomph report [--last 2h | --since ISO [--until ISO]]
  oomph top [--span inf|24h|6h|1h] [--glyphs unicode|cells|ascii] [--bell]
                                     the popup's dashboard, full screen (? lists its keys)
  oomph top --ssh [USER@]HOST       the same on another Mac, over ssh
  oomph top --once [--size 80x24]   one frame of it, as text
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
  oomph check [--json] [--measure]  verdict ok / tight / critical + advice; exit 0 / 1 / 2; a line per resource
                                    (--measure: without the logger, read CPU and GPU for a quarter second)
  oomph resources [--json]          this machine's memory, cores, GPU and disks; which can be reserved here
  oomph ps [--cpu | --gpu | --io | --memory] [-n 10] [--json]   the biggest consumers of one resource now
  oomph volumes [--all] [--json]    the disks the logger records (--all: also those it ignores, and why)
  oomph volumes watch|unwatch|hide|unhide PATH   pin a listed disk: its free space counts in your checks
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
  oomph doctor [--json]             what works on this machine and what to fix; exit 0 fine, 1 something to
                                    fix, 2 it cannot work here

another machine (over a pipe for now; the network comes later):
  oomph serve --stdio               answer for this machine on stdin/stdout, read only (what the
                                    other end runs, e.g. through ssh)
  oomph remote sync --once [--into DIR] [-- COMMAND…]   mirror the machine whose `serve --stdio`
                                    COMMAND starts (default: this one) into a directory of logs
"""
import datetime
import functools
import glob
import gzip
import heapq
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
BRAND = "oomph"  # the product's name in prose and titles: one edit renames it (tools/brandlint.py)
CMD = "oomph"    # the command, its message prefix and every identifier: never changes
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


def usage(doc):
    """A module's help as printed. The first `oomph` of its first line is the product's name, so
    it says BRAND (a docstring cannot interpolate); the commands below it stay `oomph`."""
    first, _, rest = doc.strip().partition("\n")
    return re.sub(r"\boomph\b", lambda m: BRAND, first, count=1) + ("\n" + rest if rest else "")


# Where things live, per system: one table instead of constants scattered over the modules.
# OOMPH_DIR, OOMPH_LEDGER_DIR and OOMPH_STATE_DIR still win. Reading it imports no backend, so
# the hook and the readers never load the code that measures. On Linux the ledger is per user
# (and per machine, for a home folder shared between machines) until a logger there keeps one
# for everybody (roadmap 03 §8.1); `ledger_mode` is what a new ledger folder is created with.
PATHS = {
    "darwin": {"log": "/Library/Logs/oomph",
               "ledger": "/Users/Shared/oomph", "ledger_mode": 0o777,
               "state": "~/Library/Application Support/oomph",
               "config": "/Library/Application Support/oomph/config.json",
               "libexec": "/usr/local/libexec/oomph", "service": "/Library/LaunchDaemons/local.oomph.daemon.plist"},
    "linux": {"log": "/var/log/oomph",
              "ledger": "{state}/ledger/{machine}", "ledger_mode": 0o700,
              "state": "{xdg_state}/oomph",
              "config": "/etc/oomph/config.json",
              "libexec": "/usr/local/libexec/oomph", "service": "/etc/systemd/system/oomphd.service"},
}
PATHS_HERE = PATHS["darwin" if sys.platform == "darwin" else "linux"]


def _linux_machine():
    """This machine's id for a per-user ledger's folder name: hashed like machine.id (roadmap
    01 §4.5), from /etc/machine-id or D-Bus's copy; "local" where neither exists."""
    import hashlib
    for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            with open(f) as h:
                v = h.read(64).strip()
        except OSError:
            continue
        if re.fullmatch(r"[0-9a-f]{32}", v):
            return "m-" + hashlib.sha256(("oomph-machine-v1:" + v).encode()).hexdigest()[:16]
    return "local"


def _path(kind):
    """A path of the table above, expanded: ~, the XDG state folder, {state} and {machine}."""
    v = PATHS_HERE[kind]
    if "{xdg_state}" in v:
        x = os.environ.get("XDG_STATE_HOME") or ""
        v = v.replace("{xdg_state}", x if os.path.isabs(x) else "~/.local/state")  # relative: ignored, as XDG says
    if "{state}" in v:
        v = v.replace("{state}", STATE_DIR)
    if "{machine}" in v:
        v = v.replace("{machine}", _linux_machine())
    return os.path.expanduser(v)


STATE_DIR = os.environ.get("OOMPH_STATE_DIR") or _path("state")
LOG_DIR = os.environ.get("OOMPH_DIR", PATHS_HERE["log"])

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


# What an incident is headlined by: its highest-ranked reason, ties to the earlier one. The
# logger keeps `reasons` in this order, so reasons[0] is the headline for every reader;
# incidents written before 1.8.6 keep arrival order and are shown as they are.
REASON_RANK = {"jetsam_report": 90, "dialog": 85, "lowmem": 80, "jetsam_storm": 70,
               "unowned": 60, "stall": 50, "pressure": 40}
ESCALATE_RANK = 80  # a reason this severe that takes over the headline is announced once more


def reason_rank(r):
    return REASON_RANK.get(r.get("kind"), 0)


def sort_reasons(reasons):
    return sorted(reasons, key=lambda r: (-reason_rank(r), r.get("t", 0)))


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


def _samples_in(path, since, until):
    for line in _read_lines(path):
        try:
            s = json.loads(line)
        except ValueError:
            continue
        if since <= s.get("t", 0) <= until:
            yield s


def iter_samples(since, until):
    """load_samples one sample at a time, for readers that must not hold a day of samples
    (the logger writing a report). The logger appends each file in time order, so merging
    the files gives load_samples' order without sorting them all. Only a wall clock set
    back makes a file go back in time; its samples then come in the order they were
    written, which moves a summary's from/to and a chart point or two, nothing more."""
    paths = [p for day in _day_range(since, until)
             for p in (os.path.join(LOG_DIR, "samples-%s.jsonl.gz" % day), os.path.join(LOG_DIR, "samples-%s.jsonl" % day))
             if os.path.exists(p)]
    return heapq.merge(*[_samples_in(p, since, until) for p in paths], key=lambda s: s["t"])


class SampleWindow:
    """The samples of a window, read from the files again on every iteration: what the
    report code takes instead of a list when a window may be a day or more."""

    def __init__(self, since, until):
        self.since, self.until = since, until

    def __iter__(self):
        return iter_samples(self.since, self.until)


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


# ----- what of a sample leaves the machine (roadmap 01 §4.2, §5)
# Every key a sampler writes, classified once: "keep" travels in slim samples (the history another
# machine mirrors), "drop" stays home (per-process lists: big, and named by local users), "full"
# exists in current.json only. The self-test fails on a key that is not here, so a new block cannot
# silently miss the wire or ride along unchecked.
SAMPLE_KEYS = dict(
    [(k, "keep") for k in ("t", "iso", "hot", "gap", "stall", "os", "pressure", "free_pct", "ram_gb", "app_gb",
                           "wired_gb", "compressed_gb", "compressor_logical_gb", "cached_gb", "free_gb",
                           "swap_total_gb", "swap_used_gb", "swapfiles", "swapins", "swapouts", "disk_free_gb",
                           "procs_gb", "unowned_gb", "jetsam_kills", "away", "incident", "cpu", "gpu", "io")]
    + [(k, "drop") for k in ("top", "groups", "claude", "gone", "leases", "top_cpu", "top_gpu", "top_io", "disks")]
    + [("daemon", "full")])
SLIM_STR = 64        # characters of a string in a slim sample
AWAY_KEYS = ("idle_s", "display_on", "locked", "sleep_preventers")
# The blocks of 1.9.1 travel in slim samples with the numbers a chart of another machine needs (roadmap
# 02 §8, about 60 bytes a GPU more), lists capped: {key: (cap or None for an object, fields)}.
# `disks` stays home for now: every mirror up to 1.9.1 refuses a whole row with a *_gb above 16 times
# the machine's RAM (oomph_sync.gb_ok), and a disk is bigger than that on most Macs. It travels once
# the mirrors in use bound a disk's size apart (gb_ok does from 1.9.1), with the remote protocol's next step.
SLIM_BLOCKS = {"cpu": (None, ("n", "p", "e", "busy", "user", "sys", "p_busy", "e_busy", "therm")),
               "io": (None, ("r_mb_s", "w_mb_s")),
               "gpu": (4, ("id", "util", "active", "now", "src", "mem_gb", "mem_alloc_gb"))}
# ... and in the full current sample with what names and describes them
FULL_BLOCKS = {"gpu": (4, SLIM_BLOCKS["gpu"][1] + ("name", "unified", "mem_limit_gb", "mem_limit_est"))}
# The full current sample is rebuilt from these fields only, each list capped (CONTEXT §3.2).
FULL_LISTS = {"top": (25, ("pid", "ppid", "name", "uid", "mb", "rss_mb", "g", "pn", "s", "cpu", "gpu", "w")),
              "groups": (15, ("name", "mb", "n", "cpu", "gpu")),
              "claude": (64, ("pid", "cwd", "mb", "own_mb", "n", "biggest", "cpu", "gpu", "w")),
              "gone": (64, ("pid", "name", "mb")),
              "leases": (64, ("id", "state", "gb", "purpose", "project", "used_gb", "for_min", "expires_in_min",
                              "waiting_min")),
              "top_cpu": (8, ("pid", "name", "g", "s", "cpu")),
              "top_gpu": (5, ("pid", "name", "g", "s", "gpu")),
              "top_io": (5, ("pid", "name", "g", "s", "w"))}
FULL_DAEMON = ("pid", "version", "started", "interval", "incident", "root")
FULL_MACHINE = ("id", "name", "os", "arch", "os_version", "kernel", "kind", "cpus", "virt")


def _scalar(v, cut):
    """v if it is a scalar oomph could have written (a finite number, a bool, None, a string cut to
    `cut` characters), else the marker _NOT."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v if _num(v, -1e18, 1e18) else _NOT
    if isinstance(v, str):
        return v[:cut]
    return _NOT


_NOT = object()


def _fields(src, keys, cut, nested=None):
    """The named fields of a dict that are scalars (or, for the names in `nested`, a dict of
    scalars; `roles` may be a short list of strings), nothing else."""
    out = {}
    if not isinstance(src, dict):
        return out
    for k in keys:
        if k not in src:
            continue
        v = src[k]
        if nested and k in nested:
            if isinstance(v, dict):
                out[k] = _fields(v, nested[k], cut)
            continue
        if k == "roles":
            if isinstance(v, list):
                out[k] = [x[:cut] for x in v[:8] if isinstance(x, str)]
            continue
        v = _scalar(v, cut)
        if v is not _NOT:
            out[k] = v
    return out


def _block(v, cap, keys, cut):
    """A block of SLIM_BLOCKS or FULL_BLOCKS rebuilt from its named scalar fields (a list: of its
    first `cap` objects), or _NOT."""
    if cap is None:
        return _fields(v, keys, cut) if isinstance(v, dict) else _NOT
    return [_fields(x, keys, cut) for x in v[:cap] if isinstance(x, dict)] if isinstance(v, list) else _NOT


def slim_sample(s):
    """What of a sample goes on the wire as history: its top-level scalars (finite numbers, bools,
    strings cut to SLIM_STR), the four known fields of `away` and the chart's numbers of the blocks
    in SLIM_BLOCKS; every other list and object stays home. Keys SAMPLE_KEYS drops never travel; a
    scalar key it does not know yet does (a newer logger's series reach an older protocol)."""
    out = {}
    for k, v in s.items():
        if not isinstance(k, str) or SAMPLE_KEYS.get(k, "keep") != "keep" or len(k) > SLIM_STR:
            continue
        if k in SLIM_BLOCKS:
            v = _block(v, SLIM_BLOCKS[k][0], SLIM_BLOCKS[k][1], SLIM_STR)
            if v is not _NOT:
                out[k] = v
            continue
        if k == "away":
            if isinstance(v, dict):
                a = _fields(v, AWAY_KEYS[:3], SLIM_STR)
                sp = v.get("sleep_preventers")
                if isinstance(sp, list):
                    a["sleep_preventers"] = [x[:SLIM_STR] for x in sp[:16] if isinstance(x, str)]
                out[k] = a
            continue
        v = _scalar(v, SLIM_STR)
        if v is not _NOT:
            out[k] = v
    return out


def full_sample(s):
    """The latest sample as it may leave the machine whole (current.json, for the stat tiles):
    what slim_sample keeps, plus the GPU block with its names, the per-process lists
    and the daemon block rebuilt from the fields of FULL_BLOCKS, FULL_LISTS, FULL_DAEMON and
    FULL_MACHINE with their types, strings cut to
    LIMITS["str"] characters, lists to their caps."""
    out = slim_sample(s)
    n = LIMITS["str"]
    for k, (cap, keys) in FULL_BLOCKS.items():
        v = _block(s.get(k), cap, keys, n)
        if v is not _NOT:
            out[k] = v
    for k, (cap, keys) in FULL_LISTS.items():
        if isinstance(s.get(k), list):
            out[k] = [_fields(x, keys, n, {"biggest": ("name", "pid", "mb")}) for x in s[k][:cap] if isinstance(x, dict)]
    d = s.get("daemon")
    if isinstance(d, dict):
        out["daemon"] = _fields(d, FULL_DAEMON, n)
        m = d.get("machine")
        if isinstance(m, dict):
            mm = _fields(m, FULL_MACHINE, n)
            if isinstance(m.get("measures"), dict):
                mm["measures"] = {k[:SLIM_STR]: _scalar(v, SLIM_STR) for k, v in list(m["measures"].items())[:32]
                                  if isinstance(k, str) and _scalar(v, SLIM_STR) is not _NOT}
            out["daemon"]["machine"] = mm
    return out


# ---------------------------------------------------------------- summarize
class _Risers:
    """First, peak (and when) and last size per app group or process, folded one sample at
    a time: the state grows with the names seen, not with the samples."""

    def __init__(self, key):
        self.key, self.rows = key, {}

    def add(self, s):
        groups = self.key == "groups"
        for p in s.get(self.key) or []:
            k = p["name"] if groups else "%s [%s]" % (p["name"], p["pid"])
            r = self.rows.get(k)
            if r is None:
                r = self.rows[k] = [p["mb"], -1, None, None, None]  # first, peak, peak t, last, process
            r[3] = p["mb"]
            if not groups:
                r[4] = (p["pid"], p["name"], p.get("ppid"), p.get("uid"))
            if p["mb"] > r[1]:
                r[1], r[2] = p["mb"], s["t"]

    def result(self, limit=10):
        rows = []
        for k, (first, peak, peak_t, last, proc) in self.rows.items():
            if peak_t is None:
                continue
            r = {"name": k, "first_mb": first, "peak_mb": peak, "last_mb": last,
                 "rise_mb": peak - first, "peak_iso": _hm(peak_t)}
            if proc:
                r.update(pid=proc[0], proc=proc[1], ppid=proc[2], uid=proc[3])
            rows.append(r)
        rows.sort(key=lambda r: (r["rise_mb"], r["peak_mb"]), reverse=True)
        return rows[:limit] if limit else rows


def _risers(samples, key, limit=10):
    f = _Risers(key)
    for s in samples:
        f.add(s)
    return f.result(limit)


def _hm(t):
    return datetime.datetime.fromtimestamp(t).strftime("%H:%M:%S")


def _more(a, b):
    """max() as a fold: the first of equal values wins, as with max() over a list."""
    return b if a is None or b > a else a


def _less(a, b):
    return b if a is None or b < a else a


def _peak_key(s):
    return (s.get("pressure", 0), s.get("swap_used_gb", 0), s.get("app_gb", 0) + s.get("compressed_gb", 0))


class _Summary:
    """summarize() as a fold over samples: one pass, holding a few numbers, the peak sample
    and the risers, so a long incident is summarised in bounded memory."""

    def __init__(self):
        self.n = self.kills = self.away = 0
        self.first = self.last = self.peak = self.onset = None
        self.swap = self.swap_total = self.disk = self.used = self.unowned = self.stall = None
        self.groups, self.top = _Risers("groups"), _Risers("top")

    def add(self, s):
        self.n += 1
        if self.first is None:
            self.first = s
        self.last = s
        if self.peak is None or _peak_key(s) > _peak_key(self.peak):
            self.peak = s
        if self.onset is None and (s.get("pressure", 0) >= 2 or s.get("jetsam_kills")):
            self.onset = s
        self.kills += s.get("jetsam_kills", 0)
        self.away += is_away(s)
        self.swap = _more(self.swap, s.get("swap_used_gb", 0))
        self.swap_total = _more(self.swap_total, s.get("swap_total_gb", 0))
        self.disk = _less(self.disk, s.get("disk_free_gb", 0))
        self.used = _more(self.used, s.get("app_gb", 0) + s.get("compressed_gb", 0))
        u = unowned_gb(s)
        if u is not None:
            self.unowned = _more(self.unowned, u)
        self.stall = _more(self.stall, s.get("stall", 0))
        self.groups.add(s)
        self.top.add(s)

    def result(self, events):
        if not self.n:
            return {"samples": 0}
        peak, onset, stall = self.peak, self.onset, self.stall
        reasons = {}
        killed = {}
        for e in events:
            if e.get("kind") == "jetsam":
                for r, n in (e.get("reasons") or {}).items():
                    reasons[r] = reasons.get(r, 0) + n
                for k, n in (e.get("top") or {}).items():
                    killed[k] = killed.get(k, 0) + n
            elif e.get("kind") == "stall":
                stall = _more(stall, e.get("seconds", 0))
        return {
            "samples": self.n,
            "from": self.first["iso"], "to": self.last["iso"],
            "peak_pressure": PRESSURE.get(peak.get("pressure", 0), peak.get("pressure")),
            "peak_at": peak["iso"],
            "max_swap_used_gb": self.swap,
            "max_swap_total_gb": self.swap_total,
            "min_disk_free_gb": self.disk,
            "max_app_plus_compressed_gb": round(self.used, 1),
            "ram_gb": self.last.get("ram_gb"),
            "jetsam_kills": self.kills,
            "max_unowned_gb": self.unowned,
            "max_stall_s": stall,
            "jetsam_reasons": reasons,
            "most_killed": dict(sorted(killed.items(), key=lambda kv: -kv[1])[:10]),
            "away_fraction": round(self.away / self.n, 2),
            "onset": None if not onset else {
                "at": onset["iso"], "pressure": PRESSURE.get(onset.get("pressure", 0)),
                "idle_s": (onset.get("away") or {}).get("idle_s"),
                "display_on": (onset.get("away") or {}).get("display_on"),
                "locked": (onset.get("away") or {}).get("locked"),
                "swap_used_gb": onset.get("swap_used_gb"), "disk_free_gb": onset.get("disk_free_gb")},
            "top_at_peak": (peak.get("top") or [])[:10],
            "groups_at_peak": (peak.get("groups") or [])[:10],
            "claude_at_peak": peak.get("claude") or [],
            "group_risers": self.groups.result(),
            "process_risers": self.top.result(),
        }


def summarize(samples, events):
    """The numbers of a window. `samples` may be any iterable in time order (a list, or
    iter_samples for a long window); it is read once and not held."""
    f = _Summary()
    for s in samples:
        f.add(s)
    return f.result(events)


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


DRAW_POINTS = 1200
_DRAW_KEYS = ("t", "wired_gb", "app_gb", "compressed_gb", "swap_used_gb", "disk_free_gb", "swap_total_gb",
              "jetsam_kills", "away")


def _load(s):
    return s.get("app_gb", 0) + s.get("compressed_gb", 0) + s.get("swap_used_gb", 0)


class _View:
    """One time view of a report, prepared from two passes over the samples in bounded
    state. The first pass counts and finds the five biggest app groups; the second folds
    the summary, the critical-pressure bands, the risers and the points to draw: at most
    DRAW_POINTS, per time bucket the one using the most memory (spikes survive) with the
    bucket's jetsam kills added up, each holding only what the charts draw."""

    def __init__(self, key, a, b):
        self.key, self.a, self.b = key, a, b
        self.n, self.t0, self.t1, self.peaks = 0, None, None, {}

    def count(self, s):
        self.n += 1
        if self.t0 is None:
            self.t0 = s["t"]
        self.t1 = s["t"]
        for g in s.get("groups") or []:
            self.peaks[g["name"]] = max(self.peaks.get(g["name"], 0), g["mb"])

    def start(self, meta):
        self.meta = meta
        self.top5 = [k for k, _ in sorted(self.peaks.items(), key=lambda kv: -kv[1])[:5]]
        self.summ, self.bands, self.app_pids, self.draw = _Summary(), [], {}, []
        self.w = None if self.n <= DRAW_POINTS else ((self.t1 - self.t0) / DRAW_POINTS or 1)
        self.bucket = self.cur = self.cur_load = None
        self.kills = 0

    def _point(self, s):
        p = {k: s[k] for k in _DRAW_KEYS if k in s}
        groups = s.get("groups") or []
        p["g"] = [next((g["mb"] / 1024 for g in groups if g["name"] == n), 0) for n in self.top5]
        p["rest"] = sum(g["mb"] for g in groups if g["name"] not in self.top5) / 1024
        return p

    def add(self, s):
        self.summ.add(s)
        if s.get("pressure", 0) >= 4:  # critical stretches; flips back within 2 min are bridged
            if self.bands and s["t"] - self.bands[-1][1] <= 120:
                self.bands[-1][1] = s["t"]
            else:
                self.bands.append([s["t"], s["t"]])
        for p in s.get("top") or []:
            g = (self.meta.get(p["pid"]) or {}).get("g")
            if g:
                d = self.app_pids.setdefault(g, {})
                d[p["pid"]] = max(d.get(p["pid"], 0), p["mb"])
        if self.w is None:
            self.draw.append(self._point(s))
            return
        b = int((s["t"] - self.t0) / self.w)
        if b != self.bucket:
            self.finish()
            self.bucket, self.cur, self.cur_load, self.kills = b, self._point(s), _load(s), 0
        elif _load(s) > self.cur_load:
            self.cur, self.cur_load = self._point(s), _load(s)
        self.kills += s.get("jetsam_kills", 0)

    def finish(self):
        if self.cur is not None:
            self.cur["jetsam_kills"] = self.kills
            self.draw.append(self.cur)
            self.cur = None


class _Meta:
    """pid -> name/parent/owner/app/session over the whole report, folded one sample at a time."""

    def __init__(self):
        self.meta, self.sessions = {}, {}

    def add(self, s):
        meta = self.meta
        names = {g["name"] for g in s.get("groups") or []}
        for p in s.get("top") or []:
            meta[p["pid"]] = {"n": p["name"], "pp": p.get("ppid"), "u": p.get("uid"),
                              "g": p.get("g") or _guess_group(p["name"], names), "s": p.get("s"), "pn": p.get("pn")}
        for c in s.get("claude") or []:
            self.sessions[c["pid"]] = c.get("cwd") or ""
            meta.setdefault(c["pid"], {"n": "claude"})
            b = c.get("biggest")
            if b:
                meta.setdefault(b["pid"], {"n": b["name"]})
                meta[b["pid"]].setdefault("s", c["pid"])

    def result(self):
        """(meta, owner names, session projects)."""
        users = {}
        for m in self.meta.values():
            u = m.get("u")
            if u is not None and u not in users:
                try:
                    users[u] = pwd.getpwuid(u).pw_name
                except (KeyError, TypeError):
                    users[u] = "uid %s" % u
        return self.meta, users, self.sessions


def _report_meta(samples):
    """pid -> name/parent/owner/app/session over the whole report, owner names, session projects."""
    f = _Meta()
    for s in samples:
        f.add(s)
    return f.result()


def _risers_data(view):
    procs = [{"pid": r["pid"], "name": r["proc"], "first": r["first_mb"], "peak": r["peak_mb"],
              "rise": r["rise_mb"], "at": r["peak_iso"], "ppid": r.get("ppid"), "uid": r.get("uid")}
             for r in view.summ.top.result(limit=None)]
    apps = []
    for r in view.summ.groups.result(limit=None):
        pids = sorted(view.app_pids.get(r["name"], {}).items(), key=lambda kv: -kv[1])
        apps.append({"name": r["name"], "first": r["first_mb"], "peak": r["peak_mb"], "rise": r["rise_mb"],
                     "at": r["peak_iso"], "pids": [[p, mb] for p, mb in pids]})
    return procs, apps


def _when(t):
    return datetime.datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")


def _view_html(view, events, meta, key, t0, t1):
    """One time view (a prepared _View): (sub line + KPIs + charts, sessions + top processes + kills)."""
    cls = "v v-%s" % key
    sub = '<p class="sub %s">%s → %s · %d samples</p>' % (cls, _when(t0), _when(t1), view.n)
    if not view.n:
        return (sub + '<div class="card %s"><p class=sub>No samples in this window.</p></div>' % cls, "")
    summ = view.summ.result(events)
    marks = [{"t": e["t"], "label": "%s %s %s" % (e.get("iso", "")[11:19], e["kind"].replace("_", " "), e.get("id", ""))}
             for e in events if e.get("kind") in ("incident_open", "incident_close")]
    bands = view.bands
    draw = view.draw
    mem_series = [("wired", lambda s: s.get("wired_gb"), "var(--c-wired)"),
                  ("app memory", lambda s: s.get("app_gb"), "var(--c-app)"),
                  ("compressed", lambda s: s.get("compressed_gb"), "var(--c-comp)"),
                  ("swap used", lambda s: s.get("swap_used_gb"), "var(--c-swap)")]
    ram = summ["ram_gb"]
    colors = ["var(--k1)", "var(--k2)", "var(--k3)", "var(--k4)", "var(--k5)"]
    grp_series = [(n, (lambda s, i=i: s["g"][i]), c) for i, (n, c) in enumerate(zip(view.top5, colors))]
    if len(view.peaks) > len(view.top5):
        grp_series.append(("other recorded apps", lambda s: s["rest"], "var(--k6)"))
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
    switch between (default: 24h / 6h / 1h ending at the last sample); the first is shown.
    `samples` is a list, or anything iterable more than once in time order (SampleWindow):
    it is read in two passes and not held, so a day of samples needs bounded memory."""
    if iter(samples) is samples:  # a one-shot iterator would leave the second pass empty
        samples = list(samples)
    if views is None:
        first = last = None
        for s in samples:
            first = s["t"] if first is None else first
            last = s["t"]
        views = report_views(first, last) if first is not None else [("all", "–", 0, 0)]
    prep, fold = [_View(key, a, b) for key, _, a, b in views], _Meta()
    for s in samples:
        fold.add(s)
        for v in prep:
            if v.a <= s["t"] <= v.b:
                v.count(s)
    meta, users, sessions = fold.result()
    for v in prep:
        v.start(meta)
    for s in samples:
        for v in prep:
            if v.a <= s["t"] <= v.b:
                v.add(s)
    heads, tails, vdata = [], [], {}
    for v in prep:
        v.finish()
        ve = [e for e in events if v.a <= e["t"] <= v.b]
        h, t = _view_html(v, ve, meta, v.key, v.a, v.b)
        heads.append(h)
        tails.append(t)
        procs, apps = _risers_data(v)
        vdata[v.key] = {"procs": procs, "apps": apps, "range": [v.a, v.b]}
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
        reasons_html = "<h2>Triggers</h2>" + _table(sorted(incident.get("reasons", []), key=lambda r: r.get("t", 0)), [
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
        '<p class=sub style="margin-top:24px">generated %s by %s %s</p>' % (
            datetime.datetime.now().strftime("%Y-%m-%d %H:%M"), BRAND, VERSION),
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
    samples, events = SampleWindow(lo, end), load_events(lo, end)
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


# ------------------------------------------------------------------ widths
# Every line the CLI prints fits 80 columns (roadmap 03 §3.12): each variable column has a
# budget and one way of being cut, and prose (why, advice) is wrapped at the terminal's width,
# 80 when there is no terminal, continuation lines indented. Nothing is wrapped inside a table.
def term_width():
    """The terminal's width if stdout is one (at least 40), else 80."""
    try:
        if sys.stdout.isatty():
            return max(40, os.get_terminal_size(sys.stdout.fileno()).columns)
    except (OSError, ValueError, AttributeError):
        pass
    return 80


def cut_end(s, w):
    """Purposes, commands: the beginning says what it is."""
    s = str(s)
    return s if len(s) <= w else s[:max(w - 1, 0)] + "…"


def cut_middle(s, w):
    """Names: head and tail both identify."""
    s = str(s)
    if len(s) <= w:
        return s
    head = w // 2
    return s[:head] + "…" + s[len(s) - (w - 1 - head):]


def cut_left(s, w):
    """Folders: the end says where."""
    s = str(s)
    return s if len(s) <= w else "…" + s[len(s) - w + 1:]


def fit_group(name, w):
    """A group's name in a column of w characters. A container's runtime:id stays whole (it is
    what `docker ps` shows) and its program is cut; too narrow for that, program first."""
    name = str(name)
    if len(name) <= w:
        return name
    m = re.match(r"^(\w+:[0-9a-f]{8}) \((.+)\)$", name)
    if m and w >= len(m.group(1)) + 6:
        return "%s (%s)" % (m.group(1), cut_end(m.group(2), w - len(m.group(1)) - 3))
    if m:
        name = "%s · %s" % (m.group(2), m.group(1).split(":")[0])
    return cut_middle(name, w)


def wrap(text, width=None, first="", indent=2):
    """`text` after `first`, broken at spaces into lines of at most `width` columns (the
    terminal's), continuation lines indented by `indent`. A word longer than a line stays whole."""
    import textwrap
    return "\n".join(textwrap.wrap(text, width or term_width(), initial_indent=first, subsequent_indent=" " * indent,
                                    break_long_words=False, break_on_hyphens=False)) or first.rstrip()


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
    w = max(80, term_width())

    def line(label, text):
        print(wrap(text, w, "%-11s" % label, 11))
    line("daemon", "%s (pid %s, v%s, sample %ds ago, interval %ss%s)" % (
        "running" if alive else "NOT RUNNING", d.get("pid"), d.get("version"), age, d.get("interval"),
        ", root" if d.get("root") else ", NOT root"))
    line("pressure", "%s   free %s%%" % (PRESSURE.get(c["pressure"], c["pressure"]), c.get("free_pct")))
    line("memory", "RAM %.0f GB · app %.1f · wired %.1f · compressed %.1f · cached %.1f · free %.1f GB" % (
        c["ram_gb"], c["app_gb"], c["wired_gb"], c["compressed_gb"], c["cached_gb"], c["free_gb"]))
    line("swap", "%.1f / %.1f GB used (%d swapfiles)" % (c["swap_used_gb"], c["swap_total_gb"], c["swapfiles"]))
    u = unowned_gb(c)
    if u is not None:
        line("unowned", "%.1f GB held outside any process%s" % (
            u, "  <- LEAK? only a restart frees it" if u >= unowned_limit_gb(c["ram_gb"]) else ""))
    res = resource_lines(c, *volume_prefs(), io=True)
    if not c.get("disks"):  # a logger before 1.9.1
        line("disk", "%.0f GB free" % c["disk_free_gb"])
    for label, text in res if logger_measures(c) else ():
        line(label, text)
    line("you", "idle %ss · display %s · %s · sleep held by %s" % (
        a.get("idle_s"), "on" if a.get("display_on") else "off", "locked" if a.get("locked") else "unlocked",
        ", ".join(a.get("sleep_preventers") or []) or "nobody"))
    if d.get("incident"):
        line("INCIDENT", "open: %s" % d["incident"])
    print("\ntop apps:")
    for g in (c.get("groups") or [])[:8]:
        print("  %6.1f GB  %s (%d)" % (g["mb"] / 1024, fit_group(g["name"], w - 19), g["n"]))
    for title, key, field, fmt in (("busiest (cores)", "top_cpu", "cpu", "%7.2f   "), ("GPU (%)", "top_gpu", "gpu", "%7.1f   "),
                                   ("writing to disk (MB/s)", "top_io", "w", "%7.2f   ")):
        rows = [r for r in (c.get(key) or [])[:5] if isinstance(r, dict) and _n(r.get(field)) is not None]
        if rows:
            print("\n%s:" % title)
            for r in rows:
                print(fmt % r[field] + "%s (%s)" % (cut_middle(str(r.get("name")), 30),
                                                   fit_group(str(r.get("g") or ""), w - 46)))
    if c.get("claude"):
        print("\nclaude sessions:")
        for s in c["claude"]:
            print("  %6.1f GB  pid %-6s %s" % (s["mb"] / 1024, s["pid"], cut_left(s.get("cwd"), w - 24)))
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
    w = max(80, term_width())
    for r in rows:
        worst = max(r, key=lambda s: (s.get("pressure", 0), s.get("swap_used_gb", 0)))
        g = (worst.get("groups") or [{}])[0]
        size = " %.1fG" % (g.get("mb", 0) / 1024)
        print("%-8s %-8s %6.1f %6.1f %6.1f %6.0f %5d %4s  %s%s" % (
            datetime.datetime.fromtimestamp(r[0]["t"]).strftime("%H:%M"), PRESSURE.get(worst.get("pressure", 0)),
            worst["app_gb"], worst["compressed_gb"], worst["swap_used_gb"], worst["disk_free_gb"],
            sum(s.get("jetsam_kills", 0) for s in r), "yes" if any(is_away(s) for s in r) else "",
            fit_group(g.get("name", ""), w - 58 - len(size)), size))
    summ = summarize(samples, events)
    for title, key in (("apps", "group_risers"), ("processes", "process_risers")):
        print("\nbiggest risers (%s):" % title)
        for x in summ[key][:8]:
            print("  +%6d MB  %-*s peak %d MB at %s" % (x["rise_mb"], w - 56, fit_group(x["name"], w - 56), x["peak_mb"],
                                                      x["peak_iso"]))
    notable = [e for e in events if e.get("kind") not in ("jetsam", "notified")]
    if summ["jetsam_kills"]:
        print("\njetsam kills: %d   reasons: %s" % (summ["jetsam_kills"], summ["jetsam_reasons"]))
    if notable:
        print("\nevents:")
        for e in notable[-30:]:
            print("  %s  %-16s %s" % (e["iso"][11:19], e["kind"], cut_end(_event_detail(e), w - 29)))
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


INCIDENT_ROW = "%-15s %5s  %-5s %5s  %s"  # a 36-column prefix, then the headline (44 at 80 columns)


def cmd_incidents():
    """One row per incident: when, how long, open or not, kills, and its headline. A headline
    longer than the line continues on the next, indented to its column."""
    incs = list_incidents()
    if not incs:
        print("no incidents recorded")
        return 0
    w = max(80, term_width())
    print(INCIDENT_ROW % ("incident", "took", "state", "kills", "headline"))
    for i in incs:
        dur = ("%dm" % ((i.get("end", time.time()) - i["start"]) // 60))
        kills = (i.get("summary") or {}).get("jetsam_kills")
        head = (i.get("reasons") or [{}])[0].get("desc", "")
        print(wrap(head, w, INCIDENT_ROW % (i["id"], dur, "OPEN" if i.get("open") else "",
                                           "–" if kills is None else kills, ""), 36))
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
_plat = None
BACKENDS = {"darwin": "oomph_darwin"}  # sys.platform -> the module that measures it (Linux: 1.9.4)


class Unsupported(Exception):
    """This system has no backend: oomph can read logs and ledgers here, not measure."""


def plat():
    """The backend that measures this machine (oomph_darwin.py on a Mac; its docstring lists the
    contract). Imported on first use, by code that measures: reading logs, the hook's ledger
    reads and everything else import no native code, here or on any other system."""
    global _plat
    if _plat is None:
        name = BACKENDS.get(sys.platform)
        if name is None:
            raise Unsupported("measuring %s is not supported yet: macOS only so far (Linux from 1.9.4)" % sys.platform)
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        _plat = __import__(name)
    return _plat


def _daemon_module():
    """oomphd, for summarize_procs (it measures nothing itself)."""
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
    P = plat()
    s = {"t": round(time.time(), 1), "iso": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
         "source": "live", "os": P.OS}
    s.update(P.system_memory())
    s["away"] = {k: v for k, v in P.away_state().items() if k in ("idle_s", "display_on", "locked", "sleep_preventers")}
    if with_procs:
        procs = P.collect_procs()
        top, groups, sessions = _daemon_module().summarize_procs(procs)
        s["top"], s["groups"], s["claude"] = top, groups, sessions
        s.update(P.ownership(s, procs))
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
    """ok / tight / critical for a sample, with the reasons. The rules are a system's: a sample
    without `os` is a Mac's (every sample before 1.8.8). A full disk counts only on a Mac, where
    swap grows on the startup volume (roadmap 03 §5.4)."""
    mac = s.get("os", "macos") == "macos"
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
    if mac and disk < 5:
        bump(2, "only %.0f GB disk free — swap cannot grow" % disk)
    elif mac and disk < 20:
        bump(1, "only %.0f GB disk free — swap may not be able to grow" % disk)
    if mac and swap_full and disk < 20:
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


def verdict_line(v, width=None, lines=()):
    """The verdict as `oomph check` and the hook print it, wrapped at `width` (the terminal's);
    `lines`: (label, text) of the other resources, which `check` prints before the advice."""
    w = width or term_width()
    out = [wrap("oomph: %s — %.1fG free of %.0fG · pressure %s · swap %.1f/%.1fG · disk %.0fG free" % (
        v["level"].upper(), v["free_gb"], v["ram_gb"], v["pressure"], v["swap_used_gb"] or 0,
        v["swap_total_gb"] or 0, v["disk_free_gb"]), w)]
    if v["reasons"]:
        out.append(wrap("; ".join(v["reasons"]), w, "  why: "))
    c = v.get("coordination") or {}
    if c.get("others") or c.get("mine"):
        g = [o for o in c["others"] if o["state"] == "granted"]
        q = [o for o in c["others"] if o["state"] == "queued"]
        out.append(wrap("others hold %d (%.1fG not yet used), %d waiting · yours %d · %.1fG available to you"
                        % (len(g), c["reserved_by_others_gb"], len(q), len(c["mine"]), c["available_to_me_gb"]),
                        w, "  reservations: "))
    for label, text in lines:
        out.append(wrap(text, w, "  %-6s " % label, 9))
    for n in v.get("notes") or ():
        out.append(wrap(n, w, "  note: "))
    out.append(wrap(v["advice"], w, "  advice: "))
    return "\n".join(out)


def _session_root(procs, pid):
    """pid of the outermost agent session root (`claude`) above `pid`, or None."""
    is_agent = plat().is_agent
    cur, root, hops = pid, None, 0
    while cur in procs and hops < 64:
        if is_agent(procs[cur]):
            root = cur  # keep walking: the outermost claude is the session
        cur, hops = procs[cur]["ppid"], hops + 1
    return root


def find_session(pid=None):
    """The Claude Code session (outermost `claude` process) that `pid` (default: our parent) runs in."""
    d = plat()
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


def checked_verdict(mine=None, s=None):
    """verdict() plus what other sessions have reserved or are waiting for, and the disks this user
    pinned (`resources`: the sample's CPU, GPU, disk and I/O blocks, for the caller to show)."""
    s = s or (_sample_override() if _sample_override else sample(with_procs=False))
    v = verdict(s)
    try:
        pinned_verdict(v, s, volume_prefs()[0])
    except Exception:  # a damaged settings file is no reason to fail a check
        pass
    v["resources"] = {k: s[k] for k in ("cpu", "gpu", "disks", "io") if k in s}
    try:
        coordination_verdict(v, coordination(mine if mine is not None else holder_for()["pid"], s))
    except Exception as e:  # the ledger is a bonus; never let it break a check
        v["coordination"] = {"error": repr(e)}
    return v


def cmd_check(args):
    """The verdict, and a line per resource. A plain check never waits: without the logger the CPU
    and GPU are not measured unless --measure takes a quarter-second reading."""
    s = resource_sample(measure="--measure" in args)
    v = checked_verdict(s=s)
    if "--json" in args:
        print(json.dumps(v))
    else:
        print(verdict_line(v, lines=resource_lines(s, *volume_prefs())))
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
    print("session  pid %s · %s" % (ses["pid"], cut_left(ses["cwd"], 60)))
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


# ------------------------------------------------- more resources: CPU, GPU, disks (roadmap 02 §3.6, §7.1)
# The logger records them from 1.9.1; only memory can be reserved yet (cores, GPU and disk from 1.12).
THERMAL = {0: "nominal", 1: "moderate", 2: "heavy", 3: "trapping", 4: "sleeping"}
RESERVABLE = ("memory",)
NOT_MEASURED = "not measured (logging is off; `oomph check --measure` takes a quarter-second reading)"
NOT_LOGGED = "not recorded by the logger, which is older than 1.9.1 (`oomph check --measure` reads it now)"
NOT_READ = "not read by the logger this time (`oomph check --measure` reads it now)"
_VOL_ID = re.compile(r"vol:[0-9A-Fa-f-]{8,64}")


def _n(x):
    """A number oomph could have written, else None (samples are read from files)."""
    return x if isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) else None


def _gb(x):
    return "{:,.0f}".format(x) if x >= 10 else "%.1f" % x


def settings_path():
    return os.path.join(STATE_DIR, "settings.json")


def user_settings():
    """This user's settings.json (02 §5.4): {"volumes": {"pinned": [pool id], "hidden": [pool id]}};
    a damaged or missing file reads as none."""
    d = read_bounded(settings_path(), 64 << 10)
    v = loads_untrusted(d) if d else None
    return v if isinstance(v, dict) else {}


def volume_prefs(st=None):
    """(pinned, hidden): sets of pool ids this user chose."""
    v = (st if st is not None else user_settings()).get("volumes")
    v = v if isinstance(v, dict) else {}
    ids = lambda k: {x for x in (v.get(k) if isinstance(v.get(k), list) else [])[:64]
                     if isinstance(x, str) and (_VOL_ID.fullmatch(x) or x == "data")}
    return ids("pinned"), ids("hidden")


def save_user_settings(st):
    """Into this user's own state folder (created 700), by a new file and a rename; 600."""
    import tempfile
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=STATE_DIR, prefix=".settings-", suffix=".json")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(st, f, sort_keys=True, allow_nan=False)
        os.replace(tmp, settings_path())
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def pool_floors(total_gb):
    """Floors of a pinned pool (02 §4.4): low 5 % of its size (2 to 20 GB), critical 1 % (0.5 to 5)."""
    return min(20.0, max(2.0, 0.05 * total_gb)), min(5.0, max(0.5, 0.01 * total_gb))


def disk_rows(s, pinned=frozenset()):
    """The sample's disks, checked field by field, each with `pinned`, and floors and a level for a
    pinned pool that has none of its own."""
    out = []
    for d in s.get("disks") or []:
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or _n(d.get("free_gb")) is None:
            continue
        d = dict(d, pinned=d["id"] in pinned)
        if d["pinned"] and not d.get("watch") and _n(d.get("total_gb")):
            low, crit = pool_floors(d["total_gb"])
            d.update(low_gb=round(low, 1), crit_gb=round(crit, 1),
                     level="critical" if d["free_gb"] < crit else "low" if d["free_gb"] < low else "ok")
        out.append(d)
    return out


DISK_ADVICE = ("Disk space is short on %s (pinned): write nothing big there (builds, caches, images, datasets); "
               "put scratch on another disk or free space on it, and ask the user before deleting anything this "
               "session did not create.")


def pinned_verdict(v, s, pinned):
    """A pool this user pinned that is low or critical counts like memory for this user's check and
    hook (02 §7.4), with advice about the disk rather than memory; a listed pool nobody pinned raises
    nothing. A pin the sample has no pool for is said in `notes`: it could not be checked."""
    rows = disk_rows(s, pinned)
    mem, short = v["exit_code"], []
    for d in rows:
        if d["pinned"] and not d.get("watch") and d.get("level") in ("low", "critical"):
            lv = 2 if d["level"] == "critical" else 1
            name = str(d.get("name") or d["id"])[:40]
            v["reasons"].append("only %.0f GB free on %s (pinned)" % (d["free_gb"], name))
            short.append(name)
            if lv > v["exit_code"]:
                v["exit_code"], v["level"] = lv, LEVELS[lv]
    if short:
        v["advice"] = ((ADVICE[LEVELS[mem]] + " ") if mem else "") + DISK_ADVICE % ", ".join(short)
    seen = {d["id"] for d in rows}
    gone = sorted(x for x in pinned if x not in seen)
    if gone:
        v.setdefault("notes", []).append(
            "pinned %s not checked: %s not in the logger's latest sample (not mounted, or the logger is off or older "
            "than 1.9.1)" % (", ".join(gone), "it is" if len(gone) == 1 else "they are"))
    return v


def live_disks():
    """The system's pool from the kernel's mount table: no diskutil, so no listed pools (it would
    take half a second a disk); None where this backend has no mounts."""
    P = plat()
    if not hasattr(P, "mounts"):
        return None
    recs = P.mounts()
    return P.disk_pools(recs, {})[0] if recs else None


def resource_sample(measure=False, with_procs=False):
    """A sample with the resource blocks: the logger's if it is fresh, else a live one with the
    system's disk pool and, with `measure`, a quarter-second reading of the rates."""
    s = _sample_override() if _sample_override else sample(with_procs=with_procs)
    if s.get("source") == "live" or "disks" not in s:  # no logger, or one older than 1.9.1
        try:
            d = live_disks()
            if d is not None:
                s["disks"] = d
        except Exception:
            pass
        if measure:
            blocks, use, procs = _daemon_module().measure()
            s.update(blocks)
            if with_procs:
                m = _daemon_module()
                top, s["groups"], s["claude"], session_of = m._summarize(procs, use)
                s["top"] = top
                s.update(m.rate_lists(procs, use, session_of, plat().group_key))
    return s


def _gpu_text(g):
    mem = ""
    if _n(g.get("mem_gb")) is not None:
        mem = " · %.1f%s GB GPU memory" % (g["mem_gb"], " of %.0f" % g["mem_limit_gb"] if _n(g.get("mem_limit_gb")) else "")
    name = " (%s)" % str(g.get("name"))[:40] if g.get("name") else ""
    if _n(g.get("util")) is None:
        return "not measured yet%s%s" % (mem, name)
    if g.get("src") == "ioreport":
        return "%.0f %% of full speed%s%s" % (g["util"], mem, name)
    return "busy %.0f %% of the time (speed not reported)%s%s" % (g["util"], mem, name)


def logger_measures(s):
    """Whether a sample comes from a logger that records CPU, GPU, I/O and disks (1.9.1 or later):
    its cpu block is there, or its daemon block says so. The top lists and the rates are no sign (a
    list is left out when nothing uses that resource, the rates after a start or a gap), and nor is
    `disks` (the CLI adds the system's pool itself when the logger has none)."""
    if s.get("source") == "live":
        return False
    if isinstance(s.get("cpu"), dict):
        return True
    d = s.get("daemon")
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", d.get("version") or "") if isinstance(d, dict) and \
        isinstance(d.get("version"), str) else None
    return bool(m) and tuple(int(x) for x in m.groups()) >= (1, 9, 1)


def resource_lines(s, pinned=frozenset(), hidden=frozenset(), io=False):
    """(label, text) per resource for check and status: cpu, gpu, one disk line per pool, io."""
    out = []
    off = NOT_MEASURED if s.get("source") == "live" else NOT_READ if logger_measures(s) else NOT_LOGGED
    cpu = s.get("cpu") if isinstance(s.get("cpu"), dict) else None
    if cpu is None:
        out.append(("cpu", off))
    else:
        n = _n(cpu.get("n")) or 0
        split = " (P %.1f · E %.1f)" % (cpu["p_busy"], cpu["e_busy"]) \
            if _n(cpu.get("p_busy")) is not None and _n(cpu.get("e_busy")) is not None else ""
        th = cpu.get("therm")
        therm = " · thermal %s" % THERMAL.get(th, th) if _n(th) else ""
        out.append(("cpu", ("%.1f of %d cores busy%s" % (cpu["busy"], n, split) if _n(cpu.get("busy")) is not None
                            else "%d cores · not measured yet" % n) + therm))
    gpus = s.get("gpu")
    if not isinstance(gpus, list):
        out.append(("gpu", off))
    elif not gpus:
        out.append(("gpu", "none the system reports"))
    for g in gpus if isinstance(gpus, list) else ():
        if isinstance(g, dict):
            out.append(("gpu", _gpu_text(g)))
    first = True
    for d in disk_rows(s, pinned):
        if d["id"] in hidden:
            continue
        tail = ""
        if d.get("level") in ("low", "critical"):
            tail = " · %s" % d["level"].upper()
        if not d.get("watch"):
            tail += " · pinned" if d["pinned"] else " · not watched"
        tot = _n(d.get("total_gb"))
        out.append(("disk" if first else "", "%s %s GB free%s%s" % (
            cut_middle(str(d.get("name") or d["id"]), 24), _gb(d["free_gb"]), " of %s" % _gb(tot) if tot else "", tail)))
        first = False
    if io and isinstance(s.get("io"), dict) and _n(s["io"].get("w_mb_s")) is not None:
        out.append(("io", "read %.1f MB/s · write %.1f MB/s (all processes)" % (s["io"].get("r_mb_s") or 0,
                                                                               s["io"]["w_mb_s"])))
    return out


PS_KINDS = {"--cpu": ("top_cpu", "cpu", "CORES", "%7.2f"), "--gpu": ("top_gpu", "gpu", "% GPU", "%7.1f"),
            "--io": ("top_io", "w", "MB/s W", "%7.2f"), "--memory": ("top", "mb", "MB", "%7d")}
PS_USAGE = "usage: oomph ps [--cpu | --gpu | --io | --memory] [-n 10] [--json]"


def cmd_ps(args):
    """The biggest consumers of one resource now: from the logger's latest sample, else (logging off)
    from a half-second reading of what this user may see."""
    try:
        opts, _ = _strict(args, takes=("-n",), flags=tuple(PS_KINDS) + ("--json",), npos=0)
        n = int(opts.get("-n", 10))
        if not 1 <= n <= 100:
            raise ValueError
    except (UsageError, ValueError) as e:
        print("oomph ps: %s\n%s" % (e if isinstance(e, UsageError) else "-n takes 1 to 100", PS_USAGE), file=sys.stderr)
        return 2
    kinds = [k for k in PS_KINDS if k in opts]
    if len(kinds) > 1:
        print("oomph ps: one resource at a time\n" + PS_USAGE, file=sys.stderr)
        return 2
    key, field, head, fmt = PS_KINDS[kinds[0] if kinds else "--cpu"]
    s, note = _daemon_sample(), None
    if s is None or key != "top" and not logger_measures(s):  # no logger, or one older than 1.9.1
        older, s = s is not None, live_sample(with_procs=True)
        if key != "top":
            blocks, use, procs = _daemon_module().measure(0.5)
            m = _daemon_module()
            s.update(m.rate_lists(procs, use, m._summarize(procs, use)[3], plat().group_key, n))
        note = "%s: a live reading of %s" % ("the logger is older than 1.9.1" if older else "logging is off",
                                              "your own processes" if os.geteuid() else "every process")
    rows = [r for r in (s.get(key) or []) if isinstance(r, dict) and _n(r.get(field)) is not None][:n]
    if key == "top":
        rows.sort(key=lambda r: -r["mb"])
    if "--json" in opts:
        print(json.dumps({"resource": field, "rows": rows, "source": s.get("source", "daemon"), "at": s.get("iso")}))
        return 0
    w = max(80, term_width())
    print("%7s %7s  %-*s %s" % (head, "PID", (w - 18) // 2, "NAME", "APP"))
    for r in rows:
        print(fmt % r[field] + " %7s  %-*s %s" % (r.get("pid"), (w - 18) // 2, cut_middle(str(r.get("name")), (w - 18) // 2),
                                                   fit_group(str(r.get("g") or ""), (w - 18) // 2 - 1)))
    if not rows:
        print("  nothing measurable right now" if key != "top" else "  no processes")
    if note:
        print("(%s)" % note)
    return 0


def _resources(s, c=None):
    """What `oomph resources` reports, as data: per pool its capacity, use, what is reserved and
    whether it can be reserved with this version."""
    pinned, hidden = volume_prefs()
    out = {"memory": {"ram_gb": s.get("ram_gb"), "free_gb": free_physical_gb(s), "reservable": True}}
    if c:
        out["memory"].update(reserved_gb=c["reserved_gb"], left_gb=c["available_gb"], others_gb=c["reserved_by_others_gb"])
    cpu = s.get("cpu") if isinstance(s.get("cpu"), dict) else None
    out["cpu"] = dict({k: cpu[k] for k in ("n", "p", "e", "busy", "therm") if k in cpu}, reservable=False) if cpu else None
    gpus = s.get("gpu") if isinstance(s.get("gpu"), list) else None
    out["gpu"] = None if gpus is None else [dict({k: g[k] for k in ("id", "name", "util", "active", "src", "mem_gb",
                                                                    "mem_alloc_gb", "mem_limit_gb", "mem_limit_est",
                                                                    "unified") if k in g}, reservable=False)
                                             for g in gpus if isinstance(g, dict)]
    out["disks"] = [dict({k: d[k] for k in ("id", "name", "mount", "free_gb", "total_gb", "kind", "roles", "level",
                                            "low_gb", "crit_gb", "pinned") if k in d},
                         watched=bool(d.get("watch")), reservable=False)
                    for d in disk_rows(s, pinned) if d["id"] not in hidden]
    out["reservable"] = list(RESERVABLE)
    return out


def cmd_resources(args):
    """The resources of this machine: capacity, use, what is reserved and left, and which of them
    can be reserved here (only memory so far): what an agent asks before reserving anything else."""
    try:
        opts, _ = _strict(args, flags=("--json",), npos=0)
    except UsageError as e:
        print("oomph resources: %s\nusage: oomph resources [--json]" % e, file=sys.stderr)
        return 2
    s = resource_sample(measure=True)
    try:
        c = coordination(holder_for()["pid"], s)
    except Exception:  # the ledger is a bonus here too
        c = None
    r = _resources(s, c)
    if "--json" in opts:
        print(json.dumps(r, allow_nan=False))
        return 0
    w = max(80, term_width())
    m = r["memory"]
    line = lambda label, text: print(wrap(text, w, "  %-7s " % label, 10))
    line("memory", "%.0f GB · %.1f free%s · reservable" % (m["ram_gb"] or 0, m["free_gb"], (
        " · %.1f GB reserved · %.1f GB left to reserve" % (m["reserved_gb"], m["left_gb"])) if "left_gb" in m else ""))
    for label, text in resource_lines(s, *volume_prefs()):
        if label in ("cpu", "gpu") and not text.startswith("not measured"):
            text += " · not reservable yet"
        line(label, text)
    print(wrap("Only memory can be reserved with this version: `oomph reserve 6G --for \"what\"`.", w, "  "))
    return 0


VOLUMES_USAGE = "usage: oomph volumes [--all] [--json]   ·   oomph volumes watch|unwatch|hide|unhide PATH"


def _volume_of(path, rows):
    """The mount row a path is on (by its device), or None."""
    try:
        dev = os.stat(path).st_dev & 0xFFFFFFFF
    except OSError:
        return None
    for r in rows:
        if r["dev"] == dev:
            return r
    return None


def cmd_volumes(args):
    """The volumes oomph samples (watched: the system's pool; listed: other fixed disks) and, with
    --all, those it ignores and why. `watch PATH` pins a listed volume for this user: its free space
    then counts in this user's check and hook; `hide` keeps it out of this user's lists."""
    P = plat()
    if not hasattr(P, "mounts"):
        print("oomph volumes: listing volumes is not supported on this system yet", file=sys.stderr)
        return 1
    sub = args[0] if args and args[0] in ("watch", "unwatch", "hide", "unhide") else None
    try:
        opts, pos = _strict(args[1:] if sub else args, flags=("--all", "--json"), npos=1 if sub else 0)
        if sub and not pos:
            raise UsageError("%s needs a path on the volume" % sub)
    except UsageError as e:
        print("oomph volumes: %s\n%s" % (e, VOLUMES_USAGE), file=sys.stderr)
        return 2
    pools, rows = _daemon_module().Volumes(P, wait=True).read()
    if pools is None:
        print("oomph volumes: the mount table could not be read", file=sys.stderr)
        return 1
    pool_ids = {}
    for p in pools:
        pool_ids[p["dev"]] = p
    if sub:
        if os.geteuid() == 0:
            print("oomph volumes: pins are per user: run it without sudo", file=sys.stderr)
            return 1
        r = _volume_of(pos[0], rows)
        p = pool_ids.get(r["pool"]) if r and r["cls"] in ("watched", "listed") else None
        if p is None:
            why = r["why"] if r else "no such path"
            print("oomph volumes: %s: the logger does not record this volume (%s)" % (pos[0], why), file=sys.stderr)
            return 1
        if p.get("weak"):
            print("oomph volumes: %s has no UUID, so it cannot be told from another disk by that name: "
                  "it cannot be pinned" % p["name"], file=sys.stderr)
            return 1
        st = user_settings()
        v = st.get("volumes") if isinstance(st.get("volumes"), dict) else {}
        pinned, hidden = volume_prefs(st)
        if sub == "watch" and p["id"] == "data":
            print("oomph volumes: %s is the system's pool: always watched" % p["name"])
            return 0
        {"watch": pinned.add, "unwatch": pinned.discard, "hide": hidden.add, "unhide": hidden.discard}[sub](p["id"])
        v.update(pinned=sorted(pinned), hidden=sorted(hidden))
        st["volumes"] = v
        save_user_settings(st)
        print("oomph volumes: %s %s" % (p["name"], {"watch": "pinned: its free space counts in your checks",
                                                    "unwatch": "no longer pinned", "hide": "hidden from your lists",
                                                    "unhide": "shown again"}[sub]))
        return 0
    pinned, hidden = volume_prefs()
    out = []
    for r in rows:
        p = pool_ids.get(r["pool"]) if r["cls"] in ("watched", "listed") else None
        main = p is not None and p["mount"] == r["mount"]
        if not main and "--all" not in opts:
            continue
        e = {"mount": r["mount"], "name": r["name"], "fs": r["fs"], "free_gb": r["free_gb"], "total_gb": r["total_gb"],
             "class": r["cls"], "why": r["why"]}
        if p is not None:
            e.update(id=p["id"], pinned=p["id"] in pinned, hidden=p["id"] in hidden)
            if not main:
                e["why"] = "shares its space with %s" % p["mount"]
            elif p.get("roles"):
                e["roles"] = p["roles"]
        if e.get("hidden") and "--all" not in opts:
            continue
        out.append(e)
    out.sort(key=lambda e: ({"watched": 0, "listed": 1}.get(e["class"], 2), e["mount"]))
    if "--json" in opts:
        print(json.dumps(out))
        return 0
    w = max(80, term_width())
    for e in out:
        what = "%s: %s" % (e["class"], e["why"])
        if e.get("roles"):
            what += " (%s)" % ", ".join(e["roles"])
        if e.get("pinned"):
            what += " · pinned"
        if e.get("hidden"):
            what += " · hidden by you"
        size = "%s free of %s GB" % (_gb(e["free_gb"]), _gb(e["total_gb"])) if e["total_gb"] else ""
        print(wrap("%s · %s" % (what, e["mount"]), w, "  %-14s %-20s " % (cut_middle(e["name"], 14), size), 38))
    if "--all" not in opts:
        print("(`oomph volumes --all` also lists the volumes the logger ignores, and why)")
    return 0


# ------------------------------------------------------ coordination ledger
# Sessions announce memory-heavy work before starting it ("reserve 6G for the gradle build").
# Requests queue first-come-first-served in one shared ledger; a request is granted when it
# fits into free memory minus what earlier grants have not yet used, minus a safety margin.
# So concurrent heavy steps from different sessions run side by side when there's room, and
# one after another when there isn't. Advisory: oomph never stops or kills anything.
LEDGER_DIR = os.environ.get("OOMPH_LEDGER_DIR") or _path("ledger")
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


def read_bounded(name, cap, dir_fd=None, tail=False, shared=False):
    """The bytes of a regular file with a single link, read without following a symbolic link,
    without blocking on a FIFO and never more than `cap` of them; None for anything else (missing,
    a link, a FIFO, a device, a directory, a hard-linked file, or bigger than `cap`). With `tail`
    a bigger file gives its last whole lines within `cap` instead.

    `shared` is for the shared ledger directory, where what is read may be written back into a
    file everyone can read. No check by name or by descriptor can tell a planted hard link from
    the real file for sure: the attacker links someone's private file there, the reader opens it,
    the attacker unlinks the name, and the open file has one link again (03-linux C.3, row 19).
    So the file must also be readable by everyone (oomph writes 0666): all three read bits, since
    a user in the file's group gets the group's bits and not the others'. A file someone could
    not read anyway is refused whatever its name, which no race changes, because the
    descriptor's mode is the file's (an ACL that denies one user is the gap that remains). On top of that, after the read the file must still have one link and the
    name must still be that file; a writer that renamed a new file over it meanwhile makes the
    read start again (three tries)."""
    for _ in range(3 if shared else 1):
        data = _read_once(name, cap, dir_fd, tail, shared)
        if data is not _MOVED:
            return data
    return None


_MOVED = object()


def _read_once(name, cap, dir_fd, tail, shared):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if shared and st.st_nlink == 0:  # renamed over since the open
            return _MOVED
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (shared and st.st_mode & 0o444 != 0o444):
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
        if shared:
            after, by = os.fstat(fd), _lstat(name, dir_fd)
            if after.st_nlink != 1 or not by or (by.st_dev, by.st_ino, by.st_nlink) != (st.st_dev, st.st_ino, 1):
                return _MOVED
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


def _lstat(name, dir_fd):
    try:
        return os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except OSError:
        return None


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


# Switches that survive updates live here, not in the LaunchDaemon's plist, which install.sh
# replaces. Keys are the switches' names without the prefix and in lower case
# ({"ioreport": true} for OOMPH_IOREPORT, the first one read: 1.9.3). The file is root's: one that root
# does not own, or that anyone else could change, is ignored.
CONFIG_FILE = PATHS_HERE["config"]
CONFIG_CAP = 64 << 10


def read_config(path=CONFIG_FILE):
    """The root-owned configuration as a dict; {} when it is missing or not to be trusted. Both
    the file and its directory must belong to root and be writable by nobody else, the file a
    regular file with one link (read without following links or blocking, like read_bounded),
    at most CONFIG_CAP bytes of a JSON object within LIMITS."""
    d, name = os.path.split(path)
    try:
        dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return {}
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        os.close(dfd)
        return {}
    try:
        for st in (os.fstat(dfd), os.fstat(fd)):
            if st.st_uid != 0 or st.st_mode & 0o022:
                return {}
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > CONFIG_CAP:
            return {}
        data = os.read(fd, CONFIG_CAP + 1)
    except OSError:
        return {}
    finally:
        os.close(fd)
        os.close(dfd)
    v = loads_untrusted(data) if len(data) <= CONFIG_CAP else None
    return v if isinstance(v, dict) else {}


def setting(name, default=None, config=None):
    """A switch: the environment's OOMPH_<NAME> if set (tests, a one-off run), else the
    configuration file's `name`, else `default`. Env values are strings, the file's are JSON."""
    env = os.environ.get("OOMPH_" + name.upper())
    if env is not None:
        return env
    return (read_config() if config is None else config).get(name.lower(), default)


def switched_on(v):
    """A switch's value as a yes: true in the file; 1, true, yes or on in the environment."""
    return v is True or (type(v) is int and v == 1) or \
        (isinstance(v, str) and v.strip().lower() in ("1", "true", "yes", "on"))


def ioreport_wanted(config=None):
    """Whether the logger may start the IOReport helper for the GPU's full-speed figure (roadmap 02
    §4.2): opt-in in 1.9.3, so only with "ioreport": true in the configuration file (or
    OOMPH_IOREPORT=1), and never with "no_ioreport" (OOMPH_NO_IOREPORT=1), which wins."""
    config = read_config() if config is None else config
    return switched_on(setting("ioreport", config=config)) and not switched_on(setting("no_ioreport", config=config))


def _num(x, lo=-1e15, hi=1e15):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x) and lo <= x <= hi


def _t(x):
    """A unix time oomph could have written (datetime can't take just any float)."""
    return _num(x, 0, 1e11)


def _pid(x):
    return isinstance(x, int) and not isinstance(x, bool) and 0 < x < 2 ** 31


def _segments(x):
    """A reservation's spans by size: t and gb, and a newer writer's `res` (amounts by resource,
    02 §6.2) when it has its type, so that a write here keeps it."""
    segs = []
    for s in (x if isinstance(x, list) else []):
        if isinstance(s, dict) and _t(s.get("t")) and _num(s.get("gb"), 0, 1e6):
            segs.append({"t": s["t"], "gb": s["gb"]})
            if "res" in s and _rec_amounts(s["res"], True):
                segs[-1]["res"] = _rec_amounts(s["res"], True)
    return segs or None


# ----- ledger version 2, for readers (B0, 1.9.2; roadmap §4.4, 02 §6.2 and §9, 03 §6.5)
# What newer writers add to the same two files, all optional. This code reads every field and
# carries it through its own writes, typed; it writes none of them itself except `agent` (D11)
# and, when it ends a newer writer's lease, that lease's own fields in the end record:
#   ledger root: `v` (2 once a vector-aware writer created the ledger), `boot` (the boot id at the
#     last write, Linux), `sessions` {"<pid>@<start>": {cwd, uid, seen}} (what each agent session
#     says about itself);
#   lease: `v` (2 when a vector-aware writer created it: set once, never added later), `res` {ram,
#     cpu, gpu, vram, disk, mem: {ask, min, got, used, peak, tree, w, dev, pool, unified}} (gb and
#     used_gb / peak_gb / baseline_gb stay as the memory mirrors 1.8 readers read; gb is 0 for a
#     lease without memory), `res_granted` (the time a vector-aware evaluator granted it: a v2
#     lease granted without it was granted by old code), `waiting_on` and `hold` (pool ids),
#     `base` and `last` (counters), `segments[].res` (amounts), `watch_also` [{pid, start}] and `watch_names` (more trees
#     charged to it), `holder.uid`, `holder.ns` (the holder's pid namespace: absent = the
#     reader's), `user` (the account's name), `scope` ("host" or a cgroup), `agent` {key, slot};
#   history record: `event` "grant", `res` {resource: amount, "disk_pool"} and `peak` {resource:
#     amount}, `v`, `agent`, `user`, `note`, outcomes "refused" and "volume_gone".
LEASE_RES = ("ram", "cpu", "gpu", "vram", "disk", "mem")  # a v2 lease's resources (02 §6.2)
_RES_NAME = re.compile(r"[a-z][a-z0-9_]{0,15}")  # a resource this code does not know: carried through, never used
RES_MAX = 16                              # resources in one `res`, known ones first
_RES_NUMS = ("ask", "min", "got", "used", "peak", "tree", "w")
_COUNTERS = ("t", "cpu_s", "gpu_s", "w_gb", "free_gb", "gpu_mem_gb")
_ID = re.compile(r"[\x21-\x7e]{1,80}")    # pool and device ids: compared as strings, never opened
_AGENT = re.compile(r"[0-9a-f]{8}")
_SESSION = re.compile(r"\d{1,10}@\d{1,15}")
AGENT_SLOTS = 6                           # the agent palette (02 §3.8.3)
WATCH_MAX, NAME_MAX = 8, 32               # watch_also / watch_names entries, characters of a name
MERGE_KEEP = ("res", "peak", "v", "agent", "user")  # what a later history record without them does not undo


def _int(x, lo, hi):
    return isinstance(x, int) and not isinstance(x, bool) and lo <= x <= hi


def _ver(x):
    """A format version (`v`): a small positive integer, else None (absent)."""
    return x if _int(x, 1, 1000) else None


def _str(n, pat=None):
    """A validator for a string of at most `n` characters (matching `pat`)."""
    return lambda x: x if isinstance(x, str) and 0 < len(x) <= n and (pat is None or pat.fullmatch(x)) else None


def _res_names(x):
    """The resources of a `res` this code keeps: the six it knows, then up to RES_MAX in all of
    those a later writer may add (a lowercase name), which are carried through and never counted."""
    known = [k for k in LEASE_RES if k in x]
    return known + [k for k in x if k not in LEASE_RES and k != "disk_pool" and isinstance(k, str)
                    and _RES_NAME.fullmatch(k)][:RES_MAX - len(known)]


def _res(x):
    """A lease's `res`: by resource a dict whose known fields have their types (amounts 0 … 1e6;
    `dev` an id or, for `mem`, an amount; `pool` an id; `unified` a bool). A mistyped field is
    dropped, an unknown one carried through like a lease's, and so is a resource added after this
    code (_res_names): a stale writer must not erase it from a live lease. None if empty."""
    if not isinstance(x, dict):
        return None
    out = {}
    for k in _res_names(x):
        e = x.get(k)
        if not isinstance(e, dict):
            continue
        o = dict(e)
        for f in _RES_NUMS:
            if f in o and not _num(o[f], 0, 1e6):
                del o[f]
        if "dev" in o and not (_num(o["dev"], 0, 1e6) or _str(80, _ID)(o["dev"])):
            del o["dev"]
        if "pool" in o and not _str(80, _ID)(o["pool"]):
            del o["pool"]
        if "unified" in o and not isinstance(o["unified"], bool):
            del o["unified"]
        out[k] = o
    return out or None


def _rec_amounts(x, extra=False):
    """A history record's or a segment's `res` (with `extra`, also its `disk_pool`) or `peak`:
    amounts by resource, those added after this code too (_res_names)."""
    if not isinstance(x, dict):
        return None
    out = {k: x[k] for k in _res_names(x) if _num(x.get(k), 0, 1e6)}
    if extra and _str(80, _ID)(x.get("disk_pool")):
        out["disk_pool"] = x["disk_pool"]
    return out or None


def _ids(x):
    """`waiting_on`, `hold`: a list of pool ids (empty is a value: nothing short)."""
    return x if isinstance(x, list) and len(x) <= 16 and all(_str(80, _ID)(p) for p in x) else None


def _counters(x):
    if not isinstance(x, dict):
        return None
    return {k: x[k] for k in _COUNTERS if _num(x.get(k), 0, 1e15)} or None


def _watch_also(x):
    if not (isinstance(x, list) and len(x) <= WATCH_MAX):
        return None
    out = [{"pid": w["pid"], "start": w.get("start") if _int(w.get("start"), 0, 1e15) else None}
           for w in x if isinstance(w, dict) and _pid(w.get("pid"))]
    return out if len(out) == len(x) else None


def _names(x):
    return x if isinstance(x, list) and len(x) <= WATCH_MAX and all(_str(NAME_MAX)(n) for n in x) else None


def _agent(x):
    """`agent` {key, slot}: an 8-digit hex key and, if any, a palette slot 0–5; anything else is
    "agent not known" (None). A writer can claim any key: the colour proves nothing (02 §3.8.2)."""
    if not (isinstance(x, dict) and isinstance(x.get("key"), str) and _AGENT.fullmatch(x["key"])):
        return None
    if "slot" in x and not _int(x["slot"], 0, AGENT_SLOTS - 1):
        return None
    return {k: x[k] for k in ("key", "slot") if k in x}


def _sessions(x):
    """The ledger root's `sessions`: entries keyed "<pid>@<start>" with a typed cwd, uid and seen."""
    if not isinstance(x, dict):
        return None
    out = {}
    for k, e in x.items():
        if _SESSION.fullmatch(k) and isinstance(e, dict):
            out[k] = {f: e[f] for f, ok in (("cwd", _str(4096)), ("uid", lambda u: _int(u, 0, 2 ** 32 - 1)),
                                           ("seen", _t)) if f in e and ok(e[f])}
    return out


V2_LEASE = {"v": _ver, "res": _res, "res_granted": lambda x: x if _t(x) else None, "waiting_on": _ids,
            "hold": _ids, "base": _counters, "last": _counters, "watch_also": _watch_also, "watch_names": _names,
            "user": _str(64), "scope": _str(200), "agent": _agent}
V2_RECORD = {"v": _ver, "res": lambda x: _rec_amounts(x, True), "peak": _rec_amounts, "agent": _agent,
             "user": _str(64), "note": _str(400)}
V2_ROOT = {"v": _ver, "boot": _str(64, _ID), "sessions": _sessions}


def _checked(src, out, checks):
    """Fields with a validator: replaced by the validated value, or dropped (absent) when it fails."""
    for k, ok in checks.items():
        if k in src:
            v = ok(src[k])
            if v is None:
                out.pop(k, None)
            else:
                out[k] = v
    return out


def ledger_version(x):
    """The format version of a ledger, lease or record: 1 when it says none (everything 1.8 wrote)."""
    return _ver(x.get("v")) or 1


def agent_key(pid, start):
    """The stable key of an agent (D11, 02 §3.8.2): the first 8 hex digits of SHA-256 over
    "oomph-agent:<pid>:<start>" of the agent's process (a Claude session, also for an `oomph run`
    inside it, else the holder). The same for every reservation of one session, different after
    it restarts, and it says nothing the lease does not. None while the start time is unknown."""
    if not (_pid(pid) and _int(start, 0, 10 ** 15)):
        return None
    import hashlib
    return hashlib.sha256(("oomph-agent:%d:%d" % (pid, start)).encode()).hexdigest()[:8]


def _agent_of(r, procs):
    """The agent key of a lease an older writer made without one: its holder's, or for an
    `oomph run` still running inside a Claude session (this pid namespace) the session's."""
    h = r["holder"]
    p = procs.get(h["pid"])
    if h.get("kind") == "run" and p and p.get("start") == h.get("start") and _in_own_ns(r):
        root = _session_root(procs, h["pid"])
        if root is not None and root != h["pid"]:
            return agent_key(root, procs[root].get("start"))
    return agent_key(h["pid"], h.get("start"))


def lease_res(r):
    """A lease's resources as vector-aware code reads them (02 §9.2): a v2 lease's own `res`, its
    `ram` following `gb` where an old writer's amend changed only the mirror; for a 1.8 lease, a
    vector of memory only made from gb, used_gb and peak_gb. Made here, never written back: an
    old lease does not become version 2."""
    if ledger_version(r) >= 2 and isinstance(r.get("res"), dict):
        res = {k: dict(x) for k, x in r["res"].items()}
        mem = res.get("mem", {})
        if _num(mem.get("got")) and abs(mem["got"] - r["gb"]) > 0.005:
            v = res.get("vram", {})
            on_gpu = min(v.get("got", 0), r["gb"]) if v.get("unified") else 0
            if v.get("unified") and _num(v.get("got")) and v["got"] > r["gb"]:  # unified memory is in gb too
                res["vram"] = dict(v, got=r["gb"])
            res["ram"] = dict(res.get("ram", {}), ask=round(max(0.0, r["gb"] - on_gpu), 2))
            if "got" in res["ram"] or r.get("state") == "granted":
                res["ram"]["got"] = res["ram"]["ask"]
            res["mem"] = dict(mem, got=r["gb"])
        return res
    granted = r.get("state") == "granted" or (r.get("state") is None and r.get("granted") is not None)
    ram = {"ask": r["gb"]}
    mem = {"got": r["gb"]}
    if granted:
        ram["got"] = r["gb"]
    for f, g in (("used", "used_gb"), ("peak", "peak_gb")):
        if _num(r.get(g)):
            mem[f] = r[g]
    return {"ram": ram, "mem": mem}


def _record_vector(r):
    """What an end, edit or history entry carries of a newer writer's lease beyond 1.8.1's fields:
    its `v`, `user` and, from a v2 lease's `res`, the amounts granted (asked, if never granted) and
    the peaks by resource. Nothing for a 1.8 lease. A finished entry passes its own on."""
    out = {k: r[k] for k in ("v", "user") if k in r}
    res = r.get("res")
    if not isinstance(res, dict):
        return out
    if not any(isinstance(x, dict) for x in res.values()):  # already a record's
        out.update((k, r[k]) for k in ("res", "peak") if k in r)
        return out
    if "gb" in r and ledger_version(r) >= 2:  # a lease: ram follows gb where an old writer's amend moved only the mirror
        res = lease_res(r)
    amounts, peak = {}, {}
    for k, x in res.items():
        if k == "mem" or not isinstance(x, dict):  # memory is the gb and peak_gb mirrors
            continue
        a = x.get("got", x.get("ask"))
        if _num(a):
            amounts[k] = a
        if _num(x.get("peak")):
            peak[k] = x["peak"]
        if k == "disk" and isinstance(x.get("pool"), str):
            amounts["disk_pool"] = x["pool"]
    if amounts:
        out["res"] = amounts
    if peak:
        out["peak"] = peak
    return out


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
            and _num(r.get("gb"), 0, 1e6) and isinstance(r.get("purpose"), str)
            and isinstance(h, dict) and _pid(h.get("pid")) and _t(r.get("requested"))):
        return None
    if r["state"] == "granted" and not _t(r.get("granted")):
        return None
    if r["gb"] == 0 and not ledger_version(r) >= 2:  # only a vector lease may hold no memory
        return None
    out = dict(r)
    start = h.get("start")
    out["holder"] = dict(h, start=start if isinstance(start, int) and not isinstance(start, bool) else None,
                         kind=h["kind"] if isinstance(h.get("kind"), str) else None)
    for k, lo, hi in (("uid", 0, 2 ** 32 - 1), ("ns", 1, 2 ** 64 - 1)):
        if k in h and not _int(h[k], lo, hi):
            del out["holder"][k]
    out["seen"] = r["seen"] if _t(r.get("seen")) else r["requested"]
    _typed(r, out, times=("granted", "expires"), nums=("ttl", "peak_gb", "used_gb", "baseline_gb"),
           strs=("project", "key", "note"))
    _checked(r, out, V2_LEASE)
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
    _checked(h, out, V2_RECORD)
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
    return _checked(L, out, V2_ROOT)


def _ledger_dir(create=False):
    """A descriptor of LEDGER_DIR, opened without following a symbolic link (anyone who could
    replace the directory by a link would otherwise choose where everything goes); every file
    in it is opened relative to it. None if it doesn't exist and `create` is false."""
    _not_root("opening %s" % LEDGER_DIR)
    if create and not os.path.lexists(LEDGER_DIR):
        mode = PATHS_HERE["ledger_mode"]
        old = os.umask(0 if mode == 0o777 else 0o077)
        try:  # on a Mac shared by every session (and user); on Linux, for now, the user's own
            os.makedirs(LEDGER_DIR, mode=mode, exist_ok=True)
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
    L = _valid_ledger(loads_untrusted(read_bounded("ledger.json", LIMITS["ledger"], dfd, shared=True)))
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
#    "requested", "granted", "peak_gb", and for "end": "ended", "outcome"; for "edit": "change", "expires";
#    from 1.9.2 "agent" {key} when the holder's start time is known (D11)}
# Readers merge the records of a key (merge_history): from 1.9.2 on, newer writers add a "grant" record
# and fields that a 1.8 writer ending the same reservation leaves out. `key` stays unique across ledger
# resets: it carries the request time.
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
        data = read_bounded(HISTORY_FILE, LIMITS["history"], dfd, tail=True, shared=True)
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


def merge_history(recs):
    """The history log's records merged per key, in the order keys first appear (02 §9.2): a later
    record overrides the fields it has, an "end" is never undone by a later record that is not
    one, and `res`, `peak`, `v`, `agent` and `user` stay from an earlier record when a later one
    lacks them. So a vector reservation stays a vector when a 1.8 process, which knows none of
    these, writes its end. A record without `event` is an end (as 1.8.1 read it)."""
    by = {}
    for rec in recs:
        ev = rec["event"] if isinstance(rec.get("event"), str) else "end"
        prev = by.get(rec["key"])
        if prev is None:
            by[rec["key"]] = dict(rec, event=ev)
        elif ev == "end" or prev["event"] != "end":
            prev.update((k, x) for k, x in rec.items() if not (x is None and k in MERGE_KEEP))
            prev["event"] = ev
    return list(by.values())


def _record(r, event, t, **extra):
    h = r.get("holder")  # a live lease's holder, or a finished one's holder kind
    rec = {"event": event, "t": round(t, 1), "key": _key(r), "id": r["id"], "purpose": r["purpose"],
           "project": r.get("project"), "holder": h.get("kind") if isinstance(h, dict) else h,
           "gb": r["gb"], "requested": r["requested"], "granted": r.get("granted"),
           "peak_gb": round(r.get("peak_gb", 0) or 0, 2)}
    if len(r.get("segments") or []) > 1:
        rec["segments"] = r["segments"]
    if r.get("agent"):
        rec["agent"] = r["agent"]
    rec.update(_record_vector(r))
    rec.update(extra)
    return rec


def _append_history(L, recs, now):
    """Add records to the log, under the ledger lock. No writer opens the log's existing name for
    writing: a hard link planted there would turn an append into a write to another user's
    file, and no open flag can refuse a hard link. So every write reads the log (its newest
    LIMITS["history"] bytes, a file with a single link that everyone may read: read_bounded's
    `shared`), keeps the records of the last HISTORY_DAYS that have the shape of oomph's own (what
    every reader keeps), adds the new ones, drops the oldest beyond LIMITS["history"] bytes and
    renames a fresh file over the name. The format stays one record per line: readers, and
    1.8.1–1.8.3 writers (which append under the same lock), work on it unchanged. A new log is
    seeded with the ledger's own short history."""
    _not_root("writing the history log")
    if _held is None:
        raise LedgerError("the history log is written under the ledger lock only")
    dfd = _held.dfd
    data = read_bounded(HISTORY_FILE, LIMITS["history"], dfd, tail=True, shared=True)
    cutoff = now - HISTORY_DAYS * 86400
    lines = []
    for line in (data or b"").splitlines():
        rec = _valid_finished(loads_untrusted(line), log=True)  # shaped like oomph's records, or dropped
        if rec and _rec_time(rec) >= cutoff:
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


_NS = []


def _own_ns():
    """The inode of this process's pid namespace (Linux), None where there are none (macOS)."""
    if not _NS:
        try:
            _NS.append(os.stat("/proc/self/ns/pid").st_ino)
        except OSError:
            _NS.append(None)
    return _NS[0]


def _in_own_ns(r):
    """Is a lease's holder in this process's pid namespace (a lease without `holder.ns` is)?"""
    ns = r["holder"].get("ns")
    return ns is None or ns == _own_ns()


def _held_by(r, pid):
    """Is a lease held by process `pid` of this pid namespace? The same number in a container is
    another process (03 §7.3)."""
    return pid is not None and r["holder"]["pid"] == pid and _in_own_ns(r)


TTL_CAP_S = 7 * 86400  # the longest time limit any version may set (MAX_TTL_S is this one's)


def _holder_gone(r, procs, now):
    """Has a lease's holder ended? By its pid and start time, for a holder in this pid namespace
    (a lease without `holder.ns` is in the reader's). A pid of another namespace means something
    else here (03 §7.3): such a lease ends by its time limit or, without one, when its owner
    stops stamping `seen` for QUEUE_STALE_S (`oomph run` does every 5 s). A time limit further off
    than the lease's own ttl from when it was last granted or renewed (`seen`; TTL_CAP_S at most,
    so a later version may raise MAX_TTL_S without this one retiring its grants) is not one:
    anyone can write the ledger, and a lease no pid can end must not outlive what a grant could."""
    h = r["holder"]
    if not _in_own_ns(r):
        if r["state"] != "granted":
            return False  # a request lapses when its owner stops polling
        if r.get("expires"):
            ttl = min(r["ttl"], TTL_CAP_S) if _num(r.get("ttl"), 0) else MAX_TTL_S
            return r["expires"] > max(r["seen"], r["granted"]) + ttl + 60
        return now - r["seen"] > QUEUE_STALE_S
    return not _alive(procs, h["pid"], h.get("start"))


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
    if r.get("agent"):
        h["agent"] = r["agent"]
    h.update(_record_vector(r))
    L["history"].append(h)
    L["history"] = L["history"][-HISTORY_KEEP:]
    try:
        _append_history(L, [_record(r, "end", now, ended=end, outcome=outcome)], now)
    except OSError:
        pass  # the log is a record, not the ledger: never let it block coordination


def _evaluate(L, s, procs, now):
    """Drop dead, expired and abandoned entries, account for what grants already use, then grant
    queued requests strictly in arrival order while they fit.

    Leases of version 2 (newer writers, 02 §9.3) count with their memory mirror (gb) like any
    other, but this code grants none: it cannot weigh their other resources. A queued one holds
    the line, as a request that does not fit does, until vector-aware code (the logger's child
    after an update, or its own writer's next poll) grants it. A request of another scope (a
    cgroup, 03 §7.3) is granted only by a process in it, and does not hold the line here."""
    keep = []
    for r in L["leases"]:
        why = None
        if not r.get("agent"):  # made by a writer older than 1.9.2: its agent, from the holder (D11)
            k = _agent_of(r, procs)
            if k:
                r["agent"] = {"key": k}
        if _holder_gone(r, procs, now):
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
        if r.get("scope", "host") != "host":
            continue
        if ledger_version(r) >= 2:
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
    return s, plat().collect_procs(), time.time()


def _brief(r, now):
    b = {"id": r["id"], "state": r["state"], "gb": r["gb"], "purpose": r["purpose"],
         "project": os.path.basename(r.get("project") or "") or None, "holder_pid": r["holder"]["pid"]}
    if r.get("user"):
        b["user"] = r["user"]
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
        if h and h["outcome"] == "refused":  # a newer evaluator turned it down (03 §6.5)
            return {"status": "refused", "id": rid, "outcome": "refused", "note": h.get("note"),
                    "advice": "Turned down: this request cannot fit on this machine even with nothing else reserved"
                              "%s. Ask for less, or split the work." % (" (%s)" % h["note"] if h.get("note") else "")}
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
    d = plat()
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
            k = holder.get("agent")  # `oomph run` inside a session: the session's (02 §3.8.2)
            k = k if isinstance(k, str) and _AGENT.fullmatch(k) else agent_key(holder.get("pid"), holder.get("start"))
            if k:
                r["agent"] = {"key": k}
            L["leases"].append(r)
        else:
            r["seen"] = round(now, 1)
            if r["state"] == "granted" and r.get("expires") and ttl_s:  # re-asking extends a grant
                r["ttl"] = min(max(60, ttl_s), MAX_TTL_S)  # the limit the grant now has (_holder_gone)
                r["expires"] = round(now + r["ttl"], 1)
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
        gone = [r for r in L["leases"] if r["id"] == rid or (rid == "all" and _held_by(r, holder_pid))]
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
        own = [r for r in L["leases"] if _held_by(r, mine)]
        others = [r for r in L["leases"] if r not in own]
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
    last = {rec["key"]: rec for rec in merge_history(read_history()) if _rec_time(rec) >= now - since_s}
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


VIEW_FIELDS = ("event", "key", "id", "purpose", "project", "holder", "gb", "requested", "granted", "ended",
               "outcome", "peak_gb", "used_gb", "expires", "segments")


def _view_records(recs, since):
    """The history log's records as a viewer merges them (merge_history, as oomph_view.merge_reservations
    and the app do), those that end at or after `since`, with only the fields the viewers read. One
    record per reservation keeps a root caller's answer far below LIMITS["child"]."""
    return [{f: r[f] for f in VIEW_FIELDS if f in r} for r in merge_history(recs) if _rec_time(r) >= since]


@_unprivileged()
def ledger_view(since=None):
    """What a dashboard (`oomph top`) shows of the ledger, read only: the ledger as it is (None when
    there is none or it was refused) and the history log's reservations that end at or after the
    unix time `since` (default: HISTORY_DAYS ago), one record each (_view_records). The caller's
    clock decides the window, so a frame drawn for a fixed time stays the same. Unlike read_ledger,
    never the whole log to continue a numbering: a viewer needs none."""
    if since is None:
        since = time.time() - HISTORY_DAYS * 86400
    try:
        dfd = _ledger_dir()
    except LedgerError:
        dfd = None  # replaced by a link: nothing to read
    if dfd is None:
        return {"ledger": None, "records": []}
    try:
        L = _valid_ledger(loads_untrusted(read_bounded("ledger.json", LIMITS["ledger"], dfd, shared=True)))
        return {"ledger": L, "records": _view_records(read_history(dfd=dfd), since)}
    finally:
        os.close(dfd)


@_unprivileged()
def refresh_ledger(s, procs):
    """The daemon's tick: retire leases whose holder died or that expired, close to when it
    happened, and keep the usage figures current. Skips the lock when nothing is reserved."""
    if not read_ledger()["leases"]:
        return
    with Ledger() as L:
        _evaluate(L, s, procs, time.time())


PROC_KEYS = ("pid", "ppid", "uid", "name", "start", "fp", "rss", "path")  # what the ledger's child is told of a process


def ledger_tick(s, procs, timeout=TICK_TIMEOUT_S):
    """The daemon's ledger work for one sample: refresh_ledger, then the snapshot of live
    reservations for the sample, both in a child — as nobody when the daemon is root (root
    never opens anything in the shared directory, to read or to write), as the same user when
    it isn't. Its answer is at most LIMITS["tick"] bytes of JSON, read within `timeout`, and the
    sample's block is rebuilt from it field by field (sample_leases). Returns (leases, error
    or None). The daemon calls this from a thread of its own: the sampler never waits on it."""
    payload = json.dumps({"s": s, "procs": [{k: p[k] for k in PROC_KEYS if k in p} for p in procs.values()]},
                         default=str).encode()
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


def _live(r, now):
    """Does a lease still count: not a grant past its expiry, not a queued entry gone stale."""
    if r["state"] == "granted" and r.get("expires") and now > r["expires"]:
        return False
    return not (r["state"] == "queued" and now - r["seen"] > QUEUE_STALE_S)


@_unprivileged()
def ledger_live_count():
    """How many leases count (as ledger_snapshot sees them), for doctor; raises what the read raises."""
    now = time.time()
    return sum(1 for r in read_ledger()["leases"] if _live(r, now))


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
        if procs is not None and _holder_gone(r, procs, now):
            continue
        if not _live(r, now):
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


def _fmt_brief(b, purpose_w=22):
    """A reservation as one row: id, state, size, purpose (cut at the end), project (cut in the
    middle, 10), what it uses or how long it waits. 78 columns with the default budget."""
    tail = ("using %.1fG, %.0f min" % (b.get("used_gb", 0), b["for_min"]) if b["state"] == "granted"
            else "waiting %.0f min" % b["waiting_min"])
    return "%-5s %-7s %5.1fG  %-*s %-10s %s" % (b["id"], b["state"], b["gb"], purpose_w, cut_end(b["purpose"], purpose_w),
                                               cut_middle(b.get("project") or "", 10), tail)


def _opt(args, name, default=None):
    return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else default


class UsageError(Exception):
    """A command line this oomph can't take as given: an option it doesn't know, a missing value,
    an argument too many, a size that isn't one. The command prints it with its usage, exit 2."""


def _strict(args, takes=(), flags=(), npos=1):
    """Parses args for commands whose numbers matter (reserve, run, amend, release): options in
    `takes` take the next argument as their value, `flags` stand alone, at most `npos`
    positionals. Anything else is refused rather than guessed at, so that an option from a
    newer oomph (`--cpu 8`) never turns its number into gigabytes. Returns (opts, positionals)."""
    opts, pos, i = {}, [], 0
    while i < len(args):
        a = args[i]
        if a in takes:
            if i + 1 >= len(args):
                raise UsageError("%s needs a value" % a)
            opts[a], i = args[i + 1], i + 2
            continue
        if a in flags:
            opts[a] = True
        elif a.startswith("-") and a != "-" and not a[1:2].isdigit() and a[1:2] != ".":
            raise UsageError("unknown option %s" % a)  # -1G is a (negative) size: the ledger answers it
        else:
            pos.append(a)
        i += 1
    if len(pos) > npos:
        raise UsageError("unexpected argument %s" % pos[npos])
    return opts, pos


def _size(x):
    """A size argument in GB (6G, 512M, 1.5), or UsageError. Whether it is a size the ledger
    accepts (more than 0, less than 90 % of RAM) is the ledger's to answer, with its advice."""
    try:
        gb = _parse_gb(x)
    except ValueError:
        gb = None
    if gb is None or not math.isfinite(gb):
        raise UsageError("not a size: %s (use e.g. 6G or 512M)" % x)
    return gb


def _usage_error(cmd, e, text):
    sys.stderr.write("oomph %s: %s\n%s\n" % (cmd, e, text))
    return 2


RESERVE_USAGE = "usage: oomph reserve <size, e.g. 6G> --for \"what\" [--wait 10m] [--ttl 30m] [--ticket rN] [--json]"
RELEASE_USAGE = "usage: oomph release <id | all>   (all = every reservation held by this session)"
AMEND_USAGE = "usage: oomph amend <id> [--gb 3G] [--ttl 20m] [--for \"what\"] [--json]"
RUN_USAGE = "usage: oomph run --reserve 6G [--for \"what\"] [--wait 30m] -- <command> [args…]"


def cmd_reserve(args):
    try:
        o, pos = _strict(args, ("--for", "--wait", "--ttl", "--ticket", "--pid"), ("--json", "--help", "-h"))
        ticket = o.get("--ticket")
        if "--help" in o or "-h" in o or (not pos and not ticket):
            print(RESERVE_USAGE)
            return 2
        gb = _size(pos[0]) if pos else 0
        pid = o.get("--pid")
        if pid is not None and not pid.isdigit():
            raise UsageError("--pid takes a process id, not %s" % pid)
    except UsageError as e:
        return _usage_error("reserve", e, RESERVE_USAGE)
    holder = holder_for(int(pid) if pid is not None else None)
    st = acquire(gb, o.get("--for", "unspecified"), holder, parse_dur(o.get("--ttl", "30m")),
                 parse_dur(o.get("--wait", "0s")), ticket)
    if "--json" in o:
        print(json.dumps(st))
    else:
        print(wrap("%s %s — %s" % (st["status"].upper(), st.get("id", ""), st["advice"]), first="oomph: "))
        for b in st.get("ahead") or []:
            print("  ahead: " + _fmt_brief(b, 15))
        if st.get("note"):
            print(wrap(st["note"], first="  note: "))
    return 0 if st["status"] == "granted" else 75


def cmd_release(args):
    try:
        o, pos = _strict(args, flags=("--json", "--help", "-h"))
    except UsageError as e:
        return _usage_error("release", e, RELEASE_USAGE)
    if not pos or "--help" in o or "-h" in o:
        print(RELEASE_USAGE)
        return 2
    res = release(pos[0], holder_for()["pid"] if pos[0] == "all" else None)
    if "--json" in o:
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
    try:
        o, pos = _strict(args, ("--gb", "--ttl", "--for"), ("--json", "--help", "-h"))
        if not pos or not any(k in o for k in ("--gb", "--ttl", "--for")) or "--help" in o or "-h" in o:
            print(AMEND_USAGE)
            return 2
        gb = _size(o["--gb"]) if "--gb" in o else None
    except UsageError as e:
        return _usage_error("amend", e, AMEND_USAGE)
    rid = pos[0]
    st = amend(rid, gb, parse_dur(o["--ttl"]) if "--ttl" in o else None, o.get("--for"))
    if "--json" in o:
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
    print(wrap("free %.1fG − reserved %.1fG − margin %.1fG = %.1fG available for new reservations" % (
        c["free_gb"], c["reserved_gb"], c["margin_gb"], c["available_gb"])))
    rows = [("me", b) for b in c["mine"]] + [("", b) for b in c["others"]]
    if rows:
        print("\nactive:")
        for who, b in sorted(rows, key=lambda x: (x[1]["state"] != "granted", x[1]["id"])):
            print("  %-3s %s" % (who, _fmt_brief(b, 18)))
    else:
        print("\nno active reservations")
    if c["history"]:
        print("\nrecent (reserved → peak actually added):")
        for h in c["history"][:10]:
            print("  %-5s %5.1fG → %4.1fG  %-20s %-10s %-11s held %s" % (
                h["id"], h["gb"], h["peak_gb"], cut_end(h["purpose"], 20), cut_middle(h.get("project") or "", 10),
                h["outcome"], "%dm%02ds" % divmod(h["held_s"], 60)))
    return 0


def cmd_run(args):
    if "--" not in args or "--reserve" not in args:
        print(RUN_USAGE)
        return 2
    i = args.index("--")
    cmd = args[i + 1:]
    try:
        opts, _ = _strict(args[:i], ("--reserve", "--for", "--wait"), npos=0)
        gb = _size(opts["--reserve"]) if "--reserve" in opts else None
    except UsageError as e:
        return _usage_error("run", e, RUN_USAGE)
    if gb is None:
        print(RUN_USAGE)
        return 2
    if not cmd:
        print("oomph run: no command given")
        return 2
    import signal
    purpose = opts.get("--for") or " ".join(os.path.basename(c) if j == 0 else c for j, c in enumerate(cmd[:3]))
    wait_s = parse_dur(opts.get("--wait", "30m"))
    ses = holder_for()
    me = {"pid": os.getpid(), "start": plat().collect_procs().get(os.getpid(), {}).get("start"),
          "kind": "run", "project": ses["project"] if ses["kind"] == "session" else os.getcwd(),
          "agent": agent_key(ses["pid"], ses["start"]) if ses["kind"] == "session" else None}
    last = [0.0]

    def progress(st):
        if time.time() - last[0] >= 30:
            last[0] = time.time()
            ahead = ", ".join("%s %.1fG %s (%s)" % (b["id"], b["gb"], b["purpose"], b.get("project") or "?")
                              for b in st.get("ahead", [])[:3])
            sys.stderr.write(wrap("waiting for %.1fG — queued #%s, %.1fG available%s" % (
                gb, st.get("position"), st.get("available_gb") or 0, "; ahead: " + ahead if ahead else ""),
                first="oomph: ") + "\n")
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
     "inputSchema": {"type": "object", "required": ["gb", "purpose"], "additionalProperties": False, "properties": {
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
     "inputSchema": {"type": "object", "required": ["id"], "additionalProperties": False,
                     "properties": {"id": {"type": "string"}}}},
    {"name": "update_reservation",
     "description": "Change a reservation (granted or queued) in place: a new size in GB, a new time to live "
                    "(counted from now: shorter or longer), or a new purpose. Shrink as soon as the heaviest part is "
                    "over, so others can start. Shrinking applies at once. Growing a granted reservation applies only "
                    "if the extra memory fits right now and nobody is queued; otherwise it is refused (status refused, "
                    "nothing changes, your grant stays) and you should reserve the extra separately with "
                    "reserve_memory, which queues fairly. Growing a queued request moves it to the back of the queue. "
                    "To end a reservation use release_memory.",
     "inputSchema": {"type": "object", "required": ["id"], "additionalProperties": False, "properties": {
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
     "description": "Recorded memory incidents (needs the %s daemon): id, start, triggers, peak swap, minimum free "
                    "disk, jetsam kills. Use after unexplained process deaths or an 'out of application memory' "
                    "dialog." % BRAND,
     "inputSchema": {"type": "object", "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50, "default": 10}}}},
    {"name": "incident",
     "description": "Full summary of one incident ('latest' or an id): timeline facts, biggest risers, processes and "
                    "Claude sessions at the peak, most-killed services, and the path of its HTML report.",
     "inputSchema": {"type": "object", "properties": {"id": {"type": "string", "default": "latest"}}}},
]


class ToolArgError(ValueError):
    """A tool call's arguments don't fit its schema; the caller gets an error result saying so."""


_MCP_NEEDS = {"reserve_memory": ("gb",)}  # purpose is asked for, but a call without it is "unspecified"


def _mcp_args(name, a):
    """Refuses what the tool's schema doesn't allow: a missing argument the call can't do without,
    or, where the schema closes it (the reservation tools), one it doesn't know. A client written
    for a newer oomph that sends `cpu` is told so instead of having its request read as memory
    alone. A re-poll with {gb, ticket} and no purpose keeps working as it always has."""
    tool = next((t for t in MCP_TOOLS if t["name"] == name), None)
    if tool is None:
        raise KeyError(name)
    if not isinstance(a, dict):
        raise ToolArgError("%s takes an object of arguments" % name)
    sch = tool["inputSchema"]
    missing = [k for k in _MCP_NEEDS.get(name, sch.get("required", ())) if k not in a]
    if missing:
        raise ToolArgError("%s needs %s" % (name, ", ".join(missing)))
    extra = sorted(k for k in a if k not in sch["properties"]) if sch.get("additionalProperties") is False else []
    if extra:
        raise ToolArgError("%s takes no argument %s (it takes %s)" % (
            name, ", ".join(extra), ", ".join(sch["properties"])))


def _mcp_call(name, a):
    _mcp_args(name, a)
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
            return {"error": "no such incident (is the %s daemon installed?)" % BRAND}
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
                          "serverInfo": {"name": CMD, "title": BRAND, "version": VERSION},
                          "instructions": BRAND + " reports this Mac's memory, swap and disk, and coordinates memory between "
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
                except (LedgerError, ToolArgError) as e:  # busy, refused, or arguments it can't take: say so plainly
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


# ------------------------------------------------------------------ doctor
DOCTOR_LEVELS = ("ok", "note", "warn", "fail")  # fail: oomph cannot work here at all


def _version_in(path):
    """The VERSION stamped into an installed oomph.py, or None."""
    data = read_bounded(path, 1 << 20)
    m = re.search(rb'^VERSION = "([^"]*)"', data or b"", re.M)
    return m.group(1).decode("utf-8", "replace") if m else None


def _logger_state():
    """(current.json or None, is it fresh) of the log directory."""
    data = read_bounded(os.path.join(LOG_DIR, "current.json"), 1 << 20)
    c = loads_untrusted(data) if data else None
    if not isinstance(c, dict) or not _num(c.get("t")):
        return None, False
    d = c.get("daemon") if isinstance(c.get("daemon"), dict) else {}
    iv = d.get("interval") if _num(d.get("interval")) else 30
    return c, time.time() - c["t"] < 3 * iv + 10


def _claude_setup():
    """What `oomph setup-claude` set up for this user: the skill (and whether it is this oomph's),
    the MCP server in ~/.claude.json, the hook in ~/.claude/settings.json. Bounded reads: under
    sudo HOME can be the invoking user's, though doctor skips this as root."""
    home = os.path.expanduser("~")
    got = {}
    skill = read_bounded(os.path.join(home, ".claude", "skills", CMD, "SKILL.md"), 1 << 20)
    src = _skill_source()
    got["skill"] = skill is not None
    got["skill_current"] = skill is not None and src is not None and read_bounded(src, 1 << 20) == skill

    def user_json(path):  # the user's own files, often big: plain JSON within a generous cap
        try:
            return json.loads((read_bounded(path, 32 << 20) or b"").decode("utf-8"))
        except (ValueError, RecursionError):
            return None

    cfg = user_json(os.path.join(home, ".claude.json"))
    got["mcp"] = isinstance(cfg, dict) and isinstance(cfg.get("mcpServers"), dict) and CMD in cfg["mcpServers"]
    st = user_json(os.path.join(home, ".claude", "settings.json"))
    hooks = st.get("hooks") if isinstance(st, dict) else None
    post = hooks.get("PostToolUse") if isinstance(hooks, dict) else None
    cmds = [x.get("command") for h in (post if isinstance(post, list) else []) if isinstance(h, dict)
            for x in (h.get("hooks") if isinstance(h.get("hooks"), list) else []) if isinstance(x, dict)]
    got["hook"] = any(isinstance(c, str) and c.endswith(" hook") and CMD in c for c in cmds)
    return got


def doctor():
    """What works on this machine and what to fix (roadmap 03 §3.2): one check per ability,
    each ok, note (nothing to do), warn (fixable where you stand) or fail (oomph cannot work
    here), with the fix. Opens nothing in the shared ledger folder as root, like everything else."""
    checks, root = [], os.geteuid() == 0
    mac = sys.platform == "darwin"

    def add(cid, level, text, fix=None):
        checks.append(dict({"id": cid, "level": level, "text": text}, **({"fix": fix} if fix else {})))

    py = "%d.%d.%d" % sys.version_info[:3]
    if sys.version_info < (3, 9):
        add("python", "fail", "%s at %s: needs 3.9 or newer" % (py, sys.executable))
    elif mac and not os.access(PY, os.X_OK):
        add("python", "warn", "%s at %s, but the logger needs %s" % (py, sys.executable, PY), "xcode-select --install")
    else:
        add("python", "ok", "%s at %s (needs 3.9 or newer)" % (py, sys.executable))

    machine, P = None, None
    try:
        P = plat()
        machine = P.machine(all_procs=root)
        sysm = P.system_memory()
        add("memory", "ok", "%s · %.0f GB RAM" % ("vm_stat and sysctl" if mac else P.OS, sysm.get("ram_gb") or 0))
        procs = P.collect_procs()
        add("processes", "ok", "%d visible, %d with a footprint" % (len(procs), sum(1 for p in procs.values() if p.get("fp"))))
    except Unsupported as e:
        add("memory", "fail", str(e))
    except Exception as e:  # noqa: B902  a collector that breaks is a finding, not a crash
        add("memory", "warn", "measuring failed: %s" % repr(e)[:200])

    c, fresh = _logger_state()
    d = c.get("daemon") if c and isinstance(c.get("daemon"), dict) else {}
    installed = os.path.exists(PATHS_HERE["service"])
    kick = "sudo launchctl kickstart -k system/local.oomph.daemon" if mac else "sudo systemctl restart oomphd"
    if fresh:
        if d.get("root") or not mac:
            add("logger", "ok", "running (pid %s), every %s s, writes %s" % (d.get("pid"), d.get("interval"), LOG_DIR))
        else:
            add("logger", "warn", "running without root: other users' processes are missing from %s" % LOG_DIR,
                "sudo ./install.sh, or Activate in the menu-bar app")
    elif installed:
        when = time.strftime("%H:%M", time.localtime(c["t"])) if c else "never"
        add("logger", "warn", "installed but silent (last sample: %s)" % when,
            "%s; the reason is in %s/daemon.err" % (kick, LOG_DIR) if mac else kick)
    else:
        add("logger", "note", "not installed: nothing is logged, every reading is live",
            "Activate in the menu-bar app, or sudo ./install.sh from a checkout" if mac else None)

    inst = _version_in(os.path.join(PATHS_HERE["libexec"], "oomph.py"))
    run_v = d.get("version") if fresh else None
    if fresh and inst and run_v != inst:
        add("versions", "warn", "the logger runs %s, the installed copy is %s" % (run_v, inst), kick)
    elif inst and inst != VERSION:
        add("versions", "note", "this is %s (%s), the installed copy is %s" % (VERSION, HERE, inst))
    elif inst:
        add("versions", "ok", "%s everywhere: this command, the installed copy%s" % (
            VERSION, " and the logger" if fresh else ""))
    else:
        add("versions", "note", "this is %s (%s); nothing installed" % (VERSION, HERE))

    add(*_doctor_ledger(root))

    if os.path.lexists(CONFIG_FILE):
        cfg = read_config()
        add("config", "ok" if cfg else "warn", "%s: %s" % (
            CONFIG_FILE, "%d setting(s)" % len(cfg) if cfg else "ignored: not root's, or writable by others, or not JSON"),
            None if cfg else "sudo chown root %s; sudo chmod 644 %s" % (CONFIG_FILE, CONFIG_FILE))
    if mac:
        add(*_doctor_gpu(c if fresh else None, kick))

    if root:  # the Claude setup is the user's own: their files, read as them
        add("claude", "note", "not checked as root", "oomph doctor without sudo checks your Claude setup")
    else:
        cs = _claude_setup()
        parts = ["skill %s" % ("installed" if cs["skill"] else "not installed"),
                 "MCP %s" % ("registered" if cs["mcp"] else "not registered"),
                 "hook %s" % ("installed" if cs["hook"] else "not installed")]
        if cs["skill"] and not cs["skill_current"]:
            parts[0] = "skill installed, but not this version's"
        add("claude", "ok" if cs["skill_current"] and cs["mcp"] else "note", " · ".join(parts),
            None if cs["skill_current"] and cs["mcp"] else "oomph setup-claude (--hook for the hook)")

    worst = max([DOCTOR_LEVELS.index(x["level"]) for x in checks] + [0])
    code = 2 if worst == 3 else 1 if worst == 2 else 0
    return {"version": VERSION, "machine": machine,
            "ledger": {"kind": "shared" if mac else "user", "path": LEDGER_DIR,
                       "members": "every account on this Mac" if mac else None},
            "checks": checks, "exit": code}


IOREPORT_OFF = {"crashes": "the IOReport helper crashed four times since the Mac started and stays off until the next "
                           "restart or macOS update",
                "shape": "60 GPU readings in a row did not fit this Mac; off until the next restart or macOS update",
                "missing": "switched on, but the logger found no IOReport helper (oomph_ioreport.py) next to it; "
                           "reinstall %s" % BRAND,
                "failed": "switched on, but the logger could not set the figure up (its daemon_error events say why)",
                "unavailable": "this Mac reports no GPU performance states (an Intel Mac or a VM)",
                "table": "this Mac's device tree has no usable GPU frequency table"}


def _no_full_speed():
    """True where the full-speed figure cannot work, so doctor does not suggest switching it on: an
    Intel Mac or a VM, whose device tree has no usable GPU frequency table (asked of the device tree,
    not of uname: a Python under Rosetta says x86_64 on Apple silicon)."""
    try:
        t = plat().gpu_dvfs_mhz()
    except Exception:
        return False
    return not (isinstance(t, list) and sum(1 for f in t if isinstance(f, (int, float)) and f > 0) >= 2)


def _doctor_gpu(c, kick):
    """The GPU's full-speed figure: opt-in in 1.9.3 (IOReport, in a helper that runs as nobody).
    `c`: the logger's current sample when it is fresh, which says what the logger does."""
    d = c.get("daemon") if c and isinstance(c.get("daemon"), dict) else {}
    state = d.get("ioreport") if isinstance(d.get("ioreport"), str) else None
    gpus = c.get("gpu") if c and isinstance(c.get("gpu"), list) else []
    full = any(isinstance(g, dict) and g.get("src") == "ioreport" for g in gpus)
    if state in IOREPORT_OFF:
        return "gpu", "note" if state in ("unavailable", "table") else "warn", "busy time only: " + IOREPORT_OFF[state]
    if full or state == "on":
        return "gpu", "ok", "at full speed, from IOReport (a helper that runs as nobody)" if full else \
            "full speed switched on; the logger's next sample has it"
    if ioreport_wanted():
        return "gpu", "note", "full speed switched on in %s, not yet used by the logger" % CONFIG_FILE, \
            kick if c else None
    if switched_on(setting("no_ioreport")):
        return "gpu", "note", "busy time only: the full-speed figure is switched off (no_ioreport)"
    if _no_full_speed():
        return "gpu", "note", "busy time only (the share of time the GPU worked, at any speed); this Mac has no GPU " \
            "frequency table, so the figure at full speed is not available here"
    turn_on = "add \"ioreport\": true to %s (with sudo); %s" % (CONFIG_FILE, kick) if os.path.lexists(CONFIG_FILE) else \
        "sudo mkdir -p \"%s\"; echo '{\"ioreport\": true}' | sudo tee \"%s\"; %s" % (
            os.path.dirname(CONFIG_FILE), CONFIG_FILE, kick)
    return "gpu", "note", "busy time only (the share of time the GPU worked, at any speed); the figure at full speed " \
        "is opt-in in this version", turn_on


def _doctor_ledger(root):
    """The ledger folder's check: a real folder this user can write, its files plain files with one
    link (the lock may have more: nothing is read from it), readable by everyone (owner, group
    and others: the shared read refuses anything less, and other users can't take a private
    lock) and within the limits. Only lstat and access, which open nothing; the leases are
    counted by the ledger's own reader (as root, in a child as the invoking user)."""
    L = LEDGER_DIR
    try:
        st = os.lstat(L)
    except FileNotFoundError:
        return "ledger", "note", "%s does not exist yet: the first reservation creates it" % L
    except OSError as e:
        return "ledger", "warn", "%s: %s" % (L, e.strerror)
    if not stat.S_ISDIR(st.st_mode):
        return ("ledger", "warn", "%s is not a folder (%s): every reservation is refused" % (
            L, "a symbolic link" if stat.S_ISLNK(st.st_mode) else "a file"),
            "sudo rm %s  (the next reservation makes a new one)" % L)
    if not root and not os.access(L, os.W_OK | os.X_OK):
        return "ledger", "warn", "%s is not writable for you: reservations fail" % L, \
            "sudo chmod 777 %s" % L if sys.platform == "darwin" else None
    for name in ("ledger.json", HISTORY_FILE, "ledger.lock"):
        p, lock = os.path.join(L, name), name == "ledger.lock"
        try:
            f = os.lstat(p)
        except OSError:
            continue
        what = ("is not a regular file" if not stat.S_ISREG(f.st_mode) else
                "has %d hard links" % f.st_nlink if f.st_nlink != 1 and not lock else
                "is bigger than %d MB and read as empty" % (LIMITS["ledger"] >> 20)
                if name == "ledger.json" and f.st_size > LIMITS["ledger"] else None)
        if what:
            return "ledger", "warn", "%s %s, so it is refused" % (p, what), "rm %s  (a new one is written)" % p
        if f.st_mode & 0o444 != 0o444:
            return ("ledger", "warn", "%s is not readable by everyone, so %s" % (
                p, "other users can't take the lock: their reservations fail" if lock else "it is refused"),
                "chmod 666 %s  (as its owner, or with sudo)" % p)
    try:
        n = ledger_live_count()  # as root in a child as the invoking user
    except LedgerError as e:
        return "ledger", "warn", "%s: %s" % (L, e)
    return "ledger", "ok", "%s · %d live reservation%s" % (L, n, "" if n == 1 else "s")


def cmd_doctor(args):
    r = doctor()
    if "--json" in args:
        print(json.dumps(r))
        return r["exit"]
    w = max(80, term_width())
    m = r["machine"] or {}
    head = "%s %s on %s" % (BRAND, VERSION, m.get("name") or os.uname().nodename.split(".")[0])
    if m:
        head += ": %s, %s, %s" % (m.get("os_version"), m.get("arch"), m.get("kind"))
    print(wrap(head, w, "", 0))
    if m.get("id"):
        print("machine id %s" % m["id"])
    print()
    for x in r["checks"]:
        print(wrap(x["text"], w, "  %-5s %-10s " % (x["level"], x["id"]), 19))
        if x.get("fix"):
            print(wrap(x["fix"], w, " " * 19 + "→ ", 21))
    print()
    print({0: "Everything %s needs is here.   (oomph doctor --json for a bug report)" % BRAND,
           1: "Something to fix: the lines marked warn say how.",
           2: "%s cannot work here: see the lines marked fail." % BRAND}[r["exit"]])
    return r["exit"]


# ------------------------------------------------------------ claude setup
def _skill_source():
    for p in (os.path.join(HERE, "skills", CMD, "SKILL.md"),                 # installed / app bundle
              os.path.join(os.path.dirname(HERE), "skills", CMD, "SKILL.md")):  # repo checkout
        if os.path.exists(p):
            return p
    return None


def cmd_setup_claude(args):
    import shutil
    home = os.path.expanduser("~")
    dest_dir = os.path.join(home, ".claude", "skills", CMD)
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
                if not any(x.get("command", "").endswith(" hook") and CMD in x.get("command", "")
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
            subprocess.run([claude, "mcp", "remove", CMD, "--scope", "user"], capture_output=True)
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
        subprocess.run([claude, "mcp", "remove", CMD, "--scope", "user"], capture_output=True)
        r = subprocess.run([claude, "mcp", "add", "--scope", "user", CMD, "--", me, "mcp"],
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


def _has_bytecode():
    """Whether this file has bytecode beside it (install.sh compiles every module once, as root)."""
    import importlib.util
    try:
        return os.path.isfile(importlib.util.cache_from_source(os.path.realpath(__file__)))
    except (NotImplementedError, ValueError):
        return False


def main(argv):
    try:
        return _main(argv)
    except LedgerError as e:  # the ledger is busy, or something planted in its directory was refused
        sys.stderr.write("oomph: %s\n" % e)
        return 75 if isinstance(e, LedgerBusy) else 1
    except Unsupported as e:  # a command that measures, on a system without a backend
        sys.stderr.write("oomph: %s\n" % e)
        return 1


def _main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(usage(__doc__))
        return 0
    c, rest = argv[0], argv[1:]
    if c == "status":
        return cmd_status_json() if "--json" in rest else cmd_status()
    if c == "check":
        return cmd_check(rest)
    if c == "resources":
        return cmd_resources(rest)
    if c == "ps":
        return cmd_ps(rest)
    if c == "volumes":
        return cmd_volumes(rest)
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
    if c == "top":
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        if __name__ == "__main__" and "--once" not in rest and sys.executable and _has_bytecode():
            # Run as a script, this module was compiled from source, and what that leaves behind stays
            # resident (about 9 MB) for as long as the dashboard runs: start again, same process and
            # terminal, on the bytecode install.sh made. (-I, and -B if given, as this run had them.)
            mod = os.path.splitext(os.path.basename(os.path.realpath(__file__)))[0]
            os.execv(sys.executable, [sys.executable, "-I"] + (["-B"] if sys.flags.dont_write_bytecode else []) +
                     ["-c", "import importlib, sys; sys.path.insert(0, sys.argv[1]); "
                            "sys.exit(importlib.import_module(sys.argv[2]).main(sys.argv[3:]))", HERE, mod, "top"] + rest)
        # oomph_top imports oomph: let it have this module instead of compiling and holding a second copy
        # of it (run as a script, this module is __main__). A dashboard meant to stay small needs the 10 MB.
        sys.modules.setdefault(CMD, sys.modules[__name__])
        import oomph_top
        return oomph_top.cmd_top(rest)
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
    if c in ("serve", "remote"):
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        if c == "serve":
            import oomph_net
            return oomph_net.cmd_serve(rest)
        import oomph_sync
        return oomph_sync.cmd_remote(rest)
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
    if c == "doctor":
        return cmd_doctor(rest)
    if c == "report":
        return cmd_report(rest)
    if c == "incidents":
        return cmd_incidents()
    if c == "incident":
        return cmd_incident(rest)
    if c == "html":
        return cmd_html(rest)
    if c == "version":
        print(json.dumps({"version": VERSION, "commit": COMMIT, "brand": BRAND, "command": CMD,
                          "hardening": HARDENING}) if "--json" in rest else VERSION)
        return 0
    print(usage(__doc__))
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
