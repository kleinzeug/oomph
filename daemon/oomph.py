#!/usr/bin/python3 -I
"""oomph — inspect the memory papertrail written by oomphd.

  oomph status
  oomph report [--last 2h | --since ISO [--until ISO]]
  oomph top [--span inf|24h|6h|1h] [--glyphs unicode|cells|ascii|cp437] [--bell]
                                     the popup's dashboard, full screen (? lists its keys)
  oomph top --ssh [USER@]HOST       the same on another Mac or Linux machine, over ssh
  oomph top --once [--size 80x24]   one frame of it, as text
  oomph top --machine NAME          starts on another machine's tab [--no-connect: no links]
  oomph incidents [--all]           --all: with the quiet ones (Linux: containers at their own limit)
  oomph incident <id|latest> [--html]
  oomph alert --test | --run-hooks  Linux: run the scripts in /etc/oomph/alert.d with a test record; what
                                    oomph-alert.service runs for each incident the logger opens, kills in, closes
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

coordinating memory, cores and disk space between sessions (a shared first-come-first-served ledger):
  oomph run [--reserve 6G] [--cpu 4..12] [--disk 20G[@PATH]] [--for "what"] [--wait 30m] -- <cmd…>   wait for a
                                    grant, run, release; records the peak; {cpu} in the command is the cores granted
  oomph reserve [6G] [--cpu 8] [--disk 20G[@PATH]] --for "what" [--wait 10m] [--ttl 30m] [--ticket rN] [--json]
                                    exit 0 granted, 75 not (yet); --cpu 8 grants 4 to 8 logical cores, 8..8 exactly
                                    8 (or waits); --disk: space on the disk PATH is on (default: the temporary folder's)
  oomph amend <id> [--gb 3G] [--cpu 6] [--disk 30G] [--ttl 20m] [--for "what"] [--json]   change one: shrinking applies at
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

other machines (read-only, Mac to Mac over TLS, or anything with `oomph` over ssh):
  oomph share on [--pair]           share this Mac on the networks it is on now (sudo; off by default)
  oomph share pair | revoke ID      a one-time pairing code for a viewer; end a viewer's access (sudo)
  oomph share status | networks     whether this Mac is shared, where, and who is paired or reading
  oomph share ai on|off             whether viewers may send this machine's data to an AI model (sudo)
  oomph share off [--forget]        stop sharing (--forget: drop the key and every pairing too)
  oomph remote add HOST [--code C]  watch a shared Mac (the first time with the code its `share pair` showed)
  oomph remote add USER@HOST        watch a machine over ssh (it needs `oomph` there, nothing else)
  oomph remote list [--json]        the machines this one watches, and how each link is
  oomph remote remove|forget NAME   stop watching (forget: also its history and pairing)
  oomph remote rename NAME LABEL    the tab's name
  oomph remote sync [--json]        keep the watched machines' mirrors live (what the app runs)
  oomph remote sync --once [NAME]   catch up once, then exit
  oomph serve --stdio               answer for this machine on stdin/stdout, read only (what ssh runs)
"""
import datetime
import errno
import functools
import grp
import gzip
import heapq
import html as _html
import io
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
import zlib

VERSION = "dev"  # stamped by build-app.sh / install.sh from `git describe` (tools/version.sh)
COMMIT = ""      # the git commit the stamped copy was built from
BRAND = "oomph"  # the product's name in prose and titles: one edit renames it (tools/brandlint.py)
CMD = "oomph"    # the command, its message prefix and every identifier: never changes
HARDENING = 1    # H0 (1.8.4): root never opens the shared ledger directory; `oomph share on` requires it
SHARING = 1      # R1a (1.10.0): this code serves `serve --inetd` with TLS, pairing and the peer gate


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


STAMPED = VERSION != "dev"  # an installed or bundled copy; a checkout derives its version from git
if VERSION == "dev":
    VERSION, COMMIT = _checkout_version()


def usage(doc):
    """A module's help as printed. The first `oomph` of its first line is the product's name, so
    it says BRAND (a docstring cannot interpolate); the commands below it stay `oomph`."""
    first, _, rest = doc.strip().partition("\n")
    return re.sub(r"\boomph\b", lambda m: BRAND, first, count=1) + ("\n" + rest if rest else "")


# Where things live, per system: one table instead of constants scattered over the modules.
# OOMPH_DIR, OOMPH_LEDGER_DIR and OOMPH_STATE_DIR still win. Reading it imports no backend, so
# the hook and the readers never load the code that measures. On Linux the ledger is the
# machine's, /var/lib/oomph/ledger, once `linux/install.sh --system` made it (1.13.0: open to every
# local account, as on a Mac, D16); without it, one per user (and per machine, for a home folder
# shared between machines; roadmap 03 §7.1, §8.1). `ledger_mode` is what a new per-user folder gets.
PATHS = {
    "darwin": {"log": "/Library/Logs/oomph",
               "ledger": "/Users/Shared/oomph", "ledger_mode": 0o777,
               "state": "~/Library/Application Support/oomph",
               "config": "/Library/Application Support/oomph/config.json",
               "libexec": "/usr/local/libexec/oomph", "service": "/Library/LaunchDaemons/local.oomph.daemon.plist"},
    "linux": {"log": "/var/log/oomph",
              "ledger": "{state}/ledger/{machine}", "ledger_mode": 0o700,
              "shared_ledger": "/var/lib/oomph/ledger", "daemon_state": "/var/lib/oomph/daemon",
              "alert_d": "/etc/oomph/alert.d", "bin": "/usr/local/bin/oomph",
              "state": "{xdg_state}/oomph",
              "config": "/etc/oomph/config.json",
              "libexec": "/usr/local/libexec/oomph", "service": "/etc/systemd/system/oomphd.service",
              "user_lib": "~/.local/lib/oomph", "user_bin": "~/.local/bin/oomph"},  # linux/install.sh (1.9.4)
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


def _sudo_home():
    """Under sudo on Linux, the home folder of the user who ran it: a per-user ledger is theirs (a
    root caller's ledger operation runs as them, H0), not root's. None otherwise. Only the
    ledger's path comes from it: root's own state (settings, top's state) stays root's, so root
    never writes files into the user's folder."""
    if sys.platform == "darwin" or os.geteuid() != 0:
        return None
    try:
        return pwd.getpwuid(int(os.environ.get("SUDO_UID") or 0)).pw_dir if int(os.environ.get("SUDO_UID") or 0) > 0 else None
    except (KeyError, ValueError):
        return None


def _sudo_xdg_state(home):
    """The invoking user's XDG state folder under sudo: XDG_STATE_HOME when sudo kept it, it is
    absolute and that user owns it (so that `sudo oomph run` meets their sessions' ledger), else
    the default in their home."""
    x = os.environ.get("XDG_STATE_HOME") or ""
    try:
        if os.path.isabs(x) and os.stat(x).st_uid == int(os.environ.get("SUDO_UID") or -1):
            return x
    except (OSError, ValueError):
        pass
    return os.path.join(home, ".local", "state")


def _path(kind):
    """A path of the table above, expanded: ~, the XDG state folder, {state} and {machine}. Under
    sudo, {state} (the ledger's parent) is the invoking user's: their child writes it."""
    v = PATHS_HERE[kind]
    if "{xdg_state}" in v:
        x = os.environ.get("XDG_STATE_HOME") or ""
        v = v.replace("{xdg_state}", x if os.path.isabs(x) else "~/.local/state")  # relative: ignored, as XDG says
    if "{state}" in v:
        home = _sudo_home()
        v = v.replace("{state}", os.path.join(_sudo_xdg_state(home), CMD) if home else STATE_DIR)
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
REASON_RANK = {"jetsam_report": 90, "oom": 90, "oomd": 90, "dialog": 85, "lowmem": 80, "jetsam_storm": 70,
               "unowned": 60, "stall": 50, "pressure": 40, "cgroup_oom_storm": 10}  # oom, oomd, cgroup_oom_storm: Linux
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
_NOTIFY_BAD = re.compile("[\x00-\x1f\x7f-\x9f\"\\\\\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def notify_text(x, n=200):
    """Text for a notification, which now carries names that their owners chose (a volume's, a
    process's): control and direction characters, quotes and backslashes become spaces, at most n
    characters (roadmap 02 §10.5). The one escaping function every notification goes through."""
    return _NOTIFY_BAD.sub(" ", str(x if x is not None else ""))[:n]


_TERM_BAD = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff]")


def term_text(x):
    """Text for the terminal that carries names their owners chose (a volume's, a process's): control,
    escape and direction characters become "?", so no name can move the cursor, retitle the window
    or reorder a line."""
    return _TERM_BAD.sub("?", str(x if x is not None else ""))


def _day_range(since, until):
    d = datetime.date.fromtimestamp(since)
    end = datetime.date.fromtimestamp(until)
    while d <= end:
        yield d.isoformat()
        d += datetime.timedelta(days=1)


def open_log(path, cap=None, binary=False, dir_fd=None):
    """A file of the logger's, opened for reading as text (.gz unpacked; `binary`: as bytes): a regular file only,
    never through a link, never blocking on a FIFO, and with `cap` no bigger than that. On Linux the log folder
    belongs to the logger's account (oomphd), whose files a root reader must not trust (03 §12.3): what it unpacks
    to is the reader's to bound (_read_lines, load_log_json). `dir_fd`: `path` is a name in that folder
    (open_log_dir). Raises OSError."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_NOCTTY", 0), dir_fd=dir_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or (cap is not None and st.st_size > cap):
            raise OSError(errno.EINVAL, "not a log file: %s" % path)
        f = os.fdopen(fd, "rb")
    except BaseException:
        os.close(fd)
        raise
    raw = gzip.GzipFile(fileobj=f) if path.endswith(".gz") else f
    return raw if binary else io.TextIOWrapper(raw, encoding="utf-8", errors="replace")


def open_log_dir(path, dir_fd=None):
    """A folder of the logger's (incidents/, one incident's), opened as a descriptor: never through a link, so
    what is read through it (open_log's dir_fd) is in that folder whatever the logger's account renames meanwhile
    (on Linux the log folder is its: 03 §12.3; 1.14.1). Raises OSError (ELOOP or ENOTDIR for a link)."""
    return os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=dir_fd)


def open_incident_file(iid, name, cap=None, binary=False):
    """A file of one incident's folder (LOG_DIR/incidents/<iid>/<name>), opened as open_log opens one, through the
    descriptors of incidents/ and of that folder: no part of the way is a link, whatever the logger's account
    renamed since list_incidents looked (03 §12.3; 1.14.1). Raises OSError (ENOENT when it has no such file)."""
    if not isinstance(iid, str) or not iid or "/" in iid or iid.startswith("."):
        raise OSError(errno.ENOENT, "no such incident", iid)
    dfd = open_log_dir(os.path.join(LOG_DIR, "incidents"))
    try:
        ifd = open_log_dir(iid, dfd)
    finally:
        os.close(dfd)
    try:
        return open_log(name, cap, binary, dir_fd=ifd)
    finally:
        os.close(ifd)


def load_log_json(path, cap=16 << 20, dir_fd=None):
    """A JSON file of the logger's (open_log), parsed: at most `cap` bytes, unpacked too."""
    with open_log(path, cap, binary=True, dir_fd=dir_fd) as f:
        b = f.read(cap + 1)
    if len(b) > cap:
        raise ValueError("%s: larger than %d bytes" % (path, cap))
    return json.loads(b.decode("utf-8", "replace"))


def _read_lines(path):
    """The lines of a log file of the logger's (open_log), as text: each at most LIMITS["log_line"] bytes (a
    longer one is skipped whole), at most LIMITS["log_file"] bytes in all, unpacked (a .gz that unpacks to more,
    or a file without newlines, costs a root reader nothing but the time to read that much)."""
    line_max, left, skip = LIMITS["log_line"], LIMITS["log_file"], False
    try:
        with open_log(path, binary=True) as f:
            while left > 0:
                b = f.readline(min(line_max + 1, left))
                if not b:
                    return
                left -= len(b)
                if skip or len(b) > line_max:
                    skip = not b.endswith(b"\n")
                    continue
                yield b.decode("utf-8", "replace")
    except (OSError, EOFError, ValueError, zlib.error):
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
                           "procs_gb", "unowned_gb", "jetsam_kills", "away", "incident", "cpu", "gpu", "io",
                           "psi", "scope", "cgroup_kills", "killed")]  # the last four: Linux (03 §6.1), as 01 asked
    + [(k, "drop") for k in ("top", "groups", "claude", "gone", "leases", "top_cpu", "top_gpu", "top_io", "disks",
                             "linux", "cpu_names", "pools")]  # pools: this machine's admission (02 §5.2), not the wire's
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
               "gpu": (4, ("id", "util", "active", "now", "src", "mem_gb", "mem_alloc_gb")),
               "psi": (None, ("mem_some", "mem_full", "mem_some60", "mem_full60", "cpu_some", "io_some", "io_full")),
               "scope": (None, ("kind", "limit_gb", "by", "host_ram_gb", "host_avail_gb", "host_pressure")),
               "killed": (3, ("name", "mb", "by"))}
# ... and in the full current sample with what names and describes them
# A Linux machine's own figures that its tab's tiles read (1.13.3, 03 §3.9): what is available, the kernel's swap and
# zram's size (the zram tile), in the current sample only
FULL_BLOCKS = {"gpu": (4, SLIM_BLOCKS["gpu"][1] + ("name", "unified", "mem_limit_gb", "mem_limit_est")),
               "linux": (None, ("avail_gb", "kswap_total_gb", "kswap_free_gb", "zram_disk_gb"))}
# The full current sample is rebuilt from these fields only, each list capped (CONTEXT §3.2).
FULL_LISTS = {"top": (25, ("pid", "ppid", "name", "uid", "mb", "rss_mb", "g", "pn", "s", "cpu", "gpu", "w")),
              "groups": (15, ("name", "mb", "n", "cpu", "gpu")),
              "claude": (64, ("pid", "cwd", "mb", "own_mb", "n", "biggest", "cpu", "gpu", "w")),
              "gone": (64, ("pid", "name", "mb")),
              "leases": (64, ("id", "state", "gb", "purpose", "project", "used_gb", "for_min", "expires_in_min",
                              "waiting_min")),
              "top_cpu": (8, ("pid", "name", "g", "s", "cpu")),
              "top_gpu": (5, ("pid", "name", "g", "s", "gpu")),
              "top_io": (5, ("pid", "name", "g", "s", "w")),
              "cpu_names": (5, ("name", "cpu", "n"))}
FULL_DAEMON = ("pid", "version", "started", "interval", "incident", "root", "all_procs")
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
    FULL_MACHINE with their types (and a Linux sample's stall time at a limit), strings cut to
    LIMITS["str"] characters, lists to their caps."""
    out = slim_sample(s)
    n = LIMITS["str"]
    for k, (cap, keys) in FULL_BLOCKS.items():
        v = _block(s.get(k), cap, keys, n)
        if v is not _NOT:
            out[k] = v
    # stall time taken out for containers at their own limit (Linux, 03 §5.3), and the first three of them
    lim = s["psi"].get("limit") if isinstance(s.get("psi"), dict) else None
    if isinstance(lim, dict) and isinstance(out.get("psi"), dict):
        out["psi"]["limit"] = dict(_fields(lim, ("some", "full"), n),
                                   cgroups=[x[:n] for x in (lim.get("cgroups") or [])[:3] if isinstance(x, str)]
                                   if isinstance(lim.get("cgroups"), list) else [])
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
            if r is None:   # first, peak, peak t, last, process, peak cores, peak % of the GPU
                r = self.rows[k] = [p["mb"], -1, None, None, None, None, None]
            r[3] = p["mb"]
            if not groups:
                r[4] = (p["pid"], p["name"], p.get("ppid"), p.get("uid"))
            if p["mb"] > r[1]:
                r[1], r[2] = p["mb"], s["t"]
            if s.get("cpu") is not None:        # a sample of 1.9.1 or newer: a rate it omits is zero
                r[5] = _more(r[5], p["cpu"] if _fin(p.get("cpu")) else 0.0)
            if s.get("gpu"):
                r[6] = _more(r[6], p["gpu"] if _fin(p.get("gpu")) else 0.0)

    def result(self, limit=10):
        rows = []
        for k, (first, peak, peak_t, last, proc, cpu, gpu) in self.rows.items():
            if peak_t is None:
                continue
            r = {"name": k, "first_mb": first, "peak_mb": peak, "last_mb": last,
                 "rise_mb": peak - first, "peak_iso": _hm(peak_t)}
            if proc:
                r.update(pid=proc[0], proc=proc[1], ppid=proc[2], uid=proc[3])
            if cpu is not None:
                r["cpu_peak"] = round(cpu, 2)
            if gpu is not None:
                r["gpu_peak"] = round(gpu, 1)
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


def _fin(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


def available_gb(s):
    """What is available on a Linux machine (03 §3.9, the canonical figure): RAM less app, kernel and
    compressed memory; None where the sample has no RAM figure."""
    if not _fin(s.get("ram_gb")):
        return None
    return max(0.0, s["ram_gb"] - sum(s[k] for k in ("app_gb", "wired_gb", "compressed_gb") if _fin(s.get(k))))


def cpu_busy(s):
    """(cores busy, cores) of a sample, or None: a sample before 1.9.1, or the first after a gap."""
    c = s.get("cpu")
    if isinstance(c, dict) and _fin(c.get("busy")):
        return c["busy"], c.get("n") if isinstance(c.get("n"), int) and not isinstance(c.get("n"), bool) else None
    return None


def gpu_reading(s):
    """The GPU's figure of a sample as (kind, %, GPU memory in use GB or None): kind "util" where the
    figure is the share of the GPU's capacity at full speed (src ioreport), "busy" where it is the share
    of the time it was busy at any speed. The two are never averaged or compared (roadmap 02 §3.4.11).
    The first GPU is the one charted (the built-in one on Apple silicon). None without a reading."""
    g = s.get("gpu")
    g = g[0] if isinstance(g, list) and g and isinstance(g[0], dict) else None
    if g is None:
        return None
    mem = g.get("mem_gb") if _fin(g.get("mem_gb")) else None
    if not _fin(g.get("util")):
        return (None, None, mem) if mem is not None else None
    return ("util" if g.get("src") == "ioreport" else "busy", g["util"], mem)


def disk_pools_of(s):
    """The pools of a sample's disks block that have an id and a free space."""
    d = s.get("disks")
    return [p for p in d if isinstance(p, dict) and isinstance(p.get("id"), str) and _fin(p.get("free_gb"))] \
        if isinstance(d, list) else []


def _rows(x, n, keep):
    """The first n rows of a top_cpu / top_gpu / top_io list, with the named fields only."""
    return [{k: r[k] for k in keep if k in r} for r in (x if isinstance(x, list) else [])[:n] if isinstance(r, dict)]


def by_names(rows, field, n=5):
    """A top_cpu / top_gpu list as [{"name", field, "n"}]: a name's processes added up and counted,
    the biggest first (a sample older than `cpu_names`, or the GPU's few rows)."""
    out = {}
    for r in rows if isinstance(rows, list) else ():
        if isinstance(r, dict) and _fin(r.get(field)):
            a = out.setdefault(str(r.get("name") or "?")[:64], [0.0, 0])
            a[0] += r[field]
            a[1] += 1
    return [{"name": k, field: round(v[0], 2), "n": v[1]} for k, v in sorted(out.items(), key=lambda kv: -kv[1][0])[:n]]


def names_text(rows, field, fmt):
    """`yes ×14 11.8, cc1plus ×3 2.4`: grouped rows in words, a count only where a name has several."""
    return ", ".join("%s%s %s" % (r.get("name", "?"), " ×%d" % r["n"] if _fin(r.get("n")) and r["n"] > 1 else "",
                                  fmt % (r.get(field) or 0)) for r in rows if isinstance(r, dict))


class _Summary:
    """summarize() as a fold over samples: one pass, holding a few numbers, the peak sample
    and the risers, so a long incident is summarised in bounded memory."""

    def __init__(self):
        self.n = self.kills = self.away = 0
        self.cg_kills = None  # Linux: victims at a cgroup's own limit (03 §6.3)
        self.avail = self.psi = None  # Linux: the least available, the most stall time (03 §3.9, L3)
        self.first = self.last = self.peak = self.onset = None
        self.swap = self.swap_total = self.disk = self.used = self.unowned = self.stall = None
        self.groups, self.top = _Risers("groups"), _Risers("top")
        self.cpu = self.gpu_util = self.gpu_busy = None   # (value, sample) of each peak
        self.cpu_n = self.gpu_mem = None
        self.free = {}       # pool id -> lowest free GB
        self.writers = {}    # process name -> [peak MB/s written, when]

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
        if isinstance(s.get("cgroup_kills"), int):
            self.cg_kills = (self.cg_kills or 0) + s["cgroup_kills"]
        if s.get("os") == "linux":
            av = available_gb(s)
            if av is not None:
                self.avail = _less(self.avail, av)
            p = s.get("psi") if isinstance(s.get("psi"), dict) else {}
            if _fin(p.get("mem_some")):
                self.psi = _more(self.psi, p["mem_some"])
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
        c = cpu_busy(s)
        if c:
            if self.cpu is None or c[0] > self.cpu[0]:
                self.cpu = (c[0], s)
            self.cpu_n = c[1] or self.cpu_n
        g = gpu_reading(s)
        if g:
            if g[0] == "util" and (self.gpu_util is None or g[1] > self.gpu_util[0]):
                self.gpu_util = (g[1], s)
            elif g[0] == "busy" and (self.gpu_busy is None or g[1] > self.gpu_busy[0]):
                self.gpu_busy = (g[1], s)
            if g[2] is not None:
                self.gpu_mem = _more(self.gpu_mem, g[2])
        for p in disk_pools_of(s):
            if p["id"] in self.free or len(self.free) < 32:      # (bounded: a mirror's odd ids add no more)
                self.free[p["id"]] = _less(self.free.get(p["id"]), p["free_gb"])
        for w in s.get("top_io") or () if isinstance(s.get("top_io"), list) else ():
            if isinstance(w, dict) and _fin(w.get("w")) and isinstance(w.get("name"), str):
                k = w["name"][:64]
                if k in self.writers or len(self.writers) < 500:
                    r = self.writers.setdefault(k, [0.0, s["t"]])
                    if w["w"] > r[0]:
                        r[0], r[1] = w["w"], s["t"]

    def result(self, events):
        if not self.n:
            return {"samples": 0}
        peak, onset, stall = self.peak, self.onset, self.stall
        reasons = {}
        killed = {}
        victims = []
        for e in events:
            if e.get("kind") == "jetsam":
                for r, n in (e.get("reasons") or {}).items():
                    reasons[r] = reasons.get(r, 0) + n
                for k, n in (e.get("top") or {}).items():
                    killed[k] = killed.get(k, 0) + n
            elif e.get("kind") == "oom_kill":  # Linux (03 §5.5): who the kernel or a killer took, by name
                for k, n in (e.get("top") or {}).items() if isinstance(e.get("top"), dict) else ():
                    if isinstance(n, int):
                        killed[str(k)[:64]] = killed.get(str(k)[:64], 0) + n
                for v in e.get("victims") or () if isinstance(e.get("victims"), list) else ():
                    if isinstance(v, dict) and len(victims) < 10:
                        victims.append({k: v[k] for k in ("name", "pid", "mb", "by") if k in v})
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
            "onset": None if not onset else self._onset(onset),
            "top_at_peak": (peak.get("top") or [])[:10],
            "groups_at_peak": (peak.get("groups") or [])[:10],
            "claude_at_peak": peak.get("claude") or [],
            "group_risers": self.groups.result(),
            "process_risers": self.top.result(),
            **({"cgroup_kills": self.cg_kills, "oom_victims": victims} if self.cg_kills is not None else {}),
            **({"min_available_gb": round(self.avail, 1)} if self.avail is not None else {}),
            **({"max_stall_pct": self.psi} if self.psi is not None else {}),
            **self._resources()
        }

    @staticmethod
    def _onset(onset):
        o = {"at": onset["iso"], "pressure": PRESSURE.get(onset.get("pressure", 0)),
             "idle_s": (onset.get("away") or {}).get("idle_s"),
             "display_on": (onset.get("away") or {}).get("display_on"),
             "locked": (onset.get("away") or {}).get("locked"),
             "swap_used_gb": onset.get("swap_used_gb"), "disk_free_gb": onset.get("disk_free_gb")}
        c, g = cpu_busy(onset), gpu_reading(onset)
        if c:
            o["cpu_busy"] = c[0]
        if g and g[0]:
            o["gpu_" + g[0]] = g[1]
        if g and g[2] is not None:
            o["gpu_mem_gb"] = g[2]
        return o

    def _resources(self):
        """The other resources (roadmap 02 §5.3), each only where the samples have it: absent, never
        zero, for "not recorded". The GPU's two kinds of figure stay apart."""
        out = {}
        if self.cpu:
            out.update(max_cpu_busy=self.cpu[0], max_cpu_at=self.cpu[1]["iso"],
                       top_cpu_at_peak=_rows(self.cpu[1].get("top_cpu"), 8, ("pid", "name", "g", "cpu")),
                       names_cpu_at_peak=_rows(self.cpu[1].get("cpu_names"), 5, ("name", "cpu", "n"))
                       or by_names(self.cpu[1].get("top_cpu"), "cpu"))
            if self.cpu_n:
                out["cpu_n"] = self.cpu_n
        for kind, pk in (("util", self.gpu_util), ("busy", self.gpu_busy)):
            if pk:
                out["max_gpu_" + kind] = pk[0]
                out["max_gpu_%s_at" % kind] = pk[1]["iso"]
        pk = self.gpu_util or self.gpu_busy
        if pk:
            out["top_gpu_at_peak"] = _rows(pk[1].get("top_gpu"), 5, ("pid", "name", "g", "gpu"))
        if self.gpu_mem is not None:
            out["max_gpu_mem_gb"] = self.gpu_mem
        if self.free:
            out["min_free_gb"] = dict(sorted(self.free.items()))
        if self.writers:
            out["writers"] = [{"name": k, "peak_mb_s": v[0], "at": _hm(v[1])}
                              for k, v in sorted(self.writers.items(), key=lambda kv: -kv[1][0])[:8]]
        return out


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

BAD_KINDS = ("incident_open", "stall", "unowned_memory", "jetsam", "oom_kill", "disk_low", "disk_filling", "daemon_error", "log")


def calm_event(e):
    """An event of a bad kind that is no news (Linux, 03 §5.6): an OOM kill only at a cgroup's own limit (none of
    the machine's: `kills` 0 beside a `cgroup` count), a quiet incident's open or close."""
    if e.get("kind") == "oom_kill":
        return "cgroup" in e and not (_num(e.get("kills")) and e["kills"] > 0)
    return e.get("kind") in ("incident_open", "incident_close") and e.get("quiet") is True


def _e(x):
    return _html.escape(str(x))


def _scale(v, lo, hi, a, b):
    return a if hi == lo else a + (v - lo) * (b - a) / (hi - lo)


NO_DATA_S = 300
_chart_n = 0


def _svg_chart(samples, series, stacked, marks=(), bands=(), ymax=None, unit="GB", refline=None,
               height=220, bars=None, t0=None, t1=None, refs=(), reflabel="RAM"):
    """An SVG chart of `series` (label, value of a point, colour) over the points. A line (not
    stacked) breaks where its value is None: a sample without that reading. `refline`: the dashed line
    named `reflabel` (the RAM); `refs`: more dashed lines, (value, label)."""
    W, H, L, R, T, B = 960, height, 48, 10, 10, 26
    if not samples:
        return "<p class=sub>No samples.</p>"
    t0 = samples[0]["t"] if t0 is None else min(t0, samples[0]["t"])
    t1 = samples[-1]["t"] if t1 is None else max(t1, samples[-1]["t"])
    if t1 == t0:
        t1 = t0 + 1
    xs = [_scale(s["t"], t0, t1, L, W - R) for s in samples]
    vals = [[f(s) for s in samples] for _, f, _ in series]
    vals = [[x or 0 for x in v] if stacked else [x if x is None else float(x) for x in v] for v in vals]
    if stacked:
        cum = [0.0] * len(samples)
        tops = []
        for v in vals:
            cum = [c + x for c, x in zip(cum, v)]
            tops.append(cum[:])
        top_max = max(max(t) for t in tops)
    else:
        top_max = max((x for v in vals for x in v if x is not None), default=1)
    ymax = ymax or max([top_max, refline or 0] + [r[0] for r in refs]) * 1.08 or 1
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
                run = []
                for x, vv in list(zip(xs[a:b], v[a:b])) + [(None, None)]:
                    if vv is not None:
                        run.append("%.1f,%.1f" % (x, y(vv)))
                        continue
                    if len(run) > 1:
                        out.append('<polyline points="%s" fill="none" stroke="%s" stroke-width="1.8"><title>%s</title>'
                                   '</polyline>' % (" ".join(run), color, _e(label)))
                    elif run:
                        xx, yy = run[0].split(",")
                        out.append('<circle cx="%s" cy="%s" r="1.6" fill="%s"/>' % (xx, yy, color))
                    run = []
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
        out.append('<text x="%d" y="%.1f" font-size="11" fill="var(--fg)" text-anchor="end">%s %s %s</text>'
                   % (W - R - 4, y(refline) - 4, _e(reflabel), _fmt(refline), unit))
    for v, label in refs:
        out.append('<line x1="%d" x2="%d" y1="%.1f" y2="%.1f" stroke="var(--muted)" stroke-dasharray="2 4"/>' % (L, W - R, y(v), y(v)))
        out.append('<text x="%d" y="%.1f" font-size="11" fill="var(--muted)" text-anchor="start">%s %s %s</text>'
                   % (L + 4, y(v) - 4, _e(label), _fmt(v), unit))
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
        # a Linux machine's words (03 §3.9, L3): Kernel, only the series it has shown, no "away" where no one sits
        self.lin = self.comp = self.swap = self.presence = False

    def count(self, s):
        self.n += 1
        if s.get("os") == "linux":
            self.lin = True
            self.comp = self.comp or (s.get("compressed_gb") or 0) > 0
            self.swap = self.swap or any(_fin(s.get(k)) and s[k] > 0       # as LinuxTab.Facts and oomph top
                                         for k in ("swap_total_gb", "swap_used_gb", "swapfiles"))
            a = s.get("away") if isinstance(s.get("away"), dict) else {}
            self.presence = self.presence or a.get("idle_s") is not None or a.get("display_on") is not None
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
        self.racc, self.res, self.pools = {}, {}, {}   # this bucket's resources; what the view has; its disks

    def _point(self, s):
        p = {k: s[k] for k in _DRAW_KEYS if k in s}
        groups = s.get("groups") or []
        p["g"] = [next((g["mb"] / 1024 for g in groups if g["name"] == n), 0) for n in self.top5]
        p["rest"] = sum(g["mb"] for g in groups if g["name"] not in self.top5) / 1024
        return p

    def _fold(self, s):
        """The other resources of one sample into the bucket's: peaks, the mean of the cores busy, the
        lowest free space per disk. Each kind of GPU figure apart (02 §3.4.11)."""
        a = self.racc
        c = cpu_busy(s)
        if c:
            a["cpu"] = _more(a.get("cpu"), c[0])
            a["cpu_sum"], a["cpu_k"] = a.get("cpu_sum", 0.0) + c[0], a.get("cpu_k", 0) + 1
            if c[1]:
                self.res["n"] = _more(self.res.get("n"), c[1])
        g = gpu_reading(s)
        if g:
            g0 = s["gpu"][0]
            if g[0]:
                a[g[0]] = _more(a.get(g[0]), g[1])
                self.res[g[0]] = True
            if g[0] == "util" and _fin(g0.get("active")):
                a["busy"] = _more(a.get("busy"), g0["active"])
                self.res["busy"] = True
            for k, src in (("gmem", "mem_gb"), ("galloc", "mem_alloc_gb")):
                if _fin(g0.get(src)):
                    a[k] = _more(a.get(k), g0[src])
                    self.res["gmem"] = True
            if _fin(g0.get("mem_limit_gb")):
                self.res["glim"] = _more(self.res.get("glim"), g0["mem_limit_gb"])
        for p in disk_pools_of(s):
            if p.get("watch") and len(self.pools) < 8 or p["id"] in self.pools:
                f = a.setdefault("free", {})
                f[p["id"]] = _less(f.get(p["id"]), p["free_gb"])
                self.pools[p["id"]] = (str(p.get("name") or p["id"])[:64], p.get("low_gb"), p.get("crit_gb"))

    def _flush_res(self, point):
        a, self.racc = self.racc, {}
        if "cpu_k" in a:
            a["cpu_mean"] = a.pop("cpu_sum") / a.pop("cpu_k")
        point.update(a)
        return point

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
            self._fold(s)
            self.draw.append(self._flush_res(self._point(s)))
            return
        b = int((s["t"] - self.t0) / self.w)
        if b != self.bucket:
            self.finish()
            self.bucket, self.cur, self.cur_load, self.kills = b, self._point(s), _load(s), 0
        elif _load(s) > self.cur_load:
            self.cur, self.cur_load = self._point(s), _load(s)
        self._fold(s)
        self.kills += s.get("jetsam_kills", 0)

    def finish(self):
        if self.cur is not None:
            self.cur["jetsam_kills"] = self.kills
            self.draw.append(self._flush_res(self.cur))
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
    def res(d, r):   # CPU and GPU columns of the risers (roadmap 02 §5.3), where the samples have them
        if "cpu_peak" in r:
            d["cpu"] = r["cpu_peak"]
        if "gpu_peak" in r:
            d["gpu"] = r["gpu_peak"]
        return d
    procs = [res({"pid": r["pid"], "name": r["proc"], "first": r["first_mb"], "peak": r["peak_mb"],
                  "rise": r["rise_mb"], "at": r["peak_iso"], "ppid": r.get("ppid"), "uid": r.get("uid")}, r)
             for r in view.summ.top.result(limit=None)]
    apps = []
    for r in view.summ.groups.result(limit=None):
        pids = sorted(view.app_pids.get(r["name"], {}).items(), key=lambda kv: -kv[1])
        apps.append(res({"name": r["name"], "first": r["first_mb"], "peak": r["peak_mb"], "rise": r["rise_mb"],
                         "at": r["peak_iso"], "pids": [[p, mb] for p, mb in pids]}, r))
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
             for e in events if e.get("kind") in ("incident_open", "incident_close") and not e.get("quiet")]
    bands = view.bands
    draw = view.draw
    lin = view.lin
    mem_series = [("kernel" if lin else "wired", lambda s: s.get("wired_gb"), "var(--c-wired)"),
                  ("app memory", lambda s: s.get("app_gb"), "var(--c-app)"),
                  ("compressed", lambda s: s.get("compressed_gb"), "var(--c-comp)"),
                  ("swap used", lambda s: s.get("swap_used_gb"), "var(--c-swap)")]
    if lin:  # only the series this machine has shown (03 §3.9): no Compressed without zram or zswap, no Swap without swap
        mem_series = [x for x in mem_series if (x[0] != "compressed" or view.comp) and (x[0] != "swap used" or view.swap)]
    ram = summ["ram_gb"]
    colors = ["var(--k1)", "var(--k2)", "var(--k3)", "var(--k4)", "var(--k5)"]
    grp_series = [(n, (lambda s, i=i: s["g"][i]), c) for i, (n, c) in enumerate(zip(view.top5, colors))]
    if len(view.peaks) > len(view.top5):
        grp_series.append(("other recorded groups" if lin else "other recorded apps", lambda s: s["rest"], "var(--k6)"))
    disk_series = [("free disk GB", lambda s: s.get("disk_free_gb"), "var(--k3)"),
                   ("swap total GB", lambda s: s.get("swap_total_gb"), "var(--c-swap)")]
    o = summ.get("onset") or {}
    k = [("Peak pressure", summ["peak_pressure"], summ["peak_pressure"] in ("WARN", "CRITICAL")),
         ("Max swap used", "%.1f GB" % summ["max_swap_used_gb"], False),
         ("Min free disk", "%.0f GB" % summ["min_disk_free_gb"], summ["min_disk_free_gb"] < 20),
         ("OOM kills" if "cgroup_kills" in summ else "Jetsam kills", summ["jetsam_kills"], summ["jetsam_kills"] > 0),
         ("Max unowned memory", "%.0f GB" % summ["max_unowned_gb"] if summ.get("max_unowned_gb") is not None else "–",
          (summ.get("max_unowned_gb") or 0) >= unowned_limit_gb(summ.get("ram_gb"))),
         ("Away during window", "%d%%" % round(100 * summ["away_fraction"]), False),
         ("Idle at onset", ("%d min" % (o["idle_s"] // 60)) if o.get("idle_s") is not None else "–", False)]
    if lin:  # 03 §3.9: what is available and the stall time; away only where someone sits; no unowned memory
        ram_ = summ.get("ram_gb") or 0
        k = [x for x in k if x[0] != "Max unowned memory" and (view.presence or x[0] not in ("Away during window", "Idle at onset"))]
        av = summ.get("min_available_gb")
        k.insert(3, ("Least available", "%.1f GB" % av if av is not None else "–", av is not None and ram_ and av < 0.05 * ram_))
        if summ.get("max_stall_pct") is not None:
            k.insert(4, ("Most stalled on memory", "%.1f %%" % summ["max_stall_pct"], summ["max_stall_pct"] >= 10))
    if summ.get("max_stall_s"):
        k.append(("Longest stall (awake)", "%d s" % summ["max_stall_s"], summ["max_stall_s"] >= 60))
    if summ.get("max_cpu_busy") is not None:
        n = summ.get("cpu_n")
        k.append(("Most cores busy", "%.1f%s" % (summ["max_cpu_busy"], " of %d" % n if n else ""),
                  bool(n) and summ["max_cpu_busy"] >= 0.9 * n))
    if summ.get("max_gpu_util") is not None:
        k.append(("GPU at full speed, peak", "%.0f %%" % summ["max_gpu_util"], False))
    elif summ.get("max_gpu_busy") is not None:
        k.append(("GPU busy, peak (speed not reported)", "%.0f %%" % summ["max_gpu_busy"], False))
    if summ.get("max_gpu_mem_gb") is not None:
        k.append(("GPU memory, peak", "%.1f GB" % summ["max_gpu_mem_gb"], False))
    kpis = "".join('<div class="card kpi"><div class="v %s">%s</div><div class=l>%s</div></div>'
                   % ("bad" if bad else "", _e(v), _e(l)) for l, v, bad in k)
    rng = dict(t0=t0, t1=t1)
    head = "".join([
        sub,
        '<div class="kpis %s">%s</div>' % (cls, kpis),
        '<div class="%s"><h2>System memory (stacked) vs. RAM</h2><div class=card>%s</div>' % (cls, _svg_chart(
            draw, mem_series, True, marks, bands, refline=ram, bars=(lambda s: s.get("jetsam_kills"), "var(--bad)"), **rng)),
        "<h2>%s (GB, stacked)</h2><div class=card>%%s</div>" % ("Top 5 groups" if lin else "Top 5 apps / process groups") % _svg_chart(
            draw, grp_series, True, marks, bands, **rng),
        "<h2>Free disk and swap size (GB)</h2><div class=card>%s</div>" % _svg_chart(
            draw, disk_series, False, marks, bands, height=160, **rng),
        _resource_panels(view, draw, marks, bands, rng),
        "</div>",
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
        ("<h2>Most-killed by jetsam</h2><div class=card>%s<p class=sub>reasons: %s</p></div>" % (
            _table([{"n": k2, "c": v2} for k2, v2 in (summ.get("most_killed") or {}).items()],
                   [("service", lambda r: r["n"], False), ("kills", lambda r: r["c"], True)]),
            _e(", ".join("%s × %d" % kv for kv in (summ.get("jetsam_reasons") or {}).items()) or "–"))
         if "cgroup_kills" not in summ else  # Linux: the kernel's OOM killer, systemd-oomd, earlyoom (03 §6.3)
         "<h2>Killed for memory</h2><div class=card>%s<p class=sub>%d more at a cgroup's own limit</p></div>" % (
            _table(summ.get("oom_victims") or [], [("process", lambda r: r.get("name", "?"), False),
                                                   ("pid", lambda r: r.get("pid", ""), True),
                                                   ("MB", lambda r: r.get("mb", ""), True),
                                                   ("by", lambda r: r.get("by", ""), False)]),
            summ.get("cgroup_kills") or 0)),
        _busiest_html(summ, meta),
        "</div>",
    ])
    return head, tail


def _resource_panels(view, draw, marks, bands, rng):
    """The charts of the other resources (roadmap 02 §5.3), each only where the view's samples have
    it: cores busy against the core count (the peak and, where points stand for several samples, the
    mean); the GPU at full speed with its busy time, or, without the full-speed figure, its busy time
    under that name; GPU memory in use and allocated against the working-set limit; the free space of
    each watched disk with its floors."""
    res, out = view.res, []
    if any("cpu" in p for p in draw):
        series = [("cores busy, peak" if view.w else "cores busy", lambda p: p.get("cpu"), "var(--k1)")]
        if view.w:
            series.append(("mean", lambda p: p.get("cpu_mean"), "var(--k6)"))
        n = res.get("n")
        out.append("<h2>Cores busy%s</h2><div class=card>%s</div>" % (
            " (of %d)" % n if n else "", _svg_chart(draw, series, False, marks, bands, unit="cores", refline=n,
                                                     reflabel="cores", height=160, **rng)))
    if res.get("util"):
        out.append("<h2>GPU at full speed and busy time (%%)</h2><div class=card>%s<p class=sub>Full speed: the share "
                   "of the GPU's capacity used. Busy: the share of the time it worked, at any speed.</p></div>" % _svg_chart(
                       draw, [("at full speed", lambda p: p.get("util"), "var(--k4)"),
                              ("busy time", lambda p: p.get("busy"), "var(--k6)")], False, marks, bands, ymax=100,
                       unit="%", height=160, **rng))
    elif res.get("busy"):
        out.append("<h2>GPU busy time (%%)</h2><div class=card>%s<p class=sub>The share of the time the GPU was working, "
                   "at any speed. This Mac did not report how fast it ran, so light work reads higher here than it "
                   "weighs.</p></div>" % _svg_chart(draw, [("busy time", lambda p: p.get("busy"), "var(--k6)")], False,
                                                   marks, bands, ymax=100, unit="%", height=160, **rng))
    if res.get("gmem"):
        out.append("<h2>GPU memory (GB)</h2><div class=card>%s</div>" % _svg_chart(
            draw, [("in use", lambda p: p.get("gmem"), "var(--k4)"), ("allocated", lambda p: p.get("galloc"), "var(--k5)")],
            False, marks, bands, refline=res.get("glim"), reflabel="working-set limit", height=160, **rng))
    for pid, (name, low, crit) in list(view.pools.items())[:4]:
        refs = [(v, lab) for v, lab in ((low, "low"), (crit, "critical")) if _fin(v)]
        out.append("<h2>Free space on %s (GB)</h2><div class=card>%s</div>" % (_e(name), _svg_chart(
            draw, [("free", (lambda p, pid=pid: (p.get("free") or {}).get(pid)), "var(--k3)")], False, marks, bands,
            refs=refs, height=140, **rng)))
    return "".join(out)


def _busiest_html(summ, meta):
    """The busiest processes per resource at that resource's peak, and the biggest writers."""
    out = []
    if summ.get("top_cpu_at_peak"):
        out.append("<h2>Busiest on the CPU at its peak (%s)</h2><div class=card>%s</div>" % (
            _e((summ.get("max_cpu_at") or "")[11:19]), _table(summ["top_cpu_at_peak"], [
                ("pid", lambda r: r.get("pid", ""), True, "pid"), ("name", lambda r: r.get("name", "?"), False),
                ("app", lambda r: r.get("g") or "", False), ("cores", lambda r: "%.2f" % r.get("cpu", 0), True)],
                attrs=lambda r: _row_attrs("p:%s" % r.get("pid"), [r.get("pid")], (meta.get(r.get("pid")) or {}).get("g")))))
    if summ.get("top_gpu_at_peak"):
        full = summ.get("max_gpu_util") is not None
        at = summ.get("max_gpu_util_at" if full else "max_gpu_busy_at") or ""
        out.append("<h2>Busiest on the GPU at its peak (%s)</h2><div class=card>%s</div>" % (_e(at[11:19]), _table(
            summ["top_gpu_at_peak"], [
                ("pid", lambda r: r.get("pid", ""), True, "pid"), ("name", lambda r: r.get("name", "?"), False),
                ("app", lambda r: r.get("g") or "", False),
                ("% of full speed" if full else "% busy", lambda r: "%.1f" % r.get("gpu", 0), True)],
            attrs=lambda r: _row_attrs("p:%s" % r.get("pid"), [r.get("pid")], (meta.get(r.get("pid")) or {}).get("g")))))
    if summ.get("writers"):
        out.append("<h2>Writing to disk, peak</h2><div class=card>%s</div>" % _table(summ["writers"], [
            ("name", lambda r: r["name"], False), ("MB/s", lambda r: "%.1f" % r["peak_mb_s"], True),
            ("at", lambda r: r["at"], False)]))
    return "".join(out)


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
    lin = any(v.lin for v in prep)
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
            "bad": e.get("kind") in BAD_KINDS and not calm_event(e)}
           for e in reversed(collapse_pressure_events([e for e in events if e.get("kind") != "notified"
                                                       and not (e.get("quiet") and e.get("kind") in ("incident_open", "incident_close"))]))]
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
        '<div class=hrow><h2>Biggest risers — %s</h2><div class=ctl>%s</div></div>'
        '<div class=card><div id=r-apps></div></div>' % ("groups" if lin else "apps", seg("r-apps")),
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
// the CPU and GPU columns, where the view's samples have them (1.9.1 and newer): once per view, not per row
const resOf = {};
const RES = () => resOf[view] || (resOf[view] = (() => { const v = V(), x = {cpu: false, gpu: false};
  for (const rows of [v.procs, v.apps]) for (const r of rows) { x.cpu = x.cpu || r.cpu != null; x.gpu = x.gpu || r.gpu != null; if (x.cpu && x.gpu) return x; }
  return x; })());
function resCells(r){ const x = RES(); return (x.cpu ? '<td class=n>' + esc(r && r.cpu != null ? r.cpu : '') + '</td>' : '') + (x.gpu ? '<td class=n>' + esc(r && r.gpu != null ? r.gpu : '') + '</td>' : ''); }
function nums(r, agg){
  if (r) return '<td class=n>' + esc(r.first ?? '') + '</td><td class=n>' + esc(r.peak ?? '') + '</td><td class=n>' + esc(r.rise ?? '') + '</td><td>' + esc(r.at ?? '') + '</td>' + resCells(r);
  if (agg) return '<td class=n></td><td class=n></td><td class="n agg" title="sum of the rises below">Σ ' + esc(agg) + '</td><td></td>' + resCells(null);
  return '<td></td><td></td><td></td><td></td>' + resCells(null);
}
const HEAD = (first) => { const x = RES(); return '<tr><th class="pid">pid</th><th>' + first + '</th><th class=n>first MB</th><th class=n>peak MB</th><th class=n>rise MB</th><th>peak at</th>' + (x.cpu ? '<th class=n title="the most cores it kept busy">peak cores</th>' : '') + (x.gpu ? '<th class=n title="its largest share of the GPU">peak GPU %</th>' : '') + '</tr>'; };
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
      out.push('<tr><td class=pid></td><td colspan=' + (5 + RES().cpu + RES().gpu) + ' style="padding-left:' + (22 + depth * 16) + 'px"><button type=button class=linkbtn data-all="' +
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


VOLUME_WHAT = {"mounted": "mounted", "unmounted": "unmounted", "watched": "watched", "unwatched": "no longer watched"}


def _event_detail(e):
    """An event's fields for a line of `oomph report`; a volume's in words ("Datasets unmounted"),
    the busiest of a saturation by name with a count."""
    if e.get("kind") == "volume":
        name = next((e[k] for k in ("name", "mount", "pool") if isinstance(e.get(k), str) and e[k]), "a disk")
        what = e.get("what")
        return "%s %s%s" % (name, VOLUME_WHAT.get(what, "changed") if isinstance(what, str) else "changed",
                            " (%d changes)" % e["changes"] if _fin(e.get("changes")) and e["changes"] > 1 else "")
    if e.get("kind") == "cpu_saturated" and isinstance(e.get("top"), dict):
        cnt = e.get("top_n") if isinstance(e.get("top_n"), dict) else {}
        rows = [{"name": k, "cpu": v, "n": cnt.get(k)} for k, v in e["top"].items() if _fin(v)]
        e = {k: v for k, v in e.items() if k not in ("top", "top_n")}
        return ", ".join(["%s=%s" % (k, v) for k, v in e.items() if k not in ("t", "iso", "kind")] +
                         (["busiest: " + names_text(rows, "cpu", "%.1f")] if rows else []))[:300]
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
    if not os.path.exists(p) and sys.platform.startswith("linux"):
        return cmd_status_live()
    if not os.path.exists(p):
        print("oomph: no data in %s — daemon not installed or not running" % LOG_DIR)
        return 1
    c = load_log_json(p)
    age = time.time() - c["t"]
    d = c.get("daemon", {})
    alive = age < 3 * (d.get("interval") or 30) + 10
    a = c.get("away") or {}
    w = max(80, term_width())

    def line(label, text):
        print(wrap(text, w, "%-11s" % label, 11))
    if c.get("os") == "linux":  # the Linux logger (1.13.0): never root, the words of 03 §3.3
        return _status_linux(c, d, age, alive, line, w)
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


def _status_linux(c, d, age, alive, line, w):
    """`oomph status` from the Linux logger's current sample: who it runs as and how it learns of kills,
    the lines of status_lines_linux, the other resources, the open incident, groups and sessions."""
    ms = (d.get("machine") or {}).get("measures") or {}
    kills = {"journal": "kills from the journal", "count": "kills counted (no journal)"}.get(ms.get("kills"), "")
    line("logger", "%s (pid %s, v%s, sample %ds ago, every %ss%s%s)" % (
        "running" if alive else "NOT RUNNING", d.get("pid"), d.get("version"), age, d.get("interval"),
        ", as %s" % term_text(d["user"])[:32] if isinstance(d.get("user"), str) else "", ", " + kills if kills else ""))
    for label, text in status_lines_linux(c):
        if label != "disk" or not c.get("disks"):
            line(label, text)
    for label, text in resource_lines(c, *volume_prefs(), io=True):
        line(label, text)
    if c.get("jetsam_kills") or c.get("cgroup_kills"):
        names = ", ".join(term_text(k.get("name"))[:30] for k in c.get("killed") or () if isinstance(k, dict))
        line("killed", "%d by the OOM killer or a killer of memory%s, %d at a cgroup's own limit (last sample)" % (
            c.get("jetsam_kills") or 0, " (%s)" % names if names else "", c.get("cgroup_kills") or 0))
    if d.get("incident"):
        line("INCIDENT", "open: %s" % d["incident"])
    if d.get("quiet"):
        line("quiet", "containers keep hitting their own limit: incident %s (%s incidents --all)" % (d["quiet"], CMD))
    print("\ntop groups:")
    for g in (c.get("groups") or [])[:8]:
        print("  %6.1f GB  %s (%d)" % (g["mb"] / 1024, fit_group(term_text(g["name"]), w - 19), g["n"]))
    for title, key, field, fmt in (("busiest (cores)", "top_cpu", "cpu", "%7.2f   "), ("GPU (%)", "top_gpu", "gpu", "%7.1f   ")):
        rows = [r for r in (c.get(key) or [])[:5] if isinstance(r, dict) and _n(r.get(field)) is not None]
        if rows:
            print("\n%s:" % title)
            for r in rows:
                print(fmt % r[field] + "%s (%s)" % (cut_middle(term_text(str(r.get("name"))), 30),
                                                   fit_group(term_text(str(r.get("g") or "")), w - 46)))
    if c.get("claude"):
        print("\nclaude sessions:")
        for s in c["claude"]:
            print("  %6.1f GB  pid %-6s %s" % (s["mb"] / 1024, s["pid"], cut_left(s.get("cwd") or "(another user's)", w - 24)))
    try:
        leases = ledger_snapshot()
    except LedgerError:
        leases = []
    if leases:
        print("\nreservations (oomph reservations for details):")
        for b in leases:
            print("  " + _fmt_brief(b))
    return 0


def status_lines_linux(c):
    """The lines of `oomph status` that differ on Linux (03 §3.3, F0, F3): available, stall time,
    the memory classes in Linux words, swap on disk and in zram, the scope."""
    lx = c.get("linux") if isinstance(c.get("linux"), dict) else {}
    psi = c.get("psi") if isinstance(c.get("psi"), dict) else None
    sc = c.get("scope") if isinstance(c.get("scope"), dict) else {}
    out = [("pressure", "%s   available %s%%" % (PRESSURE.get(c["pressure"], c["pressure"]), c.get("free_pct")))]
    if psi:
        out.append(("stalled", "memory some %.1f%% full %.1f%%%s (10 s)" % (
            psi.get("mem_some") or 0, psi.get("mem_full") or 0,
            " · io some %.1f%%" % psi["io_some"] if _num(psi.get("io_some")) else "")))
        lim = psi.get("limit") if isinstance(psi.get("limit"), dict) else None
        if lim:
            out.append(("", "%.0f%% more inside %s, at its own limit" % (
                lim.get("some") or 0, ", ".join(str(x) for x in (lim.get("cgroups") or [])[:3]))))
    else:
        out.append(("stalled", "not measured: PSI is off on this kernel (see `oomph doctor`)"))
    avail = free_physical_gb(c)
    out.append(("memory", "RAM %.1f GB · available %.1f · app %.1f · kernel %.1f%s" % (
        c["ram_gb"], avail, c["app_gb"], c["wired_gb"],
        " · compressed %.1f" % c["compressed_gb"] if c.get("compressed_gb") else "")))
    out.append(("", "of the available: file cache %.1f · unused %.1f GB" % (c["cached_gb"], c["free_gb"])))
    zr = lx.get("zram_disk_gb") or 0
    if c.get("swap_total_gb"):
        sw = "%.1f / %.1f GB used on disk (%d swapfile%s)" % (c["swap_used_gb"], c["swap_total_gb"], c.get("swapfiles") or 0,
                                                            "" if c.get("swapfiles") == 1 else "s")
    else:
        sw = "none on disk"
    if zr and not sc:
        held = (lx.get("kswap_total_gb") or 0) - (lx.get("kswap_free_gb") or 0) - (c.get("swap_used_gb") or 0)
        sw += " · zram holds %.1f of %.1f GB in %.1f GB of RAM" % (max(0.0, held), zr, c.get("compressed_gb") or 0)
    out.append(("swap", sw))
    if sc.get("kind") == "cgroup":
        out.append(("scope", "this cgroup's limit, %.1f GB (memory.%s); the host has %.1f GB available of %.0f GB" % (
            sc.get("limit_gb") or 0, sc.get("by") or "max", sc.get("host_avail_gb") or 0, sc.get("host_ram_gb") or 0)))
    if c.get("disk_free_gb") is not None:
        out.append(("disk", "%.0f GB free on /" % c["disk_free_gb"]))
    return out


def cmd_status_live():
    """`oomph status` without a logger (Linux, L1): a live reading under a one-line banner, exit 0
    (03 F0)."""
    c = live_sample()
    w = max(80, term_width())
    print("not logged: a live reading (no logger on this machine; see `oomph doctor`)")
    for label, text in status_lines_linux(c):
        print(wrap(text, w, "%-11s" % label, 11))
    print("\ntop groups:")
    for g in (c.get("groups") or [])[:8]:
        print("  %6.1f GB  %s (%d)" % (g["mb"] / 1024, fit_group(g["name"], w - 19), g["n"]))
    if c.get("claude"):
        print("\nclaude sessions:")
        for s in c["claude"]:
            print("  %6.1f GB  pid %-6s %s" % (s["mb"] / 1024, s["pid"], cut_left(s.get("cwd") or "(not yours)", w - 24)))
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
    lin = samples[-1].get("os") == "linux"   # 03 §3.9 (L3): what is available and the stall time, groups
    if lin:
        print("%-8s %-8s %6s %6s %6s %6s %5s %6s  %s" % ("time", "level", "app", "avail", "swap", "disk", "kills", "stall",
                                                       "biggest group"))
    else:
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
        if lin:
            st = [x["psi"]["mem_some"] for x in r if isinstance(x.get("psi"), dict) and _fin(x["psi"].get("mem_some"))]
            print("%-8s %-8s %6.1f %6.1f %6.1f %6.0f %5d %6s  %s%s" % (
                datetime.datetime.fromtimestamp(r[0]["t"]).strftime("%H:%M"), PRESSURE.get(worst.get("pressure", 0)),
                worst["app_gb"], available_gb(worst) or 0, worst["swap_used_gb"], worst["disk_free_gb"],
                sum(s.get("jetsam_kills", 0) for s in r), "%.1f%%" % max(st) if st else "–",
                fit_group(term_text(g.get("name", "")), w - 60 - len(size)), size))
            continue
        print("%-8s %-8s %6.1f %6.1f %6.1f %6.0f %5d %4s  %s%s" % (
            datetime.datetime.fromtimestamp(r[0]["t"]).strftime("%H:%M"), PRESSURE.get(worst.get("pressure", 0)),
            worst["app_gb"], worst["compressed_gb"], worst["swap_used_gb"], worst["disk_free_gb"],
            sum(s.get("jetsam_kills", 0) for s in r), "yes" if any(is_away(s) for s in r) else "",
            fit_group(term_text(g.get("name", "")), w - 58 - len(size)), size))
    summ = summarize(samples, events)
    for title, key in (("groups" if lin else "apps", "group_risers"), ("processes", "process_risers")):
        print("\nbiggest risers (%s):" % title)
        for x in summ[key][:8]:
            print("  +%6d MB  %-*s peak %d MB at %s" % (x["rise_mb"], w - 56, fit_group(term_text(x["name"]), w - 56),
                                                      x["peak_mb"], x["peak_iso"]))
    names = {}
    for x in samples:
        for d in disk_pools_of(x):
            names[d["id"]] = str(d.get("name") or d["id"])
    res = resource_summary_lines(summ, names)
    if res:
        print("\nother resources:")
        for line in res:
            print("  " + cut_end(term_text(line), w - 2))
    notable = [e for e in events if e.get("kind") not in ("jetsam", "oom_kill", "notified")]
    if summ.get("cgroup_kills") is not None:  # Linux: by the kernel's OOM killer and the user-space killers
        if summ["jetsam_kills"] or summ["cgroup_kills"]:
            print("\nOOM kills: %d of the machine, %d at a cgroup's own limit   most: %s" % (
                summ["jetsam_kills"], summ["cgroup_kills"], term_text(", ".join(
                    "%s ×%d" % kv for kv in list((summ.get("most_killed") or {}).items())[:5]) or "–")))
    elif summ["jetsam_kills"]:
        print("\njetsam kills: %d   reasons: %s" % (summ["jetsam_kills"], summ["jetsam_reasons"]))
    if notable:
        print("\nevents:")
        for e in notable[-30:]:
            print("  %s  %-16s %s" % (term_text(e["iso"][11:19]), term_text(e["kind"])[:40],
                                      cut_end(term_text(_event_detail(e)), w - 29)))
    return 0


def resource_summary_lines(summ, names=None):
    """The summary's other resources in words (roadmap 02 §5.3): the CPU's and the GPU's peaks with
    who was busiest then, GPU memory, the least free space per disk, the biggest writers. Nothing for
    samples before 1.9.1. The GPU's figure is named as what it is (full speed, or busy time)."""
    out = []
    if summ.get("max_cpu_busy") is not None:
        top = names_text((summ.get("names_cpu_at_peak") or by_names(summ.get("top_cpu_at_peak"), "cpu"))[:3], "cpu", "%.1f")
        out.append("cores: at most %.1f%s busy, at %s%s" % (
            summ["max_cpu_busy"], " of %d" % summ["cpu_n"] if summ.get("cpu_n") else "",
            (summ.get("max_cpu_at") or "")[11:16], " (%s)" % top if top else ""))
    top = names_text(by_names(summ.get("top_gpu_at_peak"), "gpu")[:3], "gpu", "%.0f %%")
    if summ.get("max_gpu_util") is not None:
        out.append("gpu: at most %.0f %% of full speed, at %s%s" % (summ["max_gpu_util"],
                                                                    (summ.get("max_gpu_util_at") or "")[11:16],
                                                                    " (%s)" % top if top else ""))
    if summ.get("max_gpu_busy") is not None:
        out.append("gpu: busy at most %.0f %% of the time (speed not reported), at %s%s" % (
            summ["max_gpu_busy"], (summ.get("max_gpu_busy_at") or "")[11:16],
            " (%s)" % top if top and summ.get("max_gpu_util") is None else ""))
    if summ.get("max_gpu_mem_gb") is not None:
        out.append("gpu memory: at most %.1f GB" % summ["max_gpu_mem_gb"])
    if summ.get("min_free_gb"):
        out.append("disks, least free: " + " · ".join("%s %.1f GB" % ((names or {}).get(k, k), v)
                                                      for k, v in summ["min_free_gb"].items()))
    if summ.get("writers"):
        out.append("writing to disk, peak: " + ", ".join("%s %.1f MB/s at %s" % (r["name"], r["peak_mb_s"], r["at"][:5])
                                                          for r in summ["writers"][:3]))
    return out


def list_incidents(quiet=True):
    """Every incident, oldest first; with quiet=False without the quiet ones (Linux: containers at their own
    limit, 03 §5.6), which never count as news."""
    out, d = [], os.path.join(LOG_DIR, "incidents")
    try:  # incidents/ itself and each incident's folder only as real folders, read through their descriptors: the
        # logger's account could have put a link to anywhere there, or swap one in between a look and a read (03 §12.3)
        dfd = open_log_dir(d)
    except OSError:
        return out
    try:
        ids = sorted(n for n in os.listdir(dfd) if not n.startswith("."))
        for iid in ids:
            try:
                ifd = open_log_dir(iid, dfd)
            except OSError:
                continue
            try:
                inc = load_log_json("incident.json", dir_fd=ifd)
            except Exception:
                continue
            finally:
                os.close(ifd)
            if not isinstance(inc, dict) or (not quiet and inc.get("quiet")):
                continue
            inc["dir"] = os.path.join(d, iid)
            out.append(inc)
    except OSError:
        pass
    finally:
        os.close(dfd)
    return out


INCIDENT_ROW = "%-15s %5s  %-5s %5s  %s"  # a 36-column prefix, then the headline (44 at 80 columns)


def cmd_incidents(args=()):
    """One row per incident: when, how long, open or not, kills, and its headline. A headline
    longer than the line continues on the next, indented to its column. Quiet incidents (Linux:
    containers at their own limit, 03 §5.6) are left out and counted in a last line; --all lists
    them, with `quiet` in the state column."""
    every = "--all" in args
    incs = list_incidents()
    shown = [i for i in incs if every or not i.get("quiet")]
    nquiet = sum(1 for i in incs if i.get("quiet"))
    if not shown:
        print("no incidents recorded" + ("" if not nquiet else " (+ %d quiet one%s, containers at their own limit: %s "
                                         "incidents --all)" % (nquiet, "" if nquiet == 1 else "s", CMD)))
        return 0
    w = max(80, term_width())
    print(INCIDENT_ROW % ("incident", "took", "state", "kills", "headline"))
    for i in shown:
        dur = ("%dm" % ((i.get("end", time.time()) - i["start"]) // 60))
        kills = (i.get("summary") or {}).get("jetsam_kills")
        head = term_text((i.get("reasons") or [{}])[0].get("desc", ""))
        state = "quiet" if i.get("quiet") else "OPEN" if i.get("open") else ""
        print(wrap(head, w, INCIDENT_ROW % (i["id"], dur, state, "–" if kills is None else kills, ""), 36))
    if nquiet and not every:
        print("+ %d quiet one%s (containers at their own limit): %s incidents --all" % (nquiet, "" if nquiet == 1 else "s", CMD))
    return 0


# ----- alert hooks (Linux, roadmap 03 §5.13): the logger writes a record per open, kill and close into
# LOG_DIR/alerts; oomph-alert.path notices it and oomph-alert.service (a DynamicUser that may reach the
# network, which the logger may not) runs this, which runs the administrator's scripts.
ALERT_SAFE = re.compile(r"[^A-Za-z0-9 .,:;()/%+@_-]")
ALERT_NAME = re.compile(r"(\d{8}-\d{6})\.(open|kill|close)\.json")
ALERT_HOOK_S = 30            # each script gets this long per record
ALERT_RUN_S = 270            # one start of the runner (the unit allows 300)
ALERT_FIRST_S = 600          # without a cursor (the first start), records younger than this are run
ALERT_VARS = ("event", "incident", "level", "host", "title", "message", "report")


def alert_dir():
    return PATHS_HERE.get("alert_d") or "/etc/oomph/alert.d"


def alert_hooks(d=None, unrunnable=None):
    """The scripts of `d` (/etc/oomph/alert.d) that may run, by name: executable regular files owned by root
    (or by the account that runs them: itself, a test), writable by neither group nor others, in a folder of
    the same kind. A dot file, a backup (~, .dpkg-*, .rpm*), a .md or .example is skipped. The runner is a
    throwaway account, not root: a script others may not read and run (0700, 0750) would fail at every real
    alert, so it is left out too, and named in `unrunnable` (a list) for doctor and `alert --test`."""
    d = d or os.environ.get("OOMPH_ALERT_D") or alert_dir()
    ok = (0, os.geteuid())
    try:
        st = os.lstat(d)
        names = sorted(os.listdir(d))
    except OSError:
        return []
    if not stat.S_ISDIR(st.st_mode) or st.st_uid not in ok or st.st_mode & 0o022:
        return []
    out, open_dir = [], st.st_mode & 0o005 == 0o005
    for n in names:
        if n.startswith(".") or n.endswith(("~", ".md", ".example", ".txt")) or ".dpkg-" in n or ".rpm" in n:
            continue
        f = os.path.join(d, n)
        try:
            st = os.lstat(f)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode) and st.st_uid in ok and not st.st_mode & 0o022 and st.st_mode & 0o111:
            if open_dir and st.st_mode & 0o005 == 0o005:
                out.append(f)
            elif unrunnable is not None:
                unrunnable.append(f)
    return out


ALERT_CRED = re.compile(r"/[A-Za-z0-9/._@:-]{1,200}")


def alert_env(rec):
    """The variables a hook gets: each field cut to 200 characters of [A-Za-z0-9 .,:;()/%+@_-], anything else
    a '?' (process names and purposes are text any local user chooses); the JSON on stdin has the original.
    Under oomph-alert.service also CREDENTIALS_DIRECTORY: where the unit put /etc/oomph/alert.secret."""
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": "/"}
    cred = os.environ.get("CREDENTIALS_DIRECTORY") or ""
    if ALERT_CRED.fullmatch(cred) and ".." not in cred:
        env["CREDENTIALS_DIRECTORY"] = cred
    for k in ALERT_VARS:
        env["OOMPH_" + k.upper()] = ALERT_SAFE.sub("?", str(rec.get(k) if rec.get(k) is not None else ""))[:200]
    return env


def run_alert_hooks(rec, hooks, out=None, deadline=None):
    """Every hook once for one record, each at most ALERT_HOOK_S; returns [(hook, exit status or why)]. With a
    `deadline` (epoch), a hook that could run past it is not started: the list then ends before it."""
    res, data = [], json.dumps(rec).encode()
    for h in hooks:
        if deadline is not None and time.time() + ALERT_HOOK_S > deadline:
            break
        try:
            r = subprocess.run([h], input=data, env=alert_env(rec), cwd="/", stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=ALERT_HOOK_S)
            res.append((h, r.returncode, r.stdout[-300:].decode("utf-8", "replace")))
        except subprocess.TimeoutExpired:
            res.append((h, "timed out after %d s" % ALERT_HOOK_S, ""))
        except OSError as e:
            res.append((h, e.strerror or str(e), ""))
        if out:
            out("%s %s: %s" % (rec.get("event"), os.path.basename(h), res[-1][1]))
    return res


def _alert_records(d, after):
    """The alert records in `d` after the cursor (t, name), oldest first: [(t, name, record)]."""
    try:
        names = os.listdir(d)
    except OSError:
        return []
    got = []
    for n in names:
        if not ALERT_NAME.fullmatch(n):
            continue
        rec = loads_untrusted(read_bounded(os.path.join(d, n), 64 << 10) or b"")
        if not isinstance(rec, dict) or not _num(rec.get("t"), 0, 1e11):
            continue
        k = (float(rec["t"]), n)
        if after is None or k > after:
            got.append((k[0], n, {x: rec.get(x) for x in ALERT_VARS + ("t", "iso", "v") if x in rec}))
    return sorted(got)


ALERT_SECRET = "/etc/oomph/alert.secret"   # the hooks' secrets: root's, 0600; the unit's LoadCredential=alert:


# oomph-alert.service's sandbox, for `alert --test` where `systemctl cat` cannot say what it is (as shipped)
ALERT_SANDBOX = ("DynamicUser=yes", "CapabilityBoundingSet=", "AmbientCapabilities=", "NoNewPrivileges=yes", "UMask=0077",
                 "ProtectSystem=strict", "ProtectHome=yes", "PrivateTmp=yes", "PrivateDevices=yes", "PrivateUsers=yes",
                 "ProtectControlGroups=yes", "ProtectKernelModules=yes", "ProtectKernelTunables=yes",
                 "ProtectKernelLogs=yes", "ProtectClock=yes", "ProtectHostname=yes", "ProtectProc=invisible",
                 "ProcSubset=pid", "KeyringMode=private", "RemoveIPC=yes",
                 "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6", "RestrictNamespaces=yes", "RestrictRealtime=yes",
                 "RestrictSUIDSGID=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
                 "SystemCallArchitectures=native", "SystemCallFilter=@system-service",
                 "SystemCallFilter=~@privileged @resources", "SystemCallErrorNumber=EPERM", "MemoryMax=256M", "TasksMax=64")
ALERT_UNIT_SKIP = ("ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost", "Type", "StateDirectory",
                   "LoadCredential", "SetCredential", "TimeoutStartSec", "TimeoutSec", "RuntimeMaxSec", "Restart",
                   "RemainAfterExit")


def _alert_unit_sandbox():
    """oomph-alert.service's [Service] settings as the machine has them (with an administrator's drop-ins, from
    `systemctl cat`), less how it starts, its cursor and its credential: what `alert --test` runs the hooks in.
    The shipped ones where systemctl cannot tell."""
    import shutil
    try:
        r = subprocess.run([shutil.which("systemctl", path="/usr/bin:/bin") or "/usr/bin/systemctl", "cat", "--no-pager", "oomph-alert.service"], stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
        text = r.stdout.decode("utf-8", "replace") if r.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        text = ""
    props, section = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line
        elif section == "[Service]" and "=" in line and not line.startswith(("#", ";")) and not line.endswith("\\"):
            if line.split("=", 1)[0].strip() not in ALERT_UNIT_SKIP:
                props.append(line)
    return props or list(ALERT_SANDBOX)


def _alert_test_as_runner(hooks):
    """`sudo oomph alert --test` on a machine with systemd: the test run as oomph-alert.service runs the hooks, in
    its sandbox (a throwaway account, its system call filter, no JIT, no devices: _alert_unit_sandbox) with the
    secrets as a credential, so that a hook that passes here also works at a real alert (one only root may read,
    or one that needs a JIT, would not). None where systemd cannot do that."""
    import shutil
    run = shutil.which("systemd-run", path="/usr/bin:/bin")
    if os.geteuid() != 0 or os.environ.get("OOMPH_ALERT_INNER") == "1" or not run or not os.path.isdir("/run/systemd/system"):
        return None
    me = os.path.join(PATHS_HERE["libexec"], "oomph.py")
    me = me if os.path.isfile(me) else os.path.realpath(__file__)
    cmd = [run, "--quiet", "--wait", "--pipe", "--collect"]
    for prop in _alert_unit_sandbox():
        cmd += ["-p", prop]
    cmd += ["-p", "RuntimeMaxSec=%d" % (ALERT_HOOK_S * len(hooks) + 60), "--setenv=OOMPH_ALERT_INNER=1"]
    if os.environ.get("OOMPH_ALERT_D"):
        cmd.append("--setenv=OOMPH_ALERT_D=%s" % os.environ["OOMPH_ALERT_D"])
    if os.path.isfile(ALERT_SECRET):
        cmd += ["-p", "LoadCredential=alert:%s" % ALERT_SECRET]
    print("(run as oomph-alert.service runs them: a throwaway account in its sandbox, the secrets of %s as "
          "$CREDENTIALS_DIRECTORY/alert)" % ALERT_SECRET)
    sys.stdout.flush()
    try:
        return subprocess.run(cmd + [PY, "-I", "-B", me, "alert", "--test"], stdin=subprocess.DEVNULL,
                              timeout=ALERT_HOOK_S * len(hooks) + 90).returncode
    except (OSError, subprocess.TimeoutExpired) as e:
        print("%s: systemd-run failed: %s" % (CMD, e), file=sys.stderr)
        return 1


def cmd_alert(args):
    """`oomph alert --test`: every hook once with a test record, and what each said (as root: the way the unit runs
    them, _alert_test_as_runner). `oomph alert --run-hooks`: the runner oomph-alert.service starts when the logger
    writes a record, and only it (its STATE_DIRECTORY holds the cursor): every record after its cursor, each to
    every hook; then it looks again until nothing newer is left, waits 2 s, looks a last time and exits (a record
    written while hooks ran is not left behind; the logger's alerts/.beat starts it again anyway)."""
    if sys.platform == "darwin":
        print("%s alert: Linux only (on a Mac the logger notifies by itself)" % CMD, file=sys.stderr)
        return 2
    bad = []
    hooks = alert_hooks(unrunnable=bad)
    if args == ["--test"]:
        rc = _alert_test_as_runner(hooks) if hooks else None
        if rc is not None:
            return rc
        for h in bad:
            print("%-40s not run: others may not read and run it, and the unit runs hooks as a throwaway account "
                  "(chmod 755 it; secrets go into %s)" % (h, ALERT_SECRET))
        if not hooks:
            print("%s: no hooks to run in %s (executable, root's, writable by root only, readable by all)"
                  % (CMD, alert_dir()))
            return 1
        if os.geteuid() != 0 and os.environ.get("OOMPH_ALERT_INNER") != "1":
            print("(run as %s: oomph-alert.service runs them as a throwaway account, with %s; sudo %s alert --test "
                  "runs them that way)" % (_whoami(), ALERT_SECRET, CMD))
        host = os.uname()[1].split(".")[0]
        rec = {"v": 1, "event": "test", "incident": "00000000-000000", "level": "notice", "host": host,
               "title": "Test from %s on %s" % (BRAND, host), "message": "%s alert --test: your hook works" % CMD,
               "report": "", "t": round(time.time(), 3), "iso": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
        res = run_alert_hooks(rec, hooks)
        for h, rc, said in res:
            print("%-40s %s%s" % (h, "ok" if rc == 0 else "exit %s" % rc if isinstance(rc, int) else rc,
                                  (": " + term_text(said.strip().splitlines()[-1])[:120]) if said.strip() else ""))
        return 0 if all(r[1] == 0 for r in res) and not bad else 1
    if args != ["--run-hooks"]:
        print("usage: %s alert --test | --run-hooks" % CMD, file=sys.stderr)
        return 2
    state = os.environ.get("STATE_DIRECTORY", "").split(":")[0]
    if not os.path.isabs(state):  # anyone else would replay a day of records through root's hooks
        print("%s alert --run-hooks: only oomph-alert.service runs this (it sets STATE_DIRECTORY); to try the hooks: "
              "sudo %s alert --test" % (CMD, CMD), file=sys.stderr)
        return 2
    os.makedirs(state, mode=0o700, exist_ok=True)
    cur_f = os.path.join(state, "cursor.json")
    c = loads_untrusted(read_bounded(cur_f, 16 << 10) or b"")
    after = (float(c["t"]), str(c["name"])) if isinstance(c, dict) and _num(c.get("t"), 0, 1e11) and \
        isinstance(c.get("name"), str) else (time.time() - ALERT_FIRST_S, "")
    part = c.get("part") if isinstance(c, dict) and isinstance(c.get("part"), dict) else None  # a record half done:
    # the hooks that ran for it (a start stops before a hook that could outlast the unit's TimeoutStartSec)
    d, looked_last = os.path.join(LOG_DIR, "alerts"), False
    deadline = time.time() + ALERT_RUN_S
    while time.time() < deadline:
        recs = _alert_records(d, after)
        if not recs:
            if looked_last:
                break
            time.sleep(2)
            looked_last = True
            continue
        looked_last = False
        for t, n, rec in recs:
            done = set(x for x in part.get("done") or () if isinstance(x, str)) \
                if part and part.get("name") == n and isinstance(part.get("done"), list) else set()
            todo = [h for h in hooks if os.path.basename(h) not in done]
            res = run_alert_hooks(rec, todo, out=lambda x: sys.stderr.write("%s\n" % term_text(x)[:300]), deadline=deadline)
            done.update(os.path.basename(r[0]) for r in res)
            if len(res) == len(todo):
                after, part = (t, n), None
            else:
                part = {"name": n, "done": sorted(done)[:256]}
            tmp = "%s.%d.tmp" % (cur_f, os.getpid())
            with open(tmp, "w") as f:
                f.write(json.dumps(dict({"t": after[0], "name": after[1]}, **({"part": part} if part else {}))))
            os.replace(tmp, cur_f)
            if part:  # out of time: the next start (the logger's .beat) goes on with the hooks not yet run
                sys.stderr.write("%s alert: out of time; the next start runs the rest of %s\n" % (CMD, n))
                return 0
    return 0


def cmd_incident(args):
    incs = list_incidents()
    if not incs:
        print("no incidents recorded")
        return 1
    ident = args[0] if args and not args[0].startswith("-") else "latest"
    loud = [i for i in incs if not i.get("quiet")]
    inc = (loud or incs)[-1] if ident == "latest" else next((i for i in incs if i["id"] == ident), None)
    if not inc:
        print("no such incident: %s" % ident)
        return 1
    if "--html" in args:
        # Render fresh rather than opening the report.html saved at close: that one is a
        # snapshot in whatever report design the daemon had back then.
        p = _report_write("%s-%s" % (CMD, inc["id"]), incident_html(inc))
        if p is None:
            return 1
        print(p)
        _open_report(p)
        return 0
    print(json.dumps(inc, indent=1))
    return 0


def _own_dir(d, uid):
    """Is `d` a folder of `uid`'s own that no one else may enter (lstat: never through a link)?"""
    try:
        st = os.lstat(d)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode) and st.st_uid == uid and not st.st_mode & 0o077


def _report_dir():
    """Where a report goes without -o (03 §12.4): never a shared folder like /tmp, which `sudo oomph html` would
    write into as root. $TMPDIR where it is this account's own (a Mac's per-user one), else $XDG_RUNTIME_DIR/oomph
    (in a runtime folder of this account's), else `reports` in this account's state folder (root's own home, by
    its account, not $HOME, under sudo); each 0700. None if none can be had."""
    uid = os.geteuid()
    t = os.environ.get("TMPDIR") or ""
    if os.path.isabs(t) and _own_dir(t, uid):
        return t
    x = os.environ.get("XDG_RUNTIME_DIR") or ""
    home = pwd.getpwuid(uid).pw_dir if uid == 0 else None
    cands = [os.path.join(x, CMD)] if os.path.isabs(x) and _own_dir(x, uid) else []
    cands.append(os.path.join(home, ".local", "state", CMD, "reports") if home else os.path.join(STATE_DIR, "reports"))
    for d in cands:
        try:
            os.makedirs(d, 0o700, exist_ok=True)
        except OSError:
            continue
        if _own_dir(d, uid):
            return d
    return None


def _report_write(stem, text, out=None):
    """Write a report: to `out` (-o: the caller's choice), else as <stem>-<random>.html, created new (O_EXCL,
    never through a link) in _report_dir(), where those older than a week are removed. Its path, or None."""
    if out:
        with open(out, "w") as f:
            f.write(text)
        return out
    d = _report_dir()
    if d is None:
        print("%s: no folder of your own to write the report into: name one with -o FILE" % CMD, file=sys.stderr)
        return None
    try:
        for n in os.listdir(d):
            f = os.path.join(d, n)
            if n.startswith(CMD + "-") and n.endswith(".html") and time.time() - os.lstat(f).st_mtime > 7 * 86400:
                os.unlink(f)
    except OSError:
        pass
    p = os.path.join(d, "%s-%s.html" % (stem, secrets.token_hex(4)))
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return p


def _open_report(p):
    """Show a written report: `open` on a Mac; on Linux xdg-open where there is one and a desktop to show it on
    (never as root); otherwise the printed path is all."""
    import shutil
    if sys.platform == "darwin":
        cmd = ["/usr/bin/open", p]
    else:
        xo = shutil.which("xdg-open")
        if not xo or os.geteuid() == 0 or not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return
        cmd = [xo, p]
    try:
        subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        pass


def cmd_html(args):
    since, until = window(args, "24h")
    out = None
    if "-o" in args:
        out = args[args.index("-o") + 1]
    s = load_samples(since, until)
    e = load_events(since, until)
    out = _report_write("%s-report" % CMD, render_html(s, e, "Memory report"), out)
    if out is None:
        return 1
    print(out)
    if "--open" in args:
        _open_report(out)
    return 0


# ------------------------------------------------------------- agent protocol
HERE = os.path.dirname(os.path.realpath(__file__))
SKILL_URL = "https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md"
LEVELS = ("ok", "tight", "critical")
_oomphd = None
_plat = None
BACKENDS = {"darwin": "oomph_darwin", "linux": "oomph_linux"}  # sys.platform -> the module that measures it


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
            raise Unsupported("measuring %s is not supported: macOS and Linux are" % sys.platform)
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
        c = load_log_json(os.path.join(LOG_DIR, "current.json"))
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
ADVICE_LINUX = dict(ADVICE, critical=ADVICE["critical"].rsplit(" If disk space", 1)[0])  # Linux swap has a fixed size


def _linux():
    """oomph_linux, for its thresholds: pure functions of numbers, so a Linux sample is judged the
    same on any system. Importing it measures nothing."""
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import oomph_linux
    return oomph_linux


def _linux_reasons(s, p):
    """Why a Linux sample's pressure is what it is, in plain words (03 §5.4): stall time, and what is
    available against the headroom bounds and swap. [(level 1|2, reason)]."""
    if p < 2:
        return []
    L = _linux()
    psi = s.get("psi") if isinstance(s.get("psi"), dict) else None
    lx = s.get("linux") if isinstance(s.get("linux"), dict) else {}
    sc = s.get("scope") if isinstance(s.get("scope"), dict) else {}
    ram = (s.get("ram_gb") or 0) - (0 if sc else (lx.get("hugetlb_gb") or 0))
    avail = free_physical_gb(s)
    upper, _lower = L.bounds(ram)
    parts = []
    if psi:
        some, full = psi.get("mem_some") or 0, psi.get("mem_full") or 0
        if full >= L.P["full_warn"]:
            parts.append("every task waited for memory %.0f%% of the last 10 s" % full)
        elif some >= L.P["some_warn"]:
            parts.append("tasks waited for memory %.0f%% of the last 10 s" % some)
    if avail < upper:
        tot, used = s.get("swap_total_gb") or 0, s.get("swap_used_gb") or 0
        zram = (lx.get("zram_disk_gb") or 0) > 0 and not sc
        if zram:
            kt, kf = lx.get("kswap_total_gb") or 0, lx.get("kswap_free_gb") or 0
            parts.append("only %.1f GB is available and the compressed swap is %.0f%% full"
                         % (avail, 100 * (kt - kf) / kt if kt else 0))
        elif tot < L.P["swap_none"] * max(ram, 0.1):
            parts.append("only %.1f GB is available and there is no swap" % avail)
        else:
            parts.append("only %.1f GB is available and swap is %.0f%% full" % (avail, 100.0 * used / tot))
    hp = sc.get("host_pressure") if sc.get("kind") == "cgroup" else None
    if isinstance(hp, int) and hp >= p and not parts:
        parts.append("the host's memory is under pressure (%s), and it can kill a container within its limit"
                     % PRESSURE.get(hp, hp))
    where = " in this cgroup" if sc.get("kind") == "cgroup" else ""
    return [(2 if p >= 4 else 1, "memory pressure%s is %s%s" % (where, "CRITICAL" if p >= 4 else "WARNING",
                                                               ": " + "; ".join(parts) if parts else ""))]


def margin_for(s):
    """What the ledger keeps free on top of all reservations, by the sample's system: on a Mac
    5 % of RAM, at least 1.5 GB; on Linux the upper headroom bound (03 §5.3, D14)."""
    if s.get("os") == "linux":
        lx = s.get("linux") if isinstance(s.get("linux"), dict) else {}
        m = lx.get("margin_gb")
        return m if _num(m, 0, 1e6) else _linux().margin(s.get("ram_gb") or 0)
    return margin_gb(s.get("ram_gb"))


def oversize_for(s):
    """The largest request granted while nothing else is: no bound on a Mac (its swap grows);
    on Linux what RAM and swap can hold, less the lower bound (03 §5.3)."""
    if s.get("os") != "linux":
        return None
    lx = s.get("linux") if isinstance(s.get("linux"), dict) else {}
    m = lx.get("oversize_gb")
    if _num(m, 0, 1e6):
        return m
    room = lx.get("swap_room_gb") if _num(lx.get("swap_room_gb"), 0, 1e6) else lx.get("kswap_free_gb") or 0
    return _linux().oversize_limit(free_physical_gb(s), room, s.get("ram_gb") or 0)


def _verdict_parts(s):
    """The verdict's findings for a sample: [(level 1|2, resource "memory"|"disk", reason)], in the
    order `oomph check` lists them. The rules are a system's: a sample without `os` is a Mac's (every
    sample before 1.8.8). A full disk counts only on a Mac, where swap grows on the startup volume
    (roadmap 03 §5.4); a full swap on a full disk is memory's (02 §3.4.9)."""
    mac = s.get("os", "macos") == "macos"
    lin = s.get("os") == "linux"
    ram = s.get("ram_gb") or 0
    free = free_physical_gb(s)
    disk = s.get("disk_free_gb", 999)
    swap_full = s.get("swap_total_gb", 0) > 0 and s.get("swap_used_gb", 0) >= 0.9 * s["swap_total_gb"]
    out = []
    p = s.get("pressure", 1)
    if lin:
        out += [(lv, "memory", why) for lv, why in _linux_reasons(s, p if isinstance(p, int) else 1)]
    elif p >= 4:
        out.append((2, "memory", "macOS memory pressure is CRITICAL"))
    elif p >= 2:
        out.append((1, "memory", "macOS memory pressure is WARNING"))
    if mac and disk < 5:
        out.append((2, "disk", "only %.0f GB disk free — swap cannot grow" % disk))
    elif mac and disk < 20:
        out.append((1, "disk", "only %.0f GB disk free — swap may not be able to grow" % disk))
    if mac and swap_full and disk < 20:
        out.append((2, "memory", "swap is full (%.1f/%.1f GB) and the disk is too full to add more"
                    % (s["swap_used_gb"], s["swap_total_gb"])))
    if ram and free < 0.05 * ram and not lin:  # on Linux the headroom bounds say it (03 §5.4)
        out.append((1, "memory", "only %.1f GB physical memory free" % free))
    lx = s.get("linux") if lin and isinstance(s.get("linux"), dict) else {}
    if lx.get("overcommit") == 2 and _num(lx.get("commit_pct")) and lx["commit_pct"] >= 95:
        out.append((1, "memory", "strict overcommit is at %d%% of its limit: allocations are about to fail"
                    % lx["commit_pct"]))
    if s.get("jetsam_kills") and lin:  # 03 §6.1: `killed` names them where the logger read the journal
        k = [x for x in s.get("killed") or () if isinstance(x, dict) and isinstance(x.get("name"), str)][:1]
        out.append((1, "memory", "the system just killed %d process%s for memory%s" % (
            s["jetsam_kills"], "" if s["jetsam_kills"] == 1 else "es", " (%s%s)" % (
                term_text(k[0]["name"])[:40], ", %.1f GB" % (k[0]["mb"] / 1024.0) if _num(k[0].get("mb"), 0, 1e9) else "")
            if k else "")))
    elif s.get("jetsam_kills"):
        out.append((1, "memory", "macOS just killed %d processes for memory" % s["jetsam_kills"]))
    u = s.get("unowned_gb")
    if u is not None and ram and u >= unowned_limit_gb(ram):
        out.append((1, "memory", "%.0f GB of memory is held outside any process (likely a GPU or driver leak) "
                                 "and won't come back until the Mac restarts" % u))
    return out


CAPSULE_WORDS = ("Normal", "tight", "critical")  # "Memory tight", "Disk critical" (02 §3.4.9, §15.13)
DISK_WORDS = ("", "low", "critical")


def capsule(s):
    """What the app's capsule and `oomph top`'s say about a sample, and the colour of the menu-bar
    chip and its mark (02 §3.4.9, §3.5; decided 2026-11-23: they follow oomph's verdict). One
    function of `verdict`'s findings, so the capsule agrees with `oomph check`: the worst finding
    names it ("Memory tight", "Memory critical", "Disk low", "Disk critical"; memory first on a
    tie), "Normal" without one. {"text", "level" 0–2, "memory" 0–2 (the chip's body), "disk" 0–2
    (its mark)}. CPU and GPU never change it. The machine-wide verdict only: never the raise one
    caller's coordination applies, and no pins (the app and the dashboard are nobody's caller)."""
    lv = {"memory": 0, "disk": 0}
    for level, res, _why in _verdict_parts(s):
        lv[res] = max(lv[res], level)
    worst = max(lv.values())
    if not worst:
        text = CAPSULE_WORDS[0]
    elif lv["memory"] >= lv["disk"]:
        text = "Memory " + CAPSULE_WORDS[lv["memory"]]
    else:
        text = "Disk " + DISK_WORDS[lv["disk"]]
    return {"text": text, "level": worst, "memory": lv["memory"], "disk": lv["disk"]}


def verdict(s):
    """ok / tight / critical for a sample, with the reasons (_verdict_parts)."""
    lin = s.get("os") == "linux"
    ram = s.get("ram_gb") or 0
    free = free_physical_gb(s)
    disk = s.get("disk_free_gb", 999)
    parts = _verdict_parts(s)
    level, reasons = max([lv for lv, _r, _w in parts] or [0]), [w for _lv, _r, w in parts]
    p = s.get("pressure", 1)
    lv = LEVELS[level]
    v = {
        "level": lv, "exit_code": level, "reasons": reasons, "advice": (ADVICE_LINUX if lin else ADVICE)[lv],
        "free_gb": free, "ram_gb": ram, "pressure": PRESSURE.get(p, p),
        "swap_used_gb": s.get("swap_used_gb"), "swap_total_gb": s.get("swap_total_gb"),
        "disk_free_gb": disk, "unowned_gb": s.get("unowned_gb"), "source": s.get("source", "daemon"), "at": s.get("iso"),
    }
    if lin:  # Linux words: what is free is "available" there (03 §5.2); the stall time and the scope
        v.update(os="linux", available_gb=free)
        for k in ("psi", "scope"):
            if isinstance(s.get(k), dict):
                v[k] = s[k]
        if not isinstance(s.get("psi"), dict) and p >= 2:
            v["notes"] = ["stall time is not measured on this kernel (PSI is off), so the level cannot go past tight; "
                          "`oomph doctor` says how to turn it on"]
    return v


def verdict_line(v, width=None, lines=()):
    """The verdict as `oomph check` and the hook print it, wrapped at `width` (the terminal's);
    `lines`: (label, text) of the other resources, which `check` prints before the advice."""
    w = width or term_width()
    lin = v.get("os") == "linux"
    if lin:  # 03 F5: "available", no disk (it does not enter the Linux verdict)
        out = [wrap("oomph: %s — %.1fG available of %s · pressure %s · swap %.1f/%.1fG" % (
            v["level"].upper(), v["free_gb"], ("%.0fG" if v["ram_gb"] >= 10 else "%.1fG") % v["ram_gb"], v["pressure"],
            v["swap_used_gb"] or 0, v["swap_total_gb"] or 0), w)]
    else:
        out = [wrap("oomph: %s — %.1fG free of %.0fG · pressure %s · swap %.1f/%.1fG · disk %.0fG free" % (
            v["level"].upper(), v["free_gb"], v["ram_gb"], v["pressure"], v["swap_used_gb"] or 0,
            v["swap_total_gb"] or 0, v["disk_free_gb"]), w)]
    sc = v.get("scope") or {}
    if sc.get("kind") == "cgroup":
        out.append(wrap("this cgroup's limit (%.1fG, memory.%s); the host has %.1fG available of %.0fG" % (
            sc.get("limit_gb") or 0, sc.get("by") or "max", sc.get("host_avail_gb") or 0, sc.get("host_ram_gb") or 0),
            w, "  scope: "))
    if v["reasons"]:
        out.append(wrap("; ".join(v["reasons"]), w, "  why: "))
    c = v.get("coordination") or {}
    if c.get("others") or c.get("mine"):
        g = [o for o in c["others"] if o["state"] == "granted"]
        q = [o for o in c["others"] if o["state"] == "queued"]
        out.append(wrap("others hold %d (%.1fG not yet used), %d waiting · yours %d · %.1fG %s"
                        % (len(g), c["reserved_by_others_gb"], len(q), len(c["mine"]), c["available_to_me_gb"],
                           "left for you" if lin else "available to you"), w, "  reservations: "))
    led = c.get("ledger") or {}
    if lin and led.get("kind") == "user":
        out.append(wrap("your own sessions only (%s)" % _home_short(led.get("path") or ""), w, "  ledger: "))
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
        pinned = volume_prefs()[0]
    except Exception:  # a damaged settings file is no reason to fail a check
        pinned = set()
    try:
        pinned_verdict(v, s, pinned)
    except Exception:
        pass
    v["resources"] = {k: s[k] for k in ("cpu", "gpu", "io") if k in s}
    if "disks" in s:   # each disk with `pinned`, and a pinned pool with its floors and level (as `resources`)
        try:           # (a damaged sample's disks are no reason to fail a check, the hook or MCP either; 1.14.1)
            v["resources"]["disks"] = disk_rows(s, pinned)
        except Exception:
            v["resources"]["disks"] = []
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
            print("oomph: waiting — %s, %.1fG %s" % (v["level"], v["free_gb"], "available" if v.get("os") == "linux" else "free"),
                  flush=True)
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


def reservable(s=None):
    """What can be reserved on this machine: memory, cores where they are measured (cpu_reservable), disk
    space where volumes are listed by id (disk_reservable), and with gpu_reservations on a GPU where the sample
    `s` lists one that can be (02 §6.5.1)."""
    gpu = gpu_reservations_on() and any(c["reservable"] for c in (_G().gpu_cards_of(s) or {}).values()) if s else False
    return ["memory"] + (["cpu"] if cpu_reservable() else []) + (["disk"] if disk_reservable() else []) + \
        (["gpu"] if gpu else [])
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
    for d in s.get("disks") if isinstance(s.get("disks"), list) else []:
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
            if d is not None:  # the system's pool alone: not a list of every pool (a reserved one missing is not gone)
                s["disks"], s["disks_partial"] = d, True
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
    name = " (%s)" % term_text(str(g.get("name")))[:40] if g.get("name") else ""
    if _n(g.get("util")) is None:
        return "not measured yet%s%s" % (mem, name)
    if g.get("src") == "ioreport":
        return "%.0f %% of full speed%s%s" % (g["util"], mem, name)
    if g.get("src") == "nvidia-smi":  # the driver's own figure: the share of time a kernel ran
        return "busy %.0f %% of the time%s%s" % (g["util"], mem, name)
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
                                              "every user's processes (the GPU counts them all)" if key == "top_gpu"
                                              else "every process" if os.geteuid() == 0 else "your own processes")
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
    out["cpu"] = dict({k: cpu[k] for k in ("n", "p", "e", "busy", "therm") if k in cpu}, reservable=cpu_reservable()) \
        if cpu else None
    if out["cpu"] is not None and c and isinstance(c.get("cpu"), dict):  # the pool (02 §7.2): reserved, left, idle
        out["cpu"].update(margin=c["cpu"]["margin"], reserved=c["cpu"]["reserved"], left=c["cpu"]["available"],
                          **({"idle": c["cpu"]["idle"]} if "idle" in c["cpu"] else {}))
    gpus = s.get("gpu") if isinstance(s.get("gpu"), list) else None
    cards, on = {c["id"]: c for c in (_G().gpu_cards_of(s) or {}).values()}, gpu_reservations_on()
    gst = (c or {}).get("gpu") if isinstance((c or {}).get("gpu"), dict) else {}
    out["gpu"] = None if gpus is None else [dict(
        {k: g[k] for k in ("id", "name", "util", "active", "src", "mem_gb", "mem_alloc_gb", "mem_limit_gb",
                           "mem_limit_est", "unified", "procs", "uuid", "mem_free_gb", "mem_total_gb", "display", "mig")
         if k in g}, **_G()._gpu_reservable(cards.get(g.get("id")), on, gst.get((cards.get(g.get("id")) or {}).get("key"))))
        for g in gpus if isinstance(g, dict)]
    pools = (c or {}).get("disk") if isinstance((c or {}).get("disk"), dict) else {}
    out["disks"] = [dict({k: d[k] for k in ("id", "name", "mount", "free_gb", "total_gb", "kind", "roles", "level",
                                            "low_gb", "crit_gb", "pinned") if k in d},
                         watched=bool(d.get("watch")), reservable=disk_reservable(),
                         **({k: pools[d["id"]][f] for k, f in (("margin_gb", "margin"), ("reserved_gb", "reserved"),
                                                               ("left_gb", "available"))}
                            if isinstance(pools.get(d["id"]), dict) else {}))
                    for d in disk_rows(s, pinned) if d["id"] not in hidden]
    out["reservable"] = reservable(s)
    return out


def cmd_resources(args):
    """The resources of this machine: capacity, use, what is reserved and left, and which of them
    can be reserved here (memory, and cores where they are measured): what an agent asks before
    reserving anything else."""
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
    cpu = r.get("cpu") or {}
    gl = list(r.get("gpu") or [])  # in the order resource_lines gives the GPU lines
    drows = list(r["disks"])  # in the order resource_lines gives the disk lines
    for label, text in resource_lines(s, *volume_prefs()):
        d = drows.pop(0) if label in ("disk", "") and drows else {}
        if d.get("reservable"):
            text += " · %s GB reserved · %s GB left to reserve" % (_gb(d["reserved_gb"]), _gb(max(0.0, d["left_gb"]))) \
                if "left_gb" in d else " · reservable"
        if label == "cpu" and cpu.get("reservable") and "left" in cpu:
            text += " · %s reserved · %s left to reserve%s" % (
                cores_text(cpu["reserved"]), cores_text(max(0.0, cpu["left"])),
                " (%s idle)" % cores_text(max(0.0, cpu["idle"])) if "idle" in cpu else "")
        elif label == "gpu" and gl:
            text += _G()._gpu_line(gl.pop(0))
        elif label in ("cpu", "gpu") and not text.startswith("not measured"):
            text += " · not reservable yet" if label == "gpu" or not cpu.get("reservable") else " · reservable"
        line(label, text)
    more = [x for x in (("cores", " --cpu 8") if "cpu" in r["reservable"] else None,
                        ("disk space", " --disk 20G") if "disk" in r["reservable"] else None,
                        ("a GPU", " --gpu-mem 16G") if "gpu" in r["reservable"] else None) if x]
    print(wrap("Memory%s can be reserved with this version: `oomph reserve 6G%s --for \"what\"`." % (
        "".join((" and " if i == len(more) - 1 else ", ") + x[0] for i, x in enumerate(more)),
        "".join(x[1] for x in more)), w, "  "))
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
        e = {"mount": r["mount"], "name": r["name"], "fs": r["fs"], "free_gb": r.get("free_gb"), "total_gb": r.get("total_gb"),
             "class": r["cls"], "why": r["why"]}  # (Linux leaves a network mount's size unread: it could block)
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
        size = "%s free of %s GB" % (_gb(e["free_gb"]), _gb(e["total_gb"])) if e["total_gb"] and e["free_gb"] is not None else ""
        print(wrap("%s · %s" % (what, term_text(e["mount"])), w, "  %-14s %-20s " % (cut_middle(term_text(e["name"]), 14),
                                                                                     size), 38))
    if "--all" not in opts:
        print("(`oomph volumes --all` also lists the volumes the logger ignores, and why)")
    return 0


# ------------------------------------------------------ coordination ledger
# Sessions announce memory-heavy work before starting it ("reserve 6G for the gradle build").
# Requests queue first-come-first-served in one shared ledger; a request is granted when it
# fits into free memory minus what earlier grants have not yet used, minus a safety margin.
# So concurrent heavy steps from different sessions run side by side when there's room, and
# one after another when there isn't. Advisory: oomph never stops or kills anything.
def _ledger_default():
    """The ledger of this machine: on Linux /var/lib/oomph/ledger whenever it exists (also when this
    caller may not use it: two ledgers would grant the same memory twice, 03 §7.1), else the per-user one."""
    shared = PATHS_HERE.get("shared_ledger")
    return shared if shared and os.path.lexists(shared) else _path("ledger")


LEDGER_DIR = os.environ.get("OOMPH_LEDGER_DIR") or _ledger_default()
QUEUE_STALE_S = 180          # a queued request lapses if its owner hasn't polled for this long
DEFAULT_TTL_S = 30 * 60      # session-held grants expire unless released or extended
MAX_TTL_S = 8 * 3600
POLL_S = 2
HISTORY_KEEP = 100           # finished reservations kept in ledger.json (the log keeps 14 days)
HISTORY_FILE = "reservations.jsonl"  # one record per edit and per finished reservation
HISTORY_DAYS = 14
_sample_override = None      # tests: a function returning the sample to decide on


def margin_gb(ram):
    """Memory kept free on top of all reservations, on a Mac (margin_for: by the sample's system)."""
    return max(1.5, 0.05 * (ram or 0))


# ----- cores (B1, 1.12.0; 02 §6.1, §6.4): a rate pool of logical cores, granted elastically
NO_MEM_GB = 0.01             # the gb mirror of a lease without memory: 1.8.4 to 1.9.1 drop a lease of gb 0 when
                             # they write the ledger (02 §9.3, found at B0), and 0.01 GB is nothing to anyone's sums
POOLS_MAX_AGE_S = 45         # current.json's `pools` count while this fresh (as the sample itself)
CPU_MAX = 4096               # cores in one request: more than any machine has, to keep the arithmetic sane


def cpu_margin(n):
    """Cores no reservation can have, for the person at the machine: max(1, round(n / 8)), 2 of 14, 1 of 8."""
    return max(1, int(n / 8.0 + 0.5))


def cpu_reservable():
    """Can cores be reserved here? Only where this machine measures them (roadmap §4.4: what a machine cannot
    measure cannot be reserved there) and its backend says so on purpose (`RESERVES_CPU`): macOS. Linux opts in
    with its own margins in a later step (roadmap gap G2), not as a side effect of reading the ticks (L2)."""
    try:
        return getattr(plat(), "RESERVES_CPU", False) is True and hasattr(plat(), "cpu_ticks")
    except Unsupported:
        return False


def _cn(x):
    """A number of cores as written to JSON: an int when whole (6, not 6.0: `-j` takes integers, 02 §6.1)."""
    return int(x) if float(x).is_integer() else float(x)


def _cores(x, asked):
    """A number of cores as granted: whole unless a fraction was asked for (-j takes integers), rounded down."""
    return int(math.floor(x + 1e-9)) if float(asked).is_integer() else _cn(math.floor(x * 10 + 1e-9) / 10.0)


def cores_text(x):
    """6, 2.5: how a number of cores is written (no ".0")."""
    return "%d" % x if float(x).is_integer() else "%.1f" % x


def elastic_min(ask):
    """The least an elastic request for `ask` cores accepts: half, rounded up (02 §6.4, §15.5: half to all)."""
    return int(math.ceil(ask / 2.0)) if float(ask).is_integer() else _cn(math.ceil(ask * 5 - 1e-9) / 10.0)


def parse_cores(x):
    """`--cpu 8` (elastic: 4 to 8), `--cpu 8..8` (exactly 8), `--cpu 1..8`; numbers with one decimal.
    Returns (ask, min); raises ValueError."""
    lo, sep, hi = str(x).partition("..")
    vals = []
    for v in ((lo, hi) if sep else (lo,)):
        try:
            f = float(v)
        except ValueError:
            raise ValueError("not a number of cores: %s (use e.g. 8, 4..8 or 8..8)" % x)
        if not (math.isfinite(f) and 0 < f <= CPU_MAX) or abs(f * 10 - round(f * 10)) > 1e-6:
            raise ValueError("cores take a number from 0.1 to %d with at most one decimal, not %s" % (CPU_MAX, v))
        vals.append(_cn(round(f, 1)))
    if len(vals) == 1:
        return vals[0], elastic_min(vals[0])
    if vals[0] > vals[1]:
        raise ValueError("--cpu %s: the fewest cores come first (e.g. 4..8)" % x)
    return vals[1], vals[0]


# ----- disk space on a volume (B2, 1.12.1; 02 §4.4, §6.1, §6.3, §7.1): a stock pool per volume, by the pool's id
DISK_MAX_GB = 1e6            # GB in one request: more than any volume holds, to keep the arithmetic sane
VOLUME_GONE_S = 120          # a reserved pool missing this long from a list of every pool: its reservations end
                             # (volume_gone). A remount, or the logger asking diskutil about it anew, takes less
DISK_STATE_MAX = 32          # disk pools in the ledger's state
WRITE_DT_MAX_S = 120         # the longest interval one evaluation charges a tree's writes for (a sleep, a stall)

# ----- advice on a grant (B3, 1.12.3; 02 §6.3): `over` and `idle`, shown and returned to the holder, never enforced
OVER_X = 1.25                # a rate grant used at more than this × what it got …
OVER_N = 2                   # … for this many evaluations in a row is `over`; a disk grant is over once it wrote more
IDLE_X = 0.1                 # a rate grant used at under this × what it got …
IDLE_S = 600                 # … for this long is `idle`
ADVICE_FLAGS = ("over", "idle", "elsewhere")  # elsewhere (1.14): a GPU grant's job runs on another card
ADVICE_FIELDS = ("flag", "over_n", "over_t", "low_t", "rate_t")  # in res.cpu, disk, vram: the advice, its counters
ADVICE_STALE_S = 300         # and when the logger last rated them: advice older than this is dropped (_advice_stale)


def disk_reservable():
    """Can disk space be reserved here? Only where this machine lists its volumes by pool id (`mounts`, the
    classes of 02 §4.4: roadmap §4.4, what a machine cannot measure cannot be reserved there) and its backend
    says so on purpose (`RESERVES_DISK`): macOS. Linux opts in once its logger lists volumes (L2)."""
    try:
        return getattr(plat(), "RESERVES_DISK", False) is True and hasattr(plat(), "mounts")
    except Unsupported:
        return False


def disk_floors(p):
    """(low, critical) GB of a pool: its own floors (the system's pool: 20 and 5), else those a pinned pool of
    its size would have (5 % and 1 % of it, 02 §4.4)."""
    if _num(p.get("low_gb"), 0, DISK_MAX_GB) and _num(p.get("crit_gb"), 0, DISK_MAX_GB):
        return float(p["low_gb"]), float(p["crit_gb"])
    return pool_floors(p["total_gb"] if _num(p.get("total_gb"), 0, DISK_MAX_GB) else 0.0)


def disk_margin(low):
    """What admission keeps back on a pool (02 §6.1): the low floor and the headroom a plan may be off by,
    low + max(2, low / 4): 25 GB where the floor is 20. A reservation used exactly as planned then does not
    leave the pool at its alert."""
    return low + max(2.0, low / 4.0)


DISK_MIN_GB = 0.01           # the least disk space a request holds: GB are kept to two decimals, and less is none


def parse_disk(x, zero=False):
    """`--disk 20G` (on the temporary folder's volume) or `--disk 20G@/Volumes/Scratch` (any path on the
    volume, 02 §7.1): (GB, path or None), the GB to two decimals and at least DISK_MIN_GB, or with `zero`
    (amend: drop the disk space) exactly 0. Raises ValueError."""
    size, sep, path = str(x).partition("@")
    try:
        gb = _parse_gb(size)
    except ValueError:
        gb = None
    if gb is None or not (math.isfinite(gb) and 0 <= gb <= DISK_MAX_GB) or (gb == 0 and not zero):
        raise ValueError("not a disk size: %s (use e.g. 20G, or 20G@/Volumes/Scratch for a volume)" % x)
    if gb and round(gb, 2) < DISK_MIN_GB:
        raise ValueError("--disk %s: too little to reserve (at least 10M)" % x)
    if sep and not path:
        raise ValueError("--disk %s: a path on the volume comes after the @ (e.g. 20G@/Volumes/Scratch)" % x)
    return round(gb, 2), (path or None)


def default_disk_path():
    """Where `--disk` without a path reserves: the temporary folder (02 §7.1), which is the system's pool on a
    stock Mac."""
    return os.environ.get("TMPDIR") or "/tmp"


_VOLS = []  # this process's oomphd.Volumes: diskutil is asked once per newly seen mount, however often a list is read


def live_volumes():
    """(pools, rows) of this machine read now, every listed pool by its id: what the logger lists, without it.
    diskutil is asked once per mount in this process (0.1 to 0.6 s each); (None, None) without a mount table."""
    if not _VOLS:
        _VOLS.append(_daemon_module().Volumes(plat(), wait=True))
    return _VOLS[0].read()


def live_volumes_partial():
    """Did the last live_volumes() leave a disk out because diskutil did not answer for it? Then its
    list is not every pool: one missing from it is not gone (`disks_partial`)."""
    return bool(_VOLS) and _VOLS[0].unsure is True


def _statvfs_gb(path, fs=None):
    """Free space where `path` is, read now (what df shows), in GB; None if it cannot be read. Admission asks
    it for the one pool a request names: the mount table can be seconds old (02 §4.4). On Linux a FUSE disk
    (`fs`, from the mount table; unknown counts as one) is waited for at most oomph_linux.STATVFS_FUSE_S, as the
    logger waits for it: a hung ntfs-3g must not hang `oomph run --reserve-disk` or a ledger child (1.14.1)."""
    bounded = getattr(plat(), "statvfs_bounded", None)
    try:
        v = bounded(path, fs if isinstance(fs, str) else "fuse") if bounded else os.statvfs(path)
    except OSError:
        return None
    return round(v.f_bavail * v.f_frsize / float(1 << 30), 1)


def disk_pool_of(path, s):
    """The pool a path is on (02 §7.1: any path on a volume names it, the reservation follows the volume's id):
    (pool, None, pools), or (None, why, None). `pool` is the sample's entry for it with the free space read
    now; `pools` every pool of this machine when the sample had no list of them and one had to be read.
    Refused with the reason: no such path, or a volume the logger ignores (a disk image, removable media, a
    network or read-only volume: `oomph volumes --all` says which). A path not made yet (the job's output
    folder) is on the volume of the nearest folder above it that exists, but never / or /Volumes: a
    mistyped volume name is not the startup disk."""
    P = plat()
    at, err = os.path.abspath(path), None
    while True:
        try:
            dev = os.stat(at).st_dev & 0xFFFFFFFF
            break
        except OSError as e:
            up, err = os.path.dirname(at), err or e
            if e.errno not in (errno.ENOENT, errno.ENOTDIR) or up in ("/", "/Volumes") or up == at:
                return None, "%s: %s" % (path, err.strerror or err), None
            at = up
    recs = P.mounts()
    rec = next((r for r in recs or () if r["dev"] == dev), None)
    if rec is None:
        return None, "%s is on no volume this machine lists" % path, None
    known = disk_pools_of(s) if isinstance(s.get("disks"), list) else None
    sys_pools, rows = P.disk_pools(recs, {})  # the system's pool, and every class the mount flags decide alone
    row = next((r for r in rows if r["mount"] == rec["mount"]), None) or {}
    pool, pools = None, None
    if row.get("cls") == "watched":
        pool = next((p for p in known or () if p["id"] == "data"), None) or next(
            (p for p in sys_pools if p["id"] == "data"), None)
    elif row.get("cls") == "pending":  # a disk: its id is the logger's (by device, while mounted), or diskutil's
        live = {r["mount"] for r in rows if r.get("pool") == row.get("pool")}
        pool = next((p for p in known or () if p.get("dev") == row.get("pool") and p.get("mount") in live), None)
        if pool is None and hasattr(P, "volume_facts"):  # diskutil about this mount alone (and its container)
            try:
                f = P.volume_facts(rec["from"])
            except Exception:
                f = None
            if not f:
                return None, "%s: diskutil did not answer about %s; try again in a moment" % (
                    path, term_text(rec["mount"])[:64]), None
            lp, rows = P.disk_pools(recs, {P.mount_key(rec): f})
            row = next((r for r in rows if r["mount"] == rec["mount"]), None) or {}
            pool = next((p for p in lp if p.get("dev") == row.get("pool")), None) \
                if row.get("cls") == "listed" else None
    if pool is None:
        return None, "%s is on %s, which %s does not record (%s)" % (
            path, term_text(row.get("name") or rec["mount"])[:64], BRAND, row.get("why") or "not a disk"), None
    free = _statvfs_gb(at, rec.get("fs"))
    return dict(pool, free_gb=free if free is not None else pool["free_gb"]), None, pools


def _disk_pool_by_id(s, pid):
    """The sample with pool `pid`'s free space read now (statvfs of its mount, from this machine's own list,
    never a path from the ledger): the logger's list where the sample has it, else every pool read live."""
    pools = disk_pools_of(s) if isinstance(s.get("disks"), list) else None
    if pools is None and disk_reservable():
        pools = live_volumes()[0]
        if pools is None:
            return s
        s = dict(s, disks=pools, **({"disks_partial": True} if live_volumes_partial() else {}))
    p = next((x for x in pools or () if x["id"] == pid), None)
    if p is None or not isinstance(p.get("mount"), str):
        return s
    free = _statvfs_gb(p["mount"], p.get("fs"))
    return s if free is None else _with_disk(s, dict(p, free_gb=free))


def _with_disk(s, pool, pools=None):
    """The sample with `pool` as just read, and every pool of `pools` when the sample had no list. A sample whose
    list holds only what was read here is marked `disks_partial`: a missing pool is then not gone."""
    base = pools if pools is not None else disk_pools_of(s) if isinstance(s.get("disks"), list) else None
    out = dict(s, disks=[p for p in base or () if p["id"] != pool["id"]] + [pool])
    if base is None:
        out["disks_partial"] = True
    return out


def _disk_of(r):
    """A lease's disk part (`res.disk` with an `ask` and a `pool` id), or None."""
    d = (r.get("res") or {}).get("disk") if ledger_version(r) >= 2 else None
    return d if isinstance(d, dict) and _num(d.get("ask"), 0.001, DISK_MAX_GB) and _str(80, _ID)(d.get("pool")) \
        else None


def _disk_name(d):
    """How a lease's volume is named to people: its name when it was reserved, else its pool id."""
    n = d.get("name") if isinstance(d.get("name"), str) and d.get("name") else None
    return term_text(n or d["pool"])[:64]


def disk_view(s, leases):
    """The disk pools as admission sees them (02 §6.1), by pool id: `free`, `low` and `crit` (floors),
    `margin` (kept back: the low floor and headroom), `level` (critical below its critical floor),
    `reserved` (Σ what grants got) and `left` = free − margin − Σ over grants max(0, got − used): what a
    new reservation can have. And whether the sample lists every pool of this machine (the logger's
    list, or one read live): only then is a reserved pool that is missing gone."""
    out = {}
    for p in disk_pools_of(s):
        low, crit = disk_floors(p)
        out[p["id"]] = {"free": p["free_gb"], "low": low, "crit": crit, "margin": disk_margin(low),
                        "level": "critical" if p["free_gb"] < crit else "low" if p["free_gb"] < low else "ok",
                        "name": p.get("name"), "reserved": 0.0, "left": p["free_gb"] - disk_margin(low)}
    for r in leases:
        d = _disk_of(r)
        if r["state"] == "granted" and d and d["pool"] in out and _num(d.get("got"), 0, DISK_MAX_GB):
            used = d["used"] if _num(d.get("used"), 0, DISK_MAX_GB) else 0.0
            out[d["pool"]]["reserved"] += d["got"]
            out[d["pool"]]["left"] -= max(0.0, d["got"] - used)
    return out, isinstance(s.get("disks"), list) and not s.get("disks_partial")


# ----- GPU reservations (G, 1.14.0; 02 §6.5.1): the code is oomph_gpu.py's, loaded when a lease or a request has a
# GPU part (_G); what readers and the sanitizer need without it stays here.
GPU_PCT_MAX = 100            # % of one GPU
VRAM_MAX_GB = 4096           # GB of GPU memory in one request: more than any card has, to keep the arithmetic sane
VRAM_MIN_GB = 0.01           # the least GPU memory a request holds (GB are kept to two decimals)
GPU_STATE_MAX = 16           # cards in the ledger's state
_GPU_UUID = re.compile(r"GPU-[0-9a-fA-F-]{8,60}")
_GPU_DEV = re.compile(r"gpu\d{1,3}")
_GPU_MOD = []


def _G():
    """oomph_gpu, bound to this module (it reads this module's names as its own): imported at the first GPU part,
    so that what never meets one (oomph top, the hook) does not compile or hold it."""
    if not _GPU_MOD:
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        sys.modules["oomph_gpu_host"] = sys.modules[__name__]
        import oomph_gpu
        _GPU_MOD.append(oomph_gpu)
    return _GPU_MOD[0]


def _gpu_parts(r):
    """A lease's GPU parts (oomph_gpu._gpu_parts), or None at once for a lease without one."""
    res = r.get("res") if isinstance(r.get("res"), dict) else None
    return _G()._gpu_parts(r) if res and ("gpu" in res or "vram" in res) else None


def gpu_reservations_on(config=None):
    """Are new GPU parts allowed here (02 §6.5.1)? "gpu_reservations" in the root-owned configuration file, or
    OOMPH_GPU_RESERVATIONS=1 (tests, one command, a per-user Linux install without root); read per request. Off by
    default in 1.14, until it has been measured with real model runs. It gates only new GPU parts: evaluating,
    measuring, ending and showing GPU reservations always run."""
    return switched_on(setting("gpu_reservations", config=config))


def _home_short(p):
    home = os.path.expanduser("~")
    return "~" + p[len(home):] if home not in ("", "/") and p.startswith(home + "/") else p


def ledger_info():
    """Which ledger this is, for people and agents (03 §3.5): `kind` shared (every account, or a
    group, coordinates through it) or user (only this user's own sessions do: Linux without a
    machine-wide ledger), its path and who shares it. By the folder's mode; lstat only."""
    try:
        st = os.lstat(LEDGER_DIR)
        mode = st.st_mode if stat.S_ISDIR(st.st_mode) else None
    except OSError:
        mode = None
    if mode is None:
        mode = PATHS_HERE["ledger_mode"] if LEDGER_DIR == _path("ledger") else 0o700
    if mode & 0o002:
        kind, members = "shared", "every account on this Mac" if sys.platform == "darwin" else "everyone"
    elif mode & 0o020:
        import grp
        try:
            members = "group " + grp.getgrgid(st.st_gid).gr_name
        except (KeyError, NameError):
            members = "a group"
        kind = "shared"
    else:
        kind, members = "user", "you"
    return {"kind": kind, "path": LEDGER_DIR, "members": members}


def _boot_id():
    """This boot's id on Linux (a ledger written before the last boot holds no live lease, 03 §7.3);
    None elsewhere."""
    if not sys.platform.startswith("linux"):
        return None
    try:
        v = plat().boot_id()
    except Exception:
        return None
    return v if isinstance(v, str) and _ID.fullmatch(v) else None


def _boot_time():
    try:
        return time.time() - time.clock_gettime(time.CLOCK_BOOTTIME)
    except (AttributeError, OSError):
        return None


def _scope_id(s):
    """The scope a request made from this sample belongs to: "host", or its cgroup (03 §7.3)."""
    sc = s.get("scope") if isinstance(s.get("scope"), dict) else {}
    return str(sc.get("id"))[:200] if sc.get("kind") == "cgroup" and sc.get("id") else "host"


def _whoami():
    try:
        return pwd.getpwuid(os.getuid()).pw_name[:64]
    except KeyError:
        return str(os.getuid())


# ----- the shared directory (H0)
# LEDGER_DIR is world-writable (dir 0777, files 0666): every session and user on this Mac
# shares it, so anything in it may have been planted — a symbolic or hard link to someone
# else's file, a FIFO, a device, an endless or sparse file, JSON with huge numbers or deep
# nesting. Everybody's file handling goes through the few functions below, and nothing
# running as root comes here at all: a root caller runs its ledger operation in a child as
# the invoking user (or nobody), and the root daemon only ever sees what such a child
# printed, rebuilt from typed, capped fields.
LIMITS = {                   # the one table of limits for what is read from the directory
    "log_line": 1 << 20,     # a line of the logger's samples or events (a real one: under 10 KB) ...
    "log_file": 256 << 20,   # ... and one of its files, unpacked (a real day: about 30 MB)
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
PY = "/usr/bin/python3" if sys.platform == "darwin" or not os.path.isabs(sys.executable or "") else sys.executable
# (on Linux the Python this runs on, which linux/install.sh chose: /usr/bin/python3 can be too old there)
_lock_wait = LOCK_WAIT_S
_held = None                 # the Ledger whose lock this process holds (the history log is written under it)
_given = None                # (sample, procs) a root parent measured for its unprivileged child
_RID = re.compile(r"r\d{1,15}")


class LedgerError(Exception):
    """The shared ledger can't be used safely right now (refused, busy, or its child failed)."""


class LedgerBusy(LedgerError):
    """The ledger lock wasn't free within the deadline."""


def _not_root(what):
    """The fence: whatever path leads here, a process running as root stops, unless the ledger is
    root's own (_root_in_place)."""
    if os.geteuid() == 0 and not _root_in_place():
        raise LedgerError("%s as root refused: root never opens the shared ledger directory" % what)


def _root_in_place():
    """True for root's own per-user ledger on Linux, which root then uses in place (03 §7.5: "euid
    0, no shared ledger: root's own per-user ledger, mode 0700, in place"): a root agent in a
    container, `su -`. Only without sudo (sudo's ledger is the user's, written by their child),
    only at the default path (not one OOMPH_LEDGER_DIR names), and only when no one but root can
    have put anything there: every folder from / down to the ledger, as far as it exists, is a
    real folder owned by root that neither group nor others can write, and the ledger folder
    itself is root's alone (0700 or less). Anything else goes through the child, as before."""
    if not sys.platform.startswith("linux") or os.geteuid() != 0 or os.environ.get("OOMPH_LEDGER_DIR"):
        return False
    try:
        if int(os.environ.get("SUDO_UID") or 0) > 0:
            return False
    except ValueError:
        return False
    if LEDGER_DIR != _path("ledger") or not os.path.isabs(LEDGER_DIR):
        return False
    p = "/"
    for part in [x for x in os.path.normpath(LEDGER_DIR).split("/") if x] + [None]:
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return True  # the rest is created by root, 0700
        except OSError:
            return False
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            return False
        if part is None:
            return not st.st_mode & 0o077
        p = os.path.join(p, part)
    return False


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
    descriptor's mode is the file's (an ACL that denies one user is the gap that remains). On top
    of that, after the read the file must still have one link and the name must still be that
    file; a writer that renamed a new file over it meanwhile makes the read start again (three
    tries)."""
    for _ in range(3 if shared else 1):
        data = _read_once(name, cap, dir_fd, tail, shared)
        if data is not _MOVED:
            return data
    return None


_MOVED = object()


def _line_start(fd, pos, cap):
    """Where the first whole line at or after `pos` starts (just past a newline), looked for within
    `cap` bytes; None without one."""
    end = pos + cap
    while pos < end:
        b = os.pread(fd, min(1 << 16, end - pos), pos)
        if not b:
            return None
        k = b.find(b"\n")
        if k >= 0:
            return pos + k + 1
        pos += len(b)
    return None


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
        start = 0
        if st.st_size > cap:
            if not tail:
                return None
            start = _line_start(fd, st.st_size - cap, cap)   # the fragment skipped here, not cut from a copy
            if start is None:
                return b""
            os.lseek(fd, start, os.SEEK_SET)
        # what the file holds in one read and one byte more to see it grow; past that 64 KB at a time.
        # One part is joined without a copy: a MB of tail costs a MB, not the three of chunks, join and cut.
        parts, n, cut = [], 0, False
        while n <= cap:
            b = os.read(fd, min(max(st.st_size - start, 0) + 1 if not parts else 1 << 16, cap + 1 - n))
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


def read_config(path=CONFIG_FILE, owner=0):
    """The root-owned configuration as a dict; {} when it is missing or not to be trusted. Both
    the file and its directory must belong to root (`owner`: a test's own user) and be writable by
    nobody else, the file a
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
            if st.st_uid != owner or st.st_mode & 0o022:
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


# The GPU at full speed (IOReport, in a helper that runs as nobody) for everybody, or only for whoever asks.
# Opt-in since 1.9.3. On by default is prepared (1.10.6) and waits for one check by hand: the figure against
# `sudo powermetrics --samplers gpu_power` under a GPU load (roadmap 02 §4.2). Then this one constant
# becomes True; "ioreport": false (OOMPH_IOREPORT=0) or "no_ioreport" still switches it off on a Mac.
IOREPORT_DEFAULT = False


def ioreport_wanted(config=None):
    """Whether the logger may start the IOReport helper for the GPU's full-speed figure (roadmap 02
    §4.2): "ioreport" in the configuration file (or OOMPH_IOREPORT) when it is set, else
    IOREPORT_DEFAULT; never with "no_ioreport" (OOMPH_NO_IOREPORT=1), which wins."""
    config = read_config() if config is None else config
    v = setting("ioreport", config=config)
    return (IOREPORT_DEFAULT if v is None else switched_on(v)) and \
        not switched_on(setting("no_ioreport", config=config))


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
#     cpu, gpu, vram, disk, mem: {ask, min, got, used, peak, tree, w, dev, pool, unified, and from 1.12.3 the
#     advice `flag` "over" | "idle" with its counters over_n, over_t, low_t}} (gb and
#     used_gb / peak_gb / baseline_gb stay as the memory mirrors 1.8 readers read; gb is 0 for a
#     lease without memory), `res_granted` (the time a vector-aware evaluator granted it: a v2
#     lease granted without it was granted by old code), `waiting_on` and `hold` (pool ids),
#     `base` and `last` (counters), `segments[].res` (amounts), `watch_also` [{pid, start}] and `watch_names` (more trees
#     charged to it), `holder.uid`, `holder.ns` (the holder's pid namespace: absent = the
#     reader's), `user` (the account's name), `scope` ("host" or a cgroup), `agent` {key, slot};
#   history record: `event` "grant", `res` {resource: amount, "disk_pool"} and `peak` {resource:
#     amount}, `v`, `agent`, `user`, `note`, outcomes "refused" and "volume_gone".
LEASE_RES = ("ram", "cpu", "gpu", "vram", "disk", "mem")  # a v2 lease's resources (02 §6.2)
SEG_RES = ("ram", "cpu", "disk", "gpu", "vram")           # the amounts a segment of a lease's span keeps
_RES_NAME = re.compile(r"[a-z][a-z0-9_]{0,15}")  # a resource this code does not know: carried through, never used
RES_MAX = 16                              # resources in one `res`, known ones first
_RES_NUMS = ("ask", "min", "got", "used", "peak", "tree", "w", "else_gb", "base")
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
    return known + [k for k in x if k not in LEASE_RES and k not in ("disk_pool", "gpu_dev") and isinstance(k, str)
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
        if "uuid" in o and not _str(64, _GPU_UUID)(o["uuid"]):  # an NVIDIA card (1.14): compared as a string
            del o["uuid"]
        for f, n in (("name", 64), ("else_dev", 8)):  # the card's name and, for `elsewhere`, where the job is
            if f in o and not (isinstance(o[f], str) and 0 < len(o[f]) <= n and o[f].isprintable()):
                del o[f]
        if "unified" in o and not isinstance(o["unified"], bool):
            del o["unified"]
        for f, ok in (("flag", lambda v: v in ADVICE_FLAGS), ("over_n", lambda v: _int(v, 0, 10 ** 6)),
                      ("over_t", _t), ("low_t", _t), ("rate_t", _t), ("missing", _t), ("mseen", _t)):
            if f in o and not ok(o[f]):
                del o[f]
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
    if extra and _str(64, _ID)(x.get("gpu_dev")):  # the card a GPU grant was on (1.14): gpu1, or a UUID
        out["gpu_dev"] = x["gpu_dev"]
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


AGENT_HUES = 3                            # slots 0–2 are three hues, 3–5 the same hues a step lighter


def agent_slot(key, leases, history, now):
    """The palette slot of an agent with `key` (02 §3.8.4), chosen once by the writer that first
    sees it without one, under the ledger lock. An agent keeps its slot: a live lease or a record of
    the ledger's own history (its last HISTORY_KEEP, at most 14 days old) with this key and a slot
    wins. Otherwise a slot no live agent holds, preferring one whose hue no live agent wears (so the
    first three agents live at once wear three hues), then the one whose last block ended longest
    ago, then the lowest. With every slot held (a seventh agent): the slot the fewest live agents
    hold, then the one whose holder started first. Every front end draws the stored slot."""
    held, first = {}, {}
    for r in leases:
        a = r.get("agent") if isinstance(r.get("agent"), dict) else {}
        if "slot" not in a:
            continue
        if a.get("key") == key:
            return a["slot"]
        held.setdefault(a["slot"], set()).add(a.get("key"))
        st = (r.get("holder") or {}).get("start")
        if _num(st):
            first[a["slot"]] = min(first.get(a["slot"], st), st)
    last = {}
    for h in history:
        a = h.get("agent") if isinstance(h.get("agent"), dict) else {}
        end = h.get("ended") if _num(h.get("ended")) else 0
        if "slot" not in a or now - end > HISTORY_DAYS * 86400:
            continue
        if a.get("key") == key:
            return a["slot"]
        last[a["slot"]] = max(last.get(a["slot"], end), end)
    worn = {s % AGENT_HUES for s in held}
    free = [s for s in range(AGENT_SLOTS) if s not in held]
    if free:
        return min(free, key=lambda s: (s % AGENT_HUES in worn, last.get(s, float("-inf")), s))
    return min(range(AGENT_SLOTS), key=lambda s: (len(held[s]), first.get(s, float("inf")), s))


def _give_slots(L, now):
    """Every live lease that has an agent key and no slot gets its slot, in ledger order (so each
    choice sees the ones before it): whichever writer evaluates first, a CLI, an MCP server or the
    logger's child, also for leases an older writer made."""
    for r in L["leases"]:
        a = r.get("agent")
        if isinstance(a, dict) and a.get("key") and "slot" not in a:
            a["slot"] = agent_slot(a["key"], L["leases"], L.get("history") or [], now)


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


def no_memory(r):
    """Does a lease hold no memory: a vector lease (v 2) with no `ram`, whose gb is the mirror NO_MEM_GB
    (or 0). Its gb still counts in the memory sums, as every older reader counts it: 10 MB at most."""
    return ledger_version(r) >= 2 and "ram" not in (r.get("res") or {}) and r["gb"] <= NO_MEM_GB + 0.005


def _cpu_of(r):
    """A lease's cores part (`res.cpu` with an `ask`), or None."""
    c = (r.get("res") or {}).get("cpu") if ledger_version(r) >= 2 else None
    return c if isinstance(c, dict) and _num(c.get("ask"), 0.1, CPU_MAX) else None


def lease_need(r):
    """What a lease asks of each pool, as (least, wanted): `ram` (its gb, the mirror an older writer's amend
    moves, so it always counts: a Mac's GPU memory is in it) unless it holds no memory, `cpu` (its minimum to
    what it asked), `disk:<pool id>` (what it asked, on that one pool: disk is a stock, granted in full or not at
    all), and `gpu:<card>` and `vram:<card>` (what it asked of a GPU, 02 §6.5.1)."""
    need = {} if no_memory(r) else {"ram": (r["gb"], r["gb"])}
    c = _cpu_of(r)
    if c:
        lo = c.get("min") if _num(c.get("min"), 0.1, c["ask"]) else elastic_min(c["ask"])
        need["cpu"] = (lo, c["ask"])
    d = _disk_of(r)
    if d:
        need["disk:" + d["pool"]] = (d["ask"], d["ask"])
    gp = _gpu_parts(r)
    if gp:  # its share (gpu:<card>) and on an NVIDIA card its memory (vram:<card>; "*" while it names none)
        for p in _G()._gpu_pools(gp):
            x = gp["gpu"] if p.startswith("gpu:") else gp["vram"]
            need[p] = (x["ask"], x["ask"])
    return need


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
        if k in ("gpu", "vram") and isinstance(x.get("uuid"), str):  # the NVIDIA card it was on (a Mac has one GPU)
            amounts["gpu_dev"] = x["uuid"]
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
    dk = st.get("disk") if isinstance(st, dict) else None
    if isinstance(dk, dict):  # what is left on each disk pool (1.12.1): pool ids and numbers only
        out["state"]["disk"] = {k: v for k, v in list(dk.items())[:DISK_STATE_MAX] if _str(80, _ID)(k) and _num(v)}
    gs = st.get("gpu") if isinstance(st, dict) else None
    if isinstance(gs, dict):  # what is left on each GPU (1.14): card keys, a label and numbers only
        out["state"]["gpu"] = {k: {f: x for f, x in v.items() if (f == "dev" and _str(8, _GPU_DEV)(x)) or
                                   (f in ("pct", "gb") and _num(x, -1e6, 1e6))}
                               for k, v in list(gs.items())[:GPU_STATE_MAX] if _str(64, _ID)(k) and isinstance(v, dict)}
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
        fd = os.open(LEDGER_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        if create:
            raise LedgerError("can't create %s" % LEDGER_DIR)
        return None
    except OSError as e:
        raise LedgerError("%s is not a plain directory (%s)" % (LEDGER_DIR, e.strerror))
    if _per_user_ledger():
        st = os.fstat(fd)
        if st.st_uid != os.geteuid() or st.st_mode & 0o077:
            os.close(fd)
            raise LedgerError("%s is refused: a per-user ledger folder must be yours alone (mode 700); this one is "
                              "uid %d's with mode %03o. If you made it, `chmod 700` it; else remove it"
                              % (LEDGER_DIR, st.st_uid, stat.S_IMODE(st.st_mode)))
    return fd


def _per_user_ledger():
    """Linux's per-user ledger at its default path (under XDG_STATE_HOME, which may be anywhere,
    /tmp included): another user who made that folder first would see and steer this user's
    reservations, so it is used only while it is the user's own with mode 700. Decided by the
    process that chose the folder: under sudo the ledger child (run_bounded) is told with
    OOMPH_LEDGER_PRIVATE=1, since it can't see the XDG_STATE_HOME its parent may have taken it from.
    The variable only switches the check on, never off."""
    return os.environ.get("OOMPH_LEDGER_PRIVATE") == "1" or \
        (PATHS_HERE["ledger_mode"] == 0o700 and LEDGER_DIR == _path("ledger"))


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
        # a fresh (or lost) ledger: continue the numbering of the history log, so ids don't repeat; made by
        # vector-aware code, so of version 2 (set at creation only, 02 §6.2)
        L = {"v": 2, "seq": _history_max_seq(dfd), "leases": [], "history": []}
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
#    from 1.9.2 "agent" {key} when the holder's start time is known (D11), from 1.11.0 with its palette "slot"}
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
        if max(r["seen"], r.get("granted") or 0) > now + 60:
            return True   # stamped in the future (no writer does): it would hold its place until then
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


def _retire(L, r, outcome, now, at=None):
    """Move a lease into the history, ending it when it really ended: an expired grant at its
    expiry, a lapsed request when its owner stopped polling, one of an earlier boot at the boot
    (`at`), anything else now. A refused request keeps its arithmetic (`note`). An agent without a
    slot yet (a lease an older writer made, retired in the evaluation that would first have given
    it one) gets it here, so its records keep a colour (02 §3.8.4)."""
    a = r.get("agent")
    if isinstance(a, dict) and a.get("key") and "slot" not in a:
        a["slot"] = agent_slot(a["key"], L["leases"], L.get("history") or [], now)
    end = now
    if at is not None:
        end = min(now, at)
    elif outcome == "expired" and r.get("expires"):
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
    note = {"note": r["note"][:400]} if outcome == "refused" and isinstance(r.get("note"), str) else {}
    h.update(note)
    L["history"].append(h)
    L["history"] = L["history"][-HISTORY_KEEP:]
    try:
        _append_history(L, [_record(r, "end", now, ended=end, outcome=outcome, **note)], now)
    except OSError:
        pass  # the log is a record, not the ledger: never let it block coordination


def _tree_cpu(procs, children, root):
    """Cores the process tree at `root` keeps busy: the sum of its processes' rates (`cpu`, given by the logger)."""
    stack, seen, tot = [root], set(), 0.0
    while stack:
        x = stack.pop()
        if x in seen or x not in procs:
            continue
        seen.add(x)
        c = procs[x].get("cpu")
        tot += c if _num(c, 0, CPU_MAX) else 0.0
        stack.extend(children.get(x, []))
    return tot


def _normalize(L):
    """Leases of version 2 that older code changed (02 §9.3). One it granted (granted, but no `res_granted`)
    goes back to the queue at its own place with its grant cleared, and is granted below if it fits: nobody
    was told "granted" (older code answers only its own callers about its own leases, and a v2 lease is new
    code's). One whose gb an older amend moved gets its ram from gb (lease_res). A lease without `v` is
    never re-queued: older code made it and may have told its owner "granted"."""
    for r in L["leases"]:
        res = r.get("res") if ledger_version(r) >= 2 else None
        if not isinstance(res, dict):
            continue
        if r["state"] == "granted" and not r.get("res_granted"):
            r["state"] = "queued"
            for k in ("granted", "expires", "baseline_gb", "used_gb", "peak_gb", "note"):
                r.pop(k, None)
            for k, x in res.items():
                for f in (("used", "peak") if k == "mem" else ("got", "used", "peak", "w", "wt") + ADVICE_FIELDS
                          if k == "disk" else ("got", "used", "peak") + ADVICE_FIELDS):
                    x.pop(f, None)
        mem = res.get("mem")
        if isinstance(mem, dict) and _num(mem.get("got")) and abs(mem["got"] - r["gb"]) > 0.005:
            fixed = lease_res(r)
            res.update((k, fixed[k]) for k in ("ram", "vram", "mem") if k in fixed)


def _rate_flag(c, used, now):
    """`over` / `idle` of a rate grant (02 §6.3): used at more than OVER_X × got for OVER_N evaluations in a row
    (`over_n`, since `over_t`), or at under IDLE_X × got for IDLE_S (since `low_t`). `flag` is what readers
    show; the counters are this function's. Advice only: nothing is revoked or charged differently."""
    got = c.get("got")
    if not _num(got) or got <= 0:
        return
    if used > OVER_X * got:
        n = c["over_n"] + 1 if _int(c.get("over_n"), 0, 10 ** 6 - 1) else 1
        c["over_n"] = n
        if n == 1 or not _t(c.get("over_t")):
            c["over_t"] = round(now, 1)
    else:
        c.pop("over_n", None)
        c.pop("over_t", None)
    if used < IDLE_X * got:
        if not (_t(c.get("low_t")) and c["low_t"] <= now):
            c["low_t"] = round(now, 1)
    else:
        c.pop("low_t", None)
    flag = "over" if c.get("over_n", 0) >= OVER_N else "idle" if "low_t" in c and now - c["low_t"] >= IDLE_S else None
    if flag:
        c["flag"] = flag
    else:
        c.pop("flag", None)
    _rated(c, now)


def _rated(part, now):
    """Stamps a grant's part with the time the logger last rated its advice (`rate_t`), while it has any."""
    if any(f in part for f in ADVICE_FIELDS[:-1]):
        part["rate_t"] = round(now, 1)
    else:
        part.pop("rate_t", None)


def _advice_stale(L, now):
    """Drops advice the logger no longer rates (02 §6.3): its `rate_t` older than ADVICE_STALE_S, or none. Only
    the logger's rated evaluation keeps a flag current; when the logger stops, or a disk pool leaves the sample
    (_charge_disk rates only pools listed), a lease must not keep saying "over on CPU since …" as if it were
    now. Every evaluation runs this, so the next `oomph` call or status poll clears it for every reader."""
    for r in L["leases"]:
        res = r.get("res") if isinstance(r.get("res"), dict) else {}
        for k in ("cpu", "disk", "vram"):
            part = res.get(k)
            if isinstance(part, dict) and any(f in part for f in ADVICE_FIELDS) and not (
                    _t(part.get("rate_t")) and -60 <= now - part["rate_t"] <= ADVICE_STALE_S):
                for f in ADVICE_FIELDS:
                    part.pop(f, None)


def advice_flags(r):
    """{resource: (flag, since)} of a lease (02 §6.3; oomph_view.res_vector and the app read the same): `over`
    or `idle` on its cores (since its run of over or low use began), `over` on its disk space (since it first
    wrote more than it got), `over` or `elsewhere` on an NVIDIA card's memory (02 §6.5.1). A queued lease has none."""
    out = {}
    if r.get("state") not in (None, "granted") or (r.get("state") is None and r.get("granted") is None):
        return out
    gp = _gpu_parts(r) or {}
    for k, part in (("cpu", _cpu_of(r)), ("disk", _disk_of(r)), ("vram", gp.get("vram") if gp.get("nvidia") else None)):
        if part and part.get("flag") in ADVICE_FLAGS:
            t = part.get("over_t") if part["flag"] in ("over", "elsewhere") else part.get("low_t")
            out[k] = (part["flag"], t if _t(t) else None)
    return out


def flag_advice(r, flags, now):
    """The words for a holder about its grant's `over` / `idle` (advice_flags), each a sentence ending in a space."""
    out = []
    c, d = _cpu_of(r), _disk_of(r)
    f, t = flags.get("cpu", (None, None))
    if f == "over" and c and _num(c.get("got")):
        out.append("Your processes keep %s cores busy, more than the %s granted: run with fewer jobs (-j%d), or "
                   "amend the reservation (`oomph amend %s --cpu N`). " % (
                       cores_text(_cn(c["used"])) if _num(c.get("used")) else "more", cores_text(_cn(c["got"])),
                       max(1, int(c["got"])), r["id"]))
    elif f == "idle" and c and _num(c.get("got")):
        out.append("Your %s cores have been nearly idle%s: release them, or amend the reservation (`oomph amend %s "
                   "--cpu 0` drops them) if the heavy part is over. " % (
                       cores_text(_cn(c["got"])), " for %d min" % round((now - t) / 60) if _t(t) else "", r["id"]))
    if flags.get("disk", (None,))[0] == "over" and d and _num(d.get("got")):
        out.append("%s GB written to %s, more than the %s GB reserved: grow it (`oomph amend %s --disk NG`) before "
                   "writing more. " % (_gb(d["w"]) if _num(d.get("w")) else "More", _disk_name(d), _gb(d["got"]), r["id"]))
    if "vram" in flags:
        out.append(_G()._gpu_flag_text(r, flags["vram"][0]))
    return "".join(out)


def _charge_cpu(L, procs, children, now=None):
    """Cores each grant's process tree keeps busy (`res.cpu.used`, and its `peak`), from the logger's rates
    per process: only the logger's child has them (02 §6.3, who measures); every other evaluation leaves the
    figures as they are. Grants watching the same tree share its load in grant order, as memory does, and
    the last takes the rest: what a holder burns beyond its grant shows in its own `used`, while admission
    charges a grant no more than it got (cpu_pool). With `now`, each grant's `over` / `idle` advice too."""
    groups = {}
    for r in L["leases"]:
        c = _cpu_of(r)
        if r["state"] == "granted" and c and _num(c.get("got")):
            groups.setdefault(r.get("watch"), []).append(r)
    for w, rs in groups.items():
        rs.sort(key=lambda r: r["granted"])
        load = 0.0 if w is None or w not in procs else _tree_cpu(procs, children, w)
        for i, r in enumerate(rs):
            c = r["res"]["cpu"]
            share = load if i == len(rs) - 1 else min(c["got"], load)
            load -= share
            c["used"] = round(share, 2)
            c["peak"] = round(max(c.get("peak", 0), share), 2)
            if now is not None:
                _rate_flag(c, share, now)


def _tree_w(procs, children, root):
    """MB/s the process tree at `root` writes to disk: the sum of its processes' rates (`w`, given by the logger)."""
    stack, seen, tot = [root], set(), 0.0
    while stack:
        x = stack.pop()
        if x in seen or x not in procs:
            continue
        seen.add(x)
        w = procs[x].get("w")
        tot += w if _num(w, 0, 1e7) else 0.0
        stack.extend(children.get(x, []))
    return tot


def _charge_disk(L, s, procs, children, now):
    """What each disk grant has used of its pool (02 §6.3), from the logger's write rates per process: only
    the logger's child has them, as for cores. `w` adds up what the grant's tree wrote since the grant (its
    rate times the time since it was last counted, `wt`, at most WRITE_DT_MAX_S: a process that ends between
    two samples is missed, which only makes `used` smaller and admission more careful). Then a pool's drop is
    shared out in grant order, as memory shares a tree's growth: used = min(got, own writes, the pool's drop
    since its own grant, what earlier grants left of the drop since the first), so Σ used over a pool never
    exceeds what it lost, and space someone else filled is not credited to a grant that wrote nothing.
    `base.free_gb` is the pool's free space at the grant."""
    free = {p["id"]: p["free_gb"] for p in disk_pools_of(s)}
    groups = {}
    for r in L["leases"]:
        d = _disk_of(r)
        if r["state"] == "granted" and d and _num(d.get("got")) and d["pool"] in free:
            groups.setdefault(d["pool"], []).append(r)
    for pid, rs in groups.items():
        rs.sort(key=lambda r: r["granted"])
        base = [(r.get("base") or {}).get("free_gb") for r in rs]
        drops = [max(0.0, b - free[pid]) if _num(b) else 0.0 for b in base]
        left = drops[0]
        for r, drop in zip(rs, drops):
            d, w = r["res"]["disk"], r.get("watch")
            t0 = d["wt"] if _t(d.get("wt")) and d["wt"] <= now else r["granted"]
            rate = _tree_w(procs, children, w) if w in procs else 0.0
            d["w"] = round((d["w"] if _num(d.get("w"), 0, 1e7) else 0.0)
                           + rate * min(max(0.0, now - t0), WRITE_DT_MAX_S) / 1024.0, 3)
            d["wt"] = round(now, 1)
            u = max(0.0, min(d["got"], d["w"], drop, left))
            left -= u
            d["used"] = round(u, 2)
            d["peak"] = round(max(d["peak"] if _num(d.get("peak")) else 0.0, u), 2)
            if d["w"] > d["got"] + 0.005:  # wrote more than it reserved: `over` (02 §6.3), since it first did
                if d.get("flag") != "over" or not _t(d.get("over_t")):
                    d["over_t"] = round(now, 1)
                d["flag"] = "over"
            else:
                d.pop("flag", None)
                d.pop("over_t", None)
            _rated(d, now)


def _volumes_gone(L, s, now):
    """Reservations on a pool that is no longer there (02 §6.2, outcome volume_gone): unplugged, or ejected. Only
    a sample that lists every pool of this machine can say a pool is missing (disk_view); one missing from it
    is marked (`missing`, when it was first missed) and its reservations end once it has been missing for
    VOLUME_GONE_S, at that first time: a remount (even at another mount point: the id is the volume's) or the
    logger asking diskutil about it again takes less. A pool that is back clears the mark. The grace counts
    only while it is looked at (`mseen`, when it was last missed): after a gap of more than VOLUME_GONE_S (the
    Mac slept, nothing evaluated) it starts again, so a volume remounted after waking is not taken for gone."""
    if not (isinstance(s.get("disks"), list) and not s.get("disks_partial")):
        return
    ids = {p["id"] for p in disk_pools_of(s)}
    for r in list(L["leases"]):
        d = _disk_of(r)
        if d is None:
            continue
        if d["pool"] in ids:
            d.pop("missing", None)
            d.pop("mseen", None)
        elif not (_t(d.get("missing")) and _t(d.get("mseen"))) or d["missing"] > now or d["mseen"] > now \
                or now - d["mseen"] > VOLUME_GONE_S:
            d["missing"] = d["mseen"] = round(now, 1)
        elif now - d["missing"] >= VOLUME_GONE_S:
            _retire(L, r, "volume_gone", now, at=d["missing"])
            L["leases"].remove(r)
        else:
            d["mseen"] = round(now, 1)


def cpu_pool(s, leases, now):
    """The pool of cores as admission sees it (02 §6.1): `cap` logical cores, `margin` kept back for the person
    at the machine, `reserved` (what grants got), `room` = cap − margin − reserved (what can still be reserved:
    a request waits for this only, never for load), `others` (load that holds no reservation) and `idle` =
    room − others (what an elastic request is given now; None when nothing says how busy the cores are).
    `others` is the logger's smoothed figure from current.json's `pools` while fresh, else the sample's busy
    cores less what the grants are charged (each at most what it got; a use not measured counts as none)."""
    pools = s.get("pools") if isinstance(s.get("pools"), dict) else {}
    pc = pools.get("cpu") if isinstance(pools.get("cpu"), dict) and _t(pools.get("t")) \
        and abs(now - pools["t"]) <= POOLS_MAX_AGE_S else {}
    cpu = s.get("cpu") if isinstance(s.get("cpu"), dict) else {}
    n = pc["cap"] if _int(pc.get("cap"), 1, CPU_MAX) else cpu["n"] if _int(cpu.get("n"), 1, CPU_MAX) \
        else (os.cpu_count() or 1)
    grants = [c for c in (_cpu_of(r) for r in leases if r["state"] == "granted") if c and _num(c.get("got"))]
    reserved = sum(c["got"] for c in grants)
    margin = cpu_margin(n)
    room = n - margin - reserved
    if _num(pc.get("others"), 0, CPU_MAX):
        others = pc["others"]
    elif _num(cpu.get("busy"), 0, CPU_MAX):
        others = max(0.0, cpu["busy"] - sum(min(c.get("used") if _num(c.get("used")) else 0.0, c["got"])
                                            for c in grants))
    else:
        others = None
    return {"cap": n, "margin": margin, "reserved": reserved, "room": room, "others": others,
            "idle": None if others is None else room - others}


POOLS = frozenset(("ram", "cpu", "disk:*", "gpu:*", "vram:*"))   # every pool this code weighs (<kind>:*: every one)
KNOWN_RES = frozenset(("ram", "cpu", "disk", "mem", "gpu", "vram"))  # the parts of a `res` it knows (mem: the mirror)


def _rate(p):
    """Does pool `p` saturate rather than run out (02 §6.1): the cores, and a GPU's share."""
    return p == "cpu" or p.startswith("gpu:")


def _blocks(p, blocked):
    """Is pool `p` held up by an earlier request that waits (`<kind>:*` in `blocked`: every pool of that kind)?"""
    return p in blocked or (":" in p and p.split(":", 1)[0] + ":*" in blocked)


def _meets(a, b):
    """Do two leases ask for a pool in common (`<kind>:*`, an NVIDIA request that names no card: any of that kind)?"""
    return any(_blocks(p, b) or _blocks(q, a) for p in a for q in b if p.split(":", 1)[0] == q.split(":", 1)[0])


def _behind(need, blocked):
    """The pools of `need` that an earlier request still waiting holds up (`disk:*` in `blocked`: every disk)."""
    return {p for p in need if _blocks(p, blocked)}


def weighable(r):
    """Can this code weigh every part of a lease? A 1.8-shaped lease always; a vector lease only when its `res`
    names nothing beyond ram, cpu, disk, gpu, vram and mem, its cores, disk and GPU parts are ones this code reads,
    and it asks for something. A later writer's lease of a resource this code does not know is not: this code
    neither grants it nor lets anyone pass it (02 §9.3, as 1.9.2 to 1.11 did with every vector lease, 1.12.0 with a
    disk lease and 1.12.1 to 1.13 with a GPU lease), so no stale process hands out what it cannot weigh."""
    if ledger_version(r) < 2:
        return True
    res = r.get("res") or {}
    if not set(res) <= KNOWN_RES or ("cpu" in res and _cpu_of(r) is None) or ("disk" in res and _disk_of(r) is None) \
            or _gpu_parts(r) is False:
        return False
    return bool(lease_need(r))


def _waits(r, waiting, hold):
    """A queued vector lease's `waiting_on` (what it is short of or queued behind) and `hold` (what it has
    ever been short of). A 1.8-shaped lease asks for memory alone and gets neither: _status tells it."""
    if ledger_version(r) >= 2:
        r["waiting_on"], r["hold"] = sorted(waiting), sorted(hold)


def _evaluate(L, s, procs, now, rated=False):
    """Drop dead, expired and abandoned entries, put back in the queue what older code granted of a
    vector lease, account for what grants already use, then grant queued requests in arrival order,
    pool by pool (02 §6.4).

    A request needs some pools: `ram` (its gb, unless it holds no memory), `cpu` (between its
    minimum and what it asked) and one disk pool (`disk:<id>`, what it asked). It is granted all of
    them at once or none: memory when it fits (or, as before, when no grant holds memory and the level
    is ok: alone), cores when what can still be reserved (room) covers its minimum, and then as many as
    are idle, between its minimum and what it asked, disk space when what is left of the pool covers it
    and the pool is not critical (never alone). Nothing is granted while memory is critical. A request that waits holds up the pools it waits
    for, so nobody behind it takes them; while it waits for a turn at the cores (a rate pool) it holds up
    only those (and the rate pools it has ever been short of), so memory requests pass it; once its turn
    has come it holds up everything it has ever been short of, so it cannot alternate between two
    shortages. With memory alone this is today's strict first come, first served. A request of another
    scope (a cgroup, 03 §7.3) is granted only by a process in it, and does not hold the line here.
    `rated`: the process table carries the logger's rates (the logger's child), so each grant's cores
    and disk writes are charged. Reservations on a pool that is gone end first (_volumes_gone)."""
    keep = []
    bid = _boot_id()
    if bid and L.get("boot") and L["boot"] != bid:  # written before the last boot: no holder is alive
        bt = _boot_time()
        for r in L["leases"]:
            _retire(L, r, "holder_gone", now, at=bt)
        L["leases"] = []
    if bid:
        L["boot"] = bid
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
    _normalize(L)
    _give_slots(L, now)  # the agent's colour (D11), before any grant record is written
    _volumes_gone(L, s, now)
    anygpu = any(_gpu_parts(r) for r in L["leases"])  # oomph_gpu is loaded only then (_G)
    if anygpu:
        _G()._gpus_gone(L, s, now)

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
    if rated:
        _charge_cpu(L, procs, children, now)
        _charge_disk(L, s, procs, children, now)
    if anygpu:
        _G()._charge_gpu(L, s, procs, children, now, rated)
    _advice_stale(L, now)

    v = verdict(s)
    free = free_physical_gb(s)
    margin = margin_for(s)
    mine = _scope_id(s)
    granted = lambda: [x for x in L["leases"] if x["state"] == "granted"]
    out_all = sum(r["gb"] - r.get("used_gb", 0) for r in granted())
    # Inside a limited cgroup both walls count, each against its own reservations (03 §7.3): the
    # cgroup's limit against the grants of the same scope, the host's memory against every grant.
    outstanding = out_all if mine == "host" else sum(r["gb"] - r.get("used_gb", 0) for r in granted()
                                                     if (r.get("scope") or "host") == mine)
    avail = free - outstanding - margin
    sc = s.get("scope") if mine != "host" else {}
    if mine != "host" and _num(sc.get("host_avail_gb")) and _num(sc.get("host_margin_gb")):
        avail = min(avail, sc["host_avail_gb"] - out_all - sc["host_margin_gb"])
    big = oversize_for(s)
    cpu = cpu_pool(s, L["leases"], now)
    disks = disk_view(s, L["leases"])[0]
    gview, glisted = _G().gpu_view(s, L["leases"]) if anygpu else ({}, False)
    blocked, recs = set(), []
    for r in [x for x in L["leases"] if x["state"] == "queued"]:
        if (r.get("scope") or "host") != mine:  # granted only by a process that can measure its scope
            continue
        if not weighable(r):  # a later writer's: it holds the line, its waiting_on and hold as they are
            blocked |= POOLS
            continue
        need = lease_need(r)
        if v["level"] == "critical":  # nothing new starts: anything new adds load
            _waits(r, {"critical"}, r.get("hold") or ())
            continue
        short, note = set(), None
        if "ram" in need and r["gb"] > avail:
            alone = "ram" not in blocked and v["level"] == "ok" and \
                not any(x["state"] == "granted" and "ram" in lease_need(x) for x in L["leases"])
            if not alone:
                short.add("ram")
            elif big is None or r["gb"] <= big:
                note = ("larger than the %.1f GB available now; granted because no other work is reserved — "
                        "expect swapping" % max(0.0, avail)) if big is None else (
                       "leaves less than the %.1f GB %s keeps free here: expect tight, and swapping"
                       % (margin, BRAND))
            else:  # Linux: even alone it would not fit (03 §5.3, §7.3)
                lx = s.get("linux") if isinstance(s.get("linux"), dict) else {}
                sw = lx.get("swap_room_gb") if _num(lx.get("swap_room_gb"), 0, 1e6) else lx.get("kswap_free_gb") or 0
                floor = lx.get("floor_gb") if _num(lx.get("floor_gb"), 0, 1e6) else max(0.0, free + sw - big)
                r["note"] = ("%.1f GB does not fit: %.1f GB is available, %s, and %.1f GB must stay free. Ask for at "
                             "most %.1f GB." % (r["gb"], free, "swap can take %.1f GB more" % sw if sw >= 0.1 else
                                                "there is no swap to spare", floor, big))
                _retire(L, r, "refused", now)
                L["leases"].remove(r)
                continue
        if "cpu" in need and cpu["room"] < need["cpu"][0] - 1e-9:
            short.add("cpu")
        for p in need:  # a disk pool: not while it is critical, and what is left of it must cover the request
            d = disks.get(p[5:]) if p.startswith("disk:") else None
            if p.startswith("disk:") and (d is None or d["level"] == "critical" or d["left"] < need[p][1] - 1e-9):
                short.add(p)
        gp, gkey, gpools, gbehind = _gpu_parts(r), None, set(), set()
        if gp:  # its card: the one it named, or where it fits now (02 §6.5.1)
            gkey, gshort, gbehind, gpools = _G()._gpu_fit(gp, gview, glisted, blocked)
            short |= gshort
        behind = _behind([p for p in need if not p.startswith(("gpu:", "vram:"))], blocked) | gbehind
        if short or behind:
            hold = set(r.get("hold") or ()) & (set(need) | gpools) | short
            _waits(r, short | behind, hold)
            turn = {p for p in short | behind if _rate(p)}  # waiting for a turn at the cores or a GPU: holds up only those
            blocked |= (turn | {p for p in hold if _rate(p)}) if turn else (short | behind | hold)
            continue
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
        notes = [note] if note else []
        if ledger_version(r) >= 2:
            res = r.setdefault("res", {})
            if "ram" in need:  # a Mac's GPU memory is memory: in gb and mem, not in ram (02 §6.2)
                u = gp["vram"]["ask"] if gp and gp["vram"] and not gp["nvidia"] else 0.0
                if "ram" in res or not u:
                    ram = round(max(0.0, r["gb"] - u), 2)
                    res["ram"] = dict(res.get("ram") or {}, ask=ram, got=ram)
                res["mem"] = dict(res.get("mem") or {}, got=r["gb"])
            if "cpu" in need:
                lo, hi = need["cpu"]
                top = min(hi, cpu["room"])
                got = _cn(max(lo, _cores(top if cpu["idle"] is None else min(max(0.0, cpu["idle"]), top), hi)))
                if got < hi:
                    if cpu["idle"] is not None and cpu["idle"] < top:
                        notes.append("the cores are busy with work that holds no reservation (%.1f of %d): granted "
                                     "%s of the %s cores asked" % (cpu["others"], cpu["cap"], cores_text(got),
                                                                    cores_text(hi)))
                    else:
                        notes.append("other reservations hold %s of the %d cores that can be reserved: granted %s of "
                                     "the %s asked" % (cores_text(cpu["reserved"]), cpu["cap"] - cpu["margin"],
                                                       cores_text(got), cores_text(hi)))
                res["cpu"] = dict({k: x for k, x in res["cpu"].items() if k not in ADVICE_FIELDS}, got=got)
                cpu["room"] -= got
                cpu["reserved"] += got
                if cpu["idle"] is not None:
                    cpu["idle"] -= got
            dk = _disk_of(r)
            if dk:  # in full; what it has used is charged from here on (its writes, the pool's drop: 02 §6.3)
                d = disks[dk["pool"]]
                res["disk"] = dict({k: x for k, x in dk.items() if k not in ("w", "wt", "used", "peak") + ADVICE_FIELDS},
                                   got=dk["ask"], w=0.0, wt=round(now, 1))  # used and peak: once measured
                r["base"] = dict(r.get("base") or {}, free_gb=d["free"])
                d["left"] -= dk["ask"]
                d["reserved"] += dk["ask"]
            if gp:  # on its card, which each part keeps
                _G()._gpu_grant(r, gp, gkey, gview, now, procs, children)
            segs = r.get("segments")
            if segs:
                segs[-1]["res"] = {k: x.get("got", x.get("ask")) for k, x in res.items() if k in SEG_RES
                                   and isinstance(x, dict) and _num(x.get("got", x.get("ask")))}
            r["res_granted"] = round(now, 1)
            r.pop("waiting_on", None)
            r.pop("hold", None)
            recs.append(_record(r, "grant", now))
        if notes:
            r["note"] = "; ".join(notes)
    if recs:
        try:
            _append_history(L, recs, now)
        except (OSError, LedgerError):
            pass  # the log is a record, not the ledger
    L["state"] = {"t": round(now, 1), "level": v["level"], "free_gb": free, "margin_gb": round(margin, 1),
                  "reserved_gb": round(outstanding, 1), "available_gb": round(avail, 1),
                  "cpu_cap": cpu["cap"], "cpu_margin": cpu["margin"], "cpu_reserved": round(cpu["reserved"], 1),
                  "cpu_available": round(cpu["room"], 1)}
    if cpu["idle"] is not None:
        L["state"]["cpu_idle"] = round(cpu["idle"], 1)
    if disks:  # what can still be reserved on each disk pool (by id), for the answers (_available)
        L["state"]["disk"] = {k: round(d["left"], 1) for k, d in sorted(disks.items())[:DISK_STATE_MAX]}
    gst = {k: dict({"dev": c["id"], "pct": round(c["room"], 1)},
                   **({"gb": round(c["left"], 2)} if c["nvidia"] and c.get("left") is not None else {}))
           for k, c in sorted(gview.items(), key=lambda kc: kc[1]["index"])[:GPU_STATE_MAX] if c["reservable"]}
    if gst:  # and on each GPU (by card: share, and an NVIDIA card's memory), when known
        L["state"]["gpu"] = gst


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


def _ids(user, group):
    """(uid, gid) of user:group, names resolved here: a group that has no such name (Debian and
    Ubuntu call nobody's group nogroup) is the user's own primary group. Numbers pass through."""
    pw = None
    if not isinstance(user, int):
        try:
            pw = pwd.getpwnam(user)
        except KeyError:
            raise LedgerError("no user named %s on this system" % user)
        user = pw.pw_uid
    if not isinstance(group, int):
        try:
            group = grp.getgrnam(group).gr_gid
        except KeyError:
            try:
                group = (pw or pwd.getpwuid(user)).pw_gid
            except KeyError:
                raise LedgerError("no group named %s on this system" % group)
    return user, group


def _drop_to(user, group):
    """subprocess arguments that run a child as user:group without root's other groups, when we
    are root; none when we aren't (the child then simply is us). The ids are numeric (_ids)."""
    if os.geteuid() != 0:
        return {}
    uid, gid = _ids(user, group)
    return {"user": uid, "group": gid, "extra_groups": []}


def run_bounded(cmd, data, cap, timeout, **kw):
    """Run `cmd` (in /, with a minimal environment) with `data` on its stdin and read at most
    `cap` bytes of its stdout, and the last few KB of its stderr, within `timeout` seconds. A
    child that takes longer or says more is killed; either way it is reaped. Returns (exit
    status, stdout, stderr text); raises LedgerError on a timeout or an overflow."""
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/",
                         env=dict({"PATH": "/usr/bin:/bin", "OOMPH_LEDGER_DIR": LEDGER_DIR},
                                  **({"OOMPH_LEDGER_PRIVATE": "1"} if _per_user_ledger() else {})), **kw)

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
    CHILD_TIMEOUT_S. Not root, or root's own ledger on Linux (_root_in_place): a plain call."""
    def wrap(fn):
        _LEDGER_CALLS[fn.__name__] = fn

        @functools.wraps(fn)
        def call(*args, **kw):
            if os.geteuid() != 0 or _root_in_place():
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


def _kept_to_group(d):
    """The gid a folder is kept to (no access for others), else None."""
    try:
        st = os.lstat(d)
    except OSError:
        return None
    return st.st_gid if stat.S_ISDIR(st.st_mode) and not st.st_mode & 0o007 else None


def _in_group(user, gid):
    try:
        return pwd.getpwnam(user).pw_gid == gid or user in grp.getgrgid(gid).gr_mem
    except (KeyError, OverflowError):
        return False


def _call_as_user(name, args, kw, inputs):
    d = {"args": [_enc(a) for a in args], "kw": {k: _enc(v) for k, v in kw.items()}}
    if gpu_reservations_on():  # the switch as root's command has it (the child's environment is a minimal one)
        d["gpu_reservations"] = True
    if inputs:
        s, procs, _ = _decide_inputs()
        d["s"], d["procs"] = s, list(procs.values())
    user, group = _child_user()
    if user == "nobody" and sys.platform.startswith("linux") and not os.environ.get("OOMPH_LEDGER_DIR") and \
            LEDGER_DIR == _path("ledger"):  # root's per-user ledger; the machine's (/var/lib/oomph/ledger) is nobody's too
        raise LedgerError("root's own ledger %s is used only where nobody else can reach it: every folder "
                          "above it root's and not writable by group or others, the folder itself 0700"
                          % LEDGER_DIR)  # nobody could not open it in root's home anyway
    if user == "nobody" and sys.platform.startswith("linux") and LEDGER_DIR == PATHS_HERE.get("shared_ledger"):
        g = _kept_to_group(LEDGER_DIR)
        if g is not None and not _in_group("nobody", g):
            raise LedgerError("the machine's ledger %s is kept to group %s, and root without sudo reaches it as "
                              "nobody, who is not in it: reserve with sudo from the account of a member (sudo %s ...)"
                              % (LEDGER_DIR, _group_name(g), CMD))
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
    if d.get("gpu_reservations") is True:  # OOMPH_GPU_RESERVATIONS=1 on root's command: for this operation too
        os.environ["OOMPH_GPU_RESERVATIONS"] = "1"
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
    s = s or (_sample_override() if _sample_override else _with_pools(live_sample(with_procs=False)))
    return s, plat().collect_procs(), time.time()


def _with_pools(s):
    """A live sample with what only the logger knows well, while its current.json is fresh (02 §5.2, §6.1): the
    pools (`others` on the cores), its cpu block (how busy the cores were), its disks (every pool of this
    machine by id: what says a reserved volume is gone) and its GPUs (each card's memory and processes: what
    GPU grants use, and what says a reserved card is gone); else as it is."""
    d = _daemon_sample()
    if d:
        s.update((k, d[k]) for k in ("pools", "cpu") if isinstance(d.get(k), dict) and k not in s)
        if isinstance(d.get("gpu"), list) and "gpu" not in s:  # its GPUs (every NVIDIA card: what says one is gone)
            s["gpu"] = d["gpu"]
        if isinstance(d.get("disks"), list) and "disks" not in s:
            s["disks"] = d["disks"]
            if d.get("disks_partial") is True:  # the logger waits for diskutil about a disk
                s["disks_partial"] = True
    return s


def _brief(r, now):
    b = {"id": r["id"], "state": r["state"], "gb": 0.0 if no_memory(r) else r["gb"], "purpose": r["purpose"],
         "project": os.path.basename(r.get("project") or "") or None, "holder_pid": r["holder"]["pid"]}
    if r.get("user"):
        b["user"] = r["user"]
    c, d = _cpu_of(r), _disk_of(r)
    if c:  # cores: what it got, or while queued what it asked
        b["cpu"] = c["got"] if r["state"] == "granted" and _num(c.get("got")) else c["ask"]
    if d:  # disk space on one pool: likewise, and which pool
        b["disk"] = d["got"] if r["state"] == "granted" and _num(d.get("got")) else d["ask"]
        b["disk_pool"] = d["pool"]
        if isinstance(d.get("name"), str) and d["name"]:
            b["disk_name"] = _disk_name(d)
    gp = _gpu_parts(r)
    for k, f in (("gpu", "gpu"), ("vram", "vram")) if gp else ():  # a GPU's share and memory, and on which card
        x = gp[k]
        if x:
            b[f] = x["got"] if r["state"] == "granted" and _num(x.get("got")) else x["ask"]
            if r["state"] == "granted" and _num(x.get("used")):
                b[f + "_used"] = x["used"]
            if isinstance(x.get("dev"), str) and _GPU_DEV.fullmatch(x["dev"]):
                b["gpu_dev"] = x["dev"]
    if r["state"] == "granted":
        b.update(used_gb=r.get("used_gb", 0), for_min=round((now - r["granted"]) / 60, 1))
        if c and _num(c.get("used")):
            b["cpu_used"] = c["used"]
        if d and _num(d.get("used")):
            b["disk_used"] = d["used"]
        if r.get("expires"):
            b["expires_in_min"] = round((r["expires"] - now) / 60, 1)
        fl = advice_flags(r)
        if fl:  # over / idle on a resource (02 §6.3): advice, shown to everyone
            b["flags"] = {k: f for k, (f, _) in fl.items()}
    else:
        b["waiting_min"] = round((now - r["requested"]) / 60, 1)
    return b


def _available(st):
    """What can still be reserved, by resource, from the ledger's state (cores, disk and GPUs only once evaluated by
    this code; disk by pool id, 02 §7.2; a GPU by its card)."""
    out = {"ram_gb": st.get("available_gb")}
    for k, f in (("cpu_cores", "cpu_available"), ("cpu_idle", "cpu_idle")):
        if _num(st.get(f)):
            out[k] = st[f]
    if isinstance(st.get("disk"), dict) and st["disk"]:
        out["disk_gb"] = {k: max(0.0, v) for k, v in st["disk"].items()}
    if isinstance(st.get("gpu"), dict) and st["gpu"]:  # by card: its label, the share and (NVIDIA) the GB left
        out["gpu"] = {k: dict({"dev": v.get("dev")}, pct=max(0.0, v.get("pct", 0.0)),
                              **({"mem_gb": max(0.0, v["gb"])} if "gb" in v else {}))
                      for k, v in st["gpu"].items()}
    return out


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
    nm, c, dk, need, gp = no_memory(r), _cpu_of(r), _disk_of(r), lease_need(r), _gpu_parts(r) or None
    out = {"status": r["state"], "id": r["id"], "gb": 0.0 if nm else r["gb"], "purpose": r["purpose"],
           "available_gb": st.get("available_gb"), "reserved_gb": st.get("reserved_gb"),
           "free_gb": st.get("free_gb"), "level": st.get("level")}
    if c or dk or gp:  # a vector request: what it asked, and what can be had (02 §7.2)
        out["asked"] = {} if nm else {"ram_gb": r["gb"]}
        if c:
            out["asked"].update(cpu_cores=_cn(c["ask"]), cpu_min=_cn(need["cpu"][0]))
        if dk:
            out["asked"].update(disk_gb=dk["ask"], disk=dk["pool"], disk_name=_disk_name(dk))
        if gp:  # a Mac's GPU memory is also in ram_gb (unified: it is memory)
            out["asked"].update((k, x) for k, x in (("gpu_pct", (gp["gpu"] or {}).get("ask")), ("gpu_device", gp["key"]),
                                                    ("gpu_mem_gb", (gp["vram"] or {}).get("ask"))) if x is not None)
        out["available"] = _available(st)
    heavy = "heavy" if c or dk or gp else "memory-heavy"
    if r["state"] == "granted":
        out["expires_in_min"] = round((r["expires"] - now) / 60, 1) if r.get("expires") else None
        if r.get("note"):
            out["note"] = r["note"]
        run = ""
        if (c and _num(c.get("got"))) or (dk and _num(dk.get("got"))):
            out["granted"] = {} if nm else {"ram_gb": r["gb"]}
        if c and _num(c.get("got")):
            got = _cn(c["got"])
            out["granted"]["cpu_cores"] = got
            out["run_with"] = {"cpu_cores": got}
            run = "Run with %s cores (-j%d): you asked for %s%s. " % (
                cores_text(got), max(1, int(got)), cores_text(c["ask"]),
                "" if got >= c["ask"] else ", and %s are what can be had now" % cores_text(got))
        if dk and _num(dk.get("got")):
            out["granted"]["disk_gb"] = dk["got"]
            run += "Write at most %s GB to %s for it. " % (_gb(dk["got"]), _disk_name(dk))
        if gp and gp["key"] and any(x and _num(x.get("got")) for x in (gp["gpu"], gp["vram"])):
            out.setdefault("granted", {} if nm else {"ram_gb": r["gb"]})
            gw, run = _G()._gpu_run_with(gp, out["granted"]), _G()._gpu_run_text(gp) + run
            out.setdefault("run_with", {})["gpu"] = gw
        out["advice"] = ("%sGranted: start the work now. Release it (release_memory / `oomph release %s`) as soon as the "
                         "%s part is over%s." % (run, r["id"], heavy, "" if not r.get("expires") else
                                                 "; it expires in %d min unless extended" % round((r["expires"] - now) / 60)))
        fl = advice_flags(r)
        if fl:  # over / idle (02 §6.3): what the grant's own processes do, said first; nothing is revoked
            out["flags"] = {k: f for k, (f, _) in fl.items()}
            out["advice"] = flag_advice(r, fl, now) + out["advice"]
    else:
        queued = [x for x in L["leases"] if x["state"] == "queued"]
        before = [x for x in queued[:queued.index(r)] if _meets(lease_need(x), need)]
        pos = len(before) + 1  # in the lines of the pools it asks for
        out["position"] = pos
        out["ahead"] = [_brief(x, now) for x in L["leases"]
                        if (x["state"] == "granted" and _meets(lease_need(x), need)) or x in before]
        waiting = r.get("waiting_on") if isinstance(r.get("waiting_on"), list) else ["ram"]
        if c or dk or gp:
            out["waiting_on"] = waiting
        room = st.get("cpu_available")
        why = ["memory is critical"] if st.get("level") == "critical" or "critical" in waiting else []
        if not why and pos > 1:
            why.append("%d request(s) are ahead of you" % (pos - 1))
        if not why and "cpu" in waiting and _num(room):
            why.append("you asked for %s %s cores, and %s can be reserved now while other reservations hold %s" % (
                "exactly" if need["cpu"][0] >= c["ask"] else "at least", cores_text(need["cpu"][0]),
                cores_text(max(0.0, room)), cores_text(st.get("cpu_reserved") or 0)))
        if not why and "ram" in waiting:
            why.append("only %.1f GB is available for new reservations" % max(0.0, st.get("available_gb") or 0))
        gw = [p for p in waiting if p.startswith(("gpu:", "vram:"))]
        if not why and gp and gw:
            why.append(_G()._gpu_wait_text(gp, gw, st))
        if not why and dk and "disk:" + dk["pool"] in waiting:
            left = (st.get("disk") or {}).get(dk["pool"])
            why.append(("%s is not mounted%s" % (_disk_name(dk), ", and this ends in %d min unless it comes back" % max(
                1, round((dk["missing"] + VOLUME_GONE_S - now) / 60)) if _t(dk.get("missing")) else "")) if left is None
                else "an earlier request waits for space on %s" % _disk_name(dk) if left >= dk["ask"]
                else "you asked for %s GB on %s, and %s GB can be reserved there now" % (
                    _gb(dk["ask"]), _disk_name(dk), _gb(max(0.0, left))))
        hint = ""
        if c and "cpu" in waiting and _num(room) and room >= 1 and need["cpu"][0] > _cores(room, c["ask"]):
            n = _cores(room, c["ask"])
            hint = " Or ask with cpu_min %s (`--cpu %s..%s`) to start now with %s." % (
                cores_text(n), cores_text(n), cores_text(c["ask"]), cores_text(n))
        out["advice"] = ("Queued #%d (%s). Don't start this work yet. Ask again with the same ticket (%s) within %d s to "
                         "keep your place — meanwhile do light work or wait.%s"
                         % (pos, "; ".join(why) or "waiting", r["id"], QUEUE_STALE_S, hint))
    return out


def _procs_around(pid):
    """The process table as far as finding `pid`'s session needs: its ancestors where the backend
    can read just those (Linux, 03 §4.4: a full scan costs ten times a Mac's), else all."""
    P = plat()
    return P.collect_procs(only={pid}) if getattr(P, "OS", "") == "linux" else P.collect_procs()


def holder_for(pid=None, kind=None):
    """Who owns a reservation made from here: the Claude session we run in, else our parent process."""
    d = plat()
    start_pid = pid or os.getppid()
    procs = _procs_around(start_pid)
    root = _session_root(procs, start_pid)
    hp = root or start_pid
    return {"pid": hp, "start": procs.get(hp, {}).get("start"), "kind": kind or ("session" if root else "process"),
            "project": d.proc_cwd(hp)}


def _on_ram(s):
    """Where a request is too big, for the refusal: "on a Mac with 16 GB RAM", "on a machine with
    …", "in a cgroup limited to 2 GB" (0.5 GB: one decimal under 1 GB, never "0 GB")."""
    ram = s.get("ram_gb") or 0
    gb = ("%.1f" if ram < 0.95 else "%.0f") % ram
    if s.get("os", "macos") == "macos":
        return "on a Mac with %s GB RAM" % gb
    return "on a machine with %s GB RAM" % gb if _scope_id(s) == "host" else "in a cgroup limited to %s GB" % gb


def _cpu_busy(s, now):
    """The sample with a reading of how busy the cores are, for an elastic request (02 §6.1): as it is when
    the logger's `pools` are fresh or the sample has its busy cores; else one quarter-second window, measured
    here and marked `window_s` (only a request with an elastic part pays for it)."""
    pools = s.get("pools") if isinstance(s.get("pools"), dict) else {}
    if (isinstance(pools.get("cpu"), dict) and _t(pools.get("t")) and abs(now - pools["t"]) <= POOLS_MAX_AGE_S) \
            or _num((s.get("cpu") or {}).get("busy") if isinstance(s.get("cpu"), dict) else None):
        return s
    try:
        blocks = _daemon_module().measure()[0]
    except Exception:  # the grant is then what can be reserved, not what is idle
        return s
    return dict(s, cpu=blocks["cpu"], window_s=blocks.get("window_s")) if isinstance(blocks.get("cpu"), dict) else s


def _refuse_cpu(s, cpu, cpu_min):
    """Why a request for cores cannot be made here, or None (02 §6.4: refusals; roadmap §4.4)."""
    if not cpu_reservable():
        return ("Cores can't be reserved on this machine: %s does not measure them here yet. Reserve memory alone, "
                "or run the work with fewer jobs." % BRAND)
    pool = cpu_pool(s, [], time.time())
    most = pool["cap"] - pool["margin"]
    if cpu_min > most:
        return ("Can't reserve %s cores %s: it has %d, %d of them are kept for the person at it, so at most %d can be "
                "reserved. Ask for fewer, or for a range that starts lower (cpu_min / `--cpu %d..%s`)." % (
                    cores_text(cpu_min), "on this Mac" if s.get("os", "macos") == "macos" else "on this machine",
                    pool["cap"], pool["margin"], most, max(1, most // 2), cores_text(cpu)))
    return None


def _to_weigh(ticket):
    """Will this reserve() call weigh a grant: a new request, or a ticket still queued? A granted ticket's
    re-poll only extends it, so it need not measure how busy the cores are (a quarter second, no logger)."""
    if not ticket:
        return True
    try:
        return any(r.get("id") == ticket and r.get("state") == "queued" for r in read_ledger()["leases"])
    except Exception:  # noqa: B902 — measure, as for a new request
        return True


def _quietly_leases():
    """The ledger's leases as they are now (read without the lock), or none."""
    try:
        return read_ledger()["leases"]
    except Exception:  # noqa: B902 — a bonus: the evaluation reads it again
        return []


def _ticket_lease(ticket):
    """The lease a ticket names as the ledger has it now (read without the lock), or None."""
    try:
        return next((r for r in read_ledger()["leases"] if r.get("id") == ticket), None) if ticket else None
    except Exception:  # noqa: B902 — as a new request
        return None


def _refuse_disk(s, gb, pool, why):
    """Why a request for `gb` of disk space on `pool` (disk_pool_of's answer, or `why` it has none) cannot be made
    here, or None (02 §6.4: a volume the logger ignores, with the reason; more than free − margin)."""
    if not disk_reservable():
        return ("Disk space can't be reserved on this machine: %s does not list its volumes here yet. Reserve "
                "memory alone, and check the free space with `oomph check`." % BRAND)
    if pool is None:
        return ("Can't reserve disk space there: %s. Name a path on a disk %s records (`oomph volumes` lists them), "
                "or leave the path out for the temporary folder's disk." % (why, BRAND))
    if not _str(80, _ID)(pool.get("id")):
        return ("Can't reserve disk space on %s: %s has no id for this volume that a reservation can keep. Reserve "
                "on another volume, or leave the path out for the temporary folder's disk."
                % (term_text(pool.get("name") or "it")[:64], BRAND))
    if not (DISK_MIN_GB <= gb <= DISK_MAX_GB):
        return "Can't reserve %s GB of disk space: ask for 0.01 to %d GB." % ("%g" % gb, DISK_MAX_GB)
    margin = disk_margin(disk_floors(pool)[0])
    if gb > pool["free_gb"] - margin:
        return ("Can't reserve %s GB on %s: it has %s GB free, and %s keeps %s GB of it back, so at most %s GB can "
                "be reserved there. Free space first, ask for less, or reserve on another volume (disk_path / "
                "`--disk %sG@/Volumes/…`)." % (_gb(gb), term_text(pool.get("name") or pool["id"])[:64],
                                               _gb(pool["free_gb"]), BRAND, _gb(margin),
                                               _gb(max(0.0, pool["free_gb"] - margin)), "%g" % gb))
    return None


@_unprivileged(inputs=True)
def reserve(gb, purpose, holder, ttl_s=DEFAULT_TTL_S, ticket=None, watch="holder", cpu=None, cpu_min=None,
            disk=None, disk_path=None, gpu=None, vram=None, gpu_device=None):
    """Request (or re-poll with `ticket`) a reservation of `gb` of memory and, with `cpu`, cores: between
    `cpu_min` (default half, rounded up) and `cpu`; with `disk`, that many GB of space on the volume
    `disk_path` is on (default the temporary folder's), named by the pool's id when the request is made, so
    the reservation follows the volume, not the path (02 §7.1); with `gpu` a share of a GPU (%) and with `vram`
    GB of its memory (02 §6.5.1): on a Mac unified memory, charged against RAM; on Linux on one NVIDIA card,
    `gpu_device` (an index or a UUID prefix, resolved to the card's UUID now) or any card with room, which the
    grant names. GPU parts only while gpu_reservations is on. A request with cores, disk or a GPU is a lease of
    version 2 (02 §6.2); one for memory alone keeps the shape every older reader writes. Returns its status
    dict."""
    gpu_new = not ticket and (gpu is not None or vram is not None or gpu_device is not None)
    if gpu_new and not gpu_reservations_on():  # switched off (1.14): refused before anything is read or written
        return {"status": "refused", "gb": gb, "advice": _G().gpu_switch_text(), "switch": "gpu_reservations"}
    s, procs, now = _decide_inputs()
    if cpu is not None:
        cpu = _cn(round(float(cpu), 1))
        cpu_min = elastic_min(cpu) if cpu_min is None else _cn(min(round(float(cpu_min), 1), cpu))
        if cpu_min < cpu and cpu_reservable() and _to_weigh(ticket):
            s = _cpu_busy(s, now)
    dpool = why_disk = None
    if disk is not None:
        disk = round(float(disk), 2) or float(disk)  # 0.004 stays itself: refused, not kept as none
    tl = _ticket_lease(ticket)
    if tl is not None and _disk_of(tl) and disk_reservable():  # a poll: its pool's free space, read now
        s = _disk_pool_by_id(s, _disk_of(tl)["pool"])
    elif tl is None and disk is not None and not ticket and disk_reservable():  # its volume, from the path
        dpool, why_disk, pools = disk_pool_of(disk_path or default_disk_path(), s)
        if dpool:
            s = _with_disk(s, dpool, pools)
    gcard = why_gpu = gnote = None
    if gpu_new or (tl is not None and _gpu_parts(tl)):  # the cards' free memory, read now (02 §6.5.1)
        s = _G()._with_gpus(s)
    if gpu_new:
        vram = None if vram is None else round(float(vram), 2)
        gpu = None if gpu is None else _cn(round(float(gpu), 1))
        gcard, why_gpu, gnote = _G()._gpu_request(s, vram, gpu_device, gpu)
    unified = 0.0 if not gpu_new or why_gpu or vram is None or (gcard or {}).get("nvidia", True) else vram
    with Ledger() as L:
        r = next((x for x in L["leases"] if x["id"] == ticket), None) if ticket else None
        if ticket and r is None:
            return _status(L, ticket, now)
        if r is None:
            ram = s.get("ram_gb") or 0
            why = _refuse_cpu(s, cpu, cpu_min) if cpu is not None else None
            if why is None and disk is not None:
                why = _refuse_disk(s, disk, dpool, why_disk)
            if why is None and gpu_new:
                why = why_gpu
            whole = gb + unified  # a Mac's GPU memory is memory (02 §6.2)
            if why or (gb <= 0 and cpu is None and disk is None and not gpu_new) or gb < 0 or (ram and whole > 0.9 * ram):
                return {"status": "refused", "gb": gb,
                        "advice": why or "Can't reserve %.1f GB%s %s. Split the work or lower its parallelism."
                                         % (whole, " (memory and GPU memory)" if unified else "", _on_ram(s))}
            L["seq"] += 1
            mirror = round(whole, 2) if whole > 0 else NO_MEM_GB
            r = {"id": "r%d" % L["seq"], "state": "queued", "gb": mirror, "purpose": (purpose or "?")[:80],
                 "project": holder.get("project"), "holder": {k: holder.get(k) for k in ("pid", "start", "kind")},
                 "watch": holder["pid"] if watch == "holder" else watch,
                 "ttl": None if ttl_s is None else min(max(60, ttl_s), MAX_TTL_S),
                 "requested": round(now, 1), "seen": round(now, 1),
                 "segments": [{"t": round(now, 1), "gb": mirror}]}
            if cpu is not None or disk is not None or gpu_new:  # a vector (02 §6.2): `v` once, at creation
                r["v"] = 2
                r["res"] = {}
                if cpu is not None:
                    r["res"]["cpu"] = {"ask": cpu, "min": cpu_min}
                if disk is not None:  # the pool's id; its name only to tell people which volume
                    r["res"]["disk"] = {"ask": disk, "pool": dpool["id"],
                                        "name": notify_text(dpool.get("name") or dpool["id"], 64)}
                if gpu_new:  # its card: the one it named (an NVIDIA card's UUID), a Mac's gpu0, or none yet
                    r["res"].update(_G()._gpu_asked(gcard, gpu, vram))
                if gb > 0:
                    r["res"].update(ram={"ask": round(gb, 2)})
                if whole > 0:
                    r["res"]["mem"] = {"got": mirror}
                r["segments"][0]["res"] = dict({"ram": round(gb, 2)} if gb > 0 else {},
                                               **{k: x["ask"] for k, x in r["res"].items() if k in SEG_RES and k != "ram"})
            r["key"] = _key(r)
            r["user"] = _whoami()  # who asked (03 §6.5): shown once several accounts hold reservations
            r["holder"]["uid"] = os.getuid()
            if _own_ns():
                r["holder"]["ns"] = _own_ns()
            if _scope_id(s) != "host":
                r["scope"] = _scope_id(s)
            k = holder.get("agent")  # `oomph run` inside a session: the session's (02 §3.8.2)
            k = k if isinstance(k, str) and _AGENT.fullmatch(k) else agent_key(holder.get("pid"), holder.get("start"))
            if k:
                r["agent"] = {"key": k}
            seen = _valid_lease(json.loads(json.dumps(r)))  # as every reader will see it: never one that jams the line
            if seen is None or not weighable(seen):
                L["seq"] -= 1
                return {"status": "refused", "gb": gb, "advice": "Can't make this reservation: %s could not record it in "
                        "a form it can weigh. Ask for memory, cores, disk space or a GPU in plain amounts." % BRAND}
            L["leases"].append(r)
        else:
            r["seen"] = round(now, 1)
            if r["state"] == "granted" and r.get("expires") and ttl_s:  # re-asking extends a grant
                r["ttl"] = min(max(60, ttl_s), MAX_TTL_S)  # the limit the grant now has (_holder_gone)
                r["expires"] = round(now + r["ttl"], 1)
        _evaluate(L, s, procs, now)
        out = _status(L, r["id"], now)
        if s.get("window_s") and out.get("status") == "granted" and "cpu_cores" in out.get("run_with", {}):
            out["window_s"] = s["window_s"]  # how busy the cores were, measured just now (no logger)
        if gnote and out.get("status") in ("granted", "queued"):  # an estimated working-set limit (02 §4.3)
            out["note"] = "; ".join(x for x in (out.get("note"), gnote) if x)
        return out


def acquire(gb, purpose, holder, ttl_s=DEFAULT_TTL_S, wait_s=0, ticket=None, watch="holder", progress=None,
            cpu=None, cpu_min=None, disk=None, disk_path=None, gpu=None, vram=None, gpu_device=None):
    kw = {"cpu": cpu, "cpu_min": cpu_min} if cpu is not None else {}
    if disk is not None:
        kw.update(disk=disk, disk_path=disk_path)
    kw.update((k, x) for k, x in (("gpu", gpu), ("vram", vram), ("gpu_device", gpu_device)) if x is not None)
    st = reserve(gb, purpose, holder, ttl_s, ticket, watch, **kw)
    t0 = time.time()
    while st["status"] == "queued" and time.time() - t0 < wait_s:
        if progress:
            progress(st)
        time.sleep(min(POLL_S, max(0.1, wait_s - (time.time() - t0))))
        st = reserve(gb, purpose, holder, ttl_s, st["id"], watch, **kw)
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


def _amend_cpu(L, r, cpu, cpu_min):
    """amend's cores (02 §6.4, today's rules per resource): (change, refusal). Shrinking applies at once;
    growing a grant only if the extra cores can be reserved now and nobody is queued for cores; a queued
    request takes the new range, and a bigger one goes to the back of the line; 0 drops the cores."""
    c = _cpu_of(r)
    if c is None:
        return None, ("%s holds no cores, and a reservation of memory made before cores could be reserved cannot "
                      "take them: reserve the cores separately (reserve cpu_cores=%s / `oomph reserve --cpu %s --for "
                      "\"…\"`)." % (r["id"], cores_text(cpu), cores_text(cpu))) if cpu else (None, None)
    was = c["got"] if r["state"] == "granted" and _num(c.get("got")) else c["ask"]
    if cpu == 0:
        if no_memory(r) and _disk_of(r) is None:
            return None, "%s holds nothing but cores: release it instead (release_memory / `oomph release %s`)." % (
                r["id"], r["id"])
        del r["res"]["cpu"]
        return [was, 0], None
    if r["state"] == "granted":
        if cpu > was:
            st = L.get("state", {})
            room = st.get("cpu_available") if _num(st.get("cpu_available")) else 0
            waiting = [x for x in L["leases"] if x["state"] == "queued" and ("cpu" in lease_need(x) or not weighable(x))]
            if waiting or cpu - was > room:
                return None, ("Can't grow %s from %s to %s cores now: %s. Keep the %s and reserve the extra %s "
                              "separately (`oomph reserve --cpu %s --for \"…\"`): it queues fairly." % (
                                  r["id"], cores_text(was), cores_text(cpu),
                                  "%d request(s) for cores are queued and come first" % len(waiting) if waiting else
                                  "only %s more can be reserved" % cores_text(max(0.0, room)),
                                  cores_text(was), cores_text(cpu - was), cores_text(cpu - was)))
        c.update(ask=cpu, got=cpu, min=min(cpu, c.get("min", cpu)))
    else:
        c.update(ask=cpu, min=elastic_min(cpu) if cpu_min is None else _cn(min(cpu_min, cpu)))
        if cpu > was:  # a bigger request takes a new place in line
            L["leases"].remove(r)
            L["leases"].append(r)
    return [was, cpu], None


def _amend_disk(L, r, disk):
    """amend's disk space (02 §6.4, today's rules per resource): (change, refusal). It stays on its pool.
    Shrinking applies at once; growing a grant only if the extra can be reserved on that pool now and nobody
    is queued for it; a bigger queued request goes to the back of the line; 0 drops the disk space."""
    d = _disk_of(r)
    if d is None:
        return (None, ("%s holds no disk space, and it cannot take some now: reserve the space separately (reserve "
                       "disk_gb=%s / `oomph reserve --disk %sG --for \"…\"`)." % (r["id"], "%g" % disk, "%g" % disk))) \
            if disk else (None, None)
    if disk and not (DISK_MIN_GB <= disk <= DISK_MAX_GB):
        return None, "Can't make %s's disk space %s GB: ask for 0.01 to %d GB, or 0 to drop it." % (
            r["id"], "%g" % disk, DISK_MAX_GB)
    was = d["got"] if r["state"] == "granted" and _num(d.get("got")) else d["ask"]
    if disk == 0:
        if no_memory(r) and _cpu_of(r) is None:
            return None, ("%s holds nothing but disk space: release it instead (release_memory / `oomph release %s`)."
                          % (r["id"], r["id"]))
        del r["res"]["disk"]
        return [was, 0], None
    if r["state"] == "granted":
        if disk > was:
            room = (L.get("state", {}).get("disk") or {}).get(d["pool"])
            room = room if _num(room) else 0.0
            pool = "disk:" + d["pool"]
            waiting = [x for x in L["leases"] if x["state"] == "queued" and (pool in lease_need(x) or not weighable(x))]
            if waiting or disk - was > room:
                return None, ("Can't grow %s from %s to %s GB on %s now: %s. Keep the %s GB and reserve the extra %s GB "
                              "separately (`oomph reserve --disk %sG --for \"…\"`): it queues fairly." % (
                                  r["id"], _gb(was), _gb(disk), _disk_name(d),
                                  "%d request(s) for space there are queued and come first" % len(waiting) if waiting
                                  else "only %s GB more can be reserved there" % _gb(max(0.0, room)),
                                  _gb(was), _gb(disk - was), "%g" % round(disk - was, 2)))
        d.update(ask=disk, got=disk)
    else:
        d["ask"] = disk
        if disk > was:  # a bigger request takes a new place in line
            L["leases"].remove(r)
            L["leases"].append(r)
    return [was, disk], None


@_unprivileged(inputs=True)
def amend(rid, gb=None, ttl_s=None, purpose=None, cpu=None, cpu_min=None, disk=None, gpu=None, vram=None):
    """Change a reservation in place: its size, its cores, its disk space (on the volume it has), its time
    to live (from now) or its purpose. Shrinking applies at once and hands the room to whoever waits.
    Growing a grant applies only when the extra would be granted to a new request right now (it fits,
    and nobody is queued for it); otherwise it is refused, with advice to reserve the extra separately,
    which queues fairly. Growing a queued request moves it to the back of the queue. A reservation of
    several resources can drop all but one (0). Every applied change is written to the history log, and
    a new size starts a new segment of the reservation's span. A GPU part (`gpu` %, `vram` GB, 02 §6.5.1) stays
    on its card; while gpu_reservations is off, one may shrink or be dropped, not be added or grow. On a Mac,
    `gb` is the memory besides the GPU's (which the gb mirror also carries)."""
    s, procs, now = _decide_inputs()
    if cpu is not None:
        cpu = _cn(round(float(cpu), 1))
        cpu_min = None if cpu_min is None else _cn(round(float(cpu_min), 1))
    tl = _ticket_lease(rid) if disk is not None or gpu is not None or vram is not None else None
    if disk is not None:
        disk = round(float(disk), 2) or float(disk)  # 0.004 stays itself: refused below, not taken for 0 (drop)
        if tl is not None and _disk_of(tl) and disk_reservable():  # its pool's free space, read now
            s = _disk_pool_by_id(s, _disk_of(tl)["pool"])
    if gpu is not None:
        gpu = _cn(round(float(gpu), 1))
    if vram is not None:
        vram = round(float(vram), 2) or float(vram)
    if tl is not None and _gpu_parts(tl) and (gpu or vram):  # its card's free memory, read now
        s = _G()._with_gpus(s)
    with Ledger() as L:
        _evaluate(L, s, procs, now)
        r = next((x for x in L["leases"] if x["id"] == rid), None)
        if r is None:
            return _status(L, rid, now)
        ram = s.get("ram_gb") or 0
        change, refused = {}, None
        gp = _gpu_parts(r) or None
        vec = _cpu_of(r) is not None or _disk_of(r) is not None or gp is not None
        rest = (_cpu_of(r) is not None and cpu != 0) or (_disk_of(r) is not None and disk != 0) or \
            bool(gp and ((gp["gpu"] and gpu != 0) or (gp["vram"] and vram != 0)))  # kept besides memory
        before, order = json.loads(json.dumps(r)), list(L["leases"])  # all or nothing: restored when refused
        if (gpu or vram) and not gpu_reservations_on() and _G()._gpu_grows(r, gp, gpu, vram):
            refused = _G().gpu_switch_text()  # switched off: a GPU part may not be added or grow
        u = _G()._unified_gb(r) if gp else 0.0  # a Mac's GPU memory, in the gb mirror too
        if refused is None and gb is not None and round(gb, 2) != (0.0 if no_memory(r) else round(r["gb"] - u, 2)):
            gb = round(gb, 2)
            old = 0.0 if no_memory(r) else round(r["gb"] - u, 2)
            if gb == 0 and (rest or u):
                pass  # a reservation with cores, disk space or a GPU drops its memory
            elif gb <= 0 or (ram and gb + u > 0.9 * ram):
                refused = ("Can't reserve %.1f GB %s. Release the reservation instead "
                           "(release_memory / `oomph release %s`) if the work is done." % (gb, _on_ram(s), rid))
            elif gb > old and r["state"] == "granted":
                extra, st = gb - old, L["state"]
                waiting = [x for x in L["leases"] if x["state"] == "queued" and ("ram" in lease_need(x) or not weighable(x))]
                if waiting or extra > st["available_gb"] or st["level"] == "critical":
                    why = ("%d request(s) are queued and come first" % len(waiting) if waiting else
                           "memory is critical" if st["level"] == "critical" else
                           "only %.1f GB is available" % max(0.0, st["available_gb"]))
                    refused = ("Can't grow %s from %.1f to %.1f GB now: %s. Keep the %.1f GB grant and reserve the "
                               "extra %.1f GB separately (reserve_memory gb=%.1f / `oomph reserve %.1fG --for \"…\"`): "
                               "it queues fairly and is granted when it fits." % (
                                   rid, old, gb, why, old, extra, extra, extra))
            if refused is None:
                change["gb"] = [old, gb]
                if gb > old and r["state"] == "queued":  # a bigger request takes a new place in line
                    L["leases"].remove(r)
                    L["leases"].append(r)
                    change["requeued"] = True
                r["gb"] = round(gb + u, 2) if gb + u > 0 else NO_MEM_GB
                if vec:  # the vector follows its memory mirror
                    if gb > 0:
                        r["res"]["ram"] = dict(r["res"].get("ram") or {}, ask=gb, **({"got": gb} if r["state"] == "granted" else {}))
                    else:
                        r["res"].pop("ram", None)
                    if gb + u > 0:
                        r["res"]["mem"] = dict(r["res"].get("mem") or {}, got=r["gb"])
                    else:
                        r["res"].pop("mem", None)
        if refused is None and cpu is not None and (vec or cpu):
            ch, refused = _amend_cpu(L, r, cpu, cpu_min)
            if ch and ch[0] != ch[1]:
                change["cpu"] = ch
                if ch[1] > ch[0] and r["state"] == "queued":
                    change["requeued"] = True
            if refused and "gb" in change:  # the memory part is not applied alone
                refused += " Nothing was changed."
        if refused is None and disk is not None and (vec or disk):
            ch, refused = _amend_disk(L, r, disk)
            if ch and ch[0] != ch[1]:
                change["disk"] = ch
                if ch[1] > ch[0] and r["state"] == "queued":
                    change["requeued"] = True
            if refused and ("gb" in change or "cpu" in change):  # nor the other parts alone
                refused += " Nothing was changed."
        for k, a in (("gpu", gpu), ("vram", vram)):
            if refused is None and a is not None and (vec or a):
                ch, refused = _G()._amend_gpu(L, r, k, a, s)
                if ch and ch[0] != ch[1]:
                    change[k] = ch
                    if ch[1] > ch[0] and r["state"] == "queued":
                        change["requeued"] = True
                if refused and set(change) & {"gb", "cpu", "disk", "gpu"}:
                    refused += " Nothing was changed."
        if refused:
            r.clear()
            r.update(before)
            L["leases"][:] = order
            change = {}
        if set(change) & {"gb", "cpu", "disk", "gpu", "vram"}:
            seg = {"t": round(now, 1), "gb": r["gb"]}
            if vec:
                seg["res"] = {k: x.get("got", x.get("ask")) for k, x in r["res"].items()
                              if k in SEG_RES and isinstance(x, dict) and _num(x.get("got", x.get("ask")))}
            r.setdefault("segments", [{"t": r.get("granted") or r["requested"],
                                       "gb": change["gb"][0] or NO_MEM_GB if "gb" in change else r["gb"]}])
            if r["segments"][-1]["t"] >= round(now, 1):
                r["segments"][-1].update(seg, t=r["segments"][-1]["t"])
            else:
                r["segments"].append(seg)
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
            out.update(status="refused", id=rid, gb=0.0 if no_memory(r) else r["gb"], requested_gb=gb,
                       advice=refused, keeps=r["state"])
            if cpu is not None:
                out["requested_cpu"] = cpu
            if disk is not None:
                out["requested_disk"] = disk
            for k, a in (("requested_gpu", gpu), ("requested_gpu_mem", vram)):
                if a is not None:
                    out[k] = a
            if refused.startswith("GPU reservations are switched off"):
                out["switch"] = "gpu_reservations"
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
    """Current reservations (refreshed), seen from session `mine`: what others hold or wait for. Asked without a
    sample (`oomph reservations`, MCP, `oomph run`'s refresh), without the logger's list of disks and with disk
    space reserved, every pool is read live (what is left on each); with an NVIDIA card reserved and no logger, the
    cards are (nvidia-smi). Never for `check` or the hook, which hand in their sample: their cost stays what it was
    (02 §7.4: the hook never touches a volume)."""
    given = s is not None
    s, procs, now = _decide_inputs(s)
    if not given and disk_reservable() and not (isinstance(s.get("disks"), list) and not s.get("disks_partial")) \
            and any(_disk_of(r) for r in _quietly_leases()):
        pools = live_volumes()[0]
        if pools is not None:
            s = dict(s, disks=pools, disks_partial=live_volumes_partial())
    if not given and not isinstance(s.get("gpu"), list) and any(  # NVIDIA grants: what they use, read now
            (_gpu_parts(r) or {}).get("nvidia") for r in _quietly_leases()):
        s = _G()._with_gpus(s)
    with Ledger() as L:
        _evaluate(L, s, procs, now)
        st = L["state"]
        own = [r for r in L["leases"] if _held_by(r, mine)]
        others = [r for r in L["leases"] if r not in own]
        others_out = sum(r["gb"] - r.get("used_gb", 0) for r in others if r["state"] == "granted")
        cpu = {"cores": st["cpu_cap"], "margin": st["cpu_margin"], "reserved": st["cpu_reserved"],
               "available": st["cpu_available"], "reservable": cpu_reservable()}
        if "cpu_idle" in st:
            cpu["idle"] = st["cpu_idle"]
        disk = {k: {"name": d["name"], "free": d["free"], "margin": round(d["margin"], 1), "level": d["level"],
                    "reserved": round(d["reserved"], 1), "available": round(max(0.0, d["left"]), 1)}
                for k, d in disk_view(s, L["leases"])[0].items()} if disk_reservable() else {}
        return {
            "free_gb": st["free_gb"], "margin_gb": st["margin_gb"], "reserved_gb": st["reserved_gb"],
            "available_gb": st["available_gb"], "grantable_gb": st["available_gb"], "ledger": ledger_info(),
            "reserved_by_others_gb": round(others_out, 1),
            "available_to_me_gb": round(st["free_gb"] - others_out - st["margin_gb"], 1),
            "cpu": cpu, "disk": disk, "gpu": st.get("gpu") or {},
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
    vec = _record_vector(rec)  # a vector's amounts (granted, or asked while queued) and peaks by resource
    if vec.get("res"):
        out["res"] = vec["res"]
        if "ram" not in vec["res"] and rec["gb"] <= NO_MEM_GB + 0.005:  # holds no memory: its gb is the mirror
            out["gb"] = 0.0
    if vec.get("peak"):
        out["peak"] = vec["peak"]
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
               "outcome", "peak_gb", "used_gb", "expires", "segments", "agent", "res")  # res: the bands (1.12.3)


def _view_records(recs, since):
    """The history log's records as a viewer merges them (merge_history, as oomph_view.merge_reservations
    and the app do), those that end at or after `since`, with only the fields the viewers read. One
    record per reservation keeps a root caller's answer far below LIMITS["child"]; `res` only where it
    holds more than memory (oomph top keeps 14 days of these within its 40 MB)."""
    out = []
    for r in merge_history(recs):
        if _rec_time(r) >= since:
            x = {f: r[f] for f in VIEW_FIELDS if f in r}
            if isinstance(x.get("res"), dict) and x["res"] and set(x["res"]) <= {"ram"}:
                del x["res"]  # memory alone: the gb mirror says the same (and its segments' res too)
                if isinstance(x.get("segments"), list) and any(isinstance(g, dict) and "res" in g for g in x["segments"]):
                    x["segments"] = [{k: v for k, v in g.items() if k != "res"} if isinstance(g, dict) else g
                                     for g in x["segments"]]
            out.append(x)
    return out


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
def refresh_ledger(s, procs, rated=False):
    """The daemon's tick: retire leases whose holder died or that expired, close to when it
    happened, and keep the usage figures current (with `rated`, the cores too: the process table
    carries the logger's CPU rates). Skips the lock when nothing is reserved."""
    if not read_ledger()["leases"]:
        return
    with Ledger() as L:
        _evaluate(L, s, procs, time.time(), rated=rated)


PROC_KEYS = ("pid", "ppid", "uid", "name", "start", "fp", "rss", "path")  # what the ledger's child is told of a process


def ledger_tick(s, procs, timeout=TICK_TIMEOUT_S, rates=None, writes=None, gpus=None):
    """The daemon's ledger work for one sample: refresh_ledger, then the snapshot of live
    reservations for the sample, both in a child — as nobody when the daemon is root (root
    never opens anything in the shared directory, to read or to write), as the same user when
    it isn't. Its answer is at most LIMITS["tick"] bytes of JSON, read within `timeout`, and the
    sample's block is rebuilt from it field by field (sample_leases). Returns (leases, error
    or None). The daemon calls this from a thread of its own: the sampler never waits on it.
    `rates`: the cores each process kept busy over the last interval ({pid: cores}, the logger's
    Meter); given, the child's input is of version 2 (02 §5.2) and it charges every grant's cores,
    with `writes` ({pid: MB/s written to disk}) every disk grant's writes, and with `gpus` ({pid: % of the
    GPU}) a Mac's GPU grants (an NVIDIA card's are charged from the sample's list of its processes)."""
    rows = [{k: p[k] for k in PROC_KEYS if k in p} for p in procs.values()]
    if rates is not None:
        for x in rows:
            c, w, g = rates.get(x["pid"]), (writes or {}).get(x["pid"]), (gpus or {}).get(x["pid"])
            if _num(c, 0, CPU_MAX):
                x["cpu"] = round(c, 3)
            if _num(w, 0, 1e7) and w > 0:
                x["w"] = round(w, 3)
            if _num(g, 0, 1e4) and g > 0:
                x["gpu"] = round(g, 2)
    payload = json.dumps(dict({"s": s, "procs": rows}, **({"v": 2} if rates is not None else {})),
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
        refresh_ledger(d["s"], procs, rated=d.get("v") == 2)
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


SAMPLE_LEASE_NUMS = ("used_gb", "for_min", "expires_in_min", "waiting_min", "cpu", "cpu_used", "disk", "disk_used",
                     "gpu", "gpu_used", "vram", "vram_used")


def sample_leases(x):
    """The leases block of a sample, rebuilt from typed fields only — what root republishes can't
    be bigger, deeper or differently shaped than this, whatever the shared directory held: at
    most LIMITS["leases_n"] entries of id, state, gb, purpose, project and the numbers of
    SAMPLE_LEASE_NUMS and a disk's pool id, strings cut to LIMITS["str"], LIMITS["leases"] bytes in all. A malformed
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
        if _str(80, _ID)(b.get("disk_pool")) and "disk" in e:  # which pool: an id, compared as a string, never opened
            e["disk_pool"] = b["disk_pool"]
        if _str(8, _GPU_DEV)(b.get("gpu_dev")) and ("gpu" in e or "vram" in e):  # which card: its label
            e["gpu_dev"] = b["gpu_dev"]
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
    cores = ("%s cores%s, " % (cores_text(b["cpu"]), " (%.1f busy)" % b["cpu_used"] if _num(b.get("cpu_used")) else "")
             if _num(b.get("cpu")) else "")
    if _num(b.get("disk")):
        cores += "%sG on %s%s, " % (_gb(b["disk"]), cut_middle(term_text(b.get("disk_name") or b.get("disk_pool") or "?"), 12),
                                    " (%sG used)" % _gb(b["disk_used"]) if _num(b.get("disk_used")) else "")
    if _num(b.get("gpu")) or _num(b.get("vram")):  # a GPU's memory and share, on which card
        cores += _G()._gpu_brief_text(b)
    tail = cores + ((("using %.1fG, " % b.get("used_gb", 0)) if b["gb"] > 0 else "") + "%.0f min" % max(0.0, b["for_min"])
                    if b["state"] == "granted" else "waiting %.0f min" % max(0.0, b["waiting_min"]))
    flags = b.get("flags") if isinstance(b.get("flags"), dict) else {}
    if flags:  # over / idle (02 §6.3), said first: "over on CPU, …"
        tail = ", ".join("%s on %s" % (f, "CPU" if k == "cpu" else k) for k, f in sorted(flags.items())) + ", " + tail
    size = "%5.1fG" % b["gb"] if b["gb"] > 0 or not cores else "%6s" % "-"
    return "%-5s %-7s %s  %-*s %-10s %s" % (b["id"], b["state"], size, purpose_w, cut_end(b["purpose"], purpose_w),
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


RESERVE_USAGE = ("usage: oomph reserve [size, e.g. 6G] [--cpu 8 | --cpu 4..8 | --cpu 8..8] [--disk 20G[@PATH]] "
                 "[--gpu 60[@CARD]] [--gpu-mem 16G[@CARD]] --for \"what\" [--wait 10m] [--ttl 30m] [--ticket rN] [--json]")
RELEASE_USAGE = "usage: oomph release <id | all>   (all = every reservation held by this session)"
AMEND_USAGE = ("usage: oomph amend <id> [--gb 3G] [--cpu 6] [--disk 30G] [--gpu 40] [--gpu-mem 12G] [--ttl 20m] "
               "[--for \"what\"] [--json]")
RUN_USAGE = ("usage: oomph run [--reserve 6G] [--cpu 4..12] [--disk 20G[@PATH]] [--gpu 60[@CARD]] [--gpu-mem 16G[@CARD]] "
             "[--pin-gpu] [--for \"what\"] [--wait 30m] -- <command> [args…]   ({cpu} in the command is the number of "
             "cores granted)")


def _cpu_opt(o):
    """--cpu's (ask, min), or (None, None); UsageError when it is not a number of cores."""
    if "--cpu" not in o:
        return None, None
    try:
        return parse_cores(o["--cpu"])
    except ValueError as e:
        raise UsageError(str(e))


def _disk_opt(o, zero=False):
    """--disk's (GB, path or None), or (None, None); UsageError when it is not a disk size (`zero`: 0 is one)."""
    if "--disk" not in o:
        return None, None
    try:
        return parse_disk(o["--disk"], zero)
    except ValueError as e:
        raise UsageError(str(e))


def _unified_rec_gb(h):
    """The GB of a Mac's GPU memory in a finished reservation's gb (its `res` has vram and no NVIDIA card), else 0."""
    res = h.get("res") if isinstance(h.get("res"), dict) else {}
    return res["vram"] if _num(res.get("vram")) and not str(res.get("gpu_dev", "")).startswith("GPU-") else 0.0


def _gpu_rec(h, short=False):
    """A finished reservation's GPU parts in words (oomph_gpu._gpu_rec_text), "" at once without one."""
    return _G()._gpu_rec_text(h, short) if set(h.get("res") or {}) & {"gpu", "vram"} else ""


def cmd_reserve(args):
    try:
        o, pos = _strict(args, ("--for", "--wait", "--ttl", "--ticket", "--pid", "--cpu", "--disk", "--gpu", "--gpu-mem"),
                         ("--json", "--help", "-h"))
        ticket = o.get("--ticket")
        cpu, cpu_min = _cpu_opt(o)
        disk, disk_path = _disk_opt(o)
        gpu, vram, card = _G()._gpu_opts(o) if {"--gpu", "--gpu-mem"} & set(o) else (None, None, None)
        if "--help" in o or "-h" in o or (not pos and not ticket and cpu is None and disk is None and gpu is None
                                          and vram is None):
            print(RESERVE_USAGE)
            return 2
        gb = _size(pos[0]) if pos else 0
        pid = o.get("--pid")
        if pid is not None and not pid.isdigit():
            raise UsageError("--pid takes a process id, not %s" % pid)
    except UsageError as e:
        return _usage_error("reserve", e, RESERVE_USAGE)
    if (gpu is not None or vram is not None) and not ticket and not gpu_reservations_on():
        return _G()._gpu_off(o, "--json" in o)
    holder = holder_for(int(pid) if pid is not None else None)
    st = acquire(gb, o.get("--for", "unspecified"), holder, parse_dur(o.get("--ttl", "30m")),
                 parse_dur(o.get("--wait", "0s")), ticket, cpu=cpu, cpu_min=cpu_min, disk=disk,
                 disk_path=os.path.abspath(disk_path) if disk_path else None,
                 **({"gpu": gpu, "vram": vram, "gpu_device": card} if gpu is not None or vram is not None else {}))
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
        cpu, peak = (h.get("res") or {}).get("cpu"), (h.get("peak") or {}).get("cpu")
        dk, dpeak = (h.get("res") or {}).get("disk"), (h.get("peak") or {}).get("disk")
        uv = _unified_rec_gb(h)  # a Mac's GPU memory is in gb too: said once, as GPU memory
        mem = "%.1fG, peak %.1fG" % (max(0.0, h["gb"] - uv), h["peak_gb"]) \
            if ("ram" in (h.get("res") or {}) and h["gb"] - uv > 0.005) or not (_num(cpu) or _num(dk) or _gpu_rec(h)) \
            else ""
        cores = "%s cores%s" % (cores_text(cpu), ", peak %.1f busy" % peak if _num(peak) else "") if _num(cpu) else ""
        disk = "%sG of disk%s" % (_gb(dk), ", %sG used" % _gb(dpeak) if _num(dpeak) else "") if _num(dk) else ""
        print("oomph: released %s (%s) — reserved %s, held %ds" % (
            h["id"], h["purpose"], " and ".join(x for x in (mem, cores, disk, _gpu_rec(h)) if x), h["held_s"]))
    if res["next_granted"]:
        print("oomph: now granted to " + ", ".join(res["next_granted"]))
    return 0


def cmd_amend(args):
    opts = ("--gb", "--ttl", "--for", "--cpu", "--disk", "--gpu", "--gpu-mem")
    try:
        o, pos = _strict(args, opts, ("--json", "--help", "-h"))
        if not pos or not any(k in o for k in opts) or "--help" in o or "-h" in o:
            print(AMEND_USAGE)
            return 2
        gb = _size(o["--gb"]) if "--gb" in o else None
        cpu, cpu_min = (0.0, None) if o.get("--cpu") == "0" else _cpu_opt(o)
        disk, disk_path = _disk_opt(o, zero=True)  # 0 (0G, 0M, …) drops the disk space
        if disk_path:
            raise UsageError("--disk %s: a reservation stays on its volume; give the new size alone" % o["--disk"])
        gpu, vram, card = _G()._gpu_opts(o, zero=True) if {"--gpu", "--gpu-mem"} & set(o) else (None, None, None)  # 0 drops it
        if card:
            raise UsageError("a reservation stays on its card; give the new amount alone")
    except UsageError as e:
        return _usage_error("amend", e, AMEND_USAGE)
    rid = pos[0]
    st = amend(rid, gb, parse_dur(o["--ttl"]) if "--ttl" in o else None, o.get("--for"), cpu=cpu, cpu_min=cpu_min,
               disk=disk, **{k: x for k, x in (("gpu", gpu), ("vram", vram)) if x is not None})
    if "--json" in o:
        print(json.dumps(st))
    else:
        ch = st.get("changed") or {}
        what = ", ".join(("%.1fG → %.1fG" % tuple(v)) if k == "gb" else
                         ("%s → %s cores" % tuple(cores_text(x) for x in v)) if k == "cpu" else
                         ("%sG → %sG of disk" % tuple(_gb(x) for x in v)) if k == "disk" else
                         ("%s → %s %% of the GPU" % tuple(cores_text(x) for x in v)) if k == "gpu" else
                         ("%sG → %sG of GPU memory" % tuple(_gb(x) for x in v)) if k == "vram" else
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
        if "cpu" in (x.get("res") or {}):  # and its cores
            gbs = ("%s cores" if not x["gb"] else gbs + " %sc") % cores_text(x["res"]["cpu"])
        if _num((x.get("res") or {}).get("disk")):  # and its disk space
            gbs = ("%sG disk" if not x["gb"] and "cpu" not in x["res"] else gbs + " %sGd") % _gb(x["res"]["disk"])
        g = _gpu_rec(x, short=True)
        if g:  # and a GPU
            gbs = g if not x["gb"] and not set(x["res"]) & {"cpu", "disk"} else gbs + " " + g
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
    if sys.platform == "darwin":
        print(wrap("free %.1fG − reserved %.1fG − margin %.1fG = %.1fG available for new reservations" % (
            c["free_gb"], c["reserved_gb"], c["margin_gb"], c["available_gb"])))
    else:  # 03 F6: "available" is the kernel's MemAvailable here; what can be reserved is "left to grant"
        print(wrap("available %.1fG − reserved %.1fG − margin %.1fG = %.1fG left to grant" % (
            c["free_gb"], c["reserved_gb"], c["margin_gb"], c["available_gb"])))
        led = c["ledger"]
        print(wrap("%s · %s" % (_home_short(led["path"]), "yours only" if led["kind"] == "user" else
                                "shared by " + led["members"]), first="ledger: "))
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
            print("  %-5s %5.1fG → %4.1fG  %-20s %-10s %-11s held %s%s" % (
                h["id"], h["gb"], h["peak_gb"], cut_end(h["purpose"], 20), cut_middle(h.get("project") or "", 10),
                h["outcome"], "%dm%02ds" % divmod(h["held_s"], 60),
                "  " + _gpu_rec(h, short=True) if _gpu_rec(h, short=True) else ""))
    return 0


JOB_VARS = ("CARGO_BUILD_JOBS", "CMAKE_BUILD_PARALLEL_LEVEL", "GOMAXPROCS", "OMP_NUM_THREADS", "RAYON_NUM_THREADS",
            "PYTEST_XDIST_AUTO_NUM_WORKERS")  # what common tools read for their number of jobs (02 §7.1)


def run_env(st, env, pin=False):
    """The environment of `oomph run`'s command for grant `st` (02 §7.1): OOMPH_RESERVATION, OOMPH_RAM_GB,
    with disk space OOMPH_DISK_GB and, with cores, OOMPH_CPU_CORES; and, only where not already set, the job
    counts that common tools read (JOB_VARS, MAKEFLAGS=-jN): on by default (02 §15.9). With a GPU (02 §6.5.1)
    always OOMPH_GPU_INDEX, OOMPH_GPU_UUID (an NVIDIA card) and OOMPH_GPU_MEM_GB; with `pin` (--pin-gpu) on an
    NVIDIA card also CUDA_DEVICE_ORDER=PCI_BUS_ID and CUDA_VISIBLE_DEVICES=<index>, replacing what was set
    (gpu_pin_changes says what): jobs are not pinned unless asked."""
    out = dict(env, OOMPH_RESERVATION=st["id"])
    if isinstance((st.get("run_with") or {}).get("gpu"), dict):
        _G()._gpu_env(st["run_with"]["gpu"], out, pin)
    if st.get("gb"):
        out["OOMPH_RAM_GB"] = "%g" % st["gb"]
    dk = (st.get("granted") or {}).get("disk_gb")
    if _num(dk, 0.001, DISK_MAX_GB):
        out["OOMPH_DISK_GB"] = "%g" % dk
    got = (st.get("run_with") or {}).get("cpu_cores")
    if _num(got, 0.1, CPU_MAX):
        out["OOMPH_CPU_CORES"] = cores_text(got)
        jobs = str(max(1, int(got)))
        for k in JOB_VARS:
            out.setdefault(k, jobs)
        out.setdefault("MAKEFLAGS", "-j" + jobs)
    return out


def run_argv(cmd, st):
    """The command with every `{cpu}` replaced by the number of cores granted (in the argument vector itself,
    never through a shell); unchanged without cores."""
    got = (st.get("run_with") or {}).get("cpu_cores")
    if not _num(got, 0.1, CPU_MAX):
        return list(cmd)
    jobs = str(max(1, int(got)))
    return [c.replace("{cpu}", jobs) for c in cmd]


def cmd_run(args):
    if "--" not in args or not any(k in args[:args.index("--")] for k in ("--reserve", "--cpu", "--disk", "--gpu",
                                                                            "--gpu-mem", "--pin-gpu")):
        print(RUN_USAGE)
        return 2
    i = args.index("--")
    cmd = args[i + 1:]
    try:
        opts, _ = _strict(args[:i], ("--reserve", "--for", "--wait", "--cpu", "--disk", "--gpu", "--gpu-mem"),
                          ("--pin-gpu",), npos=0)
        gb = _size(opts["--reserve"]) if "--reserve" in opts else 0
        cpu, cpu_min = _cpu_opt(opts)
        disk, disk_path = _disk_opt(opts)
        gpu, vram, card = _G()._gpu_opts(opts) if {"--gpu", "--gpu-mem"} & set(opts) else (None, None, None)
        pin = "--pin-gpu" in opts
        off = (pin or gpu is not None or vram is not None) and not gpu_reservations_on()  # 02 §6.5.1: the switch first
        if pin and gpu is None and vram is None and not off:
            raise UsageError("--pin-gpu comes with --gpu or --gpu-mem: it runs the job on the card granted")
    except UsageError as e:
        return _usage_error("run", e, RUN_USAGE)
    if not cmd:
        print("oomph run: no command given")
        return 2
    if off:
        sys.stderr.write(_G().gpu_switch_text("oomph: not started — ") + "\n")
        return 75
    import signal
    purpose = opts.get("--for") or " ".join(os.path.basename(c) if j == 0 else c for j, c in enumerate(cmd[:3]))
    wait_s = parse_dur(opts.get("--wait", "30m"))
    ses = holder_for()
    me = {"pid": os.getpid(), "start": _procs_around(os.getpid()).get(os.getpid(), {}).get("start"),
          "kind": "run", "project": ses["project"] if ses["kind"] == "session" else os.getcwd(),
          "agent": agent_key(ses["pid"], ses["start"]) if ses["kind"] == "session" else None}
    last = [0.0]
    want = " and ".join(([("%.1fG" % gb)] if gb else []) + (["%s cores" % cores_text(cpu_min if cpu_min == cpu else cpu)]
                                                           if cpu else []) + (["%sG of disk" % _gb(disk)] if disk else [])
                        + (["%sG of GPU memory" % _gb(vram)] if vram else []) + (["%s %% of a GPU" % cores_text(gpu)]
                                                                                 if gpu else []))

    def progress(st):
        if time.time() - last[0] >= 30:
            last[0] = time.time()
            ahead = ", ".join("%s %.1fG %s (%s)" % (b["id"], b["gb"], b["purpose"], b.get("project") or "?")
                              for b in st.get("ahead", [])[:3])
            sys.stderr.write(wrap("waiting for %s — queued #%s, %.1fG available%s" % (
                want, st.get("position"), st.get("available_gb") or 0, "; ahead: " + ahead if ahead else ""),
                first="oomph: ") + "\n")
            sys.stderr.flush()

    st = acquire(gb, purpose, me, None, wait_s, watch=None, progress=progress, cpu=cpu, cpu_min=cpu_min, disk=disk,
                 disk_path=os.path.abspath(disk_path) if disk_path else None,
                 **({"gpu": gpu, "vram": vram, "gpu_device": card} if gpu is not None or vram is not None else {}))
    if st["status"] != "granted":
        if st["status"] == "queued":
            _quietly(release, st["id"])
        sys.stderr.write("oomph: not started — %s\n" % (
            "still queued after %ds (%s)" % (wait_s, st["advice"]) if st["status"] == "queued" else st["advice"]))
        return 75
    if st.get("note"):
        sys.stderr.write("oomph: note — %s\n" % st["note"])
    if (st.get("run_with") or {}).get("gpu"):  # where the job may run (02 §6.5.1): said once; pinned only when asked
        _G()._gpu_run_note(st, pin)
    t0 = time.time()
    try:
        child = subprocess.Popen(run_argv(cmd, st), env=run_env(st, os.environ, pin))
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
    cores, dpeak = (h.get("peak") or {}).get("cpu"), (h.get("peak") or {}).get("disk")
    parts = ["reserved %.1fG, peak %.1fG" % (gb, h.get("peak_gb", 0))] if gb else []
    if "cpu_cores" in (st.get("run_with") or {}):
        parts.append("%s cores%s" % (cores_text(st["run_with"]["cpu_cores"]), ", peak %.1f busy" % cores
                                     if _num(cores) else ""))
    if disk:
        parts.append("%sG of disk%s" % (_gb(disk), ", %sG used" % _gb(dpeak) if _num(dpeak) else ""))
    vpeak = (h.get("peak") or {}).get("vram")
    if vram:
        parts.append("%sG of GPU memory%s" % (_gb(vram), ", peak %sG" % _gb(vpeak) if _num(vpeak) else ""))
    if gpu:
        parts.append("%s %% of the GPU" % cores_text(gpu))
    sys.stderr.write("oomph: %s — %s, %ds\n" % (st["id"], ", ".join(parts), time.time() - t0))
    return rc if rc >= 0 else 128 - rc


def _quietly(fn, *a):
    """Bookkeeping that mustn't stop `oomph run` (its command runs regardless): a ledger error
    is reported, not raised."""
    try:
        return fn(*a)
    except LedgerError as e:
        sys.stderr.write("oomph: %s\n" % e)
        return None


def _hook_dir():
    """Where the hook keeps what it last said, per session: a folder of this user's own, 0700, in
    $XDG_RUNTIME_DIR (Linux), else in $TMPDIR (per user on a Mac), else in /tmp, named per user
    there: never the shared /tmp itself, where anyone could plant a state that silences the
    warnings. None when no such folder can be had (the hook then keeps no state)."""
    uid = os.getuid()
    x = os.environ.get("XDG_RUNTIME_DIR")
    bases = [(x, CMD)] if x and os.path.isabs(x) else []
    t = os.environ.get("TMPDIR")
    bases += [(t if t and os.path.isabs(t) else "/tmp", "%s-%d" % (CMD, uid))]
    for base, name in bases:
        d = os.path.join(base, name)
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
        except OSError:
            continue
        try:
            st = os.lstat(d)
        except OSError:
            continue
        if stat.S_ISDIR(st.st_mode) and st.st_uid == uid and not st.st_mode & 0o077:
            return d
    return None


def _hook_load(path):
    """The hook's last state, if this user wrote it and its time is not in the future."""
    try:
        if os.lstat(path).st_uid != os.getuid():
            return {}
        prev = loads_untrusted(read_bounded(path, 4096)) or {}
    except Exception:
        return {}
    if not isinstance(prev, dict) or not _num(prev.get("t"), 0, time.time() + 60):
        return {}
    return prev


def _hook_save(path, level):
    """The hook's state, by a new file renamed over the name: never written through a link
    someone planted there (/tmp is everybody's)."""
    tmp = "%s.%s.tmp" % (path, secrets.token_hex(6))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump({"level": level, "t": time.time()}, f)
        os.rename(tmp, path)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def cmd_hook(args):
    """PostToolUse hook. Silent (exit 0) when memory is ok. When tight/critical, prints a short
    warning to stderr and exits 2, which Claude Code shows to the model. Warns again only when
    the level changes or after 10 minutes."""
    try:
        sys.stdin.read()  # the hook payload; not needed
    except Exception:
        pass
    global _lock_wait
    _lock_wait = 0.25  # after every Bash call: never wait on a held lock (03 §10). On a Mac too, since 1.9.4:
    # the hook only reads the ledger, and a check without the coordination is better than a stalled Bash call
    v = checked_verdict()
    hd = _hook_dir()
    state = os.path.join(hd, "oomph-hook-%d.json" % os.getppid()) if hd else None
    prev = _hook_load(state) if state else {}
    if v["level"] == "ok":
        if state and prev.get("level") not in (None, "ok"):
            _hook_save(state, "ok")
        return 0
    if prev.get("level") == v["level"] and time.time() - prev["t"] < 600:
        return 0
    if state:
        _hook_save(state, v["level"])
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
                    "and release it with release_memory when the heavy part is over. For parallel work (builds, test "
                    "runners, -j) also ask for cpu_cores, in the same call: what its parallelism would use. You are "
                    "granted between half of that and all of it, and the answer's run_with.cpu_cores is the number "
                    "to run with (-jN), not the number you asked for. Before writing more than about 5 GB (a download, "
                    "a dataset, an image build) also ask for disk_gb, and disk_path when it is not the temporary "
                    "folder's disk. For a model on a GPU, gpu_mem_gb (the model plus half a GB) and gpu_pct, only where "
                    "`oomph resources` lists gpu as reservable: the answer's run_with.gpu names the card to run on.",
     "inputSchema": {"type": "object", "required": ["purpose"], "additionalProperties": False, "properties": {
         "gb": {"type": "number", "exclusiveMinimum": 0, "description": "estimated peak extra memory in GB (gb, "
                                                                        "cpu_cores or disk_gb, or several)"},
         "cpu_cores": {"type": "number", "exclusiveMinimum": 0, "description": "logical cores the work would use "
                                                                               "(e.g. its -j); granted half to all"},
         "cpu_min": {"type": "number", "exclusiveMinimum": 0, "description": "the fewest cores to start with (default "
                                                                             "half of cpu_cores; equal to it: exactly "
                                                                             "that many, or wait)"},
         "disk_gb": {"type": "number", "exclusiveMinimum": 0, "description": "GB the work will write to one disk"},
         "disk_path": {"type": "string", "description": "any path on that disk (default: the temporary folder's)"},
         "gpu_pct": {"type": "number", "exclusiveMinimum": 0, "maximum": 100,
                     "description": "share of one GPU the work keeps busy, in % (where GPUs are reservable)"},
         "gpu_mem_gb": {"type": "number", "exclusiveMinimum": 0, "description": "GB of GPU memory: the model plus half a "
                                                                              "GB (a Mac: counted as memory)"},
         "gpu_device": {"type": "string", "description": "the card to use: its index (e.g. '1') or UUID prefix; "
                                                         "default: any card with room, named in run_with.gpu"},
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
         "gb": {"type": "number", "minimum": 0, "description": "new size in GB (0 drops the memory of a "
                                                                 "reservation that also holds cores or disk space)"},
         "cpu_cores": {"type": "number", "minimum": 0, "description": "new number of cores (0 drops them)"},
         "disk_gb": {"type": "number", "minimum": 0, "description": "new disk space in GB, on the same disk (0 drops it)"},
         "gpu_pct": {"type": "number", "minimum": 0, "maximum": 100, "description": "new share of the GPU (0 drops it)"},
         "gpu_mem_gb": {"type": "number", "minimum": 0, "description": "new GPU memory in GB, on the same card (0 drops it)"},
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
         "purpose": {"type": "string", "description": "only reservations whose purpose contains this text"},
         "resource": {"type": "string", "enum": ["memory", "cpu", "disk", "gpu"],
                      "description": "only reservations that held this resource"}}}},
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


_MCP_NEEDS = {"reserve_memory": ()}  # purpose is asked for, but a call without it is "unspecified"; gb, cores or disk


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
    for k in ("cpu_cores", "cpu_min", "disk_gb", "gpu_pct", "gpu_mem_gb"):  # numbers, as the schema says (gb: float())
        if a.get(k) is not None and not _num(a[k], 0, 1e6):
            raise ToolArgError("%s: %s takes a number from 0 up, not %r" % (name, k, a[k]))
    if any(a.get(k) is not None for k in ("gpu_pct", "gpu_mem_gb", "gpu_device")):
        _G()._gpu_mcp_args(name, a)
    if a.get("disk_gb") and round(float(a["disk_gb"]), 2) < DISK_MIN_GB:  # 0.004 would be kept as none
        raise ToolArgError("%s: disk_gb takes at least %g (GB), not %r" % (name, DISK_MIN_GB, a["disk_gb"]))
    if name == "reserve_memory":
        if not (a.get("gb") or a.get("cpu_cores") or a.get("disk_gb") or a.get("gpu_pct") or a.get("gpu_mem_gb")):
            raise ToolArgError("reserve_memory needs gb, cpu_cores, disk_gb, gpu_pct or gpu_mem_gb (or several)")
        if a.get("disk_path") is not None and not (a.get("disk_gb") and isinstance(a["disk_path"], str)
                                                   and 0 < len(a["disk_path"]) <= 4096 and "\0" not in a["disk_path"]):
            raise ToolArgError("reserve_memory: disk_path is a path on the disk, and comes with disk_gb")
        if a.get("cpu_min") is not None and not a.get("cpu_cores"):
            raise ToolArgError("reserve_memory: cpu_min comes with cpu_cores")
        if a.get("cpu_cores"):
            try:
                parse_cores(a["cpu_cores"])
                if a.get("cpu_min") is not None:
                    parse_cores(a["cpu_min"])
            except ValueError as e:
                raise ToolArgError("reserve_memory: %s" % e)
            if a.get("cpu_min") is not None and a["cpu_min"] > a["cpu_cores"]:
                raise ToolArgError("reserve_memory: cpu_min (%g) is more than cpu_cores (%g)" % (a["cpu_min"], a["cpu_cores"]))
    if name == "update_reservation" and a.get("cpu_cores"):
        try:
            parse_cores(a["cpu_cores"])
        except ValueError as e:
            raise ToolArgError("update_reservation: %s" % e)


def _mcp_call(name, a):
    _mcp_args(name, a)
    if name == "memory_check":
        return checked_verdict()
    if name == "reserve_memory":
        ttl = min(max(int(a.get("ttl_min", 30)), 1), 480) * 60
        cpu = parse_cores(a["cpu_cores"])[0] if a.get("cpu_cores") else None
        path = a.get("disk_path")
        gpu = {k: x for k, x in (("gpu", round(float(a["gpu_pct"]), 1) if a.get("gpu_pct") else None),
                                 ("vram", round(float(a["gpu_mem_gb"]), 2) if a.get("gpu_mem_gb") else None),
                                 ("gpu_device", a.get("gpu_device"))) if x is not None}
        return acquire(float(a.get("gb") or 0), str(a.get("purpose", "unspecified")), holder_for(), ttl,
                       min(max(int(a.get("wait_s", 120)), 0), 300), a.get("ticket"), cpu=cpu,
                       cpu_min=round(float(a["cpu_min"]), 1) if cpu and a.get("cpu_min") is not None else None,
                       disk=round(float(a["disk_gb"]), 2) if a.get("disk_gb") else None,
                       disk_path=os.path.abspath(os.path.expanduser(path)) if path else None, **gpu)
    if name == "release_memory":
        rid = str(a.get("id", ""))
        return release(rid, holder_for()["pid"] if rid == "all" else None)
    if name == "update_reservation":
        return amend(str(a["id"]), float(a["gb"]) if a.get("gb") is not None else None,
                     min(max(int(a["ttl_min"]), 1), 480) * 60 if a.get("ttl_min") else None,
                     str(a["purpose"]) if a.get("purpose") else None,
                     cpu=(parse_cores(a["cpu_cores"])[0] if a["cpu_cores"] else 0.0)
                     if a.get("cpu_cores") is not None else None,
                     disk=round(float(a["disk_gb"]), 2) if a.get("disk_gb") is not None else None,
                     **{k: x for k, x in (("gpu", round(float(a["gpu_pct"]), 1) if a.get("gpu_pct") is not None else None),
                                          ("vram", round(float(a["gpu_mem_gb"]), 2) if a.get("gpu_mem_gb") is not None
                                           else None)) if x is not None})
    if name == "reservations":
        return coordination(holder_for()["pid"])
    if name == "reservation_history":
        h = reservation_history(min(max(float(a.get("hours", 24)), 0.1), 336) * 3600, 500)
        if a.get("purpose"):
            h["reservations"] = [x for x in h["reservations"] if str(a["purpose"]).lower() in x["purpose"].lower()]
        if a.get("resource") == "cpu":
            h["reservations"] = [x for x in h["reservations"] if "cpu" in (x.get("res") or {})]
        elif a.get("resource") == "disk":
            h["reservations"] = [x for x in h["reservations"] if "disk" in (x.get("res") or {})]
        elif a.get("resource") == "gpu":
            h["reservations"] = [x for x in h["reservations"] if set(x.get("res") or {}) & {"gpu", "vram"}]
        elif a.get("resource") == "memory":
            h["reservations"] = [x for x in h["reservations"] if x["gb"] > 0]
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
        incs = list_incidents(quiet=False)[-int(a.get("limit", 10)):]
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


def _here_words(x):
    """MCP texts for the machine this runs on: "this Mac" on a Mac, "this machine" elsewhere."""
    if sys.platform == "darwin":
        return x
    if isinstance(x, str):
        return x.replace("this Mac's", "this machine's").replace("this Mac", "this machine").replace(
            "on a Mac", "on this machine")
    if isinstance(x, list):
        return [_here_words(v) for v in x]
    if isinstance(x, dict):
        return {k: _here_words(v) for k, v in x.items()}
    return x


MCP_LINE_CAP = 8 << 20  # a request longer than this is answered with a parse error and skipped
MCP_HEAD_CAP = 16 << 10  # where an installed oomph.py's stamped VERSION is looked for (line 83 of 1.10.6)
MCP_SELFCHECK_S = 5      # the new code's time to answer `mcp --selfcheck` (a test may give more: OOMPH_MCP_SELFCHECK_S)
MCP_INSTRUCTIONS = (
    "%s reports %s memory, swap and disk, and coordinates memory between Claude sessions and other agents. "
    "Before memory-heavy work call reserve_memory with the work's estimated peak (reservation_history shows what "
    "similar work really needed), for parallel work its cores (cpu_cores; run with run_with.cpu_cores), and before "
    "writing many GB the disk space (disk_gb); start only when granted. Shrink or extend it with update_reservation "
    "as the work changes, and release_memory when done. Call memory_check periodically and back off when it says tight or "
    "critical.")


def _mcp_answer(req):
    """The JSON-RPC answer to one request of the MCP server (a dict), None for a notification."""
    if not isinstance(req, dict):
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
    rid, method, params = req.get("id"), req.get("method"), req.get("params") or {}
    if rid is None:
        return None  # a notification (e.g. notifications/initialized)
    if not isinstance(params, dict):
        params = {}
    try:
        if method == "initialize":
            result = {"protocolVersion": params.get("protocolVersion", "2025-06-18"),
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": CMD, "title": BRAND, "version": VERSION},
                      "instructions": MCP_INSTRUCTIONS % (
                          BRAND, "this Mac's" if sys.platform == "darwin" else "this machine's")}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": _here_words(MCP_TOOLS)}
        elif method == "tools/call":
            try:
                data = _mcp_call(params.get("name"), params.get("arguments") or {})
                result = {"content": [{"type": "text", "text": json.dumps(data, indent=1)}], "isError": False}
            except KeyError:
                return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "unknown tool"}}
            except (LedgerError, ToolArgError) as e:  # busy, refused, or arguments it can't take: say so plainly
                result = {"content": [{"type": "text", "text": "oomph: %s" % e}], "isError": True}
            except Exception as e:
                result = {"content": [{"type": "text", "text": "oomph error: %r" % e}], "isError": True}
        else:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "method not found"}}
        return {"jsonrpc": "2.0", "id": rid, "result": result}
    except Exception as e:
        return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32603, "message": repr(e)}}


def _stamped(path, owner=0):
    """(real path, stamped VERSION, (device, inode)) of the oomph.py that `path` leads to (links followed:
    /usr/local/bin/oomph leads to the installed version's directory), or (None, None, None) unless that file
    may replace a running MCP server: a regular file of `owner` (root: an installed copy, never a checkout
    someone edits) in a directory of `owner`'s, neither writable by group or others, opened without following
    a further link or blocking. Only its first MCP_HEAD_CAP bytes are read."""
    none = None, None, None
    try:
        real = os.path.realpath(path)
        dfd = os.open(os.path.dirname(real), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except (OSError, ValueError):
        return none
    try:
        fd = os.open(os.path.basename(real), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dfd)
    except OSError:
        os.close(dfd)
        return none
    try:
        sts = (os.fstat(dfd), os.fstat(fd))
        if any(st.st_uid != owner or st.st_mode & 0o022 for st in sts) or not stat.S_ISREG(sts[1].st_mode):
            return none
        head = os.read(fd, MCP_HEAD_CAP)
    except OSError:
        return none
    finally:
        os.close(fd)
        os.close(dfd)
    m = re.search(rb'^VERSION = "([0-9A-Za-z.+_-]{1,64})"', head, re.M)
    return (real, m.group(1).decode(), (sts[1].st_dev, sts[1].st_ino)) if m else none


class _SelfReplace:
    """An MCP server lives as long as its Claude session, so after an update it would answer with old code for
    hours (roadmap 02 §9.3). Before each request it looks at the VERSION stamped into the file it was started
    from (`watch`, links followed, so an update that swapped /usr/local/libexec/oomph shows) and replaces itself
    only when all of this holds: that file is an installed copy (_stamped: root's, writable by nobody else; a
    test injects its own uid with OOMPH_MCP_OWNER), its version differs from the running one, neither is
    "dev" (a checkout's), the new code passes `mcp --selfcheck` within MCP_SELFCHECK_S, and the file is
    still the one checked (same path, device, inode and version) just before the exec. A failed self-check
    (or a file swapped meanwhile) keeps the old code and is not tried again until the stamped file changes:
    another version, or the same one installed afresh (another inode). Only a root-owned install replaces
    itself (the Mac's, Linux's system mode): a Linux user install is the user's own, not root's. The session
    keeps the tool surface it was given at its start (it asks once; every version accepts the names earlier
    ones listed) and gets the new ledger logic. A server running as root never replaces itself (the
    security rule of 1.8.4)."""

    def __init__(self, watch):
        self.watch = watch
        o = os.environ.get("OOMPH_MCP_OWNER", "")
        self.owner = int(o) if o.isdigit() else 0
        s = os.environ.get("OOMPH_MCP_SELFCHECK_S", "")
        self.deadline = min(int(s), 120) if s.isdigit() and int(s) > 0 else MCP_SELFCHECK_S
        self.failed = None  # _stamped() of the last file whose self-check (or exec) failed
        self.got = None     # _stamped() of the file target() checked

    def target(self):
        """The real path of the code to replace this server with, or None."""
        if not STAMPED or os.geteuid() == 0:  # root's server would put the bytes in hand into a shared /tmp
            return None
        got = _stamped(self.watch, self.owner)
        real, ver = got[0], got[1]
        if real is None or ver in ("dev", VERSION) or got == self.failed:
            return None
        self.got = got
        try:
            r = subprocess.run([sys.executable or "/usr/bin/python3", "-I", "-B", real, "mcp", "--selfcheck"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=self.deadline)
            ok = r.returncode == 0 and r.stdout.startswith(b"ok")
        except (OSError, subprocess.SubprocessError):
            ok = False
        if not ok:
            self.failed = got
            return None
        return real

    def hand_over(self, real, pending):
        """exec the new code with the bytes read and not yet answered (the request at hand first) in an
        unlinked file whose descriptor it inherits; it answers those, then reads on from descriptor 0. Returns
        only if the exec failed, or the file is no longer the one checked (the old code then answers)."""
        import tempfile
        py = sys.executable or "/usr/bin/python3"
        if _stamped(self.watch, self.owner) != self.got or real != self.got[0]:  # swapped since the check
            self.failed = self.got
            return
        try:
            with tempfile.TemporaryFile() as f:
                f.write(pending)
                f.flush()
                fd = os.dup(f.fileno())
            os.lseek(fd, 0, os.SEEK_SET)
            os.set_inheritable(fd, True)
            sys.stdout.flush()
            os.execv(py, [py, "-I", "-B", real, "mcp", "--resume-fd", str(fd), "--watch", self.watch])
        except OSError:
            self.failed = self.got
            try:
                os.close(fd)
            except (OSError, NameError):
                pass


def _mcp_resumed(args):
    """The bytes a replaced server handed over (`--resume-fd N`: a regular file, read once and closed), and
    the file the server was started from (`--watch PATH`)."""
    def arg(name):
        return args[args.index(name) + 1] if name in args and args.index(name) + 1 < len(args) else None
    watch = arg("--watch")
    watch = watch if watch and os.path.isabs(watch) else os.path.abspath(__file__)
    fd = arg("--resume-fd")
    if not (fd and fd.isdigit() and 2 < int(fd) < 65536):
        return b"", watch
    fd, data = int(fd), b""
    try:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            while len(data) <= MCP_LINE_CAP + 65536:
                b = os.read(fd, 65536)
                if not b:
                    break
                data += b
        os.close(fd)
    except OSError:
        pass
    return data[:MCP_LINE_CAP + 65536], watch


def _mcp_selfcheck():
    """`oomph mcp --selfcheck`: what a running server asks of new code before it becomes that code: its
    modules import, and it answers tools/list to itself. Prints ok and exits 0."""
    try:
        _daemon_module()
        r = _mcp_answer({"jsonrpc": "2.0", "id": 0, "method": "tools/list"})
        ok = len(r["result"]["tools"]) > 0 and json.dumps(r)
    except Exception as e:
        sys.stderr.write("%s mcp --selfcheck: %r\n" % (CMD, e))
        return 1
    print("ok %s %d tools" % (VERSION, len(r["result"]["tools"])) if ok else "no tools")
    return 0 if ok else 1


def cmd_mcp(args=()):
    """Minimal MCP server (JSON-RPC 2.0, newline-delimited over stdio). It reads descriptor 0 itself
    (os.read, its own lines) because a buffered reader would take bytes from the pipe that an exec then
    loses; see _SelfReplace."""
    args = list(args)
    if "--selfcheck" in args:
        return _mcp_selfcheck()
    buf, watch = _mcp_resumed(args)
    buf = bytearray(buf)
    swap = _SelfReplace(watch)
    eof, skipping, scan = False, False, 0

    def send(msg):
        sys.stdout.write(json.dumps(msg) + "\n")
        sys.stdout.flush()

    while True:
        nl = buf.find(b"\n", scan)
        if nl < 0:
            if len(buf) > MCP_LINE_CAP:  # a line too long to hold: dropped up to its end, then answered
                del buf[:]
                skipping = True
            if not eof:
                scan = len(buf)
                chunk = os.read(0, 65536)
                if chunk:
                    buf.extend(chunk)
                else:
                    eof = True
                continue
            if not buf.strip():
                return 0
            nl = len(buf)
        line, rest = bytes(buf[:nl]).strip(), nl + 1
        del buf[:rest]
        scan = 0
        if skipping:
            skipping = False
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "request too long"}})
            continue
        if not line:
            continue
        try:
            req = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError):
            send({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}})
            continue
        if isinstance(req, dict) and req.get("id") is not None:
            new = swap.target()
            if new:
                swap.hand_over(new, line + b"\n" + bytes(buf))
        out = _mcp_answer(req)
        if out is not None:
            send(out)


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
        machine = P.machine(all_procs=root if mac else None)  # Linux: /proc is world-readable, unless hidepid
        sysm = P.system_memory()
        procs = P.collect_procs()
        if mac or P.OS != "linux":
            add("memory", "ok", "%s · %.0f GB RAM" % ("vm_stat and sysctl" if mac else P.OS, sysm.get("ram_gb") or 0))
            add("processes", "ok", "%d visible, %d with a footprint" % (len(procs), sum(1 for p in procs.values() if p.get("fp"))))
        else:
            _doctor_linux(add, machine, sysm, procs)
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
        add("logger", "note", "not installed: nothing is logged, every reading is live%s" % (
            "" if mac else "; history, incidents and kills by name need the logger"),
            "Activate in the menu-bar app, or sudo ./install.sh from a checkout" if mac else
            "sudo linux/install.sh --system, from a checkout (git clone https://github.com/kleinzeug/oomph.git)")
    if not mac:
        _doctor_linux_logger(add, d if fresh else None, installed)

    inst = _version_in(os.path.join(PATHS_HERE["libexec"], "oomph.py"))
    if inst is None and not mac:  # linux/install.sh: the user's own copy
        inst = _version_in(os.path.join(os.path.expanduser(PATHS_HERE["user_lib"]), "oomph.py"))
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
    return {"version": VERSION, "machine": machine, "ledger": ledger_info(), "checks": checks, "exit": code}


def _doctor_linux(add, m, s, procs):
    """doctor's lines for what a Linux machine offers (03 §3.2, F0, F2): memory and scope, PSI (off
    by default on the RHEL 9 family: the level then stops at warning, D15), kills, processes,
    groups, swap. A note is how this machine is; a warn is what can be fixed where one stands."""
    ms = m.get("measures") or {}
    sc = s.get("scope") if isinstance(s.get("scope"), dict) else {}
    if sc.get("kind") == "cgroup":
        add("memory", "ok", "limit %.1f GB (memory.%s) on a %.1f GB host: %s measures the cgroup" % (
            sc.get("limit_gb") or 0, sc.get("by") or "max", sc.get("host_ram_gb") or 0, BRAND))
    else:
        add("memory", "ok", "/proc/meminfo with MemAvailable · %.1f GB RAM" % (s.get("ram_gb") or 0))
    if ms.get("psi"):
        add("pressure", "ok", "PSI at /proc/pressure/memory%s" % (", and of this cgroup" if sc else ""))
    else:
        add("pressure", "note", "PSI is off on this kernel: the level comes from what is available and from swap "
                                "alone, and stops at warning (memory never reads critical here)",
            "turn it on with psi=1 on the kernel command line and a restart; on the RHEL family: "
            "sudo grubby --update-kernel=ALL --args=psi=1")
    mine = sum(1 for p in procs.values() if p.get("uid") == os.getuid())
    if ms.get("all_procs") is False:
        add("processes", "note", "%d visible: /proc is mounted with hidepid, so only your own (%d) count" % (len(procs), mine))
    else:
        add("processes", "ok", "%d visible; names from command lines; working directories for your own %d" % (len(procs), mine))
    cg = ms.get("cgroup")
    add("groups", "ok" if cg == "v2" else "note", {"v2": "cgroup v2: units and containers become groups",
                                                   "v1": "cgroup v1: grouped by program name"}.get(
        cg, "no cgroups: grouped by program name"))
    tot = s.get("swap_total_gb") or 0
    lx = s.get("linux") if isinstance(s.get("linux"), dict) else {}
    z = ms.get("zswap")
    add("swap", "ok", "%s · %s · zswap %s" % (
        "%.1f GB on disk" % tot if tot else "none on disk",
        "zram %.1f GB" % lx["zram_disk_gb"] if lx.get("zram_disk_gb") else "no zram",
        {True: "on", False: "off"}.get(z, "not reported by this kernel")))
    if sc.get("kind") == "cgroup":
        add("scope", "note", "inside a cgroup limited to %.1f GB: every figure is about it, and its level is the worse of "
                             "its own and the host's" % (sc.get("limit_gb") or 0))
    else:
        add("scope", "note", "not in a limited cgroup: %s measures the whole machine" % BRAND)


def _secret_bad(path=None):
    """What is wrong with the hooks' secrets file (ALERT_SECRET), which must be root's alone (a regular file of
    uid 0, mode 0600 or less): "is a link", "belongs to uid N", "may be read by others (0644)"; None when it is
    right or missing (missing has its own line)."""
    try:
        st = os.lstat(path or ALERT_SECRET)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode):
        return "is not a regular file (a link?)"
    if st.st_uid != 0:
        return "belongs to uid %d, not root" % st.st_uid
    if st.st_mode & 0o077:
        return "may be read or written by others (%04o)" % stat.S_IMODE(st.st_mode)
    return None


def _doctor_linux_logger(add, d, installed):
    """doctor's lines for the Linux logger (1.13.0, 03 §3.2): how kills are recorded, the alert hooks, and
    who may use the machine's ledger (open to every local account, D16) with how to restrict it."""
    ms = ((d or {}).get("machine") or {}).get("measures") or {}
    mode = ms.get("kills")
    if d is None:
        add("kills", "note", "not recorded: the logger names kernel OOM kills (it is not running)")
    elif mode == "journal":
        add("kills", "ok", "named from the journal: the kernel's OOM killer, systemd-oomd and earlyoom")
    else:
        add("kills", "note", "counted, not named: the logger cannot read the journal (no systemd, or installed "
                             "with --no-journal)", "sudo linux/install.sh --system (without --no-journal)")
    if installed or d is not None:
        bad = []
        hooks = alert_hooks(unrunnable=bad)
        wants = "/etc/systemd/system/multi-user.target.wants/oomph-alert.path"
        if bad:
            add("alerts", "warn", "%d script(s) in %s cannot run: the unit runs hooks as a throwaway account, which "
                                  "may not read %s" % (len(bad), alert_dir(), ", ".join(os.path.basename(b) for b in bad[:3])),
                "sudo chmod 755 %s (secrets go into %s, which the unit hands to them)" % (" ".join(bad[:3]), ALERT_SECRET))
        elif hooks and not os.path.lexists(ALERT_SECRET):
            add("alerts", "warn", "%s is missing: oomph-alert.service cannot start without it" % ALERT_SECRET,
                "sudo install -m 600 /dev/null %s (then its KEY=value lines for the hooks)" % ALERT_SECRET)
        elif hooks and _secret_bad():
            add("alerts", "warn", "%s %s: the hooks' secrets must be root's alone" % (ALERT_SECRET, _secret_bad()),
                "sudo chown root:root %s && sudo chmod 600 %s (if it is a link: remove it and run sudo install -m "
                "600 /dev/null %s)" % (ALERT_SECRET, ALERT_SECRET, ALERT_SECRET))
        elif hooks and not os.path.lexists(wants):
            add("alerts", "warn", "%d script(s) in %s, but oomph-alert.path is not enabled" % (len(hooks), alert_dir()),
                "sudo systemctl enable --now oomph-alert.path")
        elif hooks:
            add("alerts", "ok", "%d script(s) in %s run when an incident opens, kills or closes (test: sudo %s alert "
                                "--test)" % (len(hooks), alert_dir(), CMD))
        else:
            add("alerts", "note", "incidents reach the journal only (journalctl -p crit -u oomphd); a script in %s "
                                  "hears of each" % alert_dir(),
                "examples in %s/alert.d.examples (ntfy, a Slack webhook, mail)" % PATHS_HERE["libexec"])
    shared = PATHS_HERE.get("shared_ledger")
    if shared and LEDGER_DIR == shared:
        try:
            st = os.lstat(shared)
        except OSError:
            return
        if stat.S_ISDIR(st.st_mode) and st.st_mode & 0o002:
            add("access", "note", "the machine's ledger %s is open to every local account, as on a Mac: any of them "
                                  "may reserve, and see the others' purposes" % shared,
                "to keep it to a group: sudo groupadd %(g)s; sudo usermod -aG %(g)s oomphd (and each member); "
                "sudo chgrp %(g)s %(d)s; sudo chmod 2770 %(d)s; sudo systemctl restart oomphd (the logger then "
                "keeps purposes out of %(l)s, whose process names and figures every account still reads). Root "
                "without sudo (su -, a root agent) reaches the ledger as nobody, who is not in the group: root then "
                "reserves only with sudo from a member's account" % {"g": CMD, "d": shared, "l": LOG_DIR})
        elif stat.S_ISDIR(st.st_mode):
            add("access", "note", "the machine's ledger %s is kept to group %s (mode %03o); purposes stay out of the "
                                  "logs%s" % (shared, _group_name(st.st_gid), stat.S_IMODE(st.st_mode),
                                              "" if _in_group("nobody", st.st_gid) else "; root without sudo cannot "
                                              "reserve (it would as nobody): sudo from a member's account"))
    _doctor_linux_skew(add, shared)


def _doctor_linux_skew(add, shared):
    """Copies that do not take turns with the others (03 review #16): once the machine's ledger exists, a copy of
    oomph older than 1.13 (a ~/.local/bin/oomph first on the PATH, a long-running MCP server) still uses its own
    per-user ledger. Said when that ledger is still there (with its live reservations) or the own copy is older."""
    if not shared or LEDGER_DIR != shared:
        return
    own = _path("ledger")
    if os.geteuid() != 0 and own != shared and os.path.isdir(own):
        L = _valid_ledger(loads_untrusted(read_bounded(os.path.join(own, "ledger.json"), LIMITS["ledger"]) or b""))
        now = time.time()
        n = sum(1 for r in (L or {}).get("leases") or () if _live(r, now))
        add("own ledger", "warn" if n else "note",
            "your ledger from before the machine's, %s, is still there%s: a copy of %s older than 1.13 (an MCP server "
            "started before the update, ~/.local/bin/oomph) keeps using it and does not take turns with the others"
            % (own, " with %d live reservation%s" % (n, "" if n == 1 else "s") if n else "", BRAND),
            "restart the sessions; linux/uninstall.sh (as yourself) removes your own copy; then rm -r %s" % own)
    mine = _version_in(os.path.join(os.path.expanduser(PATHS_HERE["user_lib"]), "oomph.py"))
    machine = _version_in(os.path.join(PATHS_HERE["libexec"], "oomph.py"))
    if os.geteuid() != 0 and mine and machine and mine != machine:
        add("own copy", "warn", "your own copy in ~/.local (%s) is not the machine's (%s), and it comes first on your "
                                "PATH" % (mine, machine),
            "linux/uninstall.sh (as yourself), or linux/install.sh again from the machine's version")


def _group_name(gid):
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


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
    """The GPU's full-speed figure (IOReport, in a helper that runs as nobody): opt-in, or on unless
    switched off once IOREPORT_DEFAULT is True. `c`: the logger's current sample when it is fresh,
    which says what the logger does."""
    d = c.get("daemon") if c and isinstance(c.get("daemon"), dict) else {}
    state = d.get("ioreport") if isinstance(d.get("ioreport"), str) else None
    gpus = c.get("gpu") if c and isinstance(c.get("gpu"), list) else []
    full = any(isinstance(g, dict) and g.get("src") == "ioreport" for g in gpus)
    if state in IOREPORT_OFF:
        return "gpu", "note" if state in ("unavailable", "table") else "warn", "busy time only: " + IOREPORT_OFF[state]
    if full or state == "on":
        return "gpu", "ok", "at full speed, from IOReport (a helper that runs as nobody)" if full else \
            "full speed switched on; the logger's next sample has it"
    if ioreport_wanted() and not (setting("ioreport") is None and _no_full_speed()):
        return "gpu", "note", "full speed %s, not yet used by the logger" % (
            "switched on in %s" % CONFIG_FILE if setting("ioreport") is not None else "on by default"), \
            kick if c else None
    if switched_on(setting("no_ioreport")):
        return "gpu", "note", "busy time only: the full-speed figure is switched off (no_ioreport)"
    if _no_full_speed():
        return "gpu", "note", "busy time only (the share of time the GPU worked, at any speed); this Mac has no GPU " \
            "frequency table, so the figure at full speed is not available here"
    if IOREPORT_DEFAULT:  # on by default, so here someone switched it off ("ioreport": false)
        return "gpu", "note", "busy time only: the full-speed figure is switched off (\"ioreport\": false in %s)" % \
            CONFIG_FILE
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


def _registered_path():
    """The command Claude Code is told to run (03 §10): the first of /usr/local/bin/oomph,
    /usr/bin/oomph, `oomph` on the PATH (a user install's ~/.local/bin/oomph), each only when it is
    this oomph, else this script itself. A link that stays put survives updates."""
    import shutil
    mine = os.path.realpath(__file__)
    user_bin = os.path.expanduser(PATHS_HERE.get("user_bin") or "") or None
    for c in ("/usr/local/bin/oomph", "/usr/bin/oomph", user_bin, shutil.which(CMD)):
        if c and os.path.exists(c) and (c == "/usr/local/bin/oomph" and sys.platform == "darwin"
                                        or os.path.realpath(c) == mine):
            return c
    return mine


def cmd_setup_claude(args):
    import shutil
    home = os.path.expanduser("~")
    dest_dir = os.path.join(home, ".claude", "skills", CMD)
    settings = os.path.join(home, ".claude", "settings.json")
    me = _registered_path()
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


def _importable():
    """Whether this file can be imported by its name from its folder (oomph.py, installed or in a
    checkout; behind a link, the link's target). Up to 1.12.1 `oomph top` started again only on
    bytecode install.sh made: without it the dashboard ran on in this script's process, 18 MB more at
    its peak (60 MB on Linux) than a fresh one that compiles its modules on import (1.12.2)."""
    name = os.path.basename(os.path.realpath(__file__))
    return name.endswith(".py") and name[:-3].isidentifier()


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
        if __name__ == "__main__" and "--once" not in rest and sys.executable and _importable():
            # Run as a script, this module was compiled from source, and what that leaves behind stays
            # resident for as long as the dashboard runs: start again, same process and terminal, as an
            # import (of the bytecode install.sh made, or else of the source). (-I, and -B if given.)
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
    if c in ("serve", "remote", "share"):
        if HERE not in sys.path:
            sys.path.insert(0, HERE)
        if c == "serve":
            import oomph_net
            return oomph_net.cmd_serve(rest)
        if c == "share":
            import oomph_net
            return oomph_net.cmd_share(rest)
        import oomph_sync
        return oomph_sync.cmd_remote(rest)
    if c == "hook":
        return cmd_hook(rest)
    if c == "mcp":
        return cmd_mcp(rest)
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
        return cmd_incidents(rest)
    if c == "alert":
        return cmd_alert(rest)
    if c == "incident":
        return cmd_incident(rest)
    if c == "html":
        return cmd_html(rest)
    if c == "version":
        print(json.dumps({"version": VERSION, "commit": COMMIT, "brand": BRAND, "command": CMD,
                          "hardening": HARDENING, "sharing": SHARING}) if "--json" in rest else VERSION)
        return 0
    print(usage(__doc__))
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]) or 0)
