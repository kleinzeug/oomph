"""oomph's wire protocol and its serving side (roadmap 01 §4.2, §5).

    oomph serve --stdio [--now T]

answers for this machine on its standard streams, read only, from its two directories: the log
directory (LOG_DIR, written by the root logger) and the shared ledger directory (LEDGER_DIR,
writable by everyone). It is the protocol's simplest front end: what `ssh host oomph serve
--stdio` will run, and what `oomph remote sync` and the tests talk to. There is no listener, no
TLS and no pairing yet; over a pipe the transport is the authentication, so `hello` opens the
session. `--now` fixes the clock the server reports (fixtures and tests).

The protocol: JSON-RPC 2.0, one compact JSON object per line, line lengths capped in both
directions. Everything that can grow travels zlib-compressed and base64-encoded inside a result,
in pages with a positional cursor [t, k] (the k-th row of time t, in file order), so no reply is
unbounded and every reply either moves the cursor or says `more: false`. Nothing either directory
holds is passed on whole: samples are slimmed (oomph.slim_sample), the current sample is rebuilt
from named fields (oomph.full_sample), ledger and history records from theirs, strings cut and
lists capped. One item too big for a page is skipped, counted and stepped over.

Run as root it first becomes the user who ran sudo, else nobody, for good: no process running as
root opens anything in the shared ledger directory (H0), and a server needs no privilege at all.
It writes nothing anywhere. Standard library only; Python 3.9.
"""
import base64
import gzip
import json
import math
import os
import re
import select
import socket
import stat
import sys
import time
import zlib

import oomph

PROTO = (1, 1)                       # the protocol versions this code speaks
CAPS = ("samples", "events", "incidents", "ledger")   # what this server offers (`full`, `files`, `broker`: later)
LINE_PRE = 4 << 10                   # a client's line before the session is open ...
LINE_IN = 64 << 10                   # ... and after
LINE_OUT = 1 << 20                   # a server's line
PAGE = 256 << 10                     # compressed bytes of a page at most (max_bytes)
INFLATE = 16 << 20                   # what a page may inflate to
ITEM = {"sample_raw": 512 << 10,     # a sample line as logged; a longer one is skipped
        "sample": 64 << 10,          # ... once slimmed
        "record": 16 << 10,          # an event or a reservation record
        "incident": 256 << 10,       # an incident.json
        "current": 512 << 10}        # current.json
SNAPSHOT = 256 << 10                 # the ledger snapshot, compressed
IDLE_S = 120                         # a server closes after this long without a frame
RSS_CAP = 96 << 20                   # ... and leaves after a request that made it grow by more than this
RETENTION_DAYS = 14
STREAMS = ("samples", "events", "ledger", "incidents")
ERR = {"parse": -32700, "invalid": -32600, "method": -32601, "params": -32602, "busy": -32000,
       "unauth": -32001, "auth": -32010, "pair": -32011, "proto": -32020, "large": -32030, "retention": -32040}
INCIDENT_ID = re.compile(r"\d{8}-\d{6}")
DAY_FILE = re.compile(r"samples-(\d{4}-\d{2}-\d{2})\.jsonl(\.gz)?")
# Characters that never reach a file or a screen from the wire: C0 and C1 controls, the
# bidirectional controls and the line and paragraph separators (roadmap 01 §4.3).
_UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f؜‎‏‪-‮⁦-⁩  ]")


class Closed(Exception):
    """The other end closed the stream, or sent a line longer than the limit."""


class RPCError(Exception):
    def __init__(self, code, message, data=None):
        Exception.__init__(self, message)
        self.code, self.message, self.data = code, message, data


# ------------------------------------------------------------------ framing
def dumps(obj):
    """One line of the protocol (and of a mirror): compact, ASCII, no NaN, no newline inside."""
    return json.dumps(obj, separators=(",", ":"), allow_nan=False).encode()


def pack(lines):
    """Rows (bytes, one JSON object each) as a page's `data`: zlib, then base64."""
    return base64.b64encode(zlib.compress(b"\n".join(lines), 6)).decode()


def unpack(data, cap=INFLATE):
    """A page's rows, inflated to at most `cap` bytes; ValueError for anything else."""
    if not isinstance(data, str) or len(data) > LINE_OUT:
        raise ValueError("not a page")
    raw = base64.b64decode(data.encode(), validate=True)
    d = zlib.decompressobj()
    out = d.decompress(raw, cap)
    if d.unconsumed_tail or not d.eof:
        raise ValueError("a page inflates past %d bytes" % cap)
    return out.split(b"\n") if out else []


class Lines:
    """Lines from a file descriptor, each at most `cap` bytes, read without blocking past a
    deadline. read() returns a line without its newline, None when `timeout` passed first, and
    raises Closed at the end of the stream or for a line longer than `cap`."""

    def __init__(self, fd, cap):
        self.fd, self.cap, self.buf, self.eof = fd, cap, b"", False

    def read(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            i = self.buf.find(b"\n")
            if i >= 0:
                line, self.buf = self.buf[:i], self.buf[i + 1:]
                if len(line) > self.cap:
                    raise Closed("a line longer than %d bytes" % self.cap)
                return line
            if len(self.buf) > self.cap:
                raise Closed("a line longer than %d bytes" % self.cap)
            if self.eof:
                raise Closed("end of stream")
            left = None if deadline is None else deadline - time.monotonic()
            if left is not None and left <= 0:
                return None
            if not select.select([self.fd], [], [], left)[0]:
                return None
            b = os.read(self.fd, 1 << 16)
            if not b:
                self.eof = True
                if self.buf:  # a last line without its newline is not a frame
                    raise Closed("end of stream inside a line")
            self.buf += b


def write_all(fd, data):
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


# ------------------------------------------------------------------ what leaves the machine
def clean(s, cut):
    """Display text from another machine: unsafe characters out, at most `cut` characters."""
    return _UNSAFE.sub("", s)[:cut]


def scrub(v, cut=200, depth=4, n=64):
    """Any JSON value reduced to what may travel: objects with string keys (at most n of them),
    lists of at most n items, finite numbers, bools, None and strings cut to `cut` characters,
    nothing nested deeper than `depth`. Used where a record's shape is the logger's own
    (events, an incident's summary); named fields are used everywhere else."""
    if isinstance(v, dict):
        if depth <= 0:
            return None
        return {k[:64]: scrub(x, cut, depth - 1, n) for k, x in list(v.items())[:n] if isinstance(k, str)}
    if isinstance(v, list):
        return [scrub(x, cut, depth - 1, n) for x in v[:n]] if depth > 0 else None
    if isinstance(v, str):
        return v[:cut]
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, (int, float)) and oomph._num(v, -1e18, 1e18):
        return v
    return None


LEASE_FIELDS = ("key", "id", "state", "gb", "purpose", "project", "ttl", "requested", "seen", "granted", "expires",
                "used_gb", "peak_gb", "baseline_gb", "note")
FINISHED_FIELDS = ("key", "id", "purpose", "project", "gb", "holder", "peak_gb", "outcome", "requested", "granted",
                   "ended", "waited_s", "held_s")
RECORD_FIELDS = ("event", "t", "key", "id", "purpose", "project", "holder", "gb", "requested", "granted", "ended",
                 "outcome", "peak_gb", "used_gb", "expires", "change", "backfilled", "waited_s", "held_s")
INCIDENT_FIELDS = ("id", "start", "start_iso", "last_trigger", "open", "end", "end_iso", "opened_by", "continues")


def _segments(x):
    return [{"t": s["t"], "gb": s["gb"]} for s in (oomph._segments(x) or [])[:64]]


def _named(src, keys, cut=200):
    out = oomph._fields(src, keys, cut)
    if "segments" in src:
        segs = _segments(src["segments"])
        if segs:
            out["segments"] = segs
    return out


def lease_out(r):
    """A live lease (checked by oomph._valid_lease) as it may leave the machine."""
    out = _named(r, LEASE_FIELDS)
    h = r.get("holder") or {}
    out["holder"] = oomph._fields(h, ("pid", "start", "kind"), 64)
    return out


def finished_out(h):
    return _named(h, FINISHED_FIELDS)


def record_out(rec):
    return _named(rec, RECORD_FIELDS)


def incident_out(inc):
    """An incident.json as it may leave the machine: its named fields, reasons as kind, desc and
    t, the summary scrubbed."""
    out = oomph._fields(inc, INCIDENT_FIELDS, 200)
    out["reasons"] = [oomph._fields(r, ("kind", "desc", "t"), 200)
                      for r in (inc.get("reasons") if isinstance(inc.get("reasons"), list) else [])[:64]
                      if isinstance(r, dict)]
    if isinstance(inc.get("summary"), dict):
        out["summary"] = scrub(inc["summary"], 200, 4, 64)
    return out


# ------------------------------------------------------------------ reading the directories
def _open_regular(path):
    """A file object for a regular file at `path`, never through a link, never blocking; None
    otherwise."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            os.close(fd)
            return None
    except OSError:
        os.close(fd)
        return None
    return os.fdopen(fd, "rb")


def file_lines(path, cap):
    """The lines of a log file (plain or gzipped), each without its newline, or None for a line
    longer than `cap` (skipped whole, never held). A last line without a newline is still being
    written and is left for the next look."""
    f = _open_regular(path)
    if f is None:
        return
    try:
        src = gzip.GzipFile(fileobj=f) if path.endswith(".gz") else f
        while True:
            try:
                line = src.readline(cap + 1)
            except (OSError, EOFError, zlib.error):
                return
            if not line:
                return
            if line.endswith(b"\n"):
                yield line[:-1]
                continue
            if len(line) <= cap:
                return  # the partial last line
            while line and not line.endswith(b"\n"):  # too long: skip to its end
                try:
                    line = src.readline(1 << 16)
                except (OSError, EOFError, zlib.error):
                    return
            yield None
    finally:
        f.close()


def _untrusted(line):
    return None if line is None else oomph.loads_untrusted(line)


def _day(t):
    return time.strftime("%Y-%m-%d", time.localtime(t))


def _day_before(day):
    return time.strftime("%Y-%m-%d", time.localtime(time.mktime(time.strptime(day, "%Y-%m-%d")) - 43200))


def _day_after(day):
    return time.strftime("%Y-%m-%d", time.localtime(time.mktime(time.strptime(day, "%Y-%m-%d")) + 129600))


class Server:
    """One session's answers, from a log directory and a ledger directory. handle() takes a
    request and returns its response (None for a notification); poll() returns the notifications
    a subscription has due. It keeps no file open between calls."""

    def __init__(self, log_dir=None, ledger_dir=None, now=None):
        self.log_dir = log_dir or oomph.LOG_DIR
        self.ledger_dir = ledger_dir or oomph.LEDGER_DIR
        self.fixed_now = now
        self.open = False
        self.subscribed = set()
        self.tail = {}

    def now(self):
        return self.fixed_now if self.fixed_now is not None else time.time()

    def path(self, name):
        return os.path.join(self.log_dir, name)

    # -- requests
    def handle(self, req):
        if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or not isinstance(req.get("method"), str):
            return _error(None, ERR["invalid"], "invalid request")
        rid = req.get("id")
        if not (rid is None or isinstance(rid, (int, str)) and not isinstance(rid, bool)):
            return _error(None, ERR["invalid"], "invalid id")
        params = req.get("params", {})
        if not isinstance(params, dict):
            return _error(rid, ERR["params"], "params must be an object")
        fn = getattr(self, "rpc_" + req["method"], None) if re.fullmatch(r"[a-z_]{1,32}", req["method"]) else None
        try:
            if fn is None:
                raise RPCError(ERR["method"], "method not found")
            if not self.open and req["method"] != "hello":
                raise RPCError(ERR["unauth"], "say hello first")
            result = fn(params)
        except RPCError as e:
            return _error(rid, e.code, e.message, e.data)
        except (OSError, ValueError, TypeError, KeyError, RecursionError, MemoryError) as e:
            return _error(rid, -32603, "internal error: %s" % type(e).__name__)
        if rid is None:
            return None
        return {"jsonrpc": "2.0", "id": rid, "result": result}

    def rpc_hello(self, p):
        pr = p.get("proto")
        if not (isinstance(pr, list) and len(pr) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in pr)):
            raise RPCError(ERR["params"], "proto: [min, max]")
        v = min(pr[1], PROTO[1])
        if v < max(pr[0], PROTO[0]):
            raise RPCError(ERR["proto"], "protocol not supported", {"min": PROTO[0], "max": PROTO[1]})
        self.open = True
        return {"proto": v, "nonce": base64.b64encode(os.urandom(16)).decode(), "auth": ["transport"],
                "machine": self.machine()}

    def rpc_ping(self, p):
        return {"now": self.now(), "last": self.newest()[0]}

    def rpc_samples(self, p):
        after, to, cap = _cursor(p.get("after", [0, 0])), _time(p.get("to")), _max_bytes(p.get("max_bytes"))
        if after is None or to is None:
            raise RPCError(ERR["params"], "samples: after [t, k], to t")
        oldest = self.oldest()
        if oldest is not None and to < oldest - 1:
            raise RPCError(ERR["retention"], "older than retention", {"oldest": oldest})
        files = self.day_files()
        first = _day_before(_day(after[0])) if after[0] > 0 else ""
        last = _day_after(_day(to))
        files = [(d, f) for d, f in files if first <= d <= last]

        def rows():
            for d, path in files:
                for line in file_lines(path, ITEM["sample_raw"]):
                    if line is None:
                        yield None, d, None  # too long to look at: not a row anyone can name
                        continue
                    s = _untrusted(line)
                    if not isinstance(s, dict) or not oomph._t(s.get("t")):
                        continue
                    b = dumps(oomph.slim_sample(s))
                    yield s["t"], d, (b if len(b) <= ITEM["sample"] else None)
        page = _page(rows, after, to, cap, day_counted=True)
        vouch = self.vouch()
        page["to"] = page.pop("last_t") if page["more"] else min(to, vouch)
        return page

    def rpc_events(self, p):
        after, cap = _cursor(p.get("after", [0, 0])), _max_bytes(p.get("max_bytes"))
        if after is None:
            raise RPCError(ERR["params"], "events: after [t, k]")

        def rows():
            for name in ("events.jsonl.1", "events.jsonl"):
                for line in file_lines(self.path(name), ITEM["record"]):
                    e = _untrusted(line)
                    if line is None:
                        yield None, None, None
                    elif isinstance(e, dict) and oomph._t(e.get("t")):
                        b = dumps(scrub(e))
                        yield e["t"], None, (b if len(b) <= ITEM["record"] else None)
        page = _page(rows, after, None, cap)
        page["to"] = page.pop("last_t")
        return page

    def rpc_reservations(self, p):
        after, cap = _cursor(p.get("after", [0, 0])), _max_bytes(p.get("max_bytes"))
        if after is None:
            raise RPCError(ERR["params"], "reservations: after [t, k]")
        data = self.ledger_file(oomph.HISTORY_FILE, oomph.LIMITS["history"], tail=True)

        def rows():
            for line in (data or b"").split(b"\n"):
                if len(line) > ITEM["record"]:
                    yield None, None, None
                    continue
                rec = oomph._valid_finished(oomph.loads_untrusted(line), log=True) if line else None
                if rec:
                    t = rec.get("t") if oomph._t(rec.get("t")) else oomph._rec_time(rec)
                    b = dumps(record_out(rec))
                    yield t, None, (b if len(b) <= ITEM["record"] else None)
        page = _page(rows, after, None, cap)
        page["to"] = page.pop("last_t")
        return page

    def rpc_ledger(self, p):
        L = oomph._valid_ledger(oomph.loads_untrusted(self.ledger_file("ledger.json", oomph.LIMITS["ledger"])))
        snap = {"leases": [], "state": {}, "history": []}
        if L is not None:
            snap = {"leases": [lease_out(r) for r in L["leases"]][:oomph.LIMITS["leases_n"] * 4],
                    "state": {k: v for k, v in L["state"].items() if isinstance(k, str)},
                    "history": [finished_out(h) for h in L["history"]]}
        truncated = 0
        while True:
            data = pack([dumps(snap)])
            if len(data) * 3 // 4 <= SNAPSHOT or not snap["history"]:
                break
            cut = max(1, len(snap["history"]) // 4)
            snap["history"], truncated = snap["history"][cut:], truncated + cut
        if len(data) * 3 // 4 > SNAPSHOT:
            raise RPCError(ERR["large"], "the ledger is too large to send")
        return {"enc": "zlib+b64", "data": data, "to": self.now(), "truncated": truncated}

    def rpc_incidents(self, p):
        after, cap = p.get("after", ""), _max_bytes(p.get("max_bytes"))
        if not (after == "" or isinstance(after, str) and INCIDENT_ID.fullmatch(after)):
            raise RPCError(ERR["params"], "incidents: after is an incident id")
        ids = self.incident_ids()
        lines, skipped, nxt, more, size = [], 0, after, False, 0
        for iid in [i for i in ids if i > after]:
            inc = self.incident(iid)
            b = dumps(incident_out(inc)) if isinstance(inc, dict) else None
            if b is None or len(b) > ITEM["incident"]:
                skipped += 1
                nxt = iid
                continue
            if lines and size + len(b) > cap * 4:
                more = True
                break
            lines.append(b)
            size += len(b) + 1
            nxt = iid
        open_now = [i for i in ids[-30:] if (self.incident(i) or {}).get("open") is True]
        return {"enc": "zlib+b64", "data": pack(lines), "n": len(lines), "next": nxt, "more": more,
                "skipped": skipped, "open": open_now}

    def rpc_subscribe(self, p):
        streams = p.get("streams", list(STREAMS))
        if not (isinstance(streams, list) and all(s in STREAMS for s in streams)):
            raise RPCError(ERR["params"], "streams: any of %s" % ", ".join(STREAMS))
        self.subscribed = set(streams)
        self.tail = self.marks()
        cur, skipped = self.current()
        return {"current": cur, "current_skipped": skipped, "last": [self.newest()[0], 1]}

    # -- the machine
    def current(self):
        """(the full current sample or None, whether it was skipped as too large)"""
        f = _open_regular(self.path("current.json"))
        if f is None:
            return None, False
        with f:
            data = f.read(ITEM["current"] + 1)
        if len(data) > ITEM["current"]:
            return None, True
        s = oomph.loads_untrusted(data)
        return (oomph.full_sample(s), False) if isinstance(s, dict) and oomph._t(s.get("t")) else (None, False)

    def machine(self):
        """What this machine says about itself (roadmap 01 §5.3): from the logger's machine block
        in current.json, this code's version, the clock and the history it keeps."""
        cur, _ = self.current()
        d = (cur or {}).get("daemon") or {}
        m = dict(d.get("machine") or {})
        m.pop("virt", None)
        host = clean(socket.gethostname(), 64)
        out = {"id": m.get("id"), "name": m.get("name") or host.split(".")[0] or None, "host": host,
               "os": m.get("os") or ("macos" if sys.platform == "darwin" else "linux")}
        for k in ("os_version", "arch", "kind", "kernel", "cpus", "measures"):
            if k in m:
                out[k] = m[k]
        off = time.localtime(self.now()).tm_gmtoff
        out.update(ram_gb=(cur or {}).get("ram_gb"), version=oomph.VERSION, logger=d.get("version"),
                   interval=d.get("interval") if oomph._num(d.get("interval"), 1, 3600) else 30,
                   tz="%s%02d:%02d" % ("-" if off < 0 else "+", abs(off) // 3600, abs(off) % 3600 // 60),
                   retention_days=RETENTION_DAYS, oldest=self.oldest(), now=self.now(), caps=list(CAPS))
        return out

    def day_files(self):
        """(day, path) of every samples file, oldest first; a day's plain file wins over its .gz,
        which the logger is still writing until the plain one is gone."""
        try:
            names = os.listdir(self.log_dir)
        except OSError:
            return []
        days = {}
        for n in names:
            m = DAY_FILE.fullmatch(n)
            if m and (m.group(1) not in days or not m.group(2)):
                days[m.group(1)] = os.path.join(self.log_dir, n)
        return sorted(days.items())

    def oldest(self):
        for _, path in self.day_files():
            for line in file_lines(path, ITEM["sample_raw"]):
                s = _untrusted(line)
                if isinstance(s, dict) and oomph._t(s.get("t")):
                    return s["t"]
        return None

    def newest(self):
        """(t, interval) of the newest sample on disk, (None, 30) when there is none."""
        files = self.day_files()
        cur, _ = self.current()
        iv = ((cur or {}).get("daemon") or {}).get("interval")
        iv = iv if oomph._num(iv, 1, 3600) else 30
        for _, path in reversed(files[-2:]):
            t = None
            if path.endswith(".gz"):
                for line in file_lines(path, ITEM["sample_raw"]):
                    s = _untrusted(line)
                    if isinstance(s, dict) and oomph._t(s.get("t")):
                        t = s["t"] if t is None else max(t, s["t"])
            else:
                for line in _last_lines(path, 4 * ITEM["sample_raw"]):
                    s = _untrusted(line)
                    if isinstance(s, dict) and oomph._t(s.get("t")):
                        t = s["t"] if t is None else max(t, s["t"])
            if t is not None:
                return t, iv
        return None, iv

    def vouch(self):
        """How far the log can vouch (roadmap 01 §5.4): the newest sample on disk, and only once the
        logger has been silent for 3 intervals and 15 s, now minus that."""
        t, iv = self.newest()
        quiet = 3 * iv + 15
        now = self.now()
        if t is None or now - t > quiet:
            return now - quiet
        return t

    def ledger_file(self, name, cap, tail=False):
        """A file of the shared ledger directory, read the careful way (oomph.read_bounded)."""
        try:
            dfd = os.open(self.ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            return oomph.read_bounded(name, cap, dfd, tail=tail)
        finally:
            os.close(dfd)

    def incident_ids(self):
        try:
            return sorted(i for i in os.listdir(self.path("incidents")) if INCIDENT_ID.fullmatch(i))
        except OSError:
            return []

    def incident(self, iid):
        f = _open_regular(os.path.join(self.log_dir, "incidents", iid, "incident.json"))
        if f is None:
            return None
        with f:
            data = f.read(ITEM["incident"] + 1)
        return oomph.loads_untrusted(data) if len(data) <= ITEM["incident"] else None

    # -- the live stream
    def marks(self):
        """What the subscription compares against: the newest day file's identity, length and the
        time of its last complete line; the other files' identity and length."""
        out = {}
        files = self.day_files()
        if files and not files[-1][1].endswith(".gz"):
            path = files[-1][1]
            f = _open_regular(path)
            try:
                if f is None:
                    raise OSError("not a regular file")
                with f:
                    st = os.fstat(f.fileno())
                    size = st.st_size
                    f.seek(max(0, size - 4 * ITEM["sample_raw"]))
                    chunk = f.read(4 * ITEM["sample_raw"])
                end = chunk.rfind(b"\n") + 1
                last = None
                for line in chunk[:end].split(b"\n"):
                    s = _untrusted(line) if line else None
                    if isinstance(s, dict) and oomph._t(s.get("t")):
                        last = s["t"]
                out["samples"] = (path, st.st_ino, size - (len(chunk) - end), last)
            except OSError:
                pass
        for name in ("events.jsonl", "incidents"):
            out[name] = _stamp(self.path(name))
        out["ledger"] = (_stamp(os.path.join(self.ledger_dir, "ledger.json")),
                         _stamp(os.path.join(self.ledger_dir, oomph.HISTORY_FILE)))
        return out

    def poll(self):
        """The notifications a subscription has due now (roadmap 01 §5.4): complete lines
        appended to the day file (`tick`, with `prev` read from the file), lines appended to
        events.jsonl, a changed ledger, an incident that opened or changed."""
        out = []
        if not self.subscribed:
            return out
        old, new = self.tail, self.marks()
        if "samples" in self.subscribed and new.get("samples"):
            o, n = old.get("samples"), new["samples"]
            start, prev = 0, None
            if o and o[0] == n[0] and o[1] == n[1]:
                start, prev = o[2], o[3]
            elif o:  # a new day file: the previous file's last line comes before it
                prev = o[3]
            if start < n[2]:
                rows, chunk = [], b""
                f = _open_regular(n[0])
                if f is not None:
                    with f:
                        f.seek(start)
                        chunk = f.read(min(n[2] - start, 8 * ITEM["sample_raw"]))
                for line in chunk.split(b"\n"):
                    s = _untrusted(line) if line and len(line) <= ITEM["sample_raw"] else None
                    if isinstance(s, dict) and oomph._t(s.get("t")):
                        b = dumps(oomph.slim_sample(s))
                        if len(b) <= ITEM["sample"]:
                            rows.append(json.loads(b))
                cur, _ = self.current()
                if rows:
                    out.append(_note("tick", {"samples": rows, "prev": prev, "current": cur}))
        if "events" in self.subscribed and new["events.jsonl"] != old.get("events.jsonl"):
            o = old.get("events.jsonl")
            if o and n_same(o, new["events.jsonl"]):
                rows, size = [], 0
                f = _open_regular(self.path("events.jsonl"))
                if f is not None:
                    with f:
                        f.seek(o[2])
                        chunk = f.read(min(new["events.jsonl"][2] - o[2], PAGE))
                    for line in chunk[:chunk.rfind(b"\n") + 1].split(b"\n"):
                        e = _untrusted(line) if line and len(line) <= ITEM["record"] else None
                        if isinstance(e, dict) and oomph._t(e.get("t")):
                            rows.append(scrub(e))
                if rows:
                    out.append(_note("events", {"events": rows}))
        if "ledger" in self.subscribed and new["ledger"] != old.get("ledger"):
            snap = json.loads(unpack(self.rpc_ledger({})["data"])[0])
            out.append(_note("ledger", {"leases": snap["leases"], "state": snap["state"]}))
        if "incidents" in self.subscribed and new["incidents"] != old.get("incidents"):
            ids = self.incident_ids()
            if ids:
                inc = self.incident(ids[-1])
                if isinstance(inc, dict):
                    out.append(_note("incident", {"incident": incident_out(inc)}))
        self.tail = new
        return out


def n_same(a, b):
    """Two stamps of one file that only grew."""
    return a[0] == b[0] and b[2] >= a[2]


def _stamp(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_ino, st.st_mtime, st.st_size)


def _last_lines(path, cap):
    f = _open_regular(path)
    if f is None:
        return []
    with f:
        size = os.fstat(f.fileno()).st_size
        f.seek(max(0, size - cap))
        chunk = f.read(cap)
    end = chunk.rfind(b"\n")
    if end < 0:
        return []
    lines = chunk[:end].split(b"\n")
    return lines[1:] if size > cap else lines


def _note(method, params):
    return {"jsonrpc": "2.0", "method": method, "params": params}


def _error(rid, code, message, data=None):
    e = {"code": code, "message": message}
    if data is not None:
        e["data"] = data
    return {"jsonrpc": "2.0", "id": rid, "error": e}


def _cursor(x):
    """A cursor as the server accepts it (roadmap 01 §5.5): a finite time and a small count."""
    if (isinstance(x, list) and len(x) == 2 and oomph._num(x[0], 0, 1e11) and isinstance(x[1], int)
            and not isinstance(x[1], bool) and 0 <= x[1] < 2 ** 31):
        return float(x[0]), x[1]
    return None


def _time(x):
    return float(x) if oomph._num(x, 0, 1e11) else None


def _max_bytes(x):
    return min(max(x, 4096), PAGE) if isinstance(x, int) and not isinstance(x, bool) else PAGE


def _page(make_rows, after, to, max_bytes, day_counted=False):
    """One page of rows after the cursor `after` = (t, k): the rows that follow the k-th row of time
    t in file order, whatever their times (k = 0: from the first row whose time is t or later).
    When that row no longer exists the page starts at the first row later than t and says
    `anchored: false`. `make_rows()` yields (t, day, payload) in file order; a payload of None is
    an item too big to send, skipped and counted with the cursor past it (t None: not even its
    time could be read). With `day_counted`, rows count towards k only within their own day file
    and the one before, so a cursor names the same row whichever file a scan starts at. Rows
    later than `to` are left out. At most `max_bytes` compressed."""
    t0, k = after

    def counted(it):
        seen = {}
        for t, day, p in it:
            if t is None:
                yield t, 0, p
                continue
            if day_counted and day < _day_before(_day(t)):
                yield t, 0, p
                continue
            n = seen[t] = seen.get(t, 0) + 1
            yield t, n, p

    anchored = True
    it = counted(make_rows())
    if k:
        for t, n, _ in it:
            if t == t0 and n == k:
                break
        else:
            anchored, it = False, counted(make_rows())
    started = bool(k) and anchored or not k and t0 <= 0
    taken, raw = [], 0
    more = False
    for t, n, p in it:
        if not started:
            if t is None or (t < t0 if not k else t <= t0):
                continue
            started = True
        if t is not None and to is not None and t > to:
            continue
        if p is not None and taken and raw + len(p) > 4 * max_bytes:
            more = True
            break
        taken.append((t, n, p))
        raw += len(p) + 1 if p is not None else 0
    while True:
        lines = [p for _, _, p in taken if p is not None]
        data = pack(lines)
        if len(data) * 3 // 4 <= max_bytes or len(lines) <= 1:
            break
        keep = max(1, len(lines) // 2)  # rows to keep: cut after the keep-th one that is sent
        idx = [i for i, (_, _, p) in enumerate(taken) if p is not None][keep - 1]
        taken, more = taken[:idx + 1], True
    last = next(((t, n) for t, n, _ in reversed(taken) if t is not None), None)
    return {"enc": "zlib+b64", "data": data, "n": len(lines), "next": [last[0], last[1]] if last else [t0, k],
            "more": more, "skipped": sum(1 for _, _, p in taken if p is None), "anchored": anchored,
            "last_t": last[0] if last else None}


# ------------------------------------------------------------------ oomph serve --stdio
def drop_root():
    """As root, become the user who ran sudo (else nobody) for the rest of this process: a server
    needs no privilege, and no process running as root opens anything in the shared ledger
    directory."""
    if os.geteuid() != 0:
        return
    import grp
    import pwd
    user, group = oomph._child_user()
    uid = user if isinstance(user, int) else pwd.getpwnam(user).pw_uid
    try:
        gid = group if isinstance(group, int) else grp.getgrnam(group).gr_gid
    except KeyError:  # no group of that name (Debian calls it nogroup): the user's own
        gid = pwd.getpwuid(uid).pw_gid
    os.setgroups([])
    os.setgid(gid)
    os.setuid(uid)
    if os.geteuid() == 0 or os.getuid() == 0:
        raise SystemExit("oomph: serve: could not give up root")


def _rss():
    """Bytes resident: now where /proc says (Linux), else at the most (ru_maxrss). Measured
    against the value at the start, as a high-water mark may be the parent's: Linux keeps it
    across exec, so a server started by a large process would otherwise start out past the cap."""
    try:
        with open("/proc/self/statm", "rb") as f:
            return int(f.read(200).split()[1]) * os.sysconf("SC_PAGE_SIZE")
    except (OSError, ValueError, IndexError):
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * (1 if sys.platform == "darwin" else 1024)


def serve(in_fd, out_fd, server, idle=IDLE_S):
    """The session loop: frames in, answers out, notifications while subscribed (the files are
    looked at once a second). Ends at the end of input, on a line over the limit, after `idle`
    seconds without a frame, or when the process grew by more than RSS_CAP."""
    lines = Lines(in_fd, LINE_PRE)
    base = _rss()
    quiet_since = time.monotonic()

    def send(msg):
        b = dumps(msg)
        if len(b) > LINE_OUT:
            b = dumps(_error(msg.get("id"), ERR["large"], "the answer is too large"))
        write_all(out_fd, b + b"\n")

    while True:
        try:
            line = lines.read(1.0 if server.subscribed else max(0.1, idle - (time.monotonic() - quiet_since)))
        except Closed as e:
            if "longer" in str(e):
                send(_note("bye", {"reason": "too_large"}))
            return 0
        if line is None:
            try:
                notes = server.poll()
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as e:
                notes = []
                sys.stderr.write("oomph serve: %s while watching the files\n" % type(e).__name__)
            for note in notes:
                send(note)
            if time.monotonic() - quiet_since > idle:
                send(_note("bye", {"reason": "idle"}))
                return 0
            continue
        quiet_since = time.monotonic()
        if not line.strip():
            continue
        try:
            req = json.loads(line, parse_constant=oomph._no_constant)
        except (ValueError, RecursionError):
            send(_error(None, ERR["parse"], "parse error"))
            continue
        res = server.handle(req)
        if server.open:
            lines.cap = LINE_IN
        if res is not None:
            send(res)
        if _rss() - base > RSS_CAP:
            send(_note("bye", {"reason": "busy"}))
            return 0


SERVE_USAGE = "usage: oomph serve --stdio [--now T]   (the protocol on stdin and stdout)"


def cmd_serve(args):
    now = None
    if args[:1] != ["--stdio"] or len(args) not in (1, 3) or len(args) == 3 and args[1] != "--now":
        sys.stderr.write(SERVE_USAGE + "\n")
        return 2
    if len(args) == 3:
        try:
            now = float(args[2])
        except ValueError:
            pass
        if now is None or not math.isfinite(now) or not 0 < now < 1e11:
            sys.stderr.write("oomph: serve: --now takes a unix time\n")
            return 2
    drop_root()
    # The protocol owns the descriptors it was given; whatever else prints (a warning, a
    # traceback) goes to stderr and can never land inside a frame.
    in_fd, out_fd = os.dup(0), os.dup(1)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(2, 1)
    os.close(devnull)
    try:
        return serve(in_fd, out_fd, Server(now=now))
    except (BrokenPipeError, ConnectionResetError):
        return 0
