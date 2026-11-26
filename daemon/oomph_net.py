"""oomph's wire protocol and its serving side (roadmap 01 §4.2, §5, §7).

    oomph serve --stdio [--now T]          the protocol on stdin and stdout (what ssh runs)
    oomph serve --inetd [--now T]          one TLS connection on fd 0, as launchd hands it over
    oomph serve --listen HOST:PORT [--now T]   accept, start one --inetd per connection (tests;
                                           loopback unless sharing is on)
    oomph share on|off|pair|status|revoke|networks|allow|ai|reload|purge

answers for this machine, read only, from its two directories: the log directory (LOG_DIR, written
by the root logger) and the shared ledger directory (LEDGER_DIR, writable by everyone). Over a pipe
the transport is the authentication, so `hello` opens the session. Over TCP the connection first
passes the peer gate (nothing a refused peer sends is read), then TLS with the machine's
self-signed key, then `pair` (a one-time code shown here, proved without sending it) or `auth`
(the proof of a token issued at pairing). `--now` fixes the clock the server reports (tests).

The protocol: JSON-RPC 2.0, one compact JSON object per line, line lengths capped in both
directions. Everything that can grow travels zlib-compressed and base64-encoded inside a result,
in pages with a positional cursor [t, k] (the k-th row of time t, in file order), so no reply is
unbounded and every reply either moves the cursor or says `more: false`. Nothing either directory
holds is passed on whole: samples are slimmed (oomph.slim_sample), the current sample is rebuilt
from named fields (oomph.full_sample), ledger and history records from theirs, strings cut and
lists capped. One item too big for a page is skipped, counted and stepped over.

Sharing (macOS only: Linux machines are watched over SSH) is a second, optional LaunchDaemon,
local.oomph.share, that runs `serve --inetd` per connection as the role account _oomph, which has
a group of its own. Its state is split by owner: /Library/Application Support/oomph/share holds
root's config.json, cert.pem and key.pem (root:_oomph 640); run/ below it is the service's
(pairings, the active code, the summary). Two rules hold for every privileged step: root never
opens a path inside run/ (the `share` commands fork, become _oomph, and only then touch it), and
root never interprets a string the service or a viewer wrote, except an id matching ^c-[0-9a-f]{8}$.

A server run as root first becomes the user who ran sudo, else nobody, for good: no process running
as root opens anything in the shared ledger directory (H0), and a server needs no privilege at all.
Standard library only; Python 3.9.
"""
import base64
import contextlib
import fcntl
import gzip
import hashlib
import hmac
import ipaddress
import json
import math
import os
import pwd
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import time
import zlib

try:
    import ssl
except ImportError:  # a Python built without it: --stdio still works
    ssl = None

import oomph

PROTO = (1, 1)                       # the protocol versions this code speaks
CAPS = ("samples", "events", "incidents", "ledger")   # what this server offers (`full`, `files`, `broker`: later)
AI_CAP = "ai"                        # in caps only when this machine allows AI analysis of its data (D7; off by default)
PORT = 6674                          # O-M-P-H on a phone's keypad
ROLE = "_oomph"                      # the share service's account and its group of its own (macOS)
LABEL = "local.oomph.share"
SHARE_PLIST = "/Library/LaunchDaemons/%s.plist" % LABEL
HANDSHAKE_S = 10                     # gate, TLS, hello and pair or auth: all within this
WARM_S = 90                          # share on waits this long at most for the service's first start
PAIR_S = 600                         # a pairing code lives this long ...
PAIR_TRIES = 5                       # ... and survives this many wrong proofs
PAUSE_S = 1.0                        # every failed pair or auth waits this long before it answers
PBKDF2_ROUNDS = 200000
MAX_HANDSHAKES = 4                   # connections still before authentication, at once ...
MAX_PER_ADDR = 3                     # ... from one address ...
MAX_VIEWERS = 8                      # ... and authenticated viewers
ALLOW_MIN = {4: 8, 6: 32}            # `share allow`: the widest range, by IP version (1.14.1)
ALLOW_V4_IN_V6 = (("2001::/32", "Teredo"), ("2002::/16", "6to4"), ("64:ff9b::/96", "NAT64"),
                  ("64:ff9b:1::/48", "NAT64"), ("::ffff:0:0/96", "IPv4-mapped"))  # IPv6 ranges that stand for IPv4 hosts
WRITE_S = 30                         # a peer that does not read for this long is dropped
CIPHERS = "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256"
CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"   # Crockford's base32: 12 of them are 60 bits
CLIENT_ID = re.compile(r"c-[0-9a-f]{8}")
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
CPU_S = (120, 6 * 3600)              # a TCP connection's CPU seconds: until authenticated, and in all
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


class FdStream:
    """A pipe or a terminal's descriptor, as Lines reads it and serve() writes it."""

    def __init__(self, fd):
        self.fd = fd

    def fileno(self):
        return self.fd

    def recv(self, timeout):
        """Bytes; b"" at the end of the stream; None when nothing came within `timeout` (None:
        wait for ever)."""
        if not select.select([self.fd], [], [], timeout)[0]:
            return None
        return os.read(self.fd, 1 << 16)

    def send(self, data):
        write_all(self.fd, data)

    def pending(self):
        return False


class SockStream:
    """A socket, plain or TLS. A TLS socket can hold decrypted bytes that select() does not see
    (pending()), and a record that has begun may take a moment to arrive whole: recv() then says
    None and the caller looks again. A peer that does not take what is sent within WRITE_S is
    dropped (Closed)."""

    def __init__(self, sock):
        self.sock = sock

    def fileno(self):
        return self.sock.fileno()

    def pending(self):
        p = getattr(self.sock, "pending", None)
        try:
            return bool(p and p())
        except (OSError, ValueError):
            return False

    def recv(self, timeout):
        if not self.pending():
            if not select.select([self.sock], [], [], timeout)[0]:
                return None
        self.sock.settimeout(1.0)
        try:
            return self.sock.recv(1 << 16)
        except socket.timeout:
            return None
        except OSError as e:  # the TLS layer's want-read is an OSError too
            if ssl is not None and isinstance(e, ssl.SSLWantReadError):
                return None
            return b""

    def send(self, data):
        self.sock.settimeout(WRITE_S)
        try:
            self.sock.sendall(data)
        except socket.timeout:
            raise Closed("the other end does not read")


def _stream(x):
    return x if hasattr(x, "recv") else FdStream(x)


class Lines:
    """Lines from a stream (a descriptor, or a SockStream), each at most `cap` bytes, read without
    blocking past a deadline. read() returns a line without its newline, None when `timeout`
    passed first, and raises Closed at the end of the stream or for a line longer than `cap`."""

    def __init__(self, src, cap):
        self.src, self.cap, self.buf, self.eof = _stream(src), cap, b"", False

    @property
    def fd(self):
        return self.src.fileno()

    def buffered(self):
        """Whether a whole line is already waiting (select() on the descriptor would not say)."""
        return b"\n" in self.buf

    def read(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        tried = False  # a timeout of 0 still reads what is there once
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
            if left is not None and left <= 0 and tried and not self.src.pending():
                return None
            tried = True
            b = self.src.recv(None if left is None else max(0.0, left))
            if b is None:
                continue
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


# `user`: the account that asked, which a Linux tab shows once several accounts hold reservations (03 §3.9; 1.13.3)
LEASE_FIELDS = ("key", "id", "state", "gb", "purpose", "project", "ttl", "requested", "seen", "granted", "expires",
                "used_gb", "peak_gb", "baseline_gb", "note", "user")
FINISHED_FIELDS = ("key", "id", "purpose", "project", "gb", "holder", "peak_gb", "outcome", "requested", "granted",
                   "ended", "waited_s", "held_s", "user")
RECORD_FIELDS = ("event", "t", "key", "id", "purpose", "project", "holder", "gb", "requested", "granted", "ended",
                 "outcome", "peak_gb", "used_gb", "expires", "change", "backfilled", "waited_s", "held_s", "user")
INCIDENT_FIELDS = ("id", "start", "start_iso", "last_trigger", "open", "end", "end_iso", "opened_by", "continues",
                   "quiet", "repeats", "more")


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
    t, a quiet incident's cgroups (Linux, 03 §5.6: `quiet` keeps it out of every viewer's news), the
    summary scrubbed."""
    out = oomph._fields(inc, INCIDENT_FIELDS, 200)
    if isinstance(inc.get("cgroups"), list):
        out["cgroups"] = [oomph._fields(c, ("name", "ooms", "first", "last"), 200) for c in inc["cgroups"][:20]
                          if isinstance(c, dict)]
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

    def __init__(self, log_dir=None, ledger_dir=None, now=None, session=None, ai=None, ai_watch=None):
        self.log_dir = log_dir or oomph.LOG_DIR
        self.ledger_dir = ledger_dir or oomph.LEDGER_DIR
        self.fixed_now = now
        self.open = False
        self.subscribed = set()
        self.tail = {}
        self.session = session          # a Session over TLS (pair or auth needed); None over a pipe
        self.ai = ai_allowed() if ai is None else ai
        self.ai_watch = ai_watch        # over a pipe (SSH): an AiWatch, so `share ai off` reaches the session
        self.cn = self.sn = None        # the nonces of this connection's hello (TLS)

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
            if fn is None or req["method"] in ("pair", "auth", "unpair") and self.session is None:
                raise RPCError(ERR["method"], "method not found")
            if not self.open and req["method"] not in ("hello", "pair", "auth"):
                raise RPCError(ERR["unauth"], "say hello first" if self.session is None else "not authenticated")
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
        if self.session is None:
            self.open = True
            return {"proto": v, "nonce": base64.b64encode(os.urandom(16)).decode(), "auth": ["transport"],
                    "machine": self.machine()}
        # Over TLS nothing about the machine before authentication, and the same answer whether
        # or not a code is active (roadmap 01 §5.3).
        cn = _b64(p.get("nonce"), 16)
        if cn is None:
            raise RPCError(ERR["params"], "nonce: 16 bytes, base64")
        self.open, self.cn, self.sn = False, cn, os.urandom(16)
        return {"proto": v, "nonce": base64.b64encode(self.sn).decode(), "auth": ["token", "pair"]}

    def rpc_pair(self, p):
        """First contact: the client proves it knows the code shown here, bound to the certificate
        it saw; a server that knows the code too and holds that certificate proves it back. One
        failure for everything (-32011, after the same pause)."""
        cn, self.cn = self.cn, None  # one proof per hello, right or wrong
        if cn is None:
            raise RPCError(ERR["unauth"], "say hello first")
        # a full house is told only to a proof that holds (Session.pair), and costs it no try
        r = self.session.pair(_b64(p.get("mac"), 32), cn, self.sn, viewer_name(p.get("name")))
        if r == "busy":
            raise RPCError(ERR["busy"], "too many viewers")
        if r is None:
            raise RPCError(ERR["pair"], "pairing failed")
        kp, client, token = r
        mac = proof(kp, b"server", cn, self.sn, self.session.fp)
        self.open = True
        return {"mac": base64.b64encode(mac).decode(), "client": client, "token": base64.b64encode(token).decode(),
                "machine": self.machine()}

    def rpc_auth(self, p):
        """Every later connection: the client proves it holds the token issued at pairing,
        without sending it. Unknown client and wrong proof are one answer (-32010)."""
        cn, self.cn = self.cn, None  # one proof per hello, right or wrong
        if cn is None:
            raise RPCError(ERR["unauth"], "say hello first")
        cid = p.get("client")
        cid = cid if isinstance(cid, str) and CLIENT_ID.fullmatch(cid) else None
        ok = self.session.auth(cid, _b64(p.get("mac"), 32), cn, self.sn)
        if ok == "busy":
            raise RPCError(ERR["busy"], "too many viewers")
        if ok is not True:
            raise RPCError(ERR["auth"], "authentication failed")
        self.open = True
        return {"machine": self.machine()}

    def rpc_unpair(self, p):
        """The one method that changes anything here, and only the caller's own pairing."""
        self.session.unpair()
        self.open = False
        return {}

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
        open_now = [i for i in ids[-30:] if (self.incident(i) or {}).get("open") is True]  # quiet ones too: a mirror
        # fetches an open incident again until it closes, and a quiet one grows (viewers leave it out by its flag)
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
        out["logs"] = self.logs(cur)
        out.update(ram_gb=(cur or {}).get("ram_gb"), version=oomph.VERSION, logger=d.get("version"),
                   interval=d.get("interval") if oomph._num(d.get("interval"), 1, 3600) else 30,
                   tz="%s%02d:%02d" % ("-" if off < 0 else "+", abs(off) // 3600, abs(off) % 3600 // 60),
                   retention_days=RETENTION_DAYS, oldest=self.oldest(), now=self.now(),
                   caps=self.caps())
        return out

    def logs(self, cur):
        """Whether this machine's logs can be served (roadmap §4.3, from 03): `ok` (a logger's current
        sample), `denied` (its folder is there, but this account may not read it), `absent` (no logger has
        written here: a Linux machine with oomph for agents only)."""
        if cur is not None:
            return "ok"
        try:
            os.listdir(self.log_dir)
        except PermissionError:
            return "denied"
        except OSError:
            return "absent"
        return "denied" if os.path.exists(self.path("current.json")) and not os.access(self.path("current.json"), os.R_OK) \
            else "absent"

    def caps(self):
        return list(CAPS) + ([AI_CAP] if self.ai else [])

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
        """A file of the shared ledger directory, read the careful way (oomph.read_bounded, shared)."""
        try:
            dfd = os.open(self.ledger_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError:
            return None
        try:
            return oomph.read_bounded(name, cap, dfd, tail=tail, shared=True)
        finally:
            os.close(dfd)

    def incident_ids(self):
        try:
            return sorted(i for i in os.listdir(self.path("incidents")) if INCIDENT_ID.fullmatch(i))
        except OSError:
            return []

    def incident(self, iid):
        d = os.path.join(self.log_dir, "incidents", iid)
        try:  # a real folder only: the logger's account could have put a link there (03 §12.3)
            if not stat.S_ISDIR(os.lstat(d).st_mode):
                return None
        except OSError:
            return None
        f = _open_regular(os.path.join(d, "incident.json"))
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
    try:
        uid, gid = oomph._ids(*oomph._child_user())  # nobody's group may be named nogroup (Debian)
    except oomph.LedgerError as e:
        raise SystemExit("oomph: serve: could not give up root: %s" % e)
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


def serve(inp, out, server, idle=IDLE_S, pre_auth=None):
    """The session loop: frames in, answers out, notifications while subscribed (the files are
    looked at once a second). Ends at the end of input, on a line over the limit, after `idle`
    seconds without a frame, when the process grew by more than RSS_CAP or nears its CPU limit,
    when it is still not authenticated after `pre_auth` seconds, when its pairing was revoked, or
    when sharing was turned off (both looked at once a second, read when clients.json or
    config.json changed; a change of `ai` is told as a `machine` notification, over SSH too). `inp`
    and `out` are descriptors or streams."""
    lines = Lines(inp, LINE_PRE)
    out = _stream(out)
    base = _rss()
    quiet_since = started = time.monotonic()
    looked = started  # when revocation and the files were last looked at: once a second, busy or not

    def send(msg):
        b = dumps(msg)
        if len(b) > LINE_OUT:
            b = dumps(_error(msg.get("id"), ERR["large"], "the answer is too large"))
        out.send(b + b"\n")

    while True:
        now = time.monotonic()
        if pre_auth is not None and not server.open and now - started > pre_auth:
            return 0
        if now - looked >= 1.0:
            # On a timer, not only after a quiet second: a viewer that sends a frame more often
            # than once a second must still meet its revocation, and its subscription its ticks.
            looked = now
            if server.session is not None:
                if server.session.revoked():
                    send(_note("bye", {"reason": "revoked"}))
                    return 0
                cfg = server.session.share_changed()
                if cfg is not None:  # `share off`, Deactivate, `share ai on|off`: within a second
                    if cfg.get("on") is not True:
                        send(_note("bye", {"reason": "off"}))
                        return 0
                    ai = oomph.switched_on(cfg.get("ai"))
                    if ai != server.ai:
                        server.ai = ai
                        if server.open:
                            send(_note("machine", {"caps": server.caps()}))
            elif server.ai_watch is not None:  # over SSH: `share ai on|off` alone (sharing is TCP's)
                ai = server.ai_watch.changed()
                if ai is not None and ai != server.ai:
                    server.ai = ai
                    if server.open:
                        send(_note("machine", {"caps": server.caps()}))
            if cpu_spent():
                send(_note("bye", {"reason": "busy"}))
                return 0
            try:
                notes = server.poll()
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as e:
                notes = []
                sys.stderr.write("oomph serve: %s while watching the files\n" % type(e).__name__)
            for note in notes:
                send(note)
        wait = max(0.1, idle - (now - quiet_since))
        if server.subscribed or server.session is not None or server.ai_watch is not None:
            wait = max(0.05, min(wait, 1.0 - (now - looked)))
        if pre_auth is not None and not server.open:
            wait = max(0.05, min(wait, pre_auth - (now - started)))
        try:
            line = lines.read(wait)
        except Closed as e:
            if "longer" in str(e):
                send(_note("bye", {"reason": "too_large"}))
            return 0
        if line is None:
            if time.monotonic() - quiet_since > idle:
                send(_note("bye", {"reason": "idle"}))
                return 0
            continue
        quiet_since = time.monotonic()
        if not line.strip():
            continue
        try:
            req = json.loads(line, parse_constant=oomph._no_constant, parse_int=oomph._parse_int)
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


# ------------------------------------------------------------------ pairing and tokens (roadmap 01 §5.3)
def _b64(x, n):
    """Exactly n bytes from a base64 string, or None."""
    if not isinstance(x, str) or len(x) > 4 * n + 4:
        return None
    try:
        b = base64.b64decode(x.encode("ascii"), validate=True)
    except (ValueError, TypeError, UnicodeEncodeError):
        return None
    return b if len(b) == n else None


def new_code():
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(12))


def norm_code(s):
    """A code as someone typed it (any case, dashes and spaces, O for 0, I or L for 1) as its 12
    characters, or None."""
    if not isinstance(s, str) or len(s) > 64:
        return None
    c = re.sub(r"[\s-]", "", s).upper().translate(str.maketrans("OIL", "011"))
    return c if len(c) == 12 and all(x in CODE_ALPHABET for x in c) else None


def show_code(c):
    return "-".join((c[:4], c[4:8], c[8:]))


def pair_key(code, sn, cn):
    return hashlib.pbkdf2_hmac("sha256", code.encode(), b"oomph-pair-v1" + sn + cn, PBKDF2_ROUNDS, 32)


def proof(key, label, cn, sn, fp):
    """HMAC-SHA256(key, label ‖ client nonce ‖ server nonce ‖ certificate digest)."""
    return hmac.new(key, label + cn + sn + fp, hashlib.sha256).digest()


def token_key(token):
    """What the server keeps of a token: SHA-256("oomph-token-v1" ‖ token), the key of `auth`."""
    return hashlib.sha256(b"oomph-token-v1" + token).digest()


COUNTS = {"derive": 0, "pause": 0}   # every pairing attempt derives once, every failure pauses once (tests)


def check_pairing(code, cn, sn, fp, mac):
    """The one derive-and-compare every pairing attempt goes through, with the active code or a
    random dummy alike: no code, an expired one and a wrong proof cost the same (roadmap 01 §5.3)."""
    COUNTS["derive"] += 1
    kp = pair_key(code, sn, cn)
    return kp, mac is not None and hmac.compare_digest(proof(kp, b"client", cn, sn, fp), mac)


def pause():
    COUNTS["pause"] += 1
    time.sleep(PAUSE_S)


def viewer_name(x):
    """The viewer's name as the server keeps it (roadmap 01 §5.5): spaces as '-', nothing outside
    [A-Za-z0-9._-], starting with a letter or digit, at most 63 characters; 'viewer' if nothing is
    left. Quotes, $, ;, backticks, newlines and escape sequences never reach a file."""
    s = x[:1000] if isinstance(x, str) else ""
    s = re.sub(r"[^A-Za-z0-9._-]", "", s.replace(" ", "-"))
    return re.sub(r"^[^A-Za-z0-9]+", "", s)[:63] or "viewer"


def fingerprint(der):
    return "sha256:" + hashlib.sha256(der).hexdigest()


# ------------------------------------------------------------------ the share state (roadmap 01 §5.9)
SHARE_DIRS = {"darwin": "/Library/Application Support/oomph/share", "linux": "/var/lib/oomph/share"}
LINUX_NOTE = ("Linux machines are watched over SSH and open no port of their own: on the viewer, "
              "oomph remote add USER@HOST")


class ShareError(Exception):
    pass


class ShareDir:
    """Where sharing keeps its state. config.json, cert.pem and key.pem are root's (key.pem
    root:_oomph 640); run/ is the service's. OOMPH_SHARE_DIR points elsewhere for the tests, and
    only together with OOMPH_TEST=1 and for a caller that is not root: every file there is then
    this user's, and nothing privileged runs (no account, no launchd, no privilege drop), and
    `serve --listen` stays on loopback."""

    def __init__(self, path=None):
        env = os.environ.get("OOMPH_SHARE_DIR") if os.environ.get("OOMPH_TEST") == "1" else None
        self.test = path is None and bool(env) and os.geteuid() != 0
        self.path = path or (env if self.test else SHARE_DIRS["darwin" if sys.platform == "darwin" else "linux"])
        self.owner = os.geteuid() if self.test else 0
        self.config_path, self.cert, self.key, self.run = (
            os.path.join(self.path, n) for n in ("config.json", "cert.pem", "key.pem", "run"))

    def config(self):
        """config.json, trusted only when its owner (root) alone can change it and its folder."""
        return oomph.read_config(self.config_path, owner=self.owner)

    def write_config(self, cfg):
        _write_root_file(self.path, "config.json", dumps(cfg) + b"\n", 0o644, self.owner)

    def fp(self):
        """The SHA-256 of this machine's certificate (DER): its public identity."""
        with open(self.cert) as f:
            return hashlib.sha256(ssl.PEM_cert_to_DER_cert(f.read(16 << 10))).digest()

    def key_ok(self):
        """The key is root's (or the tester's), nothing for others, not writable by its group, and
        that group is the service's own: serve refuses to speak TLS with any other key."""
        try:
            st = os.stat(self.key, follow_symlinks=False)
        except OSError:
            return False
        return stat.S_ISREG(st.st_mode) and st.st_uid == self.owner and not st.st_mode & 0o027 and \
            (self.test or st.st_gid == os.getegid())


def ai_allowed(sh=None):
    """Whether this machine lets its viewers send its data to an AI model (D7): `oomph share ai
    on` by an administrator; off by default, and off whatever a viewer asks."""
    try:
        return oomph.switched_on((sh or ShareDir()).config().get("ai"))
    except OSError:
        return False


def _write_root_file(d, name, data, mode, owner):
    """A file of root's directory `d` (which must be root's and writable by nobody else), written to
    a fresh temporary name and renamed: never through a name that exists."""
    dfd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(dfd)
        if st.st_uid != owner or st.st_mode & 0o022:
            raise ShareError("%s is not root's alone" % d)
        tmp = ".%s.%s.tmp" % (name, secrets.token_hex(8))
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        try:
            os.fchmod(fd, mode)
            write_all(fd, data)
        finally:
            os.close(fd)
        os.rename(tmp, name, src_dir_fd=dfd, dst_dir_fd=dfd)
    finally:
        os.close(dfd)


class RunDir:
    """The service's own directory, run/: pairings (clients.json), the active code (pairing.json),
    what `share status` shows (summary.json), the network cache and conn/<pid>.json. Opened
    without following links; every file is written to a fresh temporary name and renamed, and
    read with oomph.read_bounded. Root never comes here: the share commands become the service
    account first (as_service)."""

    def __init__(self, path):
        self.path = path

    def _fd(self, sub=""):
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        if not sub:
            return fd
        try:
            try:
                os.mkdir(sub, 0o755, dir_fd=fd)
            except FileExistsError:
                pass
            return os.open(sub, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
        finally:
            os.close(fd)

    def read(self, name, sub="", cap=1 << 20):
        try:
            fd = self._fd(sub)
        except OSError:
            return None
        try:
            return oomph.loads_untrusted(oomph.read_bounded(name, cap, fd))
        finally:
            os.close(fd)

    def write(self, name, obj, mode=0o600, sub=""):
        fd = self._fd(sub)
        try:
            tmp = ".%s.%s.tmp" % (name, secrets.token_hex(8))
            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                os.fchmod(out, mode)
                write_all(out, dumps(obj) + b"\n")
            finally:
                os.close(out)
            os.rename(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            os.close(fd)

    def remove(self, name, sub=""):
        try:
            fd = self._fd(sub)
        except OSError:
            return
        try:
            os.unlink(name, dir_fd=fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def names(self, sub=""):
        try:
            fd = self._fd(sub)
        except OSError:
            return []
        try:
            return os.listdir(fd)
        finally:
            os.close(fd)

    def stamp(self, name):
        """(inode, mtime, size); None when there is no such file, False when that could not be told."""
        try:
            fd = self._fd()
        except FileNotFoundError:
            return None
        except OSError:
            return False
        try:
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            return (st.st_ino, st.st_mtime_ns, st.st_size)
        except FileNotFoundError:
            return None
        except OSError:
            return False
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def lock(self, wait=5.0):
        """clients.json and pairing.json change under this lock (flock on run/lock, 5 s at most)."""
        dfd = self._fd()
        try:
            fd = os.open("lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=dfd)
        finally:
            os.close(dfd)
        try:
            deadline = time.monotonic() + wait
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise OSError("run/lock is busy")
                    time.sleep(0.05)
            yield
        finally:
            os.close(fd)

    def clients(self, strict=False):
        """The pairings, each checked: an id of the fixed pattern, a key of 64 hex digits. With
        `strict`, None when clients.json is there but could not be read: a caller about to write it
        back, or to call a viewer revoked, must not take that for "no pairings"."""
        v = self.read("clients.json")
        if v is None and strict and self.stamp("clients.json") is not None:
            return None
        out = []
        for c in v if isinstance(v, list) else []:
            if isinstance(c, dict) and isinstance(c.get("id"), str) and CLIENT_ID.fullmatch(c["id"]) and \
                    isinstance(c.get("key"), str) and re.fullmatch(r"[0-9a-f]{64}", c["key"]):
                out.append(c)
        return out[:256]

    def pairing(self):
        """The active code as {"code", "expires", "left"}, or None."""
        v = self.read("pairing.json")
        if isinstance(v, dict) and norm_code(v.get("code")) == v.get("code") and v.get("code") and \
                oomph._num(v.get("expires"), 0, 1e11) and isinstance(v.get("left"), int):
            return v
        return None

    def conns(self):
        """The live connections' entries (conn/<pid>.json); those of dead processes are swept."""
        out = []
        for n in self.names("conn"):
            m = re.fullmatch(r"(\d{1,10})\.json", n)
            if not m:
                continue
            pid = int(m.group(1))
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):  # gone, or the pid is another account's now
                self.remove(n, "conn")
                continue
            c = self.read(n, "conn", 4096)
            if isinstance(c, dict) and c.get("pid") == pid:
                out.append(c)
        return out

    def summary(self):
        """summary.json (0644): what `share status` shows, no key and no code. Display data only:
        its readers check ids and clean names again."""
        p = self.read("pairing.json")
        active = self.pairing()
        now = time.time()
        clients = [{k: c.get(k) for k in ("id", "name", "paired", "last_seen", "last_addr")} for c in self.clients()]
        reading = [{"client": c.get("client"), "peer": c.get("peer"), "since": c.get("started")}
                   for c in self.conns() if c.get("state") == "authenticated"]
        pairing = {"active": bool(active and active["expires"] > now and active["left"] > 0),
                   "expires": active and active["expires"], "left": active and active["left"],
                   "used_by": p.get("used_by") if isinstance(p, dict) else None}
        self.write("summary.json", {"v": 1, "updated": now, "clients": clients, "reading": reading,
                                    "pairing": pairing}, 0o644)


class Conn:
    """This connection's entry in conn/: what the caps count and what `share status` lists."""

    def __init__(self, run, peer):
        self.run, self.name = run, "%d.json" % os.getpid()
        self.info = {"pid": os.getpid(), "peer": peer, "started": time.time(), "client": None, "state": "handshake"}
        self.update()

    def update(self, **kw):
        self.info.update(kw)
        try:
            self.run.write(self.name, self.info, 0o644, "conn")
        except OSError:
            pass

    def close(self):
        self.run.remove(self.name, "conn")


def admit(run, conn):
    """Whether this connection may go on to TLS: at most MAX_HANDSHAKES others before
    authentication, and MAX_PER_ADDR from its own address."""
    others = [c for c in run.conns() if c.get("pid") != conn.info["pid"] and c.get("state") != "authenticated"]
    return len(others) < MAX_HANDSHAKES and sum(1 for c in others if c.get("peer") == conn.info["peer"]) < MAX_PER_ADDR


def allow_too_wide(rng):
    """Why `share allow` refuses a range (an ipaddress network), or None: wider than ALLOW_MIN, or an IPv6 range
    that stands for IPv4 hosts anywhere (Teredo, 6to4, NAT64, mapped: allow those by their IPv4 range). 1.14.1;
    the gate still honours such a range written before, and `share status` names it."""
    if rng.prefixlen < ALLOW_MIN[rng.version]:
        return "%s is too wide: at most a /%d (%s addresses) per range, e.g. 100.64.0.0/10 for a tailnet" % (
            rng, ALLOW_MIN[rng.version], "16.7 million" if rng.version == 4 else "2^96")
    for r, what in ALLOW_V4_IN_V6 if rng.version == 6 else ():
        if rng.overlaps(ipaddress.ip_network(r)):
            return "%s is within %s (%s), which stands for IPv4 hosts anywhere: allow their IPv4 range" % (rng, r, what)
    return None


def config_changed(sh, last):
    """(config.json if it changed since `last`, else None; the stamp to pass next time). A missing file
    reads as {"on": False}; one that could not be read is looked at again next time."""
    try:
        st = os.stat(sh.config_path, follow_symlinks=False)
        stamp = (st.st_dev, st.st_ino, st.st_mtime_ns, st.st_size)
    except FileNotFoundError:
        return ({"on": False} if last is not None else None), None
    except OSError:
        return None, last
    if stamp == last:
        return None, last
    cfg = sh.config()
    return cfg or None, (stamp if cfg else "unread")


class AiWatch:
    """`serve --stdio` (over SSH, roadmap 01 §8): whether this machine still lets its viewers send its data to
    an AI model (`share ai on|off`), looked at as a TLS session looks at it, so that a withdrawal reaches a
    session already open within a second (it did only at the next connection up to 1.14.0)."""

    def __init__(self, sh=None):
        self.sh, self.stamp = sh or ShareDir(), "unread"

    def changed(self):
        """The `ai` switch now if config.json changed since the last look, else None."""
        cfg, self.stamp = config_changed(self.sh, self.stamp)
        return None if cfg is None else oomph.switched_on(cfg.get("ai"))


class Session:
    """One TLS connection's side of pairing and authentication, over run/."""

    def __init__(self, run, fp, peer, conn=None, sh=None):
        self.run, self.fp, self.peer, self.conn, self.sh = run, fp, peer, conn, sh
        self.client = self.stamp = None
        self.cfg_stamp = "unread"

    def pair(self, mac, cn, sn, name):
        """(pairing key, client id, token) when the proof matches the active code, else None, after
        the pause. The code is used up by success; a wrong proof costs one of its tries. "busy" for
        a right proof while as many viewers read as are served: the code is kept, and only someone
        who knows it learns that the house is full (1.14.1)."""
        derived = good = busy = False
        kp = cid = token = None
        now = time.time()
        try:
            with self.run.lock():
                pr = self.run.pairing()
                usable = bool(pr and pr["expires"] > now and pr["left"] > 0)
                kp, good = check_pairing(pr["code"] if usable else new_code(), cn, sn, self.fp, mac)
                derived = True
                good = good and usable
                if good and not self.admit_viewer():
                    good, busy = False, True
                elif good:
                    clients = self.run.clients(strict=True)
                    if clients is None:  # never written back as only this one: the others' pairings stay
                        raise OSError("clients.json could not be read")
                    taken = {c["id"] for c in clients}
                    cid = next(c for c in ("c-" + secrets.token_hex(4) for _ in range(100)) if c not in taken)
                    token = os.urandom(32)
                    clients.append({"id": cid, "name": viewer_name(name), "key": token_key(token).hex(), "paired": now,
                                    "last_seen": now, "last_addr": self.peer})
                    self.run.write("clients.json", clients)
                    self.run.write("pairing.json", {"used_by": cid, "t": now})
                elif usable:
                    pr["left"] -= 1
                    if pr["left"] > 0:
                        self.run.write("pairing.json", pr)
                    else:
                        self.run.write("pairing.json", {"void": True, "t": now})
        except OSError:
            good = False
        if not derived:
            check_pairing(new_code(), cn, sn, self.fp, mac)
        try:
            self.run.summary()
        except OSError:
            pass
        if busy:
            return "busy"
        if not good:
            pause()
            return None
        self._authenticated(cid)
        return kp, cid, token

    def auth(self, cid, mac, cn, sn):
        """True; False for an unknown client or a wrong proof (after the pause), also for a pairing
        revoked meanwhile; "busy" when as many viewers are reading as are served (counted before
        this connection is one). Raises OSError when clients.json is there but cannot be read, or
        its lock cannot be had: no answer either way (the viewer tries again and keeps its token),
        never "authenticated" without the look under the lock (1.14.1)."""
        clients = self.run.clients(strict=True)
        if clients is None:
            raise OSError("clients.json could not be read")
        entry = next((c for c in clients if c["id"] == cid), None) if cid else None
        key = bytes.fromhex(entry["key"]) if entry else os.urandom(32)
        good = hmac.compare_digest(proof(key, b"auth", cn, sn, self.fp), mac or b"\0" * 32) and entry is not None
        if good and not self.admit_viewer():
            return "busy"
        with self.run.lock():
            clients = self.run.clients(strict=True)
            if clients is None:
                raise OSError("clients.json could not be read")
            if good and any(c["id"] == cid for c in clients):  # a revoke may have come between
                for c in clients:
                    if c["id"] == cid:
                        c["last_seen"], c["last_addr"] = time.time(), self.peer
                try:
                    self.run.write("clients.json", clients)
                except OSError:  # (last seen not noted: a full disk; the pairing itself was looked at)
                    pass
            else:
                good = False
        if not good:
            pause()
            return False
        self._authenticated(cid)
        return True

    def _authenticated(self, cid):
        """No stamp yet: the first revoked() reads clients.json, so a revoke that lands between the
        write above and now is seen within a second."""
        self.client, self.stamp = cid, "unread"  # never equal to a stamp, nor to None (a deleted file)
        lift_cpu()
        if self.conn:
            self.conn.update(state="authenticated", client=cid)
        try:
            self.run.summary()
        except OSError:
            pass

    def admit_viewer(self):
        others = [c for c in self.run.conns() if c.get("state") == "authenticated" and c.get("pid") != os.getpid()]
        return len(others) < MAX_VIEWERS

    def revoked(self):
        """Whether this connection's pairing is gone: clients.json is read again when it changed. A
        file that is there but could not be read (out of descriptors, too large) is no answer: the
        next second looks again, as the viewer deletes its token on a revocation."""
        if self.client is None:
            return False
        st = self.run.stamp("clients.json")
        if st == self.stamp or st is False:
            return False
        if st is None:  # gone: share off --forget, purge
            self.stamp = None
            return True
        clients = self.run.clients(strict=True)
        if clients is None:
            return False
        self.stamp = st
        return not any(c["id"] == self.client for c in clients)

    def share_changed(self):
        """config.json again when it changed since the last look (None while it did not): what
        `share off` and `share ai on|off` wrote. Deactivate (the service's plist gone) reads as
        off. One that could not be read is looked at again a second later."""
        if self.sh is None:
            return None
        if not self.sh.test and sys.platform == "darwin" and not os.path.lexists(SHARE_PLIST):
            return {"on": False}
        cfg, self.cfg_stamp = config_changed(self.sh, self.cfg_stamp)
        return cfg

    def unpair(self):
        with self.run.lock():
            clients = self.run.clients(strict=True)
            if clients is None:
                raise OSError("clients.json could not be read")
            self.run.write("clients.json", [c for c in clients if c["id"] != self.client])
        self.client = None
        if self.conn:
            self.conn.update(state="handshake", client=None)
        self.run.summary()


# ------------------------------------------------------------------ TLS (roadmap 01 §5.2)
def server_context(sh):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET | ssl.OP_SINGLE_ECDH_USE | ssl.OP_CIPHER_SERVER_PREFERENCE
    ctx.options |= getattr(ssl, "OP_NO_RENEGOTIATION", 0)
    ctx.load_cert_chain(sh.cert, sh.key)
    return ctx


def client_context():
    """The viewer's: no name or date check (identity is the pinned key, as with SSH host keys),
    TLS 1.2 or newer, AEAD suites with forward secrecy."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= ssl.OP_NO_COMPRESSION | ssl.OP_NO_TICKET
    return ctx


def make_key(sh, gid):
    """A P-256 key and a self-signed certificate (CN=oomph on every machine, ten years: it is only
    ever pinned), made by the system's openssl in root's directory, then renamed into place."""
    tk, tc = (os.path.join(sh.path, ".%s.%s.tmp" % (n, secrets.token_hex(6))) for n in ("key", "cert"))
    old = os.umask(0o077)
    try:
        for argv in (["/usr/bin/openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", tk],
                     ["/usr/bin/openssl", "req", "-new", "-x509", "-sha256", "-days", "3650", "-subj", "/CN=" + oomph.CMD,
                      "-key", tk, "-out", tc]):
            r = _run(argv)
            if r.returncode != 0:
                raise ShareError("openssl failed: %s" % clean((r.stderr or r.stdout or "").strip()[-200:], 200))
        if not sh.test:
            os.chown(tk, 0, gid)
            os.chmod(tk, 0o640)
        os.chmod(tc, 0o644)
        os.rename(tk, sh.key)
        os.rename(tc, sh.cert)
    finally:
        os.umask(old)
        for t in (tk, tc):
            try:
                os.unlink(t)
            except OSError:
                pass


def fix_key(sh, gid):
    """An existing key.pem put right through its descriptor (opened without following a link): root's (the
    tester's) regular file with one link, group the service's (`gid`, which changes when the account is made
    again), mode 640. Up to 1.14.0 it was never looked at again, and a changed gid closed every connection
    without a word (key_ok). Raises ShareError for a key that is not root's own file: nothing is changed then
    (`share off --forget` makes a new one, and viewers pair again)."""
    try:
        fd = os.open(sh.key, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError as e:
        raise ShareError("%s can't be opened (%s): sudo oomph share off --forget, then share on again" % (
            sh.key, e.strerror or e))
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != sh.owner or st.st_nlink != 1:
            raise ShareError("%s is not root's own file: sudo oomph share off --forget, then share on again" % sh.key)
        if not sh.test and st.st_gid != gid:
            os.fchown(fd, 0, gid)
        mode = 0o600 if sh.test else 0o640
        if stat.S_IMODE(st.st_mode) != mode:
            os.fchmod(fd, mode)
    finally:
        os.close(fd)


# ------------------------------------------------------------------ the peer gate (roadmap 01 §4.2)
IFF_UP, IFF_LOOPBACK, IFF_POINTOPOINT = 0x1, 0x8, 0x10
LINK_IFS = re.compile(r"(en|eth|wl)[A-Za-z0-9]{0,12}")   # wired or Wi-Fi: not awdl, llw, utun, bridge
IFNAME = re.compile(r"[A-Za-z0-9._-]{1,16}")


class Iface:
    def __init__(self, name, flags, addr, prefix, index):
        self.name, self.flags, self.addr, self.prefix, self.index = name, flags, addr, prefix, index

    def net(self):
        return ipaddress.ip_network((self.addr, self.prefix), strict=False)

    def __repr__(self):
        return "Iface(%s %s/%d)" % (self.name, self.addr, self.prefix)


def interfaces():
    """This machine's addresses as Iface (name, flags, address, prefix length, index), from
    getifaddrs through ctypes: no subprocess, a millisecond. None when the table can't be read
    (the gate then fails closed: loopback only)."""
    try:
        import ctypes
    except ImportError:
        return None

    class IfAddrs(ctypes.Structure):
        pass
    IfAddrs._fields_ = [("next", ctypes.POINTER(IfAddrs)), ("name", ctypes.c_char_p), ("flags", ctypes.c_uint),
                        ("addr", ctypes.c_void_p), ("netmask", ctypes.c_void_p), ("dst", ctypes.c_void_p),
                        ("data", ctypes.c_void_p)]
    try:
        libc = ctypes.CDLL(None)
        head = ctypes.POINTER(IfAddrs)()
        if libc.getifaddrs(ctypes.byref(head)) != 0:
            return None
    except (OSError, AttributeError):
        return None
    out = []
    try:
        p = head
        while p:
            ifa = p.contents
            a = _sockaddr(ctypes, ifa.addr)
            if a is not None:
                fam, raw = a
                m = _sockaddr(ctypes, ifa.netmask, fam)
                bits = len(raw) * 8
                prefix = bin(int.from_bytes(m[1], "big")).count("1") if m and len(m[1]) == len(raw) else bits
                name = (ifa.name or b"").decode("ascii", "replace")
                try:
                    index = socket.if_nametoindex(name)
                except OSError:
                    index = 0
                addr = ipaddress.ip_address(raw)
                out.append(Iface(name, ifa.flags, addr, prefix, index))
            p = ifa.next
    finally:
        libc.freeifaddrs(head)
    return out


def _sockaddr(ctypes, ptr, family=None):
    """(family, address bytes) of a struct sockaddr for IPv4 or IPv6, else None. macOS's begins with
    its length and a one-byte family (and a netmask's may be cut short, or carry family 0); Linux's
    with a two-byte family."""
    if not ptr:
        return None
    if sys.platform == "darwin":
        head = ctypes.string_at(ptr, 2)
        size, fam = head[0], head[1] or family
        data = ctypes.string_at(ptr, max(2, min(size, 28))) if size else b""
    else:
        fam = int.from_bytes(ctypes.string_at(ptr, 2), sys.byteorder) or family
        data = ctypes.string_at(ptr, 28 if fam == socket.AF_INET6 else 16)
    if fam == socket.AF_INET:
        raw = (data[4:8] + b"\0" * 4)[:4]
    elif fam == socket.AF_INET6:
        raw = bytearray((data[8:24] + b"\0" * 16)[:16])
        if raw[0] == 0xfe and raw[1] & 0xc0 == 0x80:  # a KAME-embedded scope in a link-local address
            raw[2] = raw[3] = 0
        raw = bytes(raw)
    else:
        return None
    return fam, raw


def norm_addr(sa):
    """(ip_address, scope) of a socket address as getpeername gives it: an IPv4-mapped IPv6 peer
    is the IPv4 address it is, a link-local one keeps its scope. (None, 0) for anything else."""
    if not isinstance(sa, tuple) or not sa or not isinstance(sa[0], str):
        return None, 0
    host, _, zone = sa[0].partition("%")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return None, 0
    scope = sa[3] if len(sa) >= 4 and isinstance(sa[3], int) else 0
    if not scope and zone:
        try:
            scope = int(zone) if zone.isdigit() else socket.if_nametoindex(zone)
        except OSError:
            scope = 0
    if ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped, 0
    return ip, scope


def network_allowed(ident, networks):
    """Whether the network an interface is on is one sharing was turned on for: the same default
    router (address and hardware address), or for a cable without a router the same interface
    and subnet. A router whose hardware address could not be read when sharing was turned on is
    matched by its address and the subnet; one that was read must be read again, the same."""
    for n in networks if isinstance(networks, list) else []:
        if not isinstance(n, dict):
            continue
        if ident.get("router"):
            if n.get("router") == ident["router"] and (n.get("mac") == ident.get("mac") if n.get("mac") else
                                                       n.get("net") == ident.get("net")):
                return True
        elif not n.get("router") and n.get("if") == ident.get("if") and n.get("net") == ident.get("net"):
            return True
    return False


def gate(peer, local, ifaces, cfg, network_of):
    """None if the peer may speak to this service, else why not (roadmap 01 §4.2), from the socket's
    two addresses alone: loopback; a range the owner allowed; otherwise only on a network sharing
    was turned on for (or any, with any_network), and then only a peer on the subnet of the
    interface that owns the connection's local address, or link-local on that wired or Wi-Fi
    interface. A point-to-point interface (a tailnet) has no neighbours: it is allowed by range."""
    p, pscope = norm_addr(peer)
    loc, lscope = norm_addr(local)
    if p is None or loc is None:
        return "not an IP peer"
    if p.is_loopback:
        return None
    for c in cfg.get("allow") if isinstance(cfg.get("allow"), list) else []:
        try:
            net = ipaddress.ip_network(c, strict=False)
        except (ValueError, TypeError):
            continue
        if net.version == p.version and p in net:
            return None
    if ifaces is None:
        return "no interface table"
    own = [i for i in ifaces if i.addr == loc and (not loc.is_link_local or not lscope or i.index == lscope)]
    if not own:
        return "the local address belongs to no interface"
    i = own[0]
    if not cfg.get("any_network"):
        # A network is known by its IPv4 router: a connection to an IPv4 address is judged by that
        # address (an alias on another subnet is another network); one to an IPv6 address (link-local
        # or global) by the IPv4 address on the same interface, and an interface without one is on
        # no network sharing was turned on for.
        if loc.version == 4:
            v4 = [i]
        else:
            v4 = [j for j in ifaces if j.name == i.name and j.addr.version == 4]
            v4.sort(key=lambda j: j.addr.is_link_local)
        if not v4 or not network_allowed(network_of(v4[0]), cfg.get("networks")):
            return "not a network sharing is on for"
    if p.is_link_local:
        if p.version == 6 and pscope and pscope != i.index:
            return "link-local on another interface"
        return None if LINK_IFS.fullmatch(i.name) else "link-local on %s" % i.name
    if i.flags & IFF_POINTOPOINT:
        return "a point-to-point interface: allow its range"
    return None if p.version == i.addr.version and p in i.net() else "not on this subnet (routed)"


def _run(argv, timeout=30):
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, cwd="/",
                          env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"})


def lookup_network(i):
    """The identity of the network interface `i` is on: its subnet and default router with that
    router's hardware address (or no router: a cable). Two unprivileged commands that take no
    input from a peer."""
    ident = {"if": i.name, "net": str(i.net()), "router": None, "mac": None}
    if not IFNAME.fullmatch(i.name) or i.addr.version != 4:
        return ident
    try:
        if sys.platform == "darwin":
            out = _run(["/sbin/route", "-n", "get", "default", "-ifscope", i.name], 4).stdout
            m = re.search(r"gateway:\s*([0-9.]+)", out)
        else:
            out = _run(["ip", "-4", "route", "show", "default", "dev", i.name], 4).stdout
            m = re.search(r"default via ([0-9.]+)", out)
        if not m:
            return ident
        router = str(ipaddress.ip_address(m.group(1)))
        ident["router"] = router
        for attempt in (0, 1):
            if sys.platform == "darwin":
                out = _run(["/usr/sbin/arp", "-n", router], 4).stdout
                m = re.search(r" at ([0-9a-fA-F:]{11,17}) ", out)
            else:
                out = _run(["ip", "neigh", "show", router, "dev", i.name], 4).stdout
                m = re.search(r"lladdr ([0-9a-fA-F:]{11,17})", out)
            if m or attempt:
                break
            try:  # not in the ARP table yet: one empty datagram to its discard port puts it there
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
                    u.sendto(b"", (router, 9))
            except OSError:
                pass
            time.sleep(0.3)
        if m:
            ident["mac"] = ":".join("%02x" % int(x, 16) for x in m.group(1).split(":"))
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return ident


def network_of(i, run=None):
    """lookup_network, cached in run/network.json for 30 s under the key (interface, local address,
    prefix): a move to another network changes the address or the prefix and never meets a cached
    answer."""
    key = "%s %s/%d" % (i.name, i.addr, i.prefix)
    now = time.time()
    cache = (run.read("network.json") if run else None) or {}
    hit = cache.get(key) if isinstance(cache, dict) else None
    if isinstance(hit, dict) and oomph._num(hit.get("t"), now - 30, now + 1):
        return {"if": i.name, "net": str(i.net()), "router": hit.get("router"), "mac": hit.get("mac")}
    ident = lookup_network(i)
    if run:
        fresh = {k: v for k, v in (cache.items() if isinstance(cache, dict) else [])
                 if isinstance(v, dict) and oomph._num(v.get("t"), now - 30, now + 1)}
        fresh[key] = {"router": ident["router"], "mac": ident["mac"], "t": now}
        try:
            run.write("network.json", fresh, 0o644)
        except OSError:
            pass
    return ident


def default_gate(peer, local, cfg, run):
    return gate(peer, local, interfaces(), cfg, lambda i: network_of(i, run))


def current_networks(ifaces=None, lookup=None):
    """The networks this machine is on now: one per wired or Wi-Fi interface with an IPv4 address.
    A self-assigned address (169.254/16) counts only on an interface that has no other: a cable
    between two machines without a router, known by its interface and that subnet."""
    ifaces = interfaces() if ifaces is None else ifaces
    up = [i for i in ifaces or [] if i.addr.version == 4 and i.flags & IFF_UP and
          not i.flags & (IFF_LOOPBACK | IFF_POINTOPOINT) and LINK_IFS.fullmatch(i.name)]
    routable = {i.name for i in up if not i.addr.is_link_local}
    out, seen = [], set()
    for i in up:
        if i.addr.is_link_local and (i.name in routable or i.name in seen):
            continue
        seen.add(i.name)
        out.append((lookup or lookup_network)(i))
    return out


# ------------------------------------------------------------------ the TCP front ends
_cpu_limited = []


def limit_self():
    """What a connection process may use: 64 files, CPU_S[0] seconds of CPU until it is
    authenticated (lift_cpu), 32 MB files, no core; umask 077. Memory is bounded by the code (caps
    everywhere, RSS_CAP)."""
    import resource
    _cpu_limited.append(True)
    for r, v in ((resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_CPU, CPU_S[0]), (resource.RLIMIT_FSIZE, 32 << 20),
                 (resource.RLIMIT_CORE, 0)):
        try:
            soft, hard = resource.getrlimit(r)
            resource.setrlimit(r, (v if hard == resource.RLIM_INFINITY else min(v, hard), hard))
        except (ValueError, OSError):
            pass
    signal.signal(signal.SIGXCPU, lambda *a: sys.exit(0))  # leave through the cleanup (conn/ entry)
    os.umask(0o077)


def lift_cpu():
    """After authentication a session may follow for days (a terminal's `remote sync`): its CPU
    limit grows to CPU_S[1], and serve() says bye before it is reached (cpu_spent)."""
    if not _cpu_limited:
        return
    import resource
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_S[1] if hard == resource.RLIM_INFINITY else min(CPU_S[1], hard), hard))
    except (ValueError, OSError):
        pass


def cpu_spent():
    """Whether this connection process is within 10 s of its CPU limit: serve() then ends with bye
    {reason: busy}, so the viewer comes back at once instead of meeting a closed socket."""
    if not _cpu_limited:
        return False
    import resource
    soft = resource.getrlimit(resource.RLIMIT_CPU)[0]
    ru = resource.getrusage(resource.RUSAGE_SELF)
    return soft != resource.RLIM_INFINITY and ru.ru_utime + ru.ru_stime > soft - 10


def _close(sock):
    try:
        sock.close()
    except OSError:
        pass


def serve_connection(sock, sh=None, now=None, gate_fn=None):
    """One TCP connection from start to end: the gate (a refused peer gets the connection closed
    and not one of its bytes is read), the caps on connections, TLS and hello and pair or auth
    within HANDSHAKE_S, then the session. Returns an exit status."""
    started = time.monotonic()
    sh = sh or ShareDir()
    try:
        peer, local = sock.getpeername(), sock.getsockname()
    except OSError:
        _close(sock)
        return 1
    cfg = sh.config()
    run = RunDir(sh.run)
    why = "sharing is off" if cfg.get("on") is not True else (gate_fn or default_gate)(peer, local, cfg, run)
    if why is not None or ssl is None or not sh.key_ok():
        _close(sock)
        return 0 if why is not None else 1
    ip = str(norm_addr(peer)[0])
    conn = Conn(run, ip)
    try:
        if not admit(run, conn):
            _close(sock)
            return 0
        sock.settimeout(HANDSHAKE_S)
        try:
            tls = server_context(sh).wrap_socket(sock, server_side=True)
            session = Session(run, sh.fp(), ip, conn, sh)
        except (OSError, ValueError):
            _close(sock)
            return 0
        stream = SockStream(tls)
        try:
            return serve(stream, stream, Server(now=now, session=session, ai=oomph.switched_on(cfg.get("ai"))),
                         pre_auth=max(0.1, HANDSHAKE_S - (time.monotonic() - started)))
        except (OSError, Closed):
            return 0
        finally:
            _close(tls)
    finally:
        conn.close()
        try:
            run.summary()
        except OSError:
            pass


def serve_inetd(now=None):
    """`serve --inetd`: launchd (inetdCompatibility, no Wait) passes the connection as fd 0 and fd
    1. It moves to a private descriptor first and 0, 1 and 2 point at /dev/null, so no stray print
    or traceback can put plaintext into the TLS stream."""
    fd = os.dup(0)
    null = os.open(os.devnull, os.O_RDWR)
    for i in (0, 1, 2):
        os.dup2(null, i)
    os.close(null)
    limit_self()
    if os.geteuid() == 0:  # the service runs as its own account; root serves nothing over TCP
        os.close(fd)
        return 1
    try:
        sock = socket.socket(fileno=fd)
    except OSError:
        return 1
    return serve_connection(sock, now=now)


def serve_listen(spec, now=None):
    """`serve --listen HOST:PORT`: accept, and start one `serve --inetd` per connection, as launchd
    does (tests; a machine without launchd). Loopback only unless sharing is on. Prints the address
    it listens on (port 0: a free one) as its first line. A fresh interpreter, not a bare fork: on
    macOS a forked child that does not exec reads the time zone file again at every localtime()
    (its notification of zone changes does not survive the fork), which made a pairing's
    catch-up ten times slower than the launchd service it stands in for."""
    m = re.fullmatch(r"\[?([0-9A-Fa-f:.]+)\]?:(\d{1,5})", spec or "")
    if not m:
        sys.stderr.write("oomph: serve --listen takes ADDRESS:PORT, e.g. 127.0.0.1:6674\n")
        return 2
    try:
        ip = ipaddress.ip_address(m.group(1))
    except ValueError:
        sys.stderr.write("oomph: serve --listen: not an address: %s\n" % clean(m.group(1), 64))
        return 2
    sh = ShareDir()
    if os.geteuid() == 0:
        sys.stderr.write("oomph: serve --listen does not run as root\n")
        return 1
    if not ip.is_loopback and (sh.test or sh.config().get("on") is not True):
        sys.stderr.write("oomph: serve --listen: only on loopback while sharing is off (or a test)\n")
        return 1
    s = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((str(ip), int(m.group(2))))
    s.listen(16)
    sys.stdout.write("listening %s:%d\n" % (ip, s.getsockname()[1]))
    sys.stdout.flush()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    while True:
        try:
            while os.waitpid(-1, os.WNOHANG)[0] > 0:
                pass
        except ChildProcessError:
            pass
        if not select.select([s], [], [], 1.0)[0]:
            continue
        try:
            c, _ = s.accept()
        except OSError:
            continue
        argv = [sys.executable, "-I", "-B", os.path.abspath(oomph.__file__), "serve", "--inetd"]
        pid = os.fork()
        if pid == 0:
            try:
                s.close()
                os.dup2(c.fileno(), 0)
                os.dup2(c.fileno(), 1)
                os.execv(argv[0], argv + (["--now", repr(now)] if now is not None else []))
            finally:
                os._exit(1)
        c.close()


# ------------------------------------------------------------------ oomph share …
SHARE_USAGE = """usage: oomph share on [--pair] [--any-network]   share this Mac with other machines (sudo)
       oomph share pair [--json]          a code that pairs one more viewer, valid 10 minutes (sudo)
       oomph share status [--json]        whether it is shared, on which networks, who is paired and reading
       oomph share revoke c-XXXXXXXX      end one viewer's access (sudo)
       oomph share networks               the networks sharing is on for, and those this Mac is on now
       oomph share allow CIDR | allow --remove CIDR   also a routed range, e.g. a tailnet (sudo)
       oomph share ai on|off              whether viewers may send this machine's data to an AI model
                                          (sudo; off unless turned on)
       oomph share off [--forget]         stop sharing; --forget also drops the key and every pairing (sudo)
       oomph share reload | purge         what install.sh and uninstall.sh --purge run"""


def role_ids():
    try:
        return pwd.getpwnam(ROLE).pw_uid, __import__("grp").getgrnam(ROLE).gr_gid
    except KeyError:
        raise ShareError("there is no %s account: sudo oomph share on creates it" % ROLE)


def as_service(sh, fn):
    """fn(RunDir) as the service account, its JSON answer back (at most 4 KiB): as root in a forked
    child that drops to _oomph (no other groups) before it touches run/, so a link planted there
    reaches nothing that account could not reach anyway. The parent parses that answer and nothing
    else that came out of run/. Unprivileged (the tests): in this process."""
    if os.geteuid() != 0:
        return fn(RunDir(sh.run))
    uid, gid = role_ids()
    r, w = os.pipe()
    pid = os.fork()
    if pid == 0:
        rc = 2
        try:
            os.close(r)
            os.setgroups([])
            os.setgid(gid)
            os.setuid(uid)
            if os.getuid() == 0 or os.geteuid() == 0:
                os._exit(3)
            write_all(w, dumps(fn(RunDir(sh.run)))[:4096])
            rc = 0
        finally:
            os._exit(rc)
    os.close(w)
    data, deadline = b"", time.monotonic() + 20
    try:
        while len(data) <= 4096 and time.monotonic() < deadline:
            if not select.select([r], [], [], max(0.0, deadline - time.monotonic()))[0]:
                break
            b = os.read(r, 4097 - len(data))
            if not b:
                break
            data += b
    finally:
        os.close(r)
    try:
        if os.waitpid(pid, os.WNOHANG)[0] == 0:
            time.sleep(0.2)
            if os.waitpid(pid, os.WNOHANG)[0] == 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    v = oomph.loads_untrusted(data) if len(data) <= 4096 else None
    if not isinstance(v, dict):
        raise ShareError("the service account's step failed")
    return v


def _mint(run):
    code, expires = new_code(), time.time() + PAIR_S
    with run.lock():
        run.write("pairing.json", {"code": code, "expires": expires, "left": PAIR_TRIES})
    run.summary()
    return {"code": code, "expires": expires}


def _revoke(cid):
    def fn(run):
        with run.lock():
            clients = run.clients(strict=True)
            if clients is None:
                return {"revoked": False, "unread": True}
            keep = [c for c in clients if c["id"] != cid]
            if len(keep) != len(clients):
                run.write("clients.json", keep)
        run.summary()
        return {"revoked": len(keep) != len(clients)}
    return fn


def _wipe(run):
    """Everything in run/ (as the service account): pairings, the code, the summary, the cache, conn/."""
    for n in run.names("conn"):
        run.remove(n, "conn")
    try:
        fd = run._fd()
        try:
            os.rmdir("conn", dir_fd=fd)
        finally:
            os.close(fd)
    except OSError:
        pass
    for n in run.names():
        run.remove(n)
    return {"wiped": True}


def _summary_read(run, cap=3800):
    """summary.json made to fit as_service's 4 KiB answer: short names, whole seconds, and as many
    viewers as fit, the rest counted in `more` (share status then says how many it leaves out)."""
    v = run.read("summary.json", cap=256 << 10)
    if not isinstance(v, dict):
        return {}

    def sec(t):
        return int(t) if oomph._num(t, 0, 1e11) else None
    clients = [{"id": c.get("id"), "name": clean(str(c.get("name") or ""), 24), "paired": sec(c.get("paired")),
                "last_seen": sec(c.get("last_seen")), "last_addr": clean(str(c.get("last_addr") or ""), 40)}
               for c in v.get("clients") or [] if isinstance(c, dict)][:256]
    reading = [{"client": r.get("client"), "peer": clean(str(r.get("peer") or ""), 40), "since": sec(r.get("since"))}
               for r in v.get("reading") or [] if isinstance(r, dict)][:64]
    out = {"v": 1, "clients": clients, "reading": reading, "more": 0,
           "pairing": v.get("pairing") if isinstance(v.get("pairing"), dict) else {}}
    while cap and len(dumps(out)) > cap and (out["clients"] or out["reading"]):
        if out["reading"] and len(out["reading"]) >= len(out["clients"]):
            out["reading"].pop()
        else:
            out["clients"].pop()
            out["more"] += 1
    return out


def check_installed():
    """`share on` serves the installed, root-owned code: it must be there, have root out of the
    shared ledger folder (H0) and speak this protocol (asked of the code, not of a version string)."""
    lib = os.path.join(oomph.PATHS_HERE["libexec"], "oomph.py")
    r = _run([oomph.PY, "-I", "-B", lib, "version", "--json"]) if os.path.exists(lib) else None
    v = oomph.loads_untrusted((r.stdout or "").strip()) if r is not None and r.returncode == 0 else None
    if not isinstance(v, dict):
        raise ShareError("the logger is not installed: Activate in the app (or sudo ./install.sh) first")
    if not (isinstance(v.get("hardening"), int) and v["hardening"] >= 1 and
            isinstance(v.get("sharing"), int) and v["sharing"] >= 1):
        raise ShareError("the installed logger is too old to share: Update in the app (or sudo ./install.sh) first")


def ensure_account():
    """The role account _oomph and its own group _oomph (roadmap 01 §4.2): the group first, then
    the account in it (sysadminctl picks a free id in its role range). Then what was built is
    asserted: the account's group is _oomph and not staff, the group has no other members, the home
    is /var/empty. Otherwise what this run created is removed and sharing is refused: key.pem is
    protected by that group alone. Returns (uid, gid)."""
    import grp
    made = []

    def ident(*args):
        r = _run(["/usr/bin/id"] + list(args) + [ROLE])
        return r.stdout.strip() if r.returncode == 0 else None
    try:
        try:
            grp.getgrnam(ROLE)
        except KeyError:
            r = _run(["/usr/sbin/dseditgroup", "-o", "create", "-r", oomph.CMD + " sharing", ROLE])
            if r.returncode != 0:
                raise ShareError("could not create the group %s: %s" % (ROLE, clean(r.stderr.strip(), 200)))
            made.append("group")
        out = _run(["/usr/bin/dscl", ".", "-read", "/Groups/" + ROLE, "PrimaryGroupID"]).stdout
        m = re.search(r"PrimaryGroupID:\s*(\d+)", out)
        if not m:
            raise ShareError("the group %s has no id" % ROLE)
        gid = int(m.group(1))
        if ident("-u") is None:
            base = ["/usr/sbin/sysadminctl", "-addUser", ROLE, "-fullName", oomph.CMD + " sharing", "-roleAccount",
                    "-GID", str(gid), "-home", "/var/empty", "-shell", "/usr/bin/false"]
            r = _run(base)
            if ident("-u") is None:  # an older sysadminctl that wants the id: a free one of the role range
                used = _run(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"]).stdout.split()
                free = next((u for u in range(450, 500) if str(u) not in used), None)
                if free is not None:
                    r = _run(base[:5] + ["-UID", str(free)] + base[5:])
            for _ in range(10):
                if ident("-u") is not None:
                    break
                time.sleep(0.5)
            if ident("-u") is None:
                raise ShareError("could not create the account %s: %s" % (ROLE, clean((r.stderr or r.stdout).strip(), 200)))
            made.append("user")
        uid = int(ident("-u"))
        members = _run(["/usr/bin/dscl", ".", "-read", "/Groups/" + ROLE, "GroupMembership"]).stdout
        others = [x for x in members.partition(":")[2].split() if x != ROLE]
        home = _run(["/usr/bin/dscl", ".", "-read", "/Users/" + ROLE, "NFSHomeDirectory"]).stdout
        if ident("-gn") != ROLE or int(ident("-g") or -1) != gid or others or "/var/empty" not in home or uid == 0:
            raise ShareError("the account %s is not what sharing needs (its group must be %s, with no other "
                             "members, and its home /var/empty)" % (ROLE, ROLE))
        lock_account()
        return uid, gid
    except ShareError:
        if "user" in made:
            _run(["/usr/sbin/sysadminctl", "-deleteUser", ROLE])
        if "group" in made:
            _run(["/usr/sbin/dseditgroup", "-o", "delete", ROLE])
        raise


def lock_account():
    """Nobody signs in as _oomph: no password (`*`), no AuthenticationAuthority, hidden from the
    login window. Whatever this macOS's sysadminctl left, it is set here every time, and then
    asserted: an empty password must not authenticate (key.pem is protected by that account's
    group alone)."""
    path = "/Users/" + ROLE
    _run(["/usr/bin/dscl", ".", "-create", path, "Password", "*"])
    _run(["/usr/bin/dscl", ".", "-create", path, "IsHidden", "1"])
    if "AuthenticationAuthority:" in _run(["/usr/bin/dscl", ".", "-read", path, "AuthenticationAuthority"]).stdout:
        _run(["/usr/bin/dscl", ".", "-delete", path, "AuthenticationAuthority"])
    pw = _run(["/usr/bin/dscl", ".", "-read", path, "Password"]).stdout
    if not re.search(r"Password:\s*\*\s*$", pw) or _run(["/usr/bin/dscl", ".", "-authonly", ROLE, ""], 10).returncode == 0:
        raise ShareError("the account %s could be signed in to: refusing to share" % ROLE)


def ensure_root_dir(sh):
    """The share folder alone (root's, 755), for a setting made before sharing was ever on."""
    old = os.umask(0o022)
    try:
        os.makedirs(sh.path, mode=0o755, exist_ok=True)
    finally:
        os.umask(old)


def ensure_dirs(sh, uid, gid):
    """The share folder (root's, 755) and run/ in it (the service's, 755): created if missing,
    otherwise checked, never chowned by path."""
    old = os.umask(0o022)
    try:
        os.makedirs(sh.path, mode=0o755, exist_ok=True)
    finally:
        os.umask(old)
    dfd = os.open(sh.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.fstat(dfd)
        if st.st_uid != sh.owner or st.st_mode & 0o022:
            raise ShareError("%s must be root's and writable by nobody else" % sh.path)
        try:
            os.mkdir("run", 0o755, dir_fd=dfd)
            if not sh.test:
                os.chown("run", uid, gid, dir_fd=dfd, follow_symlinks=False)
            os.chmod("run", 0o755, dir_fd=dfd)  # just made, in root's own folder
        except FileExistsError:
            pass
        st = os.stat("run", dir_fd=dfd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:
            raise ShareError("%s/run is not the service's folder" % sh.path)
    finally:
        os.close(dfd)


def share_plist(port):
    import plistlib
    return plistlib.dumps({
        "Label": LABEL, "UserName": ROLE, "GroupName": ROLE,
        "ProgramArguments": [oomph.PY, "-I", "-B", os.path.join(oomph.PATHS_HERE["libexec"], "oomph.py"),
                             "serve", "--inetd"],
        "Sockets": {"Listeners": {"SockServiceName": str(port)}},
        "inetdCompatibility": {"Wait": False, "Instances": 12},
        "StandardErrorPath": "/dev/null", "Nice": 5, "LowPriorityIO": True})


def install_service(port):
    _run(["/bin/launchctl", "bootout", "system/" + LABEL])
    _write_root_file(os.path.dirname(SHARE_PLIST), os.path.basename(SHARE_PLIST), share_plist(port), 0o644, 0)
    _run(["/bin/launchctl", "enable", "system/" + LABEL])
    r = _run(["/bin/launchctl", "bootstrap", "system", SHARE_PLIST])
    if r.returncode != 0:
        raise ShareError("launchctl bootstrap failed: %s" % clean((r.stderr or r.stdout).strip(), 200))
    if not warm_service(port):  # best effort: say so, but the service is installed
        sys.stderr.write("oomph: the sharing service did not answer within %d s (oomph share status)\n" % WARM_S)


def warm_service(port, wait=WARM_S):
    """Start the service once and wait until it ran: connect on loopback, send nothing, half-close,
    and wait for it to close (True), at most `wait` seconds (False). The first interpreter of a new
    role account through the /usr/bin/python3 shim took 14 to 26 s on CI runners
    (tools/spike_role_account.sh), longer than a viewer's 10 s for the TLS handshake: the first
    viewer met that start and timed out. Best effort; root opens no file here."""
    deadline = time.monotonic() + wait
    while time.monotonic() < deadline:
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=max(0.05, min(3.0, deadline - time.monotonic())))
        except OSError:  # not listening yet
            time.sleep(0.5)
            continue
        try:
            s.shutdown(socket.SHUT_WR)
            while time.monotonic() < deadline:
                s.settimeout(max(0.05, deadline - time.monotonic()))
                if not s.recv(4096):
                    return True
        except socket.timeout:
            pass
        except OSError:  # reset: it ran and is gone
            return True
        finally:
            s.close()
        return False
    return False


def remove_service():
    _run(["/bin/launchctl", "bootout", "system/" + LABEL])
    try:
        os.unlink(SHARE_PLIST)
    except OSError:
        pass


def _when(t):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(t)) if oomph._num(t, 0, 1e11) else "never"


def _net_line(n):
    via = "via %s (%s)" % (n.get("router"), n.get("mac") or "?") if n.get("router") else "no router (a cable)"
    return "%-6s %-18s %s" % (clean(str(n.get("if")), 16), clean(str(n.get("net")), 43), clean(via, 80))


def share_status(sh):
    """What `share status` shows: config.json (root's) and summary.json (display data: ids checked,
    names cleaned). Read by root only through the service account."""
    cfg = sh.config()
    unread = False
    try:
        s = as_service(sh, _summary_read if os.geteuid() == 0 else lambda run: _summary_read(run, None)) \
            if os.path.isdir(sh.run) else {}
    except ShareError:
        s, unread = {}, True
    clients = [{"id": c["id"], "name": clean(str(c.get("name") or ""), 64), "paired": c.get("paired"),
                "last_seen": c.get("last_seen"), "last_addr": clean(str(c.get("last_addr") or ""), 64)}
               for c in (s.get("clients") if isinstance(s.get("clients"), list) else [])
               if isinstance(c, dict) and isinstance(c.get("id"), str) and CLIENT_ID.fullmatch(c["id"])][:256]
    reading = [{"client": r["client"], "peer": clean(str(r.get("peer") or ""), 64), "since": r.get("since")}
               for r in (s.get("reading") if isinstance(s.get("reading"), list) else [])
               if isinstance(r, dict) and isinstance(r.get("client"), str) and CLIENT_ID.fullmatch(r["client"])][:64]
    p = s.get("pairing") if isinstance(s.get("pairing"), dict) else {}
    pairing = {"active": p.get("active") is True and oomph._num(p.get("expires"), time.time(), 1e11),
               "expires": p.get("expires") if oomph._num(p.get("expires"), 0, 1e11) else None,
               "left": p.get("left") if isinstance(p.get("left"), int) and 0 <= p["left"] <= PAIR_TRIES else None}
    return {"on": cfg.get("on") is True, "port": cfg.get("port") if isinstance(cfg.get("port"), int) else PORT,
            "networks": [n for n in cfg.get("networks") or [] if isinstance(n, dict)],
            "allow": [str(a) for a in cfg.get("allow") or []], "allow_too_wide": _too_wide(cfg.get("allow")),
            "any_network": cfg.get("any_network") is True,
            "ai": oomph.switched_on(cfg.get("ai")), "pairing": pairing, "clients": clients, "reading": reading,
            "more": s.get("more") if isinstance(s.get("more"), int) and 0 <= s["more"] <= 256 else 0,
            "unread": unread, "service": sh.test or sys.platform != "darwin" or os.path.exists(SHARE_PLIST),
            "fp": _public_fp(sh), "host": local_name()}


def _too_wide(allow):
    """The allowed ranges of config.json that `share allow` would refuse now (written before 1.14.1): the gate
    still lets them in, so `share status` and `share on` name them, with the command that removes them."""
    out = []
    for a in allow if isinstance(allow, list) else []:
        try:
            if allow_too_wide(ipaddress.ip_network(a, strict=False)):
                out.append(str(a))
        except (ValueError, TypeError):
            continue
    return out[:16]


def _print_too_wide(rngs):
    for a in rngs:
        print("%s is allowed, but share allow refuses it now (wider than a /8 or an IPv6 /32, or standing for IPv4 "
              "hosts). To remove it:\n  sudo oomph share allow %s --remove" % (clean(a, 43), clean(a, 43)))


def _public_fp(sh):
    """This machine's key as viewers see it (sha256:…), for comparing when pairing; None without one.
    cert.pem is public (root's, 644); read only when it is root's (or the tester's) and bounded."""
    try:
        st = os.stat(sh.cert, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != sh.owner or st.st_size > 16 << 10:
            return None
        return "sha256:" + sh.fp().hex()
    except (OSError, ValueError, AttributeError):  # AttributeError: a Python without ssl
        return None


def print_status(st):
    if not st["on"]:
        print("Sharing is off. " + (LINUX_NOTE if sys.platform.startswith("linux") else  # (no share on there: 1.14.1)
                                    "To share this Mac: sudo oomph share on --pair"))
    elif not st["service"]:
        print("Sharing is on, but its service is not installed (the logger was deactivated): Activate in the "
              "app, or sudo oomph share on, brings it back")
    else:
        print("Sharing is on (port %d)%s" % (st["port"], ", on every network" if st["any_network"] else
                                             ", on these networks:" if st["networks"] else ", on no network yet"))
        for n in st["networks"]:
            print("  " + _net_line(n))
        if st["allow"]:
            print("Also allowed: " + ", ".join(clean(a, 43) for a in st["allow"]))
        _print_too_wide(st["allow_too_wide"])
    print("AI analysis of this machine's data by viewers: %s" % ("allowed" if st["ai"] else
                                                                 "not allowed (sudo oomph share ai on)"))
    p = st["pairing"]
    if p["active"]:
        print("A pairing code is active until %s (%s tries left)." % (_when(p["expires"])[11:], p["left"]))
    if st["clients"]:
        print("Paired viewers:")
        for c in st["clients"]:
            print("  %s  %-24s last seen %s%s" % (c["id"], c["name"] or "viewer", _when(c["last_seen"]),
                                                  " from " + c["last_addr"] if c["last_addr"] else ""))
    if st["more"]:
        print("  … and %d more: oomph share status, without sudo, lists them all" % st["more"])
    if st["unread"]:
        print("The service's state could not be read: the viewers are not listed.")
    elif not st["clients"] and st["on"]:
        print("No viewer is paired yet: sudo oomph share pair")
    for r in st["reading"]:
        print("Reading now: %s from %s since %s" % (r["client"], r["peer"], _when(r["since"])[11:]))


def local_name():
    """The name viewers on the same network reach this machine by: its host name's first label, .local."""
    return socket.gethostname().split(".")[0] + ".local"


def pair_link(code, port=PORT):
    """What Share this Mac shows and Copy link copies: address and code in one paste (roadmap 01 §3.7)."""
    return "oomph://%s@%s%s" % (show_code(code), local_name(), "" if port == PORT else ":%d" % port)


def print_code(code, expires, as_json, port=PORT):
    if as_json:
        print(json.dumps({"code": show_code(code), "expires": expires, "link": pair_link(code, port),
                          "host": local_name(), "port": port}))
        return
    print("Pairing code: %s   (valid until %s, for one viewer, 5 tries)" % (show_code(code), _when(expires)[11:]))
    print("On the viewer: oomph remote add %s   (it asks for the code; not on the command line, where "
          "other users of that Mac could read it)" % local_name())
    print("Or as one link (address and code): %s" % pair_link(code, port))


def _port(cfg):
    return cfg.get("port") if isinstance(cfg.get("port"), int) and 0 < cfg["port"] < 65536 else PORT


def cmd_share(args):
    sub, rest = (args[0] if args else ""), args[1:]
    sh = ShareDir()
    admin = sh.test or os.geteuid() == 0
    takes = {"on": ((), ("--pair", "--any-network", "--json"), 0), "off": ((), ("--forget",), 0),
             "pair": ((), ("--json",), 0), "status": ((), ("--json",), 0), "revoke": ((), (), 1),
             "networks": ((), ("--json",), 0), "allow": ((), ("--remove",), 1), "ai": ((), (), 1),
             "reload": ((), (), 0), "purge": ((), (), 0)}
    if sub not in takes:
        sys.stderr.write(SHARE_USAGE + "\n")
        return 0 if sub in ("", "-h", "--help", "help") else 2
    try:
        o, pos = oomph._strict(rest, *takes[sub][:2], npos=takes[sub][2])
        if takes[sub][2] and len(pos) != 1:
            raise oomph.UsageError("%s takes one argument" % sub)
    except oomph.UsageError as e:
        return oomph._usage_error("share " + sub, e, SHARE_USAGE)
    if sub not in ("status", "networks") and not admin:
        sys.stderr.write("oomph: share %s needs an administrator: sudo oomph share %s\n" % (sub, " ".join(args[:1])))
        return 1
    if sub == "revoke" and not CLIENT_ID.fullmatch(pos[0]):  # never echoed: it may be anything
        sys.stderr.write("oomph: share revoke takes a viewer's id (c- and eight hex digits): see oomph share status\n")
        return 2
    if sub == "ai" and pos[0] not in ("on", "off"):
        return oomph._usage_error("share ai", "on or off", SHARE_USAGE)
    try:
        return _share(sh, sub, o, pos)
    except ShareError as e:
        sys.stderr.write(oomph.wrap("oomph: share %s: %s" % (sub, e)) + "\n")
        return 1
    except OSError as e:
        sys.stderr.write("oomph: share %s: %s\n" % (sub, e))
        return 1


def _share(sh, sub, o, pos):
    mac = sys.platform == "darwin" or sh.test
    if sub == "status":
        st = share_status(sh)
        print(json.dumps(st)) if "--json" in o else print_status(st)
        return 0
    if sub == "networks":
        cfg = sh.config()
        now = current_networks()
        if "--json" in o:
            print(json.dumps({"allowed": cfg.get("networks") or [], "here": now,
                              "allow": cfg.get("allow") or [], "any_network": cfg.get("any_network") is True}))
            return 0
        print("Sharing is on for:" if cfg.get("networks") else "Sharing is on for no network.")
        for n in cfg.get("networks") or []:
            print("  " + _net_line(n))
        print("This machine is on:")
        for n in now:
            print("  %s%s" % (_net_line(n), "   (allowed)" if network_allowed(n, cfg.get("networks")) else ""))
        return 0
    if sub == "ai":
        ensure_root_dir(sh)
        cfg = dict(sh.config(), v=1, ai=pos[0] == "on")
        sh.write_config(cfg)
        print("Viewers may now send this machine's data to an AI model they use." if cfg["ai"] else
              "Viewers may not send this machine's data to an AI model (the default).")
        return 0
    if not mac:
        raise ShareError(LINUX_NOTE)
    if sub == "on":
        if not sh.test:
            check_installed()
        uid, gid = (os.geteuid(), os.getegid()) if sh.test else ensure_account()
        ensure_dirs(sh, uid, gid)
        if not (os.path.exists(sh.key) and os.path.exists(sh.cert)):
            make_key(sh, gid)
        else:
            fix_key(sh, gid)
        cfg = sh.config()
        nets = [n for n in cfg.get("networks") or [] if isinstance(n, dict)]
        added = [n for n in current_networks() if not network_allowed(n, nets)]
        nets += [dict(n, added=time.time()) for n in added]
        cfg.update(v=1, on=True, port=cfg.get("port") if isinstance(cfg.get("port"), int) else PORT, networks=nets,
                   allow=cfg.get("allow") or [], any_network=bool(cfg.get("any_network")) or "--any-network" in o,
                   ai=cfg.get("ai") is True)
        sh.write_config(cfg)
        if not sh.test:
            install_service(cfg["port"])
        print("Sharing is on (port %d), read-only: paired viewers see what any user of this Mac can read in "
              "its logs, process names, project folders and purposes included." % cfg["port"])
        print("On every network." if cfg["any_network"] else "On these networks:")
        for n in nets if not cfg["any_network"] else []:
            print("  " + _net_line(n))
        _print_too_wide(_too_wide(cfg["allow"]))
        if not cfg["any_network"] and any(n.get("router") and not n.get("mac") for n in nets):
            print(oomph.wrap("A router's hardware address (?) could not be read: that network is recognised by "
                             "its router's address and subnet alone, which other networks with the same plan "
                             "share (every home router of one brand, say). On a Mac that moves, SSH is the "
                             "safer route."))
        model = _run(["/usr/sbin/sysctl", "-n", "hw.model"]).stdout if sys.platform == "darwin" else ""
        if "Book" in model:
            print(oomph.wrap("This Mac moves. On other networks nothing is read, but the port answers; to watch a "
                             "laptop, SSH needs no extra listener (oomph remote add USER@HOST on the viewer)."))
        if "--pair" in o:
            r = as_service(sh, _mint)
            if norm_code(r.get("code")) != r.get("code"):
                raise ShareError("no pairing code came back")
            print_code(r["code"], r.get("expires"), "--json" in o, cfg["port"])
        return 0
    if sub == "pair":
        if sh.config().get("on") is not True:
            raise ShareError("sharing is off: sudo oomph share on --pair")
        r = as_service(sh, _mint)
        if not r.get("code") or norm_code(r.get("code")) != r.get("code"):
            raise ShareError("no pairing code came back")
        print_code(r["code"], r.get("expires"), "--json" in o, _port(sh.config()))
        return 0
    if sub == "revoke":
        r = as_service(sh, _revoke(pos[0]))
        if r.get("revoked") is True:
            print("Revoked %s: its live connection ends within seconds, and it can't connect again." % pos[0])
            return 0
        if r.get("unread") is True:
            raise ShareError("the pairings could not be read just now: nothing was changed; try again")
        print("No viewer %s is paired (oomph share status lists them)." % pos[0])
        return 1
    if sub == "allow":
        try:
            net = ipaddress.ip_network(pos[0], strict=False)
        except ValueError:
            raise ShareError("not an address range: use e.g. 100.64.0.0/10")
        if net.prefixlen == 0:
            raise ShareError("that is every address: oomph share on --any-network means every network, "
                             "and still only neighbours")
        why = allow_too_wide(net)
        if why and "--remove" not in o:
            raise ShareError(why)
        cfg = sh.config()
        allow = [a for a in cfg.get("allow") or [] if a != str(net)]
        if "--remove" not in o:
            allow.append(str(net))
        cfg["allow"] = allow
        sh.write_config(cfg)
        print(("No longer allowed: %s" if "--remove" in o else "Also allowed: %s (peers there pass the gate; "
               "they still need a pairing)") % net)
        return 0
    if sub in ("off", "purge"):
        if not sh.test:
            remove_service()
        cfg = sh.config()
        if cfg:
            cfg["on"] = False
            sh.write_config(cfg)
        if "--forget" in o or sub == "purge":
            if os.path.isdir(sh.run):
                try:
                    as_service(sh, _wipe)
                except ShareError:
                    if sub != "purge":
                        raise
            for p in (sh.key, sh.cert):
                try:
                    os.unlink(p)
                except OSError:
                    pass
            try:
                os.rmdir(sh.run)
            except OSError:
                pass
        if sub == "purge":
            try:
                os.unlink(sh.config_path)
                os.rmdir(sh.path)
            except OSError:
                pass
            if not sh.test:
                _run(["/usr/sbin/sysadminctl", "-deleteUser", ROLE])
                _run(["/usr/sbin/dseditgroup", "-o", "delete", ROLE])
            print("Sharing removed: service, key, pairings and the %s account." % ROLE)
            return 0
        print("Sharing is off%s." % (": the key and every pairing are gone; viewers must pair again"
                                     if "--forget" in o else " (key and pairings kept: share on brings it back)"))
        return 0
    if sub == "reload":
        cfg = sh.config()
        if cfg.get("on") is True and not sh.test:
            install_service(cfg.get("port") if isinstance(cfg.get("port"), int) else PORT)
            print("oomph: sharing service reloaded")
        return 0
    return 2


SERVE_USAGE = ("usage: oomph serve --stdio [--now T]   (the protocol on stdin and stdout)\n"
               "       oomph serve --inetd [--now T]   (one TLS connection on fd 0: the share service)\n"
               "       oomph serve --listen ADDR:PORT [--now T]   (accept and serve; loopback unless shared)")


def cmd_serve(args):
    now = None
    mode = args[0] if args else ""
    rest = args[1:]
    if mode == "--listen" and rest:
        spec, rest = rest[0], rest[1:]
    if mode not in ("--stdio", "--inetd", "--listen") or \
            rest and (len(rest) != 2 or rest[0] != "--now") or mode == "--listen" and not args[1:]:
        sys.stderr.write(SERVE_USAGE + "\n")
        return 2
    if rest:
        try:
            now = float(rest[1])
        except ValueError:
            pass
        if now is None or not math.isfinite(now) or not 0 < now < 1e11:
            sys.stderr.write("oomph: serve: --now takes a unix time\n")
            return 2
    if mode == "--inetd":
        return serve_inetd(now)
    if mode == "--listen":
        return serve_listen(spec, now)
    drop_root()
    # The protocol owns the descriptors it was given; whatever else prints (a warning, a
    # traceback) goes to stderr and can never land inside a frame.
    in_fd, out_fd = os.dup(0), os.dup(1)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.dup2(2, 1)
    os.close(devnull)
    try:
        return serve(in_fd, out_fd, Server(now=now, ai_watch=AiWatch()))
    except (BrokenPipeError, ConnectionResetError):
        return 0
