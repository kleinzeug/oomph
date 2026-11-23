"""oomph's viewing side (roadmap 01 §4.3, §5.6–§5.7, §6.1): the protocol's client, coverage and
the mirror writer.

    oomph remote sync --once [--into DIR] [--json] [-- COMMAND …]

starts COMMAND (by default this machine's own `oomph serve --stdio`), talks the protocol to it over
its standard streams and mirrors what it answers into a directory: one machine's log and ledger
directories, as every reader already knows them, beside machine.json, status.json and sync.json.
Without --into the mirror is …/oomph/machines/<machine id>/ (OOMPH_MACHINES_DIR overrides the
base). The engine that keeps connections open, TCP, pairing and SSH come later; this is the core
they will share.

A mirror never claims more than it holds: `have` in sync.json is the coverage map, the stretches of
the remote's time for which the mirror holds everything the remote had, and it grows only by what
a completed reply vouched for. Everything from the other end is untrusted: parsed with the limits
of oomph.loads_untrusted, strings stripped of control and direction characters, samples and
records with numbers out of range dropped and counted, ids and dates checked before they name a
file. Every file is written to a fresh temporary file renamed into place, never through a name that
exists, inside directories opened without following links; nothing is appended in place.
Standard library only; Python 3.9.
"""
import base64
import calendar
import contextlib
import fcntl
import gzip
import hashlib
import hmac
import io
import ipaddress
import json
import math
import os
import re
import secrets
import select
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import zlib

import oomph
import oomph_net as net

MID = re.compile(r"m-[0-9a-f]{16}(-[0-9a-f]{8})?")
DAY = re.compile(r"\d{4}-\d{2}-\d{2}")
WINDOW_S = 6 * 3600            # holes are fetched in windows this long, newest first
RECENT_S = 24 * 3600           # ... the last day before anything older
OVERLAP_S = 600                # every session reaches this far back into what the mirror has
RETENTION_S = 14 * 86400
INCIDENT_KEEP_S = 90 * 86400
MIRROR_CAP = 50 << 20          # a mirror's bytes at most
HELLO_TIMEOUT_S = 20
CALL_TIMEOUT_S = 60
NOISE = (64 << 10, 200)        # what may precede the answer to hello: bytes, lines
MAX_PAGES = 20000              # requests per run, whatever the other end says


class SyncError(Exception):
    """The sync failed; `code` is one of status.json's errors (roadmap 01 §5.7)."""

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        self.code, self.detail = code, detail


# ------------------------------------------------------------------ coverage
class Coverage:
    """Sorted, disjoint closed intervals [a, b] of remote time: the coverage map (`have`), and
    the same arithmetic for `gone`."""

    def __init__(self, spans=()):
        self.spans = []
        for a, b in spans:
            self.add(a, b)

    def add(self, a, b):
        if not (b > a):
            return
        out, placed = [], False
        for x, y in self.spans:
            if y < a:
                out.append([x, y])
            elif x > b:
                if not placed:
                    out.append([a, b])
                    placed = True
                out.append([x, y])
            else:
                a, b = min(a, x), max(b, y)
        if not placed:
            out.append([a, b])
        self.spans = sorted(out)

    def remove(self, a, b):
        if not (b > a):
            return
        out = []
        for x, y in self.spans:
            if y < a or x > b:
                out.append([x, y])
                continue
            if x < a:
                out.append([x, a])
            if y > b:
                out.append([b, y])
        self.spans = out

    def holes(self, lo, hi):
        """The parts of [lo, hi] not covered, oldest first."""
        out, at = [], lo
        for x, y in self.spans:
            if y < at:
                continue
            if x > hi:
                break
            if x > at:
                out.append([at, min(x, hi)])
            at = max(at, y)
        if at < hi:
            out.append([at, hi])
        return out

    def covers(self, a, b):
        return any(x <= a and b <= y for x, y in self.spans)

    def end(self):
        return self.spans[-1][1] if self.spans else None


def windows(holes, recent_from):
    """The order a hole is fetched in (roadmap 01 §6.1): the parts within the last day first,
    then the older ones, each newest first in windows of WINDOW_S counted back from the hole's
    right edge."""
    def cut(spans):
        out = []
        for a, b in sorted(spans, key=lambda h: -h[1]):
            while b > a:
                out.append([max(a, b - WINDOW_S), b])
                b -= WINDOW_S
        return out
    recent = [[max(a, recent_from), b] for a, b in holes if b > recent_from]
    older = [[a, min(b, recent_from)] for a, b in holes if a < recent_from]
    return cut(recent) + cut(older)


# ------------------------------------------------------------------ what is let in
def clean(v, cut=200, depth=16):
    """A value from the wire with its strings cleaned (net.clean) and cut, its keys too; None
    for anything nested deeper than `depth`."""
    if isinstance(v, dict):
        return {net.clean(k, 64): clean(x, cut, depth - 1) for k, x in v.items()} if depth > 0 else None
    if isinstance(v, list):
        return [clean(x, cut, depth - 1) for x in v] if depth > 0 else None
    if isinstance(v, str):
        return net.clean(v, cut)
    return v


DISK_GB = float(1 << 20)  # a disk's size or free space: up to a pebibyte, whatever the RAM


def gb_ok(row, ram, disk_keys=("disk_free_gb",)):
    """Every gb and *_gb number of a row (and of the dicts in it) finite and between 0 and 16 times the
    machine's RAM, at most 65,536 (roadmap 01 §4.3: what the chart can be handed is bounded); the
    sizes of disks (`disk_free_gb`, anything in a `disks` block, and in an event the `free_gb` of the
    disk it is about: `disk_keys`) up to DISK_GB instead, since a disk is bigger than 16 times the
    RAM of most Macs."""
    top = min(16 * ram, 65536.0) if oomph._num(ram, 0.1, 65536) else 65536.0
    stack = [(row, top)]
    while stack:
        x, lim = stack.pop()
        if isinstance(x, dict):
            for k, v in x.items():
                if isinstance(k, str) and (k == "gb" or k.endswith("_gb")) and v is not None and \
                        not oomph._num(v, 0, DISK_GB if k in disk_keys else lim):
                    return False
                if isinstance(v, (dict, list)):
                    stack.append((v, DISK_GB if k == "disks" else lim))
        elif isinstance(x, list):
            stack.extend((y, lim) for y in x)
    return True


class Ingest:
    """The checks at ingest, against what the machine said about itself."""

    def __init__(self, machine):
        self.now = machine["now"]
        self.oldest = machine.get("oldest")
        self.ram = machine.get("ram_gb")
        self.dropped = {"samples": 0, "records": 0}

    def time_ok(self, t, slack_back=86400):
        """A time between the remote's oldest sample minus `slack_back` (None: any time after
        1970) and its now plus five minutes."""
        lo = 0 if slack_back is None else (self.oldest if self.oldest is not None else self.now - RETENTION_S) - slack_back
        return oomph._num(t, 0, 1e11) and lo <= t <= self.now + 300

    def row(self, line, kind, times=("t",), cut=200, back=86400):
        """(the bytes to write, the parsed row) for one line of a page, or None when it fails
        the checks (counted). A sample's or record's times must lie within the remote's history
        (`back`: how far before its oldest sample; None: any past time), every *_gb within range.
        Clean rows are written exactly as they came."""
        v = oomph.loads_untrusted(line)
        ok = isinstance(v, dict) and oomph._t(v.get(times[0])) and \
            all(k not in v or v[k] is None or self.time_ok(v[k], back) for k in times)
        if ok and kind == "samples":
            ok = gb_ok(v, v.get("ram_gb") if oomph._num(v.get("ram_gb"), 0.1, 65536) else self.ram)
        elif ok:
            segs = v.get("segments") if isinstance(v.get("segments"), list) else []
            ok = gb_ok(v, self.ram, ("disk_free_gb", "free_gb") if kind == "events" else ("disk_free_gb",)) and \
                all(self.time_ok(x.get("t"), back) for x in segs if isinstance(x, dict))
        if not ok:
            self.dropped["samples" if kind == "samples" else "records"] += 1
            return None
        c = clean(v, cut)
        return (line if c == v else net.dumps(c)), c


# ------------------------------------------------------------------ the mirror
class Mirror:
    """One machine's mirror directory (roadmap 01 §4.3):

        machine.json  status.json  sync.json
        log/          an OOMPH_DIR: current.json, samples-DAY.jsonl[.gz], events.jsonl, incidents/ID/incident.json
        ledger/       an OOMPH_LEDGER_DIR: ledger.json, reservations.jsonl

    Directories are created 0700 and opened without following a link; files are written to a
    temporary file with a random name, created exclusively, and renamed over their name."""

    def __init__(self, path):
        _not_root()
        self.path = os.path.abspath(path)
        old = os.umask(0o077)
        try:
            os.makedirs(self.path, mode=0o700, exist_ok=True)
        finally:
            os.umask(old)
        st = os.lstat(self.path)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise SyncError("mirror", "%s is not a directory of mine" % self.path)
        self.written = 0

    def _dir(self, sub):
        """A descriptor of the mirror's subdirectory `sub` ("", "log", "log/incidents/ID", …),
        each part created 0700 if missing and opened without following a link."""
        fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        for part in [p for p in sub.split("/") if p]:
            if part in (".", "..") or "/" in part:
                os.close(fd)
                raise SyncError("mirror", "bad path %r" % sub)
            try:
                os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError:
                pass
            try:
                nfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            finally:
                os.close(fd)
            fd = nfd
        return fd

    def write(self, sub, name, data, gz=False):
        if gz:
            buf = io.BytesIO()
            with gzip.GzipFile(filename="", mode="wb", fileobj=buf, mtime=0) as g:
                g.write(data)
            data = buf.getvalue()
        fd = self._dir(sub)
        try:
            try:
                was = os.stat(name, dir_fd=fd, follow_symlinks=False).st_size
            except OSError:
                was = 0
            if self.size() - was + len(data) > MIRROR_CAP:
                raise SyncError("mirror_full", "the mirror would pass %d MB" % (MIRROR_CAP >> 20))
            tmp = ".%s.%s.tmp" % (name, secrets.token_hex(8))
            out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
            try:
                try:
                    os.fchmod(out, 0o644)
                    net.write_all(out, data)
                finally:
                    os.close(out)
                os.rename(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
            except BaseException:
                try:
                    os.unlink(tmp, dir_fd=fd)
                except OSError:
                    pass
                raise
        finally:
            os.close(fd)
        self.written += len(data)
        self._size += len(data) - was

    def read(self, sub, name, cap=MIRROR_CAP):
        try:
            fd = self._dir(sub)
        except (OSError, SyncError):
            return None
        try:
            data = oomph.read_bounded(name, cap, fd)
        finally:
            os.close(fd)
        if data is not None and name.endswith(".gz"):
            try:
                data = gzip.decompress(data)
            except (OSError, EOFError, zlib.error):
                return None
        return data

    def remove(self, sub, name):
        try:
            fd = self._dir(sub)
        except (OSError, SyncError):
            return
        try:
            was = os.stat(name, dir_fd=fd, follow_symlinks=False).st_size
            os.unlink(name, dir_fd=fd)
            if self._size is not None:
                self._size -= was
        except OSError:
            pass
        finally:
            os.close(fd)

    def names(self, sub):
        try:
            fd = self._dir(sub)
        except (OSError, SyncError):
            return []
        try:
            return os.listdir(fd)
        finally:
            os.close(fd)

    _size = None

    def size(self):
        if self._size is None:
            n = 0
            for root, dirs, files in os.walk(self.path):
                for f in files:
                    try:
                        n += os.lstat(os.path.join(root, f)).st_size
                    except OSError:
                        pass
            self._size = n
        return self._size

    def json(self, sub, name):
        v = oomph.loads_untrusted(self.read(sub, name, 4 << 20))
        return v if isinstance(v, dict) else None

    def put_json(self, sub, name, obj):
        self.write(sub, name, net.dumps(obj) + b"\n")

    # -- days of samples
    def day_name(self, day):
        names = set(self.names("log"))
        for n in ("samples-%s.jsonl" % day, "samples-%s.jsonl.gz" % day):
            if n in names:
                return n
        return None

    def day_rows(self, day):
        """{t: line} of a mirrored day."""
        n = self.day_name(day)
        out = {}
        for line in (self.read("log", n) or b"").split(b"\n") if n else []:
            try:
                t = json.loads(line).get("t")
            except (ValueError, AttributeError):
                continue
            if oomph._t(t):
                out[t] = line
        return out

    def merge_day(self, day, rows, gz=None):
        """Merge rows {t: line} into a day file: deduplicated by t, in time order, written whole
        and renamed (a reader keyed on the file's identity reads it again from the start)."""
        old = self.day_name(day)
        have = self.day_rows(day)
        if rows and all(have.get(t) == b for t, b in rows.items()) and gz is None:
            return
        have.update(rows)
        gz = old is not None and old.endswith(".gz") if gz is None else gz
        name = "samples-%s.jsonl%s" % (day, ".gz" if gz else "")
        self.write("log", name, b"".join(have[t] + b"\n" for t in sorted(have)), gz=gz)
        if old and old != name:
            self.remove("log", old)

    def days(self):
        return sorted({m.group(1) for m in map(net.DAY_FILE.fullmatch, self.names("log")) if m})


def _not_root():
    if os.geteuid() == 0:
        raise SyncError("root", "oomph remote refuses to run as root")


def machines_dir():
    return os.environ.get("OOMPH_MACHINES_DIR") or os.path.join(oomph.STATE_DIR, "machines")


# ------------------------------------------------------------------ the client
class Link:
    """A protocol session with a server: on a child's standard streams (a pipe: `serve --stdio`
    here, or over ssh), or on a socket (TLS to a shared Mac). A child's stderr goes to a temporary
    file, its last line quoted when the session fails."""

    def __init__(self, argv=None, sock=None):
        self.p = self.sock = self.err = None
        self.cn = None
        if sock is not None:
            self.sock = sock
            self.stream = net.SockStream(sock)
            self.lines = net.Lines(self.stream, net.LINE_OUT)
        else:
            self.err = tempfile.TemporaryFile()
            try:
                self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                          close_fds=True)
            except OSError as e:
                self.err.close()
                raise SyncError("not_oomph", "can't start %s: %s" % (argv[0], e.strerror or e))
            self.stream = net.FdStream(self.p.stdin.fileno())
            self.lines = net.Lines(self.p.stdout.fileno(), net.LINE_OUT)
        self.next_id = 0
        self.notes, self.note_bytes, self.marks = [], 0, set()
        self.base = net._rss()

    def fileno(self):
        return self.lines.fd

    def ready(self):
        """Whether a notification can be had without waiting: one kept during a call, a whole line
        read already, or bytes the TLS layer decrypted that select() does not see."""
        return bool(self.notes) or self.lines.buffered() or self.lines.src.pending()

    def send(self, method, params=None):
        self.next_id += 1
        req = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        try:
            self.stream.send(net.dumps(req) + b"\n")
        except (OSError, net.Closed):
            raise SyncError("closed", "the other end closed the connection%s" % self.stderr_tail())
        return self.next_id

    def stderr_tail(self):
        if self.err is None:
            return ""
        try:
            self.err.seek(0, os.SEEK_END)
            n = self.err.tell()
            self.err.seek(max(0, n - 4096))
            last = [x for x in self.err.read().decode("utf-8", "replace").splitlines() if x.strip()]
        except OSError:
            return ""
        return (": " + net.clean(last[-1], 160)) if last else ""

    def exit_status(self, wait=0.0):
        """The child's exit status once it has ended (within `wait` seconds), else None."""
        if self.p is None:
            return None
        try:
            return self.p.wait(wait) if wait else self.p.poll()
        except subprocess.TimeoutExpired:
            return None

    def read(self, timeout):
        try:
            line = self.lines.read(timeout)
        except net.Closed as e:
            raise SyncError("closed", "the other end closed the connection (%s)%s" % (e, self.stderr_tail()))
        if line is None:
            raise SyncError("timeout", "no answer within %d s" % timeout)
        return line

    def hello_raw(self):
        """Say hello and skip whatever precedes the answer (a login banner, a shell's start-up
        output): at most NOISE[0] bytes and NOISE[1] lines (roadmap 01 §5.1). Returns (result,
        time sent, time answered)."""
        t0 = time.time()
        self.cn = os.urandom(16)
        rid = self.send("hello", {"proto": list(net.PROTO), "client": {"app": oomph.CMD, "version": oomph.VERSION,
                                                                       "os": sys.platform},
                                  "nonce": base64.b64encode(self.cn).decode()})
        skipped, lines, first = 0, 0, None
        deadline = time.monotonic() + HELLO_TIMEOUT_S
        self.lines.cap = NOISE[0]
        while True:
            try:
                line = self.lines.read(max(0.0, deadline - time.monotonic()))
            except net.Closed as e:
                if first is not None:
                    raise SyncError("not_oomph", "it answered with: %r" % net.clean(first, 80))
                raise SyncError("not_oomph", "nothing there speaks the protocol (%s)%s" % (e, self.stderr_tail()))
            if line is None:
                raise SyncError("timeout", "no answer to hello within %d s" % HELLO_TIMEOUT_S)
            msg = _json(line)
            if isinstance(msg, dict) and msg.get("id") == rid and ("result" in msg or "error" in msg):
                break
            first = line.decode("utf-8", "replace") if first is None else first
            skipped, lines = skipped + len(line) + 1, lines + 1
            if skipped > NOISE[0] or lines > NOISE[1]:
                raise SyncError("not_oomph", "it answered with: %r" % net.clean(first, 80))
        self.lines.cap = net.LINE_OUT
        t1 = time.time()
        if "error" in msg:
            e = msg["error"] if isinstance(msg["error"], dict) else {}
            if e.get("code") == net.ERR["proto"]:
                raise SyncError("incompatible", "its protocol versions %s do not overlap ours %s"
                                % (net.clean(json.dumps(e.get("data")), 60), list(net.PROTO)))
            raise SyncError("not_oomph", "hello refused: %s" % net.clean(str(e.get("message")), 120))
        r = msg["result"]
        if not (isinstance(r, dict) and r.get("proto") in range(net.PROTO[0], net.PROTO[1] + 1)):
            raise SyncError("incompatible", "an answer to hello this version does not understand")
        return r, t0, t1

    def hello(self, now=time.time):
        """hello over a pipe, where the transport is the authentication: the machine at once."""
        r, t0, t1 = self.hello_raw()
        if not isinstance(r.get("machine"), dict):
            raise SyncError("incompatible", "an answer to hello this version does not understand")
        return machine_of(r["machine"], t0, t1)

    def grown(self):
        """A link that grew by LINK_RSS_CAP (a peer that sends what parses large) leaves; the engine
        tries again later."""
        if net._rss() - self.base > LINK_RSS_CAP:
            raise SyncError("busy", "this link's process grew past %d MB: leaving, trying again later" % (LINK_RSS_CAP >> 20))

    def keep(self, msg, size):
        """A notification that came during a call, for note(): whole while NOTES_KEPT allow, after that
        only the name of one Live acts on (a trigger), once, and a tick or anything else not at all
        (the next tick's `prev` shows the hole, which is then fetched by range)."""
        if len(self.notes) < NOTES_KEPT[0] and self.note_bytes + size <= NOTES_KEPT[1]:
            self.notes.append(msg)
            self.note_bytes += size
            return
        m = msg.get("method")
        if m in TRIGGERS and m not in self.marks:
            self.marks.add(m)
            self.notes.append({"method": m})

    def call(self, method, params=None, timeout=CALL_TIMEOUT_S):
        """The answer to one request: each line within `timeout` seconds, and the answer within twice
        that since the request went out, however many notifications come meanwhile."""
        rid = self.send(method, params)
        deadline = time.monotonic() + 2 * timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise SyncError("timeout", "no answer to %s within %d s" % (net.clean(method, 32), 2 * timeout))
            line = self.read(min(timeout, max(0.05, left)))
            msg = _json(line)
            self.grown()
            if not isinstance(msg, dict):
                raise SyncError("not_oomph", "a line that is not a frame")
            if "id" not in msg:
                self.keep(msg, len(line))
                continue
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                e = msg["error"] if isinstance(msg["error"], dict) else {}
                raise net.RPCError(e.get("code"), net.clean(str(e.get("message")), 200), e.get("data"))
            return msg.get("result")

    def note(self, timeout):
        """The next notification: one that arrived during a call, else one read within `timeout`
        seconds; None when there is none (a stray answer is dropped)."""
        if self.notes:
            if not self.notes[1:]:
                self.note_bytes = 0
            n = self.notes.pop(0)
            if len(n) == 1:
                self.marks.discard(n.get("method"))
            return n
        try:
            line = self.lines.read(timeout)
        except net.Closed as e:
            raise SyncError("closed", "the other end closed the connection (%s)%s" % (e, self.stderr_tail()))
        msg = _json(line) if line is not None else None
        self.grown()
        return msg if isinstance(msg, dict) and "id" not in msg else None

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            return
        try:
            self.p.stdin.close()
        except OSError:
            pass
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.p.stdout.close()
        self.err.close()


def machine_of(m, t0, t1):
    """What a machine said about itself, cleaned, with the clock offset measured over the round
    trip that brought it (roadmap 01 §4.6) and how long that took."""
    m = clean(m, 200)
    if not oomph._num(m.get("now"), 0, 1e11):
        raise SyncError("not_oomph", "hello without the server's time")
    m["offset_s"] = round(m["now"] - (t0 + t1) / 2, 3)
    m["connect_ms"] = int((t1 - t0) * 1000)
    if not (m.get("oldest") is None or oomph._num(m["oldest"], 0, 1e11)):
        m["oldest"] = None
    m["caps"] = caps_of(m)
    return m


def _json(line):
    try:
        return json.loads(line, parse_constant=oomph._no_constant)
    except (ValueError, RecursionError):
        return None


def _rows(page):
    try:
        return net.unpack(page.get("data") if isinstance(page, dict) else None)
    except (ValueError, TypeError):
        raise SyncError("not_oomph", "a page that does not unpack")


def _next(page, after):
    c = net._cursor(page.get("next"))
    return c if c is not None else tuple(after)


def _day_of(row, tz_s):
    """The remote's day of a sample: its `iso` date (the logger's own day, right across a change
    of summer time) when that is the day of `t` at the remote's offset or one next to it, else
    the day of `t` at that offset."""
    days = [time.strftime("%Y-%m-%d", time.gmtime(row["t"] + tz_s + d)) for d in (0, -86400, 86400)]
    iso = row.get("iso")
    return iso[:10] if isinstance(iso, str) and iso[:10] in days else days[0]


def _incident_t(iid):
    """The time (UTC, as the id's digits read) an incident id names, or None for anything that is
    not an id or not a date: ids name folders and are read back as dates."""
    if not (isinstance(iid, str) and net.INCIDENT_ID.fullmatch(iid)):
        return None
    try:
        return calendar.timegm(time.strptime(iid, "%Y%m%d-%H%M%S"))
    except (ValueError, OverflowError):
        return None


def _tz_seconds(tz):
    m = re.fullmatch(r"([+-])(\d\d):(\d\d)", tz or "")
    return (1 if m.group(1) == "+" else -1) * (int(m.group(2)) * 3600 + int(m.group(3)) * 60) if m else 0


class Sync:
    """One run of `remote sync --once` over a Link into a Mirror, in the order of roadmap 01
    §6.1: the current sample, the ledger snapshot and the incidents (they end "fetching…"), the
    holes of the last day newest first, events and reservation records, the older holes."""

    def __init__(self, link, mirror, machine, max_bytes=net.PAGE):
        self.link, self.m, self.machine, self.max_bytes = link, mirror, machine, max_bytes
        self.ing = Ingest(machine)
        prev = mirror.json("", "sync.json") or {}
        self.state = {"v": 1, "have": [], "gone": [], "bad": [], "oldest": None, "samples_at": None,
                      "events_at": [0, 0], "reservations_at": [0, 0], "incidents_to": "", "incidents_open": [],
                      "synced": {"ledger": False, "reservations": False, "incidents": False},
                      "dropped": {"samples": 0, "records": 0}, "offset_s": 0}
        for k, v in prev.items():
            if k in self.state and isinstance(v, type(self.state[k])) or k in ("oldest", "samples_at"):
                self.state[k] = v
        self.have = Coverage(s for s in self.state["have"] if _span(s))
        self.gone = Coverage(s for s in self.state["gone"] if _span(s))
        self.pages = 0
        self.counts = {"samples": 0, "events": 0, "records": 0, "incidents": 0, "leases": 0}
        self.tz_s = _tz_seconds(machine.get("tz"))

    def call(self, method, params=None):
        self.pages += 1
        if self.pages > MAX_PAGES:
            raise SyncError("bad", "more than %d requests in one run" % MAX_PAGES)
        return self.link.call(method, params)

    def run(self):
        self.current()
        self.ledger()
        self.incidents()
        now = self.machine["now"]
        oldest = self.machine.get("oldest")
        lo = max(oldest if oldest is not None else now, now - RETENTION_S)
        if oldest is not None and self.have.spans and self.have.spans[0][0] < oldest:
            for a, b in self.have.holes(self.have.spans[0][0], oldest):
                self.gone.add(a, b)  # never received, and the remote no longer keeps it
        known = Coverage(self.have.spans)
        if known.spans:  # reach back into what the mirror has: a sample the logger wrote late
            known.spans[-1][1] = max(known.spans[-1][0], known.spans[-1][1] - OVERLAP_S)
        for a, b in self.gone.spans:
            known.add(a, b)
        holes = known.holes(lo, now)
        ws = windows(holes, now - RECENT_S)
        recent = [w for w in ws if w[1] > now - RECENT_S]
        for w in recent:
            self.samples(*w)
        self.events()
        self.reservations()
        for w in ws[len(recent):]:
            self.samples(*w)
        self.gzip_days()
        self.prune()
        self.state["oldest"] = oldest
        self.state["offset_s"] = self.machine.get("offset_s", 0)

    def current(self):
        r = self.call("subscribe", {"streams": []})
        cur = r.get("current") if isinstance(r, dict) else None
        if isinstance(cur, dict):
            got = self.ing.row(net.dumps(cur), "samples")
            if got:
                self.m.put_json("log", "current.json", got[1])
        self.state["current_skipped"] = bool(isinstance(r, dict) and r.get("current_skipped"))

    def ledger(self):
        r = self.call("ledger")
        rows = _rows(r)
        snap = oomph.loads_untrusted(rows[0]) if rows else None
        if not isinstance(snap, dict):
            raise SyncError("not_oomph", "a ledger snapshot that is not one")
        out = {"leases": [], "state": {}, "history": []}
        for k in ("leases", "history"):
            for x in snap.get(k) if isinstance(snap.get(k), list) else []:
                got = self.ing.row(net.dumps(x), "records", times=("requested", "granted", "ended", "seen"),
                                   back=None)
                if got:
                    out[k].append(got[1])
        if isinstance(snap.get("state"), dict):
            out["state"] = {k: v for k, v in clean(snap["state"]).items() if oomph._num(v) or k == "level"}
        self.m.put_json("ledger", "ledger.json", out)
        self.counts["leases"] = len(out["leases"])
        self.state["synced"]["ledger"] = True

    def incidents(self):
        after = self.state["incidents_to"] if _incident_t(self.state["incidents_to"]) is not None else ""
        refetch = [i for i in self.state["incidents_open"] if _incident_t(i) is not None]
        open_now = []
        while True:
            r = self.call("incidents", {"after": after, "max_bytes": self.max_bytes})
            if not isinstance(r, dict):
                raise SyncError("not_oomph", "incidents: an answer that is not an object")
            for line in _rows(r):
                inc = oomph.loads_untrusted(line)
                if isinstance(inc, dict) and _incident_t(inc.get("id")) is not None \
                        and self.ing.time_ok(inc.get("start"), INCIDENT_KEEP_S):
                    self.m.write("log/incidents/" + inc["id"], "incident.json", net.dumps(clean(inc)) + b"\n")
                    self.counts["incidents"] += 1
            nxt = r.get("next")
            ids = r.get("open") if isinstance(r.get("open"), list) else []
            open_now = [i for i in ids if _incident_t(i) is not None][:30]
            if not (_incident_t(nxt) is not None and nxt > after):
                break
            after = nxt
            if not r.get("more"):
                break
        if refetch:  # incidents that were open: their record changed since (fetched again until they close)
            prev = time.strftime("%Y%m%d-%H%M%S", time.gmtime(max(0, _incident_t(min(refetch)) - 1)))  # exclusive
            r = self.call("incidents", {"after": prev, "max_bytes": self.max_bytes})
            for line in _rows(r):
                inc = oomph.loads_untrusted(line)
                if isinstance(inc, dict) and inc.get("id") in refetch:
                    self.m.write("log/incidents/" + inc["id"], "incident.json", net.dumps(clean(inc)) + b"\n")
        self.state["incidents_to"] = after
        self.state["incidents_open"] = open_now
        self.state["synced"]["incidents"] = True

    def samples(self, a, b):
        """Fetch one window [a, b] of samples page by page, merge each page into its days, and
        extend the coverage by what the page vouched for."""
        after, start = (a, 0), a
        for _ in range(MAX_PAGES):
            try:
                r = self.call("samples", {"after": list(after), "to": b, "max_bytes": self.max_bytes})
            except net.RPCError as e:
                if e.code == net.ERR["retention"]:
                    old = e.data.get("oldest") if isinstance(e.data, dict) else None
                    self.gone.add(a, min(b, old) if oomph._num(old, 0, 1e11) else b)
                elif e.code == net.ERR["large"]:
                    self.bad(a, b, "too_large")
                else:
                    raise SyncError("not_oomph", "samples: %s" % e)
                return
            if not isinstance(r, dict):
                raise SyncError("not_oomph", "samples: an answer that is not an object")
            if after[1] and r.get("anchored") is False:  # the row we stood on is gone: ask by time
                after = (after[0], 0)
                continue
            by_day = {}
            for line in _rows(r):
                got = self.ing.row(line, "samples", cut=oomph.SLIM_STR)
                if got:
                    b2, row = got
                    by_day.setdefault(_day_of(row, self.tz_s), {})[row["t"]] = b2
                    self.counts["samples"] += 1
            for day, rows in by_day.items():
                if DAY.fullmatch(day):
                    self.m.merge_day(day, rows)
            to = r.get("to")
            if oomph._num(to, 0, 1e11) and to >= start:
                self.have.add(start, min(to, b))
            nxt = _next(r, after)
            if not r.get("more"):
                return
            if tuple(nxt) == tuple(after):  # a reply that does not move the cursor: never again
                self.bad(a, b, "stuck")
                return
            after, start = nxt, nxt[0]
        self.bad(a, b, "endless")

    def bad(self, a, b, why):
        self.state["bad"] = [x for x in self.state["bad"] if isinstance(x, dict)][-31:] + \
            [{"from": a, "to": b, "why": why, "tries": 1, "next": time.time() + 3600}]

    def paged(self, method, at_key, mirror, kind, times):
        """events or reservations: every page after the stored cursor, merged into one file."""
        after = tuple(self.state[at_key]) if net._cursor(self.state[at_key]) else (0.0, 0)
        sub, name = mirror
        existing = (self.m.read(sub, name) or b"").split(b"\n")
        rows = [x for x in existing if x]
        seen = {self.key(kind, x) for x in rows}
        cutoff = self.machine["now"] - RETENTION_S
        for _ in range(MAX_PAGES):
            r = self.call(method, {"after": list(after), "max_bytes": self.max_bytes})
            if not isinstance(r, dict):
                raise SyncError("not_oomph", "%s: an answer that is not an object" % method)
            for line in _rows(r):  # unanchored (rotated away): the page starts at the first later row
                got = self.ing.row(line, kind, times=times, back=None if kind != "events" else 86400 * 30)
                if got:
                    k = self.key(kind, got[0])
                    if k not in seen:
                        seen.add(k)
                        rows.append(got[0])
                        self.counts["events" if kind == "events" else "records"] += 1
            nxt = _next(r, after)
            if not r.get("more") or tuple(nxt) == tuple(after):
                after = nxt
                break
            after = nxt
        keep = [x for x in rows if kind != "events" or (_json(x) or {}).get("t", 0) >= cutoff]
        if keep != [x for x in existing if x]:
            self.m.write(sub, name, b"".join(x + b"\n" for x in keep))
        self.state[at_key] = list(after)

    @staticmethod
    def key(kind, line):
        v = _json(line) or {}
        if kind == "events":
            return (v.get("t"), v.get("kind"), hashlib.sha1(line).hexdigest())
        return (v.get("key"), v.get("t"), v.get("event"))

    def events(self):
        self.paged("events", "events_at", ("log", "events.jsonl"), "events", ("t",))

    def reservations(self):
        self.paged("reservations", "reservations_at", ("ledger", oomph.HISTORY_FILE), "records",
                   ("requested", "t", "granted", "ended"))
        self.state["synced"]["reservations"] = True

    def gzip_days(self):
        """Days before the remote's today are gzipped once fully covered: the coverage holds the
        day's first and last sample and runs on past the last."""
        today = time.strftime("%Y-%m-%d", time.gmtime(self.machine["now"] + self.tz_s))
        oldest = self.machine.get("oldest") or 0
        for day in self.m.days():
            n = self.m.day_name(day)
            if day >= today or not n or n.endswith(".gz"):
                continue
            ts = sorted(self.m.day_rows(day))
            if ts and self.have.covers(max(ts[0] - 1, oldest), ts[-1] + 1):
                self.m.merge_day(day, {}, gz=True)

    def prune(self):
        cut = time.strftime("%Y-%m-%d", time.gmtime(self.machine["now"] + self.tz_s - RETENTION_S - 86400))
        for day in self.m.days():
            if day < cut:
                for n in ("samples-%s.jsonl" % day, "samples-%s.jsonl.gz" % day):
                    self.m.remove("log", n)
        self.have.remove(0, self.machine["now"] - RETENTION_S - 86400)
        for iid in self.m.names("log/incidents"):
            if net.INCIDENT_ID.fullmatch(iid):  # an id shape that is no date: an older client's, gone too
                t = _incident_t(iid)
                if t is None or t < self.machine["now"] - INCIDENT_KEEP_S:
                    self.m.remove("log/incidents/" + iid, "incident.json")
                    try:
                        fd = self.m._dir("log/incidents")
                        try:
                            os.rmdir(iid, dir_fd=fd)
                        finally:
                            os.close(fd)
                    except OSError:
                        pass

    def save(self):
        self.state["have"] = self.have.spans
        self.state["gone"] = self.gone.spans
        self.state["samples_at"] = [self.have.end(), 1] if self.have.end() is not None else None
        d = self.state["dropped"]
        for k, v in self.ing.dropped.items():
            d[k] = d.get(k, 0) + v
        self.m.put_json("", "sync.json", self.state)


def _span(s):
    return isinstance(s, list) and len(s) == 2 and all(oomph._num(x, 0, 1e11) for x in s) and s[0] <= s[1]


def status(mirror, state, error=None, detail=None, machine=None, started=None):
    """status.json as a run leaves it (roadmap 01 §5.7): nobody is syncing any more (`idle`),
    and `was` says what the link last was."""
    now = time.time()
    prev = mirror.json("", "status.json") or {}
    st = {"v": 1, "state": "idle", "was": state, "since": started or now,
          "last_contact": now if state == "live" else prev.get("last_contact"),
          "error": error, "detail": net.clean(detail, 200) if detail else None, "attempt": 0, "next_try": None,
          "connect_ms": (machine or {}).get("connect_ms", prev.get("connect_ms")), "transport": "pipe",
          "peer": None, "pid": None, "updated": now}
    mirror.put_json("", "status.json", st)
    return st


def sync_once(argv, into=None, max_bytes=net.PAGE):
    """Mirror the machine whose `oomph serve --stdio` `argv` starts. Returns a summary dict;
    raises SyncError."""
    _not_root()
    started = time.time()
    link = Link(argv)
    mirror = Mirror(into) if into else None
    try:
        try:
            machine = link.hello()
        except SyncError as e:
            if mirror:
                status(mirror, "offline", e.code, e.detail, started=started)
            raise
        if mirror is None:
            mid = machine.get("id")
            if not (isinstance(mid, str) and MID.fullmatch(mid)):
                raise SyncError("not_oomph", "that machine reports no usable id; name a mirror with --into")
            mirror = Mirror(os.path.join(machines_dir(), mid))
        mirror.put_json("", "machine.json", machine)
        s = Sync(link, mirror, machine, max_bytes=max_bytes)
        try:
            s.run()
        except net.RPCError as e:
            s.save()
            status(mirror, "offline", "not_oomph", "%s (%s)" % (e.message, e.code), machine, started)
            raise SyncError("not_oomph", "%s (%s)" % (e.message, e.code))
        except SyncError as e:
            s.save()
            status(mirror, "offline", e.code, e.detail, machine, started)
            raise
        except Exception as e:  # anything else a broken or hostile answer leads to: a reason, not a traceback
            code, detail = ("mirror", "the mirror: %s" % e) if isinstance(e, OSError) else \
                ("bad", "an answer the sync could not use (%s)" % type(e).__name__)
            try:
                s.save()
                status(mirror, "offline", code, detail, machine, started)
            except (OSError, SyncError):
                pass
            raise SyncError(code, detail)
        s.save()
        status(mirror, "live", machine=machine, started=started)
        hours = sum(b - a for a, b in s.have.spans) / 3600
        return {"machine": {k: machine.get(k) for k in ("id", "name", "os", "os_version", "version")},
                "mirror": mirror.path, "counts": s.counts, "dropped": s.ing.dropped, "have_h": round(hours, 1),
                "days": len(mirror.days()), "offset_s": machine.get("offset_s"), "connect_ms": machine.get("connect_ms")}
    finally:
        link.close()


# ------------------------------------------------------------------ addresses (roadmap 01 §7.3, §8)
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}")
USER = re.compile(r"[A-Za-z_][A-Za-z0-9._-]{0,31}")
FP = re.compile(r"sha256:[0-9a-f]{64}")
TCP_ADDR_S, TCP_ALL_S, TLS_S = 3, 8, 10   # per address, for all addresses, for the handshake
NOTES_KEPT = (64, 4 << 20)                 # notifications kept whole during a call: count, bytes
TRIGGERS = ("events", "ledger", "incident", "machine", "bye")   # ... and past that by name, once each
LINK_RSS_CAP = 256 << 20                   # a link process that grew by this much leaves (and retries)
PING_S, SILENT_S = 20, 45                  # ping after this long without a frame; give up after this
FORGET_S = 30                              # forget's unpairing there may take this long
HEARTBEAT_S = 5                            # a live link rewrites status.json this often (the app's 10 s rule)
LIVE_RESET_S = 30                          # a connection that lasted this long resets the backoff
BACKOFF = (1, 2, 4, 8, 15, 30, 60)
ENGINE_IDLE_S = 60                         # the engine stays this long after the popup closed (D8)
MAX_MACHINES = 12
EXIT_STOPPED, EXIT_OFFLINE, EXIT_ATTENTION = 0, 1, 3
ATTENTION = ("identity_changed", "revoked", "incompatible", "ssh")   # needs_attention: no retries by itself
OFFLINE_ERRORS = ("refused", "turned_away", "timeout", "dns", "not_oomph", "busy", "local_network_denied")


def parse_target(s):
    """{"transport", "user", "host", "port"} of what someone typed: HOST[:PORT] or [IPv6]:PORT for
    a shared Mac (TCP), USER@HOST or ssh://[USER@]HOST[:PORT] for ssh. ValueError for anything
    else: host and user match strict patterns before they can become an argument (no leading dash,
    no space or control character, no option smuggled in as an address)."""
    if not isinstance(s, str) or not 0 < len(s) <= 300:
        raise ValueError("not an address")
    ssh = s.startswith("ssh://")
    if ssh:
        s = s[6:].rstrip("/")
    user = None
    if "@" in s:
        user, _, s = s.rpartition("@")
        ssh = True
        if not USER.fullmatch(user):
            raise ValueError("not a user name: use letters, digits, . _ -")
    port = None
    m = re.fullmatch(r"\[([0-9A-Fa-f:.]+(?:%[A-Za-z0-9._-]{1,16})?)\](?::(\d{1,5}))?", s)
    if m:
        host, port = m.group(1), m.group(2)
    elif s.count(":") >= 2:
        host = s
    if m or s.count(":") >= 2:
        addr, _, zone = host.partition("%")
        if "%" in host and (ssh or not re.fullmatch(r"[A-Za-z0-9._-]{1,16}", zone)):
            raise ValueError("not an address: a scope (%%en0) only for a shared Mac, of letters and digits")
        ipaddress.IPv6Address(addr)
    else:
        host, _, p = s.partition(":")
        port = p or None
        if not HOST.fullmatch(host) or host.endswith(".."):
            raise ValueError("not a host name or address")
    if port is not None:
        if not re.fullmatch(r"\d{1,5}", port) or not 0 < int(port) < 65536:
            raise ValueError("not a port")
        port = int(port)
    return {"transport": "ssh" if ssh else "tcp", "user": user, "host": host,
            "port": port if port or ssh else net.PORT}


def show_target(e):
    if e.get("transport") == "ssh":
        return "%s%s%s" % (e["user"] + "@" if e.get("user") else "", e.get("host"),
                           ":%d" % e["port"] if e.get("port") else "")
    h = e.get("host") or ""
    return ("[%s]" % h if ":" in h else h) + (":%d" % e["port"] if e.get("port") not in (None, net.PORT) else "")


def ssh_argv(host, user=None, port=None):
    """`ssh` for the protocol over a machine's own SSH (roadmap 01 §8, roadmap §4.3): BatchMode
    (it never asks; when it would, the state is needs_attention: ssh), fixed options that keep the
    user's multiplexing, agent and forwardings out of it and notice a dead link within about 15 s,
    the user as -l, `--` before the host, and a constant remote command wrapped in /bin/sh (a csh
    login shell could not parse it) that finds oomph on the PATH, where install.sh puts it or in
    ~/.local/bin, and exits 127 when there is none."""
    remote = ("exec /bin/sh -c 'if command -v %(c)s >/dev/null 2>&1; then o=%(c)s; "
              "elif [ -x /usr/local/bin/%(c)s ]; then o=/usr/local/bin/%(c)s; "
              "elif [ -x \"$HOME/.local/bin/%(c)s\" ]; then o=\"$HOME/.local/bin/%(c)s\"; "
              "else exit 127; fi; exec \"$o\" serve --stdio'" % {"c": oomph.CMD})
    return ([os.environ.get("OOMPH_SSH") or "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "RequestTTY=no",
             "-o", "RemoteCommand=none", "-o", "ClearAllForwardings=yes", "-o", "ForwardAgent=no",
             "-o", "ForwardX11=no", "-o", "ControlMaster=no", "-o", "ControlPath=none",
             "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2", "-o", "ConnectTimeout=15"] +
            (["-p", str(port)] if port else []) + (["-l", user] if user else []) + ["--", host, remote])


# ------------------------------------------------------------------ the known machines (roadmap 01 §5.6)
def _put(d, name, data, mode):
    """A file of a directory of this user's, by a fresh temporary file renamed over its name."""
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        tmp = ".%s.%s.tmp" % (name, secrets.token_hex(8))
        out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        try:
            os.fchmod(out, mode)
            net.write_all(out, data)
        finally:
            os.close(out)
        os.rename(tmp, name, src_dir_fd=fd, dst_dir_fd=fd)
    finally:
        os.close(fd)


ENTRY_KEYS = ("mid", "id", "name", "label", "transport", "host", "port", "user", "addrs", "fp", "client", "os",
              "os_version", "arch", "ram_gb", "version", "caps", "added", "last_connected", "last_selected",
              "pinned", "order")


def valid_entry(e):
    """A machines.json entry as this code trusts it: a mirror name of the fixed pattern, an address
    that passes parse_target, a fingerprint and a client id of theirs; display fields cleaned."""
    if not (isinstance(e, dict) and isinstance(e.get("mid"), str) and MID.fullmatch(e["mid"]) and
            e.get("transport") in ("tcp", "ssh") and isinstance(e.get("host"), str)):
        return None
    try:
        t = parse_target(("ssh://" if e["transport"] == "ssh" else "") +
                         ("%s@" % e["user"] if e.get("user") else "") +
                         ("[%s]" % e["host"] if ":" in e["host"] else e["host"]) +
                         (":%d" % e["port"] if isinstance(e.get("port"), int) else ""))
    except (ValueError, TypeError):
        return None
    out = {k: e.get(k) for k in ENTRY_KEYS}
    out.update(host=t["host"], user=t["user"], port=t["port"])
    out["fp"] = e.get("fp") if isinstance(e.get("fp"), str) and FP.fullmatch(e["fp"]) else None
    out["client"] = e.get("client") if isinstance(e.get("client"), str) and net.CLIENT_ID.fullmatch(e["client"]) else None
    out["addrs"] = [a for a in (e.get("addrs") if isinstance(e.get("addrs"), list) else [])
                    if isinstance(a, str) and (HOST.fullmatch(a) or _is_ip(a))][:16]
    for k in ("id", "name", "label", "os", "os_version", "arch", "version"):
        out[k] = net.clean(e[k], 64) if isinstance(e.get(k), str) else None
    out["caps"] = [net.clean(c, 32) for c in e.get("caps") or [] if isinstance(c, str)][:32]
    out["pinned"] = e.get("pinned") is True
    return out


def _is_ip(a):
    try:
        ipaddress.ip_address(a)
        return True
    except ValueError:
        return False


class Book:
    """The machines this account watches (machines.json: tabs and recents, no secrets) and their
    tokens (secrets.json, 0600, like an SSH key: never in an argument, the environment, a pipe or
    machines.json). Both live in machines_dir() (0700) and change under machines.lock."""

    def __init__(self, base=None):
        _not_root()
        self.base = os.path.abspath(base or machines_dir())
        old = os.umask(0o077)
        try:
            os.makedirs(self.base, mode=0o700, exist_ok=True)
        finally:
            os.umask(old)
        st = os.lstat(self.base)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid():
            raise SyncError("mirror", "%s is not a directory of mine" % self.base)
        if st.st_mode & 0o077:
            os.chmod(self.base, 0o700)
        self.load()

    def _read(self, name):
        fd = os.open(self.base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            return oomph.loads_untrusted(oomph.read_bounded(name, 4 << 20, fd))
        finally:
            os.close(fd)

    def load(self):
        v = self._read("machines.json")
        seen = set()
        self.machines = []
        for e in (v.get("machines") if isinstance(v, dict) and isinstance(v.get("machines"), list) else []):
            e = valid_entry(e)
            if e and e["mid"] not in seen:
                seen.add(e["mid"])
                self.machines.append(e)
        sv = self._read("secrets.json")
        self.secrets = {}
        for mid, x in (sv.items() if isinstance(sv, dict) else []):
            tok = net._b64(x.get("token"), 32) if isinstance(x, dict) else None
            if mid in seen and tok and net.CLIENT_ID.fullmatch(str(x.get("client"))):
                self.secrets[mid] = {"client": x["client"], "token": x["token"]}
        return self

    @contextlib.contextmanager
    def locked(self):
        """machines.lock held (5 s at most to get it), the files read fresh; save() inside."""
        fd = os.open(os.path.join(self.base, "machines.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            deadline = time.monotonic() + 5
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() > deadline:
                        raise SyncError("busy", "machines.lock is held by another process")
                    time.sleep(0.05)
            self.load()
            yield self
        finally:
            os.close(fd)

    def save(self):
        _put(self.base, "secrets.json", net.dumps(self.secrets) + b"\n", 0o600)
        _put(self.base, "machines.json", json.dumps({"v": 1, "machines": self.machines}, indent=1,
                                                    allow_nan=False).encode() + b"\n", 0o644)

    def get(self, mid):
        return next((e for e in self.machines if e["mid"] == mid), None)

    def find(self, name):
        """The machine a name means: its mirror name, its id, the tab's label, its name, an address."""
        if not isinstance(name, str):
            return None
        for keys in (("mid", "id"), ("label",), ("name",), ("host",)):
            for e in self.machines:
                if any(e.get(k) == name for k in keys):
                    return e
        for e in self.machines:
            if name in (e.get("addrs") or []) or name == show_target(e):
                return e
        return None

    def by_fp(self, fp):
        return next((e for e in self.machines if fp and e.get("fp") == fp), None)

    def pinned(self):
        return sorted((e for e in self.machines if e["pinned"]), key=lambda e: (e.get("order") or 0, e.get("added") or 0))

    def mirror(self, mid):
        return Mirror(os.path.join(self.base, mid))

    def place(self, machine, fp, t, as_=None):
        """Where a machine reached for the first time goes (roadmap 01 §4.5): (mirror name, the
        entry it replaces or None). The id it reports is a hint, never proof: a known id with
        another key (or reached another way) is a question (Ask) until answered with as_ =
        "new" (two tabs, two mirrors) or "replace:MID" (that entry, its history kept, trusts this)."""
        rid = machine.get("id") if isinstance(machine.get("id"), str) and MID.fullmatch(machine["id"]) else None
        if isinstance(as_, str) and as_.startswith("replace:"):
            old = self.get(as_[8:])
            if not old:
                raise SyncError("bad_address", "no machine %s to replace" % net.clean(as_[8:], 40))
            return old["mid"], old
        same = [e for e in self.machines if rid and e.get("id") == rid]
        match = [e for e in same if e["transport"] == t["transport"] and
                 (e.get("fp") == fp if t["transport"] == "tcp" else (e["host"], e["user"]) == (t["host"], t["user"]))]
        if match and as_ is None:
            return match[0]["mid"], match[0]
        if same and as_ != "new":
            raise Ask(same[0])
        salt = hashlib.sha256((fp or "%s@%s" % (t["user"], t["host"])).encode()).hexdigest()
        mid = rid or "m-" + salt[:16]
        if self.get(mid):
            mid = mid[:18] + "-" + salt[:8]
        if self.get(mid):
            raise SyncError("too_many", "that machine is known already: oomph remote list")
        return mid, None


class Ask(SyncError):
    """A known machine id with another key or transport: a question for the person (§4.5)."""

    def __init__(self, known):
        SyncError.__init__(self, "ask", "it reports the same machine id as %s, but has a different key or "
                           "address. That is normal after reinstalling %s or resetting sharing there, and for "
                           "cloned systems. Add it again with --as new (two tabs) or --as replace:%s (keep %s's "
                           "history and trust the new key)." % (label(known), oomph.BRAND, known["mid"], label(known)))
        self.known = known


def label(e):
    return e.get("label") or e.get("name") or e.get("host") or e.get("mid")


# ------------------------------------------------------------------ connecting (roadmap 01 §5.2, §5.3, §6.2)
def tcp_connect(host, port, addrs=(), tried=None, deadline=None):
    """A connected socket and the address it reached: the remembered numeric addresses first,
    then the name; TCP_ADDR_S per address, TCP_ALL_S for all. SyncError with refused, timeout,
    dns or unreachable otherwise. `tried` (socket addresses) are skipped, and every address tried
    is added to it."""
    deadline = deadline or time.monotonic() + TCP_ALL_S
    tried, why, fast_any = (set() if tried is None else tried), None, False
    for h in [a for a in addrs if _is_ip(a)] + [host]:
        if time.monotonic() >= deadline:
            break
        try:
            infos = socket.getaddrinfo(h, port, type=socket.SOCK_STREAM)
        except (socket.gaierror, UnicodeError) as e:
            why = why or ("dns", "%s: no such host (%s)" % (net.clean(h, 64), getattr(e, "strerror", None) or e))
            continue
        for fam, typ, proto, _, sa in infos:
            if sa in tried or time.monotonic() >= deadline:
                continue
            tried.add(sa)
            s = socket.socket(fam, typ, proto)
            s.settimeout(max(0.1, min(TCP_ADDR_S, deadline - time.monotonic())))
            t = time.monotonic()
            try:
                s.connect(sa)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                return s, sa[0]
            except ConnectionRefusedError:
                why = ("refused", "%s:%d refused the connection: sharing is off there (on it: sudo oomph share on)"
                       % (net.clean(sa[0], 64), port))
            except socket.timeout:
                why = why if why and why[0] == "refused" else ("timeout", "no answer from %s:%d" % (net.clean(h, 64), port))
            except OSError as e:
                fast = fast_any = time.monotonic() - t < 0.5 or fast_any
                why = why if why and why[0] == "refused" else (
                    "timeout", "%s: %s, after %d ms%s" % (net.clean(sa[0], 64), e.strerror or e, (time.monotonic() - t) * 1000,
                                                         "; if this terminal app is not allowed on the local network "
                                                         "(System Settings › Privacy & Security › Local Network), that is "
                                                         "the cause" if fast and sys.platform == "darwin" else ""))
            s.close()
    err = SyncError(*(why or ("timeout", "no answer from %s" % net.clean(host, 64))))
    err.fast = fast_any and sys.platform == "darwin"  # the app then asks macOS (Local Network, roadmap 01 §7.6)
    raise err


def tls_connect(host, port, addrs=()):
    """(TLS socket, certificate digest, address reached): tcp_connect, then TLS; an address that
    accepts and closes (turned_away: say an IPv6 address the gate there does not take, listed
    first for a .local name) is passed over for the next one within TCP_ALL_S."""
    deadline, tried, first = time.monotonic() + TCP_ALL_S, set(), None
    while True:
        try:
            sock, peer = tcp_connect(host, port, addrs, tried, deadline)
        except SyncError:
            if first is not None:
                raise first
            raise
        try:
            return tls_wrap(sock) + (peer,)
        except SyncError as err:
            if err.code != "turned_away":
                raise
            first = first or err
            if time.monotonic() >= deadline:
                raise first


def tls_wrap(sock):
    """TLS on a connected socket, as a viewer: (the TLS socket, SHA-256 of the certificate it
    presented). A peer that accepts and closes before a byte (the gate there, or its caps) is
    turned_away."""
    if net.ssl is None:
        raise SyncError("incompatible", "this Python has no TLS")
    sock.settimeout(TLS_S)
    try:
        tls = net.client_context().wrap_socket(sock)
        der = tls.getpeercert(binary_form=True)
    except socket.timeout:
        sock.close()
        raise SyncError("timeout", "the TLS handshake took longer than %d s" % TLS_S)
    except (OSError, ValueError) as e:
        sock.close()
        raise SyncError("turned_away", "it accepted the connection and closed it: sharing there is not on for "
                        "this network, or it is busy (%s)" % type(e).__name__)
    if not der:
        tls.close()
        raise SyncError("not_oomph", "no certificate")
    return tls, hashlib.sha256(der).digest()


def tls_auth(link, client, token, fp):
    """Authenticate on an open TLS link with a token issued at pairing, without sending it:
    HMAC(SHA-256("oomph-token-v1" ‖ token), "auth" ‖ cn ‖ sn ‖ the pinned certificate)."""
    r, t0, _ = link.hello_raw()
    sn = net._b64(r.get("nonce"), 16)
    if sn is None or "token" not in (r.get("auth") or []):
        raise SyncError("incompatible", "it does not take tokens")
    mac = net.proof(net.token_key(token), b"auth", link.cn, sn, fp)
    t0 = time.time()
    try:
        res = link.call("auth", {"client": client, "mac": base64.b64encode(mac).decode()}, timeout=TLS_S + 5)
    except net.RPCError as e:
        if e.code == net.ERR["busy"]:
            raise SyncError("busy", "it has as many viewers as it serves at once; trying again")
        if e.code != net.ERR["auth"]:  # a passing fault there: try again later, keep the token
            raise SyncError("not_oomph", "it could not authenticate this viewer just now (%s); trying again"
                            % net.clean(str(e.message), 80))
        raise SyncError("revoked", "it no longer knows this viewer: its access was revoked, or sharing was reset there")
    if not isinstance(res, dict) or not isinstance(res.get("machine"), dict):
        raise SyncError("not_oomph", "an answer to auth without the machine")
    return machine_of(res["machine"], t0, time.time())


def tls_pair(link, fp, code, name):
    """Pair on an open TLS link (roadmap 01 §5.3): prove the code bound to the certificate seen, and
    check the server's proof back before keeping anything. Returns (machine, client id, token)."""
    r, _, _ = link.hello_raw()
    sn = net._b64(r.get("nonce"), 16)
    if sn is None or "pair" not in (r.get("auth") or []):
        raise SyncError("incompatible", "it does not pair")
    kp = net.pair_key(code, sn, link.cn)
    mac = net.proof(kp, b"client", link.cn, sn, fp)
    t0 = time.time()
    try:
        res = link.call("pair", {"mac": base64.b64encode(mac).decode(), "name": net.viewer_name(name)},
                        timeout=TLS_S + 5)
    except net.RPCError:
        raise SyncError("pair_failed", "the code was not accepted: mistyped, used, expired or out of tries. Make a "
                        "new one there: sudo oomph share pair")
    smac = net._b64(res.get("mac"), 32) if isinstance(res, dict) else None
    if smac is None or not hmac.compare_digest(smac, net.proof(kp, b"server", link.cn, sn, fp)):
        raise SyncError("pair_failed", "the other side could not prove it knows the code: something may sit "
                        "between the two machines. Nothing was kept")
    token = net._b64(res.get("token"), 32)
    client = res.get("client")
    if token is None or not (isinstance(client, str) and net.CLIENT_ID.fullmatch(client)) or \
            not isinstance(res.get("machine"), dict):
        raise SyncError("not_oomph", "a pairing answer this version does not understand")
    return machine_of(res["machine"], t0, time.time()), client, token


def open_link(e, secret):
    """A Link to a known machine, authenticated, and what it said about itself (roadmap 01 §6.2):
    TCP with its pinned certificate and its token, or ssh. A changed key sends nothing past TLS
    (identity_changed); a known key reporting another id is the same."""
    if e["transport"] == "ssh":
        link = Link(argv=ssh_argv(e["host"], e.get("user"), e.get("port")))
        try:
            machine = link.hello()
        except SyncError as err:
            rc, tail = link.exit_status(2.0), link.stderr_tail()
            link.close()
            if rc == 255:
                raise SyncError("ssh", "ssh could not sign in%s" % tail)
            if rc == 127:
                raise SyncError("not_oomph", "%s is not installed on %s" % (oomph.CMD, net.clean(e["host"], 64)))
            raise err
        peer = e["host"]
    else:
        if not (e.get("fp") and secret):
            raise SyncError("revoked", "this viewer is not paired with it: oomph remote add %s (it asks for a code)" % show_target(e))
        tls, fp, peer = tls_connect(e["host"], e["port"], e.get("addrs") or ())
        if "sha256:" + fp.hex() != e["fp"]:
            tls.close()
            raise SyncError("identity_changed", "its key changed: " + oomph.BRAND + " was reinstalled or sharing reset there, or "
                            "something else answers at that address. Nothing was sent. To trust the new key: "
                            "oomph remote forget %s, then add it again with a new code" % label(e))
        link = Link(sock=tls)
        try:
            machine = tls_auth(link, secret["client"], base64.b64decode(secret["token"]), fp)
        except SyncError:
            link.close()
            raise
    if e.get("id") and machine.get("id") and machine["id"] != e["id"] and e["transport"] == "tcp":
        link.close()
        raise SyncError("identity_changed", "its key now reports another machine id (%s, not %s)"
                        % (net.clean(str(machine["id"]), 40), e["id"]))
    return link, machine, peer


def write_status(mirror, **kw):
    """status.json (roadmap 01 §5.7), the previous one's fields kept where not given."""
    prev = mirror.json("", "status.json") or {}
    st = {"v": 1, "state": "idle", "was": None, "since": None, "last_contact": None, "error": None, "detail": None,
          "attempt": 0, "next_try": None, "connect_ms": None, "transport": None, "peer": None, "pid": None,
          "fast": None, "updated": None}
    st.update({k: v for k, v in prev.items() if k in st})
    if kw.get("state", "idle") != "idle":
        st["was"] = None  # `was` is what an idle file says the link last was
    st.update(kw)
    st["detail"] = net.clean(st["detail"], 200) if isinstance(st.get("detail"), str) else None
    st["updated"] = time.time()
    mirror.put_json("", "status.json", st)
    return st


def remember(book, e, machine, peer):
    """What a connection taught about a machine: its words about itself, the address that worked
    first among the remembered ones, when."""
    with book.locked():
        x = book.get(e["mid"])
        if not x:
            return
        for k in ("name", "os", "os_version", "arch", "version"):
            if isinstance(machine.get(k), str):
                x[k] = net.clean(machine[k], 64)
        x["id"] = x.get("id") or (machine.get("id") if isinstance(machine.get("id"), str) and MID.fullmatch(machine["id"]) else None)
        x["ram_gb"] = machine.get("ram_gb") if oomph._num(machine.get("ram_gb"), 0, 65536) else x.get("ram_gb")
        x["caps"] = caps_of(machine)
        x["last_connected"] = time.time()
        if e["transport"] == "tcp" and _is_ip(str(peer)):
            x["addrs"] = ([peer] + [a for a in x.get("addrs") or [] if a != peer])[:16]
        book.save()


def caps_of(machine):
    caps = machine.get("caps") if isinstance(machine.get("caps"), list) else []
    return [net.clean(c, 32) for c in caps if isinstance(c, str)][:32]


def set_caps(mid, caps):
    """A machine's caps changed during a session (its owner ran `share ai on` or `off`): its entry
    in machines.json follows, for `remote list` and the app."""
    book = Book()
    with book.locked():
        x = book.get(mid)
        if x and x.get("caps") != caps:
            x["caps"] = caps
            book.save()


# ------------------------------------------------------------------ live (roadmap 01 §6.1)
class Live(Sync):
    """A session that stays: after the catching up of Sync.run, the notifications of a subscription
    (tick, events, ledger, incident, bye), with pings when it is quiet. Each notification is a
    trigger; what it announced is fetched with the same paged calls as a backfill, so a missed or
    hostile notification can never leave the mirror claiming more than it holds."""

    def __init__(self, link, mirror, machine, emit):
        Sync.__init__(self, link, mirror, machine)
        self.emit, self.mid = emit, os.path.basename(mirror.path)
        self.t0, self.now0 = time.monotonic(), machine["now"]

    def clock(self):
        """The remote's now, as the handshake's offset and the time since then say."""
        now = self.now0 + (time.monotonic() - self.t0)
        self.machine["now"] = self.ing.now = now
        return now

    def changed(self, *what):
        self.emit({"ev": "changed", "id": self.mid, "what": list(what)})

    def tick(self, p):
        """Samples the server tailed from its day file: merged into their days; the coverage
        grows when `prev` (read from the file there) is covered here, else the hole before them is
        fetched first."""
        rows = p.get("samples") if isinstance(p.get("samples"), list) else []
        by_day, ts = {}, []
        for row in rows[:2000]:
            got = self.ing.row(net.dumps(row), "samples", cut=oomph.SLIM_STR) if isinstance(row, dict) else None
            if got:
                b2, r = got
                by_day.setdefault(_day_of(r, self.tz_s), {})[r["t"]] = b2
                ts.append(r["t"])
        for day, rs in by_day.items():
            if DAY.fullmatch(day):
                self.m.merge_day(day, rs)
        if ts:
            lo, hi = min(ts), max(ts)
            prev, end = p.get("prev"), self.have.end()
            if oomph._num(prev, 0, 1e11) and self.have.covers(prev, prev):
                self.have.add(prev, hi)      # they follow what is here: the coverage runs on
            else:
                if end is not None and end < lo:
                    self.samples(max(0.0, end - OVERLAP_S), lo)   # a hole before them: fetched by range
                self.have.add(lo, hi)        # a tick carries every line appended since the last
            self.counts["samples"] += len(ts)
        cur = p.get("current")
        if isinstance(cur, dict):
            got = self.ing.row(net.dumps(cur), "samples")
            if got:
                self.m.put_json("log", "current.json", got[1])
        self.changed("current", "samples")

    def follow(self, stop_fd):
        """Until the engine closes stop_fd (EXIT_STOPPED), or the link fails (SyncError)."""
        r = self.call("subscribe", {"streams": list(net.STREAMS)})
        cur = r.get("current") if isinstance(r, dict) else None
        if isinstance(cur, dict):
            got = self.ing.row(net.dumps(cur), "samples")
            if got:
                self.m.put_json("log", "current.json", got[1])
        heard = beat = time.monotonic()
        self.status("live")
        self.changed("current")
        while True:
            fds = [stop_fd] + ([] if self.link.ready() else [self.link.fileno()])
            ready = select.select(fds, [], [], 0 if len(fds) == 1 else 1.0)[0]
            if stop_fd in ready and not os.read(stop_fd, 4096):
                return EXIT_STOPPED
            n = self.link.note(0) if (self.link.fileno() in ready or len(fds) == 1) else None
            now = time.monotonic()
            if n is not None:
                heard = now
                self.clock()
                method, p = n.get("method"), n.get("params") if isinstance(n.get("params"), dict) else {}
                if method == "tick":
                    self.tick(p)
                elif method == "events":
                    self.events()
                    self.changed("events")
                elif method == "ledger":
                    self.ledger()
                    self.reservations()
                    self.changed("ledger")
                elif method == "incident":
                    self.incidents()
                    self.changed("incidents")
                elif method == "machine":
                    caps = caps_of(p)
                    if caps != self.machine.get("caps"):
                        self.machine["caps"] = caps
                        self.m.put_json("", "machine.json", self.machine)
                        set_caps(self.mid, caps)
                        self.changed("machine")
                elif method == "bye":
                    why = net.clean(str(p.get("reason")), 20)
                    if why == "revoked":
                        raise SyncError("revoked", "its owner revoked this viewer's access")
                    raise SyncError("closed", "it closed the connection (%s)" % why)
            elif now - heard > PING_S:
                pong = self.link.call("ping", timeout=SILENT_S - PING_S)
                heard = time.monotonic()
                if isinstance(pong, dict) and oomph._num(pong.get("now"), 0, 1e11):
                    self.now0, self.t0 = pong["now"], heard
            if now - beat > HEARTBEAT_S:
                beat = now
                self.save()
                self.status("live")

    def status(self, state, **kw):
        return write_status(self.m, state=state, pid=os.getpid(), last_contact=time.time(), error=None, detail=None,
                            fast=None, connect_ms=self.machine.get("connect_ms"), **kw)


def run_link(mid, stop_fd=0, out=None, once=False, unpair=False):
    """One machine's connection (`oomph remote _link MID`, a child of the engine): connect, catch
    up, then follow until the engine closes stdin. Events on stdout, one JSON object a line; the
    state also in status.json. Exits EXIT_STOPPED, EXIT_OFFLINE (the engine retries with backoff)
    or EXIT_ATTENTION (it does not, until asked)."""
    out = out or sys.stdout

    def emit(ev):
        try:
            out.write(json.dumps(ev) + "\n")
            out.flush()
        except (OSError, ValueError):
            pass
    book = Book()
    e = book.get(mid)
    if not e:
        return EXIT_ATTENTION
    mirror = book.mirror(mid)
    st = write_status(mirror, state="connecting", pid=os.getpid(), transport=e["transport"], since=time.time())
    emit(dict(st, ev="state", id=mid))
    link = None
    try:
        link, machine, peer = open_link(e, book.secrets.get(mid))
        if unpair:
            if e["transport"] == "tcp":
                link.call("unpair", timeout=10)
            return EXIT_STOPPED
        mirror.put_json("", "machine.json", machine)
        remember(book, e, machine, peer)
        live = Live(link, mirror, machine, emit)
        emit(dict(live.status("catching_up", peer=net.clean(str(peer), 64), since=time.time()), ev="state", id=mid))
        try:
            live.run()
        finally:
            live.save()
        live.changed("current", "samples", "events", "ledger", "incidents")
        if once:
            write_status(mirror, state="idle", was="live", last_contact=time.time(), pid=None)
            return EXIT_STOPPED
        emit(dict(mirror.json("", "status.json") or {}, ev="state", id=mid, state="live"))
        try:
            return live.follow(stop_fd)
        finally:
            live.save()
    except (SyncError, net.RPCError, OSError, ValueError, TypeError, KeyError) as err:
        code = err.code if isinstance(err, SyncError) else "not_oomph" if isinstance(err, net.RPCError) else "bad"
        detail = err.detail if isinstance(err, SyncError) else "%s: %s" % (type(err).__name__, err)
        attention = code in ATTENTION
        if code == "revoked" and e["transport"] == "tcp":
            try:
                with book.locked():
                    book.secrets.pop(mid, None)
                    book.save()
            except SyncError:
                pass
        state = "needs_attention" if attention else "offline"
        error = code if code in OFFLINE_ERRORS + ATTENTION else "timeout" if code == "closed" else "not_oomph"
        st = write_status(mirror, state=state, error=error, detail=detail, pid=os.getpid(),
                          fast=getattr(err, "fast", False) or None)
        emit(dict(st, ev="state", id=mid))
        return EXIT_ATTENTION if attention else EXIT_OFFLINE
    finally:
        if link is not None:
            link.close()


# ------------------------------------------------------------------ the engine (roadmap 01 §4.3, §5.8, §6.2)
def backoff(attempt, rnd=None):
    """Seconds before try `attempt` (1, 2, 4, 8, 15, 30, 60, then every 60), each ±20 %."""
    import random
    base = BACKOFF[min(max(attempt, 0), len(BACKOFF) - 1)]
    return base * (rnd if rnd is not None else random.uniform(0.8, 1.2))


class Engine:
    """`oomph remote sync`: keeps the watched machines' mirrors live, one child per machine
    (`remote _link`), and says on stdout what changed. Exactly one process per account is the
    engine: whoever holds engine.lock. Another `remote sync` follows (it writes viewers/<pid>.json
    with what it wants watched, reports the states it reads from status.json) and takes over when
    the lock is free. With --json (the app): commands on stdin, one JSON object a line; the end of
    input is quit; after {"cmd": "idle"} (the popup closed) it stays ENGINE_IDLE_S, then exits
    unless another viewer wants machines watched (D8: no network while nobody looks)."""

    def __init__(self, as_json):
        self.book = Book()
        self.json = as_json
        self.lock = os.open(os.path.join(self.book.base, "engine.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW |
                            os.O_CLOEXEC, 0o600)
        self.leader = False
        self.links = {}          # mid → {"p", "attempt", "next", "state", "live_at", "hold"}
        self.watch = "all" if not as_json else []
        self.focus = None
        self.idle_since = None
        self.idle_s = float(os.environ.get("OOMPH_ENGINE_IDLE_S") or ENGINE_IDLE_S)
        self.viewers = os.path.join(self.book.base, "viewers")
        os.makedirs(self.viewers, mode=0o700, exist_ok=True)
        self.me = os.path.join(self.viewers, "%d.json" % os.getpid())
        self.stamps = {}
        self.book_stamp = None
        self.quit = False
        self.inbuf = b""
        self.forgetting = {}     # mid → (the unpairing child, until when it may take)

    def emit(self, ev):
        if self.json:
            try:
                sys.stdout.write(json.dumps(ev) + "\n")
                sys.stdout.flush()
            except (OSError, ValueError):
                self.quit = True
        elif ev.get("ev") == "state":
            e = self.book.get(ev.get("id")) or {}
            print("%s  %s%s" % (net.clean(str(label(e) or ev.get("id")), 32), ev.get("state"),
                                ": " + net.clean(str(ev["detail"]), 160) if ev.get("detail") else ""), flush=True)

    def try_lead(self):
        if self.leader:
            return True
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        self.leader = True
        return True

    def wanted(self):
        """The machines to keep connected: this process's wish and every living viewer's."""
        pinned = [e["mid"] for e in self.book.pinned()]
        out = set(pinned if self.watch == "all" else [m for m in self.watch if m in pinned])
        self.retry_asks = {}
        for n in os.listdir(self.viewers):
            m = re.fullmatch(r"(\d{1,10})\.json", n)
            if not m or int(m.group(1)) == os.getpid():
                continue
            try:
                os.kill(int(m.group(1)), 0)
            except ProcessLookupError:
                try:
                    os.unlink(os.path.join(self.viewers, n))
                except OSError:
                    pass
                continue
            except PermissionError:
                pass
            fd = os.open(self.viewers, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                v = oomph.loads_untrusted(oomph.read_bounded(n, 64 << 10, fd))
            finally:
                os.close(fd)
            if not isinstance(v, dict):
                continue
            w = v.get("watch")
            out |= set(pinned if w == "all" else [x for x in w if x in pinned] if isinstance(w, list) else [])
            for mid, t in (v.get("retry") or {}).items() if isinstance(v.get("retry"), dict) else []:
                if oomph._num(t, 0, 1e11):
                    self.retry_asks[mid] = t
        return out

    def others_want(self):
        return any(re.fullmatch(r"\d{1,10}\.json", n) and int(n[:-5]) != os.getpid() and _alive(int(n[:-5]))
                   for n in os.listdir(self.viewers))

    def write_wish(self, retry=None):
        v = {"pid": os.getpid(), "watch": self.watch, "focus": self.focus,
             "retry": retry or {}}
        _put(self.viewers, os.path.basename(self.me), net.dumps(v) + b"\n", 0o600)

    def command(self, c):
        if not isinstance(c, dict):
            return
        cmd = c.get("cmd")
        mids = [x for x in (c.get("ids") or []) if isinstance(x, str) and MID.fullmatch(x)][:64] \
            if isinstance(c.get("ids"), list) else []
        if cmd == "watch":
            self.watch, self.idle_since = mids, None
            f = c.get("focus")
            self.focus = f if isinstance(f, str) and MID.fullmatch(f) else None
            if not self.leader:
                self.write_wish()
        elif cmd == "retry":
            mid = c.get("id")
            if isinstance(mid, str) and mid in self.links:
                self.links[mid].update(next=0, hold=False)
            elif not self.leader and isinstance(mid, str) and MID.fullmatch(mid):
                self.write_wish({mid: time.time()})
        elif cmd == "idle":
            self.idle_since = time.monotonic()
        elif cmd == "quit":
            self.quit = True
        elif cmd in ("pin", "unpin", "rename", "forget"):
            mid = c.get("id")
            if not (isinstance(mid, str) and MID.fullmatch(mid)):
                return
            if cmd == "forget":
                self.stop(mid)
                if self.unpair(mid):
                    return
            self.edit(cmd, mid, c.get("label"))

    def edit(self, cmd, mid, new_label=None):
        try:
            edit(cmd, mid, new_label, unpair=False)
        except SyncError as e:
            self.emit({"ev": "failed", "cmd": cmd, "reason": e.code, "detail": e.detail})

    def unpair(self, mid):
        """forget's best-effort unpairing there, in a child (`remote _link MID --unpair`), so an
        unreachable machine holds up no other link and no command: the entry goes when the child
        ends, or after FORGET_S. True when such a child was started."""
        e = self.book.get(mid)
        if mid in self.forgetting or not (e and e["transport"] == "tcp" and mid in self.book.secrets):
            return mid in self.forgetting
        argv = [sys.executable or oomph.PY, "-I", "-B", os.path.realpath(oomph.__file__), "remote", "_link", mid, "--unpair"]
        try:
            p = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True)
        except OSError:
            return False
        self.forgetting[mid] = (p, time.monotonic() + FORGET_S)
        return True

    def forgotten(self, done=False):
        """The forgets whose unpairing child ended (or ran out of time, or `done`: shutting down)."""
        for mid, (p, until) in list(self.forgetting.items()):
            if p.poll() is None and not done and time.monotonic() < until:
                continue
            try:
                p.wait(max(0.0, min(until - time.monotonic(), 10.0)) if done else 0)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
            del self.forgetting[mid]
            self.edit("forget", mid)

    def start(self, mid):
        argv = [sys.executable or oomph.PY, "-I", "-B", os.path.realpath(oomph.__file__), "remote", "_link", mid]
        try:
            p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 close_fds=True)
        except OSError:
            return
        os.set_blocking(p.stdout.fileno(), False)
        L = self.links.setdefault(mid, {"attempt": 0, "next": 0, "state": None, "live_at": None, "hold": False})
        L.update(p=p, buf=b"", started=time.monotonic())

    def stop(self, mid, wait=2.0):
        """End one machine's child: its stdin closed (a live link ends at once), killed after `wait`
        seconds (one still catching up does not look at stdin; its status.json then names a pid that
        is gone, which every reader draws as not live)."""
        L = self.links.get(mid)
        p = L and L.get("p")
        if not p:
            return
        try:
            p.stdin.close()
        except OSError:
            pass
        try:
            p.wait(wait)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        self.drain(mid)
        p.stdout.close()
        L["p"] = None

    def drain(self, mid):
        L = self.links[mid]
        p = L.get("p")
        try:
            while True:
                b = p.stdout.read(65536)
                if not b:
                    break
                L["buf"] += b
                if len(L["buf"]) > (1 << 20):
                    L["buf"] = b""
                    break
        except (OSError, ValueError, TypeError):
            pass
        while b"\n" in L["buf"]:
            line, L["buf"] = L["buf"].split(b"\n", 1)
            ev = oomph.loads_untrusted(line) if len(line) < (64 << 10) else None
            if isinstance(ev, dict) and ev.get("id") == mid and ev.get("ev") in ("state", "changed"):
                if ev["ev"] == "state":
                    L["state"] = ev.get("state")
                    if ev.get("state") == "live" and not L.get("live_at"):
                        L["live_at"] = time.monotonic()
                self.emit(ev)

    def reap(self, mid):
        L = self.links[mid]
        rc = L["p"].poll()
        if rc is None:
            return
        self.drain(mid)
        L["p"].stdout.close()
        L["p"] = None
        lasted = L.get("live_at") and time.monotonic() - L["live_at"] >= LIVE_RESET_S
        L["live_at"] = None
        L["attempt"] = 0 if lasted else L["attempt"] + 1
        L["hold"] = rc == EXIT_ATTENTION
        L["next"] = time.monotonic() + backoff(L["attempt"] - 1 if L["attempt"] else 0)
        if not L["hold"] and rc != EXIT_STOPPED:
            try:
                write_status(self.book.mirror(mid), attempt=L["attempt"], next_try=time.time() + L["next"] - time.monotonic())
            except (SyncError, OSError):
                pass

    def follow_states(self, mids):
        """A follower reports the states the engine writes."""
        for mid in mids:
            path = os.path.join(self.book.base, mid, "status.json")
            try:
                st = os.stat(path)
            except OSError:
                continue
            stamp = (st.st_ino, st.st_mtime_ns)
            if self.stamps.get(mid) != stamp:
                self.stamps[mid] = stamp
                v = self.book.mirror(mid).json("", "status.json")
                if v:
                    self.emit(dict(v, ev="state", id=mid))

    def read_commands(self):
        try:
            b = os.read(0, 65536)
        except OSError:
            b = b""
        if not b:
            self.quit = True
            return
        self.inbuf += b
        if len(self.inbuf) > (1 << 20):
            self.inbuf = b""
        while b"\n" in self.inbuf:
            line, self.inbuf = self.inbuf.split(b"\n", 1)
            self.command(oomph.loads_untrusted(line) if len(line) < (64 << 10) else None)

    def loop(self):
        if self.json:
            self.emit({"ev": "hello", "pid": os.getpid()})
        if not self.try_lead():
            self.write_wish()
        while not self.quit:
            fds = [0] if self.json else []
            fds += [L["p"].stdout for L in self.links.values() if L.get("p")]
            try:
                ready = select.select(fds, [], [], 1.0)[0]
            except (OSError, ValueError):
                ready = []
            if 0 in ready:
                self.read_commands()
            self.forgotten()
            for mid, L in list(self.links.items()):
                if L.get("p") and L["p"].stdout in ready:
                    self.drain(mid)
                if L.get("p"):
                    self.reap(mid)
            st = _stamp(os.path.join(self.book.base, "machines.json"))
            if st != self.book_stamp:
                self.book_stamp = st
                self.book.load()
                self.emit({"ev": "machines"})
            if not self.leader and self.try_lead():
                try:
                    os.unlink(self.me)
                except OSError:
                    pass
            want = (self.wanted() if self.leader else set()) - set(self.forgetting)
            if self.leader:
                now = time.monotonic()
                for mid, t in getattr(self, "retry_asks", {}).items():
                    L = self.links.get(mid)
                    if L and not L.get("p") and t > time.time() - 60:
                        L.update(next=0, hold=False)
                for mid in list(self.links):
                    if mid not in want:
                        self.stop(mid)
                        self.idle_status(mid)
                        del self.links[mid]
                for mid in sorted(want, key=lambda m: m != self.focus)[:MAX_MACHINES]:
                    L = self.links.get(mid)
                    if L is None or not L.get("p") and not L["hold"] and L["next"] <= now:
                        self.start(mid)
            else:
                self.follow_states([e["mid"] for e in self.book.pinned()] if self.watch == "all" else self.watch)
            if self.idle_since is not None and time.monotonic() - self.idle_since >= self.idle_s and \
                    not (self.leader and self.others_want()):
                break
        self.shutdown()

    def idle_status(self, mid):
        L = self.links.get(mid) or {}
        try:
            m = self.book.mirror(mid)
            st = m.json("", "status.json") or {}
            if st.get("state") != "idle":
                write_status(m, state="idle", was=st.get("state"), pid=None)
        except (SyncError, OSError):
            pass

    def shutdown(self):
        self.forgotten(done=True)
        for mid in list(self.links):
            self.stop(mid)
            self.idle_status(mid)
        try:
            os.unlink(self.me)
        except OSError:
            pass
        os.close(self.lock)


def _alive(pid):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _stamp(path):
    try:
        st = os.stat(path)
        return (st.st_ino, st.st_mtime_ns, st.st_size)
    except OSError:
        return None


def edit(cmd, mid, new_label=None, unpair=True):
    """The edits of machines.json (roadmap 01 §5.8), under its lock: pin (a tab), unpin (Recents
    keep it), rename (the tab's label), forget (its pairing there given up when it can be reached,
    unless `unpair` is False (the engine did that in a child), then its mirror, token and entry
    gone)."""
    book = Book()
    if cmd == "forget" and unpair:
        e = book.get(mid)
        if e and e["transport"] == "tcp" and mid in book.secrets:
            try:
                run_link(mid, unpair=True, out=open(os.devnull, "w"))
            except Exception:  # best effort: an unreachable machine forgets nothing there
                pass
    with book.locked():
        e = book.get(mid)
        if not e:
            raise SyncError("bad_address", "no such machine")
        if cmd == "pin":
            if len(book.pinned()) >= MAX_MACHINES and not e["pinned"]:
                raise SyncError("too_many", "Twelve machines are watched. Remove one to add another.")
            e["pinned"] = True
        elif cmd == "unpin":
            e["pinned"] = False
        elif cmd == "rename":
            e["label"] = net.clean(new_label, 64).strip() or None if isinstance(new_label, str) else None
        elif cmd == "forget":
            book.machines = [x for x in book.machines if x["mid"] != mid]
            book.secrets.pop(mid, None)
        book.save()
    if cmd == "forget":
        import shutil
        path = os.path.join(book.base, mid)
        if MID.fullmatch(mid) and os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)


# ------------------------------------------------------------------ oomph remote …
REMOTE_USAGE = """usage: oomph remote add HOST[:PORT] [--code CODE] [--name LABEL] [--as new|replace:MID] [--json]
                                  a shared Mac (the first time with the code `sudo oomph share pair` showed
                                  there; --code - reads it from stdin)
       oomph remote add USER@HOST | ssh://[USER@]HOST[:PORT] [--name LABEL]
                                  any machine with `oomph` installed, over your ssh (keys or an agent)
       oomph remote list [--json]       the machines this account watches, and their links
       oomph remote remove NAME         stop watching it (it stays in the list as a recent one)
       oomph remote forget NAME         give up its pairing there, its history here and its entry
       oomph remote rename NAME LABEL   the tab's name
       oomph remote sync [--json]       keep the watched machines live until stopped (what the app runs)
       oomph remote sync --once [NAME]  catch every watched machine (or NAME) up once
       oomph remote sync --once --into DIR [-- COMMAND …]   mirror the machine whose `serve --stdio`
                                  COMMAND starts (default: this one) into DIR"""


def add_machine(target, code=None, name=None, as_=None, ask=None):
    """`remote add`: reach the machine, pair (TCP, first time) or sign in (TCP, a known key at a
    new address; ssh), place it (§4.5), keep it, mirror it once. Returns its entry. A question of
    §4.5 (Ask) goes to `ask` (a terminal's prompt: "new", "replace:MID" or None) while the link
    stays open, so a fresh pairing is kept; without an answer that pairing is given back there
    before the question is raised."""
    t = parse_target(target)
    book = Book()
    if len(book.pinned()) >= MAX_MACHINES:
        raise SyncError("too_many", "Twelve machines are watched. Remove one to add another.")
    client = token = fp_hex = None
    if t["transport"] == "ssh":
        link = Link(argv=ssh_argv(t["host"], t["user"], t["port"]))
        try:
            machine = link.hello()
        except SyncError:
            rc, tail = link.exit_status(2.0), link.stderr_tail()
            link.close()
            if rc == 255:
                raise SyncError("ssh", "ssh could not sign in%s. Try it in a terminal: ssh %s"
                                % (tail, show_target(t)))
            if rc == 127:
                raise SyncError("not_oomph", "%s is not installed on %s" % (oomph.CMD, net.clean(t["host"], 64)))
            raise
        peer = t["host"]
    else:
        tls, fp, peer = tls_connect(t["host"], t["port"])
        fp_hex = "sha256:" + fp.hex()
        link = Link(sock=tls)
        known = book.by_fp(fp_hex)
        try:
            if known and known["mid"] in book.secrets and not code:
                s = book.secrets[known["mid"]]
                machine = tls_auth(link, s["client"], base64.b64decode(s["token"]), fp)
            else:
                code = net.norm_code(code) if code else None
                if not code:
                    raise SyncError("needs_code", "%s needs a pairing code: run `sudo oomph share pair` there, then: "
                                    "oomph remote add %s in a terminal (it asks), or with --code - (the code on "
                                    "standard input)" % (show_target(t), show_target(t)))
                machine, client, token = tls_pair(link, fp, code, socket.gethostname().split(".")[0])
        except SyncError:
            link.close()
            raise
    try:
        while True:
            try:
                mid, e = keep_machine(book, machine, fp_hex, t, as_, name, client, token)
                break
            except Ask as q:
                as_ = ask(q) if ask is not None and as_ is None else None
                if as_ is not None:
                    continue
                if token is not None:
                    give_back(link)
                    q.detail += (" The pairing made just now was given back there and its code is used up: make a "
                                 "new one there (sudo oomph share pair) for that.")
                raise
            except SyncError:
                if token is not None:
                    give_back(link)
                raise
        mirror = book.mirror(mid)
        mirror.put_json("", "machine.json", machine)
        remember(book, e, machine, peer)
        s = Sync(link, mirror, machine)
        try:
            s.run()
        finally:
            s.save()
        write_status(mirror, state="idle", was="live", last_contact=time.time(), transport=t["transport"],
                     connect_ms=machine.get("connect_ms"), pid=None, error=None, detail=None)
        return book.load().get(mid), s
    finally:
        link.close()


def keep_machine(book, machine, fp_hex, t, as_, name, client, token):
    """add_machine's entry (and token), placed and saved under the book's lock: (mid, entry)."""
    with book.locked():
        mid, old = book.place(machine, fp_hex, t, as_)
        e = dict(old or {}, mid=mid, transport=t["transport"], host=t["host"], port=t["port"], user=t["user"],
                 fp=fp_hex, pinned=True)
        e.setdefault("added", time.time())
        e.setdefault("order", max([x.get("order") or 0 for x in book.machines] + [0]) + 1)
        if name is not None:
            e["label"] = net.clean(name, 64) or None
        e["id"] = machine.get("id") if isinstance(machine.get("id"), str) and MID.fullmatch(machine["id"]) else None
        e = valid_entry(e)
        if not e:
            raise SyncError("bad_address", "that address can't be kept")
        book.machines = [x for x in book.machines if x["mid"] != mid] + [e]
        if token is not None:
            book.secrets[mid] = {"client": client, "token": base64.b64encode(token).decode()}
        book.save()
    return mid, e


def give_back(link):
    """Best effort: a pairing this run made and cannot keep is undone there (no orphan entry)."""
    try:
        link.call("unpair", timeout=10)
    except (SyncError, net.RPCError, OSError):
        pass


def ask_as(q):
    """§4.5's question in a terminal: (new | replace:MID | None)."""
    sys.stderr.write(oomph.wrap("oomph: remote add: " + q.detail) + "\n")
    try:
        a = input("Keep it as [n]ew (a second tab), [r]eplace %s, or [c]ancel? " % net.clean(str(label(q.known)), 32))
    except (EOFError, KeyboardInterrupt):
        return None
    a = a.strip().lower()
    return "new" if a in ("n", "new") else "replace:" + q.known["mid"] if a in ("r", "replace") else None


def _read_code(arg):
    if arg == "-":
        return sys.stdin.readline(200).strip()
    if arg:
        return arg
    if sys.stdin.isatty():
        try:
            import getpass
            return getpass.getpass("Pairing code (from `sudo oomph share pair` there): ")
        except (EOFError, KeyboardInterrupt):
            return None
    return None


def list_rows(book):
    rows = []
    for e in book.machines:
        st = book.mirror(e["mid"]).json("", "status.json") or {} if os.path.isdir(os.path.join(book.base, e["mid"])) else {}
        rows.append(dict({k: e.get(k) for k in ENTRY_KEYS if k != "client"}, status={
            k: st.get(k) for k in ("state", "was", "error", "detail", "last_contact", "updated")},
            ai_allowed=net.AI_CAP in (e.get("caps") or [])))
    return rows


def print_list(rows):
    if not rows:
        print("No machines yet. Add one: oomph remote add HOST (a shared Mac; it asks for the code), or USER@HOST (ssh)")
        return
    for tabs in (True, False):
        group = [r for r in rows if r["pinned"] == tabs]
        if not tabs and group:
            print("Recent (not watched):")
        for r in group:
            st = r["status"]
            words = {"live": "live", "catching_up": "catching up", "connecting": "connecting",
                     "offline": "not connected", "needs_attention": "needs attention"}
            state = words.get(st.get("state"), st.get("state")) if st.get("state") not in (None, "idle") else \
                "not followed now" + (" (last: %s)" % words.get(st["was"], st["was"]) if st.get("was") else "")
            when = st.get("last_contact")
            print("  %-16s %-3s %-28s %s%s" % (net.clean(str(label(r)), 16), r["transport"], net.clean(show_target(r), 28),
                                               state, " · last contact %s" % time.strftime("%Y-%m-%d %H:%M", time.localtime(when))
                                               if oomph._num(when, 0, 1e11) else ""))
            bits = [x for x in (r.get("os_version") and "%s %s" % (r.get("os") or "", r["os_version"]),
                                r.get("version") and oomph.CMD + " " + r["version"],
                                "AI analysis allowed" if r["ai_allowed"] else "AI analysis not allowed there") if x]
            if st.get("error") and st.get("detail"):
                bits.append(net.clean(str(st["detail"]), 120))
            print("  %-16s     %s" % ("", " · ".join(bits)))


def cmd_remote(args):
    sub, rest = (args[0] if args else ""), args[1:]
    if sub == "_link":
        if len(rest) < 1 or not MID.fullmatch(rest[0]):
            return 2
        return run_link(rest[0], unpair="--unpair" in rest[1:])
    if sub == "sync":
        return cmd_sync(rest)
    takes = {"add": (("--code", "--name", "--as"), ("--json",), 1), "list": ((), ("--json",), 0),
             "remove": ((), (), 1), "forget": ((), (), 1), "rename": ((), (), 2)}
    if sub not in takes:
        sys.stderr.write(REMOTE_USAGE + "\n")
        return 0 if sub in ("", "-h", "--help", "help") else 2
    try:
        o, pos = oomph._strict(rest, *takes[sub][:2], npos=takes[sub][2])
        if len(pos) != takes[sub][2]:
            raise oomph.UsageError("%s takes %d argument%s" % (sub, takes[sub][2], "s" if takes[sub][2] > 1 else ""))
        if "--as" in o and not (o["--as"] == "new" or re.fullmatch(r"replace:" + MID.pattern, o["--as"])):
            raise oomph.UsageError("--as takes new or replace:MID")
    except oomph.UsageError as e:
        return oomph._usage_error("remote " + sub, e, REMOTE_USAGE)
    try:
        if sub == "add":
            try:
                parse_target(pos[0])
            except ValueError as e:
                raise SyncError("bad_address", "%s (an address is HOST[:PORT], USER@HOST or ssh://…)" % e)
            code = _read_code("-") if o.get("--code") == "-" else o.get("--code")
            if o.get("--code") not in (None, "-") and sys.stdin.isatty():
                sys.stderr.write("oomph: note: a code on the command line can be read by other users of this Mac "
                                 "while it runs; leave out --code and it is asked for\n")
            ask = ask_as if sys.stdin.isatty() and "--json" not in o and o.get("--code") != "-" else None
            try:
                e, s = add_machine(pos[0], code, o.get("--name"), o.get("--as"), ask)
            except SyncError as err:
                if err.code == "needs_code" and "--code" not in o and sys.stdin.isatty() and "--json" not in o:
                    code = _read_code(None)
                    if not code:
                        raise
                    e, s = add_machine(pos[0], code, o.get("--name"), o.get("--as"), ask)
                else:
                    raise
            if "--json" in o:
                print(json.dumps({"ok": True, "machine": {k: e.get(k) for k in ENTRY_KEYS if k != "client"},
                                  "counts": s.counts}))
            else:
                print("Added %s (%s, %s): %d samples, %d incidents, %d live reservations mirrored. Follow it live: "
                      "oomph remote sync (the app's tabs: defaults write local.oomph.menubar machinesUI -bool YES)"
                      % (net.clean(str(label(e)), 64), e["transport"], show_target(e), s.counts["samples"],
                         s.counts["incidents"], s.counts["leases"]))
                if e.get("os") not in (None, "macos"):
                    print("It is watched from the terminal for now (oomph remote sync, oomph top); the app gives "
                          "it a tab once it knows that system's words (1.13).")
            return 0
        book = Book()
        if sub == "list":
            rows = list_rows(book)
            print(json.dumps({"machines": rows})) if "--json" in o else print_list(rows)
            return 0
        e = book.find(pos[0])
        if not e:
            raise SyncError("bad_address", "no machine named %s: oomph remote list" % net.clean(pos[0], 64))
        if sub == "remove":
            edit("unpin", e["mid"])
            print("%s is no longer watched (oomph remote add %s brings it back; forget drops it)."
                  % (net.clean(str(label(e)), 64), show_target(e)))
        elif sub == "rename":
            edit("rename", e["mid"], pos[1])
            print("Renamed %s to %s." % (net.clean(str(label(e)), 64), net.clean(pos[1], 64)))
        elif sub == "forget":
            edit("forget", e["mid"])
            print("Forgot %s: its pairing there (if it could be reached), its history here and its entry."
                  % net.clean(str(label(e)), 64))
        return 0
    except SyncError as err:
        if "--json" in o:
            print(json.dumps({"ok": False, "error": err.code, "detail": err.detail}))
        else:
            sys.stderr.write(oomph.wrap("oomph: remote %s: %s" % (sub, err.detail)) + "\n")
        return 1


def cmd_sync(args):
    cmd = None
    if "--" in args:
        i = args.index("--")
        args, cmd = args[:i], args[i + 1:]
    try:
        o, pos = oomph._strict(args, takes=("--into",), flags=("--once", "--json"), npos=1)
    except oomph.UsageError as e:
        return oomph._usage_error("remote sync", e, REMOTE_USAGE)
    if "--once" not in o:
        if cmd is not None or pos or "--into" in o:
            return oomph._usage_error("remote sync", "without --once it takes only --json", REMOTE_USAGE)
        try:
            eng = Engine("--json" in o)
        except SyncError as e:
            sys.stderr.write("oomph: remote sync: %s\n" % e.detail)
            return 1
        signal.signal(signal.SIGTERM, lambda *a: setattr(eng, "quit", True))
        signal.signal(signal.SIGHUP, lambda *a: setattr(eng, "quit", True))
        try:
            eng.loop()
        except KeyboardInterrupt:
            eng.shutdown()
        return 0
    if "--into" in o or cmd is not None:
        if cmd is not None and not cmd:
            return oomph._usage_error("remote sync", "nothing after --", REMOTE_USAGE)
        argv = cmd or [sys.executable or oomph.PY, "-I", "-B", os.path.realpath(oomph.__file__), "serve", "--stdio"]
        try:
            r = sync_once(argv, into=o.get("--into"))
        except SyncError as e:
            if "--json" in o:
                print(json.dumps({"ok": False, "error": e.code, "detail": e.detail}))
            else:
                sys.stderr.write(oomph.wrap("oomph: remote sync: %s" % e.detail) + "\n")
            return 1
        if "--json" in o:
            print(json.dumps(dict(r, ok=True)))
            return 0
        c, m = r["counts"], r["machine"]
        print(oomph.wrap("Mirrored %s (%s) into %s" % (net.clean(str(m.get("name") or "?"), 64), m.get("id") or "no id",
                                                       r["mirror"])))
        print(oomph.wrap("%d samples in %d days (%.1f h covered), %d events, %d reservation records, "
                         "%d incidents, %d live reservations%s" % (
                             c["samples"], r["days"], r["have_h"], c["events"], c["records"], c["incidents"], c["leases"],
                             "; %d rows failed the checks" % sum(r["dropped"].values()) if any(r["dropped"].values()) else "")))
        return 0
    try:
        book = Book()
    except SyncError as e:
        sys.stderr.write("oomph: remote sync: %s\n" % e.detail)
        return 1
    targets = [book.find(pos[0])] if pos else book.pinned()
    if pos and not targets[0]:
        sys.stderr.write("oomph: remote sync: no machine named %s: oomph remote list\n" % net.clean(pos[0], 64))
        return 1
    if not targets and "--json" not in o:  # since 1.10 `--once` alone syncs the watched machines, not this one
        print("No machines to sync: oomph remote add HOST (this machine itself: --into DIR)")
    worst, out = 0, []
    for e in targets:
        rc = run_link(e["mid"], once=True, out=open(os.devnull, "w"))
        st = book.mirror(e["mid"]).json("", "status.json") or {}
        out.append({"id": e["mid"], "name": label(e), "ok": rc == EXIT_STOPPED, "state": st.get("state"),
                    "error": st.get("error"), "detail": st.get("detail")})
        worst = max(worst, 0 if rc == EXIT_STOPPED else 1)
        if "--json" not in o:
            print("%-16s %s" % (net.clean(str(label(e)), 16), "caught up" if rc == EXIT_STOPPED else
                                "%s: %s" % (st.get("error"), net.clean(str(st.get("detail") or ""), 160))))
    if "--json" in o:
        print(json.dumps({"ok": worst == 0, "machines": out}))
    return worst
