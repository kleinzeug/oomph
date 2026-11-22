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
import gzip
import hashlib
import io
import json
import math
import os
import re
import secrets
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
    """A protocol session with a server on a child's standard streams. The child's stderr goes to
    a temporary file, its last line quoted when the session fails."""

    def __init__(self, argv):
        self.err = tempfile.TemporaryFile()
        try:
            self.p = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.err,
                                      close_fds=True)
        except OSError as e:
            raise SyncError("not_oomph", "can't start %s: %s" % (argv[0], e.strerror or e))
        self.lines = net.Lines(self.p.stdout.fileno(), net.LINE_OUT)
        self.next_id = 0
        self.notes = []

    def send(self, method, params=None):
        self.next_id += 1
        req = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        try:
            net.write_all(self.p.stdin.fileno(), net.dumps(req) + b"\n")
        except OSError:
            raise SyncError("closed", "the other end closed the connection%s" % self.stderr_tail())
        return self.next_id

    def stderr_tail(self):
        try:
            self.err.seek(0, os.SEEK_END)
            n = self.err.tell()
            self.err.seek(max(0, n - 4096))
            last = [x for x in self.err.read().decode("utf-8", "replace").splitlines() if x.strip()]
        except OSError:
            return ""
        return (": " + net.clean(last[-1], 160)) if last else ""

    def read(self, timeout):
        try:
            line = self.lines.read(timeout)
        except net.Closed as e:
            raise SyncError("closed", "the other end closed the connection (%s)%s" % (e, self.stderr_tail()))
        if line is None:
            raise SyncError("timeout", "no answer within %d s" % timeout)
        return line

    def hello(self, now=time.time):
        """Say hello and skip whatever precedes the answer (a login banner, a shell's start-up
        output): at most NOISE[0] bytes and NOISE[1] lines (roadmap 01 §5.1)."""
        t0 = now()
        rid = self.send("hello", {"proto": list(net.PROTO), "client": {"app": oomph.CMD, "version": oomph.VERSION,
                                                                       "os": sys.platform},
                                  "nonce": base64.b64encode(os.urandom(16)).decode()})
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
        t1 = now()
        if "error" in msg:
            e = msg["error"] if isinstance(msg["error"], dict) else {}
            if e.get("code") == net.ERR["proto"]:
                raise SyncError("incompatible", "its protocol versions %s do not overlap ours %s"
                                % (net.clean(json.dumps(e.get("data")), 60), list(net.PROTO)))
            raise SyncError("not_oomph", "hello refused: %s" % net.clean(str(e.get("message")), 120))
        r = msg["result"]
        if not (isinstance(r, dict) and isinstance(r.get("machine"), dict) and r.get("proto") in range(net.PROTO[0], net.PROTO[1] + 1)):
            raise SyncError("incompatible", "an answer to hello this version does not understand")
        m = clean(r["machine"], 200)
        if not oomph._num(m.get("now"), 0, 1e11):
            raise SyncError("not_oomph", "hello without the server's time")
        m["offset_s"] = round(m["now"] - (t0 + t1) / 2, 3)
        m["connect_ms"] = int((t1 - t0) * 1000)
        if not (m.get("oldest") is None or oomph._num(m["oldest"], 0, 1e11)):
            m["oldest"] = None
        return m

    def call(self, method, params=None, timeout=CALL_TIMEOUT_S):
        rid = self.send(method, params)
        while True:
            msg = _json(self.read(timeout))
            if not isinstance(msg, dict):
                raise SyncError("not_oomph", "a line that is not a frame")
            if "id" not in msg:
                if len(self.notes) < 1000:
                    self.notes.append(msg)
                continue
            if msg.get("id") != rid:
                continue
            if "error" in msg:
                e = msg["error"] if isinstance(msg["error"], dict) else {}
                raise net.RPCError(e.get("code"), net.clean(str(e.get("message")), 200), e.get("data"))
            return msg.get("result")

    def close(self):
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


REMOTE_USAGE = ("usage: oomph remote sync --once [--into DIR] [--json] [-- COMMAND …]\n"
                "  mirror the machine whose `oomph serve --stdio` COMMAND starts (default: this one's)")


def cmd_remote(args):
    if args[:1] != ["sync"]:
        sys.stderr.write(REMOTE_USAGE + "\n")
        return 2
    args = args[1:]
    cmd = None
    if "--" in args:
        i = args.index("--")
        args, cmd = args[:i], args[i + 1:]
    try:
        oomph._strict(args, takes=("--into",), flags=("--once", "--json"), npos=0)
    except oomph.UsageError as e:
        return oomph._usage_error("remote sync", e, REMOTE_USAGE)
    if "--once" not in args:
        sys.stderr.write("oomph: remote sync: only --once exists so far (the engine that stays connected "
                         "comes later)\n" + REMOTE_USAGE + "\n")
        return 2
    if cmd is not None and not cmd:
        sys.stderr.write(REMOTE_USAGE + "\n")
        return 2
    argv = cmd or [sys.executable or oomph.PY, "-I", "-B", os.path.realpath(oomph.__file__), "serve", "--stdio"]
    try:
        r = sync_once(argv, into=oomph._opt(args, "--into"))
    except SyncError as e:
        if "--json" in args:
            print(json.dumps({"ok": False, "error": e.code, "detail": e.detail}))
        else:
            sys.stderr.write(oomph.wrap("oomph: remote sync: %s" % e.detail) + "\n")
        return 1
    if "--json" in args:
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
