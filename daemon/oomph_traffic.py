"""Internet traffic (NET, 1.15; roadmap NET-concept §12): what this machine moves through its internet line, per
process, and the per-network records in the shared ledger folder (networks.json) that say what the line can carry.

Measuring is always on and causes no traffic. On a Mac the logger runs one fresh `nettop` per sample (every live
connection with its process and its counters), reads the physical interface's 64-bit byte counters and asks the
routing table which interface and gateway reach the internet; on Linux `ss` and /proc/net/dev do the same. Each
connection's remote address is tested once, LAN or internet, and dropped there (§8): nothing here returns one. Rates
are payload (the unit of networkQuality and of every limiter): the interface's wire bytes less LAN traffic, divided
by WIRE_X, or the connections' own sum where that is more (12.4).

The backends run the programs and read the counters (oomph_darwin, oomph_linux: net_route, net_bytes, net_flows,
router_mac, router_mac6); this module parses what they hand over as untrusted input (fixed limits on rows, line
length and numbers), keeps the deltas between samples, picks the network's identity, reads and writes networks.json
under the ledger lock, and answers `oomph net`, `oomph ps --net` and the network line of the other commands.

A part of oomph.py, kept apart so that what never meets the network (oomph top, the hook) does not compile or hold
it: oomph._T() imports it and it reads oomph's names as its own (bound once, below). Standard library only."""
import hashlib
import ipaddress
import sys
import unicodedata

globals().update((k, v) for k, v in vars(sys.modules["oomph_traffic_host"]).items() if not k.startswith("__"))
_H = sys.modules["oomph_traffic_host"]   # for the host's names that change after import (_lock_wait)

WIRE_X = 1.08            # wire bytes per byte of payload at saturation (probe mac-3: 211.6 against 195.6 Mbit/s)
ACK_X = 0.03             # wire bytes of ACKs the other way per byte of TCP payload (a 66-byte ACK per two 1448-byte
                         # segments): what a LAN transfer adds to the opposite direction's counter
WIRE_CAP_X, WIRE_CAP_B = 1.1, 1 << 20   # the flows of an interval at most this × the interface's bytes (less the
                                        # LAN's) + this: the counters are read a moment apart
FLOWS_CAP = 4 << 20      # bytes of nettop's or ss's output: more is a sample without per-process figures
FLOWS_ROWS = 20000       # rows of it
LINE_MAX = 512           # characters of a nettop row (a longer one is dropped)
SS_LINE_MAX = 4096       # ... of an ss line (with -i -e -O one line carries the socket's whole state)
COUNT_DIGITS = 20        # digits of a byte counter (2**64 has 20)
MAX_DT_S = 120           # longer between two samples: no rates (a gap)
NAMES_N = 5              # rows of net_names
TOP_NET_N = 8            # rows of top_net (oomph ps --net)
NAMES_MIN_MBPS = 0.1     # a name moving less is left out of net_names
BACKOFF_S = (300, 3600)  # nettop timed out or listed too much: skipped this long, doubling up to the second
IDENT_S = 600            # a network known only by its gateway asks for the router's MAC again after this long
STALE_X = 1.1            # this machine alone seen above its line's figure by this much: the figure is stale
BUSY_X = 0.1             # `net test` on a line busy with more than this share of its figure: the result reads low
NETWORKS_MAX = 64        # entries of networks.json
FUTURE_S = 300           # a stored time at most this far ahead is kept (another user's clock read a moment later):
                         # one further ahead would rank its entry above every later one
NETWORKS_UNKNOWN = 16    # unknown scalar fields of an entry carried through (a later writer's)
FIG_MIN, FIG_MAX = 0.5, 100000.0    # Mbit/s of a stored figure
RATE_MIN, RATE_MAX = 1.0, 100000.0  # Mbit/s a command takes (--net-rate, net set)
VOL_MIN, VOL_MAX = 0.01, 1000000.0  # GB a command takes (--net, --cap)
NQ = "/usr/bin/networkQuality"
NQ_ARGS = ["-s", "-M", "60", "-c"]  # sequential (parallel reads the uplink 19 % low, mac-9), at most 60 s, JSON
                                    # last (-c takes an optional file name)
NQ_TIMEOUT_S = 120

# ------------------------------------------------------------------ LAN or internet (12.3)
# Explicit lists, not ipaddress's is_private (whose answers differ between Python 3.9 and 3.14). CGNAT space
# (100.64/10) is reached through the line: internet.
_LAN4 = tuple(ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                                "127.0.0.0/8", "0.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"))
_LAN6 = tuple(ipaddress.ip_network(x) for x in ("::1/128", "::/128", "fe80::/10", "fc00::/7", "ff00::/8"))


def onlink_nets(cidrs):
    """The on-link prefixes of the physical interface (its IPv4 subnet, its IPv6 prefixes) as networks; what does not
    parse is left out."""
    out = []
    for c in cidrs or ():
        try:
            n = ipaddress.ip_network(str(c), strict=False)
        except ValueError:
            continue
        if n.prefixlen >= (8 if n.version == 4 else 32):  # a prefix wider than that is no LAN (a /0 would be all of it)
            out.append(n)
    return tuple(out[:32])


def is_lan(host, onlink=()):
    """True for a LAN address (the lists above, or a prefix of the physical interface: a NAS reached by its global
    IPv6 address), False for the internet, None for what is not an address (not attributed)."""
    try:
        a = ipaddress.ip_address(str(host).split("%", 1)[0])
    except ValueError:
        return None
    if a.version == 6 and a.ipv4_mapped is not None:
        a = a.ipv4_mapped
    return any(a in n for n in (_LAN4 if a.version == 4 else _LAN6)) or \
        any(n.version == a.version and a in n for n in onlink)


# ------------------------------------------------------------------ parsing what the backends hand over
_FLOW = re.compile(r"(tcp4|tcp6|udp4|udp6|quic4|quic6) (\S{1,200})<->(\S{1,200})\Z")
_PROC = re.compile(r"(.{1,15})\.(\d{1,10})\Z", re.S)   # nettop cuts a process's name to 15 characters


def _count(x):
    """A byte counter: "" is 0, else up to COUNT_DIGITS digits; None for anything else (the row is dropped)."""
    if x == "":
        return 0
    return int(x) if len(x) <= COUNT_DIGITS and x.isdigit() and x.isascii() else None


def _endpoint_host(ep, v6):
    """The address of a nettop endpoint (`a.b.c.d:port`, IPv6 `addr.port`, a scope after %), None for `*`."""
    h, sep, port = ep.rpartition("." if v6 else ":")
    if not sep or not h or h == "*" or not (port.isdigit() or port == "*"):
        return None
    return h.split("%", 1)[0]


def nettop_flows(data, procs, onlink=(), phys=None, tun=None):
    """nettop's rows (`-L 1 -x -n -t external -J interface,state,bytes_in,bytes_out`) as flows, and why they are
    not every flow (None: complete; "columns", "cap"). A flow is (pid, key, where, lan, bytes in, bytes out):
    `pid` its process's (None where the process row is not one of `procs`), `key` what identifies it from sample to
    sample (a hash of nettop's own pid and the addresses, which go no further: a process started after `procs` was
    read keeps its flows' key when it is in the next one), `where` "phys" or "tun" (rows on another interface or none are
    left out: their bytes stay in the interface's total), `lan` the test of 12.3. Columns are found by the header's
    names (-J "may change order"); a process's name may hold commas, so a row is split from its end. A row that
    reads as a flow and as a process (a process named like one) is a process when nettop listed no interface or
    state for it, as for every process row (its flows are nobody's when its pid is not one of `procs`)."""
    if data is None:
        return None, "missing"
    text = data[:FLOWS_CAP + 1].decode("utf-8", "replace") if isinstance(data, bytes) else str(data)[:FLOWS_CAP + 1]
    if len(text) > FLOWS_CAP:
        return None, "cap"
    lines = text.split("\n")
    head = lines[0].rstrip("\r").split(",") if lines else []
    col = {c: i for i, c in enumerate(head) if c}
    if not head or head[0] != "" or any(c not in col for c in ("interface", "state", "bytes_in", "bytes_out")):
        return None, "columns"
    n, ii, si, bi, bo = len(head), col["interface"], col["state"], col["bytes_in"], col["bytes_out"]
    procs = procs or {}
    out, pid, raw, rows = [], None, None, 0
    for line in lines[1:]:
        line = line.rstrip("\r")
        if not line or len(line) > LINE_MAX:
            continue
        rows += 1
        if rows > FLOWS_ROWS:
            return out, "cap"
        parts = line.rsplit(",", n - 1)
        if len(parts) != n:
            continue
        name, iface, state = parts[0], parts[ii], parts[si]
        f, p = _FLOW.match(name), _PROC.match(name)
        if p and (not f or (iface == "" and state == "")):
            raw = int(p.group(2))
            pid = raw if raw in procs else None
            continue
        if not f:
            pid = raw = None  # a row of neither kind: the flows under it are nobody's
            continue
        where = "phys" if iface and iface == phys else "tun" if iface and iface == tun else None
        cin, cout = _count(parts[bi]), _count(parts[bo])
        if where is None or cin is None or cout is None or state == "Listen":
            continue
        host = _endpoint_host(f.group(3), f.group(1).endswith("6"))
        lan = is_lan(host, onlink) if host else None
        if lan is None:
            continue
        out.append((pid, hash((raw, f.group(1), f.group(2), f.group(3))), where, lan, cin, cout))
    return out, None


_SS_STATES = frozenset(("ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT", "CLOSE", "CLOSE-WAIT",
                        "LAST-ACK", "CLOSING"))
# users:(("name",pid=N,fd=N),…) right after the addresses. ss reads a name from /proc/<pid>/stat up to its first `)`,
# so a name holds none: an entry ends at the first `)`, and its pid is the one just before it (a name that imitates
# `",pid=4242,` comes earlier).
_SS_USERS = re.compile(r'users:\(\("[^)]{0,64}",pid=(\d{1,10}),fd=\d{1,10}\)'
                       r'(?:,\("[^)]{0,64}",pid=\d{1,10},fd=\d{1,10}\)){0,63}\)')
# What the kernel says of the socket (-e): [uid:N ]ino:N sk:COOKIE, then cgroup:<path> (a path the user names), the
# shutdown arrow and the -i block. The first of them after users: is the kernel's (a name of 15 characters cannot hold
# one with what must follow it).
_SS_SOCK = re.compile(r"(?:^| )(?:uid:(\d{1,10}) )?ino:\d{1,20} sk:([0-9a-f]{1,16})"
                      r"(?= (?:cgroup|fwmark):| <->| -->| <--| ---|\s*\Z)")
_SS_ARROWS = (" <->", " -->", " <--", " ---")
_SS_IN = re.compile(r"(?:^| )bytes_received:(\d{1,20})(?= |\Z)")
_SS_OUT = re.compile(r"(?:^| )bytes_acked:(\d{1,20})(?= |\Z)")


def _ss_host(ep):
    """(address, scope) of an ss endpoint (`a.b.c.d:port`, `[v6]:port`, `[fe80::1%eth0]:port`); None for `*`."""
    if ep.startswith("["):
        h = ep[1:].split("]", 1)[0]
    else:
        h = ep.rpartition(":")[0]
    h, _, scope = h.partition("%")
    return (h, scope) if h and h != "*" else (None, None)


def _ip(x):
    """An address (a prefix after / and a scope after % dropped, an IPv4-mapped one as IPv4), or None."""
    try:
        a = ipaddress.ip_address(str(x).split("/", 1)[0].split("%", 1)[0])
    except ValueError:
        return None
    return a.ipv4_mapped if a.version == 6 and a.ipv4_mapped is not None else a


def addr_set(addrs):
    """The interface's own addresses (`a.b.c.d/24`, `2001:db8::11/64`, …) as a set; what does not parse is left out."""
    return frozenset(a for a in (_ip(x) for x in list(addrs or ())[:256]) if a is not None)


def ss_flows(data, procs, onlink=(), eg=None):
    """`ss -tinpeHO`'s sockets as flows (nettop_flows' shape), and why they are not every flow. ss names no interface:
    a socket is the physical device's ("phys") when its local address is one of that device's (`eg["addrs"]`) or its
    link-local scope names it, the tunnel's ("tun") likewise (`eg["tun_addrs"]`); loopback and every other device's
    sockets (a bridge's, a container's, a second NIC's) are left out, since their bytes never crossed the device
    counted. Without those addresses nothing is attributed ("addrs": totals only). LISTEN is skipped; the counters
    are bytes_received (in) and bytes_acked (out: bytes_sent counts retransmissions), a missing one 0; the key is the
    socket's cookie (`sk:`). A socket's pid is the first of its `users:` (only one's own as a user, every one as root,
    12.2), kept only where that process is one of `procs` with the socket's owner (`uid:`, printed when not 0) or the
    socket is root's (an accepted socket keeps its listener's owner: sshd's session child, a web server's worker).
    Parsed by position, because a process's name and a cgroup's path are a user's words: the pid is the one closing
    its users: entry, uid and cookie the first kernel sequence after users:, the counters only from the -i block after
    the last shutdown arrow (a path that imitates one comes before the kernel's)."""
    if data is None:
        return None, "missing"
    eg = eg or {}
    mine, tun = addr_set(eg.get("addrs")), addr_set(eg.get("tun_addrs"))
    if not mine or (eg.get("tun") and not tun):
        return None, "addrs"
    text = data[:FLOWS_CAP + 1].decode("utf-8", "replace") if isinstance(data, bytes) else str(data)[:FLOWS_CAP + 1]
    if len(text) > FLOWS_CAP:
        return None, "cap"
    procs = procs or {}
    out, rows = [], 0
    for line in text.split("\n"):
        if not line.strip() or len(line) > SS_LINE_MAX:
            continue
        rows += 1
        if rows > FLOWS_ROWS:
            return out, "cap"
        t = line.split(None, 5)
        if len(t) < 6 or t[0] not in _SS_STATES:
            continue
        (lh, lscope), (ph, _) = _ss_host(t[3]), _ss_host(t[4])
        la, pa = _ip(lh) if lh else None, _ip(ph) if ph else None
        if la is None or pa is None or la.is_loopback or pa.is_loopback:
            continue
        if lscope:
            where = "phys" if lscope == eg.get("if") else "tun" if eg.get("tun") and lscope == eg["tun"] else None
        else:
            where = "phys" if la in mine else "tun" if la in tun else None
        lan = is_lan(ph, onlink)
        if where is None or lan is None:
            continue
        rest, pid = t[5], None
        if rest.startswith("users:"):
            m = _SS_USERS.match(rest)
            if not m:
                continue
            pid, rest = int(m.group(1)), rest[m.end():]
        k = _SS_SOCK.search(rest)
        if not k:
            continue
        uid = int(k.group(1) or 0)
        if pid is not None and (pid not in procs or uid not in (0, procs[pid].get("uid"))):
            pid = None
        tail = rest[k.end():]
        cut = max(tail.rfind(x) for x in _SS_ARROWS)
        info = tail[cut + 4:] if cut >= 0 else ""
        cin, cout = _SS_IN.search(info), _SS_OUT.search(info)
        out.append((pid, hash(("sk", k.group(2))), where, lan, int(cin.group(1)) if cin else 0,
                    int(cout.group(1)) if cout else 0))
    return out, None


def norm_mac(x):
    """A MAC as the key writes it: lowercase, zero-padded (`arp` prints 3c:a6:2f:1:2:3), or None (incomplete, all
    zeros, broadcast, not six parts, or 02:00:00:00:00:00: what macOS shows an unprivileged caller instead)."""
    parts = str(x or "").strip().lower().split(":")
    if len(parts) != 6 or not all(1 <= len(p) <= 2 and all(c in "0123456789abcdef" for c in p) for p in parts):
        return None
    mac = ":".join(p.zfill(2) for p in parts)
    return None if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:00") else mac


# ------------------------------------------------------------------ deltas, totals, attribution (12.4)
class Traffic:
    """The deltas from sample to sample. A flow counts what it moved since the previous sample (a counter that went
    down is a new connection on the same addresses: its whole count); a flow the previous sample did not list counts
    in full only when that sample listed every flow (after a start, a gap, a timeout or a capped sample every flow is
    a baseline). Rates need the previous sample on the same interface, less than MAX_DT_S before. Internet traffic
    per direction is the larger of the attributed flows and (the interface's bytes − the LAN flows' wire bytes, their
    ACKs the other way included, − the ACKs of the internet's other direction) / WIRE_X, so the sum per process never exceeds the flows, nor those the total; where the interface's bytes are known the flows are
    cut to them (WIRE_CAP_X: a counter that cannot be true never reaches a rate, a day's total or a process).
    `day`: internet bytes per network since local midnight (in memory: a restart begins again, 12.8's day counters
    come with the metered quota)."""

    def __init__(self):
        self.prev = None   # (mono, physical interface, (in, out) or None, {key: (in, out)}, complete, tunnel)
        self.day = {}      # network -> [date, in bytes, out bytes, an interval of totals only (the LAN's included)]

    def reset(self):
        self.prev = None

    def step(self, mono, now, eg, wire, flows, complete, procs, network, gap=False):
        """(block, {pid: [in, out]} bytes this interval, dt or None) for one sample; `eg` the egress (net_route)."""
        prev, phys = self.prev, eg["if"]
        dt = mono - prev[0] if prev else None
        # a VPN coming, going or moving is a baseline like another interface: the tunnel's long-lived flows, never
        # listed before (nettop -t external leaves utun out), would count their whole lives as this interval's
        ok = prev is not None and not gap and prev[1] == phys and prev[5] == eg.get("tun") and dt is not None and \
            0 < dt <= MAX_DT_S
        cur, lan, inet, per = {}, [0, 0], [0, 0], {}
        own = "tun" if eg.get("tun") else "phys"
        for pid, key, where, is_lan_, bi, bo in flows or ():
            if key in cur:  # two rows under one key (a parser's mistake, a planted cookie): the first counts
                continue
            cur[key] = (bi, bo)
            if not ok:
                continue
            if key in prev[3]:
                pi, po = prev[3][key]
                di, do = (bi - pi if bi >= pi else bi), (bo - po if bo >= po else bo)
            elif prev[4]:
                di, do = bi, bo
            else:
                continue
            if is_lan_ and where == "phys":
                lan[0] += di
                lan[1] += do
            elif where == own:   # every tunnel flow crosses the line, a private remote's (a corporate 10.x) too
                inet[0] += di
                inet[1] += do
                if pid is not None:
                    a = per.setdefault(pid, [0, 0])
                    a[0] += di
                    a[1] += do
        w = wire if wire and len(wire) == 2 and all(_num(x, 0, 2 ** 64) for x in wire) else None
        block = {"if": phys, "vpn": bool(eg.get("tun"))}
        if eg.get("tun"):
            block["tun"] = eg["tun"]
        if network:
            block["network"] = network
        block["src"] = "flows" if ok and complete and prev[4] and flows is not None else "if"
        if flows is not None:
            block["flows"] = len(flows)
        if ok:
            dw = (w[0] - prev[2][0], w[1] - prev[2][1]) if w and prev[2] and w[0] >= prev[2][0] and w[1] >= prev[2][1] \
                else None
            # the LAN's own wire bytes: its payload with the wire's overhead, and the ACKs it causes the other way
            lw = (lan[0] * WIRE_X + ACK_X * lan[1], lan[1] * WIRE_X + ACK_X * lan[0])
            if dw:  # the flows' payload never exceeds what the interface moved (less the LAN's): a new flow's whole
                for i in (0, 1):  # counter, a parser's error or a planted one is cut to that, per process alike
                    cap = max(0, dw[i] - lan[i] * WIRE_X) * WIRE_CAP_X + WIRE_CAP_B
                    if inet[i] > cap:
                        f = cap / inet[i]
                        inet[i] = cap
                        for a in per.values():
                            a[i] = int(a[i] * f)
            down, up = inet
            if dw:   # the wire less the LAN's is the internet's payload × WIRE_X plus the ACKs of the other way's
                D, U = max(0, dw[0] - lw[0]), max(0, dw[1] - lw[1])   # (d·W + a·u = D, u·W + a·d = U): a download
                k = WIRE_X * WIRE_X - ACK_X * ACK_X                   # alone reads no upload
                d, u = (WIRE_X * D - ACK_X * U) / k, (WIRE_X * U - ACK_X * D) / k
                d, u = (0, U / WIRE_X) if d < 0 else (D / WIRE_X, 0) if u < 0 else (d, u)
                down, up = max(inet[0], d), max(inet[1], u)
            rate = lambda b: round(b * 8 / dt / 1e6, 2)  # noqa: E731
            block.update(down_mbps=rate(down), up_mbps=rate(up), lan_mbps=rate(lan[0] + lan[1]))
            if network:
                self._add(network, now, down, up, block["src"] == "if")
        if network and network in self.day and self.day[network][0] == _date(now):
            block.update(in_gb=round(self.day[network][1] / 1e9, 3), out_gb=round(self.day[network][2] / 1e9, 3))
            if self.day[network][3]:
                block["day_src"] = "if"   # the day's figures hold some of the LAN's traffic too
        self.prev = (mono, phys, w, cur if complete and flows is not None else {}, bool(complete and flows is not None),
                     eg.get("tun"))
        return block, (per if ok else {}), (dt if ok else None)

    def _add(self, network, now, down, up, totals=False):
        d = _date(now)
        for k in [k for k, v in self.day.items() if v[0] != d]:
            del self.day[k]
        if network not in self.day and len(self.day) >= NETWORKS_MAX:
            return
        a = self.day.setdefault(network, [d, 0.0, 0.0, False])
        a[1] += down
        a[2] += up
        a[3] = a[3] or totals

    def rename(self, old, new):
        """The day's counters of `old` carried over to `new` (Identity.adopt: one network, its stored key)."""
        a = self.day.pop(old, None)
        if a is None or old == new:
            if a is not None:
                self.day[old] = a
            return
        b = self.day.get(new)
        if b is None or b[0] != a[0]:
            self.day[new] = a
        else:
            b[1], b[2], b[3] = b[1] + a[1], b[2] + a[2], b[3] or a[3]


def _date(t):
    return datetime.date.fromtimestamp(t).isoformat()


class Identity:
    """The network's identity (12.6): `rmac:<router MAC>` (the IPv4 gateway's ARP entry, else the IPv6 default
    router's neighbour entry: the same box), else `gw:<gateway>/<prefix>`. Sticky per (physical interface, gateway,
    subnet): the caches are read again every IDENT_S and after a gap (a sleep: when a laptop changes routers, and
    two FRITZ!Boxes share 192.168.178.1/24), and an rmac identity changes only to another MAC the IPv4 gateway's ARP
    entry names (the IPv6 default router's names only a network known by no router yet), never to gw: on a cache miss.
    None found is kept as long. The logger never sends a packet to fill a cache. `adopt`: networks.json keeps this
    gateway and subnet under an
    rmac key while this identity is a gw: one (the router's MAC not in the cache now): a cache miss never makes a
    new network. Never the other way: routers of one make share a default gateway and subnet (every FRITZ!Box is
    192.168.178.1/24), so a gw: entry names no router and an rmac identity takes none."""

    def __init__(self):
        self.tup, self.id, self.at, self.taken = None, None, None, False

    def get(self, P, eg, now, gap=False):
        tup = (eg.get("if"), eg.get("gw"), eg.get("subnet"))
        if tup != self.tup:
            self.tup, self.id, self.at, self.taken = tup, None, None, False
        if self.at is not None and not gap and 0 <= now - self.at < IDENT_S:
            return self.id   # none found is kept as long: an IPv6-only or point-to-point link asks no cache each sample
        self.at = now
        mac = mac6 = None
        try:
            if eg.get("gw") and hasattr(P, "router_mac"):
                mac = norm_mac(P.router_mac(eg["gw"], eg["if"]))
            if not mac and hasattr(P, "router_mac6"):
                mac6 = norm_mac(P.router_mac6(eg["if"]))
        except Exception:  # an identity is worth less than the sample
            mac = mac6 = None
        rmac = bool(self.id and self.id.startswith("rmac:"))
        if mac:
            if "rmac:" + mac != self.id:   # another router behind the same address (or the adopted key was not it)
                self.id, self.taken = "rmac:" + mac, False
        elif mac6 and not rmac:
            # the IPv6 default router's only names a network not yet known by a router: where the IPv4 gateway is
            # another box (a mesh, a border router), an ARP hit and miss in turn would flip between the two
            self.id, self.taken = "rmac:" + mac6, False
        elif rmac:
            pass   # a cache miss keeps the router found (or adopted)
        elif eg.get("gw") and eg.get("subnet"):
            self.id = "gw:%s/%s" % (eg["gw"], str(eg["subnet"]).rpartition("/")[2])
        else:
            self.id = None
        return self.id

    def adopt(self, key, asked=None, entry=None):
        """networks.json keeps this network under `key` (the child resolved it by gateway and subnet): that is its
        identity from now on, while interface, gateway and subnet stay. Only an answer to this identity (`asked`: the
        key the child was asked about; an answer about the network before a move is not one) for a gw: identity, and
        only an rmac key whose entry, where it says, has this gateway and subnet."""
        if not self.id or self.tup is None or key == self.id or asked != self.id or not self.id.startswith("gw:") or \
                not valid_key(key) or not key.startswith("rmac:"):
            return
        e = entry if isinstance(entry, dict) else {}
        if (e.get("gw") and e["gw"] != self.tup[1]) or (e.get("subnet") and e["subnet"] != self.tup[2]):
            return
        self.id, self.taken = key, True


class Sampler:
    """What the logger (and a live reading) does per sample: the egress, the identity, the interface's counters,
    the flows (nettop or ss, unless backing off), the deltas. read() returns (block, {pid: [in, out]}, dt); the
    block is {"if": None} offline, None where this backend measures no network."""

    def __init__(self, P):
        self.P, self.traffic, self.ident = P, Traffic(), Identity()
        self.off_until, self.backoff, self.status = 0.0, 0, None
        self.flows_kind = getattr(P, "NET_FLOWS", None)

    def adopt(self, key, asked=None, entry=None):
        """Identity.adopt, the day's counters carried along to the adopted key."""
        old = self.ident.id
        self.ident.adopt(key, asked, entry)
        if old and self.ident.id != old:
            self.traffic.rename(old, self.ident.id)

    def read(self, procs, gap=False, now=None):
        P = self.P
        if not hasattr(P, "net_route"):
            return None, {}, None
        now = time.time() if now is None else now
        eg = P.net_route()
        mono = time.monotonic()
        if not eg or not eg.get("if"):
            self.traffic.reset()
            self.ident.tup = self.ident.id = None   # back online, the network is found anew
            return {"if": None}, {}, None
        was, tup = self.ident.id, self.ident.tup
        network = self.ident.get(P, eg, now, gap)
        if was and network and was.startswith("gw:") and network.startswith("rmac:") and self.ident.tup == tup:
            self.traffic.rename(was, network)   # the router's MAC found later: the same network, its day carried on
        wire = P.net_bytes(eg["if"])
        flows, complete = None, False
        if self.flows_kind and mono >= self.off_until:
            data, why = P.net_flows(eg.get("tun"))
            if data is not None:
                parse = nettop_flows if self.flows_kind == "nettop" else ss_flows
                on = onlink_nets(eg.get("onlink"))
                flows, why = parse(data, procs, on, eg["if"], eg.get("tun")) if parse is nettop_flows \
                    else parse(data, procs, on, eg)
            if why in ("timeout", "cap"):
                self.backoff = min(BACKOFF_S[1], self.backoff * 2 or BACKOFF_S[0])
                # under a VPN nettop runs without -t external (it would leave the tunnel out) and lists loopback's
                # connections too: a Mac with many local ones (Docker, databases, language servers) reaches the
                # deadline sooner then, which the status says
                self.off_until, self.status, flows = mono + self.backoff, "too many connections" + (
                    " (loopback's included under a VPN)" if eg.get("tun") and self.flows_kind == "nettop" else ""), None
            elif why is None:
                self.backoff, self.status, complete = 0, None, True
            else:   # ss missing (the Linux service, a minimal image) is how it is there; anything else is named
                flows, self.status = None, None if why == "missing" and self.flows_kind == "ss" else \
                    "%s failed (%s)" % (self.flows_kind, why)
        block, per, dt = self.traffic.step(mono, now, eg, wire, flows, complete, procs, network, gap)
        return block, per, dt


def by_name(per, procs, dt, n=NAMES_N):
    """net_names: the busiest names by down + up (Mbit/s), merged by name with their count, at least NAMES_MIN_MBPS;
    names from the process table, never nettop's cut."""
    out = {}
    for pid, (bi, bo) in per.items():
        if pid in procs and dt:
            a = out.setdefault(str(procs[pid].get("name") or "?")[:64], [0.0, 0.0, 0])
            a[0] += bi * 8 / dt / 1e6
            a[1] += bo * 8 / dt / 1e6
            a[2] += 1
    rows = sorted(((v[0] + v[1], k, v) for k, v in out.items()), key=lambda x: (-x[0], x[1]))
    return [{"name": k, "down": round(v[0], 1), "up": round(v[1], 1), "n": v[2]} for s, k, v in rows[:n]
            if s >= NAMES_MIN_MBPS]


def top_net(per, procs, dt, session_of=None, group_key=None, n=TOP_NET_N):
    """top_net (current.json, `oomph ps --net`): the busiest processes, Mbit/s down and up, with the owner's uid."""
    rows = sorted(((bi + bo, pid) for pid, (bi, bo) in per.items() if pid in procs), reverse=True)
    out = []
    for _, pid in rows[:n]:
        p, (bi, bo) = procs[pid], per[pid]
        d, u = round(bi * 8 / dt / 1e6, 2), round(bo * 8 / dt / 1e6, 2)
        if d + u <= 0:
            break
        e = {"pid": pid, "name": p.get("name"), "uid": p.get("uid"), "down": d, "up": u}
        if group_key:
            e["g"] = group_key(p.get("path"), p.get("name"))
        if session_of and pid in session_of:
            e["s"] = session_of[pid]
        out.append(e)
    return out


def live(window=1.0, procs=None):
    """A live reading for the CLI when no logger runs: two samples `window` seconds apart. (block, top_net rows,
    net_names); (None, [], []) where this backend measures no network."""
    P = plat()
    sm = Sampler(P)
    procs = procs or P.collect_procs()
    if sm.read(procs)[0] is None:
        return None, [], []
    time.sleep(window)
    procs = P.collect_procs()
    block, per, dt = sm.read(procs)
    if block and block.get("network"):  # the key networks.json keeps it under, as the logger's child would name it
        try:
            block["network"] = resolve(read_networks()["networks"], block["network"], sm.ident.tup[1], sm.ident.tup[2])
        except LedgerError:
            pass
    if not dt:
        return block, [], []
    return block, top_net(per, procs, dt), by_name(per, procs, dt)


# ------------------------------------------------------------------ networks.json (12.7)
_KEY_RMAC = re.compile(r"rmac:[0-9a-f]{2}(?::[0-9a-f]{2}){5}")
_SET_BY = re.compile(r"[A-Za-z0-9._-]{1,32}")
_FIELD = re.compile(r"[a-z_][a-z0-9_]{0,31}")
_NOT_LABEL = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")   # controls; format (zero-width, soft hyphen, bidi); surrogates;
#                                                    private use; line and paragraph separators


def label_ok(x):
    """A label: 1 to 32 characters, not only spaces, none a control or an invisible one (Unicode categories Cc, Cf,
    Cs, Co, Zl, Zp: zero-width spaces and joiners, the soft hyphen, bidi marks), and not a word NETWORK reads as
    something else (`this`, a key, a public id `net-…`: oomph net's _target tries those before labels)."""
    return (isinstance(x, str) and 0 < len(x) <= 32 and bool(x.strip()) and
            not any(unicodedata.category(c) in _NOT_LABEL for c in x) and x.casefold() != "this" and
            not x.casefold().startswith("net-") and valid_key(x) is None)


def label_fold(x):
    """What labels are compared by (unique, and named): case folded, compatibility forms and combining marks taken
    off, so that a look-alike (`home` with a combining mark, full-width letters) is the same label."""
    return "".join(c for c in unicodedata.normalize("NFKD", str(x).casefold()) if unicodedata.category(c) != "Mn")
ENTRY_KNOWN = ("label", "gw", "subnet", "down", "up", "source", "set_by", "set", "test", "metered", "prev")


def _addr(x):
    try:
        return str(ipaddress.ip_address(x)) if isinstance(x, str) and len(x) <= 45 else None
    except ValueError:
        return None


def _cidr(x):
    try:
        return str(ipaddress.ip_network(x, strict=False)) if isinstance(x, str) and len(x) <= 49 and "/" in x else None
    except ValueError:
        return None


def valid_key(k):
    """A network's key: `rmac:` and six two-digit hex pairs, or `gw:` an address `/0–128`; at most 80 characters."""
    if not isinstance(k, str) or len(k) > 80:
        return None
    if _KEY_RMAC.fullmatch(k):
        return k
    if k.startswith("gw:"):
        a, sep, n = k[3:].rpartition("/")
        if sep and n.isdigit() and n.isascii() and len(n) <= 3 and int(n) <= (32 if ":" not in a else 128) and \
                _addr(a) == a:
            return k
    return None


def _fig(x):
    return round(float(x), 1) if _num(x, FIG_MIN, FIG_MAX) else None


def _time(x, now):
    return x if _num(x, 0, now + FUTURE_S) else None


def _keep(src, rules):
    """The fields of `src` that pass their rule (a function returning the value or None)."""
    out = {}
    for k, rule in rules.items():
        if k in src:
            v = rule(src[k])
            if v is not None:
                out[k] = v
    return out


def valid_entry(e, now=None):
    """One network's entry with every field checked (a field that fails is dropped); None when nothing of it is
    left that says something (a figure, a label, a quota)."""
    if not isinstance(e, dict):
        return None
    now = time.time() if now is None else now
    t = lambda x: _time(x, now)  # noqa: E731
    out = _keep(e, {"label": lambda x: x if label_ok(x) else None,
                    "gw": _addr, "subnet": _cidr, "down": _fig, "up": _fig,
                    "source": lambda x: x if x in ("test", "set") else None,
                    "set_by": _str(32, _SET_BY), "set": t})
    if isinstance(e.get("test"), dict):
        x = _keep(e["test"], {"down": _fig, "up": _fig, "rpm": lambda v: round(v) if _num(v, 0, 100000) else None,
                              "base_rtt": lambda v: round(v, 1) if _num(v, 0, 10000) else None,
                              "tool": lambda v: v if v == "networkQuality" else None, "t": t})
        if x:
            out["test"] = x
    m = e.get("metered")
    if isinstance(m, dict) and m.get("period") in ("month", "week", "day") and _num(m.get("cap_gb"), 0.1, 100000):
        x = {"cap_gb": round(float(m["cap_gb"]), 2), "period": m["period"]}
        fd = m.get("from_day")
        if (m["period"] == "month" and _int(fd, 1, 31)) or (m["period"] == "week" and _int(fd, 1, 7)):
            x["from_day"] = fd
        x.update(_keep(m, {"set_by": _str(32, _SET_BY), "set": t}))
        out["metered"] = x
    if isinstance(e.get("prev"), dict):
        x = _keep(e["prev"], {"down": _fig, "up": _fig, "source": lambda v: v if v in ("test", "set") else None,
                              "set_by": _str(32, _SET_BY), "set": t})
        if x:
            out["prev"] = x
    extra = [(k, v) for k, v in e.items() if k not in ENTRY_KNOWN and isinstance(k, str) and _FIELD.fullmatch(k)
             and (v is None or isinstance(v, bool) or _num(v) or (isinstance(v, str) and len(v) <= 200))]
    out.update(extra[:NETWORKS_UNKNOWN])
    if not any(k in out for k in ("down", "up", "label", "metered")):
        return None
    return out


def valid_networks(v, now=None):
    """(entries {key: entry}, how many were unreadable) of networks.json's content: at most NETWORKS_MAX entries with
    a valid key, labels unique ignoring case (a later one loses its label)."""
    nets = v.get("networks") if isinstance(v, dict) and v.get("v") == 1 else None
    if not isinstance(nets, dict):
        return {}, (1 if v is not None else 0)
    out, bad, labels = {}, 0, set()
    for k, e in nets.items():
        e = valid_entry(e, now) if valid_key(k) else None
        if e is None or len(out) >= NETWORKS_MAX:
            bad += 1
            continue
        if "label" in e:
            if label_fold(e["label"]) in labels:
                del e["label"]
            else:
                labels.add(label_fold(e["label"]))
        if not any(x in e for x in ("down", "up", "label", "metered")):
            bad += 1
            continue
        out[k] = e
    return out, bad


def _read_networks_at(dfd, raw=None):
    """valid_networks of the folder's networks.json; `raw`, a list, gets the parsed content as it is (for a writer)."""
    data = read_bounded("networks.json", LIMITS["networks"], dfd, shared=True)
    v = loads_untrusted(data) if data is not None else None
    if raw is not None:
        raw.append(v)
    return valid_networks(v)


def _foreign(v):
    """The entries of networks.json (v 1) under a key this version does not know (a later one's kind of key), as they
    are: a writer carries them through instead of dropping them (at most NETWORKS_MAX)."""
    nets = v.get("networks") if isinstance(v, dict) and v.get("v") == 1 else None
    if not isinstance(nets, dict):
        return {}
    out = [(k, e) for k, e in nets.items() if isinstance(k, str) and 0 < len(k) <= 80 and not valid_key(k) and
           isinstance(e, dict) and not k.startswith(("rmac:", "gw:"))]
    return dict(out[:NETWORKS_MAX])


@_unprivileged()
def read_networks():
    """{"networks": {key: entry}, "unreadable": n} from the shared ledger folder (nothing when it has none)."""
    try:
        dfd = _ledger_dir()
    except LedgerError:
        dfd = None
    if dfd is None:
        return {"networks": {}, "unreadable": 0}
    try:
        nets, bad = _read_networks_at(dfd)
        return {"networks": nets, "unreadable": bad}
    finally:
        os.close(dfd)


def resolve(nets, key, gw=None, subnet=None):
    """The key networks.json keeps this network under: `key` itself; for a gw: key an rmac entry with this gateway
    and subnet (12.6: a cache miss never makes a new network). An rmac key is never resolved to a gw: entry: another
    router on the same default gateway and subnet would take that network's entry (Identity.adopt)."""
    if key in nets or not isinstance(key, str):
        return key
    if key.startswith("gw:"):
        gw = gw or key[3:].rpartition("/")[0]
        hits = [k for k, e in nets.items() if k.startswith("rmac:") and e.get("gw") == gw and
                (subnet is None or e.get("subnet") == subnet)]
        if hits:  # routers of one make share a default address: the one set last
            now = time.time()
            return max(hits, key=lambda k: (_set_time(nets[k], now), k))
    return key


def _set_time(e, now=None):
    """When an entry was last set, at most `now` (a time ahead, which the sanitizer lets pass for a clock set back,
    ranks no higher than one set now)."""
    t = max([x for x in (e.get("set"), (e.get("metered") or {}).get("set")) if _num(x)] + [0])
    return min(t, now) if now is not None else t


@_unprivileged()
def networks_edit(op, key, fields=None):
    """The one way networks.json is written (D-N10: by any local user): under the ledger lock, read, change one
    entry, written through the ledger's hardened path (a new file renamed over the old). `op` "set" (a figure:
    fields down/up/source/test/gw/subnet; what it replaces becomes `prev`), "name" (fields label; "" removes it),
    "forget". Returns {"ok": True, "entry": …} or {"error": why, "code": exit status}."""
    if valid_key(key) is None:
        return {"error": "not a network: %s" % term_text(str(key)[:80]), "code": 2}
    fields, now, me = dict(fields or {}), round(time.time(), 3), _whoami()
    me = me if _SET_BY.fullmatch(me or "") else "uid%d" % os.getuid()
    dfd = _ledger_dir(create=True)
    try:
        lock = _lock(dfd, _H._lock_wait)
        try:
            raw, path = [], os.path.join(_H.LEDGER_DIR, "networks.json")
            nets, _ = _read_networks_at(dfd, raw)
            ver = raw[0].get("v") if isinstance(raw[0], dict) else None
            if isinstance(ver, int) and not isinstance(ver, bool) and ver > 1:   # a later oomph's: never rewritten
                return {"error": "%s was written by a newer %s (v%d): change it with that one, or remove the file to "
                                 "start over" % (path, BRAND, ver), "code": 1}
            if not (ver == 1 and isinstance(raw[0].get("networks"), dict)) and _regular(dfd, "networks.json"):
                # too big, broken JSON, beyond loads_untrusted's limits, not shared (0666): never replaced unread,
                # which would lose every other user's entries without a word
                return {"error": "%s is unreadable (oomph net list counts it as such): remove it to start over"
                                 % path, "code": 1}
            foreign = _foreign(raw[0])
            e = dict(nets.get(key) or {})
            if op == "forget":
                if key not in nets:
                    return {"error": "no network %s in %s" % (key, os.path.join(_H.LEDGER_DIR, "networks.json")),
                            "code": 1}
                del nets[key]
                e = None
            elif op == "name":
                label = fields.get("label") or ""
                if label:
                    if not label_ok(label):
                        return {"error": "a label is 1 to 32 visible characters, and not `this`, a network's key or "
                                         "a word starting with net-", "code": 2}
                    other = next((k for k, x in nets.items() if k != key and "label" in x and
                                  label_fold(x["label"]) == label_fold(label)), None)
                    if other:
                        return {"error": "the label %s is %s's" % (label, other), "code": 2}
                    e["label"] = label
                else:
                    e.pop("label", None)
            elif op == "set":
                if any(k in e for k in ("down", "up")):
                    e["prev"] = {k: e[k] for k in ("down", "up", "source", "set_by", "set") if k in e}
                for k in ("down", "up"):
                    if fields.get(k) is not None:
                        e[k] = round(float(fields[k]), 1)
                e.update(source=fields.get("source") or "set", set_by=me, set=now)
                if fields.get("source") == "test" and isinstance(fields.get("test"), dict):
                    e["test"] = dict(fields["test"], t=now)
                elif fields.get("source") != "test":
                    e.pop("test", None)
                for k in ("gw", "subnet"):
                    if fields.get(k):
                        e[k] = fields[k]
            else:
                return {"error": "unknown operation %s" % op, "code": 2}
            if e is not None:
                e = valid_entry(e, now)
                if e is None:
                    nets.pop(key, None)
                else:
                    nets[key] = e
                while len(nets) > NETWORKS_MAX:  # the one set longest ago goes; of a tie (a clock set back, a
                    # quick script) the one without a label, then without a figure, never by the keys' order alone
                    del nets[min((k for k in nets if k != key), key=lambda k: (
                        _set_time(nets[k], now), "label" in nets[k], "down" in nets[k] or "up" in nets[k], k))]
            while True:  # a later version's entries are carried, not kept at any price: the biggest goes first
                data = json.dumps({"v": 1, "networks": dict(foreign, **nets)}, indent=1, sort_keys=True,
                                  allow_nan=False).encode()
                if len(data) <= LIMITS["networks"] or not foreign:
                    break
                del foreign[max(foreign, key=lambda k: (len(json.dumps(foreign[k], default=str)), k))]
            if len(data) > LIMITS["networks"]:
                return {"error": "networks.json would grow past %d KB: oomph net forget a network first"
                                 % (LIMITS["networks"] >> 10), "code": 1}
            try:
                _replace(dfd, "networks.json", data)
            except OSError as x:
                raise LedgerError("can't write %s/networks.json (%s)" % (_H.LEDGER_DIR, x.strerror or x))
            return {"ok": True, "entry": e}
        finally:
            os.close(lock)
    finally:
        os.close(dfd)


def _regular(dfd, name):
    """Whether the folder holds a regular file `name` (lstat: opens nothing, follows no link)."""
    try:
        return stat.S_ISREG(os.stat(name, dir_fd=dfd, follow_symlinks=False).st_mode)
    except OSError:
        return False


def networks_signature():
    """What lstat (which opens nothing) says about networks.json: a write renames a new one in."""
    try:
        st = os.lstat(os.path.join(_H.LEDGER_DIR, "networks.json"))
        return (st.st_ino, st.st_size, st.st_mtime_ns)
    except OSError as e:
        return (e.errno,)


ENTRY_ANSWER = 2048   # bytes of the logger child's answer about the current network


def child_entry(net):
    """The ledger child's answer about the logger's network (`net`: network, gw, subnet): the network it was asked
    about, the key networks.json keeps it under and its entry, checked, at most ENTRY_ANSWER bytes; None without
    one. Runs unprivileged."""
    if not isinstance(net, dict) or not valid_key(net.get("network")):
        return None
    try:
        nets = read_networks()["networks"]
    except LedgerError:
        return None
    k = resolve(nets, net["network"], _addr(net.get("gw")), _cidr(net.get("subnet")))
    if k not in nets:
        return None
    # only what the logger reads (a later writer's extra fields, up to 16 × 200 characters, never push the answer
    # past its cap: a padded entry would never be adopted)
    keep = ("label", "gw", "subnet", "down", "up", "source", "set", "metered")
    out = {"asked": net["network"], "key": k, "entry": {f: v for f, v in nets[k].items() if f in keep}}
    return out if len(json.dumps(out)) <= ENTRY_ANSWER else None


def answer_entry(x):
    """The logger's reading of that answer (it is root: the child's words are untrusted), or None."""
    if not isinstance(x, dict) or not valid_key(x.get("key")) or not valid_key(x.get("asked")) or \
            len(json.dumps(x, default=str)) > ENTRY_ANSWER:
        return None
    e = valid_entry(x.get("entry"))
    return {"asked": x["asked"], "key": x["key"], "entry": e} if e else None


# ------------------------------------------------------------------ what commands take (12.12)
_RATE = re.compile(r"(\d{1,6}(?:\.\d)?)(m|mbit|mbit/s|mbps)?\Z", re.I)
_VOL = re.compile(r"(\d{1,7}(?:\.\d{1,3})?)(g|gb|t|tb)?\Z", re.I)


def parse_rate(x):
    """A rate in Mbit/s (`200M`, `200`, `200Mbit/s`, `200Mbps`), 1–100 000; ValueError with the reason."""
    s = str(x).strip()
    if re.fullmatch(r"\d+(\.\d+)?\s*(g|gbit|gbit/s|gbps)", s, re.I):
        raise ValueError("%s is ambiguous here: use %dM" % (s, round(float(re.match(r"[\d.]+", s).group()) * 1000)))
    if re.fullmatch(r"\d+(\.\d+)?\s*(k|kbit|kbit/s|kbps)", s, re.I):
        raise ValueError("rates start at 1M")
    if re.search(r"b", s.lower().replace("mbit", "").replace("mbps", "")) or re.search(r"[mk]?ib", s.lower()):
        raise ValueError("rates are megabits per second: 25 MB/s is 200M")
    m = _RATE.fullmatch(s)
    if not m:
        raise ValueError("not a rate: %s (Mbit/s, e.g. 200M)" % s)
    v = float(m.group(1))
    if not RATE_MIN <= v <= RATE_MAX:
        raise ValueError("a rate is 1M to 100000M")
    return v


def parse_rate_pair(x):
    """`DOWN/UP` (either side may be empty: `250/`, `/40`) or `DOWN`: (down or None, up or None)."""
    s = str(x).strip()
    d, sep, u = s.partition("/")
    out = (parse_rate(d) if d.strip() else None, parse_rate(u) if sep and u.strip() else None)
    if out == (None, None):
        raise ValueError("not a rate: %s (DOWN/UP in Mbit/s, e.g. 250/40)" % s)
    return out


def parse_volume(x):
    """A volume in GB (`40G`, `40`, `1.5T` = 1500 GB), 0.01–1 000 000; ValueError with the reason."""
    s = str(x).strip()
    if re.fullmatch(r"\d+(\.\d+)?\s*(m|mb|mib|k|kb)", s, re.I):
        raise ValueError("%s could be megabits or megabytes: use 0.5G" % s)
    m = _VOL.fullmatch(s)
    if not m:
        raise ValueError("not a volume: %s (GB, e.g. 40G)" % s)
    v = float(m.group(1)) * (1000 if (m.group(2) or "").lower() in ("t", "tb") else 1)
    if not VOL_MIN <= v <= VOL_MAX:
        raise ValueError("a volume is 0.01G to 1000000G")
    return round(v, 3)


# ------------------------------------------------------------------ reading it back
def net_block(s):
    """A sample's net block, checked, or None (a logger before 1.15, or not a dict)."""
    n = s.get("net") if isinstance(s, dict) else None
    return n if isinstance(n, dict) else None


def recent_samples(n=3, cap=256 << 10):
    """The last `n` samples of today's file (its tail, at most `cap` bytes), oldest first."""
    path = os.path.join(_H.LOG_DIR, "samples-%s.jsonl" % datetime.date.today().isoformat())
    data = read_bounded(path, cap, tail=True)
    out = []
    for line in (data or b"").splitlines()[-n:]:
        s = loads_untrusted(line)   # LIMITS apply: a per-user install's log, a mirrored one
        if isinstance(s, dict):
            out.append(s)
    return out


def stale(entry, samples, network=None):
    """The stale-figure hint (D-N8): {"dir", "seen", "cap"} when the mean of the last three samples' rate on this
    network is above STALE_X × the stored figure (payload against payload), else None. Only samples that told the
    LAN from the internet (src "flows"): a total alone ("if": the Linux service, nettop backing off) holds the LAN's
    traffic too, and a NAS at a gigabit says nothing about the line."""
    if not entry:
        return None
    nb = [net_block(x) for x in samples[-3:]]
    nb = [x for x in nb if x and x.get("src") == "flows" and (network is None or x.get("network") == network)]
    if len(nb) < 3:
        return None
    for d, k in (("down", "down_mbps"), ("up", "up_mbps")):
        v = [x[k] for x in nb if _num(x.get(k), 0, 1e6)]
        cap = entry.get(d)
        if len(v) == 3 and _num(cap) and sum(v) / 3 > STALE_X * cap:
            return {"dir": d, "seen": round(sum(v) / 3, 1), "cap": cap, "source": entry.get("source")}
    return None


def stale_text(st, cmd=True):
    """`seen 940 Mbit/s, more than the 500 tested: oomph net test` (upload: `seen 60 Mbit/s up, …`); without `cmd`
    (the lines agents read: check, status, resources) no command: a speed test is a person's to start."""
    return "seen %s Mbit/s%s, more than the %s %s%s" % (
        _mb(st["seen"]), "" if st["dir"] == "down" else " up", _mb(st["cap"]),
        "set" if st.get("source") == "set" else "tested", ": oomph net test" if cmd else "") if st else ""


def _mb(x):
    """Mbit/s as people read them: 212, 8.1, 0.4."""
    return "%.0f" % x if x >= 100 else "%.1f" % x if x < 10 else "%.0f" % x


def current_network(s=None, P=None):
    """(the sample's net block or a live one, its source "daemon"/"live"): the logger's when it is fresh and 1.15,
    else a live reading of a second (None where this backend measures no network)."""
    s = s if s is not None else _daemon_sample()
    if s is not None and s.get("source") != "live" and net_block(s) is not None:
        return net_block(s), "daemon", s
    try:
        block, top, names = live(1.0)
    except Unsupported:
        return None, "live", None
    return block, "live", {"net": block, "top_net": top, "net_names": names} if block is not None else None


def lookup(nets, block):
    """(key, entry) of networks.json for the sample's net block's network (resolved for a gw: key)."""
    if not block or not block.get("network"):
        return None, None
    k = resolve(nets, block["network"])
    return k, nets.get(k)


def public_id(key):
    """What leaves this machine in place of a network's key (MCP answers, check --json, status --json): `net-` and a
    hash of the key salted with this machine's hardware id, which is never sent. A router's MAC is a few addresses
    from its Wi-Fi's BSSID, which public databases place on a street map; the hash names the same network on this
    machine every time and nothing elsewhere. None without a key or a salt."""
    if not valid_key(key):
        return None
    try:
        salt = plat().host_secret()
    except Exception:  # noqa: B902  (a stand-in backend, an unreadable id: nothing is sent)
        salt = None
    if not salt:
        return None
    return "net-" + hashlib.sha256(("oomph-net-v1:%s:%s" % (salt, key)).encode()).hexdigest()[:10]


def public_sample(s):
    """A sample as an answer that leaves the machine: its net block's network as public_id (a copy; current.json
    itself keeps the key for the commands that read it here)."""
    n = net_block(s)
    if n is None or "network" not in n:
        return s
    out = dict(s)
    out["net"] = dict(n, network=public_id(n.get("network")))
    return out


def network_info(s, nets=None, samples=None):
    """The `network` object of memory_check, memory_status and `oomph check --json` (12.13), or None where no
    network is measured. `room` (N2) and `metered` (N3) are null until those parts exist. `id` is public_id: these
    answers go to a model's provider (`oomph net --json` has the key itself). `src` "if": totals, the LAN's
    traffic included."""
    b = net_block(s)
    if b is None:
        return None
    if nets is None:
        try:
            nets = read_networks()["networks"]
        except LedgerError:
            nets = {}
    k, e = lookup(nets, b)
    cap = [e.get("down"), e.get("up")] if e and (e.get("down") or e.get("up")) else None
    st = stale(e, samples if samples is not None else recent_samples(), b.get("network"))
    return {"id": public_id(k), "label": (e or {}).get("label"), "if": b.get("if"), "down_mbps": b.get("down_mbps"),
            "up_mbps": b.get("up_mbps"), "cap": cap, "room": None, "vpn": bool(b.get("vpn")), "metered": None,
            "stale": bool(st), "src": b.get("src")}


def resource_line(s, nets=None, samples=None):
    """("net", text) for check, status and resources: `↓212 ↑8.1 of 194/48 Mbit/s (home)`, or why not (a label as
    short as cpu's, gpu's and disk's: check prints them in 6 columns)."""
    b = net_block(s)
    if b is None:
        return ("net", "not measured (logging is off; `oomph net` reads it now)" if s.get("source") == "live" else
                "not recorded by the logger, which is older than 1.15 (`oomph net` reads it now)")
    if not b.get("if"):
        return ("net", "offline")
    if nets is None:
        try:
            nets = read_networks()["networks"]
        except LedgerError:
            nets = {}
    k, e = lookup(nets, b)
    now = ("↓%s ↑%s" % (_mb(b["down_mbps"]), _mb(b["up_mbps"]))) if _num(b.get("down_mbps")) and \
        _num(b.get("up_mbps")) else "not measured yet"
    # never the key itself: these lines reach a model's provider (SKILL.md has agents run `oomph check`), and a
    # router's MAC or a public gateway names a place (`oomph net` shows it here, oomph net name gives it a label)
    name = term_text((e or {}).get("label") or "") or ("unnamed network" if k else "unknown network")
    where = "%s%s" % (name, " · through a VPN" if b.get("vpn") else "")
    if e and (_num(e.get("down")) or _num(e.get("up"))):   # 250/ or /40 is a figure too (net set takes them)
        text = "%s of %s/%s Mbit/s (%s)" % (now, _mb(e["down"]) if _num(e.get("down")) else "?",
                                            _mb(e["up"]) if _num(e.get("up")) else "?", where)
    else:   # no command (12.13): agents read this line, and a speed test is a person's to start (`oomph net` says how)
        text = "%s%s (%s) · line not tested" % (now, " Mbit/s" if now != "not measured yet" else "", where)
    if b.get("src") == "if" and now != "not measured yet":
        text += " · totals, LAN included"
    st = stale(e, samples if samples is not None else recent_samples(), b.get("network"))
    if st:
        text += " · " + stale_text(st, cmd=False)
    return ("net", text)


def report_line(summ):
    """`oomph report`'s line among the other resources: the internet's peaks down and up, with the busiest names
    then (oomph._Summary keeps them). Peaks of totals-only samples (src "if": a Linux service logger, nettop backing
    off) hold the LAN too: they are said as such, and only for a window without one per-connection sample."""
    pre = "" if any(summ.get("max_net_%s_mbps" % k) is not None for k in ("down", "up")) else "if_"
    net = []
    for d, arrow in (("down", "↓"), ("up", "↑")):
        k = pre + d
        if summ.get("max_net_%s_mbps" % k) is not None:
            top = ", ".join("%s %.1f" % (term_text(str(r.get("name") or "?")[:64]), r.get(d) if _num(r.get(d)) else 0)
                            for r in summ.get("names_net_%s_at_peak" % k) or () if isinstance(r, dict))
            net.append("%s %.1f Mbit/s at %s%s" % (arrow, summ["max_net_%s_mbps" % k],
                                                    (summ.get("max_net_%s_at" % k) or "")[11:16],
                                                    " (%s)" % top if top else ""))
    return ("internet, peak: " if not pre else "network (interface totals, LAN included), peak: ") + " · ".join(net)


# ------------------------------------------------------------------ oomph net
NET_USAGE = """usage: oomph net [--json]                 this network: identity, its line's figure, now, busiest
       oomph net test [--yes] [--json]     macOS: measure the line (networkQuality); asks before storing
       oomph net set DOWN/UP [NETWORK]     store the line's figure in Mbit/s (250/40, 250/, /40)
       oomph net name LABEL [NETWORK]      name it ("" removes the name)
       oomph net forget NETWORK            remove its entry
       oomph net list [--json]             every network this machine's users have stored
NETWORK: a label, an id (net-…), a key (rmac:…, gw:…: net list), or `this` (the default)"""


def _ident_live(P=None):
    """(egress, network key) of this machine now, read live (no logger needed): (None, None) offline."""
    P = P or plat()
    if not hasattr(P, "net_route"):
        return None, None
    eg = P.net_route()
    if not eg or not eg.get("if"):
        return None, None
    return eg, Identity().get(P, eg, time.time())


def _target(name, nets, P=None):
    """(key, egress or None) for NETWORK: a key, a label (ignoring case) or `this` (read now; the logger's identity
    instead where both name one network, so that a cache miss now does not make another); (None, why) when
    unknown."""
    if name in (None, "this"):
        eg, k = _ident_live(P)
        if not k:
            return None, "this machine is offline, or its network has no gateway"
        gw, sub = eg.get("gw"), eg.get("subnet")
        b = net_block(_daemon_sample() or {})
        d = b.get("network") if b and b.get("if") == eg.get("if") else None
        if valid_key(d) and d != k:
            live, dk = resolve(nets, k, gw, sub), resolve(nets, d)
            de = nets.get(dk) or {}
            # the same network resolved, or the router's MAC missing now (gw:) where the logger has one whose entry
            # has this gateway and subnet (or says none): a sample from before a move names the network left
            if live == dk or (k.startswith("gw:") and d.startswith("rmac:") and de.get("gw", gw) == gw and
                              de.get("subnet", sub) == sub):
                k = d
        return resolve(nets, k, gw, sub), eg
    if valid_key(name):
        return name, None
    k = next((k for k, e in nets.items() if ("label" in e and label_fold(e["label"]) == label_fold(name)) or
              (str(name).startswith("net-") and public_id(k) == name)), None)
    return (k, None) if k else (None, "no network named %s (oomph net list)" % term_text(str(name)[:80]))


def shown(k, e=None):
    """A network as text shows it: its label, else its public id (a router's MAC names a place, 12.13 and §8; the key
    itself is in `net list` and the --json answers, for local tools)."""
    return term_text((e or {}).get("label") or "") or public_id(k) or "an unnamed network"


def _when(t):
    return datetime.datetime.fromtimestamp(t).strftime("%-d %b") if _num(t) else "?"


def _figure_text(e):
    if not e or not (_num(e.get("down")) or _num(e.get("up"))):
        return None
    d = "%s ↓" % _mb(e["down"]) if _num(e.get("down")) else "? ↓"
    u = "%s ↑" % _mb(e["up"]) if _num(e.get("up")) else "? ↑"
    return "%s / %s Mbit/s, %s %s by %s" % (d, u, "tested" if e.get("source") == "test" else "set", _when(e.get("set")),
                                            term_text(e.get("set_by") or "?"))


def cmd_net(args):
    """`oomph net …` (12.13)."""
    if args and args[0] in ("-h", "--help", "help"):
        print(NET_USAGE)
        return 0
    sub = args[0] if args and args[0] in ("test", "set", "name", "forget", "list") else None
    rest = args[1:] if sub else args
    try:
        if sub in (None, "list"):
            opts, pos = _strict(rest, flags=("--json",), npos=0)
        elif sub == "test":
            opts, pos = _strict(rest, flags=("--json", "--yes"), npos=0)
        elif sub in ("set", "name"):
            opts, pos = _strict(rest, flags=("--json",), npos=2)
            if not pos:
                raise UsageError("%s needs a %s" % (sub, "figure" if sub == "set" else "label"))
        else:
            opts, pos = _strict(rest, flags=("--json",), npos=1)
            if not pos:
                raise UsageError("forget needs a NETWORK (a key, a label, or this)")
    except UsageError as e:
        return _usage_error("net", e, NET_USAGE)
    try:
        nets_r = read_networks()
    except LedgerError as e:
        print("oomph net: %s" % e, file=sys.stderr)
        return 1
    nets = nets_r["networks"]
    js = "--json" in opts
    if sub is None:
        return _net_show(nets, js)
    if sub == "list":
        return _net_list(nets_r, js)
    if sub == "test":
        return _net_test(nets, opts)
    if sub == "set":
        try:
            down, up = parse_rate_pair(pos[0])
        except ValueError as e:
            return _usage_error("net set", e, NET_USAGE)
        k, eg = _target(pos[1] if len(pos) > 1 else None, nets)
        if k is None:
            print("oomph net set: %s" % eg, file=sys.stderr)
            return 1
        f = {"down": down, "up": up, "source": "set"}
        if eg:
            f.update(gw=eg.get("gw"), subnet=eg.get("subnet"))
        return _net_done(networks_edit("set", k, f), k, js, "stored for %s:" % shown(k, nets.get(k)), fig=True)
    if sub == "name":
        k, eg = _target(pos[1] if len(pos) > 1 else None, nets)
        if k is None:
            print("oomph net name: %s" % eg, file=sys.stderr)
            return 1
        was = public_id(k) or "the network"
        return _net_done(networks_edit("name", k, {"label": pos[0]}), k, js,
                         ("%s is now named %s" % (was, term_text(pos[0]))) if pos[0] else "%s has no name now" % was)
    k, why = _target(pos[0], nets)
    if k is None:
        print("oomph net forget: %s" % why, file=sys.stderr)
        return 1
    return _net_done(networks_edit("forget", k), k, js, "forgot %s" % shown(k, nets.get(k)))


def _net_done(r, k, js, text, fig=False):
    if "error" in r:
        print(json.dumps(r) if js else "oomph net: %s" % r["error"], file=sys.stdout if js else sys.stderr)
        return r.get("code", 1)
    if js:
        print(json.dumps({"network": k, "entry": r.get("entry")}))
    else:
        print(text + (" " + (_figure_text(r.get("entry")) or "") if fig else ""))
    return 0


def _net_list(nets_r, js):
    b = net_block(_daemon_sample() or {})
    here = resolve(nets_r["networks"], b.get("network")) if b and b.get("network") else None
    if here is None:
        _, here = _ident_live()
        here = resolve(nets_r["networks"], here) if here else None
    if js:
        print(json.dumps({"networks": nets_r["networks"], "unreadable": nets_r["unreadable"], "current": here}))
        return 0
    w = max(80, term_width())
    if not nets_r["networks"]:
        print("no network stored yet (%s)" % ("oomph net test" if sys.platform == "darwin" else
                                               "oomph net set DOWN/UP"))
    for k, e in sorted(nets_r["networks"].items(), key=lambda kv: (kv[1].get("label") or "~", kv[0])):
        print(wrap("%s %-12s %s" % ("*" if k == here else " ", cut_end(term_text(e.get("label") or "–"), 12), k),
                   w, "", 16))
        fig = _figure_text(e)
        print(wrap(fig or "line not tested", w, " " * 16, 16))
    if nets_r["unreadable"]:
        print("%d entr%s unreadable" % (nets_r["unreadable"], "y" if nets_r["unreadable"] == 1 else "ies"))
    return 0


def _net_show(nets, js):
    block, src, s = current_network()
    if block is None:
        print(json.dumps({"network": None, "measured": False}) if js else
              "oomph net: this system's network is not measured", file=sys.stdout if js else sys.stderr)
        return 0   # 12.13: not measured is an answer, not a failure (text and --json alike)
    k, e = lookup(nets, block)
    samples = recent_samples() if src == "daemon" else []
    st = stale(e, samples, block.get("network"))
    names = [x for x in (s or {}).get("net_names") or [] if isinstance(x, dict)][:3]
    if js:
        print(json.dumps({"network": k, "label": (e or {}).get("label"), "if": block.get("if"), "vpn": block.get("vpn"),
                          "tun": block.get("tun"), "entry": e, "now": {x: block.get(x) for x in
                                                                        ("down_mbps", "up_mbps", "lan_mbps", "src")},
                          "busiest": names, "stale": st, "source": src}))
        return 0
    w = max(80, term_width())
    if not block.get("if"):
        print("offline: no interface reaches the internet")
        return 0
    head = "%s on %s" % ("%s (%s)" % (term_text(e["label"]), public_id(k) or "unnamed") if e and e.get("label") else
                         public_id(k) or "an unknown network", term_text(block["if"]))
    if block.get("vpn"):
        head += " · through a VPN (%s)" % term_text(block.get("tun") or "?")
    print(wrap(head, w, "", 2))
    fig = _figure_text(e)
    print(wrap(fig or "not tested: %s" % ("oomph net test" if sys.platform == "darwin" else
                                          "measure with a tool you trust, then oomph net set DOWN/UP"),
               w, "  %-6s " % "line", 9))
    if _num(block.get("down_mbps")):
        now = "↓ %s ↑ %s Mbit/s" % (_mb(block["down_mbps"]), _mb(block.get("up_mbps") or 0))
        if names:
            now += " · busiest: " + ", ".join("%s %s" % (term_text(x.get("name")),
                                                         _mb((x.get("down") or 0) + (x.get("up") or 0))) for x in names)
        if block.get("src") == "if":
            now += " · totals, LAN included"
    else:
        now = "not measured yet"
    print(wrap(now + (" (a live reading)" if src == "live" else ""), w, "  %-6s " % "now", 9))
    if st:
        print(wrap(stale_text(st), w, "  ", 2))
    if e is None and k and k.startswith("rmac:"):
        eg, _ = _ident_live()
        g = "gw:%s/%s" % (eg.get("gw"), str(eg.get("subnet")).rpartition("/")[2]) if eg and eg.get("gw") and \
            eg.get("subnet") else None
        if g in nets:   # stored while the router's MAC was not in the cache (resolve never maps rmac to gw: 12.6)
            g = public_id(g) or g
            print(wrap("a figure is stored as %s, from before the router was known: oomph net set again (and oomph "
                       "net forget %s)" % (g, g), w, "  ", 2))
    return 0


def _net_test(nets, opts):
    js, yes = "--json" in opts, "--yes" in opts
    stand_in = os.environ.get("OOMPH_NETWORKQUALITY") if os.getuid() != 0 else None   # a test's, never root's
    if sys.platform != "darwin" and not stand_in:
        print("oomph net test: no speed test here: measure with a tool you trust, then oomph net set DOWN/UP",
              file=sys.stderr)
        return 1
    nq = stand_in or NQ
    if not os.access(nq, os.X_OK):
        print("oomph net test: %s is missing (macOS 12 or later): measure with a tool you trust, then "
              "oomph net set DOWN/UP" % nq, file=sys.stderr)
        return 1
    kw = {}
    if os.geteuid() == 0:   # networkQuality runs as the calling user, never as root (§8)
        try:
            uid = int(os.environ.get("SUDO_UID") or 0)
        except ValueError:
            uid = 0
        if uid <= 0:
            print("oomph net test: refused as root without sudo: run it as a user", file=sys.stderr)
            return 1
        try:
            kw = {"user": uid, "group": pwd.getpwuid(uid).pw_gid, "extra_groups": []}
        except KeyError:
            print("oomph net test: refused as root: SUDO_UID %d is no user here" % uid, file=sys.stderr)
            return 1
    k0, eg = _target(None, nets)
    if not k0:
        print("oomph net test: offline, or this network has no gateway", file=sys.stderr)
        return 1
    e = nets.get(k0) or {}
    warn = []
    if e.get("metered"):
        warn.append("this network is metered: the test moves a few hundred MB")
    cur = _daemon_sample()
    b = net_block(cur) if cur else None
    if b and _num(e.get("down")) and _num(b.get("down_mbps")) and b["down_mbps"] > BUSY_X * e["down"]:
        warn.append("the line is busy (↓ %s of %s Mbit/s): the result will be low" % (_mb(b["down_mbps"]),
                                                                                        _mb(e["down"])))
    if not yes and not sys.stdin.isatty():   # no one to ask: an agent following a hint starts no speed test, and is
        # shown no way round this (--yes is for a person's own scripts: NET_USAGE)
        print("oomph net test: a speed test moves a few hundred MB over the shared line: a person runs `oomph net "
              "test` in a terminal", file=sys.stderr)
        return 1
    if warn and not yes:
        print("oomph net test: %s. Run again with --yes to test anyway." % "; ".join(warn), file=sys.stderr)
        return 1
    store = yes   # 12.13: --yes stores (after a warning too: it was shown before the test)
    if not js:
        print("testing the line with networkQuality (about 30 s)…", file=sys.stderr)
    try:
        rc, out, err = run_bounded([nq] + NQ_ARGS, b"", 1 << 20, NQ_TIMEOUT_S, **kw)
    except LedgerError as x:
        print("oomph net test: networkQuality %s" % x, file=sys.stderr)
        return 1
    r = loads_untrusted(out)
    dl = r.get("dl_throughput") if isinstance(r, dict) else None
    ul = r.get("ul_throughput") if isinstance(r, dict) else None
    if rc != 0 or not _num(dl, 0, 1e12) or not _num(ul, 0, 1e12):
        print("oomph net test: networkQuality failed%s (behind a proxy? oomph net set DOWN/UP stores a figure by hand)"
              % (": " + err.strip().splitlines()[-1][:200] if err.strip() else ""), file=sys.stderr)
        return 1
    res = {"down": round(dl / 1e6, 1), "up": round(ul / 1e6, 1), "interface": str(r.get("interface_name") or "")[:32]}
    if _num(r.get("dl_responsiveness"), 0, 100000):
        res["rpm"] = round(r["dl_responsiveness"])
    if _num(r.get("base_rtt"), 0, 10000):
        res["base_rtt"] = round(r["base_rtt"], 1)
    k1, eg1 = _target(None, nets)
    if k1 != k0 and k0.startswith("gw:") and (k1 or "").startswith("rmac:") and eg1 and \
            all(eg1.get(x) == eg.get(x) for x in ("if", "gw", "subnet")):
        k0, e = k1, nets.get(k1) or {}   # the test's own traffic put the router's MAC into the cache: the same network
    why = None
    if res["interface"] != eg.get("if"):
        why = "the test ran over %s, not over %s, this network's interface" % (term_text(res["interface"]) or "?",
                                                                                 term_text(eg.get("if") or "?"))
    elif k1 != k0:
        why = "the network changed during the test"
    elif res["down"] < FIG_MIN or res["up"] < FIG_MIN:
        why = "the line is too slow to store a figure for"
    stored = False
    text = "%s ↓ / %s ↑ Mbit/s on %s (%s)%s%s" % (_mb(res["down"]), _mb(res["up"]), term_text(res["interface"]) or "?",
                                                  shown(k0, e),
                                                  ", %d RPM" % res["rpm"] if "rpm" in res else "",
                                                  ", base RTT %s ms" % res["base_rtt"] if "base_rtt" in res else "")
    if not js:
        print(text)
    if why is None and not store and not js and sys.stdin.isatty():
        try:
            store = input("store it for %s? [y/N] " % shown(k0, e)).strip().lower() in ("y", "yes")
        except EOFError:
            store = False
    if why is None and store:
        t = {k: res[k] for k in ("down", "up", "rpm", "base_rtt") if k in res}
        t["tool"] = "networkQuality"
        w = networks_edit("set", k0, {"down": res["down"], "up": res["up"], "source": "test", "test": t,
                                      "gw": eg.get("gw"), "subnet": eg.get("subnet")})
        if "error" in w:
            why = w["error"]
        else:
            stored = True
    if js:
        print(json.dumps({"network": k0, "result": res, "stored": stored, "refused": why}))
    elif why:
        print("not stored: %s" % why)
    elif stored:
        print("stored for %s" % shown(k0, e))
    else:
        print("not stored (%soomph net set %s/%s)" % ("" if yes else "oomph net test --yes stores it, or ", res["down"],
                                                    res["up"]))
    return 1 if why else 0


# ------------------------------------------------------------------ oomph ps --net, doctor
def ps_rows(n=10):
    """(rows, note, source) for `oomph ps --net`: the logger's attribution, else a live reading of a second."""
    s = _daemon_sample()
    if s is not None and net_block(s) is not None:
        return [r for r in s.get("top_net") or [] if isinstance(r, dict)][:n], net_block(s), "daemon"
    block, rows, _ = live(1.0)
    return rows[:n], block, "live"


def cmd_ps_net(n, js):
    """`oomph ps --net`: the biggest internet users now (12.13), from the logger's attribution (top_net), else a
    live reading of a second; "totals only" where no process is named (Linux without ss, too many connections)."""
    rows, block, src = ps_rows(n)
    if js:
        print(json.dumps({"resource": "net", "rows": rows, "source": src,
                          "src": (block or {}).get("src"), "if": (block or {}).get("if")}))
        return 0
    if block is None:
        print("oomph ps: internet traffic is not measured on this system", file=sys.stderr)
        return 1
    w = max(80, term_width())
    users = {}
    print("%7s %-*s %9s %9s  %s" % ("PID", w - 48, "NAME", "↓Mbit/s", "↑Mbit/s", "USER"))
    for r in rows:
        uid = r.get("uid")
        if uid not in users:
            try:
                users[uid] = pwd.getpwuid(uid).pw_name if isinstance(uid, int) else "?"
            except KeyError:
                users[uid] = str(uid)
        print("%7s %-*s %9.2f %9.2f  %s" % (r.get("pid"), w - 48, cut_middle(term_text(r.get("name")), w - 48),
                                            r.get("down") or 0, r.get("up") or 0, cut_end(term_text(users[uid]), 16)))
    if not block.get("if"):
        print("  offline")
    elif block.get("src") == "if" and not rows:
        why = ((_daemon_sample() or {}).get("daemon") or {}).get("net") if src == "daemon" else None
        print("  totals only here, LAN included: ↓ %s ↑ %s Mbit/s, no process named%s" % (
            _mb(block.get("down_mbps") or 0), _mb(block.get("up_mbps") or 0),
            " (%s)" % term_text(why[:80]) if isinstance(why, str) and why else ""))
    elif not rows:
        print("  nothing moving to or from the internet right now")
    if src == "live":
        print("(logging is off: a live reading of a second%s)" % (
            "" if sys.platform == "darwin" or os.geteuid() == 0 else ", your own processes"))
    return 0


def doctor_line(c=None):
    """(id, level, text[, fix]) of doctor's network line: how this machine measures its internet traffic; `c` the
    logger's current sample when it runs (on Linux it reads the totals alone: no netlink in its sandbox)."""
    P = plat()
    kind = getattr(P, "NET_FLOWS", None)
    if not hasattr(P, "net_route"):
        return ("network", "note", "not measured on this system")
    if kind == "nettop":
        why = ((c or {}).get("daemon") or {}).get("net")
        if isinstance(why, str) and why:   # backing off (too many connections) or nettop failing: totals alone now
            return ("network", "note", "the logger records the interface's totals alone now: %s"
                    % term_text(why[:80]))
        return ("network", "ok", "nettop per connection and the interface's counters (no traffic is caused)")
    ms = (((c or {}).get("daemon") or {}).get("machine") or {}).get("measures") or {}
    logger = " · the logger records the interface's totals" if ms.get("net") == "proc-net-dev" else ""
    if hasattr(P, "ss_path") and P.ss_path():
        try:
            why = P.net_flows()[1]   # once, as this user: an ss that refuses -e or -O, a seccomp or LSM refusal
        except Exception:
            why = None
        if why and why.startswith("exit"):
            return ("network", "warn", "totals only: ss -tinpeHO failed here (%s), so no process is named" % why
                    + logger, "run ss -tinpeHO to see why (an iproute2 without -e or -O, a security policy)")
        return ("network", "ok", "ss per TCP socket (other users' processes as root only) and /proc/net/dev" + logger)
    return ("network", "note", "totals only: ss (iproute2) is missing, so no process is named" + logger,
            "install iproute2 for the internet traffic per process")
