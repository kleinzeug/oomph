#!/usr/bin/env python3
"""Runs as oomph-share@.service (StandardInput=socket, StandardOutput=null): does the gate's lookups of
DESIGN.md section 11.1 for the connection on fd 0 and writes the findings back over that socket."""
import fcntl, ipaddress, os, socket, struct, sys, traceback
out = []
def say(*a): out.append(" ".join(str(x) for x in a))
SIOCGIFADDR, SIOCGIFNETMASK = 0x8915, 0x891b
try:
    conn = socket.socket(fileno=os.dup(0))
    local, peer = conn.getsockname(), conn.getpeername()
    say("uid", os.getuid(), "gid", os.getgid(), "family", conn.family.name, "local", local, "peer", peer)
    lip, pip = local[0], peer[0]
    if lip.startswith("::ffff:"): lip = lip[7:]
    if pip.startswith("::ffff:"): pip = pip[7:]
    try:
        s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); say("AF_INET dgram socket: ok")
    except OSError as e:
        s4 = None; say("AF_INET dgram socket: FAILED", e.errno, e.strerror)
    try:
        socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0); say("AF_NETLINK socket: allowed")
    except OSError as e:
        say("AF_NETLINK socket: refused errno", e.errno, e.strerror)
    owner = None
    for ifn in sorted(os.listdir("/sys/class/net")):
        try:
            flags = int(open("/sys/class/net/%s/flags" % ifn).read(), 16)
            typ = int(open("/sys/class/net/%s/type" % ifn).read())
            virt = os.path.realpath("/sys/class/net/" + ifn).startswith("/sys/devices/virtual/")
        except OSError as e:
            say("if", ifn, "sysfs error", e); continue
        addr = mask = None
        if s4 is not None:
            req = struct.pack("16s16x", ifn.encode()[:15])
            try:
                addr = socket.inet_ntoa(fcntl.ioctl(s4, SIOCGIFADDR, req)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(s4, SIOCGIFNETMASK, req)[20:24])
            except OSError as e:
                addr = "errno %d %s" % (e.errno, e.strerror)
        say("if %-8s flags=0x%04x up=%d loopback=%d p2p=%d noarp=%d type=%d virtual=%d addr=%s mask=%s"
            % (ifn, flags, flags & 1, bool(flags & 8), bool(flags & 0x10), bool(flags & 0x80), typ, virt, addr, mask))
        if addr == lip:
            owner = (ifn, flags, typ, virt, addr, mask)
    try:
        v6 = open("/proc/net/if_inet6").read().strip().splitlines(); say("/proc/net/if_inet6 lines:", len(v6))
    except OSError as e:
        say("/proc/net/if_inet6 error", e)
    if owner is None:
        say("VERDICT deny: no interface owns", lip)
    else:
        ifn, flags, typ, virt, addr, mask = owner
        net = ipaddress.ip_network("%s/%s" % (addr, mask), strict=False)
        same_subnet = ipaddress.ip_address(pip) in net
        router = None
        for line in open("/proc/net/route").read().splitlines()[1:]:
            f = line.split()
            if f[0] == ifn and f[1] == "00000000" and f[7] == "00000000":
                gw = socket.inet_ntoa(struct.pack("<I", int(f[2], 16)))
                if router is None or int(f[6]) < router[1]: router = (gw, int(f[6]))
        mac = None
        if router:
            for line in open("/proc/net/arp").read().splitlines()[1:]:
                f = line.split()
                if f[0] == router[0] and f[5] == ifn and int(f[2], 16) & 2:
                    mac = f[3]
        rule_ok = bool(flags & 1) and typ == 1 and not (flags & 0x10) and not (flags & 0x80)
        say("owner", ifn, "subnet", net, "peer in subnet", same_subnet, "router", router, "router MAC", mac)
        say("VERDICT on-link=%s (ignoring the virtual rule: %s; virtual=%s)"
            % (same_subnet and rule_ok and not virt, same_subnet and rule_ok, virt))
except Exception:
    say("EXCEPTION", traceback.format_exc().replace("\n", " | "))
try:
    conn.sendall(("\n".join(out) + "\n").encode())
except Exception:
    pass
