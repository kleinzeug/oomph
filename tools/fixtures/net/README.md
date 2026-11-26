# Internet traffic fixtures (NET, 1.15)

Invented by hand in the grammar of each tool's output (`nettop -J`, `ss -tinpeHO`, `networkQuality -c`, /proc/net):
no row, address, port, counter or figure comes from a recording of a real machine. Addresses are documentation
ones: public IPv4 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, public IPv6 2001:db8::/32 (this network's prefix
2001:db8:0:1::/64), the router's ULA fd00:db8:1::/48, link-local fe80::db8:x and IIDs derived from MACs of
00:00:5e:00:53:00/24 (RFC 7042). LAN hosts are invented within 192.168.178.0/24, the range a home router hands out.

| File | What |
|---|---|
| `nettop-J.csv` | `nettop -L 1 -x -n -t external -J interface,state,bytes_in,bytes_out` on a Mac whose egress is en16: processes (`name.pid`) each followed by its flows; LAN (SMB to a NAS, link-local, an on-link global IPv6 address, a mapped private IPv4), internet (IPv4, IPv6, QUIC, CGNAT space), Wi-Fi (en0, not the egress), a listener, unconnected UDP, a tunnel (utun3) |
| `nettop-J-reordered.csv` | the same rows with the columns in another order (`-J` "may change order") |
| `nettop-hostile.csv` | what a local user can put into nettop's output through a process name: commas, `<->`, a name that reads as a flow, a 600-character line, a 31-digit counter, a row with a column missing |
| `ss-tinpeHO.txt` | `ss -tinpeHO` as a user (uid 1001): its own sockets with their process, other users' without; LISTEN, loopback, IPv6 in brackets, a scoped link-local, a mapped address, a name that imitates `bytes_received:`; what is not the egress device's (loopback, a docker bridge, a socket of the WireGuard tunnel 10.8.0.2); hostile lines: a cgroup path that imitates counters, a cookie, a uid and a shutdown arrow, a name that imitates `",pid=`, a name that imitates the kernel's `ino: sk:` |
| `networkQuality-s.json` | `networkQuality -c -s` (sequential), cut to the fields `oomph net test` reads: 176.4 down, 42.3 up |
| `linux/` | an OOMPH_SYSROOT: /proc/net (dev, route, arp, if_inet6) of a server whose egress is enp1s0f0, with docker0, virbr0 and a WireGuard tunnel wg0 (/sys/class/net/*/type); the test moves it to /proc/1/net for the service oomphd's view (PrivateNetwork: its own /proc/net shows lo alone) |
