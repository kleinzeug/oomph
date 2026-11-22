#!/usr/bin/python3 -I
"""Recorded Linux machines for the tests of daemon/oomph_linux.py (roadmap 03 §15.1): each scenario
writes the dozen /proc and /sys files the backend reads, below a root that OOMPH_SYSROOT then
points at, so the Linux backend runs on a Mac too. The numbers follow what the fact spike read on
the runners and guests (03 Appendix C.3); what a scenario must produce is its `expect`.

    python3 tools/linuxfixture.py DIR SCENARIO     write one (DIR must not exist)
    python3 tools/linuxfixture.py --list
"""
import json
import os
import sys

KB = 1024
GBK = 1024 * 1024  # kB in a GB


def meminfo(total, avail, anon, shmem=0.1, free=None, swap_total=0.0, swap_free=None, zswap=None, zswapped=0.0,
            sunreclaim=0.1, huge_pages=0, commit=(0.2, 0.6)):
    """/proc/meminfo with the fields oomph reads, figures in GB (written in kB, as the kernel does).
    zswap None: a kernel without the zswap fields (Debian 12's cloud kernel)."""
    free = avail * 0.6 if free is None else free
    swap_free = swap_total if swap_free is None else swap_free
    rows = [("MemTotal", total), ("MemFree", free), ("MemAvailable", avail), ("Buffers", 0.05),
            ("Cached", max(0.0, avail - free)), ("SwapCached", 0.0), ("AnonPages", anon), ("Shmem", shmem),
            ("SUnreclaim", sunreclaim), ("Dirty", 0.001), ("SwapTotal", swap_total), ("SwapFree", swap_free),
            ("CommitLimit", total * commit[1]), ("Committed_AS", total * commit[0])]
    if zswap is not None:
        rows += [("Zswap", zswap), ("Zswapped", zswapped)]
    text = "".join("%-16s%10d kB\n" % (k + ":", round(v * GBK)) for k, v in rows)
    text += "HugePages_Total: %8d\nHugepagesize:       2048 kB\n" % huge_pages
    return text


def psi(some=0.0, full=0.0, some60=None, full60=None):
    return ("some avg10=%.2f avg60=%.2f avg300=0.00 total=%d\nfull avg10=%.2f avg60=%.2f avg300=0.00 total=%d\n"
            % (some, some if some60 is None else some60, int(some * 1e5), full, full if full60 is None else full60,
               int(full * 1e5)))


def stat(pid, comm, ppid, start, flags=0x400100):
    return ("%d (%s) S %d %d %d 0 -1 %d 100 0 0 0 5 3 0 0 20 0 1 0 %d 12345678 1000 18446744073709551615\n"
            % (pid, comm, ppid, pid, pid, flags, start))


def status(uid, rss_kb, anon_kb, swap_kb=0, nspid=None):
    ns = "\t".join(str(x) for x in (nspid or []))
    return ("Name:\tx\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t%d\t%d\t%d\t%d\nVmRSS:\t%8d kB\nRssAnon:\t%8d kB\n"
            "RssShmem:\t       0 kB\nVmSwap:\t%8d kB\n%s" % (uid, uid, uid, uid, rss_kb, anon_kb, swap_kb,
                                                        "NSpid:\t%s\n" % ns if ns else ""))


DOCKER = "a3f9c1a7e5b2d4c10f00d00d1234567890abcdef1234567890abcdef12345678"
PODMAN = "7c0ffee0123456789abcdef0123456789abcdef0123456789abcdef012345678"
HOST_PROCS = [
    # pid, comm, ppid, uid, rss MB, anon MB, cgroup, cmdline, nspid
    (1, "systemd", 0, 0, 12, 4, "/init.scope", ["/sbin/init", "splash"], None),
    (2, "kthreadd", 0, 0, 0, 0, "/", [], None),
    (812, "sshd", 1, 0, 8, 2, "/system.slice/ssh.service", ["sshd: /usr/sbin/sshd -D"], None),
    (900, "postgres", 1, 113, 900, 300, "/system.slice/postgresql@16-main.service", ["/usr/lib/postgresql/16/bin/postgres", "-D"], None),
    (901, "postgres", 900, 113, 400, 120, "/system.slice/postgresql@16-main.service", ["postgres: checkpointer"], None),
    (1500, "bash", 812, 1000, 6, 3, "/user.slice/user-1000.slice/session-4.scope", ["-bash"], None),
    (1600, "claude", 1500, 1000, 420, 400, "/user.slice/user-1000.slice/session-4.scope", ["claude"], None),
    (1610, "java", 1600, 1000, 5300, 5200, "/user.slice/user-1000.slice/session-4.scope", ["/usr/bin/java", "-jar", "gradle.jar"], None),
    (1700, "node", 1500, 1000, 300, 280, "/user.slice/user-1000.slice/session-4.scope",
     ["node", "/home/ada/.npm/lib/node_modules/@anthropic-ai/claude-code/cli.js"], None),
    (2000, "containerd-shim", 1, 0, 10, 5, "/system.slice/containerd.service", ["/usr/bin/containerd-shim-runc-v2"], None),
    (2001, "nginx", 2000, 0, 60, 40, "/system.slice/docker-%s.scope" % DOCKER, ["nginx: master process"], [2001, 1]),
    (2002, "nginx", 2001, 33, 50, 30, "/system.slice/docker-%s.scope" % DOCKER, ["nginx: worker process"], [2002, 7]),
    (2100, "conmon", 1, 0, 2, 1, "/machine.slice/libpod-conmon-%s.scope" % PODMAN,
     ["/usr/bin/conmon", "--api-version", "1", "-c", PODMAN, "-u", PODMAN, "-n", "devdb"], None),
    (2101, "postgres", 2100, 999, 200, 150, "/machine.slice/libpod-%s.scope/container" % PODMAN, ["postgres"], [2101, 1]),
    (2200, "gnome-terminal-", 1500, 1000, 80, 60,
     "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-org.gnome.Terminal-4711.scope",
     ["/usr/libexec/gnome-terminal-server"], None),
    (2300, "a) (b", 1500, 1000, 5, 4, "/user.slice/user-1000.slice/session-4.scope", ["./a) (b"], None),
    (2310, "x\x1b]0;pwn\x07", 1500, 1000, 5, 4,
     "/user.slice/user-1000.slice/user@1000.service/app.slice/app-gnome-ev\\x1b\\x5b2Jil-77.scope", ["x\x1b]0;pwn\x07"], None),
    (2400, "2.1.330", 1500, 1000, 90, 80, "/user.slice/user-1000.slice/session-4.scope",
     ["/home/ada/.local/share/claude/versions/2.1.330"], None),
]


def _w(root, path, text):
    p = os.path.join(root, path.lstrip("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as f:
        f.write(text)


def _procs(root, procs, self_cg):
    for pid, comm, ppid, uid, rss, anon, cg, argv, ns in procs:
        flags = 0x00208040 if pid == 2 else 0x400100   # kthreadd is a kernel thread (PF_KTHREAD)
        _w(root, "/proc/%d/stat" % pid, stat(pid, comm, ppid, 1000 + pid, flags))
        _w(root, "/proc/%d/status" % pid, status(uid, rss * 1024, anon * 1024, 0, ns))
        _w(root, "/proc/%d/cgroup" % pid, "0::%s\n" % cg)
        _w(root, "/proc/%d/cmdline" % pid, "".join(a + "\0" for a in argv))
    _w(root, "/proc/self/cgroup", "0::%s\n" % self_cg)
    _w(root, "/proc/self/mountinfo", "22 26 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw\n"
                                     "25 26 0:23 / /sys/fs/cgroup rw - cgroup2 cgroup2 rw,nsdelegate\n")


def _machine(root, distro="Ubuntu 24.04.3 LTS", mid="3f9c1a7e5b2d4c10a1b2c3d4e5f60718"):
    _w(root, "/etc/os-release", 'PRETTY_NAME="%s"\nNAME="%s"\nID=x\n' % (distro, distro.split()[0]))
    if mid:
        _w(root, "/etc/machine-id", mid + "\n")
    _w(root, "/proc/sys/kernel/random/boot_id", "0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0\n")
    _w(root, "/proc/sys/vm/overcommit_memory", "0\n")
    _w(root, "/sys/class/dmi/id/sys_vendor", "QEMU\n")
    _w(root, "/sys/class/dmi/id/product_name", "Standard PC (Q35 + ICH9, 2009)\n")


def _cgroup_v2(root):
    _w(root, "/sys/fs/cgroup/cgroup.controllers", "cpuset cpu io memory hugetlb pids rdma misc\n")


def _vm(root, pswpin=0, pswpout=0):
    _w(root, "/proc/vmstat", "nr_free_pages 3000000\npswpin %d\npswpout %d\noom_kill 0\n" % (pswpin, pswpout))


def _swaps(root, rows):
    _w(root, "/proc/swaps", "Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n" + "".join(
        "%s\t%s\t%d\t%d\t-2\n" % (n, t, round(size * GBK), round(used * GBK)) for n, t, size, used in rows))


def _pressure(root, mem, cpu=None, io=None):
    _w(root, "/proc/pressure/memory", mem)
    _w(root, "/proc/pressure/cpu", cpu or psi(1.2))
    _w(root, "/proc/pressure/io", io or psi(0.3, 0.1))


def base(root, mem, swaprows=(), pressure=psi(), self_cg="/user.slice/user-1000.slice/session-4.scope", **kw):
    _machine(root, **kw)
    _cgroup_v2(root)
    _vm(root)
    _w(root, "/proc/meminfo", mem)
    _swaps(root, swaprows)
    if pressure is not None:
        _pressure(root, pressure)
    _procs(root, HOST_PROCS, self_cg)


def s_ubuntu_idle(root):
    base(root, meminfo(16, 14.4, anon=1.2, shmem=0.05, free=9.0, swap_total=3.0, zswap=0.0),
         [("/swapfile", "file", 3.0, 0.0)])


def s_server_noswap_93pct(root):
    base(root, meminfo(32, 2.0, anon=27.0, shmem=0.5, free=0.6))


def s_rhel9_nopsi(root):
    base(root, meminfo(2, 0.15, anon=1.6, free=0.05), pressure=None, distro="Rocky Linux 9.9 (Blue Onyx)")


def s_rhel9_nopsi_roomy(root):
    base(root, meminfo(16, 12.0, anon=3.0, free=8.0), pressure=None, distro="Rocky Linux 9.9 (Blue Onyx)")


def s_vm_32g_noswap(root):
    """03 §5.3's example: a swapless 32 GB VM with 10 GB available is normal; 8 GB does not fit even
    alone (10 GB available, no swap, 3.2 GB must stay free: at most 6.8 GB)."""
    base(root, meminfo(32, 10.0, anon=20.0, free=3.0))


def s_pain_critical(root):
    base(root, meminfo(16, 1.0, anon=14.0, free=0.2, swap_total=4.0, swap_free=0.3),
         [("/swap.img", "file", 4.0, 3.7)], pressure=psi(45.0, 18.0))


def s_zram_desktop(root):
    base(root, meminfo(32, 2.7, anon=22.9, shmem=0.5, free=0.6, swap_total=8.0, swap_free=1.9, zswap=0.0),
         [("/dev/zram0", "partition", 8.0, 6.1)], pressure=psi(14.2, 3.1))
    gb = 1 << 30
    _w(root, "/sys/block/zram0/mm_stat", "%d %d %d 0 %d 0 0 0 0\n" % (6.1 * gb, 2.8 * gb, 2.9 * gb, 3 * gb))
    _w(root, "/sys/block/zram0/disksize", "%d\n" % (8 * gb))


def s_hugepages(root):
    base(root, meminfo(64, 30.0, anon=10.0, free=40.0, huge_pages=8192))  # MemFree > MemAvailable


def _container_cg(root, d, limit_gb, current_gb, anon_gb, file_gb, high=None, pressure=psi(), swap_max=0):
    _w(root, "/sys/fs/cgroup/%s/memory.max" % d, "%d\n" % (limit_gb * (1 << 30)) if limit_gb else "max\n")
    _w(root, "/sys/fs/cgroup/%s/memory.high" % d, "%d\n" % (high * (1 << 30)) if high else "max\n")
    _w(root, "/sys/fs/cgroup/%s/memory.current" % d, "%d\n" % (current_gb * (1 << 30)))
    _w(root, "/sys/fs/cgroup/%s/memory.swap.current" % d, "0\n")
    _w(root, "/sys/fs/cgroup/%s/memory.swap.max" % d, "%s\n" % swap_max)
    _w(root, "/sys/fs/cgroup/%s/memory.stat" % d, "anon %d\nfile %d\nshmem 0\ninactive_file %d\nactive_file %d\n"
                                                    "slab_reclaimable 0\n" % (anon_gb * (1 << 30), file_gb * (1 << 30),
                                                                              file_gb * (1 << 30) / 2, file_gb * (1 << 30) / 2))
    if pressure is not None:
        _w(root, "/sys/fs/cgroup/%s/memory.pressure" % d, pressure)


def s_container_2g(root):
    """A docker container with its own cgroup namespace: /proc/self/cgroup says "/", and the mount is
    the container's cgroup, limited to 2 GB."""
    base(root, meminfo(16, 9.1, anon=5.0, free=4.0, swap_total=4.0), [("/swap.img", "file", 4.0, 0.0)],
         self_cg="/", mid=None, distro="Debian GNU/Linux 12 (bookworm)")
    _w(root, "/.dockerenv", "")
    _container_cg(root, "", 2, 0.9, 0.6, 0.2)


def s_container_2g_neighbour_thrash(root):
    """The container of container-2g while ANOTHER container thrashes at its own limit: the machine's
    stall time (some 97 %) is the neighbour's, out of sight below this namespace's mount. The host has
    room and this container stalls not at all: below critical, never stop."""
    s_container_2g(root)
    _pressure(root, psi(97.0, 40.0))


def s_scope_memory_high(root):
    d = "user.slice/user-1000.slice/user@1000.service/app.slice/run-u42.scope"
    base(root, meminfo(16, 12.0, anon=3.0, free=8.0), self_cg="/" + d)
    _container_cg(root, d, None, 0.5, 0.4, 0.05, high=1)


def s_container_thrash_roomy_host(root):
    """One container thrashing at its own limit: the machine's stall time is all its (some 97 %),
    but the machine has room; the level must stay normal and say who lost the time."""
    base(root, meminfo(64, 44.5, anon=14.0, free=12.0, swap_total=8.0), [("/swap.img", "file", 8.0, 0.4)],
         pressure=psi(97.0, 40.0))
    _w(root, "/sys/fs/cgroup/system.slice/memory.pressure", psi(97.0, 40.0))
    _w(root, "/sys/fs/cgroup/system.slice/memory.max", "max\n")
    _w(root, "/sys/fs/cgroup/system.slice/memory.current", "%d\n" % (6 << 30))
    _container_cg(root, "system.slice/docker-%s.scope" % DOCKER, 2, 1.99, 1.9, 0.05, pressure=psi(97.0, 40.0))
    _w(root, "/sys/fs/cgroup/user.slice/memory.pressure", psi(0.0))


def s_container_thrash_short_host(root):
    s_container_thrash_roomy_host(root)
    _w(root, "/proc/meminfo", meminfo(64, 5.0, anon=55.0, free=1.0, swap_total=8.0, swap_free=1.0))


SCENARIOS = {
    "ubuntu-server-idle": (s_ubuntu_idle, {"pressure": 1, "ram_gb": 16.0, "identity": True, "psi": True,
                                           "margin_gb": 2.4, "swap_total_gb": 3.0}),
    "server-noswap-93pct": (s_server_noswap_93pct, {"pressure": 2, "level": "tight", "margin_gb": 4.8}),
    "rhel9-nopsi": (s_rhel9_nopsi, {"pressure": 2, "level": "tight", "psi": False}),
    "rhel9-nopsi-roomy": (s_rhel9_nopsi_roomy, {"pressure": 1, "level": "ok", "psi": False}),
    "vm-32g-noswap": (s_vm_32g_noswap, {"pressure": 1, "level": "ok", "margin_gb": 4.8}),
    "pain-critical": (s_pain_critical, {"pressure": 4, "level": "critical"}),
    "zram-desktop": (s_zram_desktop, {"pressure": 2, "compressed_gb": 2.9, "swap_total_gb": 0.0, "swap_used_gb": 0.0}),
    "fresh-boot-hugepages": (s_hugepages, {"free_gb": 30.0, "identity": True}),
    "container-2g": (s_container_2g, {"scope": "cgroup", "ram_gb": 2.0, "level": "ok"}),
    "container-2g-neighbour-thrash": (s_container_2g_neighbour_thrash, {"scope": "cgroup", "ram_gb": 2.0, "pressure": 2,
                                                                        "host_pressure": 2}),
    "scope-memory-high": (s_scope_memory_high, {"scope": "cgroup", "ram_gb": 1.0, "by": "high"}),
    "container-thrash-roomy-host": (s_container_thrash_roomy_host, {"pressure": 1, "limit": True}),
    "container-thrash-short-host": (s_container_thrash_short_host, {"pressure": 4}),
}


def build(root, name):
    os.makedirs(root)
    SCENARIOS[name][0](root)
    return SCENARIOS[name][1]


if __name__ == "__main__":
    if sys.argv[1:] == ["--list"]:
        print("\n".join(SCENARIOS))
    elif len(sys.argv) == 3:
        print(json.dumps(build(sys.argv[1], sys.argv[2])))
    else:
        print(__doc__.strip().splitlines()[-2:][0])
        sys.exit(2)
