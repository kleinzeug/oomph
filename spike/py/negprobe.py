#!/usr/bin/env python3
"""Negative probes run under a unit's properties. Every line says what was tried and whether it was REFUSED.
negprobe.py OUTFILE DIR... (dirs where creating a file must fail)"""
import errno, os, socket, sys
out = []
def r(what, fn):
    try:
        v = fn(); out.append("ALLOWED  %s -> %r" % (what, v if not isinstance(v, bytes) else v[:40]))
    except Exception as e:
        out.append("REFUSED  %s -> %s" % (what, e))
r("readlink /proc/1/exe", lambda: os.readlink("/proc/1/exe"))
r("open /proc/1/mem", lambda: os.close(os.open("/proc/1/mem", os.O_RDONLY)) or "opened")
r("socket AF_INET", lambda: socket.socket(socket.AF_INET, socket.SOCK_STREAM).close() or "created")
r("socket AF_INET6", lambda: socket.socket(socket.AF_INET6, socket.SOCK_STREAM).close() or "created")
r("socket AF_NETLINK", lambda: socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0).close() or "created")
try:
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    def call(name, *args):
        v = getattr(libc, name)(*args)
        if v == -1:
            e = ctypes.get_errno(); raise OSError(e, os.strerror(e))
        return v
    class iovec(ctypes.Structure):
        _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
    buf = ctypes.create_string_buffer(16); lv = iovec(ctypes.cast(buf, ctypes.c_void_p), 16); rv = iovec(0x400000, 16)
    r("process_vm_readv(pid 1)", lambda: call("process_vm_readv", 1, ctypes.byref(lv), 1, ctypes.byref(rv), 1, 0))
    r("ptrace(PTRACE_ATTACH, 1)", lambda: call("ptrace", 16, 1, 0, 0))
except Exception as e:
    out.append("SKIPPED  ctypes probes: %r" % e)
for d in sys.argv[2:]:
    p = os.path.join(d, "spike-negprobe-%d" % os.getpid())
    def mk(p=p):
        fd = os.open(p, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd); os.unlink(p); return "created"
    r("create file in " + d, mk)
st = {}
for line in open("/proc/self/status"):
    k, _, v = line.partition(":")
    if k in ("Uid", "Gid", "Groups", "CapEff", "CapBnd", "CapPrm", "NoNewPrivs", "Seccomp"): st[k] = v.strip()
out.append("STATUS %s" % st)
try:
    out.append("NETDEV " + " ".join(l.split(":")[0].strip() for l in open("/proc/self/net/dev").read().splitlines()[2:]))
except OSError as e:
    out.append("NETDEV error %s" % e)
text = "\n".join(out) + "\n"
print(text)
if sys.argv[1] != "-":
    try:
        with open(sys.argv[1], "w") as f: f.write(text)
    except OSError as e:
        print("could not write", sys.argv[1], e)
