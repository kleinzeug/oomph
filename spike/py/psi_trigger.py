#!/usr/bin/env python3
"""Register a PSI trigger and poll for it. Prints one line: REGISTERED / FAILED errno."""
import os, select, sys, time
path = sys.argv[1] if len(sys.argv) > 1 else "/proc/pressure/memory"
trig = sys.argv[2] if len(sys.argv) > 2 else "some 200000 2000000"
print("uid=%d euid=%d path=%s trigger=%r" % (os.getuid(), os.geteuid(), path, trig))
try:
    st = os.stat(path)
    print("mode=%o owner=%d:%d" % (st.st_mode & 0o7777, st.st_uid, st.st_gid))
except OSError as e:
    print("stat failed:", e)
try:
    fd = os.open(path, os.O_RDWR | os.O_NONBLOCK)
except OSError as e:
    print("RESULT: FAILED open errno=%d (%s)" % (e.errno, e.strerror)); sys.exit(0)
try:
    os.write(fd, trig.encode() + b"\0")
except OSError as e:
    print("RESULT: FAILED write errno=%d (%s)" % (e.errno, e.strerror)); sys.exit(0)
p = select.poll(); p.register(fd, select.POLLPRI)
t = time.monotonic(); ev = p.poll(2500)
print("poll after %.2fs -> %r (empty = no event, i.e. calm; POLLPRI=%d, POLLERR=%d)"
      % (time.monotonic() - t, ev, select.POLLPRI, select.POLLERR))
print("RESULT: REGISTERED")
