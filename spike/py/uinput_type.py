#!/usr/bin/env python3
"""Type a line on the active virtual console through /dev/uinput (row 29)."""
import fcntl, os, struct, sys, time
UI_SET_EVBIT, UI_SET_KEYBIT, UI_DEV_CREATE, UI_DEV_DESTROY = 0x40045564, 0x40045565, 0x5501, 0x5502
EV_SYN, EV_KEY = 0, 1
KEYS = {c: k for c, k in zip("1234567890", range(2, 12))}
KEYS.update({c: k for c, k in zip("qwertyuiop", range(16, 26))})
KEYS.update({c: k for c, k in zip("asdfghjkl", range(30, 39))})
KEYS.update({c: k for c, k in zip("zxcvbnm", range(44, 51))})
KEYS.update({" ": 57, "\n": 28, "-": 12})
fd = os.open("/dev/uinput", os.O_WRONLY | os.O_NONBLOCK)
fcntl.ioctl(fd, UI_SET_EVBIT, EV_KEY)
for k in set(KEYS.values()): fcntl.ioctl(fd, UI_SET_KEYBIT, k)
os.write(fd, struct.pack("80sHHHHi" + "i" * 256, b"spike-kbd", 3, 1, 1, 1, 0, *([0] * 256)))
fcntl.ioctl(fd, UI_DEV_CREATE); time.sleep(1.0)
def ev(t, c, v):
    s, us = divmod(int(time.time() * 1e6), 1000000)
    os.write(fd, struct.pack("llHHi", s, us, t, c, v))
for ch in sys.argv[1] + "\n":
    k = KEYS.get(ch)
    if k is None: continue
    ev(EV_KEY, k, 1); ev(EV_SYN, 0, 0); ev(EV_KEY, k, 0); ev(EV_SYN, 0, 0); time.sleep(0.03)
time.sleep(0.5); fcntl.ioctl(fd, UI_DEV_DESTROY); print("typed", repr(sys.argv[1]))
