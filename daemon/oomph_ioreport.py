#!/usr/bin/python3 -I
"""oomph's IOReport helper: how long the GPU spent in each of its performance states.

The private library libIOReport.dylib is the only source of how fast the GPU ran, which turns
"busy" (the share of time the GPU worked at any speed) into "at full speed" (roadmap 02 §4.2).
A private library may crash or change shape after a macOS update, so it is never loaded by a
process that runs as root: the logger starts this file as its own process, as nobody, and the
logger itself never imports it. This process refuses to run as root.

The protocol, over the pipes: each line in asks for one reading; each reading is one line of
JSON out, the residencies since the previous reading, in Mach time units:

  {"dt": <units since the previous reading>, "hz": <units a second>, "states": [["OFF", n], ["P1", n], ...]}

or {"error": "..."} when there is nothing to read ("no channel" on a Mac without the GPU
performance-state channel: an Intel Mac, most VMs). The first reading after the start is
measured from the start. End of input ends the process. Every CoreFoundation object a reading
creates is released: without that a reading leaks 6.3 KB (02 A.16, A.29). As a second fence the
process ends itself when its resident size passes RSS_CAP; the logger counts that as a crash.

Standard library only; it imports nothing of oomph's, so it stays small (18 MB resident on an M3 Max).
"""
import ctypes
import json
import os
import resource
import sys

GROUP, SUBGROUP, CHANNEL = "GPU Stats", "GPU Performance States", "GPUPH"
MAX_STATES = 64
RSS_CAP = 64 << 20  # bytes; the helper needs about 10 MB
UTF8 = 0x08000100


def _lib():
    """CoreFoundation and IOReport with the prototypes used here (loaded only when asked)."""
    cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
    ior = ctypes.CDLL("/usr/lib/libIOReport.dylib")
    vp, u64, i32, i64 = ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int32, ctypes.c_int64
    for name, res, args in (
            ("CFStringCreateWithCString", vp, [vp, ctypes.c_char_p, ctypes.c_uint32]),
            ("CFStringGetCString", ctypes.c_bool, [vp, ctypes.c_char_p, ctypes.c_long, ctypes.c_uint32]),
            ("CFDictionaryGetValue", vp, [vp, vp]),
            ("CFArrayGetCount", ctypes.c_long, [vp]),
            ("CFArrayGetValueAtIndex", vp, [vp, ctypes.c_long]),
            ("CFDictionaryCreateMutableCopy", vp, [vp, ctypes.c_long, vp]),
            ("CFRelease", None, [vp])):
        f = getattr(cf, name)
        f.restype, f.argtypes = res, args
    for name, res, args in (
            ("IOReportCopyChannelsInGroup", vp, [vp, vp, u64, u64, u64]),
            ("IOReportCreateSubscription", vp, [vp, vp, ctypes.POINTER(vp), u64, vp]),
            ("IOReportCreateSamples", vp, [vp, vp, vp]),
            ("IOReportCreateSamplesDelta", vp, [vp, vp, vp]),
            ("IOReportChannelGetChannelName", vp, [vp]),
            ("IOReportStateGetCount", i32, [vp]),
            ("IOReportStateGetNameForIndex", vp, [vp, i32]),
            ("IOReportStateGetResidency", i64, [vp, i32])):
        f = getattr(ior, name)
        f.restype, f.argtypes = res, args
    return cf, ior


class Reader:
    """One subscription to the GPU's performance states and the previous reading."""

    def __init__(self):
        self.cf, self.ior = cf, ior = _lib()
        sysl = ctypes.CDLL("/usr/lib/libSystem.B.dylib")
        sysl.mach_absolute_time.restype = ctypes.c_uint64
        self.clock = sysl.mach_absolute_time

        class Timebase(ctypes.Structure):
            _fields_ = [("numer", ctypes.c_uint32), ("denom", ctypes.c_uint32)]
        tb = Timebase()
        sysl.mach_timebase_info(ctypes.byref(tb))
        self.hz = 1e9 * tb.denom / tb.numer if tb.numer and tb.denom else 1e9
        self.k_channels = self.cfstr("IOReportChannels")  # kept for the life of the process, like the subscription
        g, sg = self.cfstr(GROUP), self.cfstr(SUBGROUP)
        chan = ior.IOReportCopyChannelsInGroup(g, sg, 0, 0, 0)
        cf.CFRelease(g)
        cf.CFRelease(sg)
        self.sub = self.prev = None
        if not chan:
            return
        self.chans = cf.CFDictionaryCreateMutableCopy(None, 0, chan)
        cf.CFRelease(chan)
        self.subbed = ctypes.c_void_p()
        self.sub = ior.IOReportCreateSubscription(None, self.chans, ctypes.byref(self.subbed), 0, None)
        if self.sub:
            self.prev, self.at = self.sample()

    def cfstr(self, s):
        return self.cf.CFStringCreateWithCString(None, s.encode(), UTF8)

    def pystr(self, ref):
        b = ctypes.create_string_buffer(64)
        return b.value.decode("utf-8", "replace") if ref and self.cf.CFStringGetCString(ref, b, 64, UTF8) else None

    def sample(self):
        s = self.ior.IOReportCreateSamples(self.sub, self.subbed, None)
        return s, self.clock()

    def states(self, delta):
        """[[name, residency], ...] of the GPUPH channel in a delta; the references read here are
        borrowed from the delta (Get, not Copy or Create), so releasing the delta frees them."""
        cf, ior = self.cf, self.ior
        arr = cf.CFDictionaryGetValue(delta, self.k_channels)
        if not arr:
            return None
        for i in range(min(cf.CFArrayGetCount(arr), 4096)):
            ch = cf.CFArrayGetValueAtIndex(arr, i)
            if self.pystr(ior.IOReportChannelGetChannelName(ch)) == CHANNEL:
                n = ior.IOReportStateGetCount(ch)
                return [[self.pystr(ior.IOReportStateGetNameForIndex(ch, k)), int(ior.IOReportStateGetResidency(ch, k))]
                        for k in range(max(0, min(n, MAX_STATES)))]
        return None

    def read(self):
        """The answer to one request, as a dict."""
        if not self.sub:
            return {"error": "no channel"}
        cur, at = self.sample()
        if not cur:
            return {"error": "no sample"}
        prev, t0 = self.prev, self.at
        self.prev, self.at = cur, at
        if not prev:
            return {"error": "no sample"}
        delta = self.ior.IOReportCreateSamplesDelta(prev, cur, None)
        self.cf.CFRelease(prev)
        if not delta:
            return {"error": "no delta"}
        try:
            st = self.states(delta)
        finally:
            self.cf.CFRelease(delta)
        if st is None:
            return {"error": "no channel"}
        return {"dt": int(at - t0), "hz": self.hz, "states": st}


def main():
    if os.geteuid() == 0:
        sys.stderr.write("oomph: the IOReport helper refuses to run as root\n")
        return 3
    r = Reader()
    n = 0
    for _ in sys.stdin.buffer:
        out = r.read()
        sys.stdout.write(json.dumps(out, separators=(",", ":"), allow_nan=False) + "\n")
        sys.stdout.flush()
        n += 1
        if n % 50 == 0 and resource.getrusage(resource.RUSAGE_SELF).ru_maxrss > RSS_CAP:
            sys.stderr.write("oomph: the IOReport helper grew past %d MB; ending\n" % (RSS_CAP >> 20))
            return 4
    return 0


if __name__ == "__main__":
    sys.exit(main())
