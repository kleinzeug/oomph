#!/usr/bin/env python3
"""Hard-link tests of DESIGN.md section 12.2 / 15.5.
hardlink.py writer DIR fstat|byname N SECONDS   -- append N records, paced over SECONDS
hardlink.py attacker DIR VICTIM SECONDS          -- link VICTIM to DIR/reservations.jsonl and unlink, in a tight loop
hardlink.py static DIR VICTIM fstat|byname       -- one planted static link, one write"""
import json, os, sys, time
NAME = "reservations.jsonl"
FL = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

def open_checked(dfd, mode, stats):
    for attempt in range(50):
        try:
            fd = os.open(NAME, FL, 0o666, dir_fd=dfd)
        except OSError as e:
            stats["open_err"] = stats.get("open_err", 0) + 1; continue
        ok = True
        if mode == "fstat":
            ok = os.fstat(fd).st_nlink == 1
        else:  # by-name: the name must describe the descriptor's file, with one link
            f = os.fstat(fd)
            try:
                n = os.stat(NAME, dir_fd=dfd, follow_symlinks=False)
                ok = (n.st_dev, n.st_ino) == (f.st_dev, f.st_ino) and n.st_nlink == 1
            except FileNotFoundError:
                ok = False
        if ok:
            return fd
        stats["rejected"] = stats.get("rejected", 0) + 1
        os.close(fd)
        try:
            os.unlink(NAME, dir_fd=dfd)   # removes only this name
        except OSError:
            pass
    return None

def writer(d, mode, n, secs):
    dfd = os.open(d, os.O_DIRECTORY | os.O_NOFOLLOW)
    stats = {"written": 0}; pause = secs / n
    for i in range(n):
        fd = open_checked(dfd, mode, stats)
        if fd is None:
            stats["gave_up"] = stats.get("gave_up", 0) + 1; continue
        os.write(fd, (json.dumps({"id": "r%d" % i, "purpose": "spike record %d" % i}) + "\n").encode())
        os.close(fd); stats["written"] += 1
        time.sleep(pause)
    print("writer uid=%d mode=%s %s" % (os.geteuid(), mode, json.dumps(stats)))

def attacker(d, victim, secs):
    end = time.time() + secs; links = 0; errs = {}
    p = os.path.join(d, NAME)
    while time.time() < end:
        try:
            os.unlink(p)
        except OSError:
            pass
        try:
            os.link(victim, p); links += 1
        except OSError as e:
            errs[e.strerror] = errs.get(e.strerror, 0) + 1
            if e.errno == 1 and links == 0 and errs[e.strerror] > 1000:
                break
            continue
        try:
            os.unlink(p)
        except OSError:
            pass
    print("attacker uid=%d links=%d errors=%s" % (os.geteuid(), links, errs))

def static(d, victim, mode):
    p = os.path.join(d, NAME)
    try: os.unlink(p)
    except OSError: pass
    os.link(victim, p)
    dfd = os.open(d, os.O_DIRECTORY | os.O_NOFOLLOW); stats = {}
    fd = open_checked(dfd, mode, stats)
    if fd is not None:
        os.write(fd, b'{"id":"static"}\n'); os.close(fd)
    print("static mode=%s stats=%s" % (mode, stats))

if __name__ == "__main__":
    c = sys.argv[1]
    if c == "writer": writer(sys.argv[2], sys.argv[3], int(sys.argv[4]), float(sys.argv[5]))
    elif c == "attacker": attacker(sys.argv[2], sys.argv[3], float(sys.argv[4]))
    elif c == "static": static(sys.argv[2], sys.argv[3], sys.argv[4])
    elif c == "wellformed":
        bad = good = 0
        for line in open(os.path.join(sys.argv[2], NAME), "rb"):
            try: json.loads(line); good += 1
            except ValueError: bad += 1
        print("log lines good=%d bad=%d" % (good, bad))
