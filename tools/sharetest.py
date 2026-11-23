#!/usr/bin/python3 -I
"""Tests of remote machines as 1.10.0 ships them (roadmap 01 §12): the peer gate, pairing and
tokens, TLS, the share commands against a scratch state directory, `oomph remote` over TCP and
over a fake ssh, the engine and its followers. Unprivileged and portable; tools/selftest.py runs
it. All data is invented.

    /usr/bin/python3 -I -B tools/sharetest.py          the tests (about a minute)
    sudo /usr/bin/python3 -I -B tools/sharetest.py root   CI only: the real role account, launchd job,
                                                          pairing over loopback, revoke, install.sh over
                                                          a sharing install, uninstall --purge (macOS)
"""
import atexit
import base64
import hashlib
import json
import os
import random
import select
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.join(ROOT, "daemon"))
import topfixture  # noqa: E402  (sets TZ to Europe/Berlin)
import oomph  # noqa: E402
import oomph_net as net  # noqa: E402
import oomph_sync as sync  # noqa: E402

PY = sys.executable
OOMPH = os.path.join(ROOT, "daemon", "oomph.py")
NOW = topfixture.NOW + 30
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


def cli(*args, env=None, input=None, timeout=60):
    return subprocess.run([PY, "-I", "-B", OOMPH] + list(args), capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ, **(env or {})), input=input)


def make_machine(d, mid="m-0123456789abcdef", name="studio"):
    log, led = topfixture.write_fixture(d, "default")
    cur = json.load(open(os.path.join(log, "current.json")))
    cur["daemon"]["machine"] = {"id": mid, "name": name, "os": "macos", "arch": "arm64", "os_version": "macOS 27.2",
                                "kind": "desktop", "cpus": 16}
    json.dump(cur, open(os.path.join(log, "current.json"), "w"))
    return log, led


def wait_for(pred, secs):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.1)
    return pred()


class Listener:
    """`oomph serve --listen 127.0.0.1:0` on a share directory, in the background."""

    def __init__(self, share, now=NOW):
        self.p = subprocess.Popen([PY, "-I", "-B", OOMPH, "serve", "--listen", "127.0.0.1:0", "--now", repr(now)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=dict(os.environ, OOMPH_SHARE_DIR=share))
        line = self.p.stdout.readline().decode()
        self.port = int(line.rsplit(":", 1)[1]) if line.startswith("listening") else None
        atexit.register(self.stop)  # a check that raises (a CLI timeout) must not leave it listening

    def stop(self):
        self.p.terminate()
        try:
            self.p.wait(5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()


def run_root():
    """As real root on a throwaway macOS runner (CI): the role account and the launchd job for real."""
    if os.geteuid() != 0 or sys.platform != "darwin" or not os.environ.get("CI"):
        print("sharetest root: as root, on macOS, in CI only")
        return 2
    user = int(os.environ.get("SUDO_UID") or 0)
    tmp = tempfile.mkdtemp(prefix="oomph-share-root-")
    os.chmod(tmp, 0o755)
    mdir = os.path.join(tmp, "viewer")
    os.makedirs(mdir)
    os.chown(mdir, user, -1)
    inst = "/usr/local/bin/oomph"

    def as_user(*args, timeout=90):
        return subprocess.run(["/usr/bin/sudo", "-u", "#%d" % user, "env", "OOMPH_MACHINES_DIR=" + mdir + "/machines",
                               PY, "-I", "-B", OOMPH] + list(args), capture_output=True, text=True, timeout=timeout)

    def root(*args, timeout=net.WARM_S + 90):  # share on waits for the service's first start
        return subprocess.run([inst] + list(args), capture_output=True, text=True, timeout=timeout)
    r = subprocess.run(["./install.sh"], cwd=ROOT, capture_output=True, text=True, timeout=300)
    check(r.returncode == 0, "install.sh as root (%s)" % r.stderr.strip()[-200:])
    r = root("share", "on", "--pair", "--json")
    print(r.stdout, r.stderr)
    code = json.loads(r.stdout.strip().splitlines()[-1])["code"] if r.returncode == 0 else ""
    check(r.returncode == 0 and code and "did not answer" not in r.stderr,
          "sudo oomph share on --pair: sharing on, the service started once and answered, a code printed")
    ids = subprocess.run(["/usr/bin/id", net.ROLE], capture_output=True, text=True).stdout
    check(subprocess.run(["/usr/bin/id", "-gn", net.ROLE], capture_output=True, text=True).stdout.strip() == net.ROLE,
          "the role account's group is its own (%s)" % ids.strip())
    st = os.stat(os.path.join(net.SHARE_DIRS["darwin"], "key.pem"))
    import grp
    check(st.st_uid == 0 and grp.getgrgid(st.st_gid).gr_name == net.ROLE and stat.S_IMODE(st.st_mode) == 0o640,
          "key.pem is root:%s 640" % net.ROLE)
    run = os.stat(os.path.join(net.SHARE_DIRS["darwin"], "run"))
    check(run.st_uid == __import__("pwd").getpwnam(net.ROLE).pw_uid, "run/ is the service account's")
    out = subprocess.run(["/bin/launchctl", "print", "system/" + net.LABEL], capture_output=True, text=True).stdout
    check("_oomph" in out, "the launchd job runs as %s" % net.ROLE)
    ds = lambda *a: subprocess.run(["/usr/bin/dscl", "."] + list(a), capture_output=True, text=True)  # noqa: E731
    check(ds("-authonly", net.ROLE, "").returncode != 0 and "Password: *" in ds("-read", "/Users/" + net.ROLE, "Password").stdout
          and "1" in ds("-read", "/Users/" + net.ROLE, "IsHidden").stdout,
          "nobody signs in as %s: no password, hidden, an empty one refused" % net.ROLE)
    t = time.time()
    r = as_user("remote", "add", "127.0.0.1", "--code", code, "--json")
    check(r.returncode == 0 and json.loads(r.stdout)["ok"], "a viewer pairs over loopback with the code, the first "
                                                            "connection after share on (%.1f s; %s %s)"
          % (time.time() - t, r.stdout.strip()[-300:] if r.returncode else "", r.stderr.strip()[-200:]))
    mid = json.loads(r.stdout)["machine"]["mid"] if r.returncode == 0 else None
    r = as_user("share", "status", "--json")
    stj = json.loads(r.stdout) if r.returncode == 0 else {}
    cid = (stj.get("clients") or [{}])[0].get("id")
    check(r.returncode == 0 and cid and "token" not in r.stdout and "key" not in json.dumps(stj.get("clients")),
          "share status as an ordinary user lists the viewer and no secret")
    t = time.time()
    r = as_user("remote", "sync", "--once", "--json")
    check(r.returncode == 0, "a warm connection catches up (%.1f s)" % (time.time() - t))

    def follow():
        """`remote sync --json` as the user, watching the machine: (process, its events)."""
        p = subprocess.Popen(["/usr/bin/sudo", "-u", "#%d" % user, "env", "OOMPH_MACHINES_DIR=" + mdir + "/machines",
                              PY, "-I", "-B", OOMPH, "remote", "sync", "--json"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        evs = []
        threading.Thread(target=lambda: [evs.append(json.loads(x)) for x in p.stdout], daemon=True).start()
        p.stdin.write((json.dumps({"cmd": "watch", "ids": [mid], "focus": mid}) + "\n").encode())
        p.stdin.flush()
        return p, evs

    def quit(p):
        try:
            p.stdin.write(b'{"cmd":"quit"}\n')
            p.stdin.flush()
            p.wait(20)
        except (OSError, subprocess.TimeoutExpired):
            p.kill()
            p.wait()

    def live(evs):
        return wait_for(lambda: any(x.get("ev") == "state" and x.get("state") == "live" for x in evs), 30)
    p, evs = follow()
    up = live(evs)
    mark = len(evs)
    t0 = time.time()
    r = root("share", "off")
    down = wait_for(lambda: any(x.get("ev") == "state" and x.get("state") in ("offline", "needs_attention")
                                for x in evs[mark:]), 6)
    check(up and r.returncode == 0 and down, "sudo oomph share off ends a live connection (%.1f s)" % (time.time() - t0))
    quit(p)
    r = root("share", "on")
    r2 = as_user("remote", "sync", "--once", "--json")
    check(r.returncode == 0 and r2.returncode == 0, "sudo oomph share on: back with the same key and pairings")
    r = subprocess.run(["./install.sh"], cwd=ROOT, capture_output=True, text=True, timeout=300)
    out = subprocess.run(["/bin/launchctl", "print", "system/" + net.LABEL], capture_output=True, text=True)
    check(r.returncode == 0 and out.returncode == 0, "install.sh over a sharing install keeps sharing on")
    fp1 = open(os.path.join(net.SHARE_DIRS["darwin"], "cert.pem")).read()
    subprocess.run(["./uninstall.sh"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    gone = subprocess.run(["/bin/launchctl", "print", "system/" + net.LABEL], capture_output=True, text=True).returncode != 0
    subprocess.run(["./install.sh"], cwd=ROOT, capture_output=True, text=True, timeout=300)
    back = subprocess.run(["/bin/launchctl", "print", "system/" + net.LABEL], capture_output=True, text=True).returncode == 0
    r = as_user("remote", "sync", "--once", "--json")
    check(gone and back and open(os.path.join(net.SHARE_DIRS["darwin"], "cert.pem")).read() == fp1 and r.returncode == 0,
          "Deactivate stops sharing, Activate brings it back with the same key; the old token still authenticates")
    p, evs = follow()
    up = live(evs)
    t0 = time.time()
    r = root("share", "revoke", cid)
    cut = wait_for(lambda: any(x.get("ev") == "state" and x.get("error") == "revoked" for x in evs), 6)
    check(up and r.returncode == 0 and cut, "sudo oomph share revoke ends the live connection (%.1f s): needs attention"
          % (time.time() - t0))
    quit(p)
    r = as_user("remote", "sync", "--once", "--json")
    check(r.returncode == 1 and json.loads(r.stdout)["machines"][0]["error"] == "revoked", "the revoked viewer is refused")

    # planted links in run/ (roadmap 01 §12): the service account plants them at a canary of root's
    cdir = tempfile.mkdtemp(prefix="oomph-canary-", dir="/private/var/tmp")
    os.chmod(cdir, 0o755)
    canary = os.path.join(cdir, "canary")
    with open(canary, "wb") as f:
        f.write(b"root's canary\n")
    os.chmod(canary, 0o600)

    def seen():
        st = os.stat(canary)
        return open(canary, "rb").read(), st.st_mode, st.st_uid
    first = seen()
    rundir = os.path.join(net.SHARE_DIRS["darwin"], "run")

    def plant():
        """As _oomph: links at every name run/ has, and a hard link where the file system lets it."""
        sv = ["/usr/bin/sudo", "-u", net.ROLE]
        subprocess.run(sv + ["/bin/mkdir", "-p", rundir + "/conn"], capture_output=True)
        for n in RUN_NAMES + ("conn/1.json",):
            subprocess.run(sv + ["/bin/rm", "-f", os.path.join(rundir, n)], capture_output=True)
            subprocess.run(sv + ["/bin/ln", "-s", canary, os.path.join(rundir, n)], capture_output=True)
        subprocess.run(sv + ["/bin/rm", "-f", rundir + "/summary.json"], capture_output=True)
        hard = subprocess.run(sv + ["/bin/ln", canary, rundir + "/summary.json"], capture_output=True).returncode == 0
        if not hard:
            subprocess.run(sv + ["/bin/ln", "-s", canary, rundir + "/summary.json"], capture_output=True)
        return hard
    hard = plant()
    crashed = []
    for args in (["share", "pair"], ["share", "revoke", "c-00000000"], ["share", "status"], ["share", "reload"],
                 ["share", "off", "--forget"]):
        r = root(*args)
        if "Traceback" in r.stderr:
            crashed.append(" ".join(args))
    check(seen() == first and not crashed, "links planted in run/ by the service account (a hard link too: %s): pair, "
                                           "revoke, status, reload and off --forget as root leave root's canary as it "
                                           "was %s" % (hard, crashed))
    root("share", "on")
    plant()
    r = subprocess.run(["./uninstall.sh", "--purge"], cwd=ROOT, capture_output=True, text=True, timeout=120)
    check(seen() == first and "Traceback" not in r.stderr, "… and so does uninstall.sh --purge")
    check(subprocess.run(["/usr/bin/id", net.ROLE], capture_output=True).returncode != 0 and
          not os.path.exists(net.SHARE_DIRS["darwin"]) and not os.path.exists(net.SHARE_PLIST),
          "uninstall.sh --purge removes the account, the state and the job")
    shutil.rmtree(cdir, ignore_errors=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all sharing checks passed as root"))
    return 1 if failures else 0


RUN_NAMES = ("clients.json", "pairing.json", "summary.json", "network.json", "lock")


def planted(tmp, log, led):
    """Roadmap 01 §12, the state directory: links and FIFOs planted at every name run/ has, each
    pointing at a canary outside it, before every share command that touches run/ (pair, revoke,
    status, reload, off --forget, purge). The canary stays as it was, nothing blocks, nothing
    crashes. Then the same commands in process, with os.open watched: no path under run/ is
    opened outside as_service (as root that is the service account's child)."""
    share = os.path.join(tmp, "share-planted")
    env = {"OOMPH_SHARE_DIR": share}
    canary = os.path.join(tmp, "canary")
    with open(canary, "wb") as f:
        f.write(b"canary\n")
    os.chmod(canary, 0o600)
    before = (open(canary, "rb").read(), os.stat(canary).st_mode, os.stat(canary).st_nlink)
    run = os.path.join(share, "run")

    def plant(kind):
        os.makedirs(os.path.join(run, "conn"), exist_ok=True)
        for n in RUN_NAMES + ("conn/%d.json" % os.getpid(),):
            p = os.path.join(run, n)
            if os.path.lexists(p):
                os.unlink(p)
            os.symlink(canary, p) if kind == "link" else os.mkfifo(p) if kind == "fifo" else os.link(canary, p)
    bad = []
    for kind in ("link", "fifo", "hard"):
        cli("share", "on", env=env)
        for cmd in (["pair"], ["revoke", "c-00000000"], ["status"], ["reload"], ["off", "--forget"], ["on"], ["purge"]):
            if not os.path.isdir(run):
                cli("share", "on", env=env)
            plant(kind)
            try:
                r = cli("share", *cmd, env=env, timeout=20)
                if "Traceback" in r.stderr:
                    bad.append("%s %s: %s" % (kind, cmd[0], r.stderr.strip()[-200:]))
            except subprocess.TimeoutExpired:
                bad.append("%s %s: blocked" % (kind, cmd[0]))
            now = (open(canary, "rb").read(), os.stat(canary).st_mode, os.stat(canary).st_nlink)
            if now[:2] != before[:2] or (kind != "hard" and now[2] != 1):
                bad.append("%s %s: the canary changed" % (kind, cmd[0]))
        shutil.rmtree(share, ignore_errors=True)
    check(not bad and os.stat(canary).st_nlink == 1, "planted links, FIFOs and hard links at every name in run/: the "
                                                     "canary is untouched, nothing blocks or crashes %s" % bad[:3])

    # in process: every open under run/ happens inside as_service
    import contextlib
    import io
    opened, inside, within = [], [], []
    real_open, real_as = os.open, net.as_service

    def watched_open(path, *a, **k):
        p = os.fspath(path) if not isinstance(path, int) else ""
        if "dir_fd" not in k and os.path.abspath(p).startswith(run):
            (within if inside else opened).append(p)
        return real_open(path, *a, **k)

    def watched_as(sh, fn):
        inside.append(1)
        try:
            return real_as(sh, fn)
        finally:
            inside.pop()
    old_env = os.environ.get("OOMPH_SHARE_DIR")
    os.environ["OOMPH_SHARE_DIR"] = share
    os.open, net.as_service = watched_open, watched_as
    rcs = []
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            for cmd in (["on", "--pair"], ["pair"], ["revoke", "c-00000000"], ["status"], ["networks"], ["reload"],
                        ["ai", "on"], ["off", "--forget"], ["on"], ["purge"]):
                rcs.append(net.cmd_share(cmd))
    finally:
        os.open, net.as_service = real_open, real_as
        if old_env is None:
            os.environ.pop("OOMPH_SHARE_DIR", None)
        else:
            os.environ["OOMPH_SHARE_DIR"] = old_env
    check(not opened and within and rcs[0] == 0 and not os.path.exists(share),
          "the share commands open nothing under run/ outside the service account's step %s %s" % (opened[:3], rcs))


SKEW_TAG = "v1.9.9"   # the release before 1.10.0; both directions over a pipe and ssh (roadmap §4.3, §4.7)


def skew(tmp):
    """Version skew in both directions over the pipe (ssh): this client against the previous
    release's `serve --stdio` behind a fake ssh (add, then sync), and that release's client against
    this `serve --stdio`. The TCP direction follows once 1.10.0 is tagged. Skipped where the tag is
    not in the checkout, except in CI."""
    old = os.path.join(tmp, "skew-old")
    try:
        os.makedirs(old)
        a = subprocess.run(["git", "-C", ROOT, "archive", SKEW_TAG, "daemon"], capture_output=True, timeout=60)
        if a.returncode != 0:
            raise OSError(a.stderr.decode(errors="replace").strip()[-200:])
        subprocess.run(["tar", "-x", "-C", old], input=a.stdout, check=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        if os.environ.get("CI"):
            check(False, "version skew: %s could not be read (%s)" % (SKEW_TAG, e))
        else:
            print("skip  version skew: no %s in this checkout (%s)" % (SKEW_TAG, e))
        return
    old_cli = os.path.join(old, "daemon", "oomph.py")
    fake = os.path.join(tmp, "oldssh")
    with open(fake, "w") as f:
        f.write("#!%s\nimport os\nos.execv(%r, [%r, '-I', '-B', %r, 'serve', '--stdio', '--now', %r])\n"
                % (PY, PY, PY, old_cli, repr(NOW)))
    os.chmod(fake, 0o755)
    viewer = os.path.join(tmp, "skew-viewer")
    env = {"OOMPH_SSH": fake, "OOMPH_STATE_DIR": viewer, "OOMPH_MACHINES_DIR": os.path.join(viewer, "machines")}
    r = cli("remote", "add", "sam@old-mac", "--json", env=env)
    added = json.loads(r.stdout) if r.returncode == 0 else {}
    r2 = cli("remote", "sync", "--once", "--json", env=env)
    check(added.get("ok") and added.get("counts", {}).get("samples", 0) > 0 and r2.returncode == 0,
          "version skew: this client adds and syncs %s's serve --stdio over ssh (%s)"
          % (SKEW_TAG, (r.stderr + r2.stderr).strip()[-200:]))
    into = os.path.join(tmp, "skew-into")
    r = subprocess.run([PY, "-I", "-B", old_cli, "remote", "sync", "--once", "--into", into, "--json", "--",
                        PY, "-I", "-B", OOMPH, "serve", "--stdio", "--now", repr(NOW)], capture_output=True, text=True,
                       timeout=120, env=dict(os.environ, OOMPH_STATE_DIR=os.path.join(tmp, "skew-old-state")))
    got = [n for n in os.listdir(os.path.join(into, "log"))] if os.path.isdir(os.path.join(into, "log")) else []
    check(r.returncode == 0 and any(n.startswith("samples-") for n in got),
          "version skew: %s's client mirrors this serve --stdio (%s)" % (SKEW_TAG, r.stderr.strip()[-200:]))


def main():
    tmp = tempfile.mkdtemp(prefix="oomph-sharetest-")
    os.chmod(tmp, 0o755)
    log, led = make_machine(os.path.join(tmp, "fx"))
    os.environ.update(OOMPH_TEST="1", OOMPH_DIR=log, OOMPH_LEDGER_DIR=led, OOMPH_MACHINES_DIR=os.path.join(tmp, "viewer", "machines"),
                      OOMPH_STATE_DIR=os.path.join(tmp, "viewer"))
    os.environ.pop("OOMPH_SHARE_DIR", None)
    share = os.path.join(tmp, "share")

    # ---------------------------------------------------------------- pure parts
    check(net.norm_code("k7qf-2m9x-d4tr") == "K7QF2M9XD4TR" and net.norm_code("O1IL 0000 0000") == "011100000000"
          and net.norm_code("K7QF2M9XD4T") is None and net.norm_code("K7QF2M9XD4TU") is None,
          "codes: case, dashes, O/0 and I/L/1 normalised; a wrong length or letter refused")
    hostile = ["x'; touch /tmp/p; '", 'a"b', "a`id`", "$(id)", "a\nb", "\x1b[31mred", "‮evil", "x" * 10000, "-lead", ""]
    names = [net.viewer_name(n) for n in hostile]
    check(all(n and len(n) <= 63 and all(c.isalnum() and c.isascii() or c in "._-" for c in n) and n[0].isalnum()
              for n in names) and names[-1] == "viewer", "viewer names keep [A-Za-z0-9._-] only: %s" % names[:4])
    good = ["studio.local", "studio:7000", "sam@atlas", "ssh://atlas:2222", "[fe80::1]:6674", "::1", "10.0.4.23",
            "fe80::1%en0", "[fe80::1%en0]:6674"]
    bad = ["-oProxyCommand=touch /tmp/x", "ssh://-oProxyCommand=x", "a b", "host\nx", "us=er@h", "@h", "h:99999",
           "ssh://h -oX", "", "a" * 400, "-l@h", "sam@fe80::1%en0;id", "ssh://fe80::1%`id`", "fe80::1%$(touch x)",
           "::1%\x01", "fe80::1%en0 x"]

    def ok_target(s):
        try:
            sync.parse_target(s)
            return True
        except ValueError:
            return False
    check(all(map(ok_target, good)) and not any(map(ok_target, bad)),
          "addresses: host[:port], user@host, ssh://, IPv6 accepted; options, spaces, newlines refused")
    t = sync.parse_target("sam@atlas.local")
    argv = sync.ssh_argv(t["host"], t["user"], 2222)
    check(argv[argv.index("--") + 1] == "atlas.local" and argv[argv.index("-l") + 1] == "sam" and "BatchMode=yes" in argv
          and "ForwardAgent=no" in argv and "ControlPath=none" in argv and argv[-1].startswith("exec /bin/sh -c '"),
          "ssh: -l USER, -- before the host, BatchMode, no agent or multiplexing, a constant remote command in sh")
    check([sync.backoff(i, 1.0) for i in range(9)] == [1, 2, 4, 8, 15, 30, 60, 60, 60] and
          all(0.8 * 60 <= sync.backoff(9) <= 1.2 * 60 for _ in range(50)), "backoff: 1 2 4 8 15 30 60 s, ±20 %")

    # ---------------------------------------------------------------- the peer gate (table-driven)
    import ipaddress
    I = net.Iface  # noqa: E741
    ifs = [I("lo0", 0x8 | 0x1, ipaddress.ip_address("127.0.0.1"), 8, 1),
           I("en0", 0x1, ipaddress.ip_address("192.168.1.20"), 24, 4),
           I("en0", 0x1, ipaddress.ip_address("fe80::1:2"), 64, 4),
           I("en0", 0x1, ipaddress.ip_address("2003:ca::20"), 64, 4),
           I("awdl0", 0x1, ipaddress.ip_address("fe80::aa"), 64, 9),
           I("utun3", 0x11, ipaddress.ip_address("100.101.1.2"), 32, 12),
           I("utun3", 0x11, ipaddress.ip_address("fe80::cc"), 64, 12)]
    home = {"if": "en0", "net": "192.168.1.0/24", "router": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}
    cfg = {"on": True, "networks": [home], "allow": []}

    def looked_up(router):
        """What lookup_network finds: the router only for en0's IPv4 address, nothing for IPv6."""
        return lambda i: (dict(router, **{"if": i.name, "net": str(i.net())}) if i.name == "en0" and i.addr.version == 4
                          else {"if": i.name, "net": str(i.net()), "router": None, "mac": None})
    here, other = looked_up(home), looked_up(dict(home, mac="11:22:33:44:55:66"))
    G = net.gate
    cases = [
        (G(("192.168.1.12", 5), ("192.168.1.20", 6674), ifs, cfg, here) is None, "a neighbour on an allowed network passes"),
        (G(("192.168.1.12", 5), ("192.168.1.20", 6674), ifs, cfg, other) is not None, "… not when the router's hardware address differs"),
        (G(("10.0.0.5", 5), ("192.168.1.20", 6674), ifs, cfg, here) is not None, "a routed peer never passes"),
        (G(("::ffff:192.168.1.12", 5, 0, 0), ("::ffff:192.168.1.20", 6674, 0, 0), ifs, cfg, here) is None,
         "an IPv4-mapped peer is judged as the IPv4 address it is"),
        (G(("::ffff:10.0.0.5", 5, 0, 0), ("::ffff:192.168.1.20", 6674, 0, 0), ifs, cfg, here) is not None,
         "… a mapped routed peer is refused"),
        (G(("fe80::5", 5, 0, 4), ("fe80::1:2", 6674, 0, 4), ifs, cfg, here) is None,
         "link-local on en0 passes (judged by en0's IPv4 network)"),
        (G(("fe80::5", 5, 0, 4), ("fe80::1:2", 6674, 0, 4), ifs, cfg, other) is not None, "… not on another network"),
        (G(("2003:ca::5", 5, 0, 0), ("2003:ca::20", 6674, 0, 0), ifs, cfg, here) is None,
         "an IPv6 neighbour on en0's /64 passes"),
        (G(("2003:cb::5", 5, 0, 0), ("2003:ca::20", 6674, 0, 0), ifs, cfg, here) is not None, "… a routed IPv6 peer does not"),
        (G(("fe80::5", 5, 0, 9), ("fe80::aa", 6674, 0, 9), ifs, cfg, here) is not None, "… not on awdl0"),
        (G(("fe80::5", 5, 0, 12), ("fe80::cc", 6674, 0, 12), ifs, cfg, here) is not None, "… not on utun3"),
        (G(("100.64.3.3", 5), ("100.101.1.2", 6674), ifs, cfg, here) is not None, "a tailnet peer needs share allow"),
        (G(("100.64.3.3", 5), ("100.101.1.2", 6674), ifs, dict(cfg, allow=["100.64.0.0/10"]), here) is None, "… and passes with it"),
        (G(("192.168.1.12", 5), ("192.168.1.20", 6674), ifs, {"on": True, "any_network": True}, other) is None,
         "--any-network: a neighbour anywhere passes"),
        (G(("10.0.0.5", 5), ("192.168.1.20", 6674), ifs, {"on": True, "any_network": True}, other) is not None,
         "--any-network: still no routed peer"),
        (G(("192.168.1.12", 5), ("192.168.1.20", 6674), None, cfg, here) is not None and
         G(("127.0.0.1", 5), ("127.0.0.1", 6674), None, cfg, here) is None, "no interface table: loopback only"),
        (net.network_allowed(dict(home, mac=None), [dict(home, mac=None)]) and
         not net.network_allowed(dict(home, mac=None), [home]),
         "a router recorded without its hardware address matches by address and subnet; one recorded with it must show it"),
    ]
    nomac = dict(home, mac=None)
    alias = ifs + [I("en0", 0x1, ipaddress.ip_address("10.9.0.20"), 16, 4)]
    cfg_nomac = {"on": True, "networks": [nomac], "allow": []}
    here_nomac = looked_up(nomac)
    cases += [
        (G(("192.168.1.12", 5), ("192.168.1.20", 6674), alias, cfg_nomac, here_nomac) is None and
         G(("10.9.0.5", 5), ("10.9.0.20", 6674), alias, cfg_nomac, here_nomac) is not None,
         "two IPv4 aliases on one interface: a peer that reached the alias on another subnet is judged by that one"),
    ]
    cable = {"if": "en5", "net": "169.254.0.0/16", "router": None, "mac": None}
    wire = [I("lo0", 0x8 | 0x1, ipaddress.ip_address("127.0.0.1"), 8, 1),
            I("en5", 0x1, ipaddress.ip_address("169.254.3.4"), 16, 7),
            I("en5", 0x1, ipaddress.ip_address("fe80::77"), 64, 7)]
    bare = lambda i: {"if": i.name, "net": str(i.net()), "router": None, "mac": None}  # noqa: E731
    cases += [
        (net.current_networks(wire, bare) == [cable], "a cable without a router (169.254/16 only) is a network "
                                                      "share on records"),
        (net.current_networks(ifs + [I("en0", 0x1, ipaddress.ip_address("169.254.8.8"), 16, 4)], here) == [here(ifs[1])],
         "… a self-assigned address beside a routable one on the same interface is not"),
        (G(("169.254.9.9", 5), ("169.254.3.4", 6674), wire, {"on": True, "networks": [cable]}, bare) is None and
         G(("fe80::5", 5, 0, 7), ("fe80::77", 6674, 0, 7), wire, {"on": True, "networks": [cable]}, bare) is None,
         "… and a peer on that cable passes, by IPv4 and IPv6 link-local"),
        (G(("169.254.9.9", 5), ("169.254.3.4", 6674), wire, cfg, bare) is not None,
         "… a cable sharing was not turned on for does not"),
    ]
    for c, what in cases:
        check(c, "gate: " + what)
    rd = net.RunDir(os.path.join(tmp, "rd-cache"))
    os.makedirs(rd.path)
    calls = []
    real_lookup = net.lookup_network
    net.lookup_network = lambda i: calls.append(i) or dict(home, **{"if": i.name, "net": str(i.net())})
    try:
        a = ifs[1]
        net.network_of(a, rd)
        net.network_of(a, rd)
        net.network_of(I("en0", 0x1, ipaddress.ip_address("10.9.0.20"), 16, 4), rd)
    finally:
        net.lookup_network = real_lookup
    check(len(calls) == 2, "the network cache answers the same interface, address and prefix, and never another (%d lookups)" % len(calls))
    real = net.interfaces()
    check(real is not None and any(str(i.addr) == "127.0.0.1" for i in real), "the interface table reads (getifaddrs)")

    # ---------------------------------------------------------------- pairing, structurally (in process)
    net.PAUSE_S = 0.0
    rd = net.RunDir(os.path.join(tmp, "rd"))
    os.makedirs(rd.path)
    fp = os.urandom(32)
    sess = net.Session(rd, fp, "192.168.1.12")

    def attempt(code, cn=None, sn=None):
        cn, sn = cn or os.urandom(16), sn or os.urandom(16)
        mac = net.proof(net.pair_key(code, sn, cn), b"client", cn, sn, fp)
        before = dict(net.COUNTS)
        r = sess.pair(mac, cn, sn, "a'b")
        return r, net.COUNTS["derive"] - before["derive"], net.COUNTS["pause"] - before["pause"]
    r1 = attempt(net.new_code())
    rd.write("pairing.json", {"code": "AAAABBBBCCCC", "expires": time.time() - 1, "left": 5})
    r2 = attempt("AAAABBBBCCCC")
    rd.write("pairing.json", {"code": "AAAABBBBCCCC", "expires": time.time() + 600, "left": 5})
    r3 = attempt("AAAABBBBCCCD")
    check(r1 == r2 == r3 == (None, 1, 1), "no code, an expired code and a wrong proof: one derivation and one pause each, "
                                         "the same answer (%s %s %s)" % (r1, r2, r3))
    check(rd.pairing()["left"] == 4, "a wrong proof costs one of the code's tries")
    for _ in range(4):
        attempt("AAAABBBBCCCD")
    check(rd.pairing() is None and attempt("AAAABBBBCCCC")[0] is None, "five wrong proofs void the code; the right one then fails")
    rd.write("pairing.json", {"code": "AAAABBBBCCCC", "expires": time.time() + 600, "left": 5})
    ok, _, pauses = attempt("AAAABBBBCCCC")
    kp, cid, token = ok
    cl = rd.clients()
    check(ok and pauses == 0 and len(cl) == 1 and cl[0]["id"] == cid and cl[0]["key"] == net.token_key(token).hex()
          and cl[0]["name"] == "ab" and token.hex() not in json.dumps(cl), "the right code: a client, its key kept, not its token")
    check(attempt("AAAABBBBCCCC")[0] is None, "a used code pairs nobody else")
    summ = rd.read("summary.json")
    check(isinstance(summ, dict) and "AAAABBBBCCCC" not in json.dumps(summ) and cl[0]["key"] not in json.dumps(summ),
          "summary.json carries neither the code nor a key")
    srv_a = net.Server(now=NOW, session=net.Session(rd, fp, "x"))
    srv_b = net.Server(now=NOW, session=net.Session(net.RunDir(os.path.join(tmp, "rd-none")), fp, "x"))
    os.makedirs(srv_b.session.run.path)
    ha = srv_a.handle({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1], "nonce": base64.b64encode(os.urandom(16)).decode()}})
    hb = srv_b.handle({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1], "nonce": base64.b64encode(os.urandom(16)).decode()}})
    strip = lambda h: dict(h["result"], nonce=None)  # noqa: E731
    check(strip(ha) == strip(hb) and "machine" not in ha["result"], "hello over TLS says the same with and without a "
                                                                     "code, and nothing about the machine")
    ses = net.Session(rd, fp, "x")
    cn, sn = os.urandom(16), os.urandom(16)
    key = net.token_key(token)
    good = net.proof(key, b"auth", cn, sn, fp)
    check(ses.auth(cid, good, cn, sn) and not ses.auth(cid, good, cn, os.urandom(16)) and
          not ses.auth("c-00000000", good, cn, sn) and not ses.auth(cid, None, cn, sn),
          "auth: the right proof passes; a replayed one (old nonces), an unknown client and no proof fail")
    check(not ses.revoked(), "a pairing that stands is not revoked")
    kept = rd.read("clients.json")
    with open(os.path.join(rd.path, "clients.json"), "wb") as f:
        f.write(b"[" + b" " * (1 << 20) + b"]")   # there, but past what is read: no answer
    unreadable = ses.revoked() or ses.revoked()
    rd.write("clients.json", kept)
    check(not unreadable and not ses.revoked(), "clients.json that can't be read is no revocation (the viewer would "
                                                "drop its token): looked at again a second later")
    rd.write("clients.json", [])
    check(ses.revoked(), "a pairing removed from clients.json is noticed")
    rdv = net.RunDir(os.path.join(tmp, "rd-viewers"))
    os.makedirs(rdv.path)
    rdv.write("clients.json", [{"id": cid, "name": "x", "key": key.hex()}])
    readers = [subprocess.Popen(["sleep", "30"]) for _ in range(net.MAX_VIEWERS)]
    for q in readers:
        rdv.write("%d.json" % q.pid, {"pid": q.pid, "peer": "10.0.0.1", "state": "authenticated"}, 0o644, "conn")
    mine = net.Conn(rdv, "10.0.0.2")
    cn, sn = os.urandom(16), os.urandom(16)
    full = net.Session(rdv, fp, "10.0.0.2", mine).auth(cid, net.proof(key, b"auth", cn, sn, fp), cn, sn)
    full_state = mine.info["state"]
    psrv = net.Server(now=NOW, session=net.Session(rdv, fp, "x"))
    psrv.handle({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1], "nonce": base64.b64encode(os.urandom(16)).decode()}})
    rdv.write("pairing.json", {"code": "AAAABBBBCCCC", "expires": time.time() + 600, "left": 5})
    pr = psrv.handle({"jsonrpc": "2.0", "id": 2, "method": "pair", "params": {"mac": base64.b64encode(os.urandom(32)).decode()}})
    for q in readers:
        q.kill()
        q.wait()
    mine.close()
    check(full == "busy" and full_state == "handshake" and pr["error"]["code"] == net.ERR["busy"] and rdv.pairing()["left"] == 5,
          "a full house: auth says busy without counting itself a viewer; pairing says busy and costs the code no try")
    if os.geteuid() != 0:
        rdv.write("1.json", {"pid": 1, "peer": "10.0.0.3", "state": "authenticated"}, 0o644, "conn")
        check(not any(c.get("pid") == 1 for c in rdv.conns()) and "1.json" not in rdv.names("conn"),
              "a conn/ entry whose pid now belongs to another account is swept, not counted")
    rdv.write("summary.json", {"v": 1, "clients": [{"id": "c-%08x" % i, "name": "viewer-with-a-long-name-%d" % i,
                                                    "paired": NOW, "last_seen": NOW, "last_addr": "192.168.1.%d" % (i % 250)}
                                                   for i in range(120)], "reading": [], "pairing": {"active": False}}, 0o644)
    cut, whole = net._summary_read(rdv), net._summary_read(rdv, None)
    check(len(net.dumps(cut)) <= 3800 and cut["more"] > 0 and len(cut["clients"]) + cut["more"] == 120 and
          len(whole["clients"]) == 120 and whole["more"] == 0,
          "share status as root: the summary is cut to fit the service account's answer, the rest counted (%d shown)"
          % len(cut["clients"]))

    class FakeLink:
        cn = os.urandom(16)

        def __init__(self, code):
            self.code = code

        def hello_raw(self):
            return {"nonce": base64.b64encode(os.urandom(16)).decode(), "auth": ["token"]}, 0, 0

        def call(self, *a, **k):
            raise net.RPCError(self.code, "x")

    def auth_error(code):
        try:
            sync.tls_auth(FakeLink(code), "c-00000000", os.urandom(32), os.urandom(32))
        except sync.SyncError as e:
            return e.code
    check(auth_error(net.ERR["auth"]) == "revoked" and auth_error(-32603) == "not_oomph" and
          auth_error(net.ERR["busy"]) == "busy", "only a refused proof means revoked; a passing fault there keeps the token")
    a, b = socket.socketpair()
    lk = sync.Link(sock=a)
    for _ in range(300):
        lk.keep({"method": "tick", "params": {"samples": []}}, 1 << 20)
    for _ in range(300):
        lk.keep({"method": "events", "params": {}}, 1 << 20)
    check(lk.note_bytes <= sync.NOTES_KEPT[1] and len(lk.notes) <= sync.NOTES_KEPT[0] + 4 and
          lk.notes[-1] == {"method": "events"}, "notifications kept during a call are bounded by count and bytes; "
                                                 "past that a trigger is kept by name (%d kept)" % len(lk.notes))
    for i in range(20000):
        lk.keep({"method": "x%d" % i}, 10)
    check(len(lk.notes) <= sync.NOTES_KEPT[0] + len(sync.TRIGGERS), "notifications of 20,000 made-up names during a "
                                                                    "call keep nothing (%d kept)" % len(lk.notes))
    lk.close()
    b.close()
    a, b = socket.socketpair()
    lk = sync.Link(sock=a)
    flooding = threading.Event()

    def flood():
        i = 0
        try:
            while not flooding.is_set():
                b.sendall(b'{"jsonrpc":"2.0","method":"n%d","params":{}}\n' % (i % 100000))
                i += 1
                time.sleep(0.001)
        except OSError:
            pass
    threading.Thread(target=flood, daemon=True).start()
    t0 = time.monotonic()
    try:
        lk.call("ping", timeout=0.5)
        why = "answered"
    except sync.SyncError as err:
        why = err.code
    flooding.set()
    check(why == "timeout" and time.monotonic() - t0 < 3, "a server that sends notifications and never the answer: "
                                                          "the call ends at its deadline (%.1f s)" % (time.monotonic() - t0))
    lk.close()
    b.close()
    import oomph_ai
    cutm = os.path.join(os.environ["OOMPH_MACHINES_DIR"], "m-00000000000000aa")
    os.makedirs(os.path.join(cutm, "log"))
    with open(os.path.join(cutm, "machine.json"), "w") as f:
        json.dump({"caps": []}, f)
    elsewhere = os.path.join(tmp, "copied", "log")
    os.makedirs(elsewhere)
    with open(os.path.join(tmp, "copied", "machine.json"), "w") as f:
        json.dump({"caps": []}, f)
    check(oomph_ai.remote_refusal(os.path.join(cutm, "log")) and oomph_ai.remote_refusal(elsewhere),
          "AI analysis fails closed: a mirror without sync.json yet (its first catch-up cut off), or copied elsewhere")
    srv = net.Server(now=NOW, session=net.Session(rd, fp, "x"))
    rng = random.Random(7)
    crashed = 0
    for i in range(3000):
        m = rng.choice(["hello", "pair", "auth", "samples", "ledger", "ping", "unpair", "nosuch", 5, None])
        p = rng.choice([{}, {"mac": "x" * rng.randint(0, 100)}, {"nonce": base64.b64encode(os.urandom(rng.choice([16, 3]))).decode(),
                        "proto": [1, 1]}, {"client": "c-12345678", "mac": base64.b64encode(os.urandom(32)).decode()},
                        [1], "x", {"proto": [1, 1]}, {"name": "\x00" * 50, "mac": base64.b64encode(os.urandom(32)).decode()}])
        try:
            r = srv.handle({"jsonrpc": "2.0", "id": i, "method": m, "params": p})
            if r is not None and "result" in r and m in ("samples", "ledger", "ping"):
                crashed += 1  # data before authentication
        except Exception:
            crashed += 1
    check(crashed == 0 and not srv.open, "3,000 random frames over TLS: errors by the book, no data, never open")
    srv = net.Server(now=NOW, session=net.Session(rd, fp, "x"))
    srv.handle({"jsonrpc": "2.0", "id": 1, "method": "hello", "params": {"proto": [1, 1], "nonce": base64.b64encode(os.urandom(16)).decode()}})
    first = srv.handle({"jsonrpc": "2.0", "id": 2, "method": "pair", "params": {"mac": base64.b64encode(os.urandom(32)).decode()}})
    second = srv.handle({"jsonrpc": "2.0", "id": 3, "method": "pair", "params": {"mac": base64.b64encode(os.urandom(32)).decode()}})
    check(first["error"]["code"] == net.ERR["pair"] and second["error"]["code"] == net.ERR["unauth"],
          "one proof per hello: a second try on the same nonces is not even looked at")

    # ---------------------------------------------------------------- the share commands, scratch directory
    env = {"OOMPH_SHARE_DIR": share}
    r = cli("share", "pair", env={"OOMPH_SHARE_DIR": ""})
    r2 = cli("share", "on", "--pair", env={"OOMPH_SHARE_DIR": share, "OOMPH_TEST": ""})
    check(r.returncode == 1 and "administrator" in r.stderr and r2.returncode == 1 and "administrator" in r2.stderr
          and not os.path.exists(share), "share pair needs an administrator; the test directory only with OOMPH_TEST=1")
    r = cli("share", "on", "--pair", "--json", env=env)
    code = json.loads(r.stdout.strip().splitlines()[-1])["code"] if r.returncode == 0 else ""
    check(r.returncode == 0 and net.norm_code(code), "share on --pair (scratch): sharing on and a code (%s)" % r.stderr.strip()[-200:])
    try:
        lo_only = cli("serve", "--listen", "0.0.0.0:0", env=env, timeout=10).returncode == 1
    except subprocess.TimeoutExpired:
        lo_only = False
    check(lo_only, "a test share directory never listens beyond loopback")
    check(stat.S_IMODE(os.stat(os.path.join(share, "key.pem")).st_mode) == 0o600 and
          "CN" in subprocess.run(["/usr/bin/openssl", "x509", "-noout", "-subject", "-in", os.path.join(share, "cert.pem")],
                                 capture_output=True, text=True).stdout and "oomph" in
          subprocess.run(["/usr/bin/openssl", "x509", "-noout", "-subject", "-in", os.path.join(share, "cert.pem")],
                         capture_output=True, text=True).stdout, "the key is nobody else's; the certificate says CN=oomph")
    for bad_id in ["x'; touch /tmp/p; '", "$(id)", "c-1234567", "c-1234567g", "studio"]:
        r = cli("share", "revoke", bad_id, env=env)
        if r.returncode != 2 or bad_id in r.stderr or bad_id in r.stdout:
            break
    check(r.returncode == 2 and bad_id not in r.stderr, "share revoke refuses anything but an id, without echoing it")
    srv = Listener(share)
    check(srv.port is not None, "serve --listen 127.0.0.1:0 listens")
    probe = socket.create_connection(("127.0.0.1", srv.port))

    def conn_procs():
        ps = subprocess.run(["ps", "-axo", "ppid=,args="], capture_output=True, text=True).stdout.splitlines()
        return [x for x in ps if x.split(None, 1)[0] == str(srv.p.pid) and "serve --inetd --now" in x]
    fresh = wait_for(conn_procs, 10)
    probe.close()
    check(fresh, "… and serves each connection in a fresh `serve --inetd`, as launchd does (a bare fork reads the "
                 "time zone file at every localtime() on macOS)")

    def slow_service(delay):
        """A listener whose one connection is closed `delay` s after it came (None: kept open)."""
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        held = []

        def run():
            c, _ = ls.accept()
            held.append(c)
            if delay is not None:
                time.sleep(delay)
                c.close()
        threading.Thread(target=run, daemon=True).start()
        return ls, held
    ls, held = slow_service(1.0)
    t0 = time.monotonic()
    started = net.warm_service(ls.getsockname()[1], 10)
    took = time.monotonic() - t0
    ls2, held2 = slow_service(None)
    t1 = time.monotonic()
    stuck = net.warm_service(ls2.getsockname()[1], 1.0)
    gave_up = time.monotonic() - t1
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    t2 = time.monotonic()
    nobody = net.warm_service(free.getsockname()[1], 1.0)
    check(started is True and 0.9 <= took < 5 and stuck is False and gave_up < 3 and nobody is False and
          time.monotonic() - t2 < 3, "share on waits for the service's first start: until it closes (%.1f s), at "
                                     "most as long as it may (%.1f s); nothing listening: also only that long"
          % (took, gave_up))
    for x in [ls, ls2, free] + held + held2:
        x.close()
    r = cli("remote", "add", "127.0.0.1:%d" % srv.port, "--json", env=env)
    check(r.returncode == 1 and json.loads(r.stdout)["error"] == "needs_code", "a new machine without a code: needs_code")
    t0 = time.time()
    r = cli("remote", "add", "127.0.0.1:%d" % srv.port, "--code", "ZZZZ-ZZZZ-ZZZZ", "--json", env=env)
    check(r.returncode == 1 and json.loads(r.stdout)["error"] == "pair_failed" and time.time() - t0 >= 1.0,
          "a wrong code: pair_failed, after the pause")
    t0 = time.time()
    r = cli("remote", "add", "127.0.0.1:%d" % srv.port, "--code", code.lower(), "--name", "studio", "--json", env=env)
    res = json.loads(r.stdout) if r.stdout.strip() else {}
    check(r.returncode == 0 and res.get("ok") and res["counts"]["samples"] > 1000 and time.time() - t0 < 30,
          "remote add with the code: paired, %s samples mirrored in %.1f s, under 30 (%s)"
          % (res.get("counts", {}).get("samples"), time.time() - t0, r.stderr.strip()[-200:]))
    mbase = os.environ["OOMPH_MACHINES_DIR"]
    book = sync.Book()
    e = book.find("studio")
    secrets_path = os.path.join(mbase, "secrets.json")
    tok = book.secrets.get(e["mid"], {}).get("token") if e else None
    check(e and e["fp"] and tok and tok not in open(os.path.join(mbase, "machines.json")).read() and
          stat.S_IMODE(os.stat(secrets_path).st_mode) == 0o600 and stat.S_IMODE(os.stat(mbase).st_mode) == 0o700,
          "the token is in secrets.json (600, in a 700 folder), not in machines.json")
    r = cli("share", "status", "--json", env=env)
    st = json.loads(r.stdout)
    check(st["on"] and len(st["clients"]) == 1 and tok not in r.stdout and "key" not in json.dumps(st["clients"]) and
          not st["pairing"]["active"], "share status: the viewer listed, no secret, the code used up")
    r = cli("remote", "sync", "--once", "studio", "--json")
    check(r.returncode == 0 and json.loads(r.stdout)["ok"], "remote sync --once: authenticates with the token")
    mj = json.load(open(os.path.join(mbase, e["mid"], "machine.json")))
    check("ai" not in mj.get("caps", []), "AI analysis is not allowed by default (no `ai` in caps)")
    mlog = os.path.join(mbase, e["mid"], "log")
    r = cli("ai-report", "--provider", "ollama", "--base-url", "http://127.0.0.1:9", env={"OOMPH_DIR": mlog})
    check(r.returncode == 3 and "does not allow AI analysis" in r.stdout + r.stderr,
          "ai-report on another machine's mirror is refused while it does not allow it")
    cli("share", "ai", "on", env=env)
    cli("remote", "sync", "--once", "studio")
    mj = json.load(open(os.path.join(mbase, e["mid"], "machine.json")))
    rl = json.loads(cli("remote", "list", "--json").stdout)["machines"][0]
    check("ai" in mj.get("caps", []) and rl["ai_allowed"] is True, "share ai on: the machine allows it, the viewer sees that")
    import oomph_ai
    check(oomph_ai.remote_refusal(mlog) is None and oomph_ai.remote_refusal(log) is None,
          "… then its mirror may go to a model; this machine's own logs always may")
    stp = os.path.join(mbase, e["mid"], "status.json")
    fresh = json.load(open(stp))
    json.dump(dict(fresh, last_contact=time.time() - 2 * 86400), open(stp, "w"))
    stale_ai = oomph_ai.remote_refusal(mlog)
    json.dump(fresh, open(stp, "w"))
    check(stale_ai and "more than a day" in stale_ai, "… but only while it was reached within a day: an older consent "
                                                      "may have been withdrawn there")
    cli("share", "ai", "off", env=env)

    # live: an appended sample arrives, revoke ends the session
    sh = net.ShareDir(share)
    sh.test, sh.owner = True, os.geteuid()
    day = [n for n in sorted(os.listdir(log)) if n.startswith("samples-") and n.endswith(".jsonl")][-1]
    p = subprocess.Popen([PY, "-I", "-B", OOMPH, "remote", "sync", "--json"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=dict(os.environ, OOMPH_ENGINE_IDLE_S="1"))
    evs = []
    stop_reader = threading.Event()

    def reader():
        for line in p.stdout:
            evs.append(json.loads(line))
            if stop_reader.is_set():
                break
    th = threading.Thread(target=reader, daemon=True)
    th.start()
    p.stdin.write((json.dumps({"cmd": "watch", "ids": [e["mid"]], "focus": e["mid"]}) + "\n").encode())
    p.stdin.flush()
    live = wait_for(lambda: any(x.get("ev") == "state" and x.get("state") == "live" for x in evs), 20)
    check(live, "the engine: connecting, catching up, live")
    mark = len(evs)
    with open(os.path.join(log, day), "a") as f:
        f.write(json.dumps({"t": NOW + 5, "app_gb": 9.5, "wired_gb": 3.0, "compressed_gb": 1.0, "swap_used_gb": 0.0,
                            "pressure": 1, "ram_gb": 36.0}) + "\n")

    def in_mirror():
        d = os.path.join(mbase, e["mid"], "log")
        return any(b'"t":%s' % repr(NOW + 5).encode() in open(os.path.join(d, n), "rb").read()
                   for n in os.listdir(d) if n.endswith(".jsonl"))
    got = wait_for(lambda: any(x.get("ev") == "changed" and "samples" in x.get("what", []) for x in evs[mark:]), 10)
    mirrored = wait_for(in_mirror, 5)
    check(got and mirrored, "a sample appended there arrives live (a tick) and is in the mirror")
    stj = json.load(open(os.path.join(mbase, e["mid"], "status.json")))
    check(stj["state"] == "live" and time.time() - stj["updated"] < 10 and stj["pid"], "status.json: live, fresh, a live pid")
    mark = len(evs)
    cli("share", "ai", "on", env=env)
    told = wait_for(lambda: any(x.get("ev") == "changed" and "machine" in x.get("what", []) for x in evs[mark:]), 5)
    mj = json.load(open(os.path.join(mbase, e["mid"], "machine.json")))
    check(told and "ai" in mj["caps"] and "ai" in sync.Book().get(e["mid"])["caps"],
          "share ai on during a live session: the viewer is told within seconds (machine.json and machines.json)")
    mark = len(evs)
    cli("share", "ai", "off", env=env)
    told = wait_for(lambda: any(x.get("ev") == "changed" and "machine" in x.get("what", []) for x in evs[mark:]), 5)
    check(told and "ai" not in json.load(open(os.path.join(mbase, e["mid"], "machine.json")))["caps"] and
          "ai" not in sync.Book().get(e["mid"])["caps"], "share ai off during a live session: withdrawn at once")
    cid = json.loads(cli("share", "status", "--json", env=env).stdout)["clients"][0]["id"]
    t0 = time.time()
    r = cli("share", "revoke", cid, env=env)
    gone = wait_for(lambda: any(x.get("ev") == "state" and x.get("error") == "revoked" for x in evs), 10)
    check(r.returncode == 0 and gone, "share revoke ends the live connection (%.1f s) and the viewer needs attention"
          % (time.time() - t0))
    check(sync.Book().secrets.get(e["mid"]) is None, "… and the viewer drops the token")
    p.stdin.write(b'{"cmd":"idle"}\n')
    p.stdin.flush()
    try:
        p.wait(10)
    except subprocess.TimeoutExpired:
        p.kill()
    stop_reader.set()
    stj = json.load(open(os.path.join(mbase, e["mid"], "status.json")))
    check(p.returncode == 0 and stj["state"] == "idle" and stj["was"] == "needs_attention",
          "idle: the engine exits after its minute (here 1 s); status.json keeps what the link was")

    # pair again, then the key changes
    code = json.loads(cli("share", "pair", "--json", env=env).stdout)["code"]
    r = cli("remote", "add", "127.0.0.1:%d" % srv.port, "--code", code, "--json", env=env)
    check(r.returncode == 0 and json.loads(r.stdout)["machine"]["mid"] == e["mid"], "pairing the same machine again "
                                                                                    "keeps its tab and mirror")
    srv.stop()
    cli("share", "off", "--forget", env=env)
    code = json.loads(cli("share", "on", "--pair", "--json", env=env).stdout.strip().splitlines()[-1])["code"]
    srv = Listener(share)
    old = sync.Book().get(e["mid"])
    with sync.Book().locked() as b:
        b.get(e["mid"])["port"] = srv.port
        b.save()
    r = cli("remote", "sync", "--once", "studio", "--json")
    m = json.loads(r.stdout)["machines"][0]
    check(r.returncode == 1 and m["error"] == "identity_changed", "a changed key: identity_changed, nothing sent")
    r = cli("remote", "add", "127.0.0.1:%d" % srv.port, "--code", code, "--json", env=env)
    paired = json.loads(cli("share", "status", "--json", env=env).stdout)["clients"]
    check(r.returncode == 1 and json.loads(r.stdout)["error"] == "ask" and not paired and
          "new one" in json.loads(r.stdout)["detail"], "the same machine id with another key is a question; the "
                                                       "pairing it just made is given back there (%d left)" % len(paired))
    code = json.loads(cli("share", "pair", "--json", env=env).stdout)["code"]
    r = cli("remote", "add", "127.0.0.1:%d" % srv.port, "--code", code, "--as", "new", "--json", env=env)
    mids = [x["mid"] for x in sync.Book().machines]
    check(r.returncode == 0 and len(mids) == 2 and old["fp"] == sync.Book().get(e["mid"])["fp"],
          "--as new: two tabs, two mirrors; the first machine's pin untouched (%s)" % mids)
    new_mid = [x for x in mids if x != e["mid"]][0]

    # a machine in the middle: its own certificate, relaying lines
    mitm_dir = os.path.join(tmp, "mitm")
    os.makedirs(mitm_dir)
    subprocess.run(["/usr/bin/openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout", "-out", mitm_dir + "/k"],
                   capture_output=True)
    subprocess.run(["/usr/bin/openssl", "req", "-new", "-x509", "-days", "1", "-subj", "/CN=oomph", "-key", mitm_dir + "/k",
                    "-out", mitm_dir + "/c"], capture_output=True)
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(4)
    mport = lsock.getsockname()[1]

    def mitm():
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(mitm_dir + "/c", mitm_dir + "/k")
        for _ in range(2):
            try:
                c, _ = lsock.accept()
                a = ctx.wrap_socket(c, server_side=True)
                b = net.client_context().wrap_socket(socket.create_connection(("127.0.0.1", srv.port)))
            except OSError:
                continue

            def relay(a, b):
                """Both directions in one thread (an SSLSocket is not to be read and closed from two)."""
                try:
                    while True:
                        ready = [x for x in (a, b) if x.pending()] or select.select([a, b], [], [], 30)[0]
                        if not ready:
                            break
                        for x in ready:
                            d = x.recv(65536)
                            if not d:
                                raise OSError("closed")
                            (b if x is a else a).sendall(d)
                except (OSError, ValueError):
                    pass
                for x in (a, b):
                    try:
                        x.close()
                    except OSError:
                        pass
            threading.Thread(target=relay, args=(a, b), daemon=True).start()
    threading.Thread(target=mitm, daemon=True).start()
    code = json.loads(cli("share", "pair", "--json", env=env).stdout)["code"]
    before = len(json.loads(cli("share", "status", "--json", env=env).stdout)["clients"])
    r = cli("remote", "add", "127.0.0.1:%d" % mport, "--code", code, "--as", "new", "--json", env=env)
    after = len(json.loads(cli("share", "status", "--json", env=env).stdout)["clients"])
    check(r.returncode == 1 and json.loads(r.stdout)["error"] == "pair_failed" and after == before,
          "a machine in the middle: pairing fails on both ends, no client is made (%s %s %s %s)" % (r.returncode, r.stdout[-300:], before, after))
    with sync.Book().locked() as b:
        b.get(new_mid)["port"] = mport
        b.save()
    r = cli("remote", "sync", "--once", new_mid, "--json")
    check(r.returncode == 1 and json.loads(r.stdout)["machines"][0]["error"] == "identity_changed",
          "a machine in the middle later: the pin refuses it")
    lsock.close()

    # TLS: the protocol floor and the suites; a key others can read is refused
    with sync.Book().locked() as b:
        b.get(new_mid)["port"] = srv.port
        b.save()
    import warnings
    warnings.simplefilter("ignore", DeprecationWarning)  # TLS 1.1 is old: that is the point
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_1
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        ctx.wrap_socket(socket.create_connection(("127.0.0.1", srv.port), timeout=5)).close()
        old_ok = True
    except (ssl.SSLError, OSError):
        old_ok = False
    tls = net.client_context().wrap_socket(socket.create_connection(("127.0.0.1", srv.port), timeout=5))
    suite = tls.cipher()
    tls.close()
    check(not old_ok and (suite[1] == "TLSv1.3" or suite[0] in net.CIPHERS.split(":")),
          "TLS: nothing below 1.2; an AEAD suite with forward secrecy (%s, %s)" % (suite[0], suite[1]))
    os.chmod(os.path.join(share, "key.pem"), 0o644)
    r = cli("remote", "sync", "--once", new_mid, "--json")
    os.chmod(os.path.join(share, "key.pem"), 0o600)
    check(r.returncode == 1 and json.loads(r.stdout)["machines"][0]["error"] == "turned_away",
          "a key others can read: serve speaks no TLS")
    tls = net.client_context().wrap_socket(socket.create_connection(("127.0.0.1", srv.port), timeout=5))
    tls.sendall(b"[" * 5000 + b"\n")
    tls.settimeout(5)
    data = b""
    try:
        while True:
            d = tls.recv(4096)
            if not d:
                break
            data += d
    except OSError:
        pass
    check(b"too_large" in data, "a line over 4 KB before authentication ends the connection")

    # in process: a refused peer's bytes are never read; a silent client is dropped at the deadline
    sh2 = net.ShareDir(share)
    sh2.test, sh2.owner = True, os.geteuid()
    entered = []
    real_ctx = net.server_context
    net.server_context = lambda s: entered.append(1) or real_ctx(s)

    def pair_sockets():
        ls = socket.socket()
        ls.bind(("127.0.0.1", 0))
        ls.listen(1)
        c = socket.create_connection(ls.getsockname())
        s, _ = ls.accept()
        ls.close()
        return c, s
    c, s = pair_sockets()
    c.sendall(b"\x16\x03\x01\x00\x05hello")
    rc = net.serve_connection(s, sh2, NOW, gate_fn=lambda *a: "routed")
    c.settimeout(2)
    try:
        closed = c.recv(10) == b""
    except OSError:
        closed = True
    check(rc == 0 and not entered and closed, "a refused peer: closed, and the TLS layer never entered")
    net.HANDSHAKE_S = 1.5
    c, s = pair_sockets()
    t0 = time.monotonic()
    th = threading.Thread(target=net.serve_connection, args=(s, sh2, NOW), kwargs={"gate_fn": lambda *a: None})
    th.start()
    th.join(10)
    check(not th.is_alive() and time.monotonic() - t0 < 4 and entered, "a client that says nothing is dropped at the "
                                                                        "handshake deadline (%.1f s)" % (time.monotonic() - t0))
    net.server_context, net.HANDSHAKE_S = real_ctx, 10
    c.close()
    sleepers = [subprocess.Popen(["sleep", "30"]) for _ in range(4)]
    rdc = net.RunDir(os.path.join(tmp, "rd-caps"))
    os.makedirs(rdc.path)
    for i, q in enumerate(sleepers):
        rdc.write("%d.json" % q.pid, {"pid": q.pid, "peer": "10.0.0.%d" % (1 if i < 3 else 9), "state": "handshake"}, 0o644, "conn")
    me = net.Conn(rdc, "10.0.0.7")
    four = not net.admit(rdc, me)
    sleepers[3].kill()
    sleepers[3].wait()
    me.close()
    me = net.Conn(rdc, "10.0.0.1")
    three_same = not net.admit(rdc, me)
    me.close()
    me = net.Conn(rdc, "10.0.0.2")
    other_ok = net.admit(rdc, me)
    for q in sleepers:
        q.kill()
        q.wait()
    check(four and three_same and other_ok, "caps: a fifth in the handshake and a fourth from one address are turned away")

    # serve --inetd: the connection on fd 0 and 1, as launchd hands it over
    ls = socket.socket()
    ls.bind(("127.0.0.1", 0))
    ls.listen(1)
    c = socket.create_connection(ls.getsockname())
    s, _ = ls.accept()
    q = subprocess.Popen([PY, "-I", "-B", OOMPH, "serve", "--inetd"], stdin=s, stdout=s, stderr=subprocess.PIPE,
                         env=dict(os.environ, OOMPH_SHARE_DIR=share))
    s.close()
    ls.close()
    code = json.loads(cli("share", "pair", "--json", env=env).stdout)["code"]
    try:
        tls, fpx = sync.tls_wrap(c)
        link = sync.Link(sock=tls)
        machine, client, token = sync.tls_pair(link, fpx, net.norm_code(code), "inetd-test")
        link.close()
        inetd_ok = machine.get("id") == "m-0123456789abcdef"
    except sync.SyncError as err:
        inetd_ok = False
        print("   ", err.detail)
    q.wait(10)
    check(inetd_ok and q.returncode == 0 and not q.stderr.read(), "serve --inetd: TLS on the inherited socket, a pairing, "
                                                                 "nothing on stderr")
    # a viewer that keeps talking still meets its revocation
    code = json.loads(cli("share", "pair", "--json", env=env).stdout)["code"]
    away = socket.socket(socket.AF_INET6)
    turned = []
    try:
        away.bind(("::1", srv.port))
        away.listen(4)

        def turn_away():
            try:
                while True:
                    x, _ = away.accept()
                    turned.append(1)
                    x.close()
            except OSError:
                pass
        threading.Thread(target=turn_away, daemon=True).start()
        addrs = ["::1"]
    except OSError:
        addrs = []
    bye, dt = None, None
    try:
        tls, fpx, reached = sync.tls_connect("127.0.0.1", srv.port, addrs)
        link = sync.Link(sock=tls)
        _, pinger, _ = sync.tls_pair(link, fpx, net.norm_code(code), "pinger")
        check(reached == "127.0.0.1" and (turned or not addrs), "an address that accepts and closes (turned away) is "
                                                                "passed over for the next one")
        cli("share", "revoke", pinger, env=env)
        t0 = time.monotonic()
        try:
            while time.monotonic() - t0 < 6 and bye is None:
                link.send("ping")
                end = time.monotonic() + 0.3
                while time.monotonic() < end and bye is None:
                    n = link.note(max(0.01, end - time.monotonic()))
                    if n and n.get("method") == "bye":
                        bye = (n.get("params") or {}).get("reason")
        except sync.SyncError:
            bye = bye or "closed"
        dt = time.monotonic() - t0
        link.close()
    except sync.SyncError as err:
        print("   ", err.detail)
    away.close()
    check(bye == "revoked" and dt is not None and dt < 2.5, "a viewer that pings every 0.3 s is cut off within seconds of "
                                                            "share revoke (%s after %.1f s)" % (bye, dt or -1))
    # share ai and share off reach a session that is already open
    code = json.loads(cli("share", "pair", "--json", env=env).stdout)["code"]
    notes, dt = [], None
    try:
        tls, fpx, _ = sync.tls_connect("127.0.0.1", srv.port)
        link = sync.Link(sock=tls)
        sync.tls_pair(link, fpx, net.norm_code(code), "watcher")
        link.call("subscribe", {"streams": list(net.STREAMS)})

        def until(pred, secs):
            end = time.monotonic() + secs
            while time.monotonic() < end:
                n = link.note(0.2)
                if n:
                    notes.append(n)
                    if pred(n):
                        return n
            return None
        cli("share", "ai", "on", env=env)
        caps = until(lambda n: n.get("method") == "machine", 4)
        cli("share", "ai", "off", env=env)
        t0 = time.monotonic()
        cli("share", "off", env=env)
        try:
            off = until(lambda n: n.get("method") == "bye", 4)
        except sync.SyncError:
            off = None
        dt = time.monotonic() - t0
        link.close()
    except sync.SyncError as err:
        print("   ", err.detail)
        caps = off = None
    check(caps is not None and "ai" in caps["params"]["caps"], "share ai on reaches an open session as a `machine` "
                                                               "notification")
    check(off is not None and off["params"]["reason"] == "off" and dt is not None and dt < 3,
          "share off ends a session that is already open: bye {reason: off} (%.1f s)" % (dt or -1))
    cli("share", "on", env=env)
    srv.stop()

    # ---------------------------------------------------------------- ssh, through a fake ssh
    fake = os.path.join(tmp, "fakessh")
    argv_log = os.path.join(tmp, "ssh-argv.json")
    with open(fake, "w") as f:
        f.write("#!%s\nimport json, os, sys\nmode = os.environ.get('FAKESSH', 'ok')\n"
                "json.dump(sys.argv, open(%r, 'w'))\n"
                "if mode == 'denied':\n    sys.stderr.write('sam@atlas: Permission denied (publickey).\\x1b[31m\\n'); sys.exit(255)\n"
                "if mode == 'missing':\n    sys.exit(127)\n"
                "print('Welcome to atlas'); sys.stdout.flush()\n"
                "os.execv(%r, [%r, '-I', '-B', %r, 'serve', '--stdio', '--now', %r])\n" % (PY, argv_log, PY, PY, OOMPH, repr(NOW)))
    os.chmod(fake, 0o755)
    senv = {"OOMPH_SSH": fake}
    r = cli("remote", "add", "sam@atlas", "--json", env=senv)
    check(r.returncode == 1 and json.loads(r.stdout)["error"] == "ask", "ssh to a machine known over TCP: a question first")
    r = cli("remote", "add", "sam@atlas", "--as", "new", "--name", "atlas", "--json", env=senv)
    rec = json.load(open(argv_log))
    check(r.returncode == 0 and rec[rec.index("--") + 1] == "atlas" and rec[rec.index("-l") + 1] == "sam",
          "remote add sam@atlas over ssh: a banner skipped, mirrored; -l sam and -- before the host")
    os.unlink(argv_log)
    r = cli("remote", "add", "ssh://-oProxyCommand=touch", "--json", env=senv)
    check(r.returncode == 1 and not os.path.exists(argv_log), "a hostile ssh address is refused before ssh starts")
    r = cli("remote", "add", "sam@other", "--json", env=dict(senv, FAKESSH="denied"))
    res = json.loads(r.stdout)
    check(res["error"] == "ssh" and "Permission denied" in res["detail"] and "\x1b" not in res["detail"],
          "ssh can't sign in: needs attention, ssh's own line quoted clean")
    r = cli("remote", "add", "sam@bare", "--json", env=dict(senv, FAKESSH="missing"))
    check(json.loads(r.stdout)["error"] == "not_oomph" and "not installed" in json.loads(r.stdout)["detail"],
          "no oomph there: says it is not installed")

    # ---------------------------------------------------------------- two engines
    atlas = sync.Book().find("atlas")["mid"]

    def engine():
        q = subprocess.Popen([PY, "-I", "-B", OOMPH, "remote", "sync", "--json"], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=tempfile.TemporaryFile(), env=dict(os.environ, **senv))
        out = []
        threading.Thread(target=lambda: [out.append(json.loads(x)) for x in q.stdout], daemon=True).start()
        q.stdin.write((json.dumps({"cmd": "watch", "ids": [atlas]}) + "\n").encode())
        q.stdin.flush()
        return q, out
    a, aout = engine()
    live_a = wait_for(lambda: any(x.get("state") == "live" and x.get("id") == atlas for x in aout), 20)
    b, bout = engine()
    follows = wait_for(lambda: any(x.get("id") == atlas and x.get("ev") == "state" for x in bout), 10)
    check(live_a and follows and os.path.exists(os.path.join(mbase, "viewers", "%d.json" % b.pid)),
          "a second engine follows: it reads the states and writes its wish")
    a.kill()
    a.wait()
    t0 = time.monotonic()
    took = wait_for(lambda: any(x.get("state") == "catching_up" and x.get("id") == atlas for x in bout), 15)
    check(took, "when the engine dies, the follower takes over and connects (%.1f s)" % (time.monotonic() - t0))
    t0 = time.monotonic()
    b.stdin.write(b'{"cmd":"quit"}\n')
    b.stdin.flush()
    try:
        b.wait(20)
        quit_ok = True
    except subprocess.TimeoutExpired:
        quit_ok = False
        print(subprocess.run(["ps", "-o", "pid,ppid,stat,etime,command", "-ax"], capture_output=True, text=True).stdout[-3000:])
        b.kill()
        b.wait()
    check(quit_ok, "quit: the engine stops its links and leaves (%.1f s)" % (time.monotonic() - t0))

    # rename, remove
    r = cli("remote", "rename", "atlas", "Atlas box")
    row = [x for x in json.loads(cli("remote", "list", "--json").stdout)["machines"] if x["mid"] == atlas][0]
    r2 = cli("remote", "rename", "Atlas box", "")
    row2 = [x for x in json.loads(cli("remote", "list", "--json").stdout)["machines"] if x["mid"] == atlas][0]
    check(r.returncode == 0 and row["label"] == "Atlas box" and r2.returncode == 0 and row2["label"] is None,
          "remote rename: the label shows in remote list; an empty one clears it")
    r = cli("remote", "remove", "atlas")
    ent = sync.Book().get(atlas)
    check(r.returncode == 0 and ent and ent["pinned"] is False and os.path.isdir(os.path.join(mbase, atlas)),
          "remote remove: no longer watched, kept as a recent one with its mirror")

    # forget
    r = cli("remote", "forget", "atlas")
    check(r.returncode == 0 and sync.Book().get(atlas) is None and not os.path.exists(os.path.join(mbase, atlas)),
          "remote forget: the entry, the token and the mirror are gone")

    planted(tmp, log, led)
    skew(tmp)
    shutil.rmtree(tmp, ignore_errors=True)
    print("\n%s" % ("FAILED (%d)" % len(failures) if failures else "all sharing checks passed"))
    return 1 if failures else 0


if __name__ == "__main__":
    signal.alarm(600)
    sys.exit(run_root() if sys.argv[1:] == ["root"] else main())
