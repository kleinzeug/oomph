"""Upgrading oomph from its GitHub repository: check, changelog, build.

    oomph upgrade tools [--json]      are git, swiftc, the macOS SDK and codesign available?
    oomph upgrade check [--json]      fetch main; is there a newer version than this one?
    oomph upgrade log [--json]        the changelog of main (each commit is a release)
    oomph upgrade build [--out DIR]   build the newest main into DIR (progress as JSON lines)

The source lives in ~/Library/Application Support/oomph/src: a clone with the full history,
so `git describe` versions and the whole changelog are available. Every commit on main is a
release; versions come from `git describe` over `v*` tags (tools/version.sh). Building runs
the repository's own build-app.sh into a staging folder; the menu-bar app swaps the result
in and relaunches. Nothing here needs root; the logger update after an upgrade is the app's
existing Update step. OOMPH_REPO overrides the repository URL (tests use a local one).
"""
import json
import os
import re
import shutil
import subprocess
import sys
import time

import oomph

REPO = os.environ.get("OOMPH_REPO", "https://github.com/kleinzeug/oomph.git")
BASE = os.environ.get("OOMPH_UPGRADE_DIR", oomph.STATE_DIR)  # the path table's state folder
SRC = os.path.join(BASE, "src")
STAGING = os.path.join(BASE, "staging")


class UpgradeError(Exception):
    pass


def _run(cmd, cwd=None, timeout=120, check=True):
    try:
        r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout,
                           env=dict(os.environ, GIT_TERMINAL_PROMPT="0"))
    except subprocess.TimeoutExpired:
        raise UpgradeError("%s timed out" % cmd[0])
    if check and r.returncode != 0:
        raise UpgradeError((r.stderr or r.stdout).strip().splitlines()[-1] if (r.stderr or r.stdout).strip()
                           else "%s failed (%d)" % (" ".join(cmd[:3]), r.returncode))
    return r.stdout.strip()


# ------------------------------------------------------------------ tools
def tools():
    """What a build needs. Checked through xcode-select/xcrun first: running /usr/bin/git or
    swiftc without the Command Line Tools would pop Apple's install dialog."""
    found, missing = {}, []
    devdir = _run(["/usr/bin/xcode-select", "-p"], check=False, timeout=10)
    if not devdir or not os.path.isdir(devdir):
        return {"ok": False, "missing": ["Xcode Command Line Tools"], "hint": "xcode-select --install"}
    for name in ("git", "swiftc"):
        p = _run(["/usr/bin/xcrun", "--find", name], check=False, timeout=20)
        (found.__setitem__(name, p) if p and os.path.exists(p) else missing.append(name))
    sdk = _run(["/usr/bin/xcrun", "--show-sdk-path"], check=False, timeout=20)
    if sdk and os.path.isdir(os.path.join(sdk, "System/Library/Frameworks/SwiftUI.framework")):
        found["sdk"] = sdk
    else:
        missing.append("macOS SDK with SwiftUI")
    for name, path in (("codesign", "/usr/bin/codesign"), ("plutil", "/usr/bin/plutil")):
        (found.__setitem__(name, path) if os.path.exists(path) else missing.append(name))
    return {"ok": not missing, "found": found, "missing": missing,
            "hint": "" if not missing else "xcode-select --install"}


def git(*args, timeout=120, check=True):
    return _run(["/usr/bin/xcrun", "git", "-C", SRC] + list(args), timeout=timeout, check=check)


# ------------------------------------------------------------------ versions
def parse_version(v):
    """'1.5.0-3-gabc1234-dirty' -> (1, 5, 0, 3); unknown -> (0, 0, 0, 0)."""
    m = re.match(r"(\d+)\.(\d+)\.(\d+)(?:-(\d+)-g[0-9a-f]+)?", v or "")
    return tuple(int(x) for x in m.groups(default="0")) if m else (0, 0, 0, 0)


def describe(rev):
    d = git("describe", "--tags", "--match", "v*", "--always", "--first-parent", rev, check=False)
    if not d:
        return "0.0.0-nogit"
    return d[1:] if d.startswith("v") else "0.0.0-g" + d


def sync():
    """Clone (full history: versions and changelog need it) or fetch; returns origin/main's commit."""
    os.makedirs(BASE, exist_ok=True)
    if not os.path.isdir(os.path.join(SRC, ".git")):
        shutil.rmtree(SRC, ignore_errors=True)
        _run(["/usr/bin/xcrun", "git", "clone", "--quiet", "--no-checkout", REPO, SRC], timeout=300)
    else:
        git("remote", "set-url", "origin", REPO)
        # --force: history may be rewritten upstream (tags and main alike)
        git("fetch", "--quiet", "--force", "--tags", "--prune", "--prune-tags", "origin",
            "+refs/heads/main:refs/remotes/origin/main", timeout=300)
    return git("rev-parse", "origin/main")


def _known(commit):
    """Is this commit in the clone (it isn't after a rewrite of main, or for a foreign build)?"""
    return bool(commit) and subprocess.run(["/usr/bin/xcrun", "git", "-C", SRC, "cat-file", "-e", commit + "^{commit}"],
                                           capture_output=True).returncode == 0


def _is_ancestor(a, b):
    return subprocess.run(["/usr/bin/xcrun", "git", "-C", SRC, "merge-base", "--is-ancestor", a, b],
                          capture_output=True).returncode == 0


def check(current=None, commit=None):
    current = current or oomph.VERSION
    commit = commit if commit is not None else oomph.COMMIT
    head = sync()
    available = describe(head)
    if commit and head.startswith(commit[:12]):
        newer, behind = False, 0
    elif commit and _known(commit) and _is_ancestor(commit, head):
        newer, behind = True, int(git("rev-list", "--count", "--first-parent", "%s..%s" % (commit, head)) or 0)
    elif commit and _known(commit) and _is_ancestor(head, commit):
        newer, behind = False, 0  # this build is ahead of main (a local build)
    else:  # unknown or rewritten history: compare the version numbers
        newer, behind = parse_version(available) > parse_version(current), None
    return {"current": current, "current_commit": commit, "available": available, "commit": head,
            "newer": newer, "behind": behind, "checked": time.time()}


def log(limit=60, commit=None):
    """main's first-parent history, newest first, each entry a release with its version."""
    commit = commit if commit is not None else oomph.COMMIT
    head = git("rev-parse", "origin/main")
    by_commit = bool(commit) and _known(commit) and _is_ancestor(commit, head)
    new = set(git("rev-list", "--first-parent", "%s..%s" % (commit, head)).split()) if by_commit else set()
    cur = parse_version(oomph.VERSION)
    raw = git("log", "--first-parent", "-n", str(limit), "--format=%H%x1f%aI%x1f%s%x1f%b%x1e", head)
    out = []
    for rec in raw.split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, date, subject, body = (rec.split("\x1f") + ["", "", "", ""])[:4]
        v = describe(sha)
        if by_commit:
            status = "new" if sha in new else ("installed" if sha == commit else "older")
        else:
            status = "new" if parse_version(v) > cur else "older"
        body = "\n".join(ln for ln in body.strip().splitlines() if not ln.startswith("Co-Authored-By:")).strip()
        out.append({"commit": sha, "version": v, "date": date, "subject": subject, "body": body, "status": status})
    return out


def emit(**kw):
    print(json.dumps(kw), flush=True)


def build(out=STAGING):
    """Check out origin/main and run its build-app.sh into `out`; returns the built app's path."""
    emit(progress="Checking out the newest version")
    sync()
    git("checkout", "--quiet", "--force", "--detach", "origin/main")
    git("clean", "-q", "-f", "-d", "-x")
    version = describe("HEAD")
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    emit(progress="Building %s %s" % (oomph.BRAND, version), version=version)
    p = subprocess.Popen(["/bin/bash", os.path.join(SRC, "build-app.sh"), out], cwd=SRC,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         env=dict(os.environ, OOMPH_NO_KILL="1"))
    tail = []
    for line in p.stdout:
        line = line.rstrip("\n")
        tail = (tail + [line])[-20:]
        if line.startswith("==> "):
            emit(progress=line[4:], line=line)
        else:
            emit(line=line)
    if p.wait() != 0:
        raise UpgradeError("the build failed:\n" + "\n".join(tail[-8:]))
    app = os.path.join(out, "oomph.app")
    if not os.path.isfile(os.path.join(app, "Contents", "MacOS", oomph.CMD)):
        raise UpgradeError("the build produced no app")
    return app, version


# ------------------------------------------------------------------ CLI
def cmd_upgrade(args):
    sub = args[0] if args else "check"
    js = "--json" in args
    try:
        if sub == "tools":
            r = tools()
            print(json.dumps(r) if js else ("build tools: ok" if r["ok"] else "missing: %s — run %s"
                                             % (", ".join(r["missing"]), r["hint"])))
            return 0 if r["ok"] else 1
        t = tools()
        if not t["ok"]:
            raise UpgradeError("missing %s — run %s" % (", ".join(t["missing"]), t["hint"]))
        if sub == "check":
            r = check()
            if js:
                print(json.dumps(r))
            elif r["newer"]:
                print("%s %s is available (this is %s) — oomph upgrade log, then upgrade from the app"
                      % (oomph.BRAND, r["available"], r["current"]))
            else:
                print("%s %s is up to date" % (oomph.BRAND, r["current"]))
            return 0
        if sub == "log":
            entries = log()
            if js:
                print(json.dumps(entries))
            else:
                for e in entries:
                    print("%-22s %s  %s%s" % (e["version"], e["date"][:10], e["subject"],
                                              "  [new]" if e["status"] == "new" else
                                              "  [installed]" if e["status"] == "installed" else ""))
            return 0
        if sub == "build":
            out = args[args.index("--out") + 1] if "--out" in args else STAGING
            app, version = build(out)
            emit(done=app, version=version)
            return 0
        print(oomph.usage(__doc__))
        return 2
    except UpgradeError as e:
        if js or sub == "build":
            emit(error=str(e))
        else:
            print("oomph upgrade: %s" % e, file=sys.stderr)
        return 3
