#!/usr/bin/python3 -I
"""Holds the app's connect popover (app/oomph.swift, ConnectInput; roadmap 01 §3.7) to the CLI that
does the connecting (daemon/oomph_sync.py) and to fixed words.

tools/vectors/connect.json holds inputs and the expected answers: what a pasted pairing link names
(target and code), how a typed code reads, which way a text goes (link, ssh, a shared Mac), the
command the SSH step shows, the host a target names, completion over known machines, how long ago
a machine was connected, and the popover's message for each answer of `oomph remote add --json`.
The expected answers are the app's: `oomph --connect-vectors FILE` runs its own functions over the
inputs. The link, code and kind answers must be the CLI's as well (oomph_sync.parse_link,
oomph_net.norm_code, oomph_sync.parse_target), so the popover never offers what the CLI refuses.

    tools/connectvectors.py                  the CLI against the file (the self-test runs this)
    tools/connectvectors.py --app BINARY     the app against the file (CI runs this after the build)
    tools/connectvectors.py --app BINARY --write
                                             new inputs (cases below) answered by the app, written
                                             to the file; then run without --app to see the CLI agree
Exit 0 when every group agrees, 1 when one differs, 2 when it could not run.
"""
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.join(ROOT, "tools", "vectors", "connect.json")
sys.path.insert(0, os.path.join(ROOT, "daemon"))

import oomph_net as net  # noqa: E402
import oomph_sync as sync  # noqa: E402

GROUPS = ("link", "code", "kind", "ssh_command", "host", "matches", "ago", "message", "message_shown", "note")
CLI_GROUPS = ("link", "code", "kind")


def cases():
    links = ["oomph://K7QF-2M9X-D4TR@studio.local:6674", "oomph://k7qf2m9xd4tr@studio.local", "oomph://K7QF-2M9X-D4TR@10.0.4.23/",
             "  oomph://K7QF-2M9X-D4TR@studio:7000  ", "oomph://K7QF-2M9X-D4TR@[fe80::1%en0]:6674", "oomph://K7QF 2M9X D4TR@mini",
             "oomph://O1IL-2M9X-D4TR@studio", "oomph://K7QF-2M9X-D4T@studio", "oomph://K7QF-2M9X-D4TU@studio",
             "oomph://K7QF-2M9X-D4TR@sam@atlas", "oomph://K7QF-2M9X-D4TR@-oProxyCommand=x", "oomph://K7QF-2M9X-D4TR@studio:99999",
             "oomph://K7QF-2M9X-D4TR@studio:", "oomph://K7QF-2M9X-D4TR@a b", "oomph://K7QF-2M9X-D4TR@studio/x",
             "https://K7QF-2M9X-D4TR@studio", "oomph://@studio", "oomph://K7QF-2M9X-D4TR@studio..local",
             "oomph://K7QF-2M9X-D4TR@::1", "oomph://K7QF-2M9X-D4TR@[::1]:6674", "oomph://K7QF-2M9X-D4TR@[nothex]:6674"]
    codes = ["K7QF-2M9X-D4TR", "k7qf 2m9x d4tr", "O1IL00000000", "K7QF2M9XD4T", "K7QF2M9XD4TU", "", "K7QF-2M9X-D4TR-", "ÄBCD-EFGH-JKMN"]
    kinds = ["studio.local", "studio:7000", "10.0.4.23", "sam@atlas", "ssh://atlas", "ssh://sam@atlas:2222", "[fe80::1]:6674",
             "oomph://K7QF-2M9X-D4TR@studio", "render-01"]
    ssh = ["sam@atlas", "ssh://sam@atlas:2222", "ssh://deploy@build-box/", "ann@[fe80::1]:22"]
    hosts = ["studio.local", "studio.local:7000", "[fe80::1%en0]:6674", "sam@atlas", "ssh://sam@atlas:2222", "::1", "render-01"]
    known = [{"mid": "m-7f3a9c1e5b2d4a68", "names": ["studio", "studio.local", "192.168.1.20"]},
             {"mid": "m-5a6b7c8d9e0f1a2b", "names": ["render-01", "render-01.local", "10.0.4.23"]},
             {"mid": "m-1b2c3d4e5f607182", "names": ["Mini CI", "mini-ci", "mini-ci.local", "10.0.4.31"]}]
    matches = [{"text": t, "known": known} for t in ("stu", "STUDIO.L", "10.0.4", "ren", "mini", "x", "", "  stu ", "192.168.1.2")]
    now = 1795180000.0
    ago = [{"t": now - a, "now": now} for a in (0, 90, 120, 3599, 3600, 86399, 86400, 2 * 86400 + 5, 30 * 86400, -50)]
    message = [{"code": c, "target": t, "detail": d, "side": s} for c, t, d, s in (
        ("refused", "studio.local", "", None), ("turned_away", "studio.local:7000", "", None),
        ("local_network_denied", "studio.local", "", None), ("timeout", "10.0.4.23", "", None),
        ("dns", "studoi.local", "", None), ("not_oomph", "studio.local:7000", "", None),
        ("not_oomph", "sam@atlas", "oomph is not installed on atlas", None), ("not_oomph", "sam@atlas", "unknown command", None),
        ("pair_failed", "studio.local", "", None), ("incompatible", "studio.local", "", "old"),
        ("incompatible", "studio.local", "", "new"), ("incompatible", "studio.local", "", None),
        ("too_many", "studio.local", "", None), ("busy", "studio.local", "", None), ("ssh", "sam@atlas", "", None),
        ("identity_changed", "studio.local", "", None), ("revoked", "studio.local", "", None),
        ("bad_address", "a b", "", None), ("ask", "studio.local", "", None), ("closed", "studio.local", "it closed", None))]
    return {"link": [{"s": s} for s in links], "code": [{"s": s} for s in codes], "kind": [{"s": s} for s in kinds],
            "ssh_command": [{"s": s} for s in ssh], "host": [{"s": s} for s in hosts], "matches": matches, "ago": ago,
            "message": message, "message_shown": [dict(code=c, target=t, detail=d, side=None, v=v) for c, t, d, v in SHOWN],
            "note": [{"s": s, "v": v} for s, v in NOTES]}


# the error box with words from elsewhere in it (ConnectInput.message, then noteText; 1.14.1): a typed or pasted target,
# a server's own error message as the detail. `v` must show exactly as it came, never as emphasis, code or a link
SHOWN = [("closed", "studio.local", "**x** `rm -rf` [here](https://evil.example)", "**x** `rm -rf` [here](https://evil.example)"),
         ("timeout", "**studio**", "", "**studio**"),
         ("busy", "`studio`.local", "", "`studio`"),
         ("refused", "_st_udio.local", "", "_st_udio.local"),
         ("ssh", "**sam**@atlas", "", "ssh **sam**@atlas"),
         ("closed", "studio.local", "", "Connecting to studio.local failed.")]


# a note of the popover with a machine's name, label, version or address put in (ConnectInput.md, noteText; 1.14.1):
# it reads as it came, never as a link, emphasis or code
NOTES = [("Forget {}? Its history on this Mac is deleted.", "studio"),
         ("Forget {}? Its history on this Mac is deleted.", "[click here](https://evil.example/x)"),
         ("**Here:** {} reports the same machine id.", "https://evil.example"),
         ("Whoever can sign in to {} can read it.", "sam@evil.example"),
         ("{} no longer knows this Mac.", "www.evil.example"),
         ("{}", "**bold** `code` _it_ <b>x</b> \\ \\* # 1. - [x]"),
         ("{}", "macOS 27.2 · 64 GB · oomph 1.10.2"),
         ("Paired with {}.", "<https://evil.example>"),
         ("{} reports it.", "fe80::1%en0"),
         ("{} reports it.", "mailto:a@b.c")]


def note_rules(v):
    """Each note and shown message holds its words exactly as they came and no link. A list of failures."""
    bad = []
    for g in ("note", "message_shown"):
        for c, a in zip(v["inputs"].get(g) or [], v["expected"].get(g) or []):
            if not (isinstance(a, list) and len(a) == 2 and a[1] == 0 and c["v"] in a[0]):
                bad.append("%s %r: %r" % (g, c, a))
        if len(v["expected"].get(g) or []) != len(v["inputs"].get(g) or []) or not v["inputs"].get(g):
            bad.append("%s: answers for every case" % g)
    return bad


def cli_answers(v):
    """What the CLI makes of the same inputs, in the app's shapes."""
    def link(s):
        try:
            t, c = sync.parse_link(s)
            return [t, c]
        except ValueError:
            return None

    def kind(s):
        s = s.strip()
        return "link" if s.startswith("oomph://") else sync.parse_target(s)["transport"]
    return {"link": [link(c["s"]) for c in v["link"]], "code": [net.norm_code(c["s"]) for c in v["code"]],
            "kind": [kind(c["s"]) for c in v["kind"]]}


def app_answers(binary, inputs):
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(inputs, f)
    try:
        r = subprocess.run([binary, "--connect-vectors", f.name], capture_output=True, text=True, timeout=60)
    finally:
        os.unlink(f.name)
    if r.returncode != 0:
        print("the app could not answer: %s" % r.stderr.strip())
        return None
    return json.loads(r.stdout)


def compare(got, want, groups, who):
    bad = 0
    for g in groups:
        if got.get(g) != want.get(g):
            bad += 1
            print("FAIL  %s, %s:" % (who, g))
            for i, (a, b) in enumerate(zip(got.get(g) or [], want.get(g) or [])):
                if a != b:
                    print("        case %d: %r, expected %r" % (i, a, b))
        else:
            print("ok    %s agrees on %s (%d cases)" % (who, g, len(want.get(g) or [])))
    return bad


def main(argv):
    if "--app" in argv:
        binary = argv[argv.index("--app") + 1]
        if "--write" in argv:
            inputs = cases()
            got = app_answers(binary, inputs)
            if got is None:
                return 2
            json.dump({"inputs": inputs, "expected": got}, open(FILE, "w"), indent=1, ensure_ascii=False, sort_keys=True)
            open(FILE, "a").write("\n")
            print("wrote %s" % FILE)
            return 0
        v = json.load(open(FILE))
        got = app_answers(binary, v["inputs"])
        if got is None:
            return 2
        bad = note_rules({"inputs": v["inputs"], "expected": got})
        for b in bad:
            print("FAIL  the app, " + b)
        return 1 if compare(got, v["expected"], GROUPS, "the app") or bad else 0
    v = json.load(open(FILE))
    bad = note_rules(v)
    for b in bad:
        print("FAIL  the file, " + b)
    return 1 if compare(cli_answers(v["inputs"]), v["expected"], CLI_GROUPS, "the CLI") or bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
