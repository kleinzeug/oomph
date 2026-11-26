#!/usr/bin/python3 -I
"""Keeps the brand and the identifiers apart (roadmap step N1; 05-naming §5.8).

The product's name is one constant per language: BRAND in daemon/oomph.py, `brand` (and
`descriptor`) in app/oomph.swift. Everything people read as the product's name goes through
them; everything typed, parsed, stored or sent over a wire says `oomph` (CMD) and never
changes: the command and its message prefix, paths, launchd labels, OOMPH_* variables, the
MCP server and skill names, file names, URLs. Changing the brand is then a one-line edit.

Checked, in the Python and Swift sources (prose files are edited by hand when the name
changes):
  1. The brand's value occurs only where it is defined (vacuous while it is "oomph").
  2. Every `oomph` in a string literal is a program or an identifier: part of a word, path,
     label, file name or URL (oomphd, /usr/local/bin/oomph, local.oomph., oomph.app,
     oomph/1.8), inside backticks, the message prefix (`oomph:`, `oomph run:`), a command
     (`oomph status`), the skill (`the oomph skill`). Anything else is prose that should
     say the brand, unless the exact literal is accepted in tools/brandlint.allow.
     Docstrings are not output, except the help (oomph.py's and oomph_upgrade.py's
     module docstrings), whose first `oomph` on the first line is printed as BRAND.
  3. install.sh links exactly one command into /usr/local/bin, and it is `oomph`.
  4. A brand other than "oomph" never stands before a descriptor that says "memory".
  5. Root stays out: the brand is not in oomphd.py, oomph_darwin.py, install.sh or uninstall.sh, and
     /Users/Shared appears only where the ledger directory is defined: oomph.py's path table
     and the app's constant.

    tools/brandlint.py            exit 0 clean, 1 with findings listed
    tools/brandlint.py --all      also list every accepted occurrence and why
"""
import ast
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = ("daemon/oomph.py", "daemon/oomphd.py", "daemon/oomph_darwin.py", "daemon/oomph_linux.py", "daemon/oomph_ioreport.py",
      "daemon/oomph_ai.py",
      "daemon/oomph_upgrade.py", "daemon/oomph_top.py", "daemon/oomph_view.py", "daemon/oomph_net.py", "daemon/oomph_sync.py",
      "daemon/oomph_gpu.py", "daemon/oomph_traffic.py")
SWIFT = ("app/oomph.swift",)
HELP_DOCS = ("daemon/oomph.py", "daemon/oomph_upgrade.py")  # module docstrings printed as help
SUBCOMMANDS = {"status", "report", "incidents", "incident", "html", "upgrade", "ai-report", "ai-check",
               "check", "session", "wait", "run", "reserve", "amend", "release", "reservations", "hook",
               "mcp", "setup-claude", "version", "resources", "top", "doctor", "share", "remote", "serve", "ps",
               "volumes", "alert", "net"}
WORD = re.compile(r"oomph", re.I)


def read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ------------------------------------------------------------ string literals
def py_literals(rel):
    """(line, text, kind) of every str constant; kind 'doc' for docstrings, 'help' for the
    module docstrings printed as help, else 'str'. f-string parts come as separate pieces."""
    tree = ast.parse(read(rel))
    docs = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)) and n.body:
            b = n.body[0]
            if isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant) and isinstance(b.value.value, str):
                docs[id(b.value)] = "help" if isinstance(n, ast.Module) and rel in HELP_DOCS else "doc"
    return [(n.lineno, n.value, docs.get(id(n), "str")) for n in ast.walk(tree)
            if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def swift_literals(rel):
    """(line, text, 'str') of every string literal, interpolations replaced by \\(…) and
    the literals inside interpolations listed on their own. Comments are skipped."""
    src, out, i, n = read(rel), [], 0, 0
    n = len(src)

    def line(at):
        return src.count("\n", 0, at) + 1

    def string(i):
        """Reads the literal starting at i (on its opening quote); returns (text, end)."""
        hashes = 0
        while src[i] == "#":
            hashes, i = hashes + 1, i + 1
        multi = src.startswith('"""', i)
        close = ('"""' if multi else '"') + "#" * hashes
        i += 3 if multi else 1
        text, start = [], i
        while i < n:
            if src.startswith(close, i):
                return "".join(text), i + len(close)
            c = src[i]
            if c == "\\" and src.startswith("#" * hashes, i + 1):
                j = i + 1 + hashes
                if j < n and src[j] == "(":  # interpolation: skip to the matching paren
                    depth, j = 1, j + 1
                    while j < n and depth:
                        if src[j] == '"' or (src[j] == "#" and src[j + 1:j + 2] == '"'):
                            t, j = string(j)
                            out.append((line(j), t, "str"))
                            continue
                        depth += {"(": 1, ")": -1}.get(src[j], 0)
                        j += 1
                    text.append("\\(…)")
                    i = j
                    continue
                text.append(src[i:j + 1])
                i = j + 1
                continue
            if c == "\n" and not multi:
                break
            text.append(c)
            i += 1
        return "".join(text), i

    while i < n:
        if src.startswith("//", i):
            i = src.find("\n", i)
            i = n if i < 0 else i
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
        elif src[i] == '"' or (src[i] == "#" and re.match(r'#+"', src[i:i + 8])):
            at = i
            t, i = string(i)
            out.append((line(at), t, "str"))
        else:
            i += 1
    return out


# ------------------------------------------------------------ classification
def why_ok(s, i):
    """Why the `oomph` at s[i:i+5] is a program or an identifier, or None if it reads as prose."""
    before, after = s[:i], s[i + 5:]
    if s[i:i + 5] == "OOMPH":
        return "identifier (OOMPH…)"
    if s[i:i + 5] != "oomph":
        return None
    if before[-1:] and (before[-1].isalnum() or before[-1] in "/.-_@~#$'"):
        return "part of a word, path, label or name"
    if after[:1] and (after[0].isalnum() or after[0] in "/.-_@"):
        return "part of a word, path, file name or token"
    if before.count("`") % 2:
        return "inside backticks"
    m = re.match(r"( [a-z_-]+| %s)?:", after)
    if m and not before.strip(" \n\t—-"):
        return "message prefix"
    m = re.match(r" ([a-z][a-z-]*)\b", after)
    if m and m.group(1) in SUBCOMMANDS:
        return "a command (oomph %s)" % m.group(1)
    if m and m.group(1) == "skill":
        return "the skill's name"
    if re.search(r"\bclaude mcp \w+( --scope \w+)? $", before) or re.search(r"\bMCP +$", before):
        return "the MCP server's name"
    return None


DEFINITION = re.compile(r"(BRAND|CMD) = |let (brand|descriptor) = ")


def literal_findings(rel, lits, allow):
    found, accepted, src = [], [], read(rel).splitlines()
    for ln, text, kind in lits:
        if kind == "doc" or not WORD.search(text) or DEFINITION.match(src[ln - 1]):
            continue
        lines = text.split("\n") if kind == "help" else [text]
        for k, part in enumerate(lines):
            for m in WORD.finditer(part):
                if kind == "help" and k == 0 and m.start() == part.find("oomph"):
                    accepted.append((rel, ln, part, "the help's first line: printed with BRAND"))
                    continue
                r = why_ok(part, m.start())
                if r is None and part.strip() in allow:
                    r = "accepted in brandlint.allow"
                (accepted if r else found).append((rel, ln + (k if kind == "help" else 0), part, r))
    return found, accepted


def brand_values():
    py = re.search(r'^BRAND = "([^"]*)"', read("daemon/oomph.py"), re.M)
    sw = re.search(r'^let brand = "([^"]*)"', read("app/oomph.swift"), re.M)
    de = re.search(r'^let descriptor = "([^"]*)"', read("app/oomph.swift"), re.M)
    return py and py.group(1), sw and sw.group(1), de and de.group(1)


def load_allow():
    """Exact literals accepted for good: one per line, `# why` comments after two spaces."""
    p = os.path.join(ROOT, "tools", "brandlint.allow")
    if not os.path.exists(p):
        return set()
    out = set()
    for raw in read("tools/brandlint.allow").splitlines():
        s = raw.split("  #", 1)[0].strip()
        if s and not s.startswith("#"):
            out.add(s)
    return out


def lint(verbose=False):
    errs = []
    brand, sbrand, descriptor = brand_values()
    if not brand or not sbrand or descriptor is None:
        return ["rule 1: BRAND in daemon/oomph.py, `let brand` and `let descriptor` in app/oomph.swift "
                "must each be defined on a line of their own"]
    if brand != sbrand:
        errs.append("rule 1: BRAND (%r) and the app's brand (%r) differ" % (brand, sbrand))
    if not re.search(r'^CMD = "oomph"(\s|$)', read("daemon/oomph.py"), re.M):
        errs.append('rule 1: CMD = "oomph" must be defined in daemon/oomph.py')

    # 1 and 5: the brand's value only where it is defined; never where root runs
    if brand != "oomph":
        pat = re.compile(r"\b%s\b" % re.escape(brand), re.I)
        for rel in PY + SWIFT + ("build-app.sh", "install.sh", "uninstall.sh"):
            for k, ln in enumerate(read(rel).splitlines(), 1):
                if pat.search(ln) and not re.match(r"(BRAND = |let brand = )", ln):
                    errs.append("rule 1/5: %s:%d names the brand instead of using the constant: %s"
                                % (rel, k, ln.strip()[:100]))

    # 2: every oomph in a literal is a program or an identifier
    allow = load_allow()
    for rel in PY + SWIFT:
        lits = py_literals(rel) if rel.endswith(".py") else swift_literals(rel)
        found, accepted = literal_findings(rel, lits, allow)
        for f in found:
            errs.append("rule 2: %s:%d reads as prose; use the brand constant or accept it in "
                        "tools/brandlint.allow: %r" % (f[0], f[1], f[2].strip()[:120]))
        if verbose:
            for a in accepted:
                print("ok  %s:%d  %-40s %r" % (a[0], a[1], a[3], a[2].strip()[:90]))

    # 3: one command in PATH
    links = [ln for ln in read("install.sh").splitlines()  # `relink` is its atomic ln -s
             if re.search(r"(^|[;&|]\s*)(ln|relink)\s", ln.strip()) and "/usr/local/bin" in ln]
    if len(links) != 1 or not re.search(r'/usr/local/bin/oomph"?\s*$', links[0]):
        errs.append("rule 3: install.sh must link exactly one command into /usr/local/bin, `oomph` (found %d)"
                    % len(links))

    # 4: the pair
    if sbrand != "oomph" and "memory" in descriptor:
        errs.append("rule 4: the brand %r must not stand before %r: the name ships with \"resource monitor\""
                    % (sbrand, descriptor))

    # 5: /Users/Shared only in the ledger-directory definitions
    for rel in PY + SWIFT + ("install.sh", "uninstall.sh", "build-app.sh"):
        for k, ln in enumerate(read(rel).splitlines(), 1):
            if "/Users/Shared" in ln and not re.match(r'(let ledgerDir = |\s+"ledger": "/Users/Shared/oomph",)', ln):
                errs.append("rule 5: %s:%d names /Users/Shared outside the ledger-directory definition" % (rel, k))
    for rel in ("daemon/oomphd.py", "daemon/oomph_darwin.py", "daemon/oomph_ioreport.py", "install.sh", "uninstall.sh",
                "linux/install.sh", "linux/uninstall.sh"):
        if re.search(r"\bBRAND\b|\bbrand\b", read(rel)):
            errs.append("rule 5: %s uses the brand; root's code and the installers say oomph only" % rel)
    return errs


def main(argv):
    errs = lint("--all" in argv)
    for e in errs:
        print(e)
    print("brandlint: %s" % ("%d finding(s)" % len(errs) if errs else "ok"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
