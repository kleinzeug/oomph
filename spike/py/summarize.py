#!/usr/bin/env python3
"""summarize.py OUTDIR LABEL -> markdown table of the rows' verdicts (for $GITHUB_STEP_SUMMARY)."""
import glob, os, re, sys
out, label = sys.argv[1], sys.argv[2]
rows = sorted(glob.glob(os.path.join(out, "rows", "row-*.txt"))) or sorted(glob.glob(os.path.join(out, "partial", "spike-out", "rows", "row-*.txt")))
print("## %s\n" % label)
if os.path.exists(os.path.join(out, "SKIPPED")):
    print("Skipped: " + open(os.path.join(out, "SKIPPED")).read()); sys.exit(0)
if not rows:
    print("No row output found in %s." % out); sys.exit(0)
print("| # | Fact | Verdict | Detail |\n|---|---|---|---|")
for f in rows:
    t = open(f, errors="replace").read()
    m = re.search(r"^===== ROW (\d+) \| ([^|]*)\|", t, re.M)
    v = re.findall(r"^VERDICT: (\S+) \| (.*)$", t, re.M)
    n, fact = (m.group(1), m.group(2).strip()) if m else (os.path.basename(f), "?")
    verd, det = v[-1] if v else ("?", "")
    det = det.replace("|", "/")[:400]
    print("| %s | %s | **%s** | %s |" % (n, fact, verd, det))
