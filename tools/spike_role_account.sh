#!/bin/bash
# A spike for remote machines (roadmap 01 §4.2, §12, Appendix A), run by CI as root on a throwaway
# runner: a LaunchDaemon under a role account and group of its own, started once per connection
# (inetdCompatibility, no Wait) on a loopback port, running this checkout's `oomph serve --stdio`
# through the /usr/bin/python3 shim with /var/empty as its home: the shape `oomph share on` will
# install, minus TLS. It records whether each piece works and how long a connection takes to its
# first frame, cold, warm, under simulated critical memory pressure and under real pressure at the
# warning level. Nothing here gates a release: the results go to the job summary.
#
#   sudo tools/spike_role_account.sh [SUMMARY_FILE]
#
# It creates and removes an account, a group, a LaunchDaemon and two folders. Never on a Mac in use.
set -uo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root, on a throwaway machine"; exit 2; }
cd "$(dirname "$0")/.."
OUT="${1:-/dev/stdout}"
NAME=_oomphspike
LABEL=local.oomph.spike-share
PORT=6675
CODE=/usr/local/libexec/oomph-spike
DATA=/private/var/tmp/oomph-spike
PLIST=/Library/LaunchDaemons/$LABEL.plist
ROWS=()
row() { ROWS+=("| $1 | $2 |"); echo "$1: $2"; }

cleanup() {
  launchctl bootout system/$LABEL 2>/dev/null
  rm -f "$PLIST"
  pkill -f "memory_pressure" 2>/dev/null
  sysadminctl -deleteUser $NAME >/dev/null 2>&1
  dseditgroup -o delete $NAME >/dev/null 2>&1
  rm -rf "$CODE" "$DATA"
  {
    echo "### Spike: role account, launchd job, first frame"
    echo
    echo "| What | Result |"
    echo "|---|---|"
    printf '%s\n' "${ROWS[@]}"
  } >> "$OUT"
}
trap cleanup EXIT

row "system" "$(sw_vers -productVersion) ($(uname -m)), $(sysctl -n hw.memsize | awk '{printf "%.0f GB", $1/1073741824}')"

# 1. the group, then the role account in it (as `share on` will: §4.2 step 1)
if dseditgroup -o create -r "oomph spike" $NAME 2>/tmp/spike.err; then
  GID=$(dscl . -read /Groups/$NAME PrimaryGroupID | awk '{print $2}')
  row "dseditgroup -o create" "ok, GID $GID"
else
  row "dseditgroup -o create" "FAILED: $(tail -1 /tmp/spike.err)"; exit 1
fi
if sysadminctl -addUser $NAME -fullName "oomph spike" -roleAccount -GID "$GID" -home /var/empty -shell /usr/bin/false \
     >/tmp/spike.out 2>&1 && id $NAME >/dev/null 2>&1; then
  row "sysadminctl -addUser -roleAccount -GID (no -UID)" "ok, uid $(id -u $NAME)"
else
  row "sysadminctl -addUser -roleAccount -GID (no -UID)" "FAILED: $(tail -1 /tmp/spike.out | tr '|' '/')"
  FREE=$(for u in $(seq 450 499); do dscl . -search /Users UniqueID $u | grep -q . || { echo $u; break; }; done)
  if sysadminctl -addUser $NAME -fullName "oomph spike" -roleAccount -UID "$FREE" -GID "$GID" -home /var/empty \
       -shell /usr/bin/false >/tmp/spike.out 2>&1 && id $NAME >/dev/null 2>&1; then
    row "… with -UID $FREE" "ok"
  else
    row "… with -UID $FREE" "FAILED: $(tail -1 /tmp/spike.out | tr '|' '/')"; exit 1
  fi
fi
row "id -gn $NAME" "$(id -gn $NAME) (want $NAME)"
row "home, shell" "$(dscl . -read /Users/$NAME NFSHomeDirectory | awk '{print $2}'), $(dscl . -read /Users/$NAME UserShell | awk '{print $2}')"
row "other members of the group" "$(dscl . -read /Groups/$NAME GroupMembership 2>/dev/null | cut -d: -f2- | xargs || true)"

# 2. the code (root's, readable) and a small machine to serve
mkdir -p "$CODE" "$DATA/log" "$DATA/ledger"
cp daemon/*.py "$CODE/"
chmod 755 "$CODE"; chmod 644 "$CODE"/*.py
/usr/bin/python3 -I - "$DATA/log" <<'PY'
import json, os, sys, time
d = sys.argv[1]; now = time.time()
day = time.strftime("%Y-%m-%d", time.localtime(now))
with open(os.path.join(d, "samples-%s.jsonl" % day), "w") as f:
    for i in range(120, 0, -1):
        f.write(json.dumps({"t": now - 30 * i, "app_gb": 4.0, "wired_gb": 2.0, "compressed_gb": 1.0, "swap_used_gb": 0.0}) + "\n")
json.dump({"t": now, "app_gb": 4.0, "ram_gb": 16.0, "daemon": {"interval": 30, "machine": {"id": "m-0000000000000001",
           "name": "runner", "os": "macos"}}}, open(os.path.join(d, "current.json"), "w"))
PY
chmod -R a+rX "$DATA"

# 3. the LaunchDaemon (the shape of §4.2 step 5, on loopback, without TLS)
cat > "$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>UserName</key><string>$NAME</string>
  <key>GroupName</key><string>$NAME</string>
  <key>ProgramArguments</key><array>
    <string>/usr/bin/python3</string><string>-I</string><string>-B</string>
    <string>$CODE/oomph.py</string><string>serve</string><string>--stdio</string></array>
  <key>EnvironmentVariables</key><dict>
    <key>OOMPH_DIR</key><string>$DATA/log</string><key>OOMPH_LEDGER_DIR</key><string>$DATA/ledger</string></dict>
  <key>Sockets</key><dict><key>Listeners</key><dict>
    <key>SockNodeName</key><string>127.0.0.1</string><key>SockServiceName</key><string>$PORT</string></dict></dict>
  <key>inetdCompatibility</key><dict><key>Wait</key><false/><key>Instances</key><integer>12</integer></dict>
  <key>StandardErrorPath</key><string>/dev/null</string>
  <key>Nice</key><integer>5</integer><key>LowPriorityIO</key><true/>
</dict></plist>
EOF
chmod 644 "$PLIST"
if launchctl bootstrap system "$PLIST" 2>/tmp/spike.err; then row "launchctl bootstrap system" "ok"
else row "launchctl bootstrap system" "FAILED: $(tail -1 /tmp/spike.err)"; exit 1; fi

# 4. connect-to-first-frame: connect, say hello, read the first line
measure() {  # LABEL N: N connections, the first one reported apart
  /usr/bin/python3 -I - "$PORT" "$2" <<'PY'
import json, socket, sys, time, subprocess
port, n = int(sys.argv[1]), int(sys.argv[2])
ms, who, bad = [], None, 0
for i in range(n):
    t = time.time()
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=30)
        s.sendall(b'{"jsonrpc":"2.0","id":1,"method":"hello","params":{"proto":[1,1]}}\n')
        f = s.makefile("rb")
        line = f.readline()
        ms.append((time.time() - t) * 1000)
        r = json.loads(line)
        if who is None:
            who = subprocess.run(["/bin/ps", "-axo", "user=,command="], capture_output=True, text=True).stdout
            who = sorted({l.split()[0] for l in who.splitlines() if "serve --stdio" in l and "oomph-spike" in l})
        if r.get("result", {}).get("machine", {}).get("name") != "runner":
            bad += 1
        s.close()
    except Exception as e:
        bad += 1
        print("error: %r" % e, file=sys.stderr)
    time.sleep(0.2)
ms_sorted = sorted(ms)
p = lambda q: ms_sorted[min(len(ms_sorted) - 1, int(q * len(ms_sorted)))] if ms_sorted else float("nan")
print("first %.0f ms; p50 %.0f, p95 %.0f, max %.0f ms of %d; %d failed; served as %s"
      % (ms[0] if ms else float("nan"), p(0.5), p(0.95), max(ms) if ms else float("nan"), len(ms), bad, ",".join(who or ["?"])))
PY
}
row "cold, then warm (20 connections)" "$(measure idle 20 2>&1 | tail -1)"

memory_pressure -S -l critical -s 120 >/dev/null 2>&1 &
sleep 3
row "simulated critical pressure (memory_pressure -S), level $(sysctl -n kern.memorystatus_vm_pressure_level)" \
    "$(measure simulated 20 2>&1 | tail -1)"
pkill -f "memory_pressure -S" 2>/dev/null; sleep 2

memory_pressure -l warn >/tmp/spike-mp.out 2>&1 &
MP=$!
for i in $(seq 1 90); do
  [ "$(sysctl -n kern.memorystatus_vm_pressure_level)" -ge 2 ] && break
  sleep 1
done
LEVEL=$(sysctl -n kern.memorystatus_vm_pressure_level)
SWAP=$(sysctl -n vm.swapusage | awk '{print $6}')
row "real pressure (memory_pressure -l warn): level $LEVEL after ${i}s, swap used $SWAP" "$(measure real 20 2>&1 | tail -1)"
kill $MP 2>/dev/null; wait $MP 2>/dev/null
row "decision rule (§4.2)" "p95 above 3000 ms under real pressure means: replace inetdCompatibility by a socket-owning job"
exit 0
