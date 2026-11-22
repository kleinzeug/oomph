#!/bin/bash
# The fact spike LS of roadmap/03-linux/DESIGN.md, Appendix E. Throwaway; never merged.
#   facts.sh all [ROWS]   run the rows (each in its own bash, under its own timeout)
#   facts.sh row N        run one row
# Runs as root. Each row prints a block with its commands, their output (capped) and one VERDICT line.
# No set -e on purpose: one failing command never stops a row, one failing row never stops the others.
SPIKE=$(cd "$(dirname "$0")" && pwd)
OUT=${OUT:-/var/tmp/spike-out}
STATE=$OUT/state
RAW=$OUT/raw
MODE=${MODE:-runner}
SYSNAME=${SYSNAME:-$(. /etc/os-release; echo "$ID-$VERSION_ID")}
CAP=${CAP:-6000}
LX=/usr/local/libexec/oomph
PY=$LX/spike          # helpers are copied here: ProtectHome= would hide the checkout under /home
ARCH=$(uname -m)
export LC_ALL=C SYSTEMD_PAGER= SYSTEMD_COLORS=0 PYTHONDONTWRITEBYTECODE=1

# --------------------------------------------------------------------------------------------- helpers
run() {  # run "shell command" — prints it, its output (capped) and its exit code; T= sets the timeout
    local t=${T:-60}
    echo "\$ $1"
    timeout -k 5 "$t" bash -c "$1" > "$STATE/.run.$$" 2>&1; local rc=$?
    head -c "$CAP" "$STATE/.run.$$"
    [ "$(stat -c %s "$STATE/.run.$$")" -gt "$CAP" ] && echo "[... output cut at $CAP bytes of $(stat -c %s "$STATE/.run.$$")]"
    [ $rc -eq 124 ] && echo "[TIMEOUT after ${t}s]"
    echo "[exit $rc]"
    rm -f "$STATE/.run.$$"
    return $rc
}
q() { timeout -k 5 "${T:-60}" bash -c "$1" 2>&1; }      # quiet capture for verdicts
verdict() { echo "VERDICT: $1 | $2"; }                   # MATCH MISMATCH PARTIAL INFO NOT-RUN
notrun() { echo "not run: $1"; verdict NOT-RUN "$1"; }
note() { echo "# $*"; }
in_range() { [ -n "$1" ] && [ "$1" -ge 180 ] && [ "$1" -le 220 ]; }
kver_ge() { [ "$(printf '%s\n%s\n' "$1" "$(uname -r | cut -d- -f1)" | sort -V | head -1)" = "$1" ]; }
cursor_now() { journalctl --sync >/dev/null 2>&1; journalctl -n 1 -o json --no-pager 2>/dev/null | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["__CURSOR"])' 2>/dev/null; }
vmstat_oom() { awk '$1=="oom_kill"{print $2}' /proc/vmstat; }
pkg_install() {  # best effort, quiet
    if command -v apt-get >/dev/null; then [ -e /var/tmp/.spike-apt-updated ] || { timeout 300 apt-get update -qq >/dev/null 2>&1; touch /var/tmp/.spike-apt-updated; }
        DEBIAN_FRONTEND=noninteractive timeout 300 apt-get install -y -qq "$@" >/dev/null 2>&1
    elif command -v dnf >/dev/null; then timeout 400 dnf -y -q install "$@" >/dev/null 2>&1; fi
}
ensure_helpers() { mkdir -p "$PY"; cp "$SPIKE"/py/*.py "$PY"/; chmod 755 "$LX" "$PY"; chmod 644 "$PY"/*.py; }
ensure_users() {
    for g in spikegrp spikeW spikeR; do getent group $g >/dev/null || groupadd $g; done
    for u in spikea spikeb spikej spikesg; do id $u >/dev/null 2>&1 || useradd -m -s /bin/bash $u; done
    usermod -aG spikeW spikea; usermod -aG spikeR spikeb
    getent group systemd-journal >/dev/null && usermod -aG systemd-journal spikej
}
ensure_oomph_accounts() {
    getent group oomph >/dev/null || groupadd --system oomph
    getent group oomph-read >/dev/null || groupadd --system oomph-read
    id oomphd >/dev/null 2>&1 || useradd --system -g oomph -M -d /nonexistent -s /usr/sbin/nologin oomphd 2>/dev/null || useradd --system -g oomph -M -s /sbin/nologin oomphd
    id oomph-share >/dev/null 2>&1 || useradd --system -g oomph-read -M -d /nonexistent -s /usr/sbin/nologin oomph-share 2>/dev/null || useradd --system -g oomph-read -M -s /sbin/nologin oomph-share
    install -d -o oomphd -g oomph -m 2750 /var/log/oomph
    install -d -o oomphd -g oomph -m 0750 /var/lib/oomph/daemon
    install -d -o root -g oomph -m 2770 /var/lib/oomph/ledger
    install -d -o oomph-share -g oomph-read -m 0750 /var/lib/oomph/share /var/lib/oomph/share/run
    chmod 755 /var/lib/oomph
}
ensure_zram() {
    grep -q '^/dev/zram' /proc/swaps && return 0
    [ -e /sys/block/zram0 ] || modprobe zram num_devices=1 2>/dev/null || {
        command -v apt-get >/dev/null && pkg_install "linux-modules-extra-$(uname -r)"; modprobe zram num_devices=1 2>/dev/null; }
    [ -e /sys/block/zram0 ] || return 1
    zramctl --reset /dev/zram0 2>/dev/null
    zramctl /dev/zram0 --size 1G --algorithm lz4 2>/dev/null || zramctl /dev/zram0 --size 1G || return 1
    mkswap /dev/zram0 >/dev/null && swapon -p 100 /dev/zram0
}
journal_since() {  # journal_since CURSOR FILE [journalctl args…] — writes json lines, prints the count
    local c=$1 f=$2; shift 2
    journalctl --sync >/dev/null 2>&1
    if [ -n "$c" ]; then journalctl --no-pager -o json --after-cursor="$c" "$@" > "$f" 2>/dev/null
    else journalctl --no-pager -o json -b "$@" > "$f" 2>/dev/null; fi
    wc -l < "$f"
}
# a unit file built from the draft oomphd.service: same [Unit]/[Service] sandbox, oneshot, our ExecStart and output
draft_unit() {  # draft_unit NAME EXECSTART OUTFILE [extra Service lines…]
    local name=$1 exec=$2 outf=$3; shift 3
    {
        sed -e '/^\[Install\]/,$d' -e '/^ExecStart=/d' -e '/^Type=/d' -e '/^Restart/d' "$SPIKE/units/oomphd.service"
        echo "Type=oneshot"; echo "ExecStart=$exec"; echo "StandardOutput=file:$outf"; echo "StandardError=inherit"
        for l in "$@"; do echo "$l"; done
    } > /etc/systemd/system/$name.service
    systemctl daemon-reload
}

# --------------------------------------------------------------------------------------------- rows
row1() {
    run "uname -a"; run "head -4 /etc/os-release"; run "systemctl --version | head -2"
    run "stat -fc %T /sys/fs/cgroup"; run "cat /sys/fs/cgroup/cgroup.controllers"; run "grep -E 'cgroup2|^proc ' /proc/mounts"
    run "for f in memory cpu io; do echo \"-- \$f\"; cat /proc/pressure/\$f; done"
    run "cat /proc/cmdline"; run "grep -E 'CONFIG_PSI|CONFIG_PROC_CHILDREN|CONFIG_ZSWAP=|CONFIG_ZRAM=|CONFIG_MEMCG=' /boot/config-\$(uname -r)"
    run "swapon --show; free -m; nproc"
    run "ls -l /dev/kvm"
    run "sysctl kernel.dmesg_restrict fs.protected_hardlinks fs.protected_symlinks fs.protected_regular fs.protected_fifos kernel.yama.ptrace_scope vm.overcommit_memory kernel.unprivileged_userns_clone"
    run "systemctl is-active systemd-oomd earlyoom systemd-journald systemd-logind"
    run "command -v getenforce && getenforce"; run "python3 --version"; run "id \${SUDO_USER:-root}"
    local ok=1 why=""
    [ "$(cat /proc/1/comm)" = systemd ] || { ok=0; why="$why pid1=$(cat /proc/1/comm);"; }
    [ "$(stat -fc %T /sys/fs/cgroup)" = cgroup2fs ] || { ok=0; why="$why cgroup=$(stat -fc %T /sys/fs/cgroup);"; }
    cat /proc/pressure/memory >/dev/null 2>&1 || { ok=0; why="$why PSI off/unreadable;"; }
    if [ "$ARCH" = x86_64 ] && [ "$MODE" = runner ]; then [ -e /dev/kvm ] || { ok=0; why="$why no /dev/kvm;"; }; fi
    local kvm=absent; [ -e /dev/kvm ] && kvm=present
    local s="kernel $(uname -r), systemd $(systemctl --version | head -1 | awk '{print $2}'), $(stat -fc %T /sys/fs/cgroup), PSI $(cat /proc/pressure/memory >/dev/null 2>&1 && echo on || echo OFF), kvm $kvm, swap $(swapon --show=NAME --noheadings | tr '\n' ' ')/, dmesg_restrict=$(sysctl -n kernel.dmesg_restrict) protected_hardlinks=$(sysctl -n fs.protected_hardlinks) ptrace_scope=$(sysctl -n kernel.yama.ptrace_scope 2>/dev/null)"
    [ $ok = 1 ] && verdict MATCH "$s" || verdict MISMATCH "$s;$why"
}
row2() {
    run "grep -E 'MemAvailable|Zswap|Shmem|AnonPages' /proc/meminfo"
    run "grep -E 'RssAnon|RssShmem|VmSwap|NSpid' /proc/self/status"
    local miss=""
    for f in MemAvailable Zswap Zswapped Shmem AnonPages; do grep -q "^$f:" /proc/meminfo || miss="$miss meminfo:$f"; done
    for f in RssAnon RssShmem VmSwap NSpid; do grep -q "^$f:" /proc/self/status || miss="$miss status:$f"; done
    [ -z "$miss" ] && verdict MATCH "all fields present" || verdict MISMATCH "missing:$miss"
}
row3() {
    T=120 run "python3 $PY/footprint.py 200 3" | tee "$STATE/r3a"
    if ensure_zram; then
        run "swapon --show"
        note "now under memory pressure: the child lives in a scope with MemoryHigh=64M so its pages go to zram (priority 100)"
        T=180 run "systemd-run --quiet --scope -p MemoryHigh=64M -p MemoryMax=600M -p MemorySwapMax=2G python3 $PY/footprint.py 200 20" | tee "$STATE/r3b"
        run "cat /sys/block/zram0/mm_stat"
    else
        echo "zram not available: $(modprobe zram 2>&1)"
    fi
    local a b sw
    a=$(grep -o 'DELTA_MB=-\?[0-9]*' "$STATE/r3a" | cut -d= -f2); b=$(grep -o 'DELTA_MB=-\?[0-9]*' "$STATE/r3b" 2>/dev/null | cut -d= -f2)
    sw=$(grep -o 'SWAP_MB=[0-9]*' "$STATE/r3b" 2>/dev/null | cut -d= -f2)
    if in_range "$a" && in_range "$b" && [ "${sw:-0}" -gt 50 ]; then verdict MATCH "plain +${a} MB; in zram scope +${b} MB with ${sw} MB in VmSwap"
    elif in_range "$a" && [ -z "$b" ]; then verdict PARTIAL "plain +${a} MB; zram variant did not run"
    else verdict MISMATCH "plain +${a:-?} MB; zram scope +${b:-?} MB (VmSwap ${sw:-?} MB)"; fi
}
row4() {
    if ! ensure_zram; then echo "modprobe: $(modprobe zram 2>&1)"; verdict NOT-RUN "no zram module on this kernel"; return; fi
    T=60 run "systemd-run --quiet --scope -p MemoryHigh=32M -p MemorySwapMax=1G python3 $PY/alloc.py hold 120 3"
    run "zramctl"; run "cat /sys/block/zram0/mm_stat"; run "cat /proc/swaps"; run "cat /sys/block/zram0/comp_algorithm"
    local m n o c; m=$(cat /sys/block/zram0/mm_stat); n=$(echo $m | wc -w); o=$(echo $m | awk '{print $1}'); c=$(echo $m | awk '{print $2}')
    if [ "$n" -ge 7 ] && [ "$o" -gt 0 ] && [ "$o" -ge "$c" ] && grep -q '^/dev/zram0' /proc/swaps; then
        verdict MATCH "$n columns, orig_data_size=$o >= compr_data_size=$c, third=mem_used_total=$(echo $m | awk '{print $3}'); zram0 listed in /proc/swaps"
    else verdict MISMATCH "mm_stat='$m' ($n columns)"; fi
}
row5() {
    run "runuser -u nobody -- python3 $PY/psi_trigger.py /proc/pressure/memory 'some 200000 2000000'" | tee "$STATE/r5"
    run "runuser -u nobody -- python3 $PY/psi_trigger.py /proc/pressure/memory 'some 200000 1000000'"
    run "python3 $PY/psi_trigger.py /proc/pressure/memory 'some 200000 1000000'"
    local reg=no; grep -q 'RESULT: REGISTERED' "$STATE/r5" && reg=yes
    if kver_ge 6.4; then [ $reg = yes ] && verdict MATCH "kernel $(uname -r) >= 6.4: unprivileged trigger registers" || verdict MISMATCH "kernel $(uname -r) >= 6.4 but: $(grep RESULT "$STATE/r5")"
    else [ $reg = no ] && verdict MATCH "kernel $(uname -r) < 6.4: refused ($(grep RESULT "$STATE/r5"))" || verdict MISMATCH "kernel $(uname -r) < 6.4 but registered"; fi
}
row6() {
    ensure_oomph_accounts
    rm -f "$STATE/r6.out"
    draft_unit spike-psi "/usr/bin/python3 -I -B $PY/psi_trigger.py /proc/pressure/memory 'some 200000 2000000'" "$STATE/r6.out"
    run "cat /etc/systemd/system/spike-psi.service"
    T=60 run "systemctl start spike-psi.service; systemctl status spike-psi.service --no-pager | head -12"
    run "cat $STATE/r6.out"
    run "journalctl -u spike-psi.service --no-pager -n 15"
    if grep -q 'RESULT: REGISTERED' "$STATE/r6.out" 2>/dev/null; then verdict MATCH "registers under the draft unit's properties (kernel $(uname -r))"
    elif kver_ge 6.4; then verdict MISMATCH "under the unit: $(grep -h RESULT "$STATE/r6.out" 2>/dev/null || echo 'no output')"
    else verdict INFO "kernel < 6.4: refused as everywhere unprivileged ($(grep -h RESULT "$STATE/r6.out" 2>/dev/null || echo 'no output'))"; fi
}
row7() {
    systemd-run --quiet --scope --unit spike-r7 -p MemoryMax=500M -p MemoryHigh=400M -p IOAccounting=yes sleep 120 >/dev/null 2>&1 &
    sleep 2
    local cg; cg=/sys/fs/cgroup$(systemctl show -p ControlGroup --value spike-r7.scope)
    echo "scope cgroup: $cg"
    run "ls -l $cg | head -60"
    local bad="" f
    for f in /sys/fs/cgroup/system.slice/memory.pressure /sys/fs/cgroup/user.slice/memory.pressure $cg/memory.max $cg/memory.high $cg/memory.current $cg/io.stat $cg/memory.pressure $cg/memory.events $cg/memory.stat $cg/memory.swap.current $cg/memory.peak $cg/cgroup.procs; do
        echo "--- as nobody: cat $f"
        if [ ! -e "$f" ]; then echo "(absent)"; bad="$bad absent:${f##*/}"; continue; fi
        runuser -u nobody -- head -c 600 "$f" 2>&1 || bad="$bad unreadable:${f#/sys/fs/cgroup}"
    done
    systemctl stop spike-r7.scope 2>/dev/null
    [ -z "$bad" ] && verdict MATCH "all readable by nobody" || verdict PARTIAL "readable except:$bad"
}
row8() {
    local c k0 k1
    c=$(cursor_now); echo "$c" > "$STATE/r8.cursor"; k0=$(vmstat_oom)
    T=60 run "systemd-run --quiet --scope -p MemoryMax=64M -p MemorySwapMax=0 python3 -c \"x = bytearray(b'x') * (200 << 20)\""
    sleep 2; k1=$(vmstat_oom)
    echo "/proc/vmstat oom_kill: $k0 -> $k1"
    echo "journal lines (kernel) after the cursor: $(journal_since "$c" "$RAW/r8-kernel.json" -k)"
    run "journalctl --no-pager -k -o short-monotonic --after-cursor='$c'"
    run "python3 $PY/patterns.py < $RAW/r8-kernel.json" | tee "$STATE/r8.pat"
    local co; co=$(grep '^COUNTS' "$STATE/r8.pat")
    if grep -q "SUMMARY .*CONSTRAINT_MEMCG" "$STATE/r8.pat" && grep -q "KILLED .*Memory cgroup out of memory" "$STATE/r8.pat" && [ $((k1-k0)) -eq 1 ] && grep -q '^INVOKED ' "$STATE/r8.pat" && grep -q 'UNMATCHED oom-related lines: 0' "$STATE/r8.pat"; then
        verdict MATCH "INVOKED, SUMMARY (CONSTRAINT_MEMCG) and prefixed KILLED all matched; oom_kill +1; $co"
    else verdict MISMATCH "oom_kill +$((k1-k0)); $co; $(grep -c UNMATCHED "$STATE/r8.pat") unmatched-related lines"; fi
}
row9() {
    cat > "$STATE/r9.py" <<'PYEOF'
import os, time
time.sleep(4)
for i in range(2):
    if os.fork() == 0:
        b = bytearray(25 << 20)
        for j in range(0, len(b), 4096): b[j] = 1
        time.sleep(60); os._exit(0)
time.sleep(1.5)
x = bytearray(b'x') * (200 << 20)
PYEOF
    local c k0 k1 cg
    c=$(cursor_now); k0=$(vmstat_oom)
    systemd-run --quiet --scope --unit spike-r9 --slice spike9.slice -p MemoryMax=96M -p MemorySwapMax=0 python3 "$STATE/r9.py" > "$STATE/r9.run" 2>&1 &
    local sp=$!
    sleep 1.5
    cg=/sys/fs/cgroup$(systemctl show -p ControlGroup --value spike-r9.scope)
    echo "scope cgroup $cg"; echo 1 > "$cg/memory.oom.group"; echo "memory.oom.group = $(cat $cg/memory.oom.group)"
    wait $sp; echo "scope exit: $?"; cat "$STATE/r9.run"
    sleep 2; k1=$(vmstat_oom)
    cat /sys/fs/cgroup/spike9.slice/memory.events > "$STATE/r9.events" 2>/dev/null
    echo "memory.events of the parent spike9.slice (hierarchical) after the kill:"; cat "$STATE/r9.events" 2>/dev/null
    echo "/proc/vmstat oom_kill: $k0 -> $k1"
    echo "journal lines: $(journal_since "$c" "$RAW/r9-kernel.json" -k)"
    run "journalctl --no-pager -k -o short-monotonic --after-cursor='$c' | grep -vE '^\s*$' | grep -iE 'oom|Killed|Tasks state|memory:|Memory cgroup' "
    run "python3 $PY/patterns.py < $RAW/r9-kernel.json" | tee "$STATE/r9.pat"
    local s kl dp; s=$(sed -n 's/.*SUMMARY=\([0-9]*\).*/\1/p' "$STATE/r9.pat"); kl=$(sed -n 's/.* KILLED=\([0-9]*\).*/\1/p' "$STATE/r9.pat"); dp=$(sed -n 's/.*KILLED_distinct_pids=\([0-9]*\).*/\1/p' "$STATE/r9.pat")
    local x="SUMMARY=$s KILLED lines=$kl for $dp distinct pids, /proc/vmstat oom_kill +$((k1-k0)); slice events: $(grep -E '^(oom|oom_kill|oom_group_kill) ' "$STATE/r9.events" 2>/dev/null | tr '\n' ' ')"
    if [ "$s" = 1 ] && [ "$kl" = 3 ]; then verdict MATCH "$x"; else verdict MISMATCH "$x"; fi
}
row10() {
    [ "$MODE" = guest ] || { notrun "a machine-wide OOM would take the runner down; this row runs in the QEMU guests"; return; }
    run "swapoff -a; swapon --show; free -m"
    run "systemctl is-active earlyoom systemd-oomd"
    local c k0 k1; c=$(cursor_now); k0=$(vmstat_oom)
    T=240 run "OOM_ADJ=1000 systemd-run --quiet --scope --unit spike-r10 python3 $PY/alloc.py grow 32 0.02 | tail -3"
    sleep 3; k1=$(vmstat_oom)
    echo "/proc/vmstat oom_kill: $k0 -> $k1"
    echo "journal lines: $(journal_since "$c" "$RAW/r10-journal.json")"
    run "journalctl --no-pager -k -o short-monotonic --after-cursor='$c' | grep -iE 'oom|Killed|Out of memory' | head -30"
    run "python3 $PY/patterns.py < $RAW/r10-journal.json" | tee "$STATE/r10.pat"
    if grep -q "SUMMARY .*'constraint': 'CONSTRAINT_NONE'" "$STATE/r10.pat" && ! grep -q "SUMMARY .*'memcg'" "$STATE/r10.pat" && grep -q "KILLED .*'what': 'Out of memory'" "$STATE/r10.pat"; then
        verdict MATCH "CONSTRAINT_NONE with global_oom; 'Out of memory:' prefix; oom_kill +$((k1-k0)); $(grep ^COUNTS "$STATE/r10.pat")"
    else verdict MISMATCH "oom_kill +$((k1-k0)); $(grep ^COUNTS "$STATE/r10.pat")"; fi
}
row11() {
    local how
    if ensure_zram || [ -n "$(swapon --show --noheadings)" ]; then how=anon; else how=file; fi
    run "swapon --show"
    local cgpath=system.slice/spike-r11.scope
    note "baseline 4 s, then a cgroup thrashing at its own limit for 25 s ($how)"
    {
        for i in 1 2 3 4; do echo "base $(date +%s) machine: $(head -1 /proc/pressure/memory)"; sleep 1; done
    } > "$STATE/r11.log"
    if [ $how = anon ]; then
        systemd-run --quiet --scope --unit spike-r11 -p MemoryHigh=64M -p MemoryMax=256M -p MemorySwapMax=2G python3 $PY/alloc.py thrash 160 25 > "$STATE/r11.run" 2>&1 &
    else
        dd if=/dev/urandom of=/var/tmp/spike-r11.bin bs=1M count=300 status=none
        systemd-run --quiet --scope --unit spike-r11 -p MemoryMax=64M bash -c 'end=$((SECONDS+25)); while [ $SECONDS -lt $end ]; do cat /var/tmp/spike-r11.bin > /dev/null; done' > "$STATE/r11.run" 2>&1 &
    fi
    local sp=$!; sleep 1
    local cg=/sys/fs/cgroup$(systemctl show -p ControlGroup --value spike-r11.scope)
    for i in $(seq 1 22); do
        echo "load $(date +%s) machine: $(head -1 /proc/pressure/memory) | cgroup: $(head -1 $cg/memory.pressure 2>/dev/null) | cur=$(cat $cg/memory.current 2>/dev/null) swap=$(cat $cg/memory.swap.current 2>/dev/null)" >> "$STATE/r11.log"
        sleep 1
    done
    cat "$STATE/r11.log"
    wait $sp; cat "$STATE/r11.run"; rm -f /var/tmp/spike-r11.bin
    local m0 m1 g0 g1 ma
    m0=$(grep '^base' "$STATE/r11.log" | head -1 | grep -o 'total=[0-9]*' | head -1 | cut -d= -f2)
    m1=$(grep '^load' "$STATE/r11.log" | tail -1 | grep -o 'machine: some[^|]*' | grep -o 'total=[0-9]*' | cut -d= -f2)
    g0=$(grep '^load' "$STATE/r11.log" | head -1 | grep -o 'cgroup: some.*' | grep -o 'total=[0-9]*' | cut -d= -f2)
    g1=$(grep '^load' "$STATE/r11.log" | tail -1 | grep -o 'cgroup: some.*' | grep -o 'total=[0-9]*' | cut -d= -f2)
    ma=$(grep '^load' "$STATE/r11.log" | grep -o 'machine: some avg10=[0-9.]*' | cut -d= -f2 | sort -n | tail -1)
    local dm=$(( (${m1:-0} - ${m0:-0}) / 1000 )) dg=$(( (${g1:-0} - ${g0:-0}) / 1000 ))
    if [ $dm -gt 0 ] && [ $dg -gt 0 ]; then verdict MATCH "both rise: machine some total +${dm} ms (max avg10 $ma), cgroup some total +${dg} ms over ~22 s ($how thrash)"
    else verdict MISMATCH "machine +${dm} ms, cgroup +${dg} ms ($how thrash)"; fi
}
row12() {
    ensure_users
    local c; c=$(cat "$STATE/r8.cursor" 2>/dev/null); [ -n "$c" ] || c=$(cat "$STATE/start.cursor" 2>/dev/null)
    run "id spikej"; run "ls -ld /var/log/journal /run/log/journal; grep -h '^Storage' /etc/systemd/journald.conf /etc/systemd/journald.conf.d/* 2>/dev/null"
    note "as spikej (member of systemd-journal only), the journalctl line of section 5.5 without -f, from the cursor saved before row 8"
    T=30 run "runuser -u spikej -- journalctl --no-pager -o json --after-cursor='$c' _TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service + _SYSTEMD_UNIT=earlyoom.service > $RAW/r12-spikej.json; echo rc=\$?; wc -l < $RAW/r12-spikej.json"
    run "python3 $PY/patterns.py -q < $RAW/r12-spikej.json | tail -4" | tee "$STATE/r12.pat"
    local last; last=$(tail -1 "$RAW/r12-spikej.json" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["__CURSOR"])' 2>/dev/null)
    echo "spike-r12 resume marker $$" > /dev/kmsg
    sleep 1
    T=30 run "runuser -u spikej -- journalctl --no-pager -o json --after-cursor='$last' _TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service + _SYSTEMD_UNIT=earlyoom.service | python3 -c 'import json,sys; [print(json.loads(l)[\"MESSAGE\"]) for l in sys.stdin]'" | tee "$STATE/r12.resume"
    note "the same with -f for 4 s (the logger's form)"
    T=10 run "timeout 4 runuser -u spikej -- journalctl -f -o json --after-cursor='$last' _TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service | wc -l"
    note "as nobody (not in the group)"
    T=20 run "runuser -u nobody -- journalctl --no-pager -k -n 3"
    local kl; kl=$(grep -c 'Killed process' "$RAW/r12-spikej.json")
    if [ "$kl" -ge 1 ] && grep -q "spike-r12 resume marker $$" "$STATE/r12.resume" && [ "$(grep -vc -e '^\$' -e '^\[exit' "$STATE/r12.resume")" -le 2 ]; then
        verdict MATCH "group member sees kernel OOM lines ($kl 'Killed process'); --after-cursor resumes with exactly the new line"
    else verdict MISMATCH "Killed-process lines seen: $kl; resume output: $(grep -v '^\$' "$STATE/r12.resume" | head -3 | tr '\n' ' ')"; fi
}
row13() {
    local c; c=$(cat "$STATE/start.cursor" 2>/dev/null)
    run "journalctl --version | head -1"
    T=30 run "journalctl --no-pager --after-cursor='$c' -o json _TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service + _SYSTEMD_UNIT=earlyoom.service | head -c 200; echo; exit \${PIPESTATUS[0]}" | tee "$STATE/r13a"
    T=15 run "timeout 3 journalctl -f -o json --after-cursor='$c' _TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service > /dev/null; echo rc=\$? '(124 = still following: accepted)'" | tee "$STATE/r13b"
    note "does --after-cursor return every entry after the cursor? 5 rounds: take the cursor of the newest entry, write 3 kernel lines, read after the cursor"
    local i lost=0 c2 got
    for i in 1 2 3 4 5; do
        logger -t spike-r13 "anchor $i $$"; sleep 0.5; c2=$(cursor_now)
        echo "spike-r13 kmsg $i a $$" > /dev/kmsg; echo "spike-r13 kmsg $i b $$" > /dev/kmsg; echo "spike-r13 kmsg $i c $$" > /dev/kmsg
        sleep 1; journalctl --sync 2>/dev/null
        got=$(journalctl --no-pager -o cat --after-cursor="$c2" _TRANSPORT=kernel 2>/dev/null | grep -c "spike-r13 kmsg $i . $$")
        echo "round $i: $got of 3 kernel lines after the cursor; -k form: $(journalctl --no-pager -o cat -k --after-cursor="$c2" 2>/dev/null | grep -c "spike-r13 kmsg $i . $$") of 3"
        [ "$got" = 3 ] || lost=$((lost+1))
    done 2>&1 | tee "$STATE/r13c"
    lost=$(grep -c -v ': 3 of 3 kernel lines after the cursor; -k form: 3 of 3' "$STATE/r13c")
    note "the same with the cursor of a matching (kernel) entry, as the logger stores it"
    for i in 1 2 3; do
        echo "spike-r13 anchor-k $i $$" > /dev/kmsg; sleep 0.5; journalctl --sync 2>/dev/null
        c2=$(journalctl --no-pager -n 1 -o json _TRANSPORT=kernel | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["__CURSOR"])')
        echo "spike-r13 kmsgk $i a $$" > /dev/kmsg; echo "spike-r13 kmsgk $i b $$" > /dev/kmsg; sleep 1; journalctl --sync 2>/dev/null
        echo "matching-cursor round $i: $(journalctl --no-pager -o cat --after-cursor="$c2" _TRANSPORT=kernel + _SYSTEMD_UNIT=systemd-oomd.service 2>/dev/null | grep -c "spike-r13 kmsgk $i . $$") of 2"
    done 2>&1 | tee "$STATE/r13d"
    if grep -q '^\[exit 0\]' "$STATE/r13a" && grep -q 'rc=124' "$STATE/r13b" && [ "$lost" = 0 ]; then verdict MATCH "accepted on systemd $(journalctl --version | head -1 | awk '{print $2}'); --after-cursor returned every new entry in 5 of 5 rounds; with a matching cursor: $(grep -o '[0-9] of 2' "$STATE/r13d" | tr '\n' ' ')"
    else verdict MISMATCH "systemd $(journalctl --version | head -1 | awk '{print $2}'): options accepted=$(grep -q '^\[exit 0\]' "$STATE/r13a" && echo yes || echo no), -f=$(grep -o 'rc=[0-9]*' "$STATE/r13b"); rounds with lost entries: $lost of 5 ($(grep -o 'round [0-9]: [0-9] of 3[^;]*; -k form: [0-9] of 3' "$STATE/r13c" | head -2 | tr '\n' ' ')...); with the cursor of a matching kernel entry: $(grep -o '[0-9] of 2' "$STATE/r13d" | tr '\n' ' ')"; fi
}
row14() {
    ensure_oomph_accounts
    local d=$STATE/units; mkdir -p "$d"; cp "$SPIKE"/units/* "$d"/
    T=60 run "systemd-analyze verify $d/oomphd.service" | tee "$STATE/r14v"
    local sv; sv=$(systemctl --version | head -1 | awk '{print $2}')
    CAP=30000 T=60 run "systemd-analyze security --offline=true $d/oomphd.service" > "$STATE/r14s" 2>&1
    if grep -qiE 'unrecognized option|unknown option|invalid option' "$STATE/r14s"; then
        cat "$STATE/r14s" | tail -3
        note "systemd $sv has no --offline: installing the draft and analysing the loaded unit"
        cp "$d/oomphd.service" /etc/systemd/system/oomphd.service; systemctl daemon-reload
        CAP=30000 T=60 run "systemd-analyze security oomphd.service" > "$STATE/r14s" 2>&1
    fi
    grep -vE '^\+ ' "$STATE/r14s"
    T=30 run "systemd-analyze syscall-filter @system-service | head -12; echo ...; systemd-analyze syscall-filter @system-service | grep -nE '@ipc|@debug|process_vm|process_madvise|kcmp|pidfd_getfd|ptrace'; echo '--- @ipc:'; systemd-analyze syscall-filter @ipc | grep -E 'process_vm|process_madvise'; echo '--- @debug:'; systemd-analyze syscall-filter @debug | grep -E 'ptrace|pidfd_getfd|process_vm'" | tee "$STATE/r14f"
    local exp; exp=$(grep -o 'Overall exposure level for [^:]*: [0-9.]*' "$STATE/r14s" | awk '{print $NF}')
    local vok=no; [ "$(grep -vE '^\$|^\[exit' "$STATE/r14v" | grep -c 'oomphd')" -eq 0 ] && vok=yes
    local fok=no; grep -qE '^[0-9]+:.*@ipc' "$STATE/r14f" && sed -n '/--- @ipc/,/--- @debug/p' "$STATE/r14f" | grep -q process_vm_readv && fok=yes
    local eok=no; [ -n "$exp" ] && awk "BEGIN{exit !($exp <= 2.5)}" && eok=yes
    local s="verify clean=$vok; exposure=${exp:-?} (<=2.5: $eok); @system-service includes @ipc which lists process_vm_readv=$fok; systemd $sv"
    [ $vok = yes ] && [ $eok = yes ] && [ $fok = yes ] && verdict MATCH "$s" || verdict MISMATCH "$s; verify said about oomphd: $(grep -vE '^\$|^\[exit' "$STATE/r14v" | grep oomphd | head -3 | tr '\n' ' ')"
}
row15() {
    ensure_oomph_accounts; ensure_helpers
    cp "$PY/unit_probe.py" $LX/oomphd.py; chmod 644 $LX/oomphd.py
    cp "$SPIKE/units/oomphd.service" /etc/systemd/system/oomphd.service; systemctl daemon-reload
    rm -f /var/log/oomph/samples.jsonl /var/log/oomph/probe-*
    T=30 run "systemctl restart oomphd.service; sleep 9; systemctl status oomphd.service --no-pager | head -15"
    local pid; pid=$(systemctl show -p MainPID --value oomphd.service)
    echo "MainPID=$pid"
    run "grep -E 'Uid|Gid|Groups|CapEff|CapBnd|CapPrm|CapAmb|NoNewPrivs|Seccomp' /proc/$pid/status" | tee "$STATE/r15st"
    run "cat /proc/$pid/net/dev"
    run "ls -l /var/log/oomph; wc -l /var/log/oomph/samples.jsonl"
    run "cat /var/log/oomph/probe-status.json /var/log/oomph/probe-psi.txt /var/log/oomph/probe-journal.json"
    run "cat /var/log/oomph/probe-loginctl.txt"
    run "ps -o pid,ppid,user,group,args --ppid $pid"
    run "journalctl -u oomphd.service --no-pager -n 20"
    local ce cb nn sc ns jl lc
    ce=$(awk '/^CapEff/{print $2}' "$STATE/r15st"); cb=$(awk '/^CapBnd/{print $2}' "$STATE/r15st")
    nn=$(awk '/^NoNewPrivs/{print $2}' "$STATE/r15st"); sc=$(awk '/^Seccomp:/{print $2}' "$STATE/r15st")
    ns=$(wc -l < /var/log/oomph/samples.jsonl 2>/dev/null); jl=$(grep -o '"child_alive": [a-z]*' /var/log/oomph/probe-journal.json 2>/dev/null)
    lc=$(sed -n '2p' /var/log/oomph/probe-loginctl.txt 2>/dev/null)
    local s="CapEff=$ce CapBnd=$cb NoNewPrivs=$nn Seccomp=$sc samples=${ns:-0} journalctl-child[$jl] loginctl[$lc] psi[$(cat /var/log/oomph/probe-psi.txt 2>/dev/null)]"
    if [ "$ce" = 0000000000000000 ] && [ "$cb" = 0000000000000000 ] && [ "$nn" = 1 ] && [ "$sc" = 2 ] && [ "${ns:-0}" -ge 2 ] && [ "$jl" = '"child_alive": true' ] && [ "$lc" = "exit 0" ]; then
        verdict MATCH "$s"; else verdict MISMATCH "$s"; fi
}
row16() {
    ensure_oomph_accounts; ensure_helpers
    chown oomphd /var/lib/oomph/share   # so that only the sandbox can stop the write
    rm -f "$STATE/r16.out"
    draft_unit spike-neg "/usr/bin/python3 -I -B $PY/negprobe.py - /etc /var/lib/oomph/share /var/log/oomph /tmp" "$STATE/r16.out"
    T=60 run "systemctl start spike-neg.service; systemctl is-failed spike-neg.service"
    run "cat $STATE/r16.out"
    chown oomph-share /var/lib/oomph/share
    run "systemctl show -p SystemCallFilter oomphd.service | tr ' ' '\n' | grep -nE '^(process_vm_readv|process_vm_writev|process_madvise|kcmp|pidfd_getfd|ptrace)\$' ; echo '(no lines above = none of the six is in the allow list)'" | tee "$STATE/r16f"
    run "systemd-analyze syscall-filter @system-service | grep -c process_vm_readv"
    local bad=""
    for p in "readlink /proc/1/exe" "open /proc/1/mem" "socket AF_INET " "socket AF_INET6" "create file in /etc" "create file in /var/lib/oomph/share" "process_vm_readv" "ptrace"; do
        grep -F "$p" "$STATE/r16.out" | grep -q '^REFUSED' || bad="$bad [$p not refused]"
    done
    grep -F "create file in /var/log/oomph" "$STATE/r16.out" | grep -q '^ALLOWED' || bad="$bad [cannot write its own logs]"
    grep -qE '^[0-9]+:' "$STATE/r16f" && bad="$bad [an excluded call is in SystemCallFilter]"
    [ -s "$STATE/r16.out" ] || bad="no probe output"
    [ -z "$bad" ] && verdict MATCH "every negative probe refused; its own log directory writable; $(grep NETDEV "$STATE/r16.out")" || verdict MISMATCH "$bad"
}
row17() {
    ensure_users
    note "making a logind session: su -l spikea in the background (PAM opens a session)"
    (su -l spikea -c 'sleep 60' >/dev/null 2>&1 &) ; sleep 3
    run "loginctl list-sessions --no-legend" | tee "$STATE/r17l"
    local ids; ids=$(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}' | tr '\n' ' ')
    [ -n "$ids" ] && run "loginctl show-session $ids -p Id -p Type -p Class -p Remote -p Active -p State -p TTY -p IdleHint -p IdleSinceHint -p LockedHint" | tee "$STATE/r17s"
    run "systemd-inhibit --list --no-legend"
    local miss="" p
    for p in Type Class Remote Active State TTY IdleHint IdleSinceHint LockedHint; do grep -q "^$p=" "$STATE/r17s" 2>/dev/null || miss="$miss $p"; done
    pkill -u spikea sleep 2>/dev/null
    [ -n "$ids" ] && [ -z "$miss" ] && verdict MATCH "sessions: $ids; all nine properties present" || verdict MISMATCH "sessions: '$ids'; missing:$miss"
}
row18() {
    ensure_users
    getent group spikesgg >/dev/null && { gpasswd -d spikesg spikesgg >/dev/null 2>&1; }
    getent group spikesgg >/dev/null || groupadd spikesgg
    rm -f "$STATE/r18.go"; chmod 755 "$OUT" "$STATE"
    cat > "$STATE/r18-old.sh" <<'SHEOF'
echo "old login before the change: $(id)"
while [ ! -e "$1/r18.go" ]; do sleep 0.2; done
echo "--- same process after usermod: $(id)"
echo "--- 1: sg spikesgg -c 'id; ps' with no terminal, stdin /dev/null"
timeout 10 setsid sg spikesgg -c 'id; ps -o pid,ppid,gid,args -p $$ -p $PPID' < /dev/null 2>&1; echo "rc=$?"
echo "--- 2: exec or fork? sg spikesgg -c 'exec sleep 3'"
sg spikesgg -c 'exec sleep 3' < /dev/null & sp=$!; sleep 1
ps -o pid,ppid,gid,comm,args -p $sp --ppid $sp
wait $sp
echo "--- 3: helper shape: printf 'hello\n' | sg spikesgg -c 'exec cat'"
s=$(date +%s.%N); printf 'hello\n' | timeout 10 sg spikesgg -c 'exec cat'; echo "rc=$? after $(echo "$(date +%s.%N) - $s" | bc 2>/dev/null || echo '?') s"
SHEOF
    chmod 644 "$STATE/r18-old.sh"
    local c; c=$(cursor_now)
    local authlog=/var/log/auth.log; [ -f /var/log/secure ] && authlog=/var/log/secure
    local a0; a0=$(wc -l < $authlog 2>/dev/null)
    su spikesg -s /bin/bash -c "bash $STATE/r18-old.sh $STATE" > "$STATE/r18.out" 2>&1 &
    local sp=$!; sleep 2
    usermod -aG spikesgg spikesg; echo "added spikesg to spikesgg: $(getent group spikesgg)"
    touch "$STATE/r18.go"
    T=40 run "timeout 35 tail --pid=$sp -f /dev/null; cat $STATE/r18.out"
    cat "$STATE/r18.out" > /dev/null
    journalctl --sync 2>/dev/null
    run "journalctl --no-pager --after-cursor='$c' | grep -iE 'sg\\b|sg\\[|newgrp|spikesg|group' | grep -v 'usermod\\|gpasswd\\|groupadd' | head -20"
    run "tail -n +$((a0+1)) $authlog 2>/dev/null | grep -iE 'sg|newgrp|spikesg' | head -20"
    local logl; logl=$( { journalctl --no-pager --after-cursor="$c" 2>/dev/null; } | grep -ciE '(^| )sg\[|newgrp\[|switched to group|changed group')
    local g; g=$(getent group spikesgg | cut -d: -f3)
    local how=fork; grep -A3 -- '--- 2' "$STATE/r18.out" | grep -qE "^ *[0-9]+ .* sleep " && ! grep -A3 -- '--- 2' "$STATE/r18.out" | grep -qE ' sg ' && how=exec
    if grep -A2 -- '--- 1' "$STATE/r18.out" | grep -q "gid=$g(spikesgg)" && grep -q '^hello' "$STATE/r18.out" && grep -q 'rc=0 after' "$STATE/r18.out"; then
        verdict MATCH "sg printed the new group without asking; it ${how}s (see ps); the cat helper ended when its input closed; auth-log lines for 3 calls: $logl"
    else verdict MISMATCH "see output; sg ${how}s; log lines $logl"; fi
}
row19() {
    ensure_users
    run "sysctl fs.protected_hardlinks fs.protected_symlinks fs.protected_regular"
    run "runuser -u spikea -- ln /etc/hostname /tmp/spike-x; ls -l /tmp/spike-x 2>&1; rm -f /tmp/spike-x" | tee "$STATE/r19ln"
    local D=/var/tmp/spike-ledger V=/var/tmp/spike-victims
    rm -rf $D $V; mkdir -p $D $V; chmod 0777 $D; chown spikea $V; chmod 755 $V
    local res="" m who
    victim() { rm -f $V/victim; printf 'VICTIM FILE\n' > $V/victim; chown spikea $V/victim; chmod 644 $V/victim; sha256sum $V/victim | cut -c1-16; }
    note "static links (planted once), as spikea"
    for m in fstat byname; do
        local h0 h1; h0=$(victim); runuser -u spikea -- python3 $PY/hardlink.py static $D $V/victim $m; h1=$(sha256sum $V/victim | cut -c1-16)
        echo "static $m: victim $([ "$h0" = "$h1" ] && echo unchanged || echo CHANGED)"; res="$res static-$m:$([ "$h0" = "$h1" ] && echo ok || echo HIT)"
    done
    race() {  # race LABEL MODE WRITER-USER ATTACKER-USER
        local h0 h1; rm -f $D/*; h0=$(victim)
        runuser -u "$4" -- python3 $PY/hardlink.py attacker $D $V/victim 10 > "$STATE/r19.att" 2>&1 &
        local ap=$!
        if [ "$3" = root ]; then python3 $PY/hardlink.py writer $D "$2" 2000 9 $V/victim; else runuser -u "$3" -- python3 $PY/hardlink.py writer $D "$2" 2000 9 $V/victim; fi
        wait $ap; cat "$STATE/r19.att"
        h1=$(sha256sum $V/victim | cut -c1-16)
        python3 $PY/hardlink.py wellformed $D 2>&1
        echo "race $1 $2: victim $([ "$h0" = "$h1" ] && echo unchanged || echo "CHANGED ($(wc -l < $V/victim) lines)")"
        res="$res $1-$2:$([ "$h0" = "$h1" ] && echo ok || echo HIT)"
    }
    note "race a: writer and attacker the same user (spikea)"
    for m in fstat byname exclusive; do race same-user $m spikea spikea; done
    note "race b: writer root, victim owned by and attacker = the invoking user (spikea)"
    for m in fstat byname exclusive; do race root-writer $m root spikea; done
    local ph; ph=$(sysctl -n fs.protected_hardlinks)
    note "race c: fs.protected_hardlinks=0, writer spikea, attacker spikeb (a second account)"
    sysctl -qw fs.protected_hardlinks=0
    for m in fstat byname exclusive; do race second-account $m spikea spikeb; done
    sysctl -qw fs.protected_hardlinks=$ph
    note "with protected_hardlinks=$ph: can spikeb link spikea's 0644 file?"
    run "runuser -u spikeb -- ln $V/victim $D/x"
    rm -rf $D
    echo "RESULTS:$res"
    local refused=no; grep -q 'Operation not permitted' "$STATE/r19ln" && refused=yes
    local byname_ok=yes; echo "$res" | grep -q 'byname:HIT' && byname_ok=no
    local excl_ok=yes; echo "$res" | grep -q 'exclusive:HIT' && excl_ok=no
    local fstat_hit=no; echo "$res" | grep -qE '(same-user|root-writer|second-account)-fstat:HIT' && fstat_hit=yes
    local s="protected_hardlinks=$ph, ln /etc/hostname refused=$refused; by-name held in every race=$byname_ok; fstat-only raced=$fstat_hit; exclusive-file+rename held=$excl_ok;$res"
    if [ $refused = yes ] && [ $byname_ok = yes ] && [ $fstat_hit = yes ]; then verdict MATCH "$s"
    elif [ $byname_ok = no ]; then verdict MISMATCH "$s"
    else verdict PARTIAL "$s"; fi
}
row20() {
    command -v docker >/dev/null || { notrun "no docker on this system"; return; }
    T=180 run "docker run -d --name spikeweb nginx:alpine"
    sleep 3
    local pid; pid=$(docker inspect -f '{{.State.Pid}}' spikeweb 2>/dev/null)
    run "docker info --format '{{.CgroupDriver}} {{.CgroupVersion}}'"
    run "cat /proc/$pid/cgroup; grep -E 'Name|NSpid' /proc/$pid/status; cat /proc/$pid/comm; tr '\\0' ' ' < /proc/$pid/cmdline; echo"
    local cgd; cgd=$(cut -d: -f3 /proc/$pid/cgroup)
    run "for p in \$(cat /sys/fs/cgroup$cgd/cgroup.procs); do echo \"\$p \$(cat /proc/\$p/comm) \$(grep NSpid /proc/\$p/status)\"; done"
    local pod=none conmon=""
    if command -v podman >/dev/null; then
        T=180 run "podman run -d --name devdb docker.io/library/redis:alpine"
        sleep 3
        local pp; pp=$(podman inspect -f '{{.State.Pid}}' devdb 2>/dev/null)
        run "cat /proc/$pp/cgroup; grep NSpid /proc/$pp/status"
        run "ps -o pid,args -C conmon | cut -c1-600" | tee "$STATE/r20c"
        conmon=$(grep -c -- '-n devdb' "$STATE/r20c")
        pod=$(cut -d: -f3 /proc/$pp/cgroup)
        if [ -n "$SUDO_USER" ]; then
            note "rootless podman as $SUDO_USER"
            T=180 run "sudo -u $SUDO_USER -H podman run -d --name rootlessdb docker.io/library/alpine sleep 300"
            sleep 2; local rp; rp=$(sudo -u $SUDO_USER -H podman inspect -f '{{.State.Pid}}' rootlessdb 2>/dev/null)
            run "cat /proc/$rp/cgroup; grep NSpid /proc/$rp/status"
            sudo -u $SUDO_USER -H podman rm -f rootlessdb >/dev/null 2>&1
        fi
        podman rm -f devdb >/dev/null 2>&1
    else echo "podman: not installed"; fi
    run "ls -ld /var/lib/docker/containers /var/log/pods; runuser -u nobody -- ls /var/lib/docker/containers | head -3"
    local nsp; nsp=$(grep NSpid /proc/$pid/status 2>/dev/null | awk '{print $NF}')
    docker rm -f spikeweb >/dev/null 2>&1
    local d=no; echo "$cgd" | grep -qE 'docker-[0-9a-f]{64}\.scope|/docker/[0-9a-f]{64}' && d=yes
    local s="docker cgroup=$cgd ($d); init NSpid ends in ${nsp:-?}; podman cgroup=$pod; conmon carries '-n devdb': ${conmon:-n/a}"
    if [ $d = yes ] && [ "$(echo "$pod" | grep -c libpod-)" = 1 ] && [ "${conmon:-0}" -ge 1 ]; then verdict MATCH "$s"; else verdict PARTIAL "$s"; fi
}
row21() {
    run "grep -h secure_path /etc/sudoers /etc/sudoers.d/* 2>/dev/null"
    if [ -n "$SUDO_USER" ]; then run "sudo -u $SUDO_USER sudo sh -c 'echo \$PATH'"; else run "sudo sh -c 'echo \$PATH'"; fi
    local here; here=$(sudo sh -c 'echo $PATH' 2>/dev/null)
    local rocky=""
    if command -v docker >/dev/null && [ "$MODE" = runner ]; then
        T=300 run "docker run --rm rockylinux:9 bash -c 'dnf -y -q install sudo >/dev/null 2>&1; grep secure_path /etc/sudoers; sudo sh -c \"echo \\\$PATH\"'" | tee "$STATE/r21r"
        rocky=$(grep -E '^/' "$STATE/r21r" | tail -1)
    fi
    local id; id=$(. /etc/os-release; echo $ID)
    local s="this system ($id): sudo PATH=$here; rockylinux:9 container: ${rocky:-not run}"
    case "$id" in rocky|rhel|almalinux) here_has=$(echo "$here" | grep -c /usr/local/bin); [ "$here_has" = 0 ] && verdict MATCH "$s" || verdict MISMATCH "$s";;
        *) if [ -n "$rocky" ]; then echo "$rocky" | grep -q /usr/local/bin && verdict MISMATCH "$s" || verdict MATCH "$s"; else verdict INFO "$s"; fi;; esac
}
row22() {
    [ "$MODE" = runner ] || { notrun "needs Claude Code installed from the network; runner row"; return; }
    local u=${SUDO_USER:-runner}
    note "native install (claude.ai/install.sh) as $u"
    T=300 run "sudo -u $u -H bash -c 'curl -fsSL https://claude.ai/install.sh | bash' 2>&1 | tail -5"
    local nb; nb=$(sudo -u $u -H bash -c 'ls -l ~/.local/bin/claude 2>/dev/null; readlink -f ~/.local/bin/claude')
    echo "$nb"
    probe_claude() {  # probe_claude LABEL CMD
        sudo -u $u -H bash -c "cd /tmp && timeout 15 script -qfc '$2' /dev/null > /dev/null 2>&1 &"
        sleep 8
        echo "--- $1: processes whose cmdline mentions claude:"
        local p
        for p in $(pgrep -u $u -f claude); do
            [ "$(cat /proc/$p/comm 2>/dev/null)" = script ] && continue
            echo "pid $p comm=$(cat /proc/$p/comm 2>/dev/null) exe=$(readlink /proc/$p/exe 2>/dev/null) args=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | cut -c1-160)"
        done | tee "$STATE/r22-$1"
        pkill -u $u -f claude 2>/dev/null; pkill -u $u script 2>/dev/null; sleep 1
    }
    probe_claude native "\$HOME/.local/bin/claude"
    note "npm install -g @anthropic-ai/claude-code"
    T=300 run "npm install -g @anthropic-ai/claude-code 2>&1 | tail -3; ls -l \$(npm prefix -g)/bin/claude"
    local nbin; nbin=$(npm prefix -g 2>/dev/null)/bin/claude
    probe_claude npm "$nbin"
    local a b; a=$(grep -o 'comm=[^ ]*' "$STATE/r22-native" | sort | uniq -c | tr '\n' ' '); b=$(grep -o 'comm=[^ ]*' "$STATE/r22-npm" | sort | uniq -c | tr '\n' ' ')
    local s="native: $a; npm: $b"
    if grep -q 'comm=claude' "$STATE/r22-native" && grep -q 'comm=claude' "$STATE/r22-npm"; then verdict MATCH "$s"
    elif [ -z "$a$b" ]; then verdict NOT-RUN "claude did not stay up long enough to be seen: $s"
    else verdict MISMATCH "$s"; fi
}
row23() {
    local tools="python3 sg newgrp loginctl journalctl systemd-inhibit systemd-run setfacl sudo runuser"
    echo "--- this system:"
    [ -f "$RAW/preinstall-tools.txt" ] && { echo "(before the harness installed packages:)"; cat "$RAW/preinstall-tools.txt"; }
    for t in $tools; do printf '%s=%s ' $t "$(command -v $t || echo MISSING)"; done; echo
    python3 -c "import fcntl, secrets, shlex, grp, sys; print('python', sys.version.split()[0], 'imports ok')" 2>&1
    if [ "$MODE" = runner ] && command -v docker >/dev/null; then
        local imgs="debian:12 debian:13 ubuntu:22.04 ubuntu:24.04 rockylinux:9 fedora:latest opensuse/leap:15 amazonlinux:2023 alpine:latest"
        [ "$ARCH" = x86_64 ] && imgs="$imgs archlinux:latest"
        local i
        for i in $imgs; do
            echo "--- image $i:"
            timeout 180 docker run --rm "$i" sh -c "for t in $tools; do printf '%s=%s ' \$t \"\$(command -v \$t || echo MISSING)\"; done; echo; python3 -c 'import fcntl, secrets, shlex, grp, sys; print(\"python\", sys.version.split()[0], \"imports ok\")' 2>&1 | tail -1" 2>&1 | tail -3
        done | tee "$STATE/r23"
    fi
    verdict INFO "per image above; missing tools: $(grep -o '[a-z0-9-]*=MISSING' "$STATE/r23" 2>/dev/null | sort | uniq -c | awk '{printf "%s x%s, ", $2, $1}')"
}
row24() {
    ulimit -u unlimited 2>/dev/null
    local base n; base=$(ls /proc | grep -c '^[0-9]')
    echo "processes before: $base"
    spawn_to() { local want=$1 have; have=$(ls /proc | grep -c '^[0-9]'); local k=$((want - have)); [ $k -gt 0 ] || return 0
        python3 -c "
import os, signal, sys
for i in range($k):
    if os.fork() == 0:
        os.execvp('sleep', ['sleep', '6017'])
" ; sleep 2; }
    spawn_to 500
    T=120 run "python3 $PY/scan.py; runuser -u nobody -- python3 $PY/scan.py" | tee "$STATE/r24a"
    local r5k=""
    if [ "$MODE" = runner ]; then spawn_to 5000; T=180 run "python3 $PY/scan.py; runuser -u nobody -- python3 $PY/scan.py" | tee "$STATE/r24b"; fi
    pkill -f 'sleep 6017'
    local a b; a=$(grep -o 'MEDIAN_COLD_MS=[0-9.]* MEDIAN_WARM_MS=[0-9.]* N=[0-9]*' "$STATE/r24a" | head -1); b=$(grep -o 'MEDIAN_COLD_MS=[0-9.]* MEDIAN_WARM_MS=[0-9.]* N=[0-9]*' "$STATE/r24b" 2>/dev/null | head -1)
    local ca cb; ca=$(echo "$a" | sed 's/MEDIAN_COLD_MS=\([0-9.]*\).*/\1/'); cb=$(echo "$b" | sed 's/MEDIAN_COLD_MS=\([0-9.]*\).*/\1/')
    local ok=yes; awk "BEGIN{exit !(${ca:-999} < 60)}" || ok=no; [ -n "$cb" ] && { awk "BEGIN{exit !($cb < 600)}" || ok=no; }
    local s="~500: $a; ~5000: ${b:-not run (guest)}"
    [ $ok = yes ] && verdict MATCH "$s" || verdict MISMATCH "$s"
}
row25() {
    local rt=""
    command -v docker >/dev/null && rt="$rt docker"; command -v podman >/dev/null && rt="$rt podman"
    [ -n "$rt" ] || { notrun "no container runtime"; return; }
    getent group spikeL >/dev/null || groupadd spikeL
    local gid; gid=$(getent group spikeL | cut -d: -f3)
    local G=/var/lib/oomph-spike/ledger-group O=/var/lib/oomph-spike/ledger-open
    rm -rf /var/lib/oomph-spike; mkdir -p $G $O; chown root:spikeL $G; chmod 2770 $G; chmod 0777 $O; chmod 755 /var/lib/oomph-spike
    run "ls -ldn $G $O; command -v getenforce && getenforce; ls -dZ $G 2>/dev/null"
    local img=docker.io/library/python:3.12-alpine e
    for e in $rt; do
        [ "$e" = podman ] && [ "$MODE" = runner ] && [ -z "$SUDO_USER" ] && continue
        T=240 run "$e pull -q $img >/dev/null 2>&1; echo pulled"
        note "$e (rootful): group mode, uid 1000 with --group-add $gid"
        T=60 run "$e run --rm --user 1000:1000 --group-add $gid -v $G:/ledger $img sh -c 'touch /ledger/a-$e && echo wrote'"
        note "$e: group mode without --group-add"
        T=60 run "$e run --rm --user 1000:1000 -v $G:/ledger $img sh -c 'touch /ledger/b-$e && echo wrote'"
        note "$e: open mode, uid 1000"
        T=60 run "$e run --rm --user 1000:1000 -v $O:/ledger $img sh -c 'touch /ledger/c-$e && echo wrote'"
        note "$e: with :z (relabel)"
        T=60 run "$e run --rm --user 1000:1000 --group-add $gid -v $G:/ledger:z $img sh -c 'touch /ledger/d-$e && echo wrote'"
        note "$e: root inside, setuid(nobody) and write in open mode"
        T=60 run "$e run --rm -v $O:/ledger $img python3 -c \"import os; os.setgroups([]); os.setgid(65534); os.setuid(65534); print('now', os.getuid(), os.getgid()); open('/ledger/e-$e','w').write('x'); print('wrote')\""
    done
    if command -v podman >/dev/null && [ -n "$SUDO_USER" ]; then
        note "rootless podman as $SUDO_USER: open mode, root inside"
        T=240 run "sudo -u $SUDO_USER -H podman run --rm -v $O:/ledger $img sh -c 'id; touch /ledger/f-rootless && echo wrote'"
        note "rootless podman: group mode with --group-add keep-groups (the user is not in spikeL), and as uid 1000 inside"
        T=120 run "sudo -u $SUDO_USER -H podman run --rm --group-add keep-groups -v $G:/ledger $img sh -c 'id; touch /ledger/g-rootless && echo wrote'"
        T=120 run "sudo -u $SUDO_USER -H podman run --rm --user 1000:1000 -v $O:/ledger $img sh -c 'id; touch /ledger/h-rootless && echo wrote'"
        T=120 run "sudo -u $SUDO_USER -H podman run --rm -v $O:/ledger $img python3 -c \"import os; os.setgid(65534); os.setuid(65534); print('setuid ok', os.getuid())\""
    fi
    run "ls -ln $G $O"
    verdict INFO "see the per-case 'wrote' / errors above and the owners in ls -ln (runtimes:$rt)"
}
row26() {
    ensure_users
    [ -f "$RAW/preinstall-tools.txt" ] && run "grep -o 'setfacl=[^ ]*' $RAW/preinstall-tools.txt"
    local had; had=$(command -v setfacl || echo MISSING); echo "setfacl: $had"
    command -v setfacl >/dev/null || { pkg_install acl; echo "after installing acl: $(command -v setfacl || echo still missing)"; }
    command -v setfacl >/dev/null || { notrun "no setfacl"; return; }
    local D=/var/tmp/spike-acl; rm -rf $D; mkdir $D; chown root:spikeW $D; chmod 2770 $D
    run "setfacl -m g:spikeR:rX -m d:g:spikeR:rX $D && getfacl -p $D"
    cat > "$STATE/r26.py" <<'PYEOF'
import os, sys
d = sys.argv[1]
fd = os.open(d + "/f1", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o660); os.fchmod(fd, 0o660); os.write(fd, b"one\n"); os.close(fd)
fd = os.open(d + "/.tmp-1", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o660); os.write(fd, b"two\n"); os.fchmod(fd, 0o660); os.close(fd)
os.rename(d + "/.tmp-1", d + "/f2")
fd = os.open("/tmp/spike-f3", os.O_CREAT | os.O_TRUNC | os.O_WRONLY, 0o660); os.write(fd, b"three\n"); os.close(fd)
os.rename("/tmp/spike-f3", d + "/f3") if os.stat("/tmp").st_dev == os.stat(d).st_dev else print("f3: other file system, skipped")
print("writer done")
PYEOF
    chmod 644 "$STATE/r26.py"
    run "runuser -u spikea -- sh -c 'umask 022; python3 $STATE/r26.py $D'"
    run "getfacl -p $D/f1 $D/f2 $D/f3 2>&1; ls -l $D"
    run "runuser -u spikeb -- sh -c 'cat $D/f1 $D/f2'" | tee "$STATE/r26r"
    run "runuser -u spikeb -- sh -c 'touch $D/f4'" | tee "$STATE/r26w"
    run "runuser -u spikeb -- sh -c 'echo x >> $D/f1'" | tee "$STATE/r26a"
    local rd=no wr=no ap=no inh=no
    grep -q one "$STATE/r26r" && grep -q two "$STATE/r26r" && rd=yes
    grep -q 'Permission denied' "$STATE/r26w" || wr=yes
    grep -q 'Permission denied' "$STATE/r26a" || ap=yes
    getfacl -p $D/f1 2>/dev/null | grep -q 'group:spikeR:r' && getfacl -p $D/f2 2>/dev/null | grep -q 'group:spikeR:r' && inh=yes
    local s="setfacl before install: $had; reader reads=$rd, can create=$wr, can append=$ap; inherited entry on f1 (fchmod) and f2 (rename)=$inh"
    if [ $rd = yes ] && [ $wr = no ] && [ $ap = no ] && [ $inh = yes ]; then [ "$had" = MISSING ] && verdict PARTIAL "$s" || verdict MATCH "$s"
    else verdict MISMATCH "$s"; fi
}
row27() {
    ensure_oomph_accounts; ensure_helpers
    cp "$PY/gate_probe.py" $LX/oomph.py; chmod 644 $LX/oomph.py
    modprobe ipip 2>/dev/null
    local n
    for n in lan srv rtr peer far; do ip netns del $n 2>/dev/null; ip netns add $n; ip -n $n link set lo up; done
    ip -n lan link add br0 type bridge && ip -n lan link set br0 up
    ip link add l-srv netns lan type veth peer name s0 netns srv
    ip link add l-rtr netns lan type veth peer name r0 netns rtr
    ip link add l-peer netns lan type veth peer name p0 netns peer
    for n in srv rtr peer; do ip -n lan link set l-$n master br0 up; done
    ip link add r1 netns rtr type veth peer name f0 netns far
    ip -n srv addr add 10.77.1.1/24 dev s0; ip -n srv link set s0 up; ip -n srv route add default via 10.77.1.254
    ip -n rtr addr add 10.77.1.254/24 dev r0; ip -n rtr link set r0 up; ip -n rtr addr add 10.77.2.254/24 dev r1; ip -n rtr link set r1 up
    ip netns exec rtr sysctl -qw net.ipv4.ip_forward=1
    ip -n peer addr add 10.77.1.3/24 dev p0; ip -n peer link set p0 up; ip -n peer route add default via 10.77.1.254
    ip -n far addr add 10.77.2.2/24 dev f0; ip -n far link set f0 up; ip -n far route add default via 10.77.2.254
    ip -n srv tunnel add tun0 mode ipip local 10.77.1.1 remote 10.77.1.3 && ip -n srv addr add 10.77.9.1 peer 10.77.9.2 dev tun0 && ip -n srv link set tun0 up
    ip -n peer tunnel add tun0 mode ipip local 10.77.1.3 remote 10.77.1.1 && ip -n peer addr add 10.77.9.2 peer 10.77.9.1 dev tun0 && ip -n peer link set tun0 up
    run "ip -n srv -br addr; ip -n srv route; ip -n peer -br addr"
    # the drafts, plus NetworkNamespacePath= (test only: puts the listener and the service in the namespace 'srv')
    { sed '/^\[Socket\]/a NetworkNamespacePath=/run/netns/srv' "$SPIKE/units/oomph-share.socket"; } > /etc/systemd/system/oomph-share.socket
    { sed '/^\[Service\]/a NetworkNamespacePath=/run/netns/srv' "$SPIKE/units/oomph-share@.service"; } > /etc/systemd/system/oomph-share@.service
    systemctl daemon-reload
    run "cat /etc/systemd/system/oomph-share@.service"
    T=30 run "systemctl restart oomph-share.socket; systemctl status oomph-share.socket --no-pager | head -8"
    run "ip netns exec srv ping -c1 -W2 10.77.1.254 | tail -2; ip netns exec peer ping -c1 -W2 10.77.2.2 | tail -1; ip netns exec srv cat /proc/net/arp"
    note "same link: peer 10.77.1.3 -> 10.77.1.1"
    T=30 run "ip netns exec peer python3 $PY/gate_client.py 10.77.1.1 6674" | tee "$STATE/r27-same"
    note "routed: far 10.77.2.2 -> 10.77.1.1 through rtr"
    T=30 run "ip netns exec far python3 $PY/gate_client.py 10.77.1.1 6674" | tee "$STATE/r27-routed"
    note "tunnel: peer 10.77.9.2 -> 10.77.9.1 over ipip"
    T=30 run "ip netns exec peer python3 $PY/gate_client.py 10.77.9.1 6674" | tee "$STATE/r27-tunnel"
    run "journalctl --no-pager -n 20 -u 'oomph-share@*' -u oomph-share.socket"
    run "for i in /sys/class/net/*; do echo \"\${i##*/} \$(readlink -f \$i)\"; done"
    systemctl stop oomph-share.socket
    for n in lan srv rtr peer far; do ip netns del $n 2>/dev/null; done
    local sv rv tv errs
    sv=$(grep -o 'VERDICT on-link=[A-Za-z]* (ignoring the virtual rule: [A-Za-z]*' "$STATE/r27-same"); rv=$(grep -o 'VERDICT [^;]*' "$STATE/r27-routed" | head -1); tv=$(grep -o 'VERDICT [^;]*' "$STATE/r27-tunnel" | head -1)
    errs=$(cat "$STATE"/r27-* | grep -v 'AF_NETLINK socket' | grep -cE 'errno (97|1) |EXCEPTION|FAILED')
    local mac; mac=$(grep -o "router MAC [0-9a-f:]*" "$STATE/r27-same" | head -1)
    local hostif=no; grep -q 'if eth0 ' "$STATE/r27-same" && hostif=yes
    local s="sysfs shows the host's interfaces inside NetworkNamespacePath= (test artifact)=$hostif; same link: $sv, $mac; routed: $rv; tunnel: $tv; EAFNOSUPPORT/EPERM/exceptions: $errs; $(grep -o 'AF_NETLINK socket: [a-z]*' "$STATE/r27-same" | head -1)"
    if echo "$sv" | grep -q 'virtual rule: True' && echo "$rv" | grep -qE 'on-link=False' && echo "$tv" | grep -qE 'on-link=False|deny' && [ "$errs" = 0 ] && [ -n "$mac" ]; then verdict MATCH "$s"
    else verdict MISMATCH "$s"; fi
}
row28() {
    ensure_oomph_accounts; ensure_helpers
    local d=$STATE/units28; rm -rf $d; mkdir -p $d; cp "$SPIKE"/units/oomph-share* "$SPIKE"/units/oomph-alert* $d/
    cp $d/oomph-share@.service $d/oomph-share@probe.service
    mkdir -p /var/log/oomph/alerts
    [ -e /usr/local/bin/oomph ] || { printf '#!/bin/sh\nexit 0\n' > /usr/local/bin/oomph; chmod 755 /usr/local/bin/oomph; echo "(stub /usr/local/bin/oomph created for verify)"; }
    T=60 run "systemd-analyze verify $d/oomph-share.socket $d/oomph-share@.service" | tee "$STATE/r28v1"
    T=60 run "systemd-analyze verify $d/oomph-alert.path $d/oomph-alert.service" | tee "$STATE/r28v2"
    T=60 run "systemd-analyze security --offline=true $d/oomph-share@probe.service 2>&1 | tail -3; systemd-analyze security --offline=true $d/oomph-alert.service 2>&1 | tail -3" | tee "$STATE/r28s"
    if grep -qiE 'unrecognized option|unknown option|invalid option' "$STATE/r28s"; then
        cp $d/oomph-share@.service /etc/systemd/system/; cp $d/oomph-alert.service /etc/systemd/system/; systemctl daemon-reload
        T=60 run "systemd-analyze security oomph-share@probe.service | tail -2; systemd-analyze security oomph-alert.service | tail -2" | tee "$STATE/r28s"
    fi
    # world-writable test directories in logs and ledger: only the sandbox can stop a write there
    install -d -m 1777 /var/log/oomph/spike-open /var/lib/oomph/ledger/spike-open
    local dirs="/var/log/oomph /var/log/oomph/spike-open /var/lib/oomph/ledger /var/lib/oomph/ledger/spike-open /etc"
    { sed -e '/^ExecStart=/d' -e '/^StandardInput=/d' -e '/^StandardOutput=/d' -e '/^StandardError=/d' "$SPIKE/units/oomph-share@.service"
      echo "Type=oneshot"; echo "ExecStart=/usr/bin/python3 -I -B $PY/negprobe.py - $dirs"; echo "StandardOutput=file:$STATE/r28-share.out"; } > /etc/systemd/system/spike-share-neg.service
    { sed -e '/^ExecStart=/d' "$SPIKE/units/oomph-alert.service"
      echo "ExecStart=/usr/bin/python3 -I -B $PY/negprobe.py - $dirs"; echo "StandardOutput=file:$STATE/r28-alert.out"; } > /etc/systemd/system/spike-alert-neg.service
    rm -f "$STATE"/r28-*.out; systemctl daemon-reload
    T=60 run "systemctl start spike-share-neg.service; systemctl start spike-alert-neg.service; cat $STATE/r28-share.out; echo ====; cat $STATE/r28-alert.out"
    run "journalctl --no-pager -n 10 -u spike-share-neg.service -u spike-alert-neg.service"
    T=30 run "systemctl start oomph-alert.path 2>&1; systemctl is-active oomph-alert.path" 
    local bad="" f
    for f in share alert; do
        for p in "create file in /var/log/oomph/spike-open" "create file in /var/lib/oomph/ledger/spike-open" "create file in /etc" "create file in /var/log/oomph " "create file in /var/lib/oomph/ledger "; do
            grep -F "${p% }" "$STATE/r28-$f.out" 2>/dev/null | grep -F -- "${p% } " >/dev/null || true
        done
        grep '^ALLOWED  create file' "$STATE/r28-$f.out" >/dev/null 2>&1 && bad="$bad [$f: $(grep '^ALLOWED  create file' "$STATE/r28-$f.out" | sed 's/ALLOWED  create file in //; s/ ->.*//' | tr '\n' ' ')]"
        [ -s "$STATE/r28-$f.out" ] || bad="$bad [$f: no probe output]"
    done
    local v1=clean v2=clean
    [ "$(grep -vE '^\$|^\[exit' "$STATE/r28v1" | grep -c oomph)" -eq 0 ] || v1="$(grep -vE '^\$|^\[exit' "$STATE/r28v1" | grep oomph | head -2 | tr '\n' ' ')"
    [ "$(grep -vE '^\$|^\[exit' "$STATE/r28v2" | grep -c oomph)" -eq 0 ] || v2="$(grep -vE '^\$|^\[exit' "$STATE/r28v2" | grep oomph | head -2 | tr '\n' ' ')"
    local ex; ex=$(grep -o 'Overall exposure level for [^:]*: [0-9.]* [A-Z]*' "$STATE/r28s" | sed 's/Overall exposure level for //' | tr '\n' ';')
    local s="verify share: $v1; verify alert: $v2; exposure: $ex creates allowed:${bad:- none}"
    [ -z "$bad" ] && [ "$v1" = clean ] && [ "$v2" = clean ] && verdict MATCH "$s" || verdict MISMATCH "$s"
}
row29() {
    [ "$MODE" = guest ] || { notrun "needs a virtual-console login and a typing user; guest row"; return; }
    ensure_users
    local results=""
    # --- SSH
    if command -v sshd >/dev/null || [ -x /usr/sbin/sshd ]; then
        systemctl start ssh 2>/dev/null || systemctl start sshd 2>/dev/null
        rm -f /root/.ssh/spike /root/.ssh/spike.pub; mkdir -p /root/.ssh; ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/spike
        install -d -o spikea -g spikea -m 700 /home/spikea/.ssh; cp /root/.ssh/spike.pub /home/spikea/.ssh/authorized_keys; chown spikea: /home/spikea/.ssh/authorized_keys; chmod 600 /home/spikea/.ssh/authorized_keys
        ( sleep 3; echo 'echo typed-1'; sleep 30; echo 'echo typed-2'; sleep 6; echo exit ) | timeout 60 ssh -tt -i /root/.ssh/spike -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null spikea@127.0.0.1 > "$STATE/r29-ssh.out" 2>&1 &
        local sp=$! t0; t0=$(date +%s)
        sleep 6
        local sid; sid=$(loginctl list-sessions --no-legend | awk '$3=="spikea"{print $1}' | tail -1)
        local i
        for i in 1 2 3 4 5 6 7 8; do
            echo "t+$(( $(date +%s) - t0 ))s ssh session $sid: $(loginctl show-session $sid -p TTY -p IdleHint -p IdleSinceHint 2>&1 | tr '\n' ' ') | from a PrivateDevices unit: $(systemd-run --quiet --wait --pipe -p PrivateDevices=yes -p User=nobody loginctl show-session $sid -p IdleSinceHint 2>&1 | tr '\n' ' ')"
            sleep 5
        done | tee "$STATE/r29-ssh.log"
        wait $sp; echo "ssh output:"; tr -d '\r' < "$STATE/r29-ssh.out" | grep typed | head -5
        local u; u=$(grep -o 'IdleSinceHint=[0-9]*' "$STATE/r29-ssh.log" | cut -d= -f2 | sort -u | wc -l)
        results="$results ssh: $u distinct IdleSinceHint values over 40 s (2 keystroke bursts at ~3 s and ~33 s);"
    else results="$results ssh: no sshd;"; fi
    # --- virtual console: autologin on tty3, keys typed through uinput
    modprobe uinput 2>/dev/null
    local ag; ag=$(command -v agetty)
    if [ -e /dev/tty3 ] && [ -e /dev/uinput ] && [ -n "$ag" ]; then
        mkdir -p /etc/systemd/system/getty@tty3.service.d
        printf '[Service]\nExecStart=\nExecStart=-%s --autologin spikea --noclear %%I $TERM\n' "$ag" > /etc/systemd/system/getty@tty3.service.d/autologin.conf
        systemctl daemon-reload; systemctl restart getty@tty3.service; chvt 3; sleep 6
        local vid; vid=$(loginctl list-sessions --no-legend | awk '$3=="spikea"' | grep -w tty3 | awk '{print $1}' | tail -1)
        [ -n "$vid" ] || vid=$(for s in $(loginctl list-sessions --no-legend | awk '{print $1}'); do [ "$(loginctl show-session $s -p TTY --value)" = tty3 ] && echo $s; done | tail -1)
        echo "tty3 session: ${vid:-none}"
        run "loginctl list-sessions --no-legend"
        local t0; t0=$(date +%s)
        {
            echo "t+0 $(loginctl show-session $vid -p TTY -p IdleHint -p IdleSinceHint 2>&1 | tr '\n' ' ')"
            sleep 10; python3 $PY/uinput_type.py "echo typed-on-vt" 2>&1
            sleep 2; echo "t+$(( $(date +%s) - t0 )) after typing: $(loginctl show-session $vid -p TTY -p IdleHint -p IdleSinceHint 2>&1 | tr '\n' ' ')"
            sleep 12; python3 $PY/uinput_type.py "echo again" 2>&1
            sleep 2; echo "t+$(( $(date +%s) - t0 )) after typing again: $(loginctl show-session $vid -p TTY -p IdleHint -p IdleSinceHint 2>&1 | tr '\n' ' ') | from a PrivateDevices unit: $(systemd-run --quiet --wait --pipe -p PrivateDevices=yes -p User=nobody loginctl show-session $vid -p IdleSinceHint 2>&1 | tr '\n' ' ')"
            echo "tty3 atime: $(stat -c '%X %x' /dev/tty3)"
        } | tee "$STATE/r29-vt.log"
        local v; v=$(grep -o 'IdleSinceHint=[0-9]*' "$STATE/r29-vt.log" | cut -d= -f2 | sort -u | wc -l)
        results="$results vt: $v distinct IdleSinceHint values (3 readings, 2 typing bursts);"
        rm -rf /etc/systemd/system/getty@tty3.service.d; systemctl daemon-reload; chvt 1
    else results="$results vt: not available (tty3=$([ -e /dev/tty3 ] && echo y || echo n) uinput=$([ -e /dev/uinput ] && echo y || echo n));"; fi
    local su sv; su=$(echo "$results" | grep -o 'ssh: [0-9]*' | awk '{print $2}'); sv=$(echo "$results" | grep -o 'vt: [0-9]*' | awk '{print $2}')
    if [ "${su:-0}" -ge 2 ] && [ "${sv:-0}" -ge 2 ]; then verdict MATCH "$results"
    elif [ "${su:-0}" -ge 2 ] || [ "${sv:-0}" -ge 2 ]; then verdict PARTIAL "$results"
    else verdict MISMATCH "$results"; fi
}
row30() {
    rm -rf /run/spike-path /run/spike-path.log; mkdir -p /run/spike-path
    printf '[Path]\nPathChanged=/run/spike-path\n' > /etc/systemd/system/spike-path.path
    printf '[Service]\nType=oneshot\nExecStart=/bin/sh -c "date +%%s.%%N >> /run/spike-path.log; sleep 20"\n' > /etc/systemd/system/spike-path.service
    systemctl daemon-reload; systemctl start spike-path.path; sleep 1
    local t0; t0=$(date +%s.%N); echo "t0=$t0"
    touch /run/spike-path/a; echo "created a"
    sleep 5; touch /run/spike-path/b; echo "created b at +5 s"
    sleep 45
    run "cat /run/spike-path.log; systemctl status spike-path.path --no-pager | head -6; journalctl --no-pager -u spike-path.service -n 10"
    local n; n=$(wc -l < /run/spike-path.log 2>/dev/null)
    systemctl stop spike-path.path spike-path.service
    case "$n" in 1) verdict MATCH "one start: the file created while the service ran did not start it again";;
        2) verdict MISMATCH "two starts: the change during the run started the service again after it ended (the beat is unnecessary)";;
        *) verdict MISMATCH "$n starts";; esac
}
row31() {
    ensure_users
    runuser -u spikea -- bash -c 'sleep 101 & sleep 102 & wait' &
    sleep 2
    local pid; pid=$(pgrep -u spikea -n -x bash)
    echo "shell pid $pid"
    run "grep CONFIG_PROC_CHILDREN /boot/config-\$(uname -r)"
    run "ls -l /proc/$pid/task/$pid/children; runuser -u nobody -- cat /proc/$pid/task/$pid/children; echo" | tee "$STATE/r31"
    run "ps -o pid,ppid,user,args --ppid $pid"
    pkill -u spikea sleep
    local k; k=$(grep -oE '^[0-9]+ [0-9]+ ?$' "$STATE/r31" | wc -w)
    [ "$k" -ge 2 ] && verdict MATCH "readable by nobody, lists $k children" || verdict MISMATCH "$(grep -v '^\$' "$STATE/r31" | tail -3 | tr '\n' ' ')"
}
row32() {
    local secs=30
    printf '[Unit]\nStartLimitIntervalSec=0\n[Service]\nSlice=spike32.slice\nMemoryMax=32M\nMemorySwapMax=0\nRestart=always\nRestartSec=200ms\nExecStart=/usr/bin/python3 -c "x = bytearray(b\\"x\\") * (100 << 20)"\n' > /etc/systemd/system/spike-cl@.service
    systemctl daemon-reload
    local c k0 k1 i; c=$(cursor_now); k0=$(vmstat_oom)
    run "cat /etc/systemd/system/spike-cl@.service"
    for i in $(seq 1 20); do systemctl start --no-block spike-cl@$i.service; done
    sleep $secs
    local ev; ev=$(cat /sys/fs/cgroup/spike32.slice/memory.events 2>/dev/null)
    systemctl stop 'spike-cl@*.service' spike32.slice 2>/dev/null
    sleep 3; k1=$(vmstat_oom)
    echo "spike32.slice memory.events (hierarchical) before stop:"; echo "$ev"
    echo "/proc/vmstat oom_kill: $k0 -> $k1 (+$((k1-k0)))"
    echo "journal lines: $(journal_since "$c" "$RAW/r32-kernel.json" -k)"
    run "python3 $PY/patterns.py -q < $RAW/r32-kernel.json" | tee "$STATE/r32.pat"
    run "journalctl --no-pager -k --after-cursor='$c' | grep -iE 'suppressed|ratelimit' | head; journalctl --no-pager --after-cursor='$c' -u systemd-journald | tail -5"
    local inv su kl un evk
    inv=$(sed -n 's/.*INVOKED=\([0-9]*\).*/\1/p' "$STATE/r32.pat"); su=$(sed -n 's/.*SUMMARY=\([0-9]*\).*/\1/p' "$STATE/r32.pat")
    kl=$(sed -n 's/.* KILLED=\([0-9]*\).*/\1/p' "$STATE/r32.pat"); un=$(sed -n 's/.*KILLED_unprefixed=\([0-9]*\).*/\1/p' "$STATE/r32.pat")
    evk=$(echo "$ev" | awk '$1=="oom_kill"{print $2}')
    local s="in ${secs}s: INVOKED=$inv SUMMARY=$su KILLED=$kl (unprefixed $un); memory.events oom_kill=$evk; vmstat +$((k1-k0))"
    if [ "${su:-0}" -lt "${kl:-0}" ] && [ "${un:-1}" = 0 ]; then verdict MATCH "$s"; else verdict MISMATCH "$s"; fi
}
row33() {
    [ "$MODE" = guest ] || { notrun "fills the machine's memory; guest row"; return; }
    command -v earlyoom >/dev/null || { notrun "earlyoom not installable here: $(cat $RAW/earlyoom-install.txt 2>/dev/null | tail -2)"; return; }
    run "earlyoom -v 2>&1 | head -2; swapoff -a; free -m"
    T=30 run "systemctl restart earlyoom; sleep 3; systemctl status earlyoom --no-pager | head -12"
    local c; c=$(cursor_now)
    T=240 run "IGNORE_TERM=1 OOM_ADJ=1000 systemd-run --quiet --scope --unit spike-r33 python3 $PY/alloc.py grow 16 0.1 | tail -2"
    sleep 3
    echo "journal lines: $(journal_since "$c" "$RAW/r33-journal.json")"
    run "journalctl --no-pager --after-cursor='$c' -u earlyoom | tail -20"
    run "python3 $PY/patterns.py < $RAW/r33-journal.json" | tee "$STATE/r33.pat"
    systemctl stop earlyoom
    local t k; t=$(grep -c "EARLY .*'sig': 'SIGTERM'" "$STATE/r33.pat"); k=$(grep -c "EARLY .*'sig': 'SIGKILL'" "$STATE/r33.pat")
    local p1 p2; p1=$(grep "EARLY .*'sig': 'SIGTERM'" "$STATE/r33.pat" | grep -o "'pid': '[0-9]*'" | head -1); p2=$(grep "EARLY .*'sig': 'SIGKILL'" "$STATE/r33.pat" | grep -o "'pid': '[0-9]*'" | head -1)
    local s="SIGTERM lines=$t SIGKILL lines=$k pids $p1 / $p2; kernel KILLED=$(sed -n 's/.* KILLED=\([0-9]*\).*/\1/p' "$STATE/r33.pat")"
    if [ "$t" -ge 1 ] && [ "$k" -ge 1 ] && [ "$p1" = "$p2" ]; then verdict MATCH "$s"; else verdict MISMATCH "$s"; fi
}
row34() {
    [ "$MODE" = guest ] || { notrun "RHEL 9 / Debian 12 rows; run in the guests"; return; }
    run "head -3 /etc/os-release; uname -r; systemctl --version | head -1"
    run "command -v getenforce && getenforce; command -v sestatus && sestatus | head -5"
    run "systemctl is-active oomphd.service; pid=\$(systemctl show -p MainPID --value oomphd.service); grep -E 'CapEff|CapBnd|NoNewPrivs|Seccomp' /proc/\$pid/status; wc -l < /var/log/oomph/samples.jsonl" | tee "$STATE/r34"
    local avc="n/a"
    if command -v ausearch >/dev/null; then
        T=60 run "ausearch -m avc -ts boot 2>&1 | tail -30" | tee "$STATE/r34a"
        avc=$(grep -c 'type=AVC' "$STATE/r34a")
    fi
    local r; r=$(grep -h '^VERDICT' "$OUT"/rows/row-14.txt "$OUT"/rows/row-15.txt "$OUT"/rows/row-16.txt 2>/dev/null | cut -d'|' -f1 | tr '\n' ' ')
    local s="oomphd $(grep -m1 -E '^(active|inactive|failed)' "$STATE/r34"); rows 14-16 here: $r; AVC records since boot: $avc; SELinux: $(getenforce 2>/dev/null || echo none)"
    if grep -q '^active' "$STATE/r34" && grep -q 'CapEff:.0000000000000000' "$STATE/r34" && { [ "$avc" = n/a ] || [ "$avc" = 0 ]; }; then verdict MATCH "$s"; else verdict MISMATCH "$s"; fi
}
row35() {
    [ "$MODE" = guest ] || { notrun "needs machine-wide reclaim pressure; guest row"; return; }
    run "grep cgroup2 /proc/mounts"
    if [ -z "$(swapon --show --noheadings)" ]; then
        dd if=/dev/zero of=/var/tmp/spike-swap bs=1M count=1536 status=none; chmod 600 /var/tmp/spike-swap; mkswap /var/tmp/spike-swap >/dev/null; swapon /var/tmp/spike-swap
    fi
    run "swapon --show; free -m"
    local memmb; memmb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    phase() {  # phase LABEL
        systemctl stop spike-low.service 2>/dev/null
        systemd-run --quiet --unit spike-low -p MemoryLow=32M python3 $PY/alloc.py hold 96 600
        sleep 4
        local cg=/sys/fs/cgroup/system.slice/spike-low.service
        echo "[$1] before: system.slice memory.low=$(cat /sys/fs/cgroup/system.slice/memory.low) unit memory.low=$(cat $cg/memory.low) current=$(( $(cat $cg/memory.current)>>20 ))M swap=$(( $(cat $cg/memory.swap.current)>>20 ))M"
        OOM_ADJ=1000 timeout 90 systemd-run --quiet --scope --unit spike-hog-$1 python3 $PY/alloc.py grow 64 0.05 $((memmb + 900)) > /dev/null 2>&1 &
        local hp=$! i
        for i in $(seq 1 60); do sleep 1; grep -q . /sys/fs/cgroup/system.slice/spike-hog-$1.scope/memory.current 2>/dev/null || break
            [ $(( $(cat /sys/fs/cgroup/system.slice/spike-hog-$1.scope/memory.current 2>/dev/null || echo 0) >> 20 )) -gt $((memmb - 300)) ] && [ $i -gt 5 ] && { sleep 8; break; }
        done
        echo "[$1] under pressure: current=$(( $(cat $cg/memory.current)>>20 ))M swap=$(( $(cat $cg/memory.swap.current)>>20 ))M events: $(tr '\n' ' ' < $cg/memory.events)"
        systemctl stop spike-hog-$1.scope 2>/dev/null; kill $hp 2>/dev/null; wait $hp 2>/dev/null
        echo "RES $1 $(( $(cat $cg/memory.current)>>20 )) $(( $(cat $cg/memory.swap.current)>>20 ))"
        systemctl stop spike-low.service
    }
    phase unit-only | tee "$STATE/r35"
    systemctl set-property --runtime system.slice MemoryLow=128M
    phase with-slice | tee -a "$STATE/r35"
    systemctl set-property --runtime system.slice MemoryLow=0
    local a b; a=$(grep '\[unit-only\] under' "$STATE/r35" | grep -o 'current=[0-9]*' | cut -d= -f2); b=$(grep '\[with-slice\] under' "$STATE/r35" | grep -o 'current=[0-9]*' | cut -d= -f2)
    local s="resident under pressure: unit alone ${a:-?} MB of 96; with system.slice MemoryLow too ${b:-?} MB"
    if [ -n "$a" ] && [ -n "$b" ] && [ "$a" -lt 32 ] && [ "$b" -ge 30 ]; then verdict MATCH "$s"
    elif [ -n "$a" ] && [ "$a" -ge 30 ]; then verdict MISMATCH "$s (the unit alone kept its protection)"
    else verdict MISMATCH "$s"; fi
}

# --------------------------------------------------------------------------------------------- driver
title() { case $1 in
 1) echo "What the runner is";; 2) echo "/proc/meminfo and /proc/<pid>/status fields";; 3) echo "Footprint definition";;
 4) echo "zram mm_stat columns; zram in /proc/swaps";; 5) echo "Unprivileged PSI trigger";; 6) echo "The trigger under the unit";;
 7) echo "Per-cgroup PSI and limits world-readable";; 8) echo "A cgroup OOM, for real";; 9) echo "A group kill";;
 10) echo "A machine-wide OOM (QEMU guest)";; 11) echo "Machine-wide PSI while one cgroup thrashes";; 12) echo "Journal access by group";;
 13) echo "journalctl options";; 14) echo "The draft unit (verify, security, syscall-filter)";; 15) echo "The unit starts and can do its job";;
 16) echo "The negative probes of 15.5";; 17) echo "loginctl output";; 18) echo "sg for a member in a login older than the group";;
 19) echo "Hard links and the rules of 12.2";; 20) echo "Container naming";; 21) echo "sudo and /usr/local/bin";;
 22) echo "Claude Code's process name";; 23) echo "Python and the tools";; 24) echo "Cost of a full /proc scan";;
 25) echo "Bind-mounting the ledger into a container";; 26) echo "ACLs for a read-only group";; 27) echo "The gate's lookups under the share unit";;
 28) echo "The share and alert units";; 29) echo "Last terminal input from logind";; 30) echo "PathChanged= while the service runs";;
 31) echo "/proc/<pid>/task/<tid>/children";; 32) echo "The kernel's OOM report under load";; 33) echo "earlyoom's lines";;
 34) echo "The service on RHEL 9 and Debian 12";; 35) echo "Why MemoryLow was dropped";; esac; }
rowtimeout() { case $1 in 22|23|25) echo 900;; 3|19|24|27|29|35|10|33) echo 420;; *) echo 300;; esac; }

case "$1" in
row)
    mkdir -p "$STATE" "$RAW"
    echo "===== ROW $2 | $(title $2) | system=$SYSNAME mode=$MODE kernel=$(uname -r) arch=$ARCH | $(date -u +%FT%TZ) ====="
    "row$2"
    echo "===== END ROW $2 ====="
    ;;
all)
    ROWS=${2:-"1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35"}
    mkdir -p "$OUT/rows" "$STATE" "$RAW"; chmod 755 "$OUT" "$STATE" "$RAW"
    ensure_helpers; ensure_users
    cursor_now > "$STATE/start.cursor"
    for n in $ROWS; do
        f=$OUT/rows/row-$(printf %02d $n).txt
        timeout -k 20 "$(rowtimeout $n)" bash "$0" row "$n" > "$f" 2>&1 < /dev/null
        rc=$?
        if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then echo "[ROW TIMED OUT after $(rowtimeout $n)s]" >> "$f"; grep -q '^VERDICT' "$f" || echo "VERDICT: HARNESS-TIMEOUT | the row did not finish in $(rowtimeout $n)s" >> "$f"; fi
        grep -q '^VERDICT' "$f" || echo "VERDICT: HARNESS-ERROR | the row ended (rc=$rc) without a verdict" >> "$f"
        cat "$f"
        [ -n "$AFTER_ROW" ] && bash -c "$AFTER_ROW" >/dev/null 2>&1
    done
    chmod -R a+rX "$OUT"
    ;;
*) echo "usage: $0 all [ROWS] | row N"; exit 2;;
esac
exit 0
