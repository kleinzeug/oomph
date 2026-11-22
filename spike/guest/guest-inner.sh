#!/bin/bash
# Guest side: prepares the guest, runs the rows, writes results to the output disk after each row, powers off.
echo -1000 > /proc/self/oom_score_adj
for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = spikeout ] && OUTDEV=/dev/${d##*/}; done
export OUT=/var/tmp/spike-out MODE=guest SYSNAME="guest-$(. /etc/os-release; echo "$ID-$VERSION_ID")"
export AFTER_ROW="tar -C /var/tmp -cf $OUTDEV spike-out; sync"
mkdir -p $OUT/raw
con() { echo "[spike] $*" > /dev/ttyS0; }
con "guest harness start $SYSNAME out=$OUTDEV"
timeout 600 cloud-init status --wait > /dev/null 2>&1
con "cloud-init done"
tools="python3 sg newgrp loginctl journalctl systemd-inhibit systemd-run setfacl sudo runuser earlyoom ausearch"
for t in $tools; do printf '%s=%s ' $t "$(command -v $t || echo MISSING)"; done > $OUT/raw/preinstall-tools.txt; echo >> $OUT/raw/preinstall-tools.txt
. /etc/os-release
{
case "$ID" in
  ubuntu|debian) export DEBIAN_FRONTEND=noninteractive; timeout 600 apt-get update -qq; timeout 600 apt-get install -y -qq earlyoom acl bc;;
  rocky|rhel|almalinux) timeout 600 dnf -y -q install epel-release; timeout 600 dnf -y -q install earlyoom acl bc podman;;
esac
} > $OUT/raw/earlyoom-install.txt 2>&1
systemctl disable --now earlyoom >/dev/null 2>&1
con "packages done: $(command -v earlyoom) $(command -v setfacl)"
ROWS="1 2 3 4 5 6 7 8 9 11 12 13 14 15 16 17 18 19 21 23 24 25 26 27 28 29 30 31 32 10 33 35 34"
[ -f /spike/spike/guest/rows.override ] && ROWS=$(cat /spike/spike/guest/rows.override)
bash /spike/spike/facts.sh all "$ROWS" 2>&1 | tee $OUT/guest-run.log | grep -E '^(===== ROW|VERDICT)' > /dev/ttyS0
journalctl -b --no-pager -o short-monotonic > $OUT/raw/guest-journal.txt 2>&1
tail -c 3000000 $OUT/raw/guest-journal.txt > $OUT/raw/guest-journal.tail.txt; rm -f $OUT/raw/guest-journal.txt
tar -C /var/tmp -cf $OUTDEV spike-out; sync
con "guest harness done"
sleep 2
systemctl poweroff -f || poweroff -f
