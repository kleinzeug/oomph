#!/bin/bash
# Host side of the QEMU guest harness: boots a cloud image with KVM, runs spike/facts.sh inside, collects results.
# run-guest.sh GUEST OUTDIR    (GUEST: ubuntu-24.04 | debian-12 | rocky-9)
G=$1; OUTD=$2; REPO=$(cd "$(dirname "$0")/../.." && pwd)
mkdir -p "$OUTD"; WORK=$(mktemp -d); cd "$WORK" || exit 0
if [ ! -e /dev/kvm ]; then
    echo "::notice title=guest $G skipped::no /dev/kvm on this runner"; echo "no /dev/kvm on this runner" > "$OUTD/SKIPPED"; exit 0
fi
ls -l /dev/kvm
sudo apt-get update -qq >/dev/null 2>&1; sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-system-x86 qemu-utils genisoimage >/dev/null 2>&1
command -v qemu-system-x86_64 >/dev/null || { echo "::warning::qemu could not be installed"; echo "qemu not installable" > "$OUTD/SKIPPED"; exit 0; }
case $G in
  ubuntu-24.04) URL=https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img;;
  debian-12)    URL=https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2;;
  rocky-9)      URL=https://dl.rockylinux.org/pub/rocky/9/images/x86_64/Rocky-9-GenericCloud-Base.latest.x86_64.qcow2;;
  *) echo "unknown guest $G"; exit 0;;
esac
echo "downloading $URL"; curl -fsSL --retry 5 --retry-delay 5 -o base.img "$URL" || { echo "::warning::download failed"; echo "image download failed: $URL" > "$OUTD/SKIPPED"; exit 0; }
qemu-img info base.img | head -4
FMT=$(qemu-img info --output=json base.img | python3 -c 'import json,sys; print(json.load(sys.stdin)["format"])')
qemu-img create -q -f qcow2 -F "$FMT" -b "$WORK/base.img" disk.qcow2 20G
tar -C "$REPO" -cf in.tar spike
truncate -s 256M out.raw
cat > meta-data <<MD
instance-id: spike-$G
local-hostname: spike-guest
MD
cat > user-data <<'UD'
#cloud-config
package_update: false
package_upgrade: false
write_files:
  - path: /root/spike-boot.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      for d in /sys/block/vd*; do [ "$(cat $d/serial 2>/dev/null)" = spikein ] && IN=/dev/${d##*/}; done
      mkdir -p /spike && tar -xf "$IN" -C /spike
      exec bash /spike/spike/guest/guest-inner.sh
runcmd:
  - [systemd-run, --unit, spike-guest, --no-block, /bin/bash, /root/spike-boot.sh]
UD
genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data
echo "booting $G at $(date -u +%T)"
sudo timeout ${GUEST_MINUTES:-55}m qemu-system-x86_64 -enable-kvm -cpu host -m 2048 -smp 2 -nodefaults -vga std -display none \
  -drive file=disk.qcow2,if=none,id=root,format=qcow2 -device virtio-blk-pci,drive=root,bootindex=0 \
  -drive file=seed.iso,media=cdrom,format=raw \
  -drive if=none,id=in,file=in.tar,format=raw,readonly=on -device virtio-blk-pci,drive=in,serial=spikein \
  -drive if=none,id=out,file=out.raw,format=raw -device virtio-blk-pci,drive=out,serial=spikeout \
  -nic user,model=virtio-net-pci -device virtio-rng-pci \
  -serial file:console.log -no-reboot &
QP=$!; seen=0; t0=$(date +%s)
while kill -0 $QP 2>/dev/null; do   # progress: the guest prints one line per row to its serial console
    sleep 30
    if [ $(( $(date +%s) - t0 )) -gt 420 ] && [ "$(sudo stat -c %s console.log 2>/dev/null || echo 0)" = 0 ]; then
        echo "::warning title=guest $G::no serial output after 7 minutes; stopping the guest"; sudo pkill -f "qemu-system-x86_64 -enable-kvm" ; break; fi
    n=$(sudo cat console.log 2>/dev/null | tr -d '\r' | grep -aE '^\[spike\]|^===== ROW|^VERDICT' | wc -l)
    [ "$n" -gt "$seen" ] && sudo cat console.log | tr -d '\r' | grep -aE '^\[spike\]|^===== ROW|^VERDICT' | tail -n $((n-seen)) | cut -c1-200; seen=$n
    # keep a copy of what the guest has written so far, so a timeout still leaves results
    mkdir -p "$OUTD/partial"; sudo tar -xf out.raw -C "$OUTD/partial" 2>/dev/null; sudo cp console.log "$OUTD/console.partial.log" 2>/dev/null
    sudo chown -R "$(id -u)" "$OUTD" 2>/dev/null
done
wait $QP; echo "qemu exited rc=$? at $(date -u +%T)"
sudo chown "$(id -u)" console.log out.raw 2>/dev/null
mkdir -p "$OUTD/x"; tar -xf out.raw -C "$OUTD/x" 2>&1 | tail -2
if [ -d "$OUTD/x/spike-out" ]; then cp -r "$OUTD/x/spike-out/." "$OUTD/"; rm -rf "$OUTD/partial" "$OUTD/console.partial.log"; fi
rm -rf "$OUTD/x"
tr -d '\r' < console.log > "$OUTD/console.log"
ls "$OUTD" "$OUTD/rows" 2>/dev/null | head -50
grep -h '^VERDICT' "$OUTD"/rows/*.txt 2>/dev/null | cut -c1-200
exit 0
