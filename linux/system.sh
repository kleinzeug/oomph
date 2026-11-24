# shellcheck shell=sh
# oomph: the system half of `linux/install.sh --system` (1.13.0, roadmap 03 §8), sourced by it once the
# code is in $LIBDIR/$NAME and $LIB and $BIN point there. Root once: the account oomphd, the folders, the
# units, the service started, the first sample waited for. With OOMPH_INSTALL_ROOT ($PFX) only the files,
# below that folder: no account, no owner changes, no systemd (the tests' way to look at what it writes).
# Not run on its own.
LOGS="$PFX/var/log/oomph"
VARLIB="$PFX/var/lib/oomph"
UNITS="$PFX/etc/systemd/system"
ALERTD="$PFX/etc/oomph/alert.d"
mkdir -p "$UNITS" "$PFX/etc/oomph"

# 1. the logger's account: a system user with a group of its own, no home, no shell. It is no member of
#    any oomph group: the logs and the ledger are open to every local account (D16).
if [ -z "$PFX" ] && ! getent passwd oomphd >/dev/null 2>&1; then
  NOLOGIN=/usr/sbin/nologin
  [ -x "$NOLOGIN" ] || NOLOGIN=/sbin/nologin
  useradd --system --user-group --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" --comment "oomph logger" oomphd
fi
own() {  # own MODE DIR: a folder of the logger's, in a folder of root's (made, or put right). Never one inside a
  #        folder of the logger's: the account could have put a link there, and root would follow it.
  [ ! -L "$2" ] || { echo "oomph: $2 is a symbolic link; not touching it" >&2; exit 1; }
  mkdir -p "$2"
  chmod "$1" "$2"
  [ -n "$PFX" ] || chown -h oomphd:oomphd "$2"
}
# 2. the folders. The logs and the logger's state are the logger's (what goes inside them, alerts/ too, the
#    logger makes itself); the ledger is everybody's: made 0777 without the sticky bit (a writer renames its
#    new file over another account's) and, once it exists, left alone, as on a Mac (H0 rule 4: no installer
#    changes the shared folder).
own 0755 "$LOGS"
mkdir -p "$VARLIB"
chmod 0755 "$VARLIB"
own 0700 "$VARLIB/daemon"
if [ ! -e "$VARLIB/ledger" ] && [ ! -L "$VARLIB/ledger" ]; then
  mkdir -m 0777 "$VARLIB/ledger"
  chmod 0777 "$VARLIB/ledger"
  CREATED_LEDGER=1
else
  CREATED_LEDGER=0
fi
mkdir -p "$ALERTD"
chmod 0755 "$PFX/etc/oomph" "$ALERTD"
# the hooks' secrets: root's alone; oomph-alert.service hands them to the hooks ($CREDENTIALS_DIRECTORY/alert)
if [ ! -e "$PFX/etc/oomph/alert.secret" ]; then
  (umask 077; : > "$PFX/etc/oomph/alert.secret")
fi

# 3. the units, with this Python
[ -n "$PFX" ] || getent group systemd-journal >/dev/null 2>&1 || JOURNAL=0
unit() {  # unit SRC DEST: the unit with @PY@ filled in (and, with JOURNAL=0, without the journal group)
  "$PY" -I -c 'import sys
src, dest, py, journal = sys.argv[1:5]
s = open(src).read().replace("@PY@", py)
if journal != "1":
    s = "".join(l for l in s.splitlines(True) if not l.startswith("SupplementaryGroups=systemd-journal"))
tmp = dest + ".new"
open(tmp, "w").write(s)
import os
os.chmod(tmp, 0o644)
os.replace(tmp, dest)' "$1" "$2" "$PY" "$JOURNAL"
}
unit "$HERE/linux/oomphd.service" "$UNITS/oomphd.service"
unit "$HERE/linux/oomph-alert.service" "$UNITS/oomph-alert.service"
unit "$HERE/linux/oomph-alert.path" "$UNITS/oomph-alert.path"
NVIDIA=0
if [ -x "$PFX/usr/bin/nvidia-smi" ] && { [ -n "$PFX" ] || [ -e /dev/nvidiactl ]; }; then
  NVIDIA=1
  mkdir -p "$UNITS/oomphd.service.d"
  unit "$HERE/linux/oomphd-nvidia.conf" "$UNITS/oomphd.service.d/20-nvidia.conf"
elif [ -f "$UNITS/oomphd.service.d/20-nvidia.conf" ]; then
  rm -f "$UNITS/oomphd.service.d/20-nvidia.conf"
  rmdir "$UNITS/oomphd.service.d" 2>/dev/null || true
fi
HOOKS=0
for h in "$ALERTD"/*; do [ -f "$h" ] && [ -x "$h" ] && HOOKS=$((HOOKS + 1)); done

if [ -n "$PFX" ]; then
  echo "oomph: installed $VER below $PFX (no account, no systemd: OOMPH_INSTALL_ROOT)"
  exit 0
fi

# 4. the service: started, or restarted onto this version; then its first sample
systemctl daemon-reload
systemctl enable oomphd.service >/dev/null 2>&1
systemctl restart oomphd.service
[ "$HOOKS" = 0 ] || systemctl enable --now oomph-alert.path >/dev/null 2>&1 || true
got=""
i=0
while [ "$i" -lt 30 ]; do   # read as the logger's account, not as root: the folder is the logger's
  got=$(cd / && setpriv --reuid=oomphd --regid=oomphd --clear-groups "$PY" -I -c 'import json, os, stat, sys
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        if stat.S_ISREG(os.fstat(fd).st_mode):
            print(json.loads(f.read(4 << 20))["daemon"]["version"])
except Exception:
    pass' "$LOGS/current.json" 2>/dev/null || true)
  [ "$got" = "$VER" ] && break
  sleep 1
  i=$((i + 1))
done
if [ "$got" != "$VER" ]; then
  echo "oomph: the logger did not write its first sample; what it said:" >&2
  journalctl -u oomphd -n 20 --no-pager >&2 || true
  exit 1
fi

echo "oomph: installed $VER into $LIBDIR/$NAME (python: $PY); the command is $BIN"
echo "oomph: the logger runs as the service oomphd (user oomphd: no capability, no network) and writes $LOGS"
if [ "$JOURNAL" = 1 ]; then
  echo "oomph: it names the processes the kernel's OOM killer, systemd-oomd and earlyoom kill (group systemd-journal)"
else
  echo "oomph: it counts kills without names (--no-journal, or no group systemd-journal here)"
fi
[ "$NVIDIA" = 0 ] || echo "oomph: NVIDIA cards are read through nvidia-smi (oomphd.service.d/20-nvidia.conf lets it open them)"
if [ "$CREATED_LEDGER" = 1 ]; then
  echo "oomph: the ledger $VARLIB/ledger is this machine's, open to every local account (oomph doctor says how to keep it to a group)"
fi
if [ "$HOOKS" = 0 ]; then
  echo "oomph: incidents reach the journal (journalctl -u oomphd -p crit); to hear of them elsewhere put a script into"
  echo "       $ALERTD (mode 755; examples: $LIB/alert.d.examples), its secrets into /etc/oomph/alert.secret,"
  echo "       then: sudo systemctl enable --now oomph-alert.path"
else
  echo "oomph: $HOOKS alert hook(s) in $ALERTD; try them: sudo $BIN alert --test"
fi
# every local account with a copy of its own (linux/install.sh without --system): one older than 1.13 keeps its
# own ledger and so stops taking turns with the others. Only looked at (a stat, nothing in a home is opened), only
# the accounts of /etc/passwd from UID_MIN on (not a directory service's thousands), each look at most 2 s (a
# home on NFS or autofs that does not answer holds nothing up); doctor names the rest, account by account.
UMIN=$(awk '$1 == "UID_MIN" { print $2 }' /etc/login.defs 2>/dev/null)
case "$UMIN" in ''|*[!0-9]*) UMIN=1000 ;; esac
TO=$(command -v timeout || true)
while IFS=: read -r name _ uid _ _ home _; do
  case "$uid" in ''|*[!0-9]*) continue ;; esac
  [ "$uid" -ge "$UMIN" ] && [ "$uid" -lt 65534 ] || continue
  case "$home" in /*) ;; *) continue ;; esac
  case "$home" in /|/nonexistent) continue ;; esac
  [ -n "$TO" ] || continue
  if "$TO" 2 sh -c '[ -L "$1" ] || [ -d "$1" ]' _ "$home/.local/lib/oomph" 2>/dev/null; then
    echo "oomph: $name has a copy of its own in ~/.local (it comes first on that PATH, and before 1.13 it keeps"
    echo "       a ledger of its own): as $name, linux/uninstall.sh removes it, or linux/install.sh updates it"
  fi
done < /etc/passwd
U="${SUDO_USER:-}"
if [ -n "$U" ] && [ "$U" != root ]; then
  echo "oomph: for Claude Code, as $U: $BIN setup-claude"
fi
echo "oomph: try: oomph doctor · oomph status · oomph incidents · oomph top"
