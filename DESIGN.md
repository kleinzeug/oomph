# oomph — design notes

*oom (out of memory) + "oomph", with ph for Philipp. Started life as "memwatch".*

This document records why oomph is built the way it is: the problem it was made for,
what the investigation turned up, and the decisions behind the daemon, the log format
and the menu-bar app. The [README](README.md) covers building and using it.

## The problem

The author's Mac (Apple silicon, 36 GB RAM) runs several long-lived terminal sessions —
AI coding agents, builds, Docker — often for hours. Stepping away from it, he would
regularly come back to the macOS **"Your system has run out of application memory"**
dialog (the Force Quit window), sometimes with processes already gone. It never
happened while he was sitting at the machine running the very same workload, and by the
time Activity Monitor was open everything looked normal again. There was no record of
what had happened in between.

## What the investigation found

**macOS swap is not a fixed-size partition.** It grows in 1 GB swapfiles under
`/System/Volumes/VM`, on the same APFS container as your data, and macOS refuses to add
more once free disk space gets low. On the day oomph was written the data volume had
**~10 GB free** and swap was stuck at 4 × 1 GB with 3.2 GB in use.

When you are idle, macOS starts work it deliberately postpones while you are active:
Spotlight / `spotlightknowledged`, Siri and Apple Intelligence models, Photos analysis,
Power Nap, backups. The DiagnosticReports folder showed CPU-resource reports for
`spotlightknowledged` and `Siri AI` almost daily. Idle work on top of the regular
workload fills the memory compressor → swap has to grow → the disk is too full → the
kernel declares **low swap** → jetsam starts killing processes and macOS shows the
Force Quit dialog. The same workload while you are present never triggers the idle jobs,
which is exactly the "only when I walk away" pattern.

The unified log confirmed it. In one hour (18:28–19:25) of that day:

- launchd recorded **60,850 `OS_REASON_JETSAM` exits** — system daemons (siriinferenced,
  maild, sidecar-*, trustd, countryd, …) being killed and relaunched in a loop;
- ReportSystemMemory summarised **8,179 kills with reason `low-swap`** (plus 428 normal
  `idle-exit`s);
- none of the user's own apps were among the victims in the retained logs.

Freeing ~50 GB of disk space was the actual fix. oomph exists so that the next time
anything like this happens there is evidence instead of guesswork — and so that low disk
space is flagged *before* it turns into a memory problem.

Two practical lessons that shaped the implementation:

- On current macOS, kernel `memorystatus` messages are **not** in the unified log. The
  useful signals are launchd's `OS_REASON_JETSAM` exits and ReportSystemMemory's
  `killed by jetsam reason …` lines (the latter written as a delayed batch).
- A naive `log stream` predicate is expensive. Matching message text across *all*
  processes, or including WindowServer / kernel, cost 1–5 % CPU continuously; the final
  predicate costs effectively nothing.

## Architecture

```
┌────────────────────────── root ──────────────────────────┐
│ launchd ─ local.oomph.daemon                              │
│   /usr/bin/python3 -I -B /usr/local/libexec/oomph/oomphd.py│
│     ├─ sampler loop (30 s, 5 s when hot)                  │
│     │    libproc · sysctl · vm_stat · ioreg · pmset        │
│     └─ log stream (jetsam / low-swap / dialog)             │
│           │                                               │
│           ▼                                               │
│   /Library/Logs/oomph/   (dir 755, files 644)             │
│     current.json · samples-*.jsonl[.gz] · events.jsonl    │
│     incidents/<id>/{incident.json, syslog.txt, report.html}│
└───────────────────────────────────────────────────────────┘
            ▲ reads (no privileges needed)
┌───────────┴─────────── user ─────────────────────────────┐
│ oomph.app (menu bar)        oomph CLI (/usr/local/bin)    │
└───────────────────────────────────────────────────────────┘
```

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Runner | **LaunchDaemon as root** (`local.oomph.daemon`), `KeepAlive`, `RunAtLoad` | Survives logout, reboot and closed terminals — the incidents happen exactly when nobody is watching. Only root can read the physical footprint of *every* process, including root daemons like `spotlightknowledged` and WindowServer. |
| Install path | Code in `/usr/local/libexec/oomph/` (root-owned, 755); CLI symlink `/usr/local/bin/oomph` | A root daemon must never execute user-writable files. |
| Interpreter | `/usr/bin/python3 -I -B`, standard library only | Not affected by Homebrew upgrades; no dependencies; `-I` ignores environment and current directory. |
| Metrics | `libproc` via ctypes (`proc_pid_rusage` → `ri_phys_footprint`, the same figure as Activity Monitor's *Memory* column), `sysctl` via ctypes, `vm_stat`, `ioreg`, `pmset -g assertions` | Fast (~5 ms for ~750 processes), accurate, no third-party tools. |
| Sampling | **Adaptive**: every 30 s; every 5 s ("hot mode") while pressure ≥ warning, swap grew > 512 MB within 60 s, jetsam kills occurred, free disk < 5 GB, or an incident is open | Fine resolution exactly when it matters, near-zero cost otherwise. |
| Retention | Samples 14 days (previous days gzip-compressed); incidents 90 days; `events.jsonl` rotated at 20 MB | ~50–150 MB on disk in total. |
| Logs | `/Library/Logs/oomph/`, world-readable | Inspecting the papertrail never needs `sudo`. |
| Notifications | Only on **critical pressure, a jetsam storm, a memory-shortage kill report, or the dialog**; 15 min cooldown. Plus a **disk guard below 20 GB free**, 6 h cooldown. Delivered into the console user's session via `launchctl asuser … osascript` | You come back to one or two meaningful notifications, not fifty. The disk guard catches the root cause before it bites. |
| No auto-remediation | oomph never kills, pauses or throttles anything | It could take down the very session you care about. Papertrail only. |
| Menu-bar app | Swift (AppKit + SwiftUI + Swift Charts), built with plain `swiftc`, ad-hoc signed | Tiny, no Xcode project, no dependencies. |
| App autostart | Per-user LaunchAgent `local.oomph.menubar`, toggled from the popup | Reliable for an ad-hoc-signed app. The daemon logs whether or not the app runs. |
| Privileged actions from the app | `install.sh` / `uninstall.sh` bundled in the app, run through `do shell script … with administrator privileges` | One standard macOS password prompt; no helper tool, no SMJobBless. |

## What a sample contains

One JSON object per line in `samples-YYYY-MM-DD.jsonl`; `current.json` always holds the
latest one plus daemon status.

- `t` (unix time), `iso`, `hot`, `gap` (seconds since the previous sample when it was
  more than 3× the interval — sleep/wake or a stall)
- **System memory:** pressure level (1 normal / 2 warning / 4 critical),
  `kern.memorystatus_level` (free %), RAM, app memory, wired, compressed (occupied) and
  compressor logical size, file cache, free; swap total/used and swapfile count; free
  space on the data volume; jetsam kills since the previous sample
- **Away state:** seconds since last keyboard/mouse input, display on/off, screen locked,
  console user, current sleep-preventers (caffeinate, Amphetamine, …)
- **Top 25 processes** by footprint (pid, ppid, name, footprint, RSS, uid)
- **Top 15 app groups** — processes aggregated by outermost `.app` bundle, so twelve
  Chrome helpers count as "Google Chrome"
- **Agent sessions** — every outermost process named `claude` together with its whole
  descendant tree: pid, working directory (i.e. the project), total footprint, process
  count, biggest descendant
- `gone` — processes ≥ 300 MB that disappeared since the previous sample (normal exits
  included; context only)

## Events

`events.jsonl` combines what the `log stream` sees with what the daemon derives itself.

- **From the log** (predicate in `oomph.LOG_PREDICATE`): launchd `OS_REASON_JETSAM`
  exits, ReportSystemMemory `killed by jetsam reason …`, and "application memory" text
  from loginwindow / UserNotificationCenter. Idle-exit kills are excluded. A low-swap
  storm produces ~1,000 lines per minute, so kills are **aggregated per sample** into a
  single `jetsam` event (count, reasons, most-killed services).
- **Derived:** `pressure_change`, `sleep_gap`, `disk_low`, `incident_open` /
  `incident_close`, `notified`, `daemon_start` / `daemon_stop` / `daemon_error`.

## Incidents

`incidents/<YYYYmmdd-HHMMSS>/`

- **Opened by** critical memory pressure, ≥ 10 jetsam kills within 60 s ("jetsam
  storm"), a ReportSystemMemory kill with a memory-shortage reason (`low-swap`,
  `vm-pageshortage`, `vm-thrashing`, `vm-compressor-*`, `fc-thrashing`,
  `zone-map-exhaustion`), or the dialog text. It stays open while a trigger persists
  and closes 3 minutes after the last one.
- **On open:** notification, hot mode, and `log show --last 15m` with the memory
  predicate saved to `syslog.txt`.
- **On close:** `incident.json` (triggers, start/end, peak values, biggest risers over
  the preceding 15 minutes, away state at onset, agent sessions at the peak) and
  `report.html` — a self-contained page with inline-SVG charts (stacked memory vs. RAM
  with away periods shaded and kill bars, top-5 apps, free disk vs. swap size) and
  tables.

## Menu-bar icon

A hand-drawn chip (not an SF Symbol), redrawn on every refresh:

- Body filled **pastel green** (normal), **yellow** (warning) or **red** (critical); four
  short feet on top and bottom.
- The label is **free physical memory as Activity Monitor computes it** — Physical
  Memory − (App Memory + Wired + Compressed) — abbreviated to `12G` / `4.2G`, with a
  tightened decimal point. It is **punched out** of the chip, so the menu bar shows
  through the digits in both light and dark mode.
- When the daemon is not reporting, the chip is hollow and dimmed with an **×**.

An earlier version showed `kern.memorystatus_level` × RAM; that figure counts reclaimable
cache as free and read 24 GB while Activity Monitor showed 8 GB, so it was dropped.

The popup is a borderless `NSPanel` positioned explicitly under the status item (an
`NSPopover` could end up above the menu bar), closed by clicking the icon again or
anywhere else.

## Out of scope

- Preventing or killing anything, or changing macOS's idle jobs.
- Per-thread or per-allocation detail (`vmmap`, `footprint -all`) — too heavy to run
  continuously; run them by hand on a suspect.

## Open questions

- The log line, if any, that accompanies the Force Quit dialog itself is unknown —
  nothing matching was found for the original incident. Incidents are detected through
  the jetsam storm instead; the next incident's `syslog.txt` should tell.
