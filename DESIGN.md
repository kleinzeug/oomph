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
- `log stream` never delivers launchd's lines — `log show` does. Until 1.3 every
  incident reported 0 kills (the 2026-11-19 freeze had 1,470 in one minute). launchd's
  exits are now polled with `log show` every 60 s (10 s while hot), with overlapping
  windows deduplicated by mach timestamp; everything else is still streamed.
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
│     │    host_processor_info · notify (thermal) · getfsstat│
│     │    · ioreg -c IOAccelerator (1.9.1)                  │
│     │    (oomph_darwin.py, the backend: oomph.plat())     │
│     ├─ volumes thread (1.9.1): diskutil info, once per    │
│     │    newly seen mount, off the sampling path          │
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
│ oomph top (terminal, 1.9)    oomph mcp ← Claude sessions   │
│                                 │ flock, read/write        │
│                                 ▼                          │
│        /Users/Shared/oomph/ledger.json  (reservations)     │
│        /Users/Shared/oomph/reservations.jsonl  (history)   │
└───────────────────────────────────────────────────────────┘
       (each sample, a child of the daemon running as nobody retires
        dead/expired leases and answers the live ones for the sample;
        root itself never opens anything in /Users/Shared/oomph)

Linux (1.9.4): no logger, no root. The same oomph.py, measuring live through
oomph_linux.py (/proc, /sys); installed per user in ~/.local by linux/install.sh;
the ledger is the user's own, ~/.local/state/oomph/ledger/<machine>/.

Linux (1.13.0), `sudo linux/install.sh --system`: the same oomphd.py as the systemd
service oomphd (user oomphd: no capability, no network, no devices), kills from one
`journalctl -f` child, NVIDIA cards from `nvidia-smi` runs → /var/log/oomph; the
machine's ledger /var/lib/oomph/ledger (every account); alert records → oomph-alert
.service (a DynamicUser) runs /etc/oomph/alert.d.
```

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Runner | **LaunchDaemon as root** (`local.oomph.daemon`), `KeepAlive`, `RunAtLoad` | Survives logout, reboot and closed terminals — the incidents happen exactly when nobody is watching. Only root can read the physical footprint of *every* process, including root daemons like `spotlightknowledged` and WindowServer. |
| Install path | Code in `/usr/local/libexec/oomph-<version>/` (root-owned, 755), reached through the link `/usr/local/libexec/oomph`, which an install swaps by one rename once the new directory is complete; old versions go 7 days after they were replaced. CLI symlink `/usr/local/bin/oomph` | A root daemon must never execute user-writable files. A running process (the logger, an MCP server) keeps importing from the directory it started in, so it never mixes two versions' modules. From 1.10.6 an MCP server (a session can keep one for days) replaces itself before its next request when the installed copy behind the path it was started by carries another stamped version, is root's and writable by nobody else, and passes `oomph mcp --selfcheck` within 5 s, and is still that file (device, inode, version) just before the exec; a failed check waits for another stamped file, never a timer. Only a root-owned install does this (the Mac's, Linux's system mode), not a Linux user install; it reads its input itself (`os.read`, no buffered reader) and hands the unanswered bytes to the new code in an unlinked file. A checkout (`dev`), a copy someone else may write, or a server running as root never does. |
| Interpreter | `/usr/bin/python3 -I -B`, standard library only. From 1.9 `install.sh` also compiles the installed modules once, as root (`compileall`: root-owned `__pycache__` in the root-owned version directory); `-B` still keeps every run from writing any | Not affected by Homebrew upgrades; no dependencies; `-I` ignores environment and current directory. Bytecode built by root beside root's files is as trusted as the files; `oomph top` needs it to stay small (see below). A cache that fails to build costs speed, not function. |
| Metrics | Measured only by the backend module for the system (`oomph_darwin.py` on a Mac, `oomph_linux.py` on Linux from 1.9.4, reached through `oomph.plat()`; oomph.py and oomphd.py import no native code and load on any system): `libproc` via ctypes (`proc_pid_rusage` → `ri_phys_footprint`, the same figure as Activity Monitor's *Memory* column), `sysctl` via ctypes, `vm_stat`, `ioreg`, `pmset -g assertions`. From 1.9.1 also `host_processor_info` (ticks per core), the thermal notification (`com.apple.system.thermalpressurelevel`), `getfsstat` (MNT_NOWAIT: the kernel's cached sizes, never blocking on a dead mount), `ioreg -c IOAccelerator` each sample (the GPU's busy time, unprivileged) and `diskutil info` once per newly seen mount on a thread of its own. From 1.9.3 the GPU at full speed (opt-in until `IOREPORT_DEFAULT` in oomph.py turns it on for everybody): the private `libIOReport` (the time spent in each GPU performance state) weighed with the DVFS table of the device tree, read by a helper process that runs as `nobody` and answers one bounded JSON line per sample; the library is never loaded by a process running as root, and a helper that crashes four times in a boot, or whose readings do not fit, is off until the next boot or macOS update | Fast (~5 ms for ~750 processes), accurate, no third-party tools. |
| Sampling | **Adaptive**: every 30 s; every 5 s ("hot mode") while pressure ≥ warning, swap grew > 512 MB within 60 s, jetsam kills occurred, free disk < 5 GB, or an incident is open | Fine resolution exactly when it matters, near-zero cost otherwise. |
| Retention | Samples 14 days (previous days gzip-compressed); incidents 90 days; `events.jsonl` rotated at 20 MB | ~50–150 MB on disk in total. |
| Logs | `/Library/Logs/oomph/`, world-readable | Inspecting the papertrail never needs `sudo`. |
| Notifications | Only on **critical pressure, a jetsam storm, a memory-shortage kill report, the dialog, unowned memory or a stall**; 15 min cooldown. Plus a **disk guard below 20 GB free**, 6 h cooldown. Delivered into the console user's session via `launchctl asuser … osascript` | You come back to one or two meaningful notifications, not fifty. The disk guard catches the root cause before it bites. |
| No auto-remediation | oomph never kills, pauses or throttles anything | It could take down the very session you care about. Papertrail only. |
| Menu-bar app | Swift (AppKit + SwiftUI + Swift Charts), built with plain `swiftc`, ad-hoc signed | Tiny, no Xcode project, no dependencies. |
| App autostart | Per-user LaunchAgent `local.oomph.menubar`, toggled from the popup | Reliable for an ad-hoc-signed app. The daemon logs whether or not the app runs. |
| Privileged actions from the app | `install.sh` / `uninstall.sh` bundled in the app, run through `do shell script … with administrator privileges` | One standard macOS password prompt; no helper tool, no SMJobBless. |

## What a sample contains

One JSON object per line in `samples-YYYY-MM-DD.jsonl`; `current.json` always holds the
latest one plus daemon status.

- `t` (unix time), `iso`, `os` (`"macos"`; from 1.8.8, older samples lack it), `hot`,
  `gap` (seconds since the previous sample when it was more than 3× the interval),
  `stall` (the same, when the Mac was awake throughout: `CLOCK_UPTIME_RAW` stops during
  sleep, wall time doesn't)
- **System memory:** pressure level (1 normal / 2 warning / 4 critical),
  `kern.memorystatus_level` (free %), RAM, app memory, wired, compressed (occupied) and
  compressor logical size, file cache, free; swap total/used and swapfile count; free
  space on the data volume; jetsam kills since the previous sample
- **Ownership:** `procs_gb` (all processes' footprints added up) and `unowned_gb` =
  app memory + compressor logical size − `procs_gb`. Footprints count compressed and
  swapped pages at full size, so this is normally a few GB. On 2026-11-19 a WebKit GPU
  process leak left ~150 GB (compressed ~11:1) behind after its processes were killed;
  nothing could free it and the Mac froze two hours later.
- **Away state:** seconds since last keyboard/mouse input, display on/off, screen locked,
  console user, current sleep-preventers (caffeinate, Amphetamine, …)
- **Top 25 processes** by footprint (pid, ppid, name, footprint, RSS, uid)
- **Top 15 app groups** — processes aggregated by outermost `.app` bundle, so twelve
  Chrome helpers count as "Google Chrome"
- **Agent sessions** — every outermost process named `claude` together with its whole
  descendant tree: pid, working directory (i.e. the project), total footprint, process
  count, biggest descendant
- Each top process also carries `g` (its app group), `pn` (its parent's name) and `s`
  (the Claude session it runs under), so a report can show it in the owner → parent →
  process tree and connect it to its app without the full process table
- `gone` — processes ≥ 300 MB that disappeared since the previous sample (normal exits
  included; context only)
- `current.json` only, in its `daemon` block (1.8.8): `machine` — `id` (a hash, not the
  hardware UUID), `name`, `os`, `arch`, `os_version`, `kernel`, `kind` (`laptop` or
  `desktop` on a Mac), `cpus`, `virt`, and `measures`: what this machine can measure
  (`memory`, `pressure`, `kills`, `presence`, `footprint`, `unowned`, `scope`, and
  `all_procs`: whether the logger sees every process). Additive: every reader tolerates
  samples with and without these keys.

### More resources (1.9.1)

Each block is optional: it is there when its reading worked, and every reader tolerates
samples with and without it (older samples have none).

- `cpu` — `n` cores (`p`, `e`: performance and efficiency cores), `load` (1/5/15 min),
  `therm` (thermal level 0 nominal … 4), and from the second reading on `busy`, `user`,
  `sys` in cores and `p_busy`/`e_busy` per cluster. The per-process figures never add up to
  more than `busy` plus half a core (a larger clamp is noted once per start in `daemon.err`).
- `gpu` — a list, one per device: `id`, `name`, `unified`, `util` (percent), `src` (`clients`:
  busy time from the clients' GPU time; `ioreg`: the driver's instantaneous figure, also
  kept as `now`), `active`, `mem_gb`, `mem_alloc_gb`, `mem_limit_gb` (`mem_limit_est`). If the
  clients' figure and the driver's disagree by more than 25 points for five minutes, the
  device reads `ioreg` for the rest of the run.
- `io` — `r_mb_s`, `w_mb_s`: all processes' reads and writes.
- `disks` — a list of pools: the system's (`id` `data`, `watch`, `roles`, `low_gb` 20 and
  `crit_gb` 5, `level`) and every *listed* one (another fixed disk, an external SSD: by
  `vol:<UUID>`, `name`, `mount`, `dev`, `fs`, `kind`; recorded, not watched unless a user
  pins it). Memory cards, disk images, backup, network and FUSE volumes are ignored
  (`oomph volumes --all` says why).
- `top_cpu` (8), `top_gpu` (5), `top_io` (5): the biggest consumers in cores, percent of
  the GPU and MB/s written; a list is left out when nothing used that resource and after a
  start or a gap. Top processes, groups and sessions carry `cpu`, `gpu` and `w` likewise.
- `cpu_names` (5, 1.9.9): the busiest process names over the whole process table, each
  `{name, cpu, n}` with its processes' cores added up and counted (fourteen `yes` are one row).

On the wire (`serve`, mirrors), slim samples carry the numbers of `cpu`, `gpu` and `io`; the
top lists and `disks` stay home (a mirror before 1.9.1 refuses a row whose `*_gb` exceeds
16 times the RAM, which a disk's size does). The full current sample adds the GPU's name.

## Events

`events.jsonl` combines what the system log shows with what the daemon derives itself.

- **From the log** (predicate in `oomph.LOG_PREDICATE`): launchd `OS_REASON_JETSAM`
  exits, ReportSystemMemory `killed by jetsam reason …`, and "application memory" text
  from loginwindow / UserNotificationCenter. Idle-exit kills are excluded. A low-swap
  storm produces ~1,000 lines per minute, so kills are **aggregated per sample** into a
  single `jetsam` event (count, reasons, most-killed services).
- **Derived:** `pressure_change` (the first change after a quiet minute; further flips
  within a minute of each other are batched into one `pressure_flapping` event with a
  count, written once it settles or every 15 min — the freeze logged 637 single flips),
  `sleep_gap` vs. `stall`, `unowned_memory` / `unowned_memory_cleared`, `disk_low`, `incident_open` /
  `incident_close`, `notified`, `daemon_start` / `daemon_stop` / `daemon_error`.
- **The other resources (1.9.5, roadmap 02 §5.3)**, from the blocks of 1.9.1; a sample without
  them changes nothing:

  | kind | fields | when |
  |---|---|---|
  | `thermal` | `old new busy` (`flips`) | the thermal level changed; batched like pressure flips |
  | `cpu_saturated` / `cpu_saturated_cleared` | `busy n minutes top{name: cores} top_n{name: processes}` (from `cpu_names` since 1.9.9) | busy on ≥ 90 % of the cores for 10 minutes; over below 75 %; at most once an hour |
  | `disk_low` | `disk_free_gb` as before, plus `pool name mount free_gb level` | per watched disk, every 6 hours at most; the startup disk's with the swap notification as before |
  | `disk_filling` | `pool name mount free_gb rate_gb_min eta_min top{name: MB/s}` | a watched disk lost ≥ 2 GB in two minutes and reaches its critical floor within 30 minutes at that rate; every 30 minutes at most; a notification when that is under 10 minutes away. Sampling is hot while it fills |
  | `volume` | `pool name mount what` (`mounted unmounted watched unwatched`) | a listed or watched disk came, went, or changed class; not in the first two minutes after a start |
  | `unowned_memory` | adds `gpu_alloc_gb` | as before |

  Notifications carry names their owners chose (a volume's, a process's): every text goes through
  `oomph.notify_text`, which removes quotes, backslashes, control and direction characters.

## Incidents

`incidents/<YYYYmmdd-HHMMSS>/`

- **Opened by** critical memory pressure, ≥ 10 jetsam kills within 60 s ("jetsam
  storm"), a ReportSystemMemory kill with a memory-shortage reason (`low-swap`,
  `vm-pageshortage`, `vm-thrashing`, `vm-compressor-*`, `fc-thrashing`,
  `zone-map-exhaustion`), the dialog text, unowned memory above max(16 GB, 40 % of RAM)
  for a minute, or a stall of ≥ 60 s. It stays open while a trigger persists
  and closes 3 minutes after the last one, or after 2 hours: then it is closed with
  `"rolled": true` while triggers still come, and a trigger within the next 3 minutes
  opens one with `"continues": "<id>"` and no notification (one left open across a
  sleep or a restart just closes). A continuation keeps the kill notice of the one it
  continues: a kill it had announced is not announced again.
- **Headline:** `reasons` is kept sorted by `REASON_RANK` (a jetsam report 90, the dialog
  85, low swap 80, a storm 70, unowned 60, a stall 50, pressure 40; ties by time), so
  `reasons[0]` is the most severe cause for every reader. The id, `start` and
  `opened_by` keep the moment and the kind that opened it. Incidents from before 1.8.6
  keep their reasons in arrival order.
- **On open:** notification, hot mode, and `log show --last 15m` with the memory
  predicate saved to `syslog.txt`.
- **Escalation:** a reason of rank 80 or more that joins later and outranks everything
  the incident had is notified once more, past the 15-minute cool-down (`notified` with
  `"event": "kill"`), at most once per incident; `incident.json` is rewritten whenever a
  reason joins.
- **On close:** `incident.json` (triggers, start/end, peak values, biggest risers over
  the preceding 15 minutes, away state at onset, agent sessions at the peak) and
  `report.html` — a self-contained page with inline-SVG charts (stacked memory vs. RAM
  with away periods shaded and kill bars, top-5 apps, free disk vs. swap size) and
  tables. Both read the samples one at a time (`iter_samples`, `summarize` as a fold,
  the report in two passes that keep at most 1,200 points per view), so closing an
  incident does not hold a day of samples in the logger's memory.
- **The other resources (1.9.5):** the summary adds, only where the samples have them (absent,
  never zero, for "not recorded"): `max_cpu_busy` `cpu_n` `max_cpu_at` `top_cpu_at_peak`
  `names_cpu_at_peak` (1.9.9: by name with a count);
  `max_gpu_util` (the share of the GPU's capacity at full speed, from samples with IOReport's
  figure) and `max_gpu_busy` (busy time, from the others), each with its time, never averaged or
  compared; `top_gpu_at_peak`; `max_gpu_mem_gb`; `min_free_gb{pool}`; `writers` (the peak MB/s
  written per process); `onset` gains `cpu_busy`, `gpu_util` or `gpu_busy`, `gpu_mem_gb`; the
  risers gain `cpu_peak` and `gpu_peak`. The report adds panels below the memory charts (cores
  busy against the core count, peak and mean; the GPU at full speed with its busy time, or
  "GPU busy time" where the speed was not recorded; GPU memory in use and allocated against the
  working-set limit; the free space of each watched disk with its floors), the busiest
  processes per resource and the biggest writers, and CPU and GPU columns in the risers. The AI
  report's `timeline` and `current_status` carry the same, and `top_at` takes `by`.

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

## Four resources (1.11.0, behind `resourcesUI`)

The popup of roadmap 02 §3.7 and §3.8, built whole and switched off until its renders have
been reviewed (`defaults write local.oomph.menubar resourcesUI -bool YES`; read once at launch).
With the default off every picture is byte for byte the one before (tools/renderfixture.py
`--against`, also on a fixture whose samples carry the other resources).

| Decision | Why |
|---|---|
| Tiles in the place of the stats rows, working as tabs: `selection` (a set, in tile order, never empty) and `focus` (one of it), in UserDefaults (`selectedResources`, `focusResource`). A click shows one alone, ⌘-click toggles (the last is refused with a shake), ⇧-click adds the run from the focus; only a click, or removing the focus, moves the focus. `m c g d` / `M C G D` while no text field has the keyboard | the owner's design D21; `Selection.apply` is `oomph top`'s `selection_apply` too, held together by tools/vectors/chart.json |
| The big chart is the focus's, under its legend with live values; the other shown resources are 22 pt rows under it on the same `TimeAxis`, drawn in the chart's overlay with its plot frame, the hover line through them. Memory's chart gets an explicit y scale (to the next 10 GB above RAM or the highest stack) | the legend and the unit stay next to the chart they describe (02 §3.7.2); the rows share the mapper, grid, hatch and incident rules |
| A `Point` carries the other resources (Float, NaN for none) only with the switch on; a bucket keeps the rates' mean, the GPU of its newest kind only (busy time and the figure at full speed are never averaged), the most GPU memory, the least free disk | the memory series and the default's loading time stay as they were |
| The capsule and the chip are one function of oomph's verdict (`oomph.capsule` over the verdict's findings, tagged memory or disk): "Normal", "Memory tight/critical", "Disk low/critical"; the chip's body the memory level, a disc for a critical disk; the popup opens on a resource that is critical, added to the selection for that opening only. A low disk or tight memory marks neither the chip nor the opening: it stays on the capsule and the tile | the chip agrees with `oomph check` (roadmap §11, 02 §15.13). Attention is for change, not standing state (roadmap D9): a small SSD must not mark the chip for weeks. The machine-wide verdict: no caller's coordination, no pins |
| The strip has a band per shown resource reserved in the 14 days kept (1.12.3, B3): the focus's first and 46 pt with its scale, the time left of live grants and purpose labels; each other one 12 pt (9 from level 2, none at level 4) with its name in the gutter. Each band stacks the reservations that hold its resource on its own scale (`ResBlock.stack(kind:)`, from `segments[].res`); the Disk band holds the tile's pool. The list holds what holds a shown resource, flagged grants first, every amount as text, the status column with the flag, one use figure and what a request waits for (`waiting_on`); one line sums up the rest. Hovering a row or a block outlines that reservation in every band | which bands exist is a slow fact (02 §3.4.5), so the strip changes height when a resource is first reserved, not on a click; colour says who and the band says what (D11); `Reservation.bands`, the row words and `ResBlock.stack(kind:)` are `oomph_view`'s `bands`, `amounts_text`, `status_text`, `other_text` and `stack_reservations(kind=)` too, held together by the `rows`, `band_stack` and `band_top` groups of tools/vectors/chart.json |
| `over` and `idle` (1.12.3): the logger's child, which alone has the rates, marks a cores grant used at more than 1.25 × what it got for two evaluations, or under 10 % for ten minutes, and a disk grant that wrote more than it got (`res.cpu.flag`, `res.disk.flag`, with counters and since when). The holder's answer leads with the advice, `_brief` and `oomph reservations` carry it. Each rating stamps `rate_t`; every evaluation drops advice not rated for 5 minutes (`_advice_stale`) | 02 §6.3: advice, never enforced; one writer of the flag, so every view reads the same; the sanitizer types the fields, and a re-queued grant loses them with its other figures; a stopped logger or a pool gone from the sample must not leave "over on CPU since …" standing |
| Every block, swatch and card in its agent's colour (`agent.slot`), gray for a record without one | D11: colour says who; the resource is the band |
| Compact levels 0–5 (capped lists, smaller rows, a shorter chart, no rows, incidents in a line), chosen when the popup opens and when the selection changes, by measuring the panel against the screen | 02 §3.7.5; `--ai lvl:N` renders one |
| In `oomph top` the same behind `"resourcesUI": true` in top.json: tiles in rows 1–2, `m c g d` / `M C G D`, the focus's plot, one sparkline row per other shown resource from 30 rows; from 1.12.3 the strip's rows split into bands (the first takes what the others leave, each other one a row named in the gutter; with more bands than rows the last are left out), the list's amounts in a column as wide as the 14 days need (a row whose amounts need more widens it for itself: amounts and status are never cut; the project gives way first, then the purpose in its middle, as in the app), "▾ n more: 2 granted, 1 waiting" as the app words it, and the "other" line as the list's last row | 04 §3.14, 02 §3.7.12; nothing is added below 30 rows |

## Coordinating sessions (1.2)

Several Claude Code sessions on one Mac each make locally sensible decisions — "8 GB
free, start the build" — that together exhaust memory. 1.2 adds a shared, advisory
reservation queue that the sessions use through the skill, the CLI and the MCP server.

| Topic | Decision | Why |
|---|---|---|
| Where the queue lives | A JSON ledger in `/Users/Shared/oomph/` (dir 777, files 666), every read-modify-write under `flock`, written with an atomic rename. No installer creates or changes the directory; the first session that reserves creates it | Works without the root daemon, so checks-only installs and CI get it too. RAM is shared by all users, so one ledger per Mac rather than per user. A root daemon as broker would make every request depend on the logger being installed and current. |
| Unit | A **reservation**: estimated *peak extra* GB + a purpose label + the holder (Claude session, or the `oomph run` process) | Peak, because the peak is what tips the machine over. The label makes past peaks reusable for estimates. |
| Admission | Strict FIFO. Grant the head while `gb ≤ free − outstanding − margin`; margin = max(1.5 GB, 5 % RAM). Never while pressure is critical. Head bigger than that is granted only when no other grant exists and the verdict is ok; > 90 % of RAM is refused | FIFO is what "one after another" means and prevents starving big jobs. The alone rule prevents a deadlock on requests that can never fit; it is flagged with a note so the agent expects swapping. |
| Free figure | Activity Monitor's (RAM − app − wired − compressed), from a live sample | Conservative on purpose: cached files are reclaimable, but the point is to space out heavy steps, and the same figure is shown everywhere. |
| Outstanding | Per grant, `gb − growth`, where growth is the footprint its watched process tree added since the grant (several grants on one tree share it in grant order) | Without it a running job is counted twice — as used memory and as reservation — and the queue stalls. Growth also gives the measured peak recorded in the history. Memory outside the tree (e.g. inside Docker's VM) isn't seen, which errs on the safe side until release. |
| Liveness | Holder pid + process start time; dead holder → entry dropped. Session-held grants expire (default 30 min, re-asking extends, max 8 h); `oomph run` grants live exactly as long as the run. Queued entries lapse after 180 s without a poll | No entry can block the queue after its owner is gone or has forgotten it. |
| Waiting | Clients poll every 2 s (CLI) or within the MCP call (≤ 300 s); a queued response carries the position and who is ahead | Polling a locked file is simple and robust; no daemon, sockets or notifications to keep alive. The MCP cap keeps tool calls bounded; the ticket keeps the place across calls. |
| Visibility | `oomph check` folds in others' reservations (tight when they exceed what's free); the daemon copies live reservations into every sample; the popup lists them | Uncoordinated checks still see planned work, and incidents show what was reserved at the time. |
| Enforcement | None — advisory, like the rest of oomph | Killing or pausing an agent's work would be worse than the problem. The skill tells sessions never to start reserved-for work early and never to release others' entries. |
| Edits | `oomph amend` / MCP `update_reservation`: gb, ttl (from now), purpose, and from 1.12.0 cores (`--cpu` / `cpu_cores`, per resource by the same rules; a reservation with cores can drop its memory or its cores with 0, not both, and a lease of memory alone takes no cores). Shrinking applies at once and is re-evaluated in the same call, so whoever waits is granted then. Growing a grant applies only if a new request for the extra would be granted now (fits, nobody queued, not critical); otherwise refused with advice to reserve the extra separately, and nothing changes. Growing a queued request moves it to the back | Growth that skipped the queue would let a holder overtake everyone waiting; a pending-growth state would complicate every client. Refusal keeps the grant intact and the queue fair, and the advice is one tool call. |
| History | `reservations.jsonl` next to the ledger (666), one record per line, written under the ledger lock: an `edit` record per applied change, an `end` record when a lease is retired, each a full snapshot (key, purpose, project, holder kind, gb and `segments` [{t, gb}] once edited, requested, granted, ended, outcome, peak). Every write rewrites it (see the next table): 14 days and at most 8 MB are kept; seeded once from the ledger's own last-100 history | Agents and the popup need spans of sessions that are long gone. Snapshots make the last record per key self-contained; from 1.9.2 readers merge the records of a key, so fields a later writer leaves out are not lost (Version 2 below). The key is `id@requested`, and a fresh ledger continues the id numbering from the log, so ids never repeat after a reset. Ends are the real ones: an expiry at its expiry time, a lapse when polling stopped, a dead holder within one daemon sample. |
| Popup strip | One block per reservation under the memory chart, drawn on the chart's own time mapping (same plot frame, same animated linear/log blend). Height ∝ GB; stacked by lanes (first-fit by start), and the stack at any moment is the sum of what is reserved there, so a block steps down when one below ends or shrinks; queued stretches hatched. The list below uses the same colours, hashed from the purpose; from 1.9 it is ordered as in `oomph top`: waiting first, in the ledger's queue order (by request time where that is unknown), then grants by time left, the one ending soonest first, a grant without a ttl last | Lining up with the chart lets you read cause and effect; stacking shows the total the ledger promised. With the list capped, the rows that explain why an agent waits are the ones that stay. |
| Agent's colour | From 1.11.0 `agent` also carries `slot`, the agent's place in a palette of six (three hues kept away from the resource and state hues, then the same three lighter), chosen once under the ledger lock by whichever writer evaluates first (`agent_slot`, `_give_slots`): an agent keeps a slot it has in a live lease or in the ledger's own history (14 days at most); else a slot no live agent holds, one whose hue nobody live wears first, then the one whose last block ended longest ago; a seventh agent shares the slot of the fewest live agents, then the one whose holder started first. Copied into its records like the key | every front end draws the stored slot, so the app, `oomph top`, a machine tab and a report agree without computing anything (roadmap 02 §3.8.4). The sanitizer has taken `slot` since 1.9.2 |
| Agent | From 1.9.2 a lease and its records carry `agent` {key}: the first 8 hex digits of SHA-256 over `oomph-agent:<pid>:<start>` of the agent's process: the holder, or for an `oomph run` inside a Claude session that session (the run passes the session's key). Any writer fills it into a lease an older one made, from the holder (for a run still inside its session, the session's); a lease whose holder's start time is unknown gets none | Colour per agent, for good (roadmap D11): a finished reservation keeps its agent's colour after the session is gone, so the key must be in the history before any block is coloured by it. Additive: 1.8 readers ignore it |
| Version 2, readers first (1.9.2, B0) | Newer writers will add to the same two files (roadmap §4.4): resource vectors (`v: 2`, `res`, `res_granted`, `waiting_on`, `hold`, `base`, `last`, `watch_also`, `watch_names`; `gb` and `used_gb`/`peak_gb`/`baseline_gb` stay as memory mirrors, `gb` 0 for a lease without memory), several accounts and containers (`holder.uid`, `holder.ns`, `user`, `scope`, root `boot` and `sessions`), `grant` records with `res` and `peak`, the outcomes `refused` and `volume_gone`. Every reader takes them now, typed by one table per place (lease, record, root): a mistyped field is absent, an unknown field carried through, and so is a resource added later (a lowercase name, at most 16 in one `res`, never counted here); a segment keeps its `res`. Writers still write what 1.8.1 writes, plus `agent`, and a v2 lease's own fields into its end. 1.9.2 to 1.11 grant no v2 request (they cannot weigh its other resources) and let nobody pass one (from 1.12.0 see the next row); it tests no pid of a holder in another pid namespace (such a lease ends by its time, at once if that is further off than its own `ttl` (7 days at most) from its grant or last renewal, or a run by its `seen`), and never counts it as the caller's in `release all` or coordination's "mine"; it grants no request of another scope. The history is read **merged** per key: a later record overrides the fields it has, `res`, `peak`, `v`, `agent` and `user` stay when a later one lacks them, nothing undoes an `end` (the app and `oomph top` merge the same way, nulls included, held together by `tools/vectors/chart.json`) | A release that only reads comes first, so that by the time anything writes vectors every reader on the machine, stale MCP servers included, already reads them. A vector reservation ended by a 1.8 process (whose `end` knows no `res`) stays a vector. `tools/ledgercompat.py` runs 1.8.1's ledger code from git and this code on each other's files and on a v2 ledger, both directions |
| Cores (1.12.0, B1) | `oomph reserve 5G --cpu 8`, `oomph run --cpu 8`, MCP `cpu_cores`/`cpu_min`: **logical** cores, a rate pool. `cap` = the machine's cores, `margin` = max(1, round(cap / 8)) kept for the person at it, `room` = cap − margin − what grants got; a request waits only for room, never for load. Elastic: `--cpu 8` takes 4..8 (half, rounded up), `8..8` exactly, `1..8` a range; it is granted what is idle (room less unreserved load), between its minimum and its ask, whole cores unless a fraction was asked (`run_with.cpu_cores`, an int in JSON: `-j` takes integers). `oomph run` hands the number to the job (`{cpu}` in its argv, `OOMPH_CPU_CORES`, and the common job variables and `MAKEFLAGS=-jN` where not set). A minimum above cap − margin is refused; so are cores where the backend does not opt in (`RESERVES_CPU`: macOS; Linux later, with its own margins). Admission is per pool, in arrival order: a request is granted all its pools at once or none; one that waits sets `waiting_on` and `hold` (what it has ever been short of) and holds up those pools, except that while it waits for a turn at the cores it holds up only the rate pools, so memory requests pass it. A request with cores is a v2 lease (`v`, `res.cpu` {ask, min, got, used, peak}, `res.ram`/`res.mem` with memory, `res_granted`, a `grant` record); a lease without memory keeps the gb mirror `NO_MEM_GB` = 0.01 (1.8.4 to 1.9.1 drop a lease of gb 0); a request for memory alone keeps 1.8.1's shape. A v2 lease naming anything else (a later resource; disk until 1.12.1, gpu and vram until 1.14.0), or cores this code cannot read, is not weighed here: it is not granted and holds every pool's line, as in 1.9.2 to 1.11. The logger's child gets payload v 2 with each process's CPU rate, charges every grant its tree's busy cores (`used`, `peak`), and current.json carries `pools.cpu` {cap, margin, reserved, busy, others}, others smoothed; without a fresh logger an elastic request measures a quarter-second window itself, only when it is to be weighed. Queueing defaults from roadmap 02 §15 | Parallelism is what overloads a machine as surely as memory does, and `-j` is the knob agents hold. A rate pool saturates instead of running out, so elastic grants keep the machine busy without overcommitting; holding only the cores while waiting for a turn keeps memory requests flowing. Old writers keep working: a v2 lease that a 1.8.x process granted by its gb (no `res_granted`) goes back in the queue at its place on the next evaluation here, and an old client's request stuck behind a cores request is granted by the next refresh (`tools/ledgercompat.py` E) |
| Disk space (1.12.1, B2) | `oomph reserve --disk 20G[@PATH]`, `oomph run --disk …`, `oomph amend --disk 30G`, MCP `disk_gb`/`disk_path`: GB on **one pool** (roadmap 02 §4.4: an APFS container or a volume), a stock granted in full or not at all. At least 0.01 GB (two decimals are kept; less is refused, not kept as none). The path (default `$TMPDIR`; one not made yet counts as the nearest folder above it that exists, never `/` or `/Volumes`) is resolved when the request is made, by the caller (as the user, in the child for a root caller): its device in the mount table, then the system's pool (`data`), or the logger's pool of that device in current.json, or diskutil about that one mount (and its container); the lease keeps the pool id (`data`, `vol:<UUID>`, `mnt:` and 16 hex digits of the mount point's SHA-256 for one without a UUID: an id always fits the ledger's 80 printable characters, and a new lease the ledger's reader could not weigh is refused, never written) and the volume's name for people, never the path. A volume the logger ignores is refused with the reason, as is a request above free − margin. `margin` = low floor + max(2, low / 4): 25 GB where the floor is 20 (the system's pool), the floors of a pinned pool of that size elsewhere. `left` = free − margin − Σ over grants max(0, got − used); a pool under its critical floor grants nothing; no alone rule. Free space is the logger's (or one read live), and statvfs of the named pool's own mount right before a request is weighed. The logger's child, given each process's write rate (payload v 2, `w`), adds up what each grant's tree wrote since the grant (`res.disk.w`, counted up to `wt`) and charges `used` = min(got, own writes, the pool's drop since its grant (`base.free_gb`), what earlier grants left of the drop): Σ used over a pool never exceeds what it lost. Only a sample that lists every pool (the logger's, or one read live; not the system's pool alone, nor one while diskutil has not answered, or failed, for a mounted disk: `disks_partial`; a container diskutil cannot read fails the volume, so a pool's id never falls back to another while mounted) can say a pool is gone: a reserved pool missing from it is marked (`missing`) and its reservations end `volume_gone` after 120 s, at the time it went, counted only while evaluations come less than 120 s apart (`mseen`: after a sleep the grace starts again); back earlier, even at another mount point, the mark is cleared. The ledger's state carries `disk` {pool id: what is left}; the sample's leases `disk`, `disk_used`, `disk_pool` (an id, printable, at most 80). 1.12.0 cannot weigh a disk lease: it grants none and lets none pass, and the next refresh here grants an old client's request stuck behind one (`tools/ledgercompat.py` F) | A download or a dataset fills a disk as surely as a build fills memory, and the person and the other agents need the space that is promised. A pool id, not a mount point, because a second disk of the same name mounts as "Name 1" and must not inherit the first one's reservations. Own writes cap `used`, so space someone else filled is not handed out again as if the holder had written it; under-counting (a process that ends between two samples) only makes admission more careful. The grace before `volume_gone` covers a remount and the logger's first answer from diskutil after it. Linux refuses disk space until its logger lists volumes by id (`RESERVES_DISK`, as for cores) |
| GPU (1.14.0, G, switched off) | `oomph reserve --gpu-mem 16G[@CARD] --gpu 60[@CARD]`, `oomph run … [--pin-gpu]`, `oomph amend --gpu/--gpu-mem`, MCP `gpu_mem_gb`/`gpu_pct`/`gpu_device`; the code is `daemon/oomph_gpu.py`, loaded only when a request or lease has a GPU part. **Switch** `gpu_reservations`: `"gpu_reservations": true` in the root-owned settings file (`read_config`'s rules) or `OOMPH_GPU_RESERVATIONS=1` in the environment, read per request; off, a request, run or amend that adds or grows a GPU part is refused before anything is written (exit 75, `switch: gpu_reservations`, with the command that switches it on), while evaluation, `used`, `gpu_gone`, release and display of GPU leases always run. **Linux**: each NVIDIA card is two pools by its UUID (the identity; the index is only a label, refreshed from every sample): `vram:<UUID>`, a stock in GB, `left` = memory.free − margin − Σ over grants on the card max(0, got − used), margin 5 % of total − the driver's own part, no swap to fall back on; and `gpu:<UUID>`, a rate, `room` = 100 − Σ got, not elastic. A card in MIG mode, without memory figures or without a UUID is listed and not reservable; more than total − driver − margin of every card (or of the named card) is refused. Both parts land on one card; a job across two cards makes two reservations. A request names a card (`@1`, `@GPU-6ab19ebf`, a UUID prefix of 8 hex digits or more, resolved to the UUID at once) or none: among the cards that fit now and no earlier waiting request holds up, the **least committed** (used + promised and unused), then the lowest index; a waiting request that named none holds up every card it could ever fit on (pools `gpu:*`/`vram:*` until granted). Admission reads nvidia-smi itself (`live_gpus`, the cache of failures bypassed); without a list nothing new is granted on any card. **The grant** keeps the card in its parts (`dev`, `uuid`, `name`, `unified` false) and says it in `run_with.gpu` {index, uuid, name, env: CUDA_DEVICE_ORDER=PCI_BUS_ID, CUDA_VISIBLE_DEVICES=index} and the advice's first sentence. Jobs are not pinned: `oomph run` always exports `OOMPH_GPU_INDEX`/`_UUID`/`_MEM_GB`, and with `--pin-gpu` also the two CUDA variables (replacing inherited ones, said on stderr). **Use**: a grant's `used` is what its watched trees added on its card since the first of their grants there (`base`, the GB they already held at the grant: an unreserved model loaded before, as memory's `baseline_gb`), from `--query-compute-apps`/pmon, shared in grant order and capped at got (`peak` follows); more than got is `over`, more on another card than on its own is `elsewhere` (advice only), never for a card where the same trees hold a grant (a job split across two cards from one holder); `[N/A]` figures leave `used` out and the grant counts in full. A queued request amended past what its card (or, naming none, any card) can ever give is refused as a new one would be, so it never holds up every card for good. nvidia-smi's short question of 1.13 is asked only when the driver refused the long one (exit 2: a field it does not know); a timeout leaves the cards unread (asked again after 60 s), never without free memory. A model served by another account's process (Ollama, ComfyUI) is not measured in 1.14 (no `--watch-pid` yet). A reserved UUID missing from a full list (not cut at 16 cards) for 120 s ends its grants (`gpu_gone`) and refuses requests naming it; nvidia-smi failing says nothing. **Mac**: one pool `gpu:gpu0` for the share (charged from the logger's GPU rates per process); `--gpu-mem` is unified memory, charged against RAM through `mem` and carried in the gb mirror, refused above the exact working-set limit (`iogpu.wired_limit_mb`), noted above an estimated one; an exact limit is also a pool `vram:gpu0` for all grants together (Metal wires no more for all of them), so a request that would pass it with the others waits, and a queued one may not be amended past it; another card, or `--pin-gpu`'s variables, have no meaning there. **Older readers** (1.13 and before, the Mac's 1.9.8 logger child) cannot weigh a GPU lease: it holds the queue until a 1.14 client evaluates (`weighable`, roadmap 02 §9.3). Not built in 1.14: the desktop's 15 % on a display card, `others` by name, `--watch-pid`, a measured `dev` on a Mac | The cards that hold models are the scarcest thing agents share on a workstation, and CUDA fails an allocation instead of swapping, so a stock per card admitted on the driver's own free figure is the safe unit. Naming the card in the grant without pinning leaves agents and launchers in charge of their own processes; the least committed card keeps the same ledger and sample choosing the same card. Shipped off until it has been measured with real model runs (ROADMAP §11) |

### The shared directory is untrusted (1.8.4, H0)

Every user can write to `/Users/Shared/oomph`, so anything in it may be planted: a symbolic
or hard link to someone else's file, a FIFO, a device, an endless or sparse file, JSON with
huge numbers or deep nesting. The invariant: **no process running as root opens anything
inside it, to read or to write, by any route; root never waits on it; whatever root
republishes from it is rebuilt from typed, capped fields.**

| Topic | Decision | Why |
|---|---|---|
| The logger | Its ledger work (retire, evaluate, snapshot) runs in `oomph _ledger-refresh` as `nobody`, started by a thread of its own. The sampler drops its newest sample and process table into a one-slot mailbox (latest wins) and goes on; the thread reads at most 64 KB of answer within 5 s, kills the child after that, and the sample carries the last snapshot, unless it is older than two intervals. While nothing is reserved the child is skipped as long as `ledger.json`'s `lstat` is unchanged (at most 5 min) | A FIFO planted as `ledger.json` used to stop the logger, a held lock delayed every sample, a malformed lease made every sample raise |
| Other root callers | `sudo oomph reserve/release/amend/run/reservations/check/status/mcp…`: each ledger operation runs in `oomph _ledger-call` as the user who ran sudo (`SUDO_UID`), else `nobody`, with the sample and process table root measured. `oomph run` still runs its command as root; only its bookkeeping drops privileges. The ledger code refuses to run as root at all (a fence in `Ledger`, `read_ledger`, `read_history` and the history writer) | `sudo oomph reserve` followed planted links |
| Reading | One reader, `read_bounded`: `O_NOFOLLOW` + `O_NONBLOCK`, a regular file with a single link (checked on the descriptor), a size cap; the directory itself opened `O_DIRECTORY` + `O_NOFOLLOW` and every file relative to it. One parser, `loads_untrusted`: no integers over 30 digits, no NaN/Infinity, ≤ 256 keys per object, no deep nesting. One table of limits (`LIMITS`). The app's `readShared` does the same. What a writer may carry back into the directory (the ledger, the history log) and what `oomph serve` sends is read `shared` (1.8.10): the file must also be readable by everyone (all three read bits: a user in the file's group gets the group's bits, not the others'), and after the read still have one link and still be the file the name leads to (read again, up to three times, when a writer renamed a new one over it); the history rewrite carries over only lines shaped like oomph's records | No FIFO, device or giant file can hang or flood a reader. No check can tell a hard link from the real file for sure: an attacker links someone's private file at the name and unlinks it right after the writer's open, so the open file has one link again, and even a check by name can be raced. The mode, read on the descriptor, can't be: a file everyone may read leaks nothing when it is copied into a file everyone may read. What remains: a file whose mode lets everyone read it but whose ACL denies the attacker, and then only lines shaped like oomph's records |
| Validation | `read_ledger` checks every lease and history entry field by field; one that doesn't fit was never written by oomph and is dropped. Types are checked, nothing is cut: a view limit never reaches the read-modify-write path | A malformed ledger can't make the CLI, the MCP server or the logger raise |
| Writing | No writer opens an existing name for writing: a random temporary name created `O_EXCL`, `fchmod` on the descriptor, then a rename. The history log is rewritten the same way on every write (read, keep 14 days and ≤ 8 MB, add, rename) instead of being appended to, so it stays one file in the same format; 1.8.1–1.8.3, which append under the same lock, keep working | A hard link can't be refused by any open flag; a rename never writes through one |
| The lock | `ledger.lock` opened read-only, `O_NOFOLLOW` + `O_NONBLOCK`, a regular file; `flock` polled to a deadline: 5 s for interactive callers (a holder keeps it for milliseconds, so this only runs out when it is stuck or hostile, yet survives one swapped out under pressure), 1 s for the logger's child (it runs again next sample). Then "busy" (exit 75), never a hang | |
| Installers | Leave the directory alone: no `chown`, `chmod`, `install -d` or sticky bit | Root touching it is exactly what this rules out |
| Tests | `tools/selftest.py` covers the unprivileged half; `tools/roottest.py` runs as real root in CI with an audit hook on every file root opens | |

`oomph version --json` reports `"hardening": 1`, so a later `oomph share on` can refuse code
without it.

## The terminal dashboard (1.9)

`oomph top` is the popup's dashboard full screen in a terminal (spans, the two lists and their
cards, the panels, help, themes, glyph sets); `--once` prints one frame, `--ssh host` runs it on
another machine.

| Topic | Decision | Why |
|---|---|---|
| What it may do | Read only: it shows the logs, the ledger and the incidents and starts no change to any of them. `o` writes a report through `oomph html` / `oomph incident --html` (a child in its own session, left to finish after `q`, one at a time), `y` copies a path | The first full-screen release is a viewer; acting on reservations from it is a later decision |
| As root | `sudo oomph top` is a pure viewer: the ledger is read as in every root path (a child as `SUDO_UID` or `nobody`, here every 30 s), nothing is saved, no report is written, no clipboard tool runs; the status line says "read-only" | The 1.8.4 invariant: root opens nothing in the shared directory, and writes nothing into a user's folder |
| Settings | `top.json` in the user's own state folder (`~/Library/Application Support/oomph`, on Linux `$XDG_STATE_HOME/oomph`, found from the password database, not `$HOME`), mode 600, written by a new file and a rename; the span, `--bell`, and a colour, theme or glyph set given by hand. A folder that is not the user's makes the run read-only; choices passed by `--ssh` are not saved on the far side | `sudo -u` keeps `$HOME`; a damaged file falls back to the defaults |
| `--ssh` | The local `oomph top` stays as the parent of `ssh -t` with fixed options (no multiplexing, agent, forwardings or `RemoteCommand` from `~/.ssh/config`; keep-alive ends a dead link in about 15 s). It puts this terminal back when ssh exits; the far side leaves when its terminal hangs up. The far side's shell exits 121/122/123 (no oomph on macOS / Linux / other) or 124 (an oomph without the dashboard); the parent then prints the install line for that system and exits 127. Nothing is copied to the other machine | A far side that dies cannot restore this terminal; no code runs remotely without an install |
| Budget | Under 1 % of a core and 40 MB resident for a day in a pane, measured in CI (`tools/toptest.py --minute`). The worker reads only what changed (file identities once a second), keeps the history as typed arrays, draws a quiet screen every 10 s and writes nothing when nothing changed. Started as a script, `oomph.py` compiles itself and keeps that resident, so `oomph top` starts again (`execv`, same process and terminal) on the bytecode `install.sh` built. Without a logger it measures itself every 30 s and keeps only the chart's points | A dashboard that watches memory must not be what uses it |
| The terminal | Raw mode, the alternate screen and bracketed paste, restored on every way out (`q`, an exception, SIGTERM, SIGHUP, a vanished terminal) without waiting on a terminal that stopped reading; ctrl-z stops it where a shell does job control | A broken terminal after a crash is worse than the crash |
| Inspect (1.9.5) | `i`: a cursor column on the chart and the strip; the readout is docked in the place of the lists (a floating card beside the cursor where a pane has none) and says what the app's hover card says for that column: `oomph_view.hover_info` is a port of `MemoryChart.hoverInfo`, held to it by the `hover` group of `tools/vectors/chart.json`, which includes every column of the golden frame `80x24-inspect`. The cursor keeps its time when the span changes; `enter` selects the incident or reservation under it | One readout, two programs, the same words |
| Time axis (1.10.7) | The app's x axis is one `TimeAxis`, built once in `PopoverView` and shared by every chart row: the mapper and its inversion (`time(at:)`), the clock-aligned grid and labels, a row bucketed into screen columns, the away, no-data and not-received bands, the incident rules, and `start`, which takes another machine's axis back to the oldest sample it reported. `oomph_view` ports its maths (`mapper`, `time_at`, `calm_bands`), held to it by the `mapper`, `invert` and `calm_bands` groups of `tools/vectors/chart.json`. Splitting it out of `MemoryChart` changed no pixel: every popup state, light and dark, drawn before and after by `tools/renderfixture.py --against` | More resources become more rows (roadmap 02 §3.7), and rows that share a time line must share the maths that draws it |
| Mouse (1.9.5) | Off by default; `ctrl-o` or `--mouse`, remembered in `top.json`. Buttons and the wheel in SGR coordinates (modes 1000 and 1006), no motion: no hover, nothing streams over an SSH link. Clicks choose spans, rows (a second click opens) and the column to inspect; the wheel changes the span or scrolls a list. The leave sequences always turn it off | Mouse reporting takes the terminal's own text selection away, and copying a number is common |
| Machine tabs (1.10.3, T2) | Row 0 is a tab per machine: this one, then the pinned entries of `machines.json`, the app's tabs. The terminal has no switch: it is not subject to the app's Local Network question. `oomph top` starts the app's engine, `oomph remote sync --json`, as a child in its own session, and uses it as the app does: `watch` (every tab, the selected one first), `retry`, `pin`/`unpin` (disconnect, undo), `rename`, `forget`; `+` runs `remote add --json --no-mirror --ask` as the app's popover does (the code on stdin, bound to the key shown with `--fp`; the identity question answered on stdin). It never writes `machines.json` nor anything in a mirror, opens no socket and takes no lock: engine or follower is the child's business (01 §4.3). What it draws comes from the files alone: a tab is live only while `status.json` says so, was rewritten within 10 s and names a living process; otherwise what claims to be now is grey, and what was not received is dotted by kind from `sync.json`'s coverage map. The child runs only while another machine is a tab; `ctrl-z` closes its input first (the lock is free for the app at once), `fg` starts a new one, an ended one is started again after 1, 2, 4 … 60 s. Its events are read on a thread of their own, and the engine writes them without ever waiting (a full pipe drops one): a terminal that stops reading cannot hold engine.lock hostage. Over `--ssh` the far side runs as `--no-connect`: it shows that account's mirrors as they were received and makes that host dial nobody. The start tab follows D9 as the app does: this machine only for critical pressure, an open incident or a silent logger. Not as root, nor read-only: then there are no tabs. On Linux too from 1.13.4 (T3): `oomph remote` and the engine run there unchanged, their files in `$XDG_STATE_HOME/oomph/machines`, so a Linux machine is a viewer and adds a Mac over ssh (it opens no port: R3, a TCP listener on Linux, is dropped) | 04 §4.7: the dashboard adds no protocol; one engine per account, whoever started it, so the app and the terminal never compete for a machine |

## Linux for agents (1.9.4)

The commands agents use, on Ubuntu 22.04+, Debian 12 and the RHEL 9 family (Python 3.9+, cgroup
v2): `check`, `reserve`, `run`, `mcp`, `hook`, `doctor`, `oomph top`, with the Mac's exit codes.
No logger yet (until 1.13.0; see The Linux logger) (no history, incidents or kills), so every reading is live. Plan and reasons:
roadmap 03 (§5, §7.3, §7.5).

| Topic | Decision | Why |
|---|---|---|
| Sources | `daemon/oomph_linux.py` reads `/proc` and `/sys` only (no subprocess, no root; from 1.13.0 the logger and the CLI also run `nvidia-smi`, and the logger `journalctl`, each as a separate program): `meminfo`, `swaps`, zram's `mm_stat`, `/proc/pressure/*`, the process's cgroup files, `/proc/<pid>/{stat,status,cmdline,cgroup}`. Every path goes through `OOMPH_SYSROOT`, so `tools/linuxfixture.py` replays recorded machines on any system | One backend contract (`oomph_darwin`'s names), testable on a Mac |
| Memory classes | available = `MemAvailable`; compressed = zswap's pool + what zram's swap devices cost in RAM; swap = swap on disk (zram is not counted as swap); app = anon + shmem; wired the remainder, so the classes add up to RAM | `MemAvailable` is the kernel's own estimate of what can be had without swapping; the popup and `oomph top` keep their rows |
| Level | From PSI (memory `some`/`full` over 10 s: 10/5 % warning, 40/15 % critical) plus headroom: below min(15 %, 8 GB) of RAM available with swap half gone, or below min(10 %, 4 GB), is a warning. **Headroom alone stops at warning**: critical needs measured stall time. Stall time of a cgroup at its own limit is not the machine's (attributed and discounted). Without PSI (RHEL 9's default) the level stops at warning and `doctor` explains `psi=1` | A container thrashing at its limit, or a full page cache, is not a machine about to kill something |
| Margin and admission | The ledger's margin is the upper bound, min(15 %, 8 GB) of RAM, at least 0.2 GB, rounded up, so a grant used as declared cannot change the level by itself. A lone request bigger than what is left is granted only up to what RAM and swap can hold less the lower bound: available + swap room − min(10 %, 4 GB), rounded down. Swap room counts free disk swap whole and free zram only by what compressing saves (the ratio the devices achieve, 1 to 3, else 2). A request beyond it is `refused` (exit 75) with the arithmetic and the largest that fits | Linux has no swap that grows; zram's pages stay in RAM. `tools/linuxtest.py` checks the three invariants over a table of machines |
| Scope | Inside a cgroup whose `memory.max` or `memory.high` is below RAM (a container, a systemd slice), the figures are the cgroup's: the limit is RAM, available what it leaves, its own swap allowance within the host's. Requests carry `scope`; both walls count, each against its own grants: the cgroup's limit against the same scope's, the host's memory against all. A request of another scope is granted only by a process in it | A container's agent must not reserve the host's 64 GB |
| The ledger | Per user and per machine: `$XDG_STATE_HOME/oomph/ledger/<machine>/` (folder 0700), `<machine>` hashed from `/etc/machine-id` (`local` without one). `ledger.kind` says `user` ("yours only"). Leases carry `user`, `holder.uid`, `holder.ns` and `scope`; the ledger records the boot id, and every lease of an earlier boot ends `holder_gone` at that boot | No root and no shared folder until the Linux logger brings a group ledger (roadmap §10) |
| Root | Under `sudo` the ledger is the invoking user's and the operation runs in a child as them (H0); root's own state (settings, `oomph top`'s) stays root's. Root **without** sudo (a root agent in a container, `su -`) uses root's own per-user ledger **in place**, only at the default path and only when every folder from `/` down to it is root's and not group- or world-writable and the ledger folder is 0700; otherwise it is refused with that reason. A folder `OOMPH_LEDGER_DIR` names always goes through the child | 03 §7.5: root's 0700 ledger is not shared, so the 1.8.4 invariant (root opens nothing in a *shared* folder) holds |
| Processes | Names from `comm` and argv, **never from `exe`** (Claude Code's native binary is named by its version); footprint = RssAnon + VmSwap; groups by container, systemd unit or app scope, else the program | Both Claude Code installs show as `claude` |
| Install | `git clone` + `linux/install.sh`: `~/.local/lib/oomph-<version>` behind the link `~/.local/lib/oomph` (one rename), `~/.local/bin/oomph`; the skill and MCP server when Claude Code is set up. As root only as itself with root's own `HOME`; never under sudo. `linux/uninstall.sh` (`--purge` also the ledger) | No root needed for what agents use |
| The hook's state | `$XDG_RUNTIME_DIR/oomph`, else `oomph-<uid>` in `$TMPDIR` or `/tmp`, a folder of the user's own, 0700; a state file of another owner, or with a time in the future, is ignored | A shared `/tmp` would let another user silence the warnings |
| Presence | None without the logger: `idle_s` is unknown, drawn as a dash; nothing is drawn as away | |

## The Linux logger (1.13.0)

`sudo linux/install.sh --system`: the same `oomphd.py` as on a Mac, as a systemd service, plus
the machine's ledger and alert hooks. Plan and reasons: roadmap 03 (§5.5, §5.6, §5.13, §8, §11.2,
§12.3, Appendix A and C.3), ROADMAP §11 (D16, NVIDIA).

| Topic | Decision | Why |
|---|---|---|
| The service | `linux/oomphd.service`: `User=oomphd` (a system user with its own group, no home, no shell), `SupplementaryGroups=systemd-journal`, empty capability sets, `NoNewPrivileges`, `PrivateNetwork`, `RestrictAddressFamilies=AF_UNIX`, `IPAddressDeny=any`, `ProtectSystem=strict` with its log, state and ledger folders writable, `ProtectHome=read-only` (a separate `/home` disk stays visible to `statvfs`), `PrivateDevices`, `SystemCallFilter=@system-service ~@privileged` and the six calls that reach other processes (`ptrace`, `process_vm_*`, …), `MemoryDenyWriteExecute`, `MemoryMax=256M`, `OOMScoreAdjust=-900`, `Restart=always` with a start limit (five in five minutes, then `failed`). Exposure 0.8 (`systemd-analyze security`, checked in CI and on a machine with systemd 255) | It parses text any user chooses (process names, log lines): it must be no bug away from root, and unable to send anything anywhere |
| Kills | One `journalctl -f -o json` child with the kernel's and the user-space killers' filter. A victim is (killer, pid) for 30 s: a group kill's repeated line and earlyoom's SIGTERM then SIGKILL count once; the class comes from the kill line's own prefix (`Memory cgroup out of memory` / `Out of memory`), since summaries are rate-limited. OOM events are summaries, or kill lines of one class and cgroup within a second. The stored cursor is always that of an entry this filter returned; the first start reads the boot from its beginning without counting its past. `/proc/vmstat oom_kill` is only a lost-record check, compared with the kill lines before de-duplication, a gap that stays 30 s is `unknown` (journald lags under pressure; a later line for it is then not counted twice). Without a readable journal: the counter, as machine-wide at warning or above, else at a cgroup's limit. State in `/var/lib/oomph/daemon/state.json` | C.3 rows 9 and 13: a group kill reports its victim twice, and systemd 249 drops the first match after a foreign cursor |
| Incidents | A machine-wide kill (`oom`, rank 90) or a user-space killer's (`oomd`) opens one at once, headlined "OOM killer killed node (pid 48211, 2.1 GB)" (44 characters at most: the pid goes before the name is cut). A cgroup with five OOM events in ten minutes makes a **quiet** incident: one per machine and day, no notification or hook, kept 14 days, left out of `oomph incidents` and the dashboard (`--all` lists it). `syslog.txt` holds the OOM reports (header, memory summary, kill lines: not the table of every task, which `hidepid` would hide) and the killers' lines of the last 15 minutes and nothing else of the kernel log (256 KB; of a storm, the latest) | The logs are readable by every local account; `kernel.dmesg_restrict` exists for a reason |
| Telling somebody | A journal line at critical for an open and a kill (`<2>` on stderr), at notice for a close or a quiet incident. An alert record `alerts/<id>.<event>.json` per open, kill and close; `oomph-alert.path` starts `oomph-alert.service` (a `DynamicUser` that may reach the network, exposure 1.1), which runs `oomph alert --run-hooks`: each record after its cursor to every script in `/etc/oomph/alert.d` that is root's, writable by root only and readable by all (a 0700 script would fail as the runner), 30 s each, with `OOMPH_*` variables cut to `[A-Za-z0-9 .,:;()/%+@_-]` and the record on stdin; it looks again until nothing is left. The logger rewrites `alerts/.beat` with each sample while a record is younger than ten minutes, so a record written as the runner finishes is not left behind. Records go after a day. Secrets live in `/etc/oomph/alert.secret` (root's, 0600), which the unit hands over as `$CREDENTIALS_DIRECTORY/alert` (`LoadCredential`); `sudo oomph alert --test` runs the hooks the same way (`systemd-run`, a `DynamicUser` with that credential), and `--run-hooks` runs only under the unit | The logger has no network and runs nothing; the scripts' account can write nothing of oomph's; scripts are readable by every account, so they hold no secret |
| Who may use it | The logs (0755/0644) and the machine's ledger `/var/lib/oomph/ledger` (0777, no sticky bit; made once, then left alone) are open to every local account, as on a Mac. A client takes that folder whenever it exists, never a per-user one beside it; root without sudo (`su -`, a root agent) uses it through a child as nobody, as on a Mac. `doctor` says how to keep it to a group (`chgrp`, `chmod 2770`, the members and `oomphd` in it); the logger then keeps purposes and projects out of the samples, which stay readable by all. `doctor` also names a per-user ledger left from before and an own copy in `~/.local` that is not the machine's | D16: a personal workstation; two ledgers would grant the same memory twice |
| CPU, disks, I/O | Ticks per core from `/proc/stat`; each process's CPU from its world-readable `stat` (its own `utime`, `stime` and its reaped children's), new processes known by their start date (boot time + start ticks); I/O from `/proc/diskstats`, whole disks only (no partition, loop, device-mapper or md twice); disks from `/proc/self/mountinfo` by the file system's own read-only flag (the sandbox's view of `/` is read-only), `statvfs` only for local disks (a dead network mount would block it; a FUSE disk such as ntfs-3g is waited for at most 2 s in a thread, then skipped while that thread waits and for a minute after, by the logger and by admission alike), pools by device, ids `vol:<UUID>` from udev's database (the sandbox has no `/dev/disk`), the system pool's floors 5 % and 1 % within 2..20 and 1..5 GB; below them a `disk_low` event and a journal warning, for `/` too | Other users' `/proc/<pid>/io` needs ptrace rights the logger does not have; a small server's disk is not red at 19 GB |
| NVIDIA | `nvidia-smi --query-gpu` and `pmon -c 1 -s um` (30 and 100 ms on two RTX 4090): per card busy time, memory used and the card's size, and from 1.14.0 its free memory, `display_active` and `mig.mode.current` (a driver that refuses one of those fields is asked the short form instead, for NV_RETRY_S); `card_sample` makes the sample's block of a card (the logger's and admission's live read alike, the driver's own part = total − used − free); per process memory and SM share, names from the logger's own process table. A driver without pmon: memory per process from `--query-compute-apps`. Run as a program of its own, as nobody when the caller is root; never loaded as a library. Where `nvidia-smi` and `/dev/nvidiactl` exist the installer adds `oomphd.service.d/20-nvidia.conf` (`PrivateDevices=no`, `DevicePolicy=closed`, only the NVIDIA devices, an empty `/dev/shm` of its own, no `/dev/mqueue`: exposure 1.0) | No GPU library in a process that parses untrusted text, none as root |
| Install | `linux/install.sh --system` (root; `sudo ./install.sh` on Linux): the code side by side in `/usr/local/libexec/oomph-<version>` behind one link, `/usr/local/bin/oomph`, the account, the folders, the units (with the Python it chose), the service restarted onto the new version and its first sample awaited (read as `oomphd`). Root makes and changes nothing inside a folder of the logger's (`alerts/` is the logger's to make), where the account could have put a link. `--no-journal` leaves the journal group out. `linux/uninstall.sh --system [--purge]`: `--purge` empties the ledger as nobody, with the ledger's group (root opens nothing in it) | Root once; a user's own `~/.local` install keeps working beside it |
| Linux words (1.13.4, L3 and T3) | A tab, a frame, a report and the AI harness speak the words of the machine whose data they show, never of the one they run on: a sample's `os` and the machine block in it decide. `oomph top` (`oomph_view.linux_tiles`, from `oomph_top.linux_facts`): the tile matrix of the app's Linux tab in the terminal's labels (Kernel, Available or Compressed, the RAM with its decimal or the Memory limit, swap or zram, Stalled or Idle or what is available, the biggest group), held to the app's answers by `tools/linuxvectors.py`; the legend's series only as the machine has them, no *away* on a server; the header's *avail*; the readout's Available in place of the peak; the `cp437` glyph set for the Linux console (`TERM=linux`: half blocks, square corners). The app: the legend's series and Linux texts, the hover card's row budget (series 2 to 4, Available, one Stalled line from each point's PSI, one incident, two events, two reservations), the capsule's tooltip, *Biggest groups now*, the tour's notes, ✦ by the machine's consent as for a Mac. `oomph report` and `oomph html`: available and stall time per step, Kernel, groups, the least available and the most stall time (`min_available_gb`, `max_stall_pct` in a Linux summary), no unowned memory or away on a server. `oomph ai-report`: `oomph_ai.data_os` picks `SYSTEM_LINUX` (the OOM killer, stall time, containers at their own limit; no jetsam), and the tools answer in its words (kernel, available, stall time, `oom_kills` from the kernel log) | The same data can be read on a Mac, on Linux or over a mirror: only the data knows which system it describes |
| `serve --stdio` | Answers for a Linux machine as for a Mac (the same code), with `machine.logs`: `ok`, `absent` (no logger), `denied`. An incident leaves with its `quiet` flag and cgroups, so a mirror's viewers (`oomph top`, the app) leave a quiet one out as the machine's own do; `incidents.open` still lists it, so the mirror fetches it again until it closes | Linux machines are tabs over SSH (D6) |
| Others' processes | Where `/proc` is mounted with `hidepid`, the logger does not name what it cannot see: another account's victim is `?` with its size (no pid, account or cgroup) in events, samples, headlines and alert records, and so is a storm in another account's slice; `syslog.txt` is written 0640 for the logger's group only (it holds the kernel's lines, root's under `dmesg_restrict`), and `serve` never sends it | 03 §5.6: the logs are readable by every local account |
| Calm | `oom_kill` events carry `kills` (the machine's) and `cgroup` (at a cgroup's own limit) apart; one with only the latter, and a quiet incident's open and close, is no alarm in `oomph top`'s events or the HTML report, and no mark on its chart | 03 §5.6: a container at its own limit is never news |
| Root reading the logs | The logger's account owns `/var/log/oomph`: a root reader takes a line of at most 1 MB and at most 256 MB of a file, unpacked (a gz bomb or a file without newlines costs only that much time), and never follows an incident folder that is a link. Reports without `-o` go into a folder of the caller's own (`$TMPDIR` where it is that, else `$XDG_RUNTIME_DIR/oomph`, else `reports` in the state folder; root's own home under sudo), created new; `--open` uses `xdg-open` only with a desktop and never as root | 1.8.4's invariant; 03 §12.3, §12.4 |

## Remote machines (1.10)

Read-only, Mac to Mac over TLS, or anything with oomph over ssh (roadmap `01-remote-machines`).

| Decision | Why |
|---|---|
| The listener is not the logger: `local.oomph.share`, a second LaunchDaemon, runs `oomph serve --inetd` once per connection as `_oomph`, a role account with a group of its own | a root daemon on the network is the main danger; the logs are world-readable, so serving them needs no privilege. A crash or a flaw dies with one connection |
| `share on` and `share reload` start the service once and wait for it to close the connection (90 s at most). `serve --listen` (tests) starts a fresh `serve --inetd` per connection, as launchd does, not a bare fork | a new role account's first interpreter through the `/usr/bin/python3` shim took 14 to 26 s on CI runners, longer than a viewer's 10 s for the handshake. On macOS a child that forks without exec reads the time zone file at every `localtime()`, which made a pairing's catch-up ten times slower than the real service |
| A peer gate before TLS: loopback, ranges allowed by `share allow` (at most a /8 or an IPv6 /32, none of Teredo, 6to4, NAT64 or mapped; the CLI refuses wider ones, `--remove` takes any, and `share status` and `share on` name one allowed before 1.14.1 that the gate still honours), else only peers on the subnet (or link-local on a wired or Wi-Fi interface) of a network sharing was turned on for, identified by its router's address and hardware address | nothing a stranger sends reaches Apple's old TLS library (LibreSSL 2.8.3). The port still accepts and closes everywhere; laptops should be watched over ssh |
| TLS with a self-signed key the viewer pins; a one-time code (60 bits, 10 minutes, 5 tries) proved by both sides over the certificate each sees (PBKDF2, HMAC); then a per-viewer token, of which the server keeps only a hash | no CA, no accounts; a machine in the middle fails both proofs. Every pairing failure looks the same and costs the same derivation and pause; "too many viewers" is told only after a right proof, and the code is kept. Authentication fails closed: a `clients.json` that can't be read or a lock not had is no answer (the viewer keeps its token and tries again), never "authenticated" |
| State split by owner: root's `config.json`, `cert.pem`, `key.pem` (root:_oomph 640; `share on` re-checks an existing key through its descriptor, puts its group and mode back, and refuses one that is a link or not root's); the service's `run/`. Root never opens a path in `run/` (the share commands fork and become `_oomph` first) and interprets nothing from it but ids matching `^c-[0-9a-f]{8}$` | a compromised service account must not steer root |
| An administrator per pairing code and per revoke (`sudo oomph share pair`, `revoke`) | handing out access is an administrator's act (roadmap §11) |
| The viewer's one client is the engine, `oomph remote sync`: one child per machine, mirrors in the log's own layout, a coverage map of what was received, backoff 1 to 60 s. The app starts it while its popup is open and tells it to go idle when it closes (it leaves a minute later) | no background network traffic (D8); every reader already reads a directory |
| A machine's AI consent travels as the capability `ai`, absent unless its owner ran `sudo oomph share ai on`; a change reaches open sessions within a second (a `machine` notification; over SSH too, subscribed or not), and a consent last heard more than a day ago no longer counts | another machine's process names and paths reach a model only with that machine's consent (D7), and only while it still gives it |
| Tabs in the app behind `machinesUI` (off) | macOS's Local Network permission for an ad hoc signed, self-rebuilt app is untried (roadmap 01 §7.6) |
| The + (1.10.2) runs the bundled `oomph remote add TARGET --json --no-mirror --ask` once per step, not a pairing inside the engine: the code goes on stdin, `--fp` binds the pairing to the key the code step showed, the identity question comes out as a line and its answer goes in. The tab then fills live through the engine | the logic stays in Python, where it is tested (tools/sharetest.py); the popover's own reading of links, codes and addresses is held to the CLI's by tools/vectors/connect.json |
| Share this Mac runs the installed, root-owned CLI through one administrator prompt per action, from a closed set (`share on --pair`, `share pair`, `share off`, `share revoke ID` with the id matched and quoted); its view reads `share status --json` as the user | the bundle is the user's to change; root runs only code root installed |
| The connect popover is an `NSPopover` pointed at the + inside the borderless panel; the panel stays under the administrator prompt and while a fresh code waits (at floating level, so dialogs stay above it). `connectSheet` shows it as a sheet instead | the popover in the panel was never tried on a real screen (roadmap 01 Appendix A): renders draw its content in place |
| "Blocked by macOS" is established by the app, not guessed: after the engine reports a connection that failed at once, the app opens one `NWConnection` to the same host and port, sends nothing, and reads `localNetworkDenied` from the path. Its only networking | an error number can't tell a denied app from a machine that is away; the probe comes from the process the system's alert names |
| A connection looks at its pairing and at `config.json` once a second on a timer, whatever the viewer sends: a revoke, `share off` and Deactivate end it with a `bye`. A pairings file it cannot read is no revocation | a viewer that talks without pause must still meet its revocation; a viewer deletes its token on one, so a passing read error must not look like it |
| Every opening is a reconnect (D8), so a machine that was live at the last close goes through 01 §3.6's three steps: a grace (twice its last connect time, 0.8 to 3 s, ssh 1.5 to 6 s) with its last values at 60 %, then *Connecting…*, then the verdict at 8 s (ssh 20 s) or on a definite failure | "Not connected" is never said of a machine that is only reconnecting |
| Only critical pressure, an open or unseen incident and a silent logger make the popup open on This Mac instead of the remembered tab | a small disk or hours of Warning must not take over every opening (D9) |
| A Linux machine is a tab from 1.13.3 (the Linux-tab gate, roadmap 03 §3.9), behind the same switch; a machine of any other system is still not drawn. A tile's meaning follows facts of the machine, never its momentary state: `machine.measures` (zram, zswap, PSI, kills, all processes seen), its kind (desktop or laptop: Idle; server or container: stall time) and the sample's `scope` (a cgroup: Memory limit). The words are pure functions (`LinuxTab`), held by `tools/vectors/linux.json` to samples the real Linux backend measured on recorded machines and to the gate's rules: no "Wired", "Idle 0 s", "Compressed 0.0 GB", a RAM without its decimal or "biggest app"; an `oom_kill` alarms unless `oomph.calm_event` calls it no news, and kills at a container's limit are never in the machine's count. The vectors' machine blocks are invented, never the measuring host's. Under the four-resource layout (`resourcesUI`, gap G3) a Linux tab keeps the four tiles and its Memory tile takes the Linux words (the RAM with its decimal, the group's Linux name, *stalled* in the flag slot); the remedy still replaces the tiles. A mirror bounds a cgroup sample's `scope` and `linux` blocks (the host's figures) by 16 x the host's RAM, not the limit's | the first app that shows a Linux tab must not show it in a Mac's words (03 Appendix B, finding 5); a small container must reach the app whole |
| Quiet incidents (containers at their own limit) are kept in the mirror and folded into one grey row for the latest, with how many came before; they are never unseen and never on a tab's badge. A lease and a reservation record carry `user` over the wire, so a Linux tab shows who holds what once two accounts do | a container host's routine must not bury its real incidents; on a machine whose ledger is open to every account (D16) the owner wants to know whose job it is |
| A reached machine with little to show gets a capsule and a remedy instead of a banner (no added height): *No readings* (`logs` ok, its current sample older than three intervals and 15 s; a callout from the capsule), *No access* (`logs` denied) and *No logger* (`logs` absent, or a current sample left by an earlier logger: *No readings*), the latter two in the tiles' place (also under `resourcesUI`); never *No readings* while the link catches up; each with one command for the other machine (at most 31 characters) and Copy | 01 allows no banner; every remedy fits the 480 pt popup |
| Another machine's reports (1.14.2, R2) are drawn on the viewer by its own `render_html` over that machine's data: the full samples of the window (`samples` with `full`, a day at most, rebuilt from named fields with the disks but no mount paths; above 48 MB of them the oldest go and the cover starts at the first kept, since an incident ends its window; parsed for an AI analysis that is about 300 MB at the peak) in the mirror's `full/` for a day, the summary samples around them. A remote page is never opened. The gate is a test: over strings of every hostile kind the page has no element or attribute the template lacks, one JSON data block and the template's script | a machine that turned hostile could put anything in a page the browser runs as a local file; trusted code over untrusted data is only as good as its escaping, so that is what is tested |
| `oomph --machine NAME` points the log and ledger directories at the mirror and allows only commands that read; nothing of this machine is measured under the other's name (`live_sample` refuses). One connection catches up the current sample, ledger and incidents (and a report's full samples, an AI analysis's incident system logs) and touches nothing the engine keeps account of: not `sync.json`, the day files, events, records or `status.json` while the engine runs (its contact goes to `contact.json`). What it read is retyped as the readers here expect (`typed_sample`, `typed_current`, `typed_incident`), and a failure to read it exits 4, never 1 or 2. `--machine` counts anywhere before `--`. No machine of that name exits 64 (`top` too), and so does a usage error under `--machine` (no command, one that measures here, one that decides or writes). A check without a fresh sample (it can't be reached, or its logger has gone silent) exits 3. Its verdict and reservations (`check`, the AI's `current_status`) come from its typed latest sample and its ledger as its logger judged them (`remote_coordination`), never from this machine's processes judged against its leases; as a second wall `Ledger` and `_decide_inputs` refuse under `--machine`, so nothing is written into the mirror's ledger (a test holds the folder byte for byte). `full/` is pruned by any `--machine` command too, not only by the engine | an agent can ask about another machine; a stale answer must not pass for a current one, and a command must not race the engine's coverage |
| Remote text is labelled: a line above text output, `origin` and `remote_text` in JSON, a sentence in the AI's system prompt and around each of its tool results | another machine's process names, paths and purposes must not steer an agent here (01 §7.3) |
| The app registers the `oomph` URL scheme; a link only fills in the popover (with `machinesUI`; otherwise it shows and sends nothing, though the registration itself can't be switched, so a link may launch or bring up the app) | a web page or a message must not connect or pair by itself (01 §7.3) |

## AI analysis (1.4)

| Decision | Choice | Why |
|---|---|---|
| Who investigates | The model, through ten read-only tools over the logs (`overview`, `timeline`, `top_at`, `process_history`, `events`, `incidents`, `incident`, `syslog`, `current_status`, `claude_sessions`), up to 12 rounds, then a forced write-up | A fixed prompt with a data dump can't follow a lead; tools let it zoom from "critical at 03:53" to the process, its parent and its session. Results are capped at 14 k characters so a broad query can't flood the context. |
| Providers | Claude (Messages API, `claude-opus-5-5`, adaptive thinking at effort high, server-side refusal fallback), OpenAI (Responses API), Ollama (`/api/chat`; models without tool support get one pass over the briefing) | What the user asked for; all over plain HTTPS with the standard library. The Claude turn sends the whole previous assistant content back unchanged. |
| Credentials | Login keychain, one item per provider; handed to the harness in `OOMPH_AI_TOKEN`; read only for a report (an ad hoc signed build is trusted by its hash, so each upgrade asks once), forgotten on Disconnect | Never in a file, a preference or `ps` output. |
| Progress and abort | The harness prints one JSON object per line (`progress`, then `done` or `error`); the app shows the latest as the Report button's tooltip and stops the run with SIGTERM | No IPC beyond a pipe; aborting leaves nothing behind. |
| Output | The normal 24 h report with the analysis on top and the tool-call log in a fold | The model's claims sit right above the evidence they cite. |

## Upgrades (1.5)

| Decision | Choice | Why |
|---|---|---|
| Release model | Every commit on `main` is a release; versions are `git describe --tags --match 'v*' --always --dirty --first-parent` without the `v` (`tools/version.sh`, the scheme Glow uses); `v*` tags mark the milestones | No separate release process to forget; the version says exactly which commit you run. |
| Where versions live | Source carries `VERSION = "dev"`; `build-app.sh` / `install.sh` stamp the describe version and commit into the bundle, the CLI and the logger; a checkout derives it at runtime | One number everywhere, and the app knows its commit for exact comparisons. |
| When to check | When the popup opens and the last check is over 24 h old (and on **Check**); tools (`xcode-select`, `xcrun git/swiftc`, SDK, `codesign`) once a day | No background network traffic; never pops Apple's "install developer tools" dialog. |
| Newer? | By commit ancestry in the clone (`merge-base --is-ancestor`); after a history rewrite, by comparing versions | Exact while history is linear; still sane after a force-push. |
| Source | `~/Library/Application Support/oomph/src`, full history (fetch `--force --tags --prune-tags`) | The changelog and `git describe` need the history; force-fetch follows rewrites. |
| Build and swap | The checked-out `build-app.sh` builds into `…/oomph/staging` (`OOMPH_NO_KILL=1`), progress lines `==> …` stream into the drawer; the app moves itself to `…/previous.app`, moves the new one in, relaunches with `--after-upgrade`, which runs the logger Update | Built locally, so no quarantine and no certificate; the running copy is only replaced once the build succeeded; the root part keeps its own password prompt. |
| Skip | Remembers the skipped commit; the daily check won't offer it, **Check** will | A version you skipped shouldn't nag, but stays reachable. |

## Out of scope

- Preventing or killing anything, or changing macOS's idle jobs.
- Per-thread or per-allocation detail (`vmmap`, `footprint -all`) — too heavy to run
  continuously; run them by hand on a suspect.

## Open questions

- The log line, if any, that accompanies the Force Quit dialog itself is unknown —
  nothing matching was found for the original incident. Incidents are detected through
  the jetsam storm instead; the next incident's `syslog.txt` should tell.
