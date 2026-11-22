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
│     │    (oomph_darwin.py, the backend: oomph.plat())     │
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
│                              oomph mcp ← Claude sessions   │
│                                 │ flock, read/write        │
│                                 ▼                          │
│        /Users/Shared/oomph/ledger.json  (reservations)     │
│        /Users/Shared/oomph/reservations.jsonl  (history)   │
└───────────────────────────────────────────────────────────┘
       (each sample, a child of the daemon running as nobody retires
        dead/expired leases and answers the live ones for the sample;
        root itself never opens anything in /Users/Shared/oomph)
```

## Decisions

| Topic | Decision | Why |
|---|---|---|
| Runner | **LaunchDaemon as root** (`local.oomph.daemon`), `KeepAlive`, `RunAtLoad` | Survives logout, reboot and closed terminals — the incidents happen exactly when nobody is watching. Only root can read the physical footprint of *every* process, including root daemons like `spotlightknowledged` and WindowServer. |
| Install path | Code in `/usr/local/libexec/oomph-<version>/` (root-owned, 755), reached through the link `/usr/local/libexec/oomph`, which an install swaps by one rename once the new directory is complete; old versions go 7 days after they were replaced. CLI symlink `/usr/local/bin/oomph` | A root daemon must never execute user-writable files. A running process (the logger, an MCP server) keeps importing from the directory it started in, so it never mixes two versions' modules. |
| Interpreter | `/usr/bin/python3 -I -B`, standard library only | Not affected by Homebrew upgrades; no dependencies; `-I` ignores environment and current directory. |
| Metrics | Measured only by the backend module for the system (`oomph_darwin.py` on a Mac, reached through `oomph.plat()`; oomph.py and oomphd.py import no native code and load on any system): `libproc` via ctypes (`proc_pid_rusage` → `ri_phys_footprint`, the same figure as Activity Monitor's *Memory* column), `sysctl` via ctypes, `vm_stat`, `ioreg`, `pmset -g assertions` | Fast (~5 ms for ~750 processes), accurate, no third-party tools. |
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
| Edits | `oomph amend` / MCP `update_reservation`: gb, ttl (from now), purpose. Shrinking applies at once. Growing a grant applies only if a new request for the extra would be granted now (fits, nobody queued, not critical); otherwise refused with advice to reserve the extra separately, and nothing changes. Growing a queued request moves it to the back | Growth that skipped the queue would let a holder overtake everyone waiting; a pending-growth state would complicate every client. Refusal keeps the grant intact and the queue fair, and the advice is one tool call. |
| History | `reservations.jsonl` next to the ledger (666), one record per line, written under the ledger lock: an `edit` record per applied change, an `end` record when a lease is retired, each a full snapshot (key, purpose, project, holder kind, gb and `segments` [{t, gb}] once edited, requested, granted, ended, outcome, peak). Every write rewrites it (see the next table): 14 days and at most 8 MB are kept; seeded once from the ledger's own last-100 history | Agents and the popup need spans of sessions that are long gone. Snapshots make the last record per key self-contained. The key is `id@requested`, and a fresh ledger continues the id numbering from the log, so ids never repeat after a reset. Ends are the real ones: an expiry at its expiry time, a lapse when polling stopped, a dead holder within one daemon sample. |
| Popup strip | One block per reservation under the memory chart, drawn on the chart's own time mapping (same plot frame, same animated linear/log blend). Height ∝ GB; stacked by lanes (first-fit by start), and the stack at any moment is the sum of what is reserved there, so a block steps down when one below ends or shrinks; queued stretches hatched. The list below uses the same colours, hashed from the purpose | Lining up with the chart lets you read cause and effect; stacking shows the total the ledger promised. |

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
| Reading | One reader, `read_bounded`: `O_NOFOLLOW` + `O_NONBLOCK`, a regular file with a single link (checked on the descriptor), a size cap; the directory itself opened `O_DIRECTORY` + `O_NOFOLLOW` and every file relative to it. One parser, `loads_untrusted`: no integers over 30 digits, no NaN/Infinity, ≤ 256 keys per object, no deep nesting. One table of limits (`LIMITS`). The app's `readShared` does the same | No FIFO, device or giant file can hang or flood a reader |
| Validation | `read_ledger` checks every lease and history entry field by field; one that doesn't fit was never written by oomph and is dropped. Types are checked, nothing is cut: a view limit never reaches the read-modify-write path | A malformed ledger can't make the CLI, the MCP server or the logger raise |
| Writing | No writer opens an existing name for writing: a random temporary name created `O_EXCL`, `fchmod` on the descriptor, then a rename. The history log is rewritten the same way on every write (read, keep 14 days and ≤ 8 MB, add, rename) instead of being appended to, so it stays one file in the same format; 1.8.1–1.8.3, which append under the same lock, keep working | A hard link can't be refused by any open flag; a rename never writes through one |
| The lock | `ledger.lock` opened read-only, `O_NOFOLLOW` + `O_NONBLOCK`, a regular file; `flock` polled to a deadline: 5 s for interactive callers (a holder keeps it for milliseconds, so this only runs out when it is stuck or hostile, yet survives one swapped out under pressure), 1 s for the logger's child (it runs again next sample). Then "busy" (exit 75), never a hang | |
| Installers | Leave the directory alone: no `chown`, `chmod`, `install -d` or sticky bit | Root touching it is exactly what this rules out |
| Tests | `tools/selftest.py` covers the unprivileged half; `tools/roottest.py` runs as real root in CI with an audit hook on every file root opens | |

`oomph version --json` reports `"hardening": 1`, so a later `oomph share on` can refuse code
without it.

## AI analysis (1.4)

| Decision | Choice | Why |
|---|---|---|
| Who investigates | The model, through ten read-only tools over the logs (`overview`, `timeline`, `top_at`, `process_history`, `events`, `incidents`, `incident`, `syslog`, `current_status`, `claude_sessions`), up to 12 rounds, then a forced write-up | A fixed prompt with a data dump can't follow a lead; tools let it zoom from "critical at 03:53" to the process, its parent and its session. Results are capped at 14 k characters so a broad query can't flood the context. |
| Providers | Claude (Messages API, `claude-opus-5-5`, adaptive thinking at effort high, server-side refusal fallback), OpenAI (Responses API), Ollama (`/api/chat`; models without tool support get one pass over the briefing) | What the user asked for; all over plain HTTPS with the standard library. The Claude turn sends the whole previous assistant content back unchanged. |
| Credentials | Login keychain, one item per provider; handed to the harness in `OOMPH_AI_TOKEN` | Never in a file, a preference or `ps` output. |
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
