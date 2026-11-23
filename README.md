# *oomph*

[![Build](https://github.com/kleinzeug/oomph/actions/workflows/build.yml/badge.svg)](https://github.com/kleinzeug/oomph/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform: macOS 14+](https://img.shields.io/badge/platform-macOS%2014%2B-lightgrey.svg)

***oomph*** does two things for a Mac that runs heavy work:

- **It watches memory for you.** A menu-bar monitor keeps a papertrail of what happened
  to your RAM, swap and disk while you were away — so the next *"Your system has run out
  of application memory"* dialog comes with an explanation.
- **It lets agents share RAM.** Claude sessions and other agents reserve the memory a
  heavy step needs before they start it — a Gradle build, a Playwright run, a model
  download — and take turns through one shared ledger instead of crashing each other.
  You see every reservation over time, right under the memory chart.

A [Kleinzeug](https://github.com/kleinzeug) tool — small tools, properly made.
Home: [kleinzeug.github.io/oomph](https://kleinzeug.github.io/oomph/) · Source: [github.com/kleinzeug/oomph](https://github.com/kleinzeug/oomph)

You leave the Mac alone for an hour with a few long-running jobs. You come back to the
Force Quit window, some processes are gone, and Activity Monitor says everything is
fine. ***oomph*** was built for exactly that: a tiny root daemon samples memory,
swap, disk space and per-process footprints around the clock, watches the system log
for memory kills, and turns every incident into a report with charts of the minutes
leading up to it.

Running several Claude Code sessions or other agents at once? Paste the
[oomph skill](https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md)
link into each (or run `oomph setup-claude` once) and they become memory-aware: they
reserve RAM before heavy work, shrink or release it when the heavy part is over, and
wait their turn when another agent needs the room. See
[Taking turns](#taking-turns-sessions-coordinating-memory).

The name: **oom** (out of memory) + *oomph* — and the trailing **ph** is the
author's initials.

## The icon

The chip in the menu bar shows how much physical memory is free right now — the same
figure Activity Monitor arrives at (Physical Memory − Memory Used) — abbreviated so it
fits: `12G`, `4.2G`. The digits are cut out of the chip, so they look right on light
and dark menu bars alike.

| Chip | Meaning |
|---|---|
| pastel green | memory pressure normal |
| yellow | memory pressure *warning* |
| red | memory pressure *critical* |
| hollow with **×** | logging is off — click to activate |

Click it for the popup:

- current pressure, app / compressed / wired memory, swap used and size, free disk,
  how long you have been idle, the biggest app;
- a chart of **all history (∞) / 24 h / 6 h / 1 h** — wired, app, compressed and swap
  stacked against your RAM, with the periods you were away shaded, stretches without data
  hatched (never bridged) and incidents marked in red. ∞ uses a logarithmic time axis: the
  last hour stays readable next to two weeks of context. Switching ranges morphs the chart
  in half a second, so you can follow where each stretch of time goes. Hover for a line
  that follows the pointer and a tooltip with the readings, gaps, incidents and events
  under it — on the log axis one pixel can hold hours, so it shows each value's range;
- the list of incidents — click one to open its report; right-click to copy its path
  or reveal it in Finder;
- **Activate / Deactivate**, **Report** (HTML report for the selected range),
  **Launch at login**, and Quit. Each button explains itself in a tooltip.

New to it? Hover the chip in the popup's top-left corner: it turns into a **?**. Click it
for a four-step tour. It lights up one part of the dashboard at a time, with notes on what
each control does. Move through it with the bar under the header or with ← / →, and close
it with Esc.

## What gets recorded

Every 30 seconds — every 5 seconds while things are getting tight:

| | |
|---|---|
| System memory | pressure level, app memory, wired, compressed, file cache, free |
| Swap | used, total, number of swapfiles |
| Disk | free space on the data volume (swap lives there too) |
| You | seconds since the last keyboard/mouse input, display on/off, screen locked, who is keeping the Mac awake |
| Processes | the 25 biggest by physical footprint, and the 15 biggest apps with all their helper processes added up |
| Agent sessions | every `claude` process with its whole process tree: project directory, total memory, biggest child |
| Memory kills | jetsam kills from the system log, aggregated per sample with their reasons |
| Unowned memory | memory no running process accounts for — normally a few GB; a large, lasting amount is a leak outside the processes (e.g. in the GPU driver) that only a restart frees |

An **incident** opens when memory pressure goes critical, when macOS starts killing
processes for memory (≥ 10 jetsam kills in a minute), when it reports kills for
`low-swap` or similar reasons, when the out-of-memory dialog appears, when more than
40 % of RAM (at least 16 GB) belongs to no process for a minute, or when the Mac is
awake but so starved that oomph itself can't run for a minute. It is named after its
most severe cause, so a kill that follows critical pressure becomes the headline. You get
one notification, and one more if such a kill joins later; an incident longer than two
hours is closed and continues in a new one. Once it is over the incident folder holds:

- `report.html` — a self-contained page with charts and tables: memory vs. RAM with
  away periods, critical-pressure stretches and kills, the top five apps stacked, free
  disk vs. swap size (gaps without data are hatched), the biggest risers as a list or a
  tree by owner, parent process and app, the agent sessions at the peak, the most-killed
  services, and the events newest-first with a text and time filter. Where the samples
  have them (logger 1.9.1 and newer) it also charts the cores busy, the GPU (at full speed
  or busy time), GPU memory and the free space of each recorded disk, lists who was busiest
  on the CPU and the GPU at their peaks and who wrote most to disk, and adds peak-cores and
  peak-GPU columns to the risers. Click any row to highlight that process (or app) in every
  table;
- `incident.json` — the same summary as data;
- `syslog.txt` — the relevant 15 minutes of the system log.

***oomph*** also warns you once (every six hours at most) when free disk space drops
below **20 GB** — see below for why that matters — and, per disk, when a disk it watches
(`oomph volumes`) runs low. When a watched disk is **filling up** (2 GB or more gone within
two minutes, at a rate that reaches its critical floor within 30 minutes) the logger records
it with the processes writing most, and notifies you (once in 30 minutes) when that is less
than ten minutes away. It also records when the thermal level changes, when the cores stay
90 % busy for ten minutes (and when that is over), and when a disk is mounted, unmounted,
watched or no longer watched.

It never kills, pauses or throttles anything. It only keeps the record.

## Why your Mac runs out of memory when you walk away

The incident that led to ***oomph*** turned out to be a disk problem, not a memory leak.
macOS swap is not a fixed partition: it grows in 1 GB swapfiles on your startup disk,
and macOS stops adding them when free space runs low. When you are idle, macOS starts
the work it holds back while you are busy — Spotlight indexing, Siri and Apple
Intelligence models, Photos analysis, backups. Add that to a heavy workload and the
memory compressor fills up, swap needs to grow, there is no room on the disk, and the
kernel declares *low swap*: jetsam starts killing processes and the Force Quit dialog
appears.

On the author's machine, with ~10 GB of disk free, the log showed 60,850 jetsam kills
with reason `low-swap` in a single hour. Freeing ~50 GB fixed it.

**Keep at least 20 GB free** and most of these dialogs never happen. The full story,
and every design decision, is in [DESIGN.md](DESIGN.md).

## Getting ***oomph***

Build it yourself — it is free, the source here is complete, and it takes about
a minute. There are no binaries.

## Building

Requirements: **macOS 14+** and **Xcode 16+** (only its Swift compiler and SDK are
used — there is no Xcode project; the Command Line Tools alone may well suffice).
Developed on Apple silicon; `build-app.sh` targets the machine's own architecture, so
Intel should work but is untested. The daemon uses the system's `/usr/bin/python3` and
only the Python standard library — no other dependencies.

```sh
git clone https://github.com/kleinzeug/oomph.git
cd oomph

./build-app.sh               # builds ~/Applications/oomph.app
open ~/Applications/oomph.app
```

`./build-app.sh /Applications` installs to `/Applications` instead. The app is
ad-hoc signed; no Apple account is needed.

### On Linux, for agents

On Ubuntu 22.04 and newer, Debian 12 and the RHEL 9 family (Python 3.9+, cgroup v2),
`oomph` gives agents the same commands, MCP tools, skill and exit codes as on a Mac:
`check`, `reserve`, `run`, `mcp`, `hook`, `doctor` and `oomph top`. No root, nothing
system-wide: it installs into your `~/.local`, every reading is live (there is no Linux
logger yet, so no history or incidents), and the reservation ledger is your own, shared
by your own sessions. Inside a container or a limited cgroup it speaks about that cgroup.

```sh
git clone https://github.com/kleinzeug/oomph.git
oomph/linux/install.sh       # ~/.local/bin/oomph; the skill and MCP server if Claude Code is set up
oomph doctor                 # what this machine offers; on RHEL 9 how to turn PSI on
```

`linux/install.sh` again updates it (after a `git pull`); `linux/uninstall.sh` removes it.
In a container where the agent is root, run both as root: root gets its own `~/.local` and
its own ledger, as any user does (under `sudo` they refuse: install as yourself).
`sudo oomph run …` reserves in the ledger of the user who ran sudo; if your sessions set
`XDG_STATE_HOME`, keep it for sudo (`sudo --preserve-env=XDG_STATE_HOME`), or it uses the
default `~/.local/state` and does not meet them.

### Activating the logger

The menu-bar app is only the viewer. The logging is done by a small daemon that runs as
root, because only root can see the memory footprint of *every* process, including the
system daemons that are often the ones growing.

Click the icon → **Activate** and enter your administrator password once. That runs the
bundled `install.sh`, which:

- copies `oomphd.py`, `oomph.py` and the rest to `/usr/local/libexec/oomph-<version>/` (root-owned,
  so nothing user-writable ever runs as root) and, once that is complete, points the link
  `/usr/local/libexec/oomph` at it in one step: a process that is running keeps the version
  it started with, and versions replaced more than 7 days ago are removed (restart an MCP
  server that has been running for longer than that),
- makes `/usr/local/libexec` and `/usr/local/bin` root's (755) if they weren't, so nobody else
  can swap what the daemon runs; a tool that wrote there as your user then needs `sudo`,
- installs and starts the LaunchDaemon `local.oomph.daemon`,
- links the `oomph` command into `/usr/local/bin`.

Prefer the terminal:

```sh
sudo ./install.sh
```

Re-running it updates an existing installation. **Deactivate** in the popup, or
`sudo ./uninstall.sh`, removes the daemon and every installed version and keeps the logs;
`sudo ./uninstall.sh --purge` removes the logs and the settings too. To remove the app, quit it and
delete `oomph.app` (and `~/Library/LaunchAgents/local.oomph.menubar.plist` if you
turned on launch at login).

## Upgrading

Every commit on `main` is a release. If the Xcode Command Line Tools are installed
(`xcode-select --install`), the popup shows a **Check** button next to Deactivate:

- Once a day, when you open the popup, oomph asks GitHub whether `main` has moved on (no
  background timer — it only checks while you look). **Check** does the same right away;
  either way the button spins while it asks.
- If there's something newer, the button turns into **Upgrade** (its tooltip names both
  versions). If not, it says **Up to date** until you open the popup again.
- **Upgrade** shows the changelog — every release since yours, from the commit messages —
  with **Cancel**, **Skip This Version** (the daily check won't offer it again; **Check** still
  does) and **Upgrade Now**.
- **Upgrade Now** builds the new version from source on your Mac (a clone with the full
  history in `~/Library/Application Support/oomph/src`, then its own `build-app.sh`), with
  the build's progress in a drawer, replaces `~/Applications/oomph.app`, relaunches, and goes
  straight on to updating the logger (one password prompt). Building locally means no
  download quarantine and no developer certificate.

*Upgrade* replaces the app; *Update* installs the logger the app carries. Right-click
**Check** to turn the daily check off. `oomph upgrade check | log | build` is the same from
the terminal.

**Versions** come from git history, `git describe` style: the `v1.5.0` tag builds `1.5.0`,
three commits later builds `1.5.0-3-g<sha>`, uncommitted changes add `-dirty`
(`tools/version.sh`). The build stamps it into the app, the CLI and the logger.

## The `oomph` command

Everything the app shows is also available in the terminal, without `sudo`:

```sh
oomph status                    # current memory, swap, disk, idle state, top apps, agent sessions
oomph report --last 2h          # timeline, biggest risers, other resources (cores, GPU, disks, writers), kills and events
oomph report --since 2026-11-13T18:00 --until 2026-11-13T20:00
oomph incidents                 # list of incidents
oomph incident latest --html    # open the latest incident's report
oomph html --open               # HTML report of the last 24 h (switch to 6 h / 1 h on the page; --last 3d for longer)
oomph top                       # the popup's dashboard, full screen in the terminal (see below)
oomph doctor                    # what works here and what to fix: logger, versions, ledger, Claude setup (--json)
oomph ps --cpu                  # the busiest processes now (--gpu, --io: writing to disk, --memory)
oomph volumes --all             # the disks oomph records, and the ones it ignores and why
oomph resources                 # memory, cores, GPU and disks of this Mac, and which can be reserved
```

From 1.9.1 the logger also records the CPU (cores busy, per process too), the thermal level, the
GPU (how busy, from the IO registry, and its memory), reads and writes to disk, and the free space
of the system's disk and of other fixed disks (an external SSD; not memory cards, disk images,
backup or network volumes). `oomph status` and `oomph check` show them; the app does not yet.
`oomph volumes watch /Volumes/Scratch` pins such a disk for you: its free space then counts in
your `oomph check` and hook like the system disk's (`unwatch`, `hide`, `unhide` likewise).

How busy the GPU is says little on its own: an idle desktop keeps it busy half the time, at its
lowest speed. From 1.9.3 the logger can also record how much of the GPU's capacity at full speed
was used, from the system's IOReport library, which only a helper process running as `nobody`
loads (never the logger itself, which runs as root). `oomph doctor` says whether it is on by
default in your version; where it is not, add `"ioreport": true` to the settings file (below) and
restart the logger with `sudo launchctl kickstart -k system/local.oomph.daemon` (`"no_ioreport": true`
keeps it off either way). `oomph status` then says "% of full
speed" instead of "busy … of the time", and `oomph doctor` says whether it works. A helper that
crashes four times, or whose readings do not fit the Mac, is switched off until the Mac restarts
or macOS is updated (`/Library/Logs/oomph/ioreport.json` keeps the count).

### In the terminal

`oomph top` is the popup in a terminal window: the readings, the memory chart with its four
spans, the reservations agents hold and wait for, and the incidents. It is driven by the
keyboard and only reads: `←` `→` change the span (∞, 24 h, 6 h, 1 h), `↓` steps into the
reservations and `↑` into the incidents (`space` switches between the two lists, `enter` shows
a row's details, `esc` lets go), `a` `s` `e` show the biggest apps, the Claude sessions and the
events in place of the lists, `o` opens the report, `?` lists every key and explains every mark,
`q` quits. `i` inspects a moment: a cursor on the chart and the strip, moved with `←` `→` (ten
columns with `shift`, `home` and `end` for the oldest and now), and in the place of the lists
everything in that column, as the popup's hover card has it: the readings, their peak against
the RAM, stretches without data, incidents, events and reservations; `enter` selects the
incident or reservation there, `esc` goes back. `ctrl-o` (or `--mouse`) turns the mouse on: a
click in the chart inspects that column, a click on a span or a row chooses it (a second click
opens the row), and the wheel changes the span over the chart and scrolls a list; while it is on,
the terminal selects text with `shift` (iTerm2: `option`). It fits 80 × 24 and uses the room of a
bigger window; it works in tmux, and `--bell` rings the terminal's bell when an incident opens,
at most every 15 minutes. Other machines are tabs in it ([below](#other-machines-110)).

```sh
oomph top                       # this Mac
oomph top --ssh build-mac       # another Mac, over ssh: needs oomph there, nothing else
ssh -t build-mac /usr/local/bin/oomph top   # the same by hand: sshd's PATH lacks /usr/local/bin
oomph top --once                # one frame as text (--span, --size 100x30, --glyphs cells|ascii)
```

`--glyphs cells` draws the chart with whole cells only, for a font or line spacing that shows thin
lines between block characters; `--glyphs ascii` uses no Unicode at all. The span, `--bell`, the mouse and
a `--glyphs`, `--color` or `--theme` you give are remembered in
`~/Library/Application Support/oomph/top.json` (`--glyphs auto` forgets the glyph set); under
`sudo` the dashboard writes nothing, its reservations lag by up to 30 seconds, and it refuses
`--ssh`. `--ssh` needs oomph 1.9.0 or newer on the other Mac and says so when it is missing or
older.

For scripts and agents there are also `oomph check`, `oomph session`, `oomph wait`,
`oomph run --reserve`, `oomph reserve` / `amend` / `release` / `reservations`,
`oomph status --json`, `oomph hook` and `oomph mcp` — see
[Making Claude sessions oom-aware](#making-claude-sessions-oom-aware).

Groundwork for watching other machines: `oomph serve --stdio` answers for this machine on its
standard streams (read only), and `oomph remote sync --once [--into DIR] -- COMMAND` mirrors the
machine whose `serve --stdio` COMMAND starts (for instance through `ssh`) into a directory that
every reader understands (a logger older than 1.8.8 names no machine id: give such a machine
a mirror with `--into`). A mirror receives the CPU, GPU and I/O figures of 1.9.1; the disks
stay on their machine for now. Nothing listens on the network.

### AI analysis

Click the **✦** next to **Report** in the popup, pick **Claude**, **OpenAI Codex** or a
local **Ollama**, paste an access token (Ollama needs none) and click **Connect**. oomph
first confirms that the provider accepts the token and knows the model (one cheap request,
no tokens spent; `oomph ai-check` does the same from a terminal) and shows a spinner in
place of ✦ meanwhile. Once connected, ✦ shows the provider's mark, and from then on **Report**
asks the model to investigate the last 24 hours before writing the page: it reads the
timeline, follows the processes that rose, their parents and Claude sessions, the events
and the incidents' system-log excerpts through read-only tools, and puts its analysis —
verdict, timeline, root cause, evidence, who was involved, risk now, recommendations —
above the usual charts, with the list of tool calls it made. While it works, Report
shows a spinner whose tooltip says what it is looking at, and the mark turns into a stop
button. Click the mark to see which provider and model are connected; **Disconnect** there
goes back to plain reports and forgets the token, so connecting again takes it pasted again.
A token saved by an earlier version of the app can't be deleted by a later one without asking,
so it may stay in the login keychain under `local.oomph.ai` until you delete it in Keychain
Access.

The token is read from your keychain only when a report needs it, never when oomph starts or
the dialog opens. A self-built app is signed ad hoc, so the keychain knows each build only by
its hash: after every upgrade, the first AI report asks once for access to the token (choose
**Always Allow** and that build won't ask again).

```sh
OOMPH_AI_TOKEN=sk-ant-… oomph ai-report --open                     # Claude (claude-opus-5-5)
oomph ai-report --provider ollama --model qwen3 --open             # local, nothing leaves the Mac
oomph ai-report --provider openai --model gpt-5-codex --last 6h --open
```

The harness is `daemon/oomph_ai.py`, standard library only like the rest. Tokens are kept
in the login keychain and passed to it through the environment, never on a command line.

## Making Claude sessions oom-aware

Long-running coding agents are exactly the kind of workload that tips a Mac into
"out of application memory": a build here, a container there, three sub-agents running
test suites in parallel. ***oomph*** ships a [Claude skill](skills/oomph/SKILL.md) that
teaches a session to check memory before heavy work and to back off when it is tight —
lower parallelism, no new containers or sub-agents, stop what it started, wait, and tell
you. With several sessions on one Mac, they also **take turns**: each reserves the memory
a heavy step will need, and ***oomph*** grants the reservations in order, side by side
while they fit and one after another when they don't.

**Per project** — paste this into a Claude Code session (the popup's link button
(🔗, next to Report and the AI star) copies it for you, or the all-projects variant with
`~/.claude/skills/oomph`):

```
Add the oomph skill to this project: run `mkdir -p .claude/skills/oomph && cp /usr/local/libexec/oomph/skills/oomph/SKILL.md .claude/skills/oomph/SKILL.md`, then read .claude/skills/oomph/SKILL.md and follow it for the rest of this session.
```

The skill travels with the command: the prompt copies the one installed with the logger, so
it describes exactly the `oomph` the session will run. Without an installed logger it
downloads the skill on `main` verbatim with `curl` instead (a web fetch would hand the model
a summary of the page, not the file):

```
Add the oomph skill to this project: run `mkdir -p .claude/skills/oomph && curl -fsSL https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md -o .claude/skills/oomph/SKILL.md`, then read .claude/skills/oomph/SKILL.md and follow it for the rest of this session.
```

Commit `.claude/skills/oomph/` and every session in that repo has it.

**For every session**, once:

```sh
oomph setup-claude            # installs the skill to ~/.claude/skills/oomph and
                              # registers the oomph MCP server for all sessions
oomph setup-claude --hook     # …and adds a PostToolUse hook (see below)
oomph setup-claude --remove   # undo all of it
```

What a session gets:

| | |
|---|---|
| `oomph check` | one-line verdict **ok / tight / critical** with reasons, advice and other sessions' reservations, then a line each for CPU, GPU and disks; exit code 0 / 1 / 2; `--json`; `--measure` reads CPU and GPU for a quarter second when the logger is off |
| `oomph resources` | this Mac's memory, cores, GPU and disks, and which of them can be reserved (memory only so far) |
| `oomph run --reserve 6G --for "gradle build" -- ./gradlew assembleDebug` | waits its turn for 6 GB, runs the command, releases when it exits and records the peak it really added; exit 75 if it never got a turn |
| `oomph reserve 6G --for "…"` · `oomph release <id\|all>` | the same for multi-step work: reserve, start once granted, release when the heavy part is over |
| `oomph amend r7 --gb 2G [--ttl 20m] [--for "…"]` | change a reservation in place: shrink it once the heaviest part is over, grow it, extend or shorten it, rename it |
| `oomph reservations` | who holds or waits for how much (project, purpose, memory actually used), what's available, and the measured peaks of recent work |
| `oomph reservations --history --last 3d` | every reservation of the last 14 days, also of sessions that are gone: span, size changes, reserved vs. peak, how it ended |
| `oomph session` | the memory of the Claude session it runs in — its whole process tree and the biggest children |
| `oomph wait --timeout 10m --free 4G` | blocks until memory is ok again |
| `oomph status --json` | the full latest sample |
| MCP server `oomph mcp` | the same as tools: `memory_check`, `reserve_memory`, `update_reservation`, `release_memory`, `reservations`, `reservation_history`, `my_session`, `wait_for_memory`, `memory_status`, `incidents`, `incident`. A server that outlives an update takes the installed new version at its next request, once the new code has passed a self-check, when the install is root's (a Mac, or Linux's system mode; a Linux user install is restarted with its session); the session keeps the tools it was shown at its start |
| `oomph hook` | optional `PostToolUse` hook on Bash: silent while memory is fine, tells the model once when it turns tight or critical (and again only if it changes or after 10 minutes) |

The verdict is **tight** at macOS memory pressure *warning*, under 5 % physical memory
free, under 20 GB free disk, right after jetsam kills, or when a large amount of
memory belongs to no process; **critical** at pressure
*critical*, under 5 GB free disk, or full swap on a nearly full disk. All of these
commands work without the background logger too — they measure live — so the skill is
useful even before you click Activate. Already installed an older version? A blue
refresh icon (↻) appears next to the chart's time range when the app carries a different
logger than the one installed; clicking it updates the logger.

### Taking turns: sessions coordinating memory

Two sessions that each see "8 GB free" and each start a 6 GB build at the same moment
are how a Mac runs out. So heavy steps are announced first, in a shared queue
(`/Users/Shared/oomph/ledger.json`, locked with `flock`, no daemon needed):

```
session A  $ oomph run --reserve 6G --for "gradle assembleDebug" -- ./gradlew assembleDebug
           → granted r7, build runs
session B  reserve_memory(gb: 4, purpose: "jest full suite")
           → queued #1 — only 1.9 GB available; ahead: r7 6.0G gradle assembleDebug (IREngine)
           … B keeps working on light things and asks again with its ticket …
session A  build exits → r7 released, peak 4.8 GB recorded
session B  → granted r8, tests start
```

- **Admission:** a request is granted when it fits into *free memory − what earlier grants
  haven't used yet − a safety margin* (5 % of RAM, at least 1.5 GB). Strictly
  first-come-first-served, so a small request can't overtake a big one that's waiting.
  Nothing is granted while memory pressure is critical. A request bigger than what's
  free is granted only when nothing else holds a reservation, so it runs alone instead
  of waiting forever; one bigger than 90 % of RAM is refused.
- **No double counting:** as a granted job's processes grow, the growth is taken off its
  reservation, so memory is never counted once as used and again as reserved. That
  growth is also how the real peak gets measured, and `oomph reservations` shows it next
  to what was reserved, so the next estimate is better.
- **Edits:** a session changes its reservation as the work changes (`oomph amend`,
  MCP `update_reservation`). **Shrinking** applies at once and hands the room to whoever
  waits. **Growing** a grant applies only when the extra memory would be granted to a new
  request right now — it fits, and nobody is queued; otherwise it is *refused*, nothing
  changes, and the session reserves the extra separately, which queues fairly behind the
  others. (Growing a queued request moves it to the back of the queue.) A new `--ttl`
  counts from now, shorter or longer.
- **Nothing gets stuck:** a reservation disappears when the process or session holding it
  exits, a session's grant expires after 30 minutes unless extended, and a queued request
  lapses if its session stops asking for 3 minutes. The logger checks the ledger every
  sample, so a reservation of a session that died ends within half a minute.
- **A history that outlives the agents:** every edit and every finished reservation is
  recorded in `/Users/Shared/oomph/reservations.jsonl` (14 days kept): its span from
  request and grant to its *actual* end — the release, the expiry, the holder's exit —
  its size over time, the peak it really used and how it ended. Ids carry the request
  time, so they stay unique even if the ledger is reset. From 1.9.2 each reservation and
  record also carries a short agent key, the same for every reservation of one Claude
  session, so a session's reservations can later be told apart from another's after it
  is gone. `oomph reservations --history` and MCP `reservation_history` read it.
- **Visible everywhere:** `oomph check` turns *tight* when other sessions' reservations
  exceed what's free, and the logger records them in each sample, so an incident report
  shows what was planned at the time. In the menu-bar popup a block chart under the
  memory chart shows every reservation over time — one block per reservation, its
  height the GB reserved, stacked when they overlap, hatched while queued, aligned with
  the memory chart in every range — and the **Reserved by agents** list below it shows
  the active ones in the same colours, waiting ones first, then grants by the time they have
  left (up to five lines; with more, the last one reads "+N more" and opens the full list).
- **Advisory:** ***oomph*** still never stops or kills anything. Taking turns is
  something the sessions agree on through the skill.
- **Nothing in the shared folder is trusted:** every user can write to
  `/Users/Shared/oomph`, so anyone could plant a link, a FIFO or a huge file there.
  oomph never follows a link there (not even when the folder itself was replaced by
  one), takes only plain files of bounded size, writes every file as a new one renamed
  into place, and gives up with "busy" instead of hanging on a held lock. Nothing
  running as root ever opens anything in it: the logger's ledger work runs in a child as
  `nobody` that the sampler never waits for, and `sudo oomph reserve` (any root caller)
  runs its ledger operation as the user who ran sudo.

### Other machines (1.10)

A Mac can watch other machines, read-only: Macs that are shared with it over the network, and
any machine with oomph installed that it can reach over `ssh`. Mac to Mac first; in 1.10.0
from the terminal, with tabs in the app behind a switch (below).

```sh
# on the Mac to be watched (an administrator; off by default)
sudo oomph share on --pair        # share it on the networks it is on now, and print a pairing code
sudo oomph share pair             # a new one-time code (10 minutes, five tries) for the next viewer,
                                  # and its link, oomph://CODE@HOST (share on --pair prints both too)
oomph share status                # on which networks, who is paired, who is reading now
sudo oomph share revoke c-4f2a9d10   # end one viewer's access (its live connection ends within seconds)
sudo oomph share ai on            # let viewers send this Mac's data to their AI analysis (off by default)
sudo oomph share off [--forget]   # stop sharing (--forget: a new key, every viewer pairs again)

# on the Mac you sit at (no sudo)
oomph remote add studio.local    # asks for the code `share pair` showed, pairs, then mirrors its 14 days
oomph remote add 'oomph://K7QF-2M9X-D4TR@studio.local'   # or the link: code and address in one (the code is
                                  # then on the command line, where ps shows it; the address alone asks for it)
oomph remote add sam@atlas        # or over ssh: nothing to set up there but oomph
oomph remote list                 # the machines watched, and how each link is
oomph remote sync                 # follow them live in this terminal (the app does this while its popup is open)
oomph remote sync --once          # catch every watched machine up once (before 1.10 this mirrored this Mac
                                  # into machines/<its id>: that folder can go; --into DIR still does it)
oomph remote remove studio        # stop watching (forget: also its history here and its pairing there)
```

How it works, briefly. Sharing is a second, optional service (`local.oomph.share`) that
launchd starts once per connection as a role account of its own, `_oomph`, never as root and
never inside the logger; it only reads what every user of that Mac can read in its logs.
Before a byte is read, a peer must be on the same network (one that sharing was turned on
for; `share allow CIDR` adds a routed range such as a tailnet). Then TLS with the Mac's own
key, which the viewer pins at pairing; the pairing code is never sent, both sides prove they
know it, so a machine in between cannot pair. Each viewer keeps a token in a file only it can
read (`~/Library/Application Support/oomph/machines/secrets.json`) and its mirror of the other
machine next to it, in the same layout as `/Library/Logs/oomph`. A laptop is best watched over
`ssh`: that opens no port of ours.

**Tabs in the app** are switched off in 1.10.0, until macOS's Local Network permission for a
self-built app is tried on a second Mac. To switch them on:
`defaults write local.oomph.menubar machinesUI -bool YES`, then quit and reopen oomph. The
popup then has a tab per machine added with `oomph remote add`: the header and everything below
belong to the selected tab, the menu-bar chip stays this Mac's, and the popup opens on the tab
it was closed on unless this Mac is critical, has an incident or its logger is silent.

With the switch on (1.10.2), a **+** sits on the line under the header (at the end of the tabs
once there are some). It opens a popover: type an address, a name or `user@host`, or paste the
link Share this Mac shows (`oomph://K7QF-2M9X-D4TR@studio.local`); Recents brings back a machine
paired before with one click (the trash forgets it). A pasted link only fills in the code step:
nothing is sent until Pair, and the pairing proof itself makes sure no machine in between can
pair. A typed address is reached first, and the code step shows the key the other machine
presented; Pair binds the pairing to it. Closing the popup keeps the step for 15 minutes. **Share this Mac…** (in the popover, and on the This Mac tab) shows the switch, the
key, the networks and the paired machines; turning it on, a new pairing code and each revoke ask
for the administrator password, and a fresh code keeps the popup up until it is used or Done. If
the popover misbehaves inside the popup, `defaults write local.oomph.menubar connectSheet -bool YES`
shows it as a sheet.

**In the terminal** (1.10.3, on without a switch: a terminal is not subject to the app's Local
Network question) `oomph top` has the same tabs on its first row: this machine, then every machine
added in the app or with `oomph remote add`, each with a mark for its link and its pressure
(`●` `◐` `◆` connected, `◦` its logger is silent, `↻` connecting or catching up, `⊘` not
connected, `▲` needs attention, a red `!` an open incident), and `+`. The second row says how the
selected machine is (`No answer since 10:15 · next try in 40 s`); what claims to be now is greyed
when it is not connected, what was received keeps its colours, and stretches never received
are dotted (`:`) in the chart. Keys: `1`–`9` and `tab` (`n` `p`) pick a tab, `0` lists every machine with its
address, `+` connects to one (a new Mac asks for the code `sudo oomph share pair` shows there,
with its key; `user@host` goes over ssh after showing the command it runs), `x` disconnects (`u`
undoes it for six seconds), `X` forgets (it asks), `r` tries now, `R` renames the tab, and `enter`
on an orange capsule explains what happened. The dashboard keeps the machines live only while it
runs, through the same `oomph remote sync` the app runs; with the app open both share one
connection per machine, and either can quit without the other going stale. `ctrl-z` lets go of
the connections until `fg`. `--machine NAME` starts on that tab (otherwise it is the tab of the
last run, unless this machine has something to say: critical pressure, an open incident or a
silent logger), and `--no-connect` shows the mirrors without connecting (`oomph top --ssh host`
always runs so on the far side); `oomph top --once --machine NAME` prints that tab's frame. On a Mac for now:
a Linux machine becomes a viewer in a later release.

## Files

| Path | What |
|---|---|
| `/Library/Logs/oomph/current.json` | the latest sample plus daemon status |
| `/Library/Logs/oomph/samples-YYYY-MM-DD.jsonl[.gz]` | one sample per line; older days compressed; kept 14 days |
| `/Library/Logs/oomph/events.jsonl` | memory kills, pressure changes (flapping batched), sleep gaps vs. stalls, unowned memory, notifications; since 1.9.5 also `thermal`, `cpu_saturated` (and `_cleared`), `disk_low` per disk, `disk_filling` and `volume` |
| `/Library/Logs/oomph/incidents/<id>/` | `report.html`, `incident.json`, `syslog.txt`; kept 90 days |
| `/Library/Logs/oomph/ioreport.json` | how often the IOReport helper crashed since the Mac started (only when it is switched on) |
| `/usr/local/libexec/oomph/` | a link to the installed daemon and CLI, `/usr/local/libexec/oomph-<version>/` |
| `/Library/LaunchDaemons/local.oomph.daemon.plist` | the daemon's launchd job (replaced by every install) |
| `/Library/Application Support/oomph/config.json` | settings that survive updates (optional, see below) |
| `/Library/Application Support/oomph/share/` | sharing (1.10, only once turned on): its settings, certificate and key (root's), and `run/` (the `_oomph` account's: pairings, the active code, who is reading) |
| `/Library/LaunchDaemons/local.oomph.share.plist` | the share service's launchd job (only while sharing is on) |
| `~/Library/Application Support/oomph/machines/` | the machines you watch (`machines.json`, tokens in `secrets.json`) and a mirror of each |
| `/Users/Shared/oomph/ledger.json` | the sessions' memory reservations and the last 100 finished ones (shared by all users; advisory) |
| `/Users/Shared/oomph/reservations.jsonl` | every reservation edit and finished reservation, one JSON record per line; kept 14 days |

All in, that is roughly 50–150 MB of logs. The daemon itself uses about 25 MB of
memory and no measurable CPU.

### Settings

Switches that should survive updates go into `/Library/Application Support/oomph/config.json`,
a JSON object that no install or upgrade writes: `{"<switch>": value}`, the switch's name
without `OOMPH_` and in lower case. An `OOMPH_<SWITCH>` variable in the environment takes
precedence. The file is read only if it and its folder belong to root and nobody else can
write them (`sudo mkdir -p "/Library/Application Support/oomph"`, then edit the file with
`sudo`); otherwise it is ignored. The switches read from it:

| Switch | Effect |
|---|---|
| `"ioreport": true` | the GPU's figure at full speed, from the IOReport helper (from 1.9.3; `false` switches it off; see above) |
| `"no_ioreport": true` | never start the IOReport helper, also once it is on by default |

### Privacy

The logs contain process names and working directories — never command-line arguments
or file contents — and are readable by every user on the Mac. From 1.9.1 they also hold
how much CPU, GPU time and disk writing each process used, and the names and mount points
of the disks oomph records (a volume's name can say something: `oomph volumes hide` keeps it
out of your own lists, not out of the logs). No telemetry. oomph does not talk to the
network unless you ask it to: when you turn on the AI analysis with Claude or OpenAI, which
sends figures, process names, project paths and the names and mount points of recorded disks
from the logs to that provider for each AI report (Ollama keeps it local); when you check for
upgrades; when you **share this Mac** (off by default, needs an administrator, only on the
networks you turn it on for) or **watch one that was shared with you**. Shared data goes
directly between your machines, encrypted, and nowhere else, and a watching machine only
connects while its popup is open (and a minute after), or while you run `oomph remote add`,
`oomph remote sync` or `oomph top` (with another machine as a tab) in a terminal; `oomph top
--ssh host` shows that account's machines there as they were last received, and never makes
that host connect to them. Another machine's data goes to an AI
provider only if its owner allowed it there (`sudo oomph share ai on`; off by default).

## Layout

```
daemon/oomphd.py                  the sampler daemon (root)
daemon/oomph.py                   CLI, summaries and HTML reports (shared with the daemon), the path table
daemon/oomph_darwin.py            everything that measures a Mac (the backend the daemon and CLI call)
daemon/oomph_linux.py             everything that measures a Linux machine, from /proc and /sys (no root)
daemon/oomph_ioreport.py          the IOReport helper: the GPU's performance states, as nobody (never root)
daemon/oomph_top.py               `oomph top`: reads the files; the terminal, the keys, the loop, --ssh
daemon/oomph_view.py              `oomph top`: draws the frame (pure: no I/O, no clock)
daemon/oomph_net.py               the wire protocol and `oomph serve --stdio` (read only)
daemon/oomph_sync.py              `oomph remote sync`: the client, coverage and the mirror writer
daemon/local.oomph.daemon.plist   the LaunchDaemon job
app/oomph.swift                   the menu-bar app (AppKit + SwiftUI + Swift Charts)
app/Info.plist
build-app.sh                      builds oomph.app and bundles the daemon + scripts into it
install.sh / uninstall.sh         install or remove the daemon (run as root)
linux/install.sh, uninstall.sh    install or remove oomph for one Linux user, in ~/.local (no root)
skills/oomph/SKILL.md             the Claude skill (raw link above)
tools/selftest.py                 unprivileged end-to-end check of daemon + CLI (also run by CI)
tools/linuxtest.py                Linux: the backend on recorded machines, the CLI's exit codes, the installer
tools/linuxfixture.py             recorded Linux machines (/proc and /sys trees) for those tests
tools/roottest.py                 the same for what only root can show (CI runs it with sudo)
tools/brandlint.py                keeps the product's name (BRAND) apart from the command and paths
tools/chartvectors.py             holds `oomph top`'s chart maths to the app's (tools/vectors/chart.json)
tools/topfixture.py               the golden frames of `oomph top` (tools/golden/top), from fixed data
tools/toptest.py                  `oomph top` in a pseudo-terminal: keys, signals, --ssh; tmux as the oracle
tools/nettest.py                  the protocol's tests: serve, sync through a pipe, coverage, hostile input
tools/mirrorfixture.py            another machine's mirror, for `oomph.app --render-popup … --mirror DIR`
tools/renderfixture.py            renders that repeat themselves: `--render-popup … --fixture DIR --now T --no-liveness`
tools/spike_role_account.sh       a CI spike: a launchd job under a role account, time to first frame
DESIGN.md                         the investigation and the design decisions
docs/index.html                   the website (GitHub Pages, served from /docs)
```

Before sending a change, `/usr/bin/python3 -I tools/selftest.py` runs the same
end-to-end check of the daemon and CLI as CI — no `sudo`, nothing installed.

## Contributing

Pull requests are welcome and appreciated. Bug reports and feature ideas go in
[Issues](https://github.com/kleinzeug/oomph/issues) — if it is about a memory incident,
attaching the incident's `report.html` (check it for anything private first) helps
a lot.

## License

[MIT](LICENSE): clone it, build it, change it, ship your fork. If you improve
***oomph***, sending the change back upstream as a pull request is appreciated
(a request, not a condition).

## Support the work

If ***oomph*** saved you from staring at the Force Quit window wondering what just
happened:

<a href="https://www.buymeacoffee.com/holzschneider" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50" width="180"></a>
