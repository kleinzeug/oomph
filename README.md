# *oomph*

[![Build](https://github.com/kleinzeug/oomph/actions/workflows/build.yml/badge.svg)](https://github.com/kleinzeug/oomph/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Platform: macOS 14+](https://img.shields.io/badge/platform-macOS%2014%2B-lightgrey.svg)

***oomph*** is a menu-bar memory monitor for macOS that keeps a papertrail of what
happened to your RAM, swap and disk while you were away — so the next
*"Your system has run out of application memory"* dialog comes with an explanation.

A [Kleinzeug](https://github.com/kleinzeug) tool — small tools, properly made.
Home: [kleinzeug.github.io/oomph](https://kleinzeug.github.io/oomph/) · Source: [github.com/kleinzeug/oomph](https://github.com/kleinzeug/oomph)

You leave the Mac alone for an hour with a few long-running jobs. You come back to the
Force Quit window, some processes are gone, and Activity Monitor says everything is
fine. ***oomph*** was built for exactly that: a tiny root daemon samples memory,
swap, disk space and per-process footprints around the clock, watches the system log
for memory kills, and turns every incident into a report with charts of the minutes
leading up to it.

Running long Claude Code sessions? Paste the
[oomph skill](https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md)
link into one and it becomes memory-aware — and when several sessions run at once,
they reserve memory through ***oomph*** and take turns with heavy work instead of
competing for RAM. See [Making Claude sessions oom-aware](#making-claude-sessions-oom-aware).

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
awake but so starved that oomph itself can't run for a minute. You get one
notification, and once it is over the incident folder holds:

- `report.html` — a self-contained page with charts and tables: memory vs. RAM with
  away periods, critical-pressure stretches and kills, the top five apps stacked, free
  disk vs. swap size (gaps without data are hatched), the biggest risers as a list or a
  tree by owner, parent process and app, the agent sessions at the peak, the most-killed
  services, and the events newest-first with a text and time filter. Click any row to
  highlight that process (or app) in every table;
- `incident.json` — the same summary as data;
- `syslog.txt` — the relevant 15 minutes of the system log.

***oomph*** also warns you once (every six hours at most) when free disk space drops
below **20 GB** — see below for why that matters.

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

### Activating the logger

The menu-bar app is only the viewer. The logging is done by a small daemon that runs as
root, because only root can see the memory footprint of *every* process, including the
system daemons that are often the ones growing.

Click the icon → **Activate** and enter your administrator password once. That runs the
bundled `install.sh`, which:

- copies `oomphd.py` and `oomph.py` to `/usr/local/libexec/oomph/` (root-owned, so
  nothing user-writable ever runs as root),
- installs and starts the LaunchDaemon `local.oomph.daemon`,
- links the `oomph` command into `/usr/local/bin`.

Prefer the terminal:

```sh
sudo ./install.sh
```

Re-running it updates an existing installation. **Deactivate** in the popup, or
`sudo ./uninstall.sh`, removes the daemon and keeps the logs;
`sudo ./uninstall.sh --purge` removes the logs too. To remove the app, quit it and
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
oomph report --last 2h          # timeline, biggest risers, kills and events
oomph report --since 2026-11-13T18:00 --until 2026-11-13T20:00
oomph incidents                 # list of incidents
oomph incident latest --html    # open the latest incident's report
oomph html --open               # HTML report of the last 24 h (switch to 6 h / 1 h on the page; --last 3d for longer)
```

For scripts and agents there are also `oomph check`, `oomph session`, `oomph wait`,
`oomph run --reserve`, `oomph reserve` / `amend` / `release` / `reservations`,
`oomph status --json`, `oomph hook` and `oomph mcp` — see
[Making Claude sessions oom-aware](#making-claude-sessions-oom-aware).

### AI analysis

Turn on the **✦** next to **Report** in the popup, pick **Claude**, **OpenAI Codex** or a
local **Ollama**, and paste an access token (Ollama needs none). From then on **Report**
asks the model to investigate the last 24 hours before writing the page: it reads the
timeline, follows the processes that rose, their parents and Claude sessions, the events
and the incidents' system-log excerpts through read-only tools, and puts its analysis —
verdict, timeline, root cause, evidence, who was involved, risk now, recommendations —
above the usual charts, with the list of tool calls it made. While it works, Report
shows a spinner whose tooltip says what it is looking at, and ✦ turns into a stop
button. Click ✦ again to go back to plain reports.

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
Add the oomph memory skill to this project: run `mkdir -p .claude/skills/oomph && curl -fsSL https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md -o .claude/skills/oomph/SKILL.md`, then read .claude/skills/oomph/SKILL.md and follow it for the rest of this session.
```

The skill is downloaded verbatim with `curl` on purpose: a web fetch hands the model a
summary of the page, not the file. Commit `.claude/skills/oomph/` and every session in
that repo has it.

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
| `oomph check` | one-line verdict **ok / tight / critical** with reasons, advice and other sessions' reservations; exit code 0 / 1 / 2; `--json` |
| `oomph run --reserve 6G --for "gradle build" -- ./gradlew assembleDebug` | waits its turn for 6 GB, runs the command, releases when it exits and records the peak it really added; exit 75 if it never got a turn |
| `oomph reserve 6G --for "…"` · `oomph release <id\|all>` | the same for multi-step work: reserve, start once granted, release when the heavy part is over |
| `oomph amend r7 --gb 2G [--ttl 20m] [--for "…"]` | change a reservation in place: shrink it once the heaviest part is over, grow it, extend or shorten it, rename it |
| `oomph reservations` | who holds or waits for how much (project, purpose, memory actually used), what's available, and the measured peaks of recent work |
| `oomph reservations --history --last 3d` | every reservation of the last 14 days, also of sessions that are gone: span, size changes, reserved vs. peak, how it ended |
| `oomph session` | the memory of the Claude session it runs in — its whole process tree and the biggest children |
| `oomph wait --timeout 10m --free 4G` | blocks until memory is ok again |
| `oomph status --json` | the full latest sample |
| MCP server `oomph mcp` | the same as tools: `memory_check`, `reserve_memory`, `update_reservation`, `release_memory`, `reservations`, `reservation_history`, `my_session`, `wait_for_memory`, `memory_status`, `incidents`, `incident` |
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
  appended to `/Users/Shared/oomph/reservations.jsonl` (14 days kept): its span from
  request and grant to its *actual* end — the release, the expiry, the holder's exit —
  its size over time, the peak it really used and how it ended. Ids carry the request
  time, so they stay unique even if the ledger is reset. `oomph reservations --history`
  and MCP `reservation_history` read it.
- **Visible everywhere:** `oomph check` turns *tight* when other sessions' reservations
  exceed what's free, the menu-bar popup lists every reservation, and the logger records
  them in each sample, so an incident report shows what was planned at the time.
- **Advisory:** ***oomph*** still never stops or kills anything. Taking turns is
  something the sessions agree on through the skill.

## Files

| Path | What |
|---|---|
| `/Library/Logs/oomph/current.json` | the latest sample plus daemon status |
| `/Library/Logs/oomph/samples-YYYY-MM-DD.jsonl[.gz]` | one sample per line; older days compressed; kept 14 days |
| `/Library/Logs/oomph/events.jsonl` | memory kills, pressure changes (flapping batched), sleep gaps vs. stalls, unowned memory, notifications |
| `/Library/Logs/oomph/incidents/<id>/` | `report.html`, `incident.json`, `syslog.txt`; kept 90 days |
| `/usr/local/libexec/oomph/` | the installed daemon and CLI |
| `/Library/LaunchDaemons/local.oomph.daemon.plist` | the daemon's launchd job |
| `/Users/Shared/oomph/ledger.json` | the sessions' memory reservations and the last 100 finished ones (shared by all users; advisory) |
| `/Users/Shared/oomph/reservations.jsonl` | every reservation edit and finished reservation, one JSON record per line; kept 14 days |

All in, that is roughly 50–150 MB of logs. The daemon itself uses about 25 MB of
memory and no measurable CPU.

### Privacy

The logs contain process names and working directories — never command-line arguments
or file contents — and are readable by every user on the Mac. Nothing leaves your
machine: no network access, no telemetry — except when you turn on the AI analysis with
Claude or OpenAI, which sends figures, process names and project paths from the logs to
that provider for each AI report (Ollama keeps it local).

## Layout

```
daemon/oomphd.py                  the sampler daemon (root)
daemon/oomph.py                   CLI, summaries and HTML reports (shared with the daemon)
daemon/local.oomph.daemon.plist   the LaunchDaemon job
app/oomph.swift                   the menu-bar app (AppKit + SwiftUI + Swift Charts)
app/Info.plist
build-app.sh                      builds oomph.app and bundles the daemon + scripts into it
install.sh / uninstall.sh         install or remove the daemon (run as root)
skills/oomph/SKILL.md             the Claude skill (raw link above)
tools/selftest.py                 unprivileged end-to-end check of daemon + CLI (also run by CI)
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
