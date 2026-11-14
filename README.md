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
- a chart of the last **1 h / 6 h / 24 h** — wired, app, compressed and swap stacked
  against your RAM, with the periods you were away shaded and incidents marked in red;
- the list of incidents — click one to open its report; right-click to copy its path
  or reveal it in Finder;
- **Activate / Deactivate**, **Report** (HTML report for the selected range),
  **Launch at login**, and Quit.

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

An **incident** opens when memory pressure goes critical, when macOS starts killing
processes for memory (≥ 10 jetsam kills in a minute), when it reports kills for
`low-swap` or similar reasons, or when the out-of-memory dialog appears. You get one
notification, and once it is over the incident folder holds:

- `report.html` — a self-contained page with charts and tables: memory vs. RAM with
  away periods and kills, the top five apps, free disk vs. swap size, the biggest
  risers, the agent sessions at the peak, the most-killed services;
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

## The `oomph` command

Everything the app shows is also available in the terminal, without `sudo`:

```sh
oomph status                    # current memory, swap, disk, idle state, top apps, agent sessions
oomph report --last 2h          # timeline, biggest risers, kills and events
oomph report --since 2026-11-13T18:00 --until 2026-11-13T20:00
oomph incidents                 # list of incidents
oomph incident latest --html    # open the latest incident's report
oomph html --last 24h --open    # HTML report for any time range
```

## Files

| Path | What |
|---|---|
| `/Library/Logs/oomph/current.json` | the latest sample plus daemon status |
| `/Library/Logs/oomph/samples-YYYY-MM-DD.jsonl[.gz]` | one sample per line; older days compressed; kept 14 days |
| `/Library/Logs/oomph/events.jsonl` | memory kills, pressure changes, sleep gaps, notifications |
| `/Library/Logs/oomph/incidents/<id>/` | `report.html`, `incident.json`, `syslog.txt`; kept 90 days |
| `/usr/local/libexec/oomph/` | the installed daemon and CLI |
| `/Library/LaunchDaemons/local.oomph.daemon.plist` | the daemon's launchd job |

All in, that is roughly 50–150 MB of logs. The daemon itself uses about 25 MB of
memory and no measurable CPU.

### Privacy

The logs contain process names and working directories — never command-line arguments
or file contents — and are readable by every user on the Mac. Nothing leaves your
machine: no network access, no telemetry.

## Layout

```
daemon/oomphd.py                  the sampler daemon (root)
daemon/oomph.py                   CLI, summaries and HTML reports (shared with the daemon)
daemon/local.oomph.daemon.plist   the LaunchDaemon job
app/oomph.swift                   the menu-bar app (AppKit + SwiftUI + Swift Charts)
app/Info.plist
build-app.sh                      builds oomph.app and bundles the daemon + scripts into it
install.sh / uninstall.sh         install or remove the daemon (run as root)
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
