---
name: oomph
description: Make a long-running session memory-aware with oomph (macOS). Check memory pressure, free physical memory, swap and free disk before memory-heavy work — builds, test suites, Docker/VMs, browsers, parallel jobs, sub-agents — back off when memory is tight, find what this session is using, and read oomph incident reports after crashes, killed processes or an "out of application memory" dialog. Use when asked to watch or monitor memory or be "OOM-aware", during long autonomous runs, before starting heavy or parallel work, and after unexplained process deaths.
---

# oomph — be memory-aware

[oomph](https://github.com/kleinzeug/oomph) measures this Mac's memory, swap and disk,
and keeps a papertrail of memory incidents. This skill makes you use it so a long
session doesn't push the machine into "Your system has run out of application memory",
where macOS starts killing processes — possibly yours or the user's.

## 1. Find oomph

Use the first one that works and remember it as `OOMPH` for the rest of the session:

1. MCP tools named `memory_check`, `my_session`, `wait_for_memory`, `incidents`,
   `incident`, `memory_status` (server `oomph`) — prefer these if present.
2. `oomph` on the PATH (`command -v oomph`), normally `/usr/local/bin/oomph`.
3. A checkout: `/usr/bin/python3 -I <checkout>/daemon/oomph.py`.

If none exists, tell the user oomph isn't installed and offer two options; do neither
without their OK:

- **Full install** (menu-bar app + background logger, recommended):
  `git clone https://github.com/kleinzeug/oomph.git && cd oomph && ./build-app.sh`,
  then the user clicks the chip in the menu bar → Activate.
- **Checks only, nothing installed system-wide:**
  `git clone --depth 1 https://github.com/kleinzeug/oomph.git ~/.oomph-src`, then use
  `/usr/bin/python3 -I ~/.oomph-src/daemon/oomph.py` as `OOMPH`. Every command below
  works without the logger; it measures live.

## 2. The commands

| Command | What it gives you |
|---|---|
| `OOMPH check` | One-line verdict **ok / tight / critical**, reasons, advice. Exit code 0 / 1 / 2. `--json` for structured output. |
| `OOMPH session` | This Claude session's memory: its whole process tree, total, biggest children (pid, name, MB). |
| `OOMPH wait --timeout 10m [--free 4G]` | Blocks until memory is ok again. Exit 1 on timeout. |
| `OOMPH status --json` | Full sample: memory breakdown, swap, disk, top processes and apps, all Claude sessions. |
| `OOMPH incidents` / `OOMPH incident latest` | Recorded incidents (needs the logger) and their summaries; `--html` opens the report. |

The MCP tools map one-to-one: `memory_check`, `my_session`, `wait_for_memory`
(timeout ≤ 300 s), `memory_status`, `incidents`, `incident`.

## 3. When to check

- **At the start** of a long or autonomous task.
- **Before every memory-heavy step**: full builds, large test suites, `docker run` /
  `docker compose up`, starting VMs, emulators or headless browsers, data processing,
  model inference, running jobs in parallel, spawning sub-agents.
- **Periodically** during long runs — roughly every 20–30 minutes of work, or every
  10 or so heavy commands.
- **After anything suspicious**: a process killed without explanation (exit 137 /
  SIGKILL, "Killed: 9"), a build that died silently, the machine becoming very slow.
  Then also look at `OOMPH incidents`.

Checking is cheap (well under a second). Don't check before trivial commands.

## 4. What to do per level

**ok** — proceed.

**tight** — keep going, but lighter:
- Run builds and tests with less parallelism (`-j2`, `--maxWorkers=2`, `-n 2`, `--parallel 1`).
- Don't start new containers, VMs, browsers or sub-agents; reuse or stop the ones you started.
- Stop processes *this session* started and no longer needs (dev servers, watchers,
  finished containers). Use `OOMPH session` to see them.
- Mention it to the user in one line, e.g. "Memory is tight (3.1 GB free), so I'm running
  the tests with 2 workers."

**critical** — stop and protect the machine:
- Start nothing heavy. Pause the plan.
- Stop memory-heavy processes **this session** started (see `OOMPH session`).
- `OOMPH wait --timeout 10m`, then check again.
- Tell the user what you saw and did. If the reason is low disk space, ask them to free
  some — swap lives on the startup disk and can't grow when it's full.

Never kill processes this session didn't start (the user's apps, other sessions,
system daemons) without asking. oomph only reports; acting is your job, within the
session's own work.

## 5. Reading the numbers

- **free** is Activity Monitor's figure: Physical Memory − (App Memory + Wired + Compressed).
  A few GB free is normal; macOS uses spare memory as cache.
- **pressure** is macOS's own judgement (normal / WARN / CRITICAL) and matters more
  than "free".
- **swap a/b** — used / current size. Swap grows in 1 GB files on the startup disk; with
  less than ~20 GB disk free it may not be able to grow, which is the usual cause of
  the "out of application memory" dialog.
- **jetsam kills** — macOS killed processes to free memory. Any in a burst is a red flag.
