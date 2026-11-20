---
name: oomph
description: Make a long-running session memory-aware with oomph (macOS), and coordinate memory with the other Claude sessions on the same Mac. Reserve memory before heavy work — builds, test suites, Docker/VMs, browsers, parallel jobs, sub-agents — so sessions take turns instead of competing for RAM; check memory pressure, free memory, swap and disk; back off when memory is tight; find what this session is using; and read oomph incident reports after crashes, killed processes or an "out of application memory" dialog. Use when asked to watch or monitor memory, be "OOM-aware" or coordinate with other sessions, during long autonomous runs, before starting heavy or parallel work, and after unexplained process deaths.
---

# oomph — be memory-aware, take turns

> **Installing this skill:** it belongs at `.claude/skills/oomph/SKILL.md` in a project, or
> `~/.claude/skills/oomph/SKILL.md` for every project. Download it verbatim — never retype
> or summarize it: `mkdir -p .claude/skills/oomph && curl -fsSL
> https://raw.githubusercontent.com/kleinzeug/oomph/main/skills/oomph/SKILL.md -o
> .claude/skills/oomph/SKILL.md` — then follow it for the rest of the session.

[oomph](https://github.com/kleinzeug/oomph) measures this Mac's memory, swap and disk,
keeps a papertrail of memory incidents, and keeps a shared queue in which Claude
sessions reserve memory before heavy work. This skill makes you use it so a long
session doesn't push the machine into "Your system has run out of application memory",
where macOS starts killing processes — possibly yours, another session's or the user's.

Other Claude sessions may be working on this Mac right now. Each one thinking "there's
8 GB free, I'll start my build" at the same moment is exactly how the machine runs out.
So: **announce heavy work before starting it, and start only when oomph grants it.**

## 1. Find oomph

Use the first one that works and remember it as `OOMPH` for the rest of the session:

1. MCP tools named `memory_check`, `reserve_memory`, `update_reservation`,
   `release_memory`, `reservations`, `reservation_history`, `my_session`, `wait_for_memory`, `incidents`, `incident`, `memory_status` (server
   `oomph`) — prefer these if present.
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
  works without the logger, reservations included; it measures live.

If `OOMPH reserve` / `reserve_memory` doesn't exist, the installed oomph is older than
1.2: tell the user once that updating it (click the chip → Update) enables coordination,
and use the checks in §4 until then.

## 2. The commands

| Command | What it gives you |
|---|---|
| `OOMPH run --reserve 6G --for "what" [--wait 9m] -- <cmd…>` | Queue for 6 GB, run the command when granted, release when it exits, record its real peak. Exit code is the command's; **75** if it was never granted within `--wait` (then nothing ran). |
| `OOMPH reserve 6G --for "what" [--wait 5m] [--ttl 30m] [--ticket rN]` | Reserve for multi-step work. Exit 0 = granted, 75 = still queued (prints the ticket and who is ahead) or refused. Re-run with `--ticket` to keep your place or to extend a grant. |
| `OOMPH amend rN [--gb 3G] [--ttl 20m] [--for "what"]` | Change a reservation in place. Shrinking applies at once; growing a grant applies only if the extra fits now and nobody is queued, else it is **refused** (exit 75, nothing changes) — then reserve the extra separately. `--ttl` counts from now (shorter or longer). |
| `OOMPH release <id \| all>` | Give it back (`all` = everything this session holds). |
| `OOMPH reservations` | Who holds or waits for how much (with project and actual use), memory available for new reservations, and recent finished reservations with the **peak each really needed**. |
| `OOMPH reservations --history [--last 24h]` | Past reservations of every session, also ones that are gone (14 days kept): spans, size changes, reserved vs. peak, how each ended. |
| `OOMPH check` | One-line verdict **ok / tight / critical**, reasons, advice, and other sessions' reservations. Exit code 0 / 1 / 2. `--json` for structured output. |
| `OOMPH session` | This Claude session's memory: its whole process tree, total, biggest children (pid, name, MB). |
| `OOMPH wait --timeout 10m [--free 4G]` | Blocks until memory is ok again. Exit 1 on timeout. |
| `OOMPH status --json` | Full sample: memory breakdown, swap, disk, top processes and apps, all Claude sessions. |
| `OOMPH incidents` / `OOMPH incident latest` | Recorded incidents (needs the logger) and their summaries; `--html` opens the report. |

The MCP tools map one-to-one: `reserve_memory` (gb, purpose, wait_s ≤ 300, ttl_min,
ticket), `update_reservation` (id, gb?, ttl_min?, purpose?), `release_memory` (id or
"all"), `reservations`, `reservation_history` (hours ≤ 336, limit, purpose filter),
`memory_check`, `my_session`,
`wait_for_memory` (timeout ≤ 300 s), `memory_status`, `incidents`, `incident`.
`oomph run` has no MCP twin: run it through your shell.

## 3. Coordinate heavy work with other sessions

**What counts as heavy:** anything likely to add more than ~1 GB — full builds
(Gradle, Xcode, cargo, C++), large test suites or parallel test runners, `docker run` /
`docker compose up`, VMs, emulators, headless browsers, model inference, big data
processing, and every sub-agent you spawn. Trivial commands need no reservation.

**1. Estimate the peak** extra memory the step adds (not the average):
- First look at `OOMPH reservations` / `reservations`: the "recent" list shows the peak
  that earlier runs with the same purpose label actually added. Use it, plus ~25%. For
  older runs, `reservation_history` with `purpose` set (or `OOMPH reservations --history
  --last 7d`) goes back 14 days.
- Otherwise rough guides: Gradle/Android build 4–8 GB · Xcode build 3–6 GB · cargo /
  C++ `-jN` ≈ 0.5–1 GB per job · Jest/Vitest/pytest-xdist ≈ 0.5–1 GB per worker ·
  headless Chrome 0.3–1 GB per instance · a container: its memory limit, or 1–2 GB ·
  a sub-agent 1 GB · a local model: its file size × 1.2.
- Round up a little, never wildly: over-reserving blocks the other sessions for nothing.
- Keep the purpose label stable for the same work (`gradle assembleDebug`, `jest full
  suite`), so its measured peak helps the next estimate.

**2. Reserve, wait for the grant, then start.**
- **One command:** wrap it — `OOMPH run --reserve 6G --for "gradle assembleDebug" --wait 9m
  -- ./gradlew assembleDebug`. It queues, runs when granted and releases at exit. Keep
  `--wait` under your shell tool's own timeout (the Bash tool stops at 10 min), or run it
  in the background. Exit code 75 means it never got a turn and **did not run**.
- **Several steps or a long-lived process** (a dev server plus tests, `docker compose up`,
  sub-agents): `reserve_memory` (or `OOMPH reserve`), start only once `status` is
  `granted`, and `release_memory` with its `id` as soon as the heavy part is over — not
  at the end of the session. A grant expires after `ttl_min` (default 30); if the work
  will take longer, call `reserve_memory` again with `ticket` set to extend it, or
  `update_reservation` with a new `ttl_min`.

**Keep the reservation honest while the work runs** (`update_reservation` /
`OOMPH amend`); every change is recorded, and the menu-bar app draws it:
- The heavy part is over but you still need some memory (the build finished, the dev
  server keeps running): **shrink** it to what is left, e.g. `gb: 1`. It applies at once
  and lets the next session start.
- The work turns out bigger: **grow** it. If the extra fits now and nobody is waiting it
  is granted at once; otherwise the answer is `refused`, your grant stays as it was, and
  you reserve the extra separately with `reserve_memory` — it queues fairly behind the
  others. Don't start the bigger work before that grant.
- Done earlier, or later, than planned: set `ttl_min` (from now). A new `purpose` is fine
  when the work changes.
- Finished: `release_memory`. Don't shrink to zero instead.

**3. When you are queued:**
- Don't start the work, and don't "just start it anyway" because memory looks free —
  the memory you see is promised to whoever is ahead of you.
- Keep your place: ask again with the same `ticket` within 3 minutes (`reserve_memory`
  with `ticket`, or `OOMPH reserve --ticket rN --wait 5m`). A place you stop polling lapses.
- Meanwhile do light work that doesn't depend on the step: read code, edit, plan.
- Tell the user in one line who you're waiting for, e.g. "Waiting for memory: another
  session (IREngine) is running an 8 GB build; I'm next in line."
- If you've waited more than ~20 minutes, ask the user whether to keep waiting, run with
  less (lower parallelism, smaller reservation) or skip the step.
- If the response is `refused`, the request is larger than this Mac can hold — split
  the work or lower its parallelism.

**4. Grants and the rest of this skill:** a grant is a turn, not immunity. Still follow
the levels in §5 while the work runs, and if `memory_check` turns critical, back off
even with a grant. A grant with a `note` ("granted because no other work is reserved")
means the work is bigger than free memory: expect swapping, lower parallelism if you can.

Only ever release reservations your session made. Other sessions' entries in
`reservations` are information, not something to clear.

## 4. When to check

- **At the start** of a long or autonomous task.
- **Before every memory-heavy step** — and then reserve it (§3).
- **Periodically** during long runs — roughly every 20–30 minutes of work, or every
  10 or so heavy commands.
- **After anything suspicious**: a process killed without explanation (exit 137 /
  SIGKILL, "Killed: 9"), a build that died silently, the machine becoming very slow.
  Then also look at `OOMPH incidents`.

Checking is cheap (well under a second). Don't check before trivial commands.

## 5. What to do per level

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

## 6. Reading the numbers

- **free** is Activity Monitor's figure: Physical Memory − (App Memory + Wired + Compressed).
  A few GB free is normal; macOS uses spare memory as cache.
- **pressure** is macOS's own judgement (normal / WARN / CRITICAL) and matters more
  than "free".
- **swap a/b** — used / current size. Swap grows in 1 GB files on the startup disk; with
  less than ~20 GB disk free it may not be able to grow, which is the usual cause of
  the "out of application memory" dialog.
- **jetsam kills** — macOS killed processes to free memory. Any in a burst is a red flag.
- **unowned** — memory no running process accounts for. If `check` says a large amount is
  "held outside any process", it's a leak (typically GPU/driver memory left behind by a
  crashed or killed browser/GPU process). Stopping processes won't free it; only a restart
  will. Start nothing heavy, tell the user, and suggest saving work and restarting soon —
  the last time this happened the Mac froze two hours later.
- **available (reservations)** = free − what grants haven't used yet − a safety margin
  (5% of RAM, at least 1.5 GB). As a granted job's processes grow, its reservation turns
  into real usage instead of being counted twice. `check` turns **tight** when other
  sessions' reservations exceed what's free, even if macOS still looks relaxed.
