What `nvidia-smi` printed on a Linux machine with two RTX 4090 (Ubuntu 24.04, driver 580.178.04,
2026-11-24 and 25) for the commands of `oomph_linux.gpu_cards`, one process (`python`) holding 386 MiB
on card 0, both cards idle. The cards' UUIDs and the pid are replaced by made-up ones of the same form.
`query-gpu.csv` answers the short question of 1.13 (`NV_QUERY_OLD`), `query-gpu-full.csv` the long one
of 1.14 (`NV_QUERY`: free memory, display_active, mig.mode.current; the driver keeps 484 MiB of each
card, so total = 484 + used + free). `tools/linuxtest.py` reads these, and builds a busy variant from
them (`sm` figures in pmon's columns); `tools/gputest.py`, which `tools/selftest.py` runs, builds the
GPU pools of 1.14 from the long one.
