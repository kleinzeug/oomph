What `nvidia-smi` printed on a Linux machine with two RTX 4090 (Ubuntu 24.04, driver 580.178.04,
2026-11-24) for the three commands of `oomph_linux.gpu_cards`, one process (`python`) holding 386 MiB
on card 0, both cards idle. The cards' UUIDs and the pid are replaced by made-up ones of the same form.
`tools/linuxtest.py` reads these, and builds a busy variant from them (`sm` figures in pmon's columns).
