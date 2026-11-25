#!/usr/bin/python3 -I
"""Tests of the GPU reservations of 1.14 (roadmap 02 §6.5.1): the switch `gpu_reservations` and its refusals, a
Mac's GPU (its share, its memory charged against RAM) and the NVIDIA pools, one per card by UUID, on the cards
nvidia-smi described on a machine with two RTX 4090 (tools/fixtures/nvidia, UUIDs made up): which card a request
lands on, the queue, naming a card, what a grant uses (over, elsewhere), cards that go, amend, `oomph run --pin-gpu`,
`oomph resources` and the MCP arguments. Unprivileged and portable (no GPU needed: the cards are fixtures); a
ledger of its own. tools/selftest.py runs it.

    /usr/bin/python3 -I -B tools/gputest.py
"""
import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TMP = tempfile.mkdtemp(prefix="oomph-gputest-")
os.environ.update(OOMPH_DIR=TMP, OOMPH_LEDGER_DIR=os.path.join(TMP, "ledger"), OOMPH_STATE_DIR=os.path.join(TMP, "state"))
for k in ("OOMPH_GPU_RESERVATIONS", "CUDA_VISIBLE_DEVICES", "CUDA_DEVICE_ORDER"):
    os.environ.pop(k, None)
sys.path.insert(0, os.path.join(ROOT, "daemon"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import oomph  # noqa: E402
import oomph_linux  # noqa: E402  (its parsers and card_sample are pure functions)

G = oomph._G()  # the GPU code (daemon/oomph_gpu.py), bound to oomph
if sys.platform != "darwin":  # the ledger's process table, as tools/selftest.py has it on Linux
    import fixtureplat  # noqa: E402
    oomph._plat = fixtureplat
failures = []


def check(cond, what):
    print(("ok    " if cond else "FAIL  ") + what)
    if not cond:
        failures.append(what)


NV = os.path.join(ROOT, "tools", "fixtures", "nvidia")
U0, U1 = "GPU-1f2e3d4c-5b6a-7980-1a2b-3c4d5e6f7081", "GPU-9e8d7c6b-5a49-3827-1605-f4e3d2c1b0a9"
CARDS = oomph_linux.parse_nvidia_gpus(open(os.path.join(NV, "query-gpu-full.csv")).read())
CARDS[0]["procs"] = {48211: {"mb": 386.0}}            # another account's idle process on card 0, as recorded
BASE = dict(ram_gb=251.0, app_gb=20.0, wired_gb=4.0, compressed_gb=0.0, pressure=1, disk_free_gb=600.0,
            swap_used_gb=0.0, swap_total_gb=0.0, os="macos", cpu={"n": 48, "busy": 0.0})
state = {"cards": None, "gpu": None, "sample": None}


def nv_block(cards=None):
    return [oomph_linux.card_sample(c, {}) for c in (CARDS if cards is None else cards)]


def use(gpu):
    """The machine's GPU block, as the logger and a live read both give it (None: nvidia-smi did not answer)."""
    state["gpu"] = gpu


def sample():
    s = dict(BASE, t=time.time())
    if state["gpu"] is not None:
        s["gpu"] = json.loads(json.dumps(state["gpu"]))
    return s


oomph._sample_override = sample
G.live_gpus = lambda: json.loads(json.dumps(state["gpu"])) if state["gpu"] is not None else None
sleepers = [subprocess.Popen(["/bin/sleep", "120"]) for _ in range(4)]
H = [{"pid": x.pid, "start": None, "kind": "session", "project": "/tmp/g-%d" % i} for i, x in enumerate(sleepers)]
lease = lambda rid: next((x for x in oomph.read_ledger()["leases"] if x["id"] == rid), {})  # noqa: E731


def clear():
    for h in H:
        oomph.release("all", h["pid"])


def on(v=True):
    if v:
        os.environ["OOMPH_GPU_RESERVATIONS"] = "1"
    else:
        os.environ.pop("OOMPH_GPU_RESERVATIONS", None)


try:
    # --- the parsers, the card list
    bad = []
    for f, x in ((G.parse_gpu, "0"), (G.parse_gpu, "101"), (G.parse_gpu, "lots"), (G.parse_gpu, "60@"),
                 (G.parse_gpu_mem, "0G"), (G.parse_gpu_mem, "4M"), (G.parse_gpu_mem, "16G@"),
                 (G.parse_gpu_mem, "nanG")):
        try:
            f(x)
        except ValueError:
            bad.append(x)
    check(G.parse_gpu("60") == (60, None) and G.parse_gpu("60@1") == (60, "1")
          and G.parse_gpu("12.5%") == (12.5, None) and G.parse_gpu("0", zero=True) == (0, None)
          and G.parse_gpu_mem("16G@GPU-6ab19ebf") == (16.0, "GPU-6ab19ebf")
          and G.parse_gpu_mem("512M") == (0.5, None) and len(bad) == 8,
          "--gpu 60[@card] (a share of one GPU) and --gpu-mem 16G[@card]; nonsense refused (%s)" % bad)
    check(len(CARDS) == 2 and CARDS[1]["free_mb"] == 24077 and CARDS[0]["display"] is False and CARDS[0]["mig"] is False
          and oomph_linux.parse_nvidia_gpus("0, GPU-x, A, B, 7, 24564, 1, 2, Enabled, Enabled\n")[0]["name"] == "A,B",
          "nvidia-smi's long question: free memory, display and MIG mode; a name with a comma stays whole")
    cv = G.gpu_cards_of({"gpu": nv_block()})
    c0, c1 = cv[U0], cv[U1]
    check(list(cv) == [U0, U1] and c0["nvidia"] and c0["index"] == 0 and c1["id"] == "gpu1"
          and abs(c0["reserved"] - 484 / 1024.0) < 0.02 and abs(c1["margin"] - 0.05 * (24564 - 484) / 1024.0) < 0.02
          and abs(c1["cap"] - (24564 - 484) * 0.95 / 1024.0) < 0.02 and c0["reservable"] and 48211 in c0["procs"],
          "a pool per NVIDIA card by UUID: the driver keeps 484 MiB (total − used − free), 5 %% of the rest is kept back: "
          "at most %.1f GB on one 4090" % c1["cap"])
    mig = G.gpu_cards_of({"gpu": nv_block([dict(CARDS[0], mig=True), dict(CARDS[1], free_mb=None)])})
    check(not mig[U0]["reservable"] and "MIG" in mig[U0]["why"] and not mig[U1]["reservable"]
          and "free" in mig[U1]["why"], "a card in MIG mode, or one that gives no free memory, is listed, not reservable")

    odd = G.gpu_cards_of({"gpu": nv_block([dict(CARDS[0], uuid=None), CARDS[1]])})
    try:
        odd_req = G._gpu_request({"gpu": nv_block([dict(CARDS[0], uuid=None), CARDS[1]])}, 4.0, None, None)
        lone = G._gpu_request({"gpu": nv_block([dict(CARDS[0], uuid=None)])}, 4.0, None, None)
    except Exception as e:  # noqa: B902
        odd_req = lone = (None, repr(e), None)
    check(odd["gpu0"]["nvidia"] and not odd["gpu0"]["reservable"] and "UUID" in odd["gpu0"]["why"]
          and odd_req[1] is None and lone[0] is None and "UUID" in (lone[1] or ""),
          "an NVIDIA card whose UUID is missing or odd: listed as NVIDIA, not reservable, never a Mac's (%s)" % (lone[1],))
    many = [dict(CARDS[0], index=i, uuid="GPU-%08x-0000-0000-0000-000000000000" % i) for i in range(16)]
    Lg = {"leases": [{"id": "r1", "state": "granted", "v": 2, "gb": 0.01, "granted": 1.0,
                      "res": {"vram": {"ask": 4, "got": 4, "unified": False, "uuid": U1, "dev": "gpu16"}}}]}
    G._gpus_gone(Lg, {"gpu": nv_block(many)}, time.time())
    check("missing" not in Lg["leases"][0]["res"]["vram"],
          "a list of 16 cards may have been cut (gpu_cards_of): a card missing from it is not marked gone")
    plain = G.gpu_switch_text("oomph: REFUSED — ")
    cmd = next((x.strip() for x in plain.splitlines() if x.startswith("    ")), "")
    check(cmd in (oomph.CONFIG_FILE, "sudo mkdir -p \"%s\"; echo '{\"gpu_reservations\": true}' | sudo tee \"%s\"" % (
          os.path.dirname(oomph.CONFIG_FILE), oomph.CONFIG_FILE)) and plain.startswith("oomph: REFUSED — GPU"),
          "switched off, in a terminal: what is to be pasted stands on a line of its own, unbroken (%r)" % cmd[:60])

    # --- the switch: off by default, refused before anything is written, with how to switch it on
    use(nv_block())
    n0 = len(oomph.read_ledger()["leases"]) if os.path.exists(os.path.join(TMP, "ledger", "ledger.json")) else 0
    off = oomph.reserve(0, "a model", H[0], vram=16)
    off2 = oomph.reserve(4, "a model", H[0], gpu=60)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = oomph.cmd_reserve(["--gpu-mem", "16G", "--for", "x", "--json"])
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc_run = oomph.cmd_run(["--gpu-mem", "8G", "--pin-gpu", "--", "/usr/bin/true"])
    err_pin = io.StringIO()
    with contextlib.redirect_stderr(err_pin):
        rc_pin = oomph.cmd_run(["--pin-gpu", "--", "/usr/bin/true"])
    check(rc_pin == 75 and "switched off" in err_pin.getvalue(),
          "switched off: --pin-gpu alone says how to switch it on (exit 75), not a usage error")
    j = json.loads(out.getvalue())
    check(off["status"] == off2["status"] == j["status"] == "refused" and rc == 75 and rc_run == 75
          and "switched off" in off["advice"] and oomph.CONFIG_FILE in off["advice"]
          and "OOMPH_GPU_RESERVATIONS=1" in off["advice"] and "Memory, cores and disk" in off["advice"]
          and off.get("switch") == "gpu_reservations" and "switched off" in err.getvalue()
          and (not os.path.exists(os.path.join(TMP, "ledger", "ledger.json"))
               or len(oomph.read_ledger()["leases"]) == n0),
          "switched off: reserve, the CLI (exit 75) and oomph run --pin-gpu are refused with how to switch it on; "
          "nothing written")
    check(oomph.gpu_reservations_on({"gpu_reservations": True}) and not oomph.gpu_reservations_on({})
          and not oomph.gpu_reservations_on({"gpu_reservations": "maybe"}) and not oomph.reservable(sample()).count("gpu"),
          "the switch is one key of the root-owned configuration (or OOMPH_GPU_RESERVATIONS=1); off by default")
    m0 = oomph.reserve(2, "memory as usual", H[0])
    check(m0["status"] == "granted", "switched off: memory is reserved as usual")
    clear()

    # --- NVIDIA: which card, the queue, naming a card
    on()
    a = oomph.reserve(0, "model a", H[0], vram=16)
    b = oomph.reserve(0, "model b", H[1], vram=16)
    c = oomph.reserve(0, "model c", H[2], vram=16)
    la = lease(a["id"])
    va = la.get("res", {}).get("vram", {})
    check(a["status"] == "granted" and a["run_with"]["gpu"]["index"] == 1 and a["run_with"]["gpu"]["uuid"] == U1
          and a["run_with"]["gpu"]["env"] == {"CUDA_DEVICE_ORDER": "PCI_BUS_ID", "CUDA_VISIBLE_DEVICES": "1"}
          and a["advice"].startswith("Run on GPU 1, NVIDIA GeForce RTX 4090 (GPU-9e8d7c6b): CUDA_DEVICE_ORDER=PCI_BUS_ID "
                                     "CUDA_VISIBLE_DEVICES=1 (it is cuda:0 inside the job), or `oomph run --pin-gpu`.")
          and a["granted"] == {"gpu_mem_gb": 16.0},
          "16 GB lands on the least committed card (1: 4 MiB in use against 396), and the answer says which and how to "
          "run there (%s)" % a.get("advice", "")[:60])
    check(la.get("v") == 2 and la["gb"] == oomph.NO_MEM_GB and oomph.no_memory(la)
          and va == {"ask": 16.0, "unified": False, "got": 16.0, "dev": "gpu1", "uuid": U1,
                     "name": "NVIDIA GeForce RTX 4090", "used": 0.0, "peak": 0.0},
          "the lease keeps the card in its part (dev, uuid, name, unified false); discrete memory is not memory (%s)" % va)
    check(b["status"] == "granted" and b["run_with"]["gpu"]["index"] == 0 and c["status"] == "queued"
          and sorted(c.get("waiting_on") or []) == ["vram:" + U0, "vram:" + U1]
          and "GPU memory" in c["advice"] and "on a card" in c["advice"],
          "a second 16 GB lands on card 0, a third waits for either card (%s)" % c.get("waiting_on"))
    m = oomph.reserve(4, "memory meanwhile", H[3])
    n1 = oomph.reserve(0, "named card 1", H[3], vram=2, gpu_device="1")
    check(m["status"] == "granted" and n1["status"] == "queued" and n1.get("waiting_on") == ["vram:" + U1],
          "memory passes a request that waits for a card; a request naming card 1 waits behind the one that holds up "
          "every card it could fit on (first come, first served)")
    rel = oomph.release(a["id"])
    c2 = oomph.reserve(0, "model c", H[2], ticket=c["id"])
    check(c["id"] in rel.get("next_granted", []) and c2["status"] == "granted" and c2["run_with"]["gpu"]["index"] == 1
          and lease(n1["id"]).get("state") == "granted" and lease(n1["id"])["res"]["vram"]["uuid"] == U1,
          "released: the waiting request gets card 1, and the one behind it fits there too (%s)" % rel.get("next_granted"))
    hist = [h for h in oomph.reservation_history(3600, 50)["reservations"] if h["id"] == a["id"]]
    check(hist and hist[0].get("res", {}).get("vram") == 16.0 and hist[0]["res"].get("gpu_dev") == U1,
          "the history keeps the GPU memory and the card it was on (%s)" % (hist[:1] and hist[0].get("res")))
    clear()
    n0 = len(oomph.read_ledger()["leases"])
    r1 = oomph.reserve(0, "too big", H[0], vram=30)
    r2 = oomph.reserve(0, "no such card", H[0], vram=2, gpu_device="7")
    r3 = oomph.reserve(0, "short prefix", H[0], vram=2, gpu_device="GPU-1f2e")
    r4 = oomph.reserve(0, "no amount", H[0], gpu_device="0")
    use(nv_block([dict(CARDS[0], mig=True), CARDS[1]]))
    r5 = oomph.reserve(0, "MIG", H[0], vram=2, gpu_device="0")
    use(None)
    r6 = oomph.reserve(0, "no answer", H[0], vram=2)
    use([])
    r7 = oomph.reserve(0, "no GPU", H[0], vram=2)
    use(nv_block())
    check(all(x["status"] == "refused" for x in (r1, r2, r3, r4, r5, r6, r7)) and "at most 22" in r1["advice"]
          and "no card here is 7" in r2["advice"] and "names no card" in r3["advice"]
          and "without an amount" in r4["advice"] and "MIG" in r5["advice"] and "could not read" in r6["advice"]
          and "none" in r7["advice"] and len(oomph.read_ledger()["leases"]) == n0,
          "refused, nothing written: more than any card can give, a card that is not there or not named well, no "
          "amount, a card in MIG mode, no answer from nvidia-smi, no GPU (%s)" % r1["advice"][:60])
    p0 = oomph.reserve(0, "by uuid", H[0], vram=4, gpu=50, gpu_device="GPU-1F2E3D4C")
    lp = lease(p0["id"])
    check(p0["status"] == "granted" and p0["run_with"]["gpu"]["index"] == 0 and lp["res"]["gpu"]["uuid"] == U0
          and lp["res"]["gpu"]["got"] == 50 and p0["granted"] == {"gpu_mem_gb": 4.0, "gpu_pct": 50}
          and oomph.lease_need(lp) == {"vram:" + U0: (4.0, 4.0), "gpu:" + U0: (50, 50)},
          "a card named by a UUID prefix of 8 hex digits (any case) is resolved to its UUID; its share and memory on "
          "that card (%s)" % oomph.lease_need(lp))
    q = oomph.reserve(0, "share", H[1], gpu=60, gpu_device="0")
    mm = oomph.reserve(1, "memory", H[2])
    check(q["status"] == "queued" and q.get("waiting_on") == ["gpu:" + U0] and mm["status"] == "granted"
          and "50 %" in q["advice"], "60 %% of card 0 waits while 50 %% is granted there: a turn at the GPU holds up "
          "only that card's share")
    clear()

    # --- what a grant uses, from nvidia-smi's processes per card: used, over, elsewhere, [N/A]
    g = oomph.reserve(0, "used", H[0], vram=8)  # card 1
    pid = H[0]["pid"]
    for mb, want in ((5120, (5.0, None)), (9216, (8.0, "over"))):
        use(nv_block([CARDS[0], dict(CARDS[1], procs={pid: {"mb": float(mb), "sm": 40.0}})]))
        oomph.coordination(pid)
        v = lease(g["id"])["res"]["vram"]
        check(v.get("used") == want[0] and v.get("flag") == want[1] and v.get("peak") >= want[0],
              "a grant's use is its processes' memory on its card, capped at what it got; more is `over` (%s MB: %s)"
              % (mb, {k: v.get(k) for k in ("used", "peak", "flag")}))
    st = oomph.reserve(0, "used", H[0], ticket=g["id"])
    check(st.get("flags") == {"vram": "over"} and st["advice"].startswith("Your job uses 9 GB on GPU 1, more than the 8 GB"),
          "over: the answer says so first (%s)" % st["advice"][:70])
    use(nv_block([dict(CARDS[0], procs={pid: {"mb": 15565.0}}), CARDS[1]]))
    oomph.coordination(pid)
    st = oomph.reserve(0, "used", H[0], ticket=g["id"])
    v = lease(g["id"])["res"]["vram"]
    check(v.get("flag") == "elsewhere" and v.get("used") == 0.0 and v.get("else_dev") == "gpu0"
          and st["advice"].startswith("Your job uses 15.2 GB on GPU 0; it was granted GPU 1: run it with "
                                      "CUDA_DEVICE_ORDER=PCI_BUS_ID CUDA_VISIBLE_DEVICES=1, or `oomph run --pin-gpu`."),
          "an unpinned job on another card: its grant reads unused, flag elsewhere (%s)" % st["advice"][:80])
    use(nv_block([CARDS[0], dict(CARDS[1], procs={pid: {}})]))
    oomph.coordination(pid)
    v = lease(g["id"])["res"]["vram"]
    check("used" not in v and "flag" not in v, "no memory per process from the driver ([N/A]): no `used`, the grant "
          "counts in full")
    use(nv_block([dict(CARDS[0], procs={pid: {"mb": 15565.0}}), CARDS[1]]))
    oomph.coordination(pid)
    fl = oomph.advice_flags(lease(g["id"]))
    check(fl.get("vram", (None, None))[0] == "elsewhere" and fl["vram"][1] is not None,
          "elsewhere carries since when (%s)" % (fl,))
    two = [oomph.reserve(0, "split model", H[1], vram=8, gpu_device=d) for d in ("0", "1")]
    p1 = H[1]["pid"]
    use(nv_block([dict(CARDS[0], procs={48211: {"mb": 386.0}, p1: {"mb": 7000.0}}),
                  dict(CARDS[1], procs={p1: {"mb": 4000.0}})]))
    oomph.coordination(p1)
    st2 = [oomph.reserve(0, "split model", H[1], ticket=x["id"]) for x in two]
    v2 = [lease(x["id"])["res"]["vram"] for x in two]
    check(all(x["status"] == "granted" for x in two) and [x.get("flag") for x in v2] == [None, None]
          and [x.get("used") for x in v2] == [6.84, 3.91] and not any(x.get("flags") for x in st2)
          and not any(x["advice"].startswith("Your job uses") for x in st2),
          "a job split across two cards, a reservation for each from one holder: each grant reads its own card's use, "
          "and neither is `elsewhere` for the other card (%s)" % [(x.get("used"), x.get("flag")) for x in v2])
    for x in two:
        oomph.release(x["id"])
    use(nv_block([CARDS[0], dict(CARDS[1], procs={p1: {"mb": 3072.0}})]))  # a model it loaded before, unreserved
    bg = oomph.reserve(0, "after a model", H[1], vram=8, gpu_device="1")
    vb = lease(bg["id"])["res"]["vram"]
    use(nv_block([CARDS[0], dict(CARDS[1], procs={p1: {"mb": 5120.0}})]))
    oomph.coordination(p1)
    vb2 = lease(bg["id"])["res"]["vram"]
    check(vb.get("base") == 3.0 and vb2.get("used") == 2.0 and "flag" not in vb2,
          "what the tree held on the card before the grant is its base: only what it adds is used (%s)"
          % {k: vb2.get(k) for k in ("base", "used", "flag")})
    oomph.release(bg["id"])
    use(nv_block([dict(CARDS[1], index=0), dict(CARDS[0], index=1)]))  # the same cards, their indices swapped
    oomph.coordination(pid)
    st = oomph.reserve(0, "used", H[0], ticket=g["id"])
    check(lease(g["id"])["res"]["vram"].get("dev") == "gpu0" and st["run_with"]["gpu"]["index"] == 0
          and st["run_with"]["gpu"]["env"]["CUDA_VISIBLE_DEVICES"] == "0" and st["run_with"]["gpu"]["uuid"] == U1,
          "the index is only a label: a card whose index changed is pinned by its index now (%s)"
          % st.get("run_with", {}).get("gpu"))
    use(nv_block())
    clear()
    with oomph.Ledger() as L:  # a granted NVIDIA part whose uuid the reader dropped (planted, malformed)
        L["leases"].append({"id": "r77", "state": "granted", "gb": oomph.NO_MEM_GB, "purpose": "odd", "v": 2,
                            "holder": dict(H[0]), "requested": time.time(), "granted": time.time(),
                            "expires": time.time() + 600, "res_granted": time.time(), "res": {"vram": {"ask": 8, "got": 8, "unified": False,
                                                                          "uuid": "GPU-zzzzzzzz"}}})
    try:
        odd_amend = oomph.amend("r77", vram=9)
    except Exception as e:  # noqa: B902
        odd_amend = {"status": "crashed", "advice": repr(e)}
    try:
        odd_poll = oomph.reserve(0, "odd", H[0], ticket="r77")
        odd_rel = oomph.release("r77")
    except Exception as e:  # noqa: B902
        odd_poll, odd_rel = {"status": "crashed", "advice": repr(e)}, {}
    check(odd_amend["status"] == "refused" and "not known" in odd_amend["advice"] and odd_poll["status"] == "granted"
          and [h["id"] for h in odd_rel.get("released", [])] == ["r77"],
          "a GPU grant whose card is unknown: growing it is refused, polling and releasing it work (%s)"
          % odd_amend["advice"][:70])
    clear()

    # --- cards that come and go
    saved_gone = G.GPU_GONE_S
    G.GPU_GONE_S = 1.0
    g1 = oomph.reserve(0, "on card 1", H[0], vram=8, gpu_device="1")
    w1 = oomph.reserve(0, "waits on card 1", H[1], vram=20, gpu_device="1")
    use(None)  # nvidia-smi fails: that says nothing
    oomph.coordination(H[0]["pid"])
    time.sleep(0.6)
    oomph.coordination(H[0]["pid"])
    kept = lease(g1["id"]).get("state") == "granted"
    use(nv_block([CARDS[0]]))   # a list without card 1
    oomph.coordination(H[0]["pid"])
    marked = lease(g1["id"]).get("res", {}).get("vram", {}).get("missing")
    time.sleep(0.6)
    oomph.coordination(H[0]["pid"])
    still = lease(g1["id"]).get("state") == "granted"
    time.sleep(0.6)
    oomph.coordination(H[0]["pid"])
    gone = [h for h in oomph.read_ledger()["history"] if h["id"] in (g1["id"], w1["id"])]
    st = oomph.reserve(0, "waits", H[1], ticket=w1["id"])
    check(kept and marked and still and {h["id"]: h["outcome"] for h in gone} == {g1["id"]: "gpu_gone", w1["id"]: "refused"}
          and st["status"] == "refused",
          "a card missing from a list nvidia-smi gave: marked, then its grants end (gpu_gone) and what named it is "
          "refused; nvidia-smi failing ends nothing (%s)" % {h["id"]: h["outcome"] for h in gone})
    G.GPU_GONE_S = saved_gone
    use(nv_block())
    clear()

    # --- amend: grow on its card, shrink, drop; switched off only shrinking
    fill = [oomph.reserve(0, "fill", H[1], vram=16) for _ in range(2)]
    wq = oomph.reserve(0, "queued", H[2], vram=16)
    big_q = oomph.amend(wq["id"], vram=30)
    ok_q = oomph.amend(wq["id"], vram=18)
    check(all(x["status"] == "granted" for x in fill) and wq["status"] == "queued" and big_q["status"] == "refused"
          and "at most 22" in big_q["advice"] and lease(wq["id"])["res"]["vram"]["ask"] == 18.0
          and ok_q.get("changed", {}).get("vram") == [16.0, 18.0],
          "amend: a queued request may not grow past what any card can ever give (it would hold up every card); "
          "within it, it may (%s)" % big_q["advice"][:60])
    clear()
    g = oomph.reserve(0, "amend", H[0], vram=8, gpu=30)
    a1 = oomph.amend(g["id"], vram=12)
    a2 = oomph.amend(g["id"], vram=30)
    a3 = oomph.amend(g["id"], gpu=0)
    on(False)
    a4 = oomph.amend(g["id"], vram=14)
    a5 = oomph.amend(g["id"], vram=6)
    on()
    lg = lease(g["id"])["res"]
    check(a1.get("changed", {}).get("vram") == [8.0, 12.0] and a2["status"] == "refused" and "only" in a2["advice"]
          and a3.get("changed", {}).get("gpu") == [30, 0] and a4["status"] == "refused" and "switched off" in a4["advice"]
          and a5.get("changed", {}).get("vram") == [12.0, 6.0] and "gpu" not in lg and lg["vram"]["got"] == 6.0
          and lg["vram"]["uuid"] == U1,
          "amend: GPU memory grows on its card while it fits, its share drops with 0; switched off it may shrink, not "
          "grow (%s)" % [a1.get("changed"), a2["advice"][:40], a4["status"], a5.get("changed")])
    clear()

    # --- oomph run: the card in the environment, pinned only when asked
    os.environ["CUDA_VISIBLE_DEVICES"] = "0,1"
    envf = os.path.join(TMP, "env.txt")
    dump = ["/bin/sh", "-c", "env | grep -E '^(CUDA|OOMPH_GPU)' | sort > %s" % envf]
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = oomph.cmd_run(["--gpu-mem", "8G", "--pin-gpu", "--"] + dump)
    pinned = open(envf).read().split()
    err2 = io.StringIO()
    with contextlib.redirect_stderr(err2):
        rc2 = oomph.cmd_run(["--gpu-mem", "8G@0", "--"] + dump)
    free = open(envf).read().split()
    os.environ.pop("CUDA_VISIBLE_DEVICES")
    check(rc == rc2 == 0 and "CUDA_DEVICE_ORDER=PCI_BUS_ID" in pinned and "CUDA_VISIBLE_DEVICES=1" in pinned
          and "OOMPH_GPU_INDEX=1" in pinned and "OOMPH_GPU_UUID=" + U1 in pinned and "OOMPH_GPU_MEM_GB=8" in pinned
          and "replaces CUDA_VISIBLE_DEVICES=0,1 with 1" in err.getvalue(),
          "oomph run --pin-gpu: CUDA_DEVICE_ORDER=PCI_BUS_ID and the card's index, replacing what was set (said); "
          "OOMPH_GPU_* always (%s)" % pinned)
    check("CUDA_VISIBLE_DEVICES=0,1" in free and "OOMPH_GPU_INDEX=0" in free and "CUDA_DEVICE_ORDER=PCI_BUS_ID" not in free
          and "not pinned" in err2.getvalue(),
          "oomph run without --pin-gpu: the job is not pinned; OOMPH_GPU_INDEX names the card granted (%s)" % free)
    with contextlib.redirect_stderr(io.StringIO()):
        rc3 = oomph.cmd_run(["--pin-gpu", "--reserve", "1G", "--", "/usr/bin/true"])
    check(rc3 == 2, "--pin-gpu without a GPU part is a usage error")

    # --- oomph resources and the MCP arguments
    rs = oomph._resources(sample(), oomph.coordination(H[0]["pid"], sample()))
    on(False)
    rs_off = oomph._resources(sample(), None)
    on()
    check("gpu" in rs["reservable"] and rs["gpu"][1]["reservable"] and rs["gpu"][1].get("left_gb") is not None
          and "gpu" not in rs_off["reservable"] and rs_off["gpu"][0]["reservable"] is False
          and rs_off["gpu"][0].get("reservable_off") == "gpu_reservations",
          "oomph resources: the cards with what is left to reserve, or \"reservable: off (gpu_reservations)\"")
    ok_args = []
    for a_ in ({"purpose": "x", "gpu_mem_gb": 16}, {"purpose": "x", "gpu_pct": 60, "gpu_device": "1"},
               {"purpose": "x", "gpu_device": "1"}, {"purpose": "x", "gpu_pct": 150}, {"purpose": "x", "gpu_mem_gb": 0.001}):
        try:
            oomph._mcp_args("reserve_memory", a_)
            ok_args.append(True)
        except oomph.ToolArgError:
            ok_args.append(False)
    check(ok_args == [True, True, False, False, False],
          "MCP: gpu_mem_gb, gpu_pct and gpu_device are arguments; a card without an amount, 150 %%, 1 MB are not (%s)"
          % ok_args)
    mc = oomph._mcp_call("reserve_memory", {"purpose": "mcp", "gpu_mem_gb": 2, "wait_s": 0})
    check(mc["status"] == "granted" and mc["run_with"]["gpu"]["uuid"] in (U0, U1), "MCP reserve_memory with gpu_mem_gb")
    oomph.release(mc["id"])
    clear()

    # --- a Mac: the GPU's share, its memory unified and charged against RAM
    MAC = [{"id": "gpu0", "name": "Apple M3 Max", "unified": True, "src": "clients", "mem_limit_gb": 27.0,
            "mem_limit_est": True}]
    use(MAC)
    BASE.update(ram_gb=36.0, app_gb=20.0, wired_gb=4.0, compressed_gb=2.0)  # 10 GB free, 1.8 kept back
    x = oomph.reserve(2, "mac model", H[0], vram=4, gpu=60)
    lx = lease(x["id"])
    check(x["status"] == "granted" and lx["gb"] == 6.0 and lx["res"]["ram"] == {"ask": 2.0, "got": 2.0}
          and lx["res"]["vram"]["unified"] is True and lx["res"]["vram"]["got"] == 4.0 and lx["res"]["mem"]["got"] == 6.0
          and x["run_with"]["gpu"] == {"index": 0, "unified": True, "name": "Apple M3 Max", "pct": 60, "mem_gb": 4.0}
          and x["advice"].startswith("Use at most 4 GB of memory for the GPU"),
          "a Mac: GPU memory is memory (gb 2 + 4 = 6, ram 2, mem 6), the share is of gpu0 (%s)" % lx.get("res"))
    y = oomph.reserve(0, "second share", H[1], gpu=50)
    z = oomph.reserve(1, "memory", H[2])
    w = oomph.reserve(0, "too much", H[3], vram=4)
    check(y["status"] == "queued" and y.get("waiting_on") == ["gpu:gpu0"] and z["status"] == "granted"
          and w["status"] == "queued" and w.get("waiting_on") == ["ram"] and "on the GPU" in y["advice"],
          "a Mac: a second share waits for gpu0 alone (memory passes); GPU memory waits for memory (%s)"
          % [y.get("waiting_on"), w.get("waiting_on")])
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        oomph.cmd_release([x["id"]])
    check("reserved 2.0G, peak" in out.getvalue() and "4G of GPU memory" in out.getvalue(),
          "a Mac: the release line says the memory and the GPU's memory once each (%s)" % out.getvalue().strip()[:90])
    clear()
    # 02 §13 (a), (b): a request for 6 GB and the whole GPU waits short of both while a share is granted; memory
    # passes it while it waits for its turn at the GPU; once the GPU is free and it lacks only memory, a later
    # memory request and a later GPU request wait behind it (no alternation); 100 % waits while any share is granted
    s1 = oomph.reserve(0, "a share", H[0], gpu=30)
    m1 = oomph.reserve(5, "memory held", H[1])
    big = oomph.reserve(6, "a model alone on the GPU", H[2], gpu=100)
    small = oomph.reserve(1, "memory meanwhile", H[3])
    a_ = (big["status"], sorted(big.get("waiting_on") or []), small["status"])
    oomph.release(s1["id"])
    big2 = oomph.reserve(6, "a model alone on the GPU", H[2], ticket=big["id"])
    later_m = oomph.reserve(1, "later memory", H[0])
    later_g = oomph.reserve(0, "later share", H[0], gpu=10)
    check(a_ == ("queued", ["gpu:gpu0", "ram"], "granted") and big2["status"] == "queued"
          and big2.get("waiting_on") == ["ram"] and later_m["status"] == "queued" and later_g["status"] == "queued",
          "a Mac (02 §13 a, b): 6 GB and the whole GPU wait short of both while memory passes; once the GPU is free "
          "and only memory is short, neither a later memory request nor a later GPU share overtakes it (%s; %s)"
          % (a_, [big2.get("waiting_on"), later_m.get("waiting_on"), later_g.get("waiting_on")]))
    clear()
    BASE.update(ram_gb=64.0, app_gb=10.0)
    e1 = oomph.reserve(0, "estimated limit", H[0], vram=28)
    use([dict(MAC[0], mem_limit_est=False)])
    e2 = oomph.reserve(0, "exact limit", H[0], vram=28)
    e3 = oomph.reserve(0, "another card", H[0], gpu=10, gpu_device="1")
    check(e1["status"] == "granted" and "estimate" in (e1.get("note") or "") and e2["status"] == "refused"
          and "iogpu.wired_limit_mb" in e2["advice"] and e3["status"] == "refused" and "only its GPU" in e3["advice"],
          "a Mac: above the exact working-set limit refused, above an estimated one a note; no card but gpu0")
    clear()
    f1 = oomph.reserve(0, "first model", H[0], vram=20)
    f2 = oomph.reserve(0, "second model", H[1], vram=20)
    m3 = oomph.reserve(2, "memory meanwhile", H[2])
    f2b = oomph.amend(f2["id"], vram=28)
    f1b = oomph.amend(f1["id"], vram=26)
    oomph.release(f1["id"])
    f2c = oomph.reserve(0, "second model", H[1], ticket=f2["id"])
    check(f1["status"] == "granted" and f2["status"] == "queued" and f2.get("waiting_on") == ["vram:gpu0"]
          and "iogpu.wired_limit_mb" in f2["advice"] and m3["status"] == "granted" and f2b["status"] == "refused"
          and "at most 27" in f2b["advice"] and f1b["status"] == "refused" and f2c["status"] == "granted",
          "a Mac: the exact working-set limit is a pool for all grants (20 + 20 GB > 27 waits; memory passes); a queued "
          "request may not grow past it (%s)" % [f2.get("waiting_on"), f2b["advice"][:50], f1b["advice"][:50]])
    clear()
    err = io.StringIO()
    with contextlib.redirect_stderr(err):
        rc = oomph.cmd_run(["--gpu-mem", "1G", "--pin-gpu", "--", "/usr/bin/true"])
    check(rc == 0 and "sets nothing on a Mac" in err.getvalue(), "a Mac: --pin-gpu sets nothing, and says so")

    # --- reading the ledger: GPU parts this code reads, and those it does not
    q = {"id": "r90", "state": "queued", "gb": 0.01, "purpose": "x", "holder": {"pid": H[0]["pid"]}, "requested": 1e9,
         "v": 2}
    V = oomph._valid_lease
    good = V(dict(q, res={"vram": {"ask": 4, "unified": False}}))
    mixed = V(dict(q, res={"vram": {"ask": 4, "unified": False, "uuid": U0}, "gpu": {"ask": 4, "uuid": U1}}))
    planted = V(dict(q, res={"vram": {"ask": 4, "unified": False, "uuid": "../../dev/nvidia0", "name": "x\x1b[2J"}}))
    check(oomph.weighable(good) and oomph.lease_need(good) == {"vram:*": (4, 4)} and not oomph.weighable(mixed)
          and "uuid" not in planted["res"]["vram"] and "name" not in planted["res"]["vram"]
          and not oomph.weighable(V(dict(q, res={"tpu": {"ask": 1}}))),
          "the ledger: a request that names no card waits for any (vram:*); parts on two cards, or a resource this "
          "code does not know, cannot be weighed; a planted uuid or name is dropped")
finally:
    for x in sleepers:
        x.kill()
        x.wait()
    shutil.rmtree(TMP, ignore_errors=True)

print("\nFAILED (%d)" % len(failures) if failures else "\nall GPU checks passed")
sys.exit(1 if failures else 0)
