"""GPU reservations (G, 1.14.0; roadmap 02 §6.5.1): the share of a GPU (a rate pool, % at full speed) and its
memory. On a Mac the memory is unified: charged against RAM through `mem` and the gb mirror (02 §6.2). On Linux each
NVIDIA card is two pools by its UUID, `vram:<UUID>` (a stock, GB) and `gpu:<UUID>` (a rate, %); a request lands on one
card, the one it names or the least committed, and the grant says which (jobs are not pinned: `oomph run --pin-gpu`
does it). Shipped switched off (gpu_reservations); everything else always runs.

A part of oomph.py, kept apart so that what never meets a GPU part (oomph top, the hook) does not compile or hold
it: oomph._G() imports it and it reads oomph's names as its own (bound once, below). Standard library only."""
import sys

globals().update((k, v) for k, v in vars(sys.modules["oomph_gpu_host"]).items() if not k.startswith("__"))

VRAM_MARGIN = 0.05           # of what the driver leaves usable on a card (total − its own part), kept back: 1.2 GB of a 4090
GPU_GONE_S = VOLUME_GONE_S   # a reserved card missing this long from a list of every card: its reservations end (gpu_gone)
GPU_ELSEWHERE_GB = 0.5       # a grant's processes holding this much on another card, more than on its own: `elsewhere`
GPU_OVER_GB = 0.05           # GPU memory used beyond what was granted before a grant reads `over`
_GPU_MEASURED = ("used", "peak", "missing", "mseen", "else_gb", "else_dev", "base") + ADVICE_FIELDS  # a part's figures, not its ask


def _gpu_gb(x):
    """GB of GPU memory as people read them: 16, 15.2, 0.5 (one decimal, none when whole)."""
    return "%g" % round(x, 1)


def gpu_switch_text(plain=None):
    """The refusal of a GPU part while the switch is off: why, and how to switch it on (for everyone, for one command).
    `plain`: the lead of its first line in a terminal; the text is then wrapped, and what is to be pasted (the
    command, or the file's path) stands on a line of its own, never broken inside its quoted path."""
    head = ("GPU reservations are switched off on this machine (%s 1.14 ships them off until they have been measured "
            "with real model runs). To switch them on for everyone" % BRAND)
    tail = "For one command: `OOMPH_GPU_RESERVATIONS=1 oomph reserve …`. Memory, cores and disk can be reserved as usual."
    if os.path.lexists(CONFIG_FILE):
        how, lead, paste = "add \"gpu_reservations\": true to %s (with sudo)" % CONFIG_FILE, \
            ", add \"gpu_reservations\": true to this file (with sudo):", CONFIG_FILE
    else:
        paste = "sudo mkdir -p \"%s\"; echo '{\"gpu_reservations\": true}' | sudo tee \"%s\"" % (
            os.path.dirname(CONFIG_FILE), CONFIG_FILE)
        how, lead = paste, ", run:"
    if plain is None:
        return "%s: %s. %s" % (head, how, tail)
    return "%s\n    %s\n%s" % (wrap(head + lead, first=plain), paste, wrap(tail, first="  "))


def parse_gpu(x, zero=False):
    """`--gpu 60` (% of one GPU) or `--gpu 60@1` (on card 1, or @GPU-6ab19ebf): (share, card or None), the share
    with at most one decimal, 0.1 to 100, or with `zero` (amend: drop it) exactly 0. Raises ValueError."""
    v, sep, card = str(x).partition("@")
    try:
        f = float(v.strip().rstrip("%"))
    except ValueError:
        raise ValueError("not a share of a GPU: %s (use e.g. 60 for 60 %%, or 60@1 on card 1)" % x)
    if not (math.isfinite(f) and (0.1 <= round(f, 1) <= GPU_PCT_MAX or (zero and f == 0))):
        raise ValueError("--gpu takes a share of one GPU from 0.1 to 100 (%%), not %s" % x)
    if sep and not card:
        raise ValueError("--gpu %s: the card comes after the @ (e.g. 60@1)" % x)
    return _cn(round(f, 1)), (card or None)


def parse_gpu_mem(x, zero=False):
    """`--gpu-mem 16G` or `--gpu-mem 16G@1` (on card 1, or @GPU-6ab19ebf): (GB, card or None), the GB to two
    decimals and at least VRAM_MIN_GB, or with `zero` (amend: drop it) exactly 0. Raises ValueError."""
    size, sep, card = str(x).partition("@")
    try:
        gb = _parse_gb(size)
    except ValueError:
        gb = None
    if gb is None or not (math.isfinite(gb) and 0 <= gb <= VRAM_MAX_GB) or (gb == 0 and not zero) or \
            (gb and round(gb, 2) < VRAM_MIN_GB):
        raise ValueError("not an amount of GPU memory: %s (use e.g. 16G, or 16G@1 on card 1)" % x)
    if sep and not card:
        raise ValueError("--gpu-mem %s: the card comes after the @ (e.g. 16G@1)" % x)
    return round(gb, 2), (card or None)


def _gpu_name(c):
    """How a card is named to people: "GPU 1, NVIDIA GeForce RTX 4090 (GPU-6ab19ebf)", a Mac's "the GPU (Apple M3 Max)"."""
    if c.get("nvidia"):
        return "GPU %d, %s (%s)" % (c["index"], c["name"], c["key"][:12])
    return "the GPU (%s)" % c["name"] if c.get("name") else "the GPU"


def gpu_cards_of(s):
    """The GPUs of a sample as the pools see them, by key (an NVIDIA card's UUID, the identity; a Mac's id, gpu0), in
    the sample's order: key, id (gpu<index>: only a label), index, name, nvidia, unified, reservable and `why` not,
    and for an NVIDIA card its memory in GB: total, reserved (the driver's own), free, used, margin (VRAM_MARGIN of
    total − reserved), cap (the most one request can ever have there), display, and procs {pid: (MB or None, SM %
    or None)} (02 §6.5.1). A card in MIG mode, or one that does not say how much memory it has, is listed and not
    reservable. None when the sample has no list (no logger, or nvidia-smi did not answer): nothing is known then."""
    gl = s.get("gpu")
    if not isinstance(gl, list):
        return None
    out = {}
    for i, g in enumerate(gl[:16]):
        if not isinstance(g, dict):
            continue
        dev = g["id"] if _str(8, _GPU_DEV)(g.get("id")) else "gpu%d" % i
        uuid = g["uuid"] if _str(64, _GPU_UUID)(g.get("uuid")) else None
        nv = g.get("src") == "nvidia-smi"  # an NVIDIA card, even one whose UUID is missing or odd: never a Mac's
        c = {"key": (uuid or dev) if nv else dev, "id": dev, "index": int(dev[3:]), "nvidia": nv,
             "uuid": uuid if nv else None,
             "name": term_text(g["name"])[:64] if isinstance(g.get("name"), str) and g["name"].strip() else dev,
             "unified": g.get("unified") is True and not nv, "display": g.get("display") is True}
        if nv:
            tot = g.get("mem_total_gb") if _num(g.get("mem_total_gb"), 0.01, 1e5) else \
                g.get("mem_limit_gb") if _num(g.get("mem_limit_gb"), 0.01, 1e5) else None
            free = g.get("mem_free_gb") if _num(g.get("mem_free_gb"), 0, 1e5) else None
            used = g.get("mem_gb") if _num(g.get("mem_gb"), 0, 1e5) else 0.0
            c["why"] = "the driver gives no UUID for it" if uuid is None else \
                "it is in MIG mode" if g.get("mig") is True else \
                "the driver does not say how much memory it has" if tot is None else \
                "the driver does not say how much of its memory is free" if free is None else None
            if c["why"] is None:
                rsv = g["mem_reserved_gb"] if _num(g.get("mem_reserved_gb"), 0, tot) else max(0.0, tot - used - free)
                margin = VRAM_MARGIN * (tot - rsv)
                c.update(total=tot, reserved=rsv, free=free, used=used, margin=margin, cap=tot - rsv - margin)
            procs = {}
            for p in g.get("procs") if isinstance(g.get("procs"), list) else ():
                if isinstance(p, dict) and _pid(p.get("pid")):
                    procs[p["pid"]] = (p["mb"] if _num(p.get("mb"), 0, 1e7) else None,
                                       p["util"] if _num(p.get("util"), 0, 1e4) else None)
            c["procs"] = procs
        else:
            c["why"] = None if dev == "gpu0" else "only a Mac's first GPU can be reserved"
            c["limit"] = g.get("mem_limit_gb") if _num(g.get("mem_limit_gb"), 0.1, 1e5) else None
            c["limit_est"] = g.get("mem_limit_est") is True
        c["reservable"] = c["why"] is None
        out.setdefault(c["key"], c)
    return out


def _gpu_parts(r):
    """A lease's GPU parts (02 §6.5.1): {"gpu": its share part or None, "vram": its memory part or None, "key": its
    card (an NVIDIA card's UUID, a Mac's id) or None (an NVIDIA request that named none, until it is granted),
    "nvidia": on a discrete NVIDIA card (a part with a uuid, or `unified` false)}. None without a GPU part; False
    when a part is not one this code reads (it then cannot weigh the lease, 02 §9.3)."""
    res = r.get("res") if ledger_version(r) >= 2 and isinstance(r.get("res"), dict) else {}
    g, v = res.get("gpu"), res.get("vram")
    if g is None and v is None:
        return None
    if (g is not None and not (isinstance(g, dict) and _num(g.get("ask"), 0.1, GPU_PCT_MAX))) or \
            (v is not None and not (isinstance(v, dict) and _num(v.get("ask"), VRAM_MIN_GB / 2, VRAM_MAX_GB)
                                    and isinstance(v.get("unified"), bool))):
        return False
    parts = [x for x in (g, v) if x is not None]
    nv = {x.get("unified") is False or "uuid" in x for x in parts}
    if len(nv) != 1:
        return False
    nv = nv.pop()
    if nv:
        uu = {x.get("uuid") for x in parts if "uuid" in x}
        if len(uu) > 1 or not all(_str(64, _GPU_UUID)(u) for u in uu) or (v is not None and v["unified"]):
            return False
        key = uu.pop() if uu else None
    else:
        devs = {x.get("dev", "gpu0") for x in parts}
        key = devs.pop() if len(devs) == 1 else None
        if not _str(8, _GPU_DEV)(key):
            return False
    return {"gpu": g, "vram": v, "key": key, "nvidia": nv}


def _gpu_pools(gp, key=None):
    """The pool ids of a lease's GPU parts on card `key` (its own by default; "*" while an NVIDIA request names none):
    gpu:<key> for its share, vram:<key> for its memory (on a Mac it is in `ram` too; its own pool is what the GPU may
    wire of it, iogpu.wired_limit_mb, where that limit is exact)."""
    k = key or gp["key"] or "*"
    return ({"gpu:" + k} if gp["gpu"] else set()) | ({"vram:" + k} if gp["vram"] else set())


def gpu_view(s, leases):
    """The GPU pools as admission sees them (02 §6.1, §6.5.1), by card key: gpu_cards_of's card with `room` (% that
    can still be reserved: 100 − Σ what grants got), and on an NVIDIA card `left` (GB a new request can have: free −
    margin − Σ over grants on it max(0, got − used)), `committed` (used + what grants were promised and have not used:
    how a card is chosen) and what grants hold; on a Mac `ugb`, the GPU memory its grants hold (against the working-set
    limit). A Mac's GPU is there from its grants alone when the sample lists none. Returns (view, listed): `listed`
    when the sample lists the cards (else nothing new lands on an NVIDIA card)."""
    cards = gpu_cards_of(s)
    view = {}
    for k, c in (cards or {}).items():
        view[k] = dict(c, room=float(GPU_PCT_MAX), pct=0.0, gb=0.0, ugb=0.0, committed=c.get("used", 0.0),
                       left=c["free"] - c["margin"] if "cap" in c else None)
    for r in leases:
        gp = _gpu_parts(r) if r["state"] == "granted" else None
        if not gp or not gp["key"]:
            continue
        c = view.get(gp["key"])
        if c is None:
            if gp["nvidia"]:
                continue  # a card this sample does not list: gone, or no list (_gpus_gone)
            c = view[gp["key"]] = _mac_gpu(gp["key"])
        g, v = gp["gpu"], gp["vram"]
        if g and _num(g.get("got"), 0, GPU_PCT_MAX):
            c["room"] -= g["got"]
            c["pct"] += g["got"]
        if v and gp["nvidia"] and _num(v.get("got"), 0, VRAM_MAX_GB):
            out = max(0.0, v["got"] - (v["used"] if _num(v.get("used"), 0, VRAM_MAX_GB) else 0.0))
            c["gb"] += v["got"]
            c["committed"] += out
            if c.get("left") is not None:
                c["left"] -= out
        elif v and _num(v.get("got"), 0, VRAM_MAX_GB):
            c["ugb"] += v["got"]
    return view, cards is not None


def _mac_gpu(key):
    """A Mac's GPU that the sample does not list (no logger): its share is counted from the grants alone."""
    return {"key": key, "id": key, "index": int(key[3:]), "nvidia": False, "uuid": None, "name": key, "unified": True,
            "reservable": key == "gpu0", "why": None if key == "gpu0" else "only a Mac's first GPU can be reserved",
            "room": float(GPU_PCT_MAX), "pct": 0.0, "gb": 0.0, "ugb": 0.0, "committed": 0.0, "left": None,
            "limit": None, "limit_est": False}


def _gpu_fit(gp, view, listed, blocked):
    """Where a queued request's GPU parts fit now (02 §6.5.1): (the card's key or None, short, behind, pools). A Mac's
    GPU: its share must fit what can still be reserved, and its memory, with what grants hold, an exact working-set
    limit (iogpu.wired_limit_mb: Metal wires no more for all of them together). An NVIDIA request: on the card it named, else on any card it
    could ever fit on; among those that fit now and that no earlier waiting request holds up, the least committed,
    then the lowest index (the same ledger and sample always give the same card). It waits short of, or behind, the
    pools of every card it could have, so that it holds them all up (first come, first served, as memory does).
    Without a list of the cards nothing new lands on any of them."""
    g, v = gp["gpu"], gp["vram"]
    if not gp["nvidia"]:
        c, p = view.get(gp["key"]) or _mac_gpu(gp["key"]), _gpu_pools(gp)
        lim = c.get("limit") if not c.get("limit_est") else None
        short = ({"gpu:" + gp["key"]} if g and c["room"] < g["ask"] - 1e-9 else set()) | \
            ({"vram:" + gp["key"]} if v and lim and c.get("ugb", 0.0) + v["ask"] > lim + 1e-9 else set())
        behind = {x for x in p if _blocks(x, blocked)}
        return (None if short or behind else gp["key"]), short, behind, p
    if gp["key"]:
        cands = [gp["key"]] if listed and gp["key"] in view and view[gp["key"]]["reservable"] else []
    else:
        cands = [k for k, c in view.items() if listed and c["nvidia"] and c["reservable"]
                 and (not v or v["ask"] <= c["cap"] + 1e-9)]
    if not cands:  # no list, the card is not listed (gone?) or not reservable now, or none could ever hold it
        p = _gpu_pools(gp)
        return None, set(p), set(), p
    short, behind, pools, fit = set(), set(), set(), []
    for k in cands:
        c, p = view[k], _gpu_pools(gp, k)
        pools |= p
        s = ({"vram:" + k} if v and c["left"] < v["ask"] - 1e-9 else set()) | \
            ({"gpu:" + k} if g and c["room"] < g["ask"] - 1e-9 else set())
        b = {x for x in p if _blocks(x, blocked)}
        short |= s
        behind |= b
        if not s and not b:
            fit.append(k)
    if fit:
        k = min(fit, key=lambda k: (round(view[k]["committed"], 3), view[k]["index"]))
        return k, set(), set(), _gpu_pools(gp, k)
    return None, short, behind, pools


def _gpu_grant(r, gp, key, view, now, procs=None, children=None):
    """Grants a request's GPU parts on card `key` (02 §6.5.1): each part keeps the card (dev, and on an NVIDIA card its
    uuid and name), and what is left there shrinks. On an NVIDIA card the memory part keeps `base`, the GB its watched
    trees already hold there (an unreserved model the session loaded before, say): only what they add is its `used`,
    as memory has its baseline_gb."""
    c = view.get(key) or _mac_gpu(key)
    view[key] = c
    card = {"dev": c["id"]}
    if gp["nvidia"]:
        card.update(uuid=key, name=c["name"])
    elif c.get("name") and c["name"] != c["id"]:
        card["name"] = c["name"]
    for k in ("gpu", "vram"):
        x = gp[k]
        if x is None:
            continue
        r["res"][k] = dict({f: y for f, y in x.items() if f not in _GPU_MEASURED}, got=x["ask"], **card)
        if k == "vram":
            r["res"][k]["unified"] = not gp["nvidia"]
            if gp["nvidia"] and procs is not None and c.get("procs"):
                mine = [c["procs"][p][0] for p in _tree_pids(procs, children or {}, [p for p in _watched(r) if p])
                        if p in c["procs"]]
                if mine and None not in mine and sum(mine) > 0:  # [N/A]: no base, as there is no `used`
                    r["res"][k]["base"] = round(sum(mine) / 1024.0, 2)
    if gp["gpu"]:
        c["room"] -= gp["gpu"]["ask"]
        c["pct"] += gp["gpu"]["ask"]
    if gp["vram"] and gp["nvidia"]:
        c["left"] = (c["left"] or 0.0) - gp["vram"]["ask"]
        c["committed"] += gp["vram"]["ask"]
        c["gb"] += gp["vram"]["ask"]
    elif gp["vram"]:
        c["ugb"] = c.get("ugb", 0.0) + gp["vram"]["ask"]


def _tree_pids(procs, children, roots):
    """The pids of the process trees at `roots` (those in the table)."""
    stack, seen = list(roots), set()
    while stack:
        x = stack.pop()
        if x in seen or x not in procs:
            continue
        seen.add(x)
        stack.extend(children.get(x, []))
    return seen


def _watched(r):
    """The roots of the process trees charged to a lease: what it watches, and `watch_also` (02 §6.2)."""
    return [r.get("watch")] + [w["pid"] for w in r.get("watch_also") or () if isinstance(w, dict) and _pid(w.get("pid"))]


def _charge_gpu(L, s, procs, children, now, rated):
    """What each GPU grant uses (02 §6.3, §6.5.1). On an NVIDIA card, from the sample's list (memory and SM share per
    process per card, any account's): what its watched trees added on its card since the first of them was granted
    (`base`), shared in grant order among grants watching the same tree, as memory shares a tree's growth, `used`
    capped at what it got, `peak` following; more than it got is `over`; its trees holding more on another card than
    on its own is `elsewhere` (an unpinned job that landed there), never on a card where the same trees hold a grant
    of their own (a job split across two cards, a reservation for each). Where the driver gives no memory per process
    ([N/A]) a grant has no `used` and counts in full. Nothing of another process is credited to a grant. A Mac's share, from the logger's GPU rates per process
    (`rated`), as cores are charged. Only with a list of the cards (or the rates): otherwise the figures stay."""
    cards = gpu_cards_of(s) or {}
    groups = {}
    for r in L["leases"]:
        gp = _gpu_parts(r) if r["state"] == "granted" else None
        if gp and gp["nvidia"] and gp["key"] in cards:  # the index is only a label, read anew from every sample
            for x in (gp["gpu"], gp["vram"]):
                if x is not None and x.get("dev") != cards[gp["key"]]["id"]:
                    x["dev"] = cards[gp["key"]]["id"]
        if gp and gp["key"] and ((gp["nvidia"] and gp["key"] in cards) or (not gp["nvidia"] and rated)):
            groups.setdefault((gp["key"], r.get("watch")), []).append((r, gp))
    trees = {}
    for gk, rs in groups.items():
        rs.sort(key=lambda x: x[0]["granted"])
        trees[gk] = _tree_pids(procs, children, [p for r, _ in rs for p in _watched(r) if p is not None])
    for (key, w), rs in groups.items():
        pids = trees[(key, w)]
        if rs[0][1]["nvidia"]:
            mine = [cards[key]["procs"][p] for p in pids if p in cards[key]["procs"]]
            na = any(mb is None for mb, _ in mine)
            raw = sum(mb or 0.0 for mb, _ in mine) / 1024.0
            bases = [v["base"] if _num(v.get("base"), 0, VRAM_MAX_GB) else 0.0 for _, gp in rs for v in (gp["vram"],) if v]
            mem = max(0.0, raw - min(bases or [0.0]))  # the first grant's base, shared (memory's baseline_gb)
            util = sum(u or 0.0 for _, u in mine)
            held = {k for (k, _w), p in trees.items() if k != key and p & pids}  # the same trees' grants elsewhere
            other = {}
            for k, c in cards.items():
                if k != key and k not in held and c["nvidia"]:
                    gb = sum((c["procs"][p][0] or 0.0) for p in pids if p in c["procs"]) / 1024.0
                    if gb > 0:
                        other[c["id"]] = gb
            away = max(other.items(), key=lambda x: x[1]) if other else None
        else:
            na, mem, raw, away = True, 0.0, 0.0, None
            util = sum(procs[p]["gpu"] for p in pids if _num(procs[p].get("gpu"), 0, 1e4))
        for i, (r, gp) in enumerate(rs):
            last = i == len(rs) - 1
            g, v = gp["gpu"], gp["vram"]
            if g and _num(g.get("got")) and (gp["nvidia"] or rated):
                share = util if last else min(g["got"], util)
                util -= share
                g["used"] = round(share, 1)
                g["peak"] = round(max(g["peak"] if _num(g.get("peak")) else 0.0, share), 1)
            if not (v and gp["nvidia"] and _num(v.get("got"))):
                continue
            if na:
                for f in ("used", "else_gb", "else_dev"):
                    v.pop(f, None)
                v.pop("flag", None)
                _rated(v, now)
                continue
            share = mem if last else min(v["got"], mem)
            mem -= share
            v["used"] = round(min(v["got"], share), 2)
            v["peak"] = round(max(v["peak"] if _num(v.get("peak")) else 0.0, v["used"]), 2)
            flag = None
            if share > v["got"] + GPU_OVER_GB:
                flag = "over"
                v["else_gb"] = round(share, 2)  # what its trees hold on its card: the advice says it
            elif away and away[1] >= GPU_ELSEWHERE_GB and away[1] > raw and last:
                flag = "elsewhere"
                v["else_gb"], v["else_dev"] = round(away[1], 2), away[0]
            if flag != v.get("flag") or not _t(v.get("over_t")):
                v["over_t"] = round(now, 1)
            if flag:
                v["flag"] = flag
            else:
                for f in ("flag", "over_t", "else_gb", "else_dev"):
                    v.pop(f, None)
            if flag != "elsewhere":
                v.pop("else_dev", None)
            _rated(v, now)


def _gpus_gone(L, s, now):
    """Reservations on an NVIDIA card that is no longer there (02 §6.5.1, outcome gpu_gone), as _volumes_gone does for a
    volume: only a list nvidia-smi answered is every card; a reserved card missing from it is marked, and once it has
    been missing for GPU_GONE_S its grants end (gpu_gone) and the requests that named it are refused. The grace counts
    only while it is looked at (after a gap it starts again). No list (nvidia-smi failing, a driver reload) says
    nothing: the leases stay, and nothing new lands on any card until a list comes back."""
    if not _nvidia_list(s) or len(s["gpu"]) >= 16:  # a list cut at 16 cards (gpu_cards_of) may not be every card
        return
    cards = gpu_cards_of(s)
    for r in list(L["leases"]):
        gp = _gpu_parts(r)
        if not gp or not gp["nvidia"] or not gp["key"]:
            continue
        d = gp["vram"] or gp["gpu"]
        if gp["key"] in cards:
            for x in (gp["gpu"], gp["vram"]):
                if x:
                    x.pop("missing", None)
                    x.pop("mseen", None)
        elif not (_t(d.get("missing")) and _t(d.get("mseen"))) or d["missing"] > now or d["mseen"] > now \
                or now - d["mseen"] > GPU_GONE_S:
            d["missing"] = d["mseen"] = round(now, 1)
        elif now - d["missing"] >= GPU_GONE_S:
            if r["state"] == "granted":
                _retire(L, r, "gpu_gone", now, at=d["missing"])
            else:
                r["note"] = "the card it named (%s) is no longer there" % term_text(gp["key"])[:16]
                _retire(L, r, "refused", now)
            L["leases"].remove(r)
        else:
            d["mseen"] = round(now, 1)


def _nvidia_list(s):
    """Does the sample's `gpu` block come from nvidia-smi (a list of every NVIDIA card), not a Mac's registry?"""
    gl = s.get("gpu")
    return isinstance(gl, list) and bool(gl) and all(isinstance(g, dict) and g.get("src") == "nvidia-smi" for g in gl)


def live_gpus():
    """This machine's GPUs as a sample's `gpu` block, read now (02 §6.5.1: admission asks nvidia-smi for the free
    memory of the cards itself; 30 to 130 ms): on Linux the NVIDIA cards (oomph_linux.card_sample), [] without
    nvidia-smi, None when it did not answer; on a Mac the registry's GPUs and the first one's working-set limit."""
    P = plat()
    if hasattr(P, "gpu_cards"):
        if not P.gpu_available():
            return []
        cards = P.gpu_cards(fresh=True)
        return None if cards is None else [P.card_sample(c, None) for c in cards]
    if not hasattr(P, "gpu_registry"):
        return []
    devs = P.gpu_registry()
    if devs is None:
        return None
    out = [{"id": "gpu%d" % i, "name": d.get("name"), "unified": os.uname().machine == "arm64"} for i, d in enumerate(devs)]
    if out and hasattr(P, "gpu_mem_limit_gb"):
        try:
            lim = P.gpu_mem_limit_gb(P.system_memory()["ram_gb"])
            out[0]["mem_limit_gb"], out[0]["mem_limit_est"] = lim[0], bool(lim[1])
        except Exception:  # noqa: B902 — the limit is a bonus here
            pass
    return out


def _with_gpus(s):
    """The sample with its GPUs read now (live_gpus), for a request or a poll with a GPU part: the cards' free memory
    must be current. A block that could not be read is left out (nothing new lands on an NVIDIA card then). A Mac's
    sample that lists its GPUs is kept as it is: nothing there changes from one second to the next that admission
    reads (the GPU's name, unified, the working-set limit)."""
    gl = s.get("gpu")
    if not hasattr(plat(), "gpu_cards") and not _nvidia_list(s) and isinstance(gl, list) and gl and \
            isinstance(gl[0], dict) and isinstance(gl[0].get("unified"), bool):
        return s  # a Mac: only gpu0 is reservable, and the logger's sample lists it (no ioreg run per request)
    try:
        g = live_gpus()
    except Exception:  # noqa: B902 — as if nvidia-smi had not answered
        g = None
    s = dict(s)
    if g is None:
        s.pop("gpu", None)
    else:
        s["gpu"] = g
    return s


def _resolve_gpu(cards, name):
    """The card a request names (02 §6.5.1): an index ("1", "gpu1") or a UUID or its prefix of at least 8 hex digits
    ("GPU-6ab19ebf", as CUDA takes it). (card, None) or (None, why)."""
    n = str(name).strip()
    if re.fullmatch(r"(gpu)?\d{1,3}", n, re.I):
        i = int(re.sub(r"(?i)gpu", "", n))
        c = next((c for c in cards.values() if c["index"] == i), None)
    elif re.fullmatch(r"GPU-[0-9a-fA-F]{8}[0-9a-fA-F-]{0,52}", n):
        found = [c for c in cards.values() if c["uuid"] and c["uuid"].lower().startswith(n.lower())]
        c = found[0] if len(found) == 1 else None
    else:
        return None, "%s names no card (name one by its index, e.g. 1, or its UUID, e.g. GPU-6ab19ebf)" % term_text(n)[:40]
    if c is None:
        return None, "no card here is %s (%s)" % (term_text(n)[:40], ", ".join(
            "%d: %s" % (c["index"], c["key"][:12]) for c in cards.values()) or "none listed")
    return c, None


def _gpu_request(s, vram, device, gpu=0):
    """Checks a new request's GPU parts against this machine's GPUs (02 §6.4 refusals, §6.5.1): (card or None, refusal
    or None, note or None). The card is the one it named (an NVIDIA card: resolved to its UUID now, as `--disk …@PATH`
    is to a volume), a Mac's gpu0, or None for an NVIDIA request that may land on any card. Refused: no GPU here; a
    name that matches no card, a card that cannot be reserved (MIG mode, no memory figures); more GPU memory than the
    card it named or every card can ever give (total − the driver's part − the margin); on a Mac, another card than
    gpu0, GPU memory above the exact working-set limit (an estimated one earns a note) or a Mac whose GPU memory is
    not unified."""
    if gpu is None and vram is None:
        return None, "Can't reserve a GPU without an amount: ask for its share (--gpu 60) or its memory (--gpu-mem 16G).", None
    cards = gpu_cards_of(s)
    if cards is None:
        return None, ("Can't reserve a GPU now: %s could not read %s. Try again in a moment." % (
            BRAND, "this Mac's GPU" if not hasattr(plat(), "gpu_cards") else
            "this machine's GPUs (nvidia-smi did not answer)")), None
    if not cards:
        return None, "Can't reserve a GPU here: this machine has none that %s can see." % BRAND, None
    nv = any(c["nvidia"] for c in cards.values())
    if nv:
        card = None
        if device is not None:
            card, why = _resolve_gpu(cards, device)
            if why:
                return None, "Can't reserve on that GPU: %s." % why, None
            if not card["reservable"]:
                return None, "Can't reserve on %s: %s. Name another card, or none." % (_gpu_name(card), card["why"]), None
        ok = [card] if card else [c for c in cards.values() if c["reservable"] and "cap" in c]
        if not ok:
            return None, "Can't reserve a GPU here: %s." % "; ".join(
                "%s: %s" % (_gpu_name(c), c["why"]) for c in cards.values()), None
        if vram is not None:
            why = _vram_too_big(vram, ok, card)
            if why:
                return None, why, None
        return card, None, None
    card = cards.get("gpu0")
    if device is not None and str(device).strip().lower() not in ("0", "gpu0"):
        return None, "Can't reserve on %s: on a Mac only its GPU (gpu0) can be reserved." % term_text(str(device))[:40], None
    if card is None:
        return None, "Can't reserve a GPU here: this Mac has none that %s can see." % BRAND, None
    note = None
    if vram is not None:
        if not card["unified"]:
            return None, ("Can't reserve GPU memory on this Mac: its GPU has memory of its own, which %s does not "
                          "measure. Reserve its share (--gpu) and memory alone." % BRAND), None
        lim = card.get("limit")
        if lim and vram > lim + 1e-9 and not card["limit_est"]:
            return None, _mac_too_big(vram, lim), None
        if lim and vram > lim + 1e-9:
            note = ("%s GB of GPU memory is more than the GPU may use by default (about %s GB, an estimate of Metal's "
                    "working-set limit): the model may not load" % (_gpu_gb(vram), _gpu_gb(lim)))
    return card, None, note

def _vram_too_big(vram, ok, card=None):
    """The refusal of more GPU memory than any of the cards `ok` (or `card`, the one named) can ever give, else None."""
    most = max(c["cap"] for c in ok)
    if vram <= most + 1e-9:
        return None
    return ("Can't reserve %s GB of GPU memory: %s can give at most %s GB (of %s GB, the driver keeps %s GB and %s keeps "
            "%s GB back). Ask for less, or split the model across two reservations, one per card (`--gpu-mem NG@0`, "
            "`--gpu-mem NG@1`)." % (
                _gpu_gb(vram), _gpu_name(card) if card else "a card here", _gpu_gb(max(0.0, most)),
                _gpu_gb(max(c["total"] for c in ok)), _gpu_gb(min(c["reserved"] for c in ok)), BRAND,
                _gpu_gb(min(c["margin"] for c in ok))))


def _mac_too_big(vram, lim):
    return ("Can't reserve %s GB of GPU memory: the GPU may use at most %s GB of this Mac's memory "
            "(iogpu.wired_limit_mb). Ask for less." % (_gpu_gb(vram), _gpu_gb(lim)))


def _vram_cap_refusal(s, gp, vram):
    """An amend that grows a lease's GPU memory beyond what its card (or, naming none, any card) can ever give: the
    refusal a new request of that size gets; on a Mac beyond the exact working-set limit. None when it can be, or
    when the sample does not tell (it then waits, as before)."""
    cards = gpu_cards_of(s) if s else None
    if not cards:
        return None
    if not gp["nvidia"]:
        c = cards.get(gp["key"] or "gpu0")
        lim = c.get("limit") if c and not c.get("limit_est") else None
        return _mac_too_big(vram, lim) if lim and vram > lim + 1e-9 else None
    card = cards.get(gp["key"]) if gp["key"] else None
    ok = [card] if gp["key"] else [c for c in cards.values() if c["nvidia"] and c["reservable"]]
    ok = [c for c in ok if c and "cap" in c]
    return _vram_too_big(vram, ok, card) if ok else None


def _gpu_label(part):
    """A GPU part's card as people call it: "GPU 1" (nvidia-smi's index), else "the GPU"."""
    dev = part.get("dev") if isinstance(part.get("dev"), str) else ""
    return "GPU %s" % dev[3:] if _GPU_DEV.fullmatch(dev) and part.get("unified") is not True else "the GPU"

def _cuda_env(part):
    """The environment that runs a job on a granted NVIDIA card (02 §6.5.1): PCI bus order, so that CUDA numbers the
    cards as nvidia-smi does (its default, FASTEST_FIRST, matches only by chance), and the card's index (launchers
    that read the variable themselves take integers; it is cuda:0 inside the job)."""
    return {"CUDA_DEVICE_ORDER": "PCI_BUS_ID", "CUDA_VISIBLE_DEVICES": part["dev"][3:]}

def _cuda_env_text(part):
    return " ".join("%s=%s" % kv for kv in sorted(_cuda_env(part).items())) if _GPU_DEV.fullmatch(
        str(part.get("dev"))) else "the card's index in CUDA_VISIBLE_DEVICES"

def _gpu_run_with(gp, granted):
    """A GPU grant's `run_with.gpu` (02 §6.5.1): the card (index, and on an NVIDIA card its uuid, name and the
    environment that runs a job there), the share and the memory granted; `granted` gains gpu_pct and gpu_mem_gb."""
    g, v = gp["gpu"], gp["vram"]
    part = v or g
    dev = part.get("dev") if isinstance(part.get("dev"), str) and _GPU_DEV.fullmatch(part["dev"]) else "gpu0"
    out = {"index": int(dev[3:])}
    if gp["nvidia"]:
        out.update(uuid=gp["key"], name=part.get("name") or "NVIDIA GPU", env=_cuda_env(dict(part, dev=dev)))
    else:
        out["unified"] = True
        if part.get("name"):
            out["name"] = part["name"]
    if g and _num(g.get("got")):
        granted["gpu_pct"] = out["pct"] = g["got"]
    if v and _num(v.get("got")):
        granted["gpu_mem_gb"] = out["mem_gb"] = v["got"]
    return out

def _gpu_run_text(gp):
    """The first sentence of a GPU grant's advice: where to run, and how much of the card the job may take."""
    g, v = gp["gpu"], gp["vram"]
    part = v or g
    amounts = " and ".join(x for x in ("%s GB of its memory" % _gpu_gb(v["got"]) if v and _num(v.get("got")) else "",
                                       "%s %% of its time" % cores_text(g["got"]) if g and _num(g.get("got")) else "") if x)
    if gp["nvidia"]:
        return ("Run on %s, %s (%s): %s (it is cuda:0 inside the job), or `oomph run --pin-gpu`. Keep the job within %s "
                "(a CUDA context takes about half a GB of it). " % (
                    _gpu_label(part), term_text(part.get("name") or "NVIDIA GPU")[:64], gp["key"][:12],
                    _cuda_env_text(part), amounts))
    mac = [x for x in ("%s GB of memory for the GPU (this Mac's memory, counted in the reservation)" % _gpu_gb(v["got"])
                       if v and _num(v.get("got")) else "",
                       "%s %% of the GPU's time" % cores_text(g["got"]) if g and _num(g.get("got")) else "") if x]
    return "Use at most %s. " % " and ".join(mac)

def _gpu_wait_text(gp, waiting, st):
    """Why a request waits for a GPU, for its advice (02 §6.5.1)."""
    cards = st.get("gpu") if isinstance(st.get("gpu"), dict) else {}
    g, v = gp["gpu"], gp["vram"]
    if gp["nvidia"] and not any("gb" in c for c in cards.values()):
        return "the cards could not be read (nvidia-smi did not answer): nothing new is granted on them until they can"
    mine = [cards[gp["key"]]] if gp["key"] in cards else [] if gp["key"] else list(cards.values())
    where = "on the GPU" if not gp["nvidia"] else "on %s" % _gpu_label(mine[0]) if gp["key"] and mine else "on a card"
    if gp["key"] and not mine:
        return "the card it named (%s) is not listed now" % term_text(gp["key"])[:16]
    if v and gp["nvidia"] and any("vram:" in p for p in waiting):
        most = max([c.get("gb", 0.0) for c in mine] or [0.0])
        if most < v["ask"]:
            return "you asked for %s GB of GPU memory, and %s GB can be reserved %s now" % (
                _gpu_gb(v["ask"]), _gpu_gb(max(0.0, most)), where)
    if v and not gp["nvidia"] and any(p.startswith("vram:") for p in waiting):
        return ("you asked for %s GB of GPU memory, and with what other reservations hold for the GPU that is more than "
                "it may use of this Mac's memory (iogpu.wired_limit_mb)" % _gpu_gb(v["ask"]))
    if g and any(p.startswith("gpu:") for p in waiting):
        most = max([c.get("pct", 0.0) for c in mine] or [0.0])
        if most < g["ask"]:
            return "you asked for %s %% of a GPU, and other reservations leave %s %% %s" % (
                cores_text(g["ask"]), cores_text(max(0.0, most)), where)
    return "an earlier request waits for the GPU"

def _unified_gb(r):
    """The GB of a Mac's GPU memory in a lease's gb (02 §6.2: unified memory is memory), else 0."""
    gp = _gpu_parts(r)
    v = gp["vram"] if gp and not gp["nvidia"] else None
    return (v["got"] if r["state"] == "granted" and _num(v.get("got")) else v["ask"]) if v else 0.0

def _amend_gpu(L, r, k, amount, s=None):
    """amend's share of a GPU (k "gpu", %) or GPU memory (k "vram", GB) (02 §6.4, §6.5.1): (change, refusal). It
    stays on its card. Shrinking applies at once; growing a grant only if the extra can be reserved on its card now
    and nobody is queued for it; a bigger queued request goes to the back of the line, unless no card could ever
    hold it (the sample `s` tells: refused as a new request would be); 0 drops it. A Mac's GPU memory is memory: the
    gb follows it, and growing it needs the memory and, with an exact working-set limit, room under it."""
    gp = _gpu_parts(r) or None
    x = gp[k] if gp else None
    word, flag = ("a share of a GPU", "--gpu %s" % cores_text(amount)) if k == "gpu" else \
        ("GPU memory", "--gpu-mem %sG" % _gpu_gb(amount))
    if x is None:
        return (None, "%s holds no %s, and it cannot take some now: reserve it separately (`oomph reserve %s --for "
                      "\"…\"`)." % (r["id"], word, flag)) if amount else (None, None)
    if amount and not (0.1 <= amount <= GPU_PCT_MAX if k == "gpu" else VRAM_MIN_GB <= amount <= VRAM_MAX_GB):
        return None, "Can't make %s's %s %s: ask for %s, or 0 to drop it." % (
            r["id"], word, flag.split(" ", 1)[1], "0.1 to 100 (%)" if k == "gpu" else "0.01 GB or more")
    was = x["got"] if r["state"] == "granted" and _num(x.get("got")) else x["ask"]
    unified = k == "vram" and not gp["nvidia"]
    other = gp["vram" if k == "gpu" else "gpu"]
    if amount == 0:
        if not ("ram" in r["res"] or _cpu_of(r) or _disk_of(r) or other):
            return None, "%s holds nothing but %s: release it instead (release_memory / `oomph release %s`)." % (
                r["id"], word, r["id"])
        del r["res"][k]
    else:
        if r["state"] == "granted" and amount > was:
            st = L.get("state", {})
            if gp["nvidia"] and not gp["key"]:  # its card's UUID was dropped as malformed: nowhere to grow
                return None, "Can't grow %s's %s now: the card it was granted on is not known. Keep it, or reserve " \
                             "the extra separately (`oomph reserve --for \"…\"`)." % (r["id"], word)
            if unified:
                room, pool = st.get("available_gb"), "ram"
                c = (gpu_cards_of(s) or {}).get(gp["key"]) if s else None
                lim = c.get("limit") if c and not c.get("limit_est") else None
                if lim and _num(room):  # and what the GPU may still wire, with the other grants' GPU memory
                    held = sum(_unified_gb(q) for q in L["leases"] if q is not r and q["state"] == "granted")
                    room = min(room, lim - held - was)
            else:
                room = ((st.get("gpu") or {}).get(gp["key"]) or {}).get("pct" if k == "gpu" else "gb")
                pool = ("gpu:" if k == "gpu" else "vram:") + gp["key"]
            room = room if _num(room) else 0.0
            waiting = [q for q in L["leases"] if q["state"] == "queued" and (not weighable(q) or any(
                p == pool or p == pool.split(":")[0] + ":*" for p in lease_need(q)))]
            if waiting or amount - was > room + 1e-9 or (unified and st.get("level") == "critical"):
                extra = "--gpu %s" % cores_text(round(amount - was, 1)) if k == "gpu" else "--gpu-mem %sG" % _gpu_gb(amount - was)
                return None, ("Can't grow %s's %s from %s to %s%s now: %s. Keep it, and reserve the extra separately "
                              "(`oomph reserve %s --for \"…\"`): it queues fairly." % (
                                  r["id"], word, _gpu_amount(k, was), _gpu_amount(k, amount),
                                  "" if unified else " on %s" % _gpu_label(x),
                                  "%d request(s) for it are queued and come first" % len(waiting) if waiting else
                                  "memory is critical" if unified and st.get("level") == "critical" else
                                  "only %s more can be reserved" % _gpu_amount(k, max(0.0, room)), extra))
        if k == "vram" and r["state"] == "queued" and amount > was:
            why = _vram_cap_refusal(s, gp, amount)
            if why:
                return None, why
        x["ask"] = amount
        if r["state"] == "granted":
            x["got"] = amount
        elif amount > was:  # a bigger request takes a new place in line
            L["leases"].remove(r)
            L["leases"].append(r)
    if unified:  # the gb mirror carries a Mac's GPU memory
        r["gb"] = round(max(NO_MEM_GB, r["gb"] + amount - was), 2)
        if "mem" in r["res"] or r["gb"] > NO_MEM_GB:
            r["res"]["mem"] = dict(r["res"].get("mem") or {}, got=r["gb"])
    return [was, amount], None

def _gpu_amount(k, x):
    return "%s %%" % cores_text(round(x, 1)) if k == "gpu" else "%s GB" % _gpu_gb(x)

def _gpu_rec_text(h, short=False):
    """A finished reservation's GPU parts in words (its record's `res` amounts, 02 §6.2): "16G of GPU memory on
    gpu1, 60 % of the GPU"; `short`: "16Gv 60%g". Empty without one."""
    res = h.get("res") if isinstance(h.get("res"), dict) else {}
    v, g = res.get("vram"), res.get("gpu")
    if short:
        return " ".join(x for x in ("%sGv" % _gpu_gb(v) if _num(v) else "", "%s%%g" % cores_text(g) if _num(g) else "") if x)
    dev = res.get("gpu_dev") if isinstance(res.get("gpu_dev"), str) else ""
    on = " on %s" % dev[:12] if dev.startswith("GPU-") else ""  # an NVIDIA card, by its UUID's prefix
    return ", ".join(x for x in ("%sG of GPU memory%s" % (_gpu_gb(v), on) if _num(v) else "",
                                 "%s %% of the GPU" % cores_text(g) if _num(g) else "") if x)

def _gpu_reservable(card, on, left):
    """A GPU's `reservable` for `oomph resources --json` (02 §6.5.1): false while gpu_reservations is off
    (`reservable_off`: the switch), or with the reason it cannot be; else true, with what is left to reserve."""
    if card is None:
        return {"reservable": False}
    if not card["reservable"]:
        return {"reservable": False, "why": card["why"]}
    if not on:
        return {"reservable": False, "reservable_off": "gpu_reservations"}
    out = {"reservable": True, "key": card["key"]}
    if card["nvidia"]:
        out.update(cap_gb=round(card["cap"], 2), margin_gb=round(card["margin"], 2))
    if not isinstance(left, dict):  # nothing reserved on any GPU: the whole of it
        left = dict({"pct": float(GPU_PCT_MAX)}, **({"gb": round(card["free"] - card["margin"], 2)} if card["nvidia"]
                                                    else {}))
    out.update(left_pct=left.get("pct"), **({"left_gb": left["gb"]} if "gb" in left else {}))
    return out

def gpu_pin_changes(st, env):
    """What --pin-gpu changes of an inherited environment: [(name, was, now)] where a value was set and differs."""
    g = (st.get("run_with") or {}).get("gpu") or {}
    new = g.get("env") if isinstance(g.get("env"), dict) else {}
    return [(k, env[k], str(v)) for k, v in sorted(new.items()) if k in env and env[k] != str(v)]


def _gpu_flag_text(r, f):
    """The words for a holder about its GPU memory's `over` or `elsewhere` (flag_advice), a sentence and a space."""
    v = (_gpu_parts(r) or {}).get("vram") or {}
    if f == "over" and _num(v.get("got")):
        return ("Your job uses %s GB on %s, more than the %s GB granted: grow it (`oomph amend %s --gpu-mem NG`) or "
                "load less. " % (_gpu_gb(v["else_gb"]) if _num(v.get("else_gb")) else "more", _gpu_label(v),
                                 _gpu_gb(v["got"]), r["id"]))
    if f == "elsewhere" and _num(v.get("got")):
        return "Your job uses %s GB on %s; it was granted %s: run it with %s, or `oomph run --pin-gpu`. " % (
            _gpu_gb(v["else_gb"]) if _num(v.get("else_gb")) else "memory", _gpu_label({"dev": v.get("else_dev")}),
            _gpu_label(v), _cuda_env_text(v))
    return ""


def _gpu_env(g, out, pin):
    """run_env's GPU part: OOMPH_GPU_INDEX, OOMPH_GPU_UUID, OOMPH_GPU_MEM_GB, and with `pin` the card's CUDA_* (02 §6.5.1)."""
    if not _int(g.get("index"), 0, 999):
        return
    out["OOMPH_GPU_INDEX"] = str(g["index"])
    if isinstance(g.get("uuid"), str) and _GPU_UUID.fullmatch(g["uuid"]):
        out["OOMPH_GPU_UUID"] = g["uuid"]
    if _num(g.get("mem_gb"), 0.001, VRAM_MAX_GB):
        out["OOMPH_GPU_MEM_GB"] = "%g" % g["mem_gb"]
    if pin and isinstance(g.get("env"), dict):
        out.update((k, str(v)) for k, v in g["env"].items() if k in ("CUDA_DEVICE_ORDER", "CUDA_VISIBLE_DEVICES"))


def _gpu_run_note(st, pin):
    """What `oomph run` says on stderr about a GPU grant: where the job may run, and what --pin-gpu changed."""
    g = st["run_with"]["gpu"]
    where = "GPU %d, %s (%s)" % (g["index"], term_text(g.get("name") or "")[:64], g["uuid"][:12]) if g.get("uuid") \
        else "the GPU"
    if pin and not g.get("env"):
        sys.stderr.write("oomph: --pin-gpu sets nothing on a Mac: it has one GPU, and its memory is the Mac's\n")
    elif pin:
        for k, was, now in gpu_pin_changes(st, os.environ):
            sys.stderr.write("oomph: --pin-gpu replaces %s=%s with %s\n" % (k, term_text(was)[:40], now))
        sys.stderr.write("oomph: running on %s (CUDA_VISIBLE_DEVICES=%d)\n" % (where, g["index"]))
    elif g.get("env"):
        sys.stderr.write("oomph: granted %s; the job is not pinned (--pin-gpu, or CUDA_VISIBLE_DEVICES=%d)\n"
                         % (where, g["index"]))


def _gpu_brief_text(b):
    """A reservation row's GPU part (_fmt_brief): "16G (5.0G used) + 60 % on gpu1, "."""
    dev = b["gpu_dev"] if isinstance(b.get("gpu_dev"), str) and _GPU_DEV.fullmatch(b["gpu_dev"]) else "gpu"
    return "%s%s on %s, " % (
        "%sG%s" % (_gb(b["vram"]), " (%sG used)" % _gb(b["vram_used"]) if _num(b.get("vram_used")) else "")
        if _num(b.get("vram")) else "", ("%s%s %%" % (" + " if _num(b.get("vram")) else "", cores_text(b["gpu"])))
        if _num(b.get("gpu")) else "", dev)


def _gpu_mcp_args(name, a):
    """The MCP tools' GPU arguments (_mcp_args): a share 0.1 to 100, at least VRAM_MIN_GB, a card only with an amount."""
    if a.get("gpu_pct") is not None and (a["gpu_pct"] > GPU_PCT_MAX or (a["gpu_pct"] and round(a["gpu_pct"], 1) < 0.1)):
        raise ToolArgError("%s: gpu_pct takes a share of one GPU, 0.1 to 100 (%%), not %r" % (name, a["gpu_pct"]))
    if a.get("gpu_mem_gb") and round(float(a["gpu_mem_gb"]), 2) < VRAM_MIN_GB:
        raise ToolArgError("%s: gpu_mem_gb takes at least %g (GB), not %r" % (name, VRAM_MIN_GB, a["gpu_mem_gb"]))
    if a.get("gpu_device") is not None and not (isinstance(a["gpu_device"], str) and 0 < len(a["gpu_device"]) <= 64
                                                and (a.get("gpu_pct") or a.get("gpu_mem_gb"))):
        raise ToolArgError("%s: gpu_device names a card (an index or a UUID prefix), and comes with gpu_pct or "
                           "gpu_mem_gb" % name)


def _gpu_line(g):
    """The tail of a GPU's line in `oomph resources`: off (the switch), why not, or what is reserved and left."""
    if g.get("reservable_off"):
        return " · reservable: off (gpu_reservations)"
    if g.get("why"):
        return " · not reservable (%s)" % g["why"]
    if not g.get("reservable"):
        return " · not reservable"
    return " · %s %% reserved%s · reservable" % (cores_text(round(100 - max(0.0, g.get("left_pct", 100)), 1)),
                                                ", %s GB left to reserve" % _gb(max(0.0, g["left_gb"]))
                                                if "left_gb" in g else "")


def _gpu_opts(o, zero=False):
    """--gpu's share and --gpu-mem's GB, and the card either names: (share, GB, card), each None when not given;
    UsageError when one is not a share or an amount, or the two name different cards (one card per reservation)."""
    try:
        gpu, c1 = _G().parse_gpu(o["--gpu"], zero) if "--gpu" in o else (None, None)
        vram, c2 = _G().parse_gpu_mem(o["--gpu-mem"], zero) if "--gpu-mem" in o else (None, None)
    except ValueError as e:
        raise UsageError(str(e))
    if c1 and c2 and c1 != c2:
        raise UsageError("--gpu @%s and --gpu-mem @%s: one reservation is on one card (make two for two cards)" % (c1, c2))
    return gpu, vram, c1 or c2


def _gpu_off(o, as_json):
    """A command with a GPU flag while gpu_reservations is off (02 §6.5.1): refused before anything is written, exit 75."""
    st = {"status": "refused", "advice": _G().gpu_switch_text(), "switch": "gpu_reservations"}
    print(json.dumps(st) if as_json else _G().gpu_switch_text("oomph: REFUSED — "))
    return 75


def _gpu_asked(card, gpu, vram):
    """A new request's GPU parts (02 §6.5.1): its share and memory, on `card` (the one it named, an NVIDIA card by its
    UUID; a Mac's gpu0) or, an NVIDIA request that named none, on none yet (`unified` false says it is discrete)."""
    nv = card is None or card["nvidia"]
    where = {} if card is None else dict({"dev": card["id"]}, **({"uuid": card["key"], "name": card["name"]} if nv else {}))
    out = {}
    if gpu is not None:
        out["gpu"] = dict({"ask": gpu}, **where, **({"unified": False} if nv else {}))
    if vram is not None:
        out["vram"] = dict({"ask": vram}, **where, unified=not nv)
    return out


def _gpu_grows(r, gp, gpu, vram):
    """Would an amend add a GPU part to lease `r` or grow one (what the switch, off, refuses)?"""
    return any(a and (not gp or not gp[k] or a > (gp[k]["got"] if r["state"] == "granted" and _num(gp[k].get("got"))
                                                 else gp[k]["ask"])) for k, a in (("gpu", gpu), ("vram", vram)))
