#!/usr/bin/env python3
"""chain_log.py — run limpio con TODAS las sondas log_only (cero pausas).

Mantiene el timing natural del regimen B y registra en poll_events qué sites
de la cadena AppKeyX se ejecutan y cuantas veces. Deteccion de hits por
eventos 'breakpoint' con arg == addr del site.

Uso: python3 chain_log.py
"""
import subprocess, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
PROBES = [
    ("poll_loop",     0x157D0),
    ("isdbg_site",    0x15810),
    ("ok_cont_entry", 0x15348),
    ("ok_cont2",      0x1519C),
    ("virt_14EE8",    0x14EE8),
    ("mid_14DB4",     0x14DB4),
    ("leaf_14D60",    0x14D60),
    ("err_loop",      0x157F8),
    ("ord1_ret",      0x15846),
]

def call(cmd, args=None, tmo=25):
    argv = DBG + [cmd]
    if args is not None:
        argv.append(json.dumps(args))
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=tmo, env=ENV)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    out = p.stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return {"ok": False, "raw": (out or "")[:200]}

def fmt(a):
    return "0x%08x" % a if a is not None else "None"

def rdmem(addr, n=8):
    d = call("read_mem", {"addr": "0x%08x" % addr, "size": n})
    return d.get("hex", "") or ""

def appkey_bases(mods):
    return sorted({m["base"] for m in (mods or []) if m.get("name", "").lower().startswith("appkey")})

def find_live_base():
    mods = call("modules").get("modules") or []
    for b in appkey_bases(mods):
        hx = rdmem(b + 0x1561C, 12)
        if len(hx) >= 8 and hx != "00" * 12 and hx != "ff" * 12:
            return b
    return None

print("estado:", call("status").get("state"), flush=True)
print("restart:", json.dumps(call("restart")), flush=True)

base_appkey = None
site_addrs = {}
t0 = time.time()
deadline = time.time() + 90

while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED" % el, flush=True)
        break
    if s == "running":
        if el > 15:
            print("[%5.2fs] RUNNING estable -> pause" % el, flush=True)
            call("pause")
            time.sleep(0.4)
            r = (call("get_regs").get("regs") or {})
            print("  eip=%s esp=%s" % (fmt(r.get("eip")), fmt(r.get("esp"))), flush=True)
            d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
            print("  mem[0x403E70..] =", (d.get("hex") or "")[:64], flush=True)
        time.sleep(0.25)
        continue
    if s != "paused":
        time.sleep(0.05)
        continue

    r = (call("get_regs").get("regs") or {})
    e = r.get("eip") or 0

    if base_appkey is None:
        base_appkey = find_live_base()
        if base_appkey is None:
            if (e >> 28) == 0x7:
                print("[%5.2fs] loader pause %s (sin AppKeyX) -> go" % (el, fmt(e)), flush=True)
                call("go")
                time.sleep(0.2)
            else:
                call("go")
                time.sleep(0.2)
            continue
        print("[%5.2fs] AppKeyX vivo base=%s" % (el, fmt(base_appkey)), flush=True)
        for name, rva in PROBES:
            a = base_appkey + rva
            res = call("set_bp", {"addr": "0x%08x" % a, "log_only": True})
            if res.get("ok"):
                site_addrs[a] = name
                print("   log_bp %-14s @0x%08x" % (name, a), flush=True)
            else:
                print("   log_bp %-14s @0x%08x -> %s" % (name, a, json.dumps(res)), flush=True)
        print("   -> go", flush=True)
        call("go")
        time.sleep(0.25)
        continue

    if 0x403E60 <= e <= 0x403EF0:
        print("[%5.2fs] *** TRAMPA 0x403E70: eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))), flush=True)
        break
    if (e >> 28) == 0x7:
        print("[%5.2fs] loader pause %s -> go" % (el, fmt(e)), flush=True)
        call("go")
        time.sleep(0.2)
        continue
    print("[%5.2fs] pausa inesperada eip=%s esp=%s -> go" % (el, fmt(e), fmt(r.get("esp"))), flush=True)
    call("go")
    time.sleep(0.15)

print("--- conteo de hits por site (eventos breakpoint con arg=addr) ---", flush=True)
ev = call("poll_events", {"since": 0})
events = ev.get("events") or []
print("eventos totales:", len(events), flush=True)
cnt = {name: 0 for _, name, in [(0, n) for n in [x[0] for x in PROBES]]}
cnt = {name: 0 for name, _ in PROBES}
bp_others = {}
bp_hits = []
for x in events[-2000:]:
    if x.get("type") == "breakpoint":
        a = x.get("arg")
        if a in site_addrs:
            cnt[site_addrs[a]] += 1
        else:
            bp_others[a] = bp_others.get(a, 0) + 1
            bp_hits.append(a)
for name, _ in PROBES:
    if cnt[name]:
        print("  %-14s %d" % (name, cnt[name]), flush=True)
print("  otros breakpoints:", {("0x%08x" % k): v for k, v in bp_others.items()}, flush=True)
print("--- ultimos 25 eventos ---", flush=True)
for x in events[-25:]:
    print("   ", x, flush=True)
print("--- limpieza ---", flush=True)
d = call("list_bp")
for b in (d.get("bps") or []):
    call("del_bp", {"addr": "0x%08x" % b.get("addr")})
print("ok", flush=True)
