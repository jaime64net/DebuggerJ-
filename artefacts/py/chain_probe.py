#!/usr/bin/env python3
"""chain_probe.py v2 — sondas dinamicas en la cadena AppKeyX (RVA correcto).

Fix v1: los sites del modelo ak1561c (0x157D0, 0x15348, ...) son RVAs ->
abs = base_appkey + rva (NO base + rva - 0x400000). log_only booleano.
Discriminacion de instancia viva: entre los candidatos AppKeyX del listado
modules (que acumula procesos muertos), el valido es el que devuelve codigo
real (no vacio/ceros) al leer base + 0x1561C.

Uso: python3 chain_probe.py
"""
import subprocess, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
PROBES = [
    ("poll_loop",      0x157D0, "log"),
    ("isdbg_site",     0x15810, "log"),
    ("ok_cont_entry",  0x15348, "hit"),
    ("ok_cont2",       0x1519C, "hit"),
    ("virt_14EE8",     0x14EE8, "hit"),
    ("mid_14DB4",      0x14DB4, "hit"),
    ("leaf_14D60",     0x14D60, "hit"),
    ("err_loop",       0x157F8, "hit"),
    ("ord1_ret",       0x15846, "hit"),
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
    """Entre los bases AppKeyX del listado, devuelve el que tiene codigo real
    en base+0x1561C (instancia del proceso actual vivo)."""
    mods = call("modules").get("modules") or []
    cands = appkey_bases(mods)
    for b in cands:
        hx = rdmem(b + 0x1561C, 12)
        if len(hx) >= 8 and hx not in ("00" * 12, "ff" * 12) and hx != "?":
            # evitar lecturas vacias de modulos muertos
            return b, hx
    return None, None

print("estado:", call("status").get("state"), flush=True)
print("restart:", json.dumps(call("restart")), flush=True)

base_appkey = None
armed = []
t0 = time.time()
deadline = time.time() + 120
hits = {name: 0 for name, _, _ in PROBES}
n_pauses = 0
scanned = 0

while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED" % el, flush=True)
        ev = call("poll_events", {"since": 0})
        for e in (ev.get("events") or [])[-14:]:
            print("   ", e, flush=True)
        break
    if s == "running":
        if el > 12:
            print("[%5.2fs] RUNNING estable -> pause (posible licencia OK)" % el, flush=True)
            call("pause")
            time.sleep(0.5)
            r = (call("get_regs").get("regs") or {})
            e = r.get("eip")
            print("  eip=%s esp=%s" % (fmt(e), fmt(r.get("esp"))), flush=True)
            d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
            print("  mem[0x403E70..] =", (d.get("hex") or "")[:64], flush=True)
            dd = call("disasm", {"addr": "0x403E70", "count": 8})
            for i in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(i.get("addr")), i.get("text")), flush=True)
            break
        time.sleep(0.2)
        continue
    if s != "paused":
        time.sleep(0.05)
        continue

    r = (call("get_regs").get("regs") or {})
    e = r.get("eip") or 0

    if base_appkey is None:
        scanned += 1
        base_appkey, probe_hex = find_live_base()
        if base_appkey is None:
            if (e >> 28) == 0x7:
                print("[%5.2fs] loader pause %s (AppKeyX aun no vivo) -> go" % (el, fmt(e)), flush=True)
                call("go")
                time.sleep(0.25)
            else:
                print("[%5.2fs] pausa inesperada pre-armado eip=%s -> go" % (el, fmt(e)), flush=True)
                call("go")
                time.sleep(0.2)
            continue
        print("[%5.2fs] AppKeyX vivo base=%s (scan#%d) bytes@+0x1561C=%s" %
              (el, fmt(base_appkey), scanned, probe_hex[:24]), flush=True)
        for name, rva, mode in PROBES:
            a = base_appkey + rva
            v = rdmem(a, 6)
            args = {"addr": "0x%08x" % a, "break_on_hit": 1}
            if mode == "log":
                args = {"addr": "0x%08x" % a, "log_only": True}
            res = call("set_bp", args)
            ok = res.get("ok")
            print("   set_bp %-14s @0x%08x (bytes=%s) -> %s" % (name, a, v[:12], "ok" if ok else json.dumps(res)), flush=True)
            if ok:
                armed.append((name, a))
        print("   -> go", flush=True)
        call("go")
        time.sleep(0.25)
        continue

    hit = None
    for name, a in armed:
        if e == a:
            hit = (name, a)
            break
    if hit:
        name, a = hit
        hits[name] += 1
        n_pauses += 1
        print("[%5.2fs] *** SONDA %-14s hit#%d eip=%s esp=%s eax=%s ebx=%s ecx=%s edx=%s esi=%s edi=%s" %
              (el, name, hits[name], fmt(e), fmt(r.get("esp")), fmt(r.get("eax")),
               fmt(r.get("ebx")), fmt(r.get("ecx")), fmt(r.get("edx")),
               fmt(r.get("esi")), fmt(r.get("edi"))), flush=True)
        stk = call("read_mem", {"addr": "0x%08x" % (r.get("esp") or 0), "len": 16})
        print("   [esp..] =", (stk.get("hex") or ""), flush=True)
        if n_pauses >= 15:
            print("  (15 pausas de sonda -> quito sondas y sigo al destino natural)", flush=True)
            for nm, ad in armed:
                call("del_bp", {"addr": "0x%08x" % ad})
            armed = []
        call("go")
        time.sleep(0.15)
        continue

    if 0x403E60 <= e <= 0x403EF0:
        print("[%5.2fs] *** TRAMPA 0x403E70: eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))), flush=True)
        d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
        print("  mem[0x403E70..] =", (d.get("hex") or "")[:64], flush=True)
        break
    if (e >> 28) == 0x7:
        print("[%5.2fs] loader pause %s -> go" % (el, fmt(e)), flush=True)
        call("go")
        time.sleep(0.25)
        continue
    print("[%5.2fs] pausa inesperada eip=%s esp=%s -> go" % (el, fmt(e), fmt(r.get("esp"))), flush=True)
    call("go")
    time.sleep(0.15)

print("--- resumen hits ---", flush=True)
for k, v in hits.items():
    if v:
        print("  %-14s %d" % (k, v), flush=True)
print("--- limpieza ---", flush=True)
for nm, ad in armed:
    call("del_bp", {"addr": "0x%08x" % ad})
print("list_bp:", json.dumps(call("list_bp")), flush=True)
ev = call("poll_events", {"since": 0})
print("--- eventos (ultimos 14) ---", flush=True)
for x in (ev.get("events") or [])[-14:]:
    print("   ", x, flush=True)
