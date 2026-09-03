#!/usr/bin/env python3
"""leafwatch.py [--noleaf] — caza del escritor de los 99 B (DR0 WRITE @0x403E70).
  --noleaf: sin bp software en leaf_14D60 (control limpio: solo DR0 + poll log).

Preguntas:
 A) ¿alguien RESTAURA los 99 B durante el regimen B? -> DR0 write hwbp en 0x403E70
    (si salta: eip=escritor real)
 B) ¿qué hay en 0x403E70 cuando se ejecuta leaf_14D60 (0x14D60)? CC o codigo real
 C) estado del manager [0x45FFF4] (obj AppKeyX: abs = base+0x5FFF4) en el leaf
 D) ¿sigue el flujo al trap 0x403E70 o el proceso sale distinto (255)?

Uso: python3 leafwatch.py
"""
import subprocess, json, time, sys

NOLEAF = "--noleaf" in sys.argv

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
RVA_LEAF = 0x14D60
RVA_POLL = 0x157D0
RVA_MGR = 0x5FFF4   # VA 0x45FFF4 -> RVA

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

base = None
dr0_armed = False
leaf_addr = None
t0 = time.time()
deadline = time.time() + 90
leaf_hits = 0
dr0_hits = 0

while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED" % el, flush=True)
        break
    if s == "running":
        if el > 20:
            print("[%5.2fs] RUNNING estable -> pause" % el, flush=True)
            call("pause")
            time.sleep(0.4)
            r = (call("get_regs").get("regs") or {})
            print("  eip=%s esp=%s" % (fmt(r.get("eip")), fmt(r.get("esp"))), flush=True)
            print("  mem[0x403E70..] =", (rdmem(0x403E70, 0x40))[:96], flush=True)
        time.sleep(0.25)
        continue
    if s != "paused":
        time.sleep(0.05)
        continue

    r = (call("get_regs").get("regs") or {})
    e = r.get("eip") or 0

    if base is None:
        base = find_live_base()
        if base is None:
            if (e >> 28) == 0x7:
                print("[%5.2fs] loader pause %s (sin AppKeyX) -> go" % (el, fmt(e)), flush=True)
                call("go")
                time.sleep(0.2)
            else:
                call("go")
                time.sleep(0.2)
            continue
        print("[%5.2fs] AppKeyX vivo base=%s" % (el, fmt(base)), flush=True)
        # DR0 WRITE sobre 0x403E70 (el byte 0 del bloque de 99)
        print("  set_hwbp DR0 write 0x403E70:", json.dumps(call("set_hwbp", {"addr": "0x403E70", "type": 1, "len": 1})), flush=True)
        leaf_addr = base + RVA_LEAF
        if not NOLEAF:
            print("  set_bp leaf log:", json.dumps(call("set_bp", {"addr": "0x%08x" % leaf_addr, "log_only": True})), flush=True)
        else:
            print("  (--noleaf: sin bp en leaf_14D60)", flush=True)
        print("  set_bp poll log:", json.dumps(call("set_bp", {"addr": "0x%08x" % (base + RVA_POLL), "log_only": True})), flush=True)
        dr0_armed = True
        print("   -> go", flush=True)
        call("go")
        time.sleep(0.25)
        continue

    # pausa por leaf (int3 -> eip = leaf+1)
    if (not NOLEAF) and leaf_addr and e == leaf_addr + 1:
        leaf_hits += 1
        print("[%5.2fs] *** LEAF 0x14D60 hit#%d eip=%s esp=%s eax=%s ebx=%s ecx=%s edx=%s esi=%s edi=%s" %
              (el, leaf_hits, fmt(e), fmt(r.get("esp")), fmt(r.get("eax")), fmt(r.get("ebx")),
               fmt(r.get("ecx")), fmt(r.get("edx")), fmt(r.get("esi")), fmt(r.get("edi"))), flush=True)
        print("  mem[0x403E70..0x403EAF] =", rdmem(0x403E70, 0x40), flush=True)
        mgr = rdmem(base + RVA_MGR, 0x20)
        print("  mem[0x45FFF4](mgr)       =", mgr, flush=True)
        stk = call("read_mem", {"addr": "0x%08x" % (r.get("esp") or 0), "len": 24})
        print("  [esp..] =", (stk.get("hex") or ""), flush=True)
        call("go")
        time.sleep(0.15)
        continue

    # pausa por DR0 write (eip = instruccion posterior al write)
    if dr0_armed and not (0x403E60 <= e <= 0x403EF0):
        # distinguir: si es el trap normal (int3 0x403E71) lo manejamos abajo
        pass
    if 0x403E60 <= e <= 0x403EF0:
        print("[%5.2fs] *** TRAMPA 0x403E70: eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))), flush=True)
        print("  mem[0x403E70..0x403EAF] =", rdmem(0x403E70, 0x40), flush=True)
        d = call("disasm", {"addr": "0x403E70", "count": 8})
        for i in (d.get("insns") or []):
            print("    %s: %s" % (fmt(i.get("addr")), i.get("text")), flush=True)
        break
    # posible pausa DR0: eip no es leaf+1 ni trap: comprobar hwbp list
    hw = call("list_hwbp")
    if dr0_armed:
        # el server pausa en el write: eip apunta DESPUES del mov. Ver si 0x403E70 cambio:
        cur = rdmem(0x403E70, 8)
        if cur and cur[:2] != "cc":
            dr0_hits += 1
            print("[%5.2fs] *** ?WRITE en 0x403E70: eip=%s esp=%s nuevos bytes=%s" % (el, fmt(e), fmt(r.get("esp")), cur[:16]), flush=True)
            call("go")
            time.sleep(0.15)
            continue
    if (e >> 28) == 0x7:
        print("[%5.2fs] loader pause %s -> go" % (el, fmt(e)), flush=True)
        call("go")
        time.sleep(0.2)
        continue
    print("[%5.2fs] pausa eip=%s esp=%s -> go" % (el, fmt(e), fmt(r.get("esp"))), flush=True)
    call("go")
    time.sleep(0.15)

print("--- resumen ---", flush=True)
print("leaf_hits=%d dr0_write_hits=%d" % (leaf_hits, dr0_hits), flush=True)
ev = call("poll_events", {"since": 0})
events = ev.get("events") or []
print("eventos totales:", len(events), flush=True)
for x in events[-18:]:
    print("   ", x, flush=True)
print("--- limpieza ---", flush=True)
print("del_hwbp:", json.dumps(call("del_hwbp", {"addr": "0x403E70"})), flush=True)
d = call("list_bp")
for b in (d.get("bps") or []):
    call("del_bp", {"addr": "0x%08x" % b.get("addr")})
print("ok", flush=True)
