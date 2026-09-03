#!/usr/bin/env python3
"""trap_jump2.py — parche de trampa + hwb de diagnostico en 0x403E70.

Tras parchear la trampa (0x403E70=NOP, 0x403E71=jmp 0x403ED3, NOPs al resto),
el run anterior murio re-cayendo en 0x403E70. Preguntas:
  A) llega codigo a 0x403E70?        -> DR1 EXEC: quien salta ahi (eip=0x403E70)
  B) alguien REESCRIBE el CC?        -> DR0 WRITE: quien escribe (eip=escritor)
Con la pausa se inspecciona: mem[0x403E70] (CC? 90?), esp/retaddr, eip, disasm.

Uso: python3 trap_jump2.py
"""
import subprocess, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}

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

def is_loader(addr):
    return bool(addr) and (addr >> 28) == 0x7

print("estado:", call("status").get("state"))
print("restart:", json.dumps(call("restart")))

t0 = time.time()
patched = False
armed = False
trap_hits = 0
deadline = time.time() + 60
while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED" % el)
        ev = call("poll_events", {"since": 0})
        for e in (ev.get("events") or [])[-10:]:
            print("   ", e)
        break
    if s == "paused":
        r = (call("get_regs").get("regs") or {})
        e = r.get("eip")
        if is_loader(e) and not patched:
            print("[%5.2fs] loader pause %s -> go" % (el, fmt(e)))
            call("go")
            time.sleep(0.2)
            continue
        if not patched and 0x403E60 <= (e or 0) <= 0x403EF0:
            print("[%5.2fs] TRAMPA: eip=%s esp=%s -> parcheo" % (el, fmt(e), fmt(r.get("esp"))))
            blob = bytes([0x90, 0xE9, 0x5D, 0x00, 0x00, 0x00]) + b"\x90" * (0x403ED3 - 0x403E71 - 6 + 1)
            w = call("write_mem", {"addr": "0x403E70", "hex": blob.hex()})
            print("  write_mem len=%d -> %s" % (len(blob), json.dumps(w)))
            v = call("read_mem", {"addr": "0x403E70", "len": 16})
            print("  post-parche:", (v.get("hex") or "")[:32])
            # DR0 write, DR1 exec en 0x403E70
            print("  set_hwbp write:", json.dumps(call("set_hwbp", {"addr": "0x403E70", "type": 1, "len": 1})))
            print("  set_hwbp exec :", json.dumps(call("set_hwbp", {"addr": "0x403E70", "type": 0, "len": 1})))
            patched = True
            print("  -> go")
            call("go")
            time.sleep(0.2)
            continue
        if patched:
            trap_hits += 1
            print("[%5.2fs] HIT#%d: eip=%s esp=%s" % (el, trap_hits, fmt(e), fmt(r.get("esp"))))
            d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
            print("  mem[0x403E70..] =", (d.get("hex") or "")[:64])
            # pila: 4 dwords por encima de esp
            stk = call("read_mem", {"addr": "0x%08x" % (r.get("esp") or 0), "len": 16})
            print("  [esp..] =", (stk.get("hex") or ""))
            dd = call("disasm", {"addr": "0x%08x" % ((e or 0x403E70) - 16), "count": 8})
            for a in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
            if trap_hits >= 4:
                print("  (4 hits -> paro)")
                break
            # continuar y ver siguiente
            call("go")
            time.sleep(0.2)
            continue
    if s == "running":
        el2 = time.time() - t0
        if patched and el2 > 8:
            print("[%5.2fs] RUNNING estable -> pause" % el2)
            print("  pause:", json.dumps(call("pause")))
            time.sleep(0.4)
            r = (call("get_regs").get("regs") or {})
            e = r.get("eip")
            print("  eip=%s esp=%s" % (fmt(e), fmt(r.get("esp"))))
            d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
            print("  mem[0x403E70..] =", (d.get("hex") or "")[:64])
            dd = call("disasm", {"addr": "0x%08x" % ((e or 0) - 8), "count": 10})
            for a in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
            break
    time.sleep(0.05)

print("--- limpieza ---")
print("del hwbp:", json.dumps(call("del_hwbp", {"addr": "0x403E70"})))
ev = call("poll_events", {"since": 0})
print("--- eventos (ultimos 10) ---")
for x in (ev.get("events") or [])[-10:]:
    print("   ", x)
