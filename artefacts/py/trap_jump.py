#!/usr/bin/env python3
"""trap_jump.py — EXPERIMENTO: parche en memoria sobre la trampa int3.

Tras restart limpio (sin bps), el proceso cae pausado en 0x403E71 (int3 de
0x403E70 = camino licencia-no-valida). Parche: saltar la zona CC hacia el
codigo intacto en 0x403ED3 y continuar, para ver si la app arranca bajo
debugger sin la restauracion de AppKeyX.

  eip=0x403E70 -> E9 5E 00 00 00 (jmp 0x403ED3) + NOPs hasta 0x403ED2
  eip=0x403E71 -> E9 5D 00 00 00 (jmp 0x403ED3) + NOPs hasta 0x403ED2

Uso: python3 trap_jump.py   (write_mem => requiere permiso Modificacion, OK)
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

def is_trap(addr):
    return bool(addr) and 0x403E60 <= addr <= 0x403EF0

print("estado inicial:", call("status").get("state"))
print("restart:", json.dumps(call("restart")))

t0 = time.time()
patched = False
deadline = time.time() + 45
while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    rip = st.get("rip")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED (antes de llegar a la trampa)" % el)
        ev = call("poll_events", {"since": 0})
        for e in (ev.get("events") or [])[-6:]:
            print("   ", e)
        break
    if s == "paused":
        r = (call("get_regs").get("regs") or {})
        e = r.get("eip")
        if is_loader(e):
            print("[%5.2fs] loader pause %s -> go" % (el, fmt(e)))
            call("go")
            time.sleep(0.2)
            continue
        if is_trap(e) and not patched:
            print("[%5.2fs] TRAMPA: eip=%s esp=%s (int3 en 0x403E70)" % (el, fmt(e), fmt(r.get("esp"))))
            d = call("read_mem", {"addr": "0x403E70", "len": 0x80})
            print("  mem pre-parche[0x403E70..] =", (d.get("hex") or "")[:160])
            # construir parche
            if e == 0x403E70:
                blob = bytes([0xE9, 0x5E, 0x00, 0x00, 0x00]) + b"\x90" * (0x403ED3 - 0x403E70 - 5)
                patcha = "0x403E70"
            else:
                # resume en 0x403E71: 0x403E70 = NOP (protege reentradas), 0x403E71 = jmp 0x403ED3
                blob = bytes([0x90, 0xE9, 0x5D, 0x00, 0x00, 0x00]) + b"\x90" * (0x403ED3 - 0x403E71 - 6 + 1)
                patcha = "0x403E70"
            hx = blob.hex()
            w = call("write_mem", {"addr": patcha, "hex": hx})
            print("  write_mem %s len=%d -> %s" % (patcha, len(blob), json.dumps(w)))
            v = call("read_mem", {"addr": "0x403E70", "len": 0x80})
            print("  mem post-parche[0x403E70..] =", (v.get("hex") or "")[:160])
            patched = True
            print("  -> go (continuar tras la trampa parcheada)")
            call("go")
            time.sleep(0.2)
            continue
        if patched:
            print("[%5.2fs] PAUSADO tras parche: eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))))
            dd = call("disasm", {"addr": "0x%08x" % (e - 8 if e else 0x403E70), "count": 10})
            for a in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
            break
    if s == "running":
        el2 = time.time() - t0
        if patched and el2 > 5:
            print("[%5.2fs] RUNNING estable tras parche -> pause para inspeccionar" % el2)
            print("  pause:", json.dumps(call("pause")))
            time.sleep(0.4)
            r = (call("get_regs").get("regs") or {})
            e = r.get("eip")
            print("  eip=%s esp=%s" % (fmt(e), fmt(r.get("esp"))))
            d = call("read_mem", {"addr": "0x403E70", "len": 0x80})
            print("  mem[0x403E70..] =", (d.get("hex") or "")[:160])
            dd = call("disasm", {"addr": "0x%08x" % (e - 4 if e else 0x403ED3), "count": 12})
            for a in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
            break
        if not patched and el2 > 3 and is_trap is False:
            pass
    time.sleep(0.05)
else:
    print("deadline 45s; estado:", call("status").get("state"))

if patched:
    ev = call("poll_events", {"since": 0})
    print("--- ultimos eventos ---")
    for e in (ev.get("events") or [])[-10:]:
        print("   ", e)
