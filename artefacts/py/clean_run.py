#!/usr/bin/env python3
"""clean_run.py — lanza el target SIN NINGUN bp/hwb y observa.

Pregunta: el proceso muere por la mera presencia del debugger (DebugPort) o
solo por la instrumentacion (int3 en codigo / DR regs)? Si corre libre hasta
la UI, AppKeyX restaura el OEP: al pausarlo podremos leer los 0x70 bytes
originales en 0x403E70 (clave para el bypass sin AppKeyX).

Uso: python3 clean_run.py
"""
import subprocess, sys, json, time

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

def fmt(addr):
    return "0x%08x" % addr if addr is not None else "None"

# 1) limpiar instrumentacion
print("clean bps:", call("del_bp", {"addr": "0x54EC080"}))
for h in ("0x77C59D90", "0x77C14060", "0x7628B0B0", "0x76292E90"):
    call("del_hwbp", {"addr": h})
print("hwbp restantes:", json.dumps(call("list_hwbp")))

# 2) lanzar
print("restart:", json.dumps(call("restart")))
time.sleep(0.5)

# 3) go y observar
call("go")
t0 = time.time()
last = None
while time.time() - t0 < 30:
    st = call("status")
    s = st.get("state")
    if s != last:
        print("[%4.1fs] state=%s rip=%s" % (time.time() - t0, s, fmt(st.get("rip"))))
        last = s
    if s == "paused":
        # ver donde estamos y si el OEP se restauro
        r = (call("get_regs").get("regs") or {})
        print("  eip=", fmt(r.get("eip")), "esp=", fmt(r.get("esp")))
        d = call("read_mem", {"addr": "0x403E70", "len": 32})
        print("  mem[0x403E70] =", (d.get("hex") or ""))
        break
    if s == "exited":
        ev = call("poll_events", {"since": 0})
        evs = ev.get("events") or []
        print("  --- ultimos eventos ---")
        for e in evs[-6:]:
            print("   ", e)
        break
    time.sleep(0.5)
