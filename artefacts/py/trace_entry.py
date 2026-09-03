#!/usr/bin/env python3
"""Lanza (si hace falta) y traza paso a paso desde el entry 0x54EC080.
Uso: python3 trace_entry.py <nsteps>
El proceso debe estar abierto en el debugger (contabilidad_i.exe). Si no hay
proceso activo lo lanza. Se acerca al entry con 'go' y luego pisa sin pausas.
"""
import subprocess, sys, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
ENTRY = 0x54EC080
N = int(sys.argv[1]) if len(sys.argv) > 1 else 25

def call(cmd, args=None, tmo=45):
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
        return {"ok": False, "raw": out[:200]}

def eip_state():
    d = call("get_regs")
    if not d.get("ok"):
        return None, None
    r = d.get("regs") or {}
    return r.get("eip"), "paused"

def dis1(addr):
    d = call("disasm", {"addr": "0x%x" % addr, "count": 1})
    if d.get("insns"):
        return d["insns"][0].get("text", "")
    return "?"

# 1) Estado inicial
st = call("status")
state = st.get("state")
print("estado inicial:", state)
if state in ("exited", "idle", None):
    call("launch")
    time.sleep(3)

# 2) Acercarse al entry
for k in range(8):
    eip, _ = eip_state()
    stt = call("status").get("state")
    if eip == ENTRY:
        print(f"== ENTRY alcanzado (intento {k}) ==")
        break
    if stt == "paused":
        call("go")
    else:
        call("go")
    time.sleep(2.5)
else:
    print("No se alcanzo el entry; estado:", call("status").get("state"))
    sys.exit(1)

# 3) Trace por pasos (sin pausas entre llamadas)
for i in range(N):
    d = call("step_into")
    time.sleep(0.25)
    eip, _ = eip_state()
    if eip is None:
        s = call("status")
        print(f"[{i}] proceso no pausado/terminado: state={s.get('state')}")
        break
    print(f"[{i}] 0x{eip:x}  {dis1(eip)}")
