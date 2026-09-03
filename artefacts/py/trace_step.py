#!/usr/bin/env python3
"""Trace paso a paso del proceso depurado via dbg.mjs (DebuggerJ++ MCP).
Uso: python3 trace_step.py <nsteps> [addr_stop]
"""
import subprocess, sys, json, time

DBG = ["node", "dbg.mjs"]
ENV_PORT = "8378"

def call(cmd, args=None):
    argv = DBG + [cmd]
    if args is not None:
        argv.append(json.dumps(args))
    p = subprocess.run(argv, capture_output=True, text=True, timeout=45, env={"DBGJPP_PORT": ENV_PORT, "PATH": "/usr/bin:/bin:/usr/local/bin"})
    out = p.stdout.strip()
    try:
        return json.loads(out)
    except Exception:
        return {"raw": out}

n = int(sys.argv[1]) if len(sys.argv) > 1 else 20
stop = None
if len(sys.argv) > 2:
    stop = int(sys.argv[2], 16)

def cur_eip():
    d = call("get_regs")
    r = d.get("regs") or {}
    return r.get("eip")

for i in range(n):
    eip0 = cur_eip()
    d = call("step_into")
    if not d.get("ok"):
        print(f"[{i}] step_into ERROR: {d}")
        break
    time.sleep(0.35)
    eip = cur_eip()
    if eip is None:
        print(f"[{i}] no eip (proceso termino?)")
        st = call("status")
        print("   status:", st.get("state"))
        break
    ds = call("disasm", {"addr": "0x%x" % eip, "count": 1})
    ins = ""
    if ds.get("insns"):
        ins = ds["insns"][0].get("text", "")
    print(f"[{i}] 0x{eip:x}  {ins}")
    if stop and eip == stop:
        print("== stop alcanzado ==")
        break
