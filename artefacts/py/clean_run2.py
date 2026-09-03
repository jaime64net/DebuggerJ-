#!/usr/bin/env python3
"""clean_run2.py — lanza SIN bps; atraviesa pauses del loader y observa.

- paused en 0x77cxxxxx (loader): go y seguir.
- running: el proceso vivo -> pause -> leer 0x403E70 (OEP restaurado?) y eip.
- paused en otro sitio (p.ej. trampa 0x403E7x): dump y parar.
- exited: reportar eventos (cuando/como murio).

Uso: python3 clean_run2.py
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

print("estado inicial:", call("status").get("state"))
call("go")
t0 = time.time()
while time.time() - t0 < 60:
    st = call("status")
    s = st.get("state")
    rip = st.get("rip")
    el = time.time() - t0
    if s == "exited":
        print("[%4.1fs] EXITED" % el)
        ev = call("poll_events", {"since": 0})
        for e in (ev.get("events") or [])[-8:]:
            print("   ", e)
        break
    if s == "paused":
        r = call("get_regs").get("regs") or {}
        e = r.get("eip")
        if e and (e >> 28) == 0x7:  # 0x77cxxxxx loader
            print("[%4.1fs] loader pause eip=%s -> go" % (el, fmt(e)))
            call("go")
            time.sleep(0.3)
            continue
        print("[%4.1fs] PAUSED en eip=%s esp=%s (no-loader)" % (el, fmt(e), fmt(r.get("esp"))))
        d = call("read_mem", {"addr": "0x403E70", "len": 256})
        h = d.get("hex") or ""
        cc = h.replace("cc", "").replace("CC", "")
        print("  mem[0x403E70] no-CC?:", "SIPARECIO" if cc else "todo CC")
        if cc:
            print("  mem[0x403E70..] =", h[:512])
            print("  disasm 0x403E70:")
            dd = call("disasm", {"addr": "0x403E70", "count": 16})
            for a in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
        break
    if s == "running":
        print("[%4.1fs] RUNNING (app viva, sin bps) -> pause para leer OEP" % el)
        time.sleep(2)
        print("  pause:", json.dumps(call("pause")))
        time.sleep(0.5)
        r = call("get_regs").get("regs") or {}
        print("  eip=", fmt(r.get("eip")))
        d = call("read_mem", {"addr": "0x403E70", "len": 256})
        h = d.get("hex") or ""
        print("  mem[0x403E70..] =", h[:512])
        dd = call("disasm", {"addr": "0x403E70", "count": 16})
        for a in (dd.get("insns") or []):
            print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
        break
    time.sleep(0.4)
else:
    print("timeout 60s, estado final:", call("status").get("state"))
