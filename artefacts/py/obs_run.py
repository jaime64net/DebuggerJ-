#!/usr/bin/env python3
"""obs_run.py — run limpio tras el renombrado de fechas en el registro.

Observa si la validacion de AppKeyX cambia: trampa (0x403E70 CC) = sigue
fallando; si corre estable y al pausar 0x403E70 muestra codigo real (no CC)
= la licencia valido y AppKeyX RESTAURO el OEP (objetivo!).

Uso: python3 obs_run.py
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

print("estado:", call("status").get("state"))
print("restart:", json.dumps(call("restart")))
t0 = time.time()
deadline = time.time() + 90
while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED" % el)
        ev = call("poll_events", {"since": 0})
        for e in (ev.get("events") or [])[-8:]:
            print("   ", e)
        break
    if s == "paused":
        r = (call("get_regs").get("regs") or {})
        e = r.get("eip")
        if e and (e >> 28) == 0x7:
            print("[%5.2fs] loader %s -> go" % (el, fmt(e)))
            call("go")
            time.sleep(0.2)
            continue
        if 0x403E60 <= (e or 0) <= 0x403EF0:
            print("[%5.2fs] *** TRAMPA 0x403E70 (licencia NO valida): eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))))
            d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
            print("  mem[0x403E70..] =", (d.get("hex") or "")[:64])
            break
        print("[%5.2fs] PAUSA inesperada eip=%s" % (el, fmt(e)))
        d = call("read_mem", {"addr": "0x403E70", "len": 0x20})
        print("  mem[0x403E70..] =", (d.get("hex") or "")[:64])
        dd = call("disasm", {"addr": "0x%08x" % (e - 8), "count": 6})
        for a in (dd.get("insns") or []):
            print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
        break
    if s == "running":
        el2 = time.time() - t0
        if el2 > 8:
            print("[%5.2fs] *** RUNNING estable -> pause (posible licencia OK)" % el2)
            call("pause")
            time.sleep(0.5)
            r = (call("get_regs").get("regs") or {})
            e = r.get("eip")
            print("  eip=%s esp=%s" % (fmt(e), fmt(r.get("esp"))))
            d = call("read_mem", {"addr": "0x403E70", "len": 0x80})
            hx = (d.get("hex") or "")
            print("  mem[0x403E70..0x403EEF] =", hx[:160])
            if hx and hx[:2] == "cc":
                print("  -> OEP SIGUE EN CC (sin restaurar)")
            else:
                print("  -> *** OEP NO ES CC: bytes presentes (¿restaurados?)")
            dd = call("disasm", {"addr": "0x403E70", "count": 16})
            for a in (dd.get("insns") or []):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
            ev = call("poll_events", {"since": 0})
            print("--- eventos (ultimos 6) ---")
            for x in (ev.get("events") or [])[-6:]:
                print("   ", x)
            break
    time.sleep(0.05)
