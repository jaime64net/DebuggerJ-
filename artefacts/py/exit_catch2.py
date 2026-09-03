#!/usr/bin/env python3
"""exit_catch2.py — captura el punto de muerte (v2, cadencia probada).

Fase A: avanzar por loader hasta el entry (sw bp 0x54EC080), con sleeps
cortos (0.4 s) como hacia dbg_run.py (los pauses del loader SI se sostienen).
Fase B: desde el entry, go y poll rapido (0.08 s) para cazar el hwb de salida
antes del auto-resume. Vuelco regs+pila+caller+disasm si paramos; si el
proceso muere sin disparar hwb, lo reporta con eventos.

Uso: python3 exit_catch2.py
Precondicion: exe cargado, hwb de salida puestos, estado pausado o exited.
"""
import subprocess, sys, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
ENTRY = 0x54EC080

def call(cmd, args=None, tmo=20):
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
        return {"ok": False, "raw": (out or "")[:300]}

def stt():
    d = call("status")
    return d.get("state")

def eip():
    d = call("get_regs")
    r = d.get("regs") or {}
    return r.get("eip")

def poll_until(max_t, states, step=0.08):
    """Pollea status hasta entrar en algun estado de `states`."""
    t0 = time.time()
    while time.time() - t0 < max_t:
        s = stt()
        if s in states:
            return s
        time.sleep(step)
    return "?"

def dis(addr, count=1):
    d = call("disasm", {"addr": "0x%x" % addr, "count": count})
    return d.get("insns") or []

def fmt(addr):
    return "0x%08x" % addr if addr is not None else "None"

print("estado inicial:", stt())

# ---- Fase A: acercarse al entry ----
alcanzado = False
for k in range(14):
    s = stt()
    if s == "exited":
        print("FaseA: proceso terminado antes de llegar al entry")
        break
    if s == "paused":
        e = eip()
        print("FaseA[%d]: paused eip=%s" % (k, fmt(e)))
        if e == ENTRY:
            alcanzado = True
            print("== ENTRY alcanzado (sw bp) ==")
            break
        call("go")
    else:  # running
        call("go")
    # espera corta al siguiente evento estable
    s2 = poll_until(3.0, ("paused", "exited"), step=0.12)
    if s2 == "exited":
        print("FaseA: proceso termino (tras go %d)" % k)
        break
    if s2 == "?":
        print("FaseA[%d]: sin pause estable (auto-resume?)" % k)

if not alcanzado:
    s = stt()
    if s == "exited":
        print("RESULTADO: proceso murio en FaseA sin llegar al entry")
    else:
        print("RESULTADO: no se alcanzo el entry; estado:", s)
    sys.exit(0)

# ---- Fase B: soltar desde el entry, cazar el hwb de salida ----
print("FaseB: soltando desde el entry...")
call("go")
s = poll_until(30.0, ("paused", "exited"), step=0.06)
print("desenlace:", s)

if s == "paused":
    r = call("get_regs").get("regs") or {}
    e = r.get("eip")
    esp = r.get("esp")
    print("eip  =", fmt(e), " esp =", fmt(esp))
    print("regs = eax=%s ebx=%s ecx=%s edx=%s esi=%s edi=%s ebp=%s"
          % tuple(fmt(r.get(k)) for k in ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp")))
    who = {0x77C59D90: "ntdll!NtTerminateProcess", 0x77C14060: "ntdll!RtlExitUserProcess",
           0x7628B0B0: "kernel32!ExitProcess", 0x76292E90: "kernel32!TerminateProcess"}.get(e, "?")
    print("API  =", who)
    if esp:
        d = call("read_mem", {"addr": "0x%x" % esp, "len": 128})
        b = bytes.fromhex(d.get("hex") or "")
        words = [int.from_bytes(b[i:i+4], "little") for i in range(0, min(len(b), 128), 4)]
        print("--- pila (esp->) ---")
        for i, v in enumerate(words[:28]):
            ins = ""
            if v and v > 0x400000 and v < 0x80000000:
                il = dis(v, 1)
                if il:
                    ins = il[0].get("text", "")
            print("  +%02d: %s  %s" % (i * 4, fmt(v), ins))
    print("--- contexto caller ---")
    if esp:
        d = call("read_mem", {"addr": "0x%x" % esp, "len": 4})
        ret = int.from_bytes(bytes.fromhex(d.get("hex") or ""), "little")
        print("return addr [esp] =", fmt(ret))
        for a in dis(ret - 12, 10):
            print("   %s: %s" % (fmt(a.get("addr")), a.get("text")))
    print("hwbp hits:", json.dumps(call("list_hwbp")))
elif s == "exited":
    print("RESULTADO: murio sin disparar hwb de salida")
    print("hwbp hits:", json.dumps(call("list_hwbp")))
    ev = call("poll_events", {"since": 0})
    evs = ev.get("events") or []
    print("--- ultimos eventos ---")
    for e in evs[-8:]:
        print("  ", e)
