#!/usr/bin/env python3
"""exit_catch.py — captura el punto exacto donde el proceso intenta morir.

Idea: en vez de trazar desde el entry (el server auto-reanuda ~1-2 s tras pause
por hwbp), ponemos hwb en los choke-points de salida y soltamos el proceso.
Cuando un hwb dispara, el EIP estara en la API y [esp] = direccion de retorno
= el caller (el sitio anti-debug de AppKeyX). Polleo rapido para ganarle al
auto-resume y vuelco registros + pila + caller + disasm del caller.

Uso: python3 exit_catch.py
Precondicion: proceso abierto y pausado en system bp con hwb de salida puestos.
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

def status():
    return call("status")

def regs():
    d = call("get_regs")
    return d.get("regs") or {}

def poll_until_paused(max_t=25, step=0.15):
    """Pollea status hasta que el proceso este paused (o exited)."""
    t0 = time.time()
    while time.time() - t0 < max_t:
        st = status()
        s = st.get("state")
        if s in ("paused", "exited"):
            return st
        time.sleep(step)
    return {"state": "?", "ok": False, "note": "sin cambio en %ss" % max_t}

def dis(addr, count=1):
    d = call("disasm", {"addr": "0x%x" % addr, "count": count})
    return d.get("insns") or []

def fmt(addr):
    return "0x%08x" % addr if addr is not None else "None"

# 1) estado actual
st0 = status()
print("estado inicial:", st0.get("state"), "rip=", hex(st0.get("rip") or 0))

# 2) si estamos en system bp -> go. Esperamos el sw-bp del entry como checkpoint.
if st0.get("state") == "paused":
    call("go")
    st = poll_until_paused(max_t=20)
    r = regs()
    print("checkpoint:", st.get("state"), "eip=", hex(r.get("eip") or 0))
    if r.get("eip") == ENTRY:
        print("== en el entry (sw bp) ==")
        # 3) soltar el proceso hacia la muerte
        call("go")
        st = poll_until_paused(max_t=40, step=0.12)
    else:
        # quizas ya disparo un hwb de salida directamente
        pass

s = st.get("state")
print("desenlace:", s)
r = regs()
eip = r.get("eip")
print("eip      =", fmt(eip))
print("regs     = eax=%s ebx=%s ecx=%s edx=%s esi=%s edi=%s esp=%s ebp=%s"
      % tuple(fmt(r.get(k)) for k in ("eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp")))

if s == "paused":
    esp = r.get("esp")
    # identificar en que API estamos
    who = "?"
    if eip == 0x77C59D90: who = "ntdll!NtTerminateProcess"
    elif eip == 0x77C14060: who = "ntdll!RtlExitUserProcess"
    elif eip == 0x7628B0B0: who = "kernel32!ExitProcess"
    elif eip == 0x76292E90: who = "kernel32!TerminateProcess"
    print("API      =", who)

    # pila: primeros 24 dwords
    if esp:
        d = call("read_mem", {"addr": "0x%x" % esp, "len": 96})
        hexs = d.get("hex") or ""
        if len(hexs) >= 96:
            words = []
            b = bytes.fromhex(hexs)
            for i in range(0, 96, 4):
                v = int.from_bytes(b[i:i+4], "little")
                words.append(v)
            print("--- pila (esp->) ---")
            for i, v in enumerate(words[:24]):
                ins = ""
                if v > 0x400000:
                    insl = dis(v, 1)
                    if insl:
                        ins = insl[0].get("text", "")
                print("  +%02d: %s  %s" % (i * 4, fmt(v), ins))
            # return address = [esp] (o [esp] si estamos en el prologo)
            ret = words[0]
            print("--- caller [esp] ---")
            for a in dis(ret - 8, 8):
                print("   %s: %s" % (fmt(a.get("addr")), a.get("text")))
    # dump de los hwb que dispararon
    print("hwbp:", json.dumps(call("list_hwbp")))
else:
    print("el proceso termino sin disparar hwb de salida (exit code? revisar eventos)")
    ev = call("poll_events", {"since": 0})
    evs = ev.get("events") or []
    for e in evs[-6:]:
        print("  event:", e)
