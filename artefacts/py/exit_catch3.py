#!/usr/bin/env python3
"""exit_catch3.py — para en el primer pause post-loader y hace dump completo.

Los pauses del loader (0x77cxxxxx) se sostienen; el del entry (0x54EC080) se
auto-reanuda rapido. Tras el entry, AppKeyX transfiere a 0x403E70 (int3) y ahi
el server SI pausa (excepcion first-chance). Este driver NO continua: vuelca
todo y se detiene para decidir.

Uso: python3 exit_catch3.py
Precondicion: exe cargado + hwb de salida puestos (estado pausado o exited).
"""
import subprocess, sys, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
ENTRY = 0x54EC080
LOADER = (0x77c5bf30, 0x77cf87f9, 0x77c1bf30)

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
    return call("status").get("state")

def regs():
    d = call("get_regs")
    return d.get("regs") or {}

def poll_until(max_t, states, step=0.07):
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

def dump(e, esp):
    print("  eip  =", fmt(e), " esp =", fmt(esp))
    if esp:
        d = call("read_mem", {"addr": "0x%x" % esp, "len": 160})
        b = bytes.fromhex(d.get("hex") or "")
        words = [int.from_bytes(b[i:i+4], "little") for i in range(0, min(len(b), 160), 4)]
        print("  --- pila (esp->) ---")
        for i, v in enumerate(words[:32]):
            ins = ""
            if v and 0x400000 <= v < 0x80000000:
                il = dis(v, 1)
                if il:
                    ins = il[0].get("text", "")
            print("    +%02d: %s  %s" % (i * 4, fmt(v), ins))
        # ret addr = [esp]
        d = call("read_mem", {"addr": "0x%x" % esp, "len": 4})
        ret = int.from_bytes(bytes.fromhex(d.get("hex") or ""), "little")
        print("  ret [esp] =", fmt(ret))
        if ret and 0x400000 <= ret < 0x80000000:
            print("  --- contexto del caller (ret-16) ---")
            for a in dis(ret - 16, 14):
                print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))
    print("  --- alrededor de eip ---")
    for a in dis(e - 8, 8):
        print("    %s: %s" % (fmt(a.get("addr")), a.get("text")))

def mem(addr, ln):
    d = call("read_mem", {"addr": "0x%x" % addr, "len": ln})
    h = d.get("hex") or ""
    print("  mem[%s..+%d] = %s (len=%s ok=%s)" % (fmt(addr), ln, h[:min(len(h), 160)], d.get("len"), d.get("ok")))

# arranque
print("estado inicial:", stt())

loops = 0
while loops < 12:
    s = stt()
    if s == "exited":
        print("proceso termino")
        break
    if s == "paused":
        r = regs()
        e = r.get("eip")
        print("paused eip=%s esp=%s" % (fmt(e), fmt(r.get("esp"))))
        if e not in LOADER and e != ENTRY:
            # pause post-entry: dump y PARAR
            print("== PAUSE POST-ENTRY (no continuo) ==")
            dump(e, r.get("esp"))
            print("--- memoria util ---")
            mem(0x403E70, 32)
            mem(0x54EC080, 16)
            mem(r.get("esp"), 32)
            print("hwbp:", json.dumps(call("list_hwbp")))
            sys.exit(0)
        call("go")
        poll_until(3.0, ("paused", "exited"), step=0.1)
    else:
        call("go")
        poll_until(3.0, ("paused", "exited"), step=0.1)
    loops += 1

print("fin sin pause post-entry")
ev = call("poll_events", {"since": 0})
for e in (ev.get("events") or [])[-8:]:
    print("  ", e)
