#!/usr/bin/env python3
"""stack_trap.py — en la pausa de la trampa (0x403E71) vuelca la pila para
mapear la cadena de llamadas del camino de fallo de AppKeyX.

La direccion de retorno del transferidor (AppKeyX -> 0x403E70) y los frames
superiores (dentro de AppKeyX 0x5E0xxxxx / ntdll / exe) permiten localizar
la funcion que decide el fallo (y la rama de restauracion).

Uso: python3 stack_trap.py
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
        return {"ok": False, "raw": (out or "")[:300]}

def fmt(a):
    return "0x%08x" % a if a is not None else "None"

print("restart:", json.dumps(call("restart")))
t0 = time.time()
# modulo info (listo para anotar)
mods = call("modules")
ranges = []
for m in (mods.get("modules") or mods.get("mods") or []):
    b = m.get("base") or m.get("addr")
    sz = m.get("size") or m.get("len")
    nm = m.get("name") or m.get("module") or m.get("path") or "?"
    if b and sz:
        ranges.append((b, b + sz, nm))
    elif b:
        ranges.append((b, b + 0x10000, nm))
ranges.sort()

def who(a):
    if a is None:
        return ""
    for lo, hi, nm in ranges:
        if lo <= a < hi:
            return nm
    return ""

deadline = time.time() + 40
while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t0
    if s == "exited":
        print("[%5.2fs] EXITED (no hubo trampa)" % el)
        break
    if s == "paused":
        r = (call("get_regs").get("regs") or {})
        e = r.get("eip")
        if e and (e >> 28) == 0x7:
            print("[%5.2fs] loader %s -> go" % (el, fmt(e)))
            call("go")
            time.sleep(0.2)
            continue
        print("[%5.2fs] TRAMPA eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))))
        esp = r.get("esp") or 0
        # 0x60 dwords de pila
        d = call("read_mem", {"addr": "0x%08x" % esp, "len": 0xF0})
        hx = (d.get("hex") or "")
        data = bytes.fromhex(hx) if hx else b""
        print("esp base 0x%08x (%d bytes leidos)" % (esp, len(data)))
        for i in range(0, len(data) - 3, 4):
            val = int.from_bytes(data[i:i+4], "little")
            off = esp + i
            tag = ""
            if 0x5D00000 <= val <= 0x5E10000:
                tag = " <== AppKeyX?"
            elif 0x400000 <= val <= 0x6000000:
                tag = " <== exe/otro"
            elif val and (val >> 28) == 0x7:
                tag = " ntdll/dll"
            print("  [0x%08x] 0x%08x%s %s" % (off, val, tag, who(val)))
        # hilos
        print("--- threads ---")
        th = call("threads")
        for t in (th.get("threads") or th.get("list") or [])[:12]:
            print("   ", t)
        break
    time.sleep(0.05)
else:
    print("deadline; estado:", call("status").get("state"))
