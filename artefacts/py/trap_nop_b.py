#!/usr/bin/env python3
"""trap_nop_b.py — RE-RUN 2026-09-03 de la variante (b) de §13.4 (parche NOP de los 99 B CC),
ahora con child-tracking ON para discriminar la pregunta abierta de §13.4:
la recaida en 0x403E70 tras ~3.5 s, es REMAPEO DE PAGINA o PROCESO NUEVO (auto-restart)?

Variante (b) exacta: en 0x403E70 -> 90 E9 5D 00 00 00 (NOP; jmp +0x5D -> 0x403ED3)
                      + 93 NOPs (0x403E76..0x403ED2)  => bloque completo 99 B (0x63).
Solo write_mem en memoria del proceso vivo (efimero, muere con el proceso);
0 escrituras a disco/registro, 0 bps dentro de AppKeyX.

Discriminador:
  - al recaer (pause en zona trampa) leer 0x403E70:
      CC restaurado + eventos child/exit   -> proceso nuevo o pagina remapeada
      parche intacto (90 E9...)            -> el MISMO proceso re-ejecuto el bloque (sin int3)
  - poll_events: create_process_child / breakpoint 0x77CF87F8 / exit code.
"""
import subprocess, json, time, sys

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

def is_loader(addr):
    return bool(addr) and (addr >> 28) == 0x7

def is_trap(addr):
    return bool(addr) and 0x403E60 <= addr <= 0x403EF0

def rd(addr, ln):
    d = call("read_mem", {"addr": addr, "len": ln})
    h = d.get("hex") or ""
    return h

print("== estado inicial:", call("status").get("state"))
print("== follow_children:", json.dumps(call("set_follow_children", {"on": True})))
print("== list_bp inicial:", json.dumps(call("list_bp")))

# limpiar bp residual si el server conserva la sesion (ak_ep_tmp 0x54EC080 y otros)
for b in (call("list_bp").get("bps") or []):
    a = b.get("addr") or b.get("address")
    if a:
        print("== del_bp", a, "->", json.dumps(call("del_bp", {"addr": a})))
print("== restart:", json.dumps(call("restart")))

# --- fase 1: llevar el run a la trampa 0x403E70 (sin bps); hasta 4 intentos ---
t0 = time.time()
patched = False
deadline = time.time() + 120
attempt = 1
last_loader_eip = None
lp_same = 0
st_last = None
while time.time() < deadline and attempt <= 4:
    st = call("status")
    s = st.get("state")
    if s != st_last:
        print("[%5.2fs] state=%s" % (time.time() - t0, s))
        st_last = s
    if s == "exited":
        print("[%5.2fs] EXITED antes de llegar a la trampa (intento %d/4)" % (time.time() - t0, attempt))
        ev = call("poll_events", {"since": 0})
        for e in (ev.get("events") or [])[-6:]:
            print("    ", e)
        attempt += 1
        last_loader_eip = None
        lp_same = 0
        print("== restart (intento %d)" % attempt)
        call("restart")
        st_last = None
        # esperar a que el nuevo proceso salga del estado 'exited' (race del restart)
        t_w = time.time()
        while time.time() - t_w < 8:
            s2 = call("status").get("state")
            if s2 not in ("exited", None):
                break
            time.sleep(0.15)
        time.sleep(0.4)
        continue
    if s == "paused":
        r = (call("get_regs").get("regs") or {})
        e = r.get("eip")
        if is_loader(e):
            if e == last_loader_eip:
                lp_same += 1
            else:
                lp_same = 0
            last_loader_eip = e
            if lp_same >= 6:
                print("[%5.2fs] park loader ciclico eip=%s (x%d) -> stop" % (time.time() - t0, fmt(e), lp_same))
                break
            print("[%5.2fs] park loader eip=%s -> go" % (time.time() - t0, fmt(e)))
            call("go")
            time.sleep(0.25)
            continue
        if is_trap(e):
            print("[%5.2fs] TRAMPA: eip=%s esp=%s" % (time.time() - t0, fmt(e), fmt(r.get("esp"))))
            break
        # pausa no esperada: go y seguir
        print("[%5.2fs] pause no esperada eip=%s -> go" % (time.time() - t0, fmt(e)))
        call("go")
        time.sleep(0.1)
        continue
    if s == "running":
        time.sleep(0.05)
else:
    print("deadline fase-1; estado:", call("status").get("state"))
    sys.exit(1)

# --- fase 2: parche variante (b) sobre la trampa ---
h_pre = rd("0x403E70", 0x63)
print("== mem pre-parche [0x403E70..+0x63] =", h_pre[:160], ("..." if len(h_pre) > 160 else ""))
print("== pre-parche CC puro:", h_pre.replace("cc", "").replace("CC", "") == "")

blob = bytes([0x90, 0xE9, 0x5D, 0x00, 0x00, 0x00]) + b"\x90" * 93   # 99 B = 0x63
assert len(blob) == 0x63, len(blob)
w = call("write_mem", {"addr": "0x403E70", "hex": blob.hex()})
print("== write_mem 0x403E70 len=%d -> %s" % (len(blob), json.dumps(w)))
h_post = rd("0x403E70", 0x63)
print("== mem post-parche  [0x403E70..+0x63] =", h_post[:160], ("..." if len(h_post) > 160 else ""))
print("== go (continuar tras la trampa parcheada)")
call("go")
patched = True
time.sleep(0.3)

# --- fase 3: observacion hasta recaida / exit / estabilidad ---
t1 = time.time()
deadline = time.time() + 20
since = 0
falls = 0
last_events = []
while time.time() < deadline:
    st = call("status")
    s = st.get("state")
    el = time.time() - t1
    if s == "exited":
        ev = call("poll_events", {"since": since})
        last_events = ev.get("events") or []
        since = ev.get("last_seq") or since
        print("[%5.2fs] EXITED post-parche" % el)
        break
    if s == "paused":
        r = (call("get_regs").get("regs") or {})
        e = r.get("eip")
        ev = call("poll_events", {"since": since})
        last_events += ev.get("events") or []
        since = ev.get("last_seq") or since
        print("[%5.2fs] PAUSA post-parche: eip=%s esp=%s" % (el, fmt(e), fmt(r.get("esp"))))
        if is_trap(e):
            falls += 1
            hh = rd("0x403E70", 0x20)
            print("    RECAIDA %d en zona trampa; mem[0x403E70..+0x20] = %s" % (falls, hh[:64]))
            print("    -> parche intacto?" , hh[:12].lower().startswith("90e95d000000"))
            hd = rd("0x403ED3", 0x20)
            print("    mem[0x403ED3..+0x20] (codigo real) =", hd[:64])
            print("    list_children:", json.dumps(call("list_children")))
        else:
            dd = call("disasm", {"addr": "0x%08x" % (e - 8 if e else 0x403ED3), "count": 10})
            print("    disasm:")
            for a in (dd.get("insns") or []):
                print("      %s: %s" % (fmt(a.get("addr")), a.get("text")))
        if falls >= 2 or (not is_trap(e)):
            break
        call("go")
        time.sleep(0.2)
        continue
    if s == "running":
        # estabilidad: si lleva > 8 s corriendo sin morir tras el parche, es dato
        if patched and el > 8:
            print("[%5.2fs] RUNNING estable post-parche > 8 s -> pause para inspeccionar" % el)
            call("pause")
            time.sleep(0.3)
            continue
        time.sleep(0.05)
    else:
        time.sleep(0.05)
else:
    print("deadline fase-3; estado:", call("status").get("state"))

ev = call("poll_events", {"since": since})
last_events += ev.get("events") or []
print("--- ultimos eventos (%d) ---" % len(last_events))
for e in last_events[-14:]:
    print("   ", e)

# --- fase 4: si hubo hijo, UNA query puntual de identificacion (sin watchers) ---
pids = set()
for e in last_events:
    if isinstance(e, dict) and e.get("type") == "create_process_child":
        pids.add(e.get("pid"))
    if isinstance(e, dict) and "create_process_child" in str(e):
        import re
        m = re.search(r"pid[:\s]*(\d+)", str(e))
        if m:
            pids.add(int(m.group(1)))
cl = call("list_children")
if isinstance(cl, dict) and cl.get("ok"):
    for p in (cl.get("children") or []):
        if isinstance(p, dict):
            pids.add(p.get("pid"))
        else:
            pids.add(p)
for pid in sorted(pids):
    print("== identificacion UNA query para hijo pid=%d" % pid)
    try:
        pp = subprocess.run(["tasklist.exe", "/FO", "LIST", "/FI", "PID eq %d" % pid],
                            capture_output=True, text=True, timeout=10)
        print(pp.stdout.strip()[:500] or pp.stderr.strip()[:200])
    except subprocess.TimeoutExpired:
        print("   tasklist timeout (interop) -> omitido")

print("== list_bp final:", json.dumps(call("list_bp")))
for b in (call("list_bp").get("bps") or []):
    a = b.get("addr") or b.get("address")
    if a:
        call("del_bp", {"addr": a})
print("== fin; estado:", call("status").get("state"))
