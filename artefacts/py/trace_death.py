#!/usr/bin/env python3
"""trace_death.py — captura el run-trace desde el entry hasta la muerte del proceso.
Uso: python3 trace_death.py [tail_n]
"""
import subprocess, sys, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
ENTRY = 0x54EC080

def call(cmd, args=None, tmo=60):
    argv = DBG + [cmd]
    if args is not None:
        argv.append(json.dumps(args))
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=tmo, env=ENV)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "timeout"}
    try:
        return json.loads(p.stdout.strip())
    except Exception:
        return {"ok": False, "raw": (p.stdout.strip() or "")[:300]}

def status():
    return call("status")

def regs():
    d = call("get_regs")
    return (d.get("regs") or {}) if d.get("ok") else {}

def go_to_entry():
    st = status()
    if st.get("state") not in ("paused",):
        call("restart")
        time.sleep(0.5)
    for i in range(20):
        st = status()
        eip = regs().get("eip")
        if eip == ENTRY:
            return True
        if st.get("state") == "exited":
            return False
        call("go")
        time.sleep(0.6)
    return False

def main():
    tail = int(sys.argv[1]) if len(sys.argv) > 1 else 120
    if not go_to_entry():
        print("no se alcanzo el entry")
        return
    print("en entry, iniciando run_trace...")
    print(call("run_trace"))
    print("go...")
    call("go")
    # esperar muerte
    for i in range(30):
        time.sleep(0.5)
        if status().get("state") == "exited":
            print(f"proceso murio tras {i*0.5:.1f}s")
            break
    else:
        print("proceso NO murio en 15s")
    tr = call("get_trace")
    print(json.dumps(tr, ensure_ascii=False)[:800])
    # extraer lineas de instrucciones si vienen en otro formato
    print("=== fin ===")

if __name__ == "__main__":
    main()
