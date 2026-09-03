#!/usr/bin/env python3
"""dbg_run.py — orquesta el debugger via dbg.mjs: go hasta una condicion.
Uso:
  dbg_run.py go_until_entry          -> go hasta EIP==entry (0x54EC080) o exit
  dbg_run.py go_until <hex>          -> go hasta una direccion o exit
  dbg_run.py observe <n>             -> lanza y observa: tras cada go, status+regs n veces
"""
import subprocess, sys, json, time

DBG = ["node", "dbg.mjs"]
ENV = {"DBGJPP_PORT": "8378", "PATH": "/usr/bin:/bin:/usr/local/bin"}
ENTRY = 0x54EC080

def call(cmd, args=None, tmo=45):
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
        return {"ok": False, "raw": (p.stdout.strip() or "")[:200]}

def status():
    return call("status")

def regs():
    d = call("get_regs")
    return (d.get("regs") or {}) if d.get("ok") else {}

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "observe"
    target = int(sys.argv[2], 16) if len(sys.argv) > 2 else ENTRY
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 12

    if mode == "go_until_entry" or mode == "go_until":
        st = status()
        print("estado inicial:", st.get("state"), "eip_obj=", target)
        for i in range(n):
            st = status()
            s = st.get("state")
            r = regs()
            eip = r.get("eip")
            print(f"[{i}] state={s} eip={eip and hex(eip)}")
            if eip == target:
                print("ALCANZADO", hex(target))
                return
            if s == "exited":
                print("PROCESO TERMINADO (exit)")
                return
            call("go")
            time.sleep(1.5)
        print("agotado. estado final:", status().get("state"))

    elif mode == "observe":
        call("launch")
        for i in range(n):
            time.sleep(0.8)
            st = status()
            r = regs()
            print(f"[{i}] state={st.get('state')} eip={r.get('eip') and hex(r.get('eip'))}")

if __name__ == "__main__":
    main()
