#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""disasm_akx2.py — analisis estatico read-only de AppKeyX.dll (CONTPAQ i).
Modos:
  iat          : dump imports .idata (slot RVA/VA) y tabla de thunks 0x6454-0x6634
  sites [api...] : sweep capstone de CODE; call/jmp [IAT] y call/jmp a thunk;
                   mapa por API con RVA de call-site y funcion contenedora
  reach        : grafo de calls intra-CODE desde export#1 0x158C4 (y 0x1561C/0x136B8)
  funcs RVA... : desensamblado completo (prologo->ret) de las funciones dadas
  xref RVA...  : xrefs (push imm32) hacia los VAs string dados dentro de CODE
  strdump VA...: regex de ASCII runs + hexdump +/-96B alrededor del fileoff de cada VA
  mz           : scan de 'MZ'/'PE\\0\\0' por seccion y cadenas BTMemoryModule/... con xrefs
Hechos fijos del modelo (ver ak1561c_note): imagebase 0x400000; CODE rva 0x1000
fileoff 0x400 vsize 0x58D04 (rsize 0x58E00); .idata rva 0x95000 fileoff 0x62600.
"""
import sys, re, struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_GRP_CALL, CS_GRP_JUMP

PATH = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
IB = 0x400000

d = open(PATH, "rb").read()

# ---------------- PE ----------------
def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

pe = u32(d, 0x3C); opt = pe + 24
magic = u16(d, opt); optsz = 224 if magic == 0x10B else 240
imagebase = u32(d, opt + 28)
nsec = u16(d, pe + 6)
secs = []
soff = opt + optsz
for s in range(nsec):
    name = d[soff + s*40: soff + s*40 + 8].rstrip(b"\0").decode("latin1")
    vsize = u32(d, soff + s*40 + 8); vaddr = u32(d, soff + s*40 + 12)
    rsize = u32(d, soff + s*40 + 16); roff = u32(d, soff + s*40 + 20)
    secs.append((name, vaddr, vsize, roff, rsize))

def r2o(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return ro + (rva - va)
    return None

def sec_of_rva(rva):
    for n, va, vs, ro, rs in secs:
        if va <= rva < va + max(vs, rs):
            return n
    return "?"

def dd(idx):
    return u32(d, opt + 96 + idx*8)

# ---------------- imports .idata ----------------
def parse_imports():
    out = []          # (dll, fname, slot_rva)
    imp_rva = dd(1)
    off = r2o(imp_rva)
    while off is not None:
        ilt = u32(d, off); name_rva = u32(d, off + 12); ft = u32(d, off + 16)
        if name_rva == 0:
            break
        noff = r2o(name_rva)
        end = d.index(b"\0", noff)
        dll = d[noff:end].decode("latin1")
        iat_rva = ilt if r2o(ilt) is not None else ft
        io = r2o(iat_rva); idx = 0
        while io is not None:
            v = u32(d, io)
            if v == 0:
                break
            if v & 0x80000000:
                fname = "ord#%d" % (v & 0xFFFF)
            else:
                hn = r2o(v & 0x7FFFFFFF)
                e2 = d.index(b"\0", hn + 2)
                fname = d[hn + 2:e2].decode("latin1")
            out.append((dll, fname, ft + idx*4))
            io += 4; idx += 1
        off += 20
    return out

# slot VA -> (dll, fname)
IMPORTS = parse_imports()
SLOT = {IB + s: (dl, fn) for (dl, fn, s) in IMPORTS}
SLOT_RVA_OF = {fn: s for (dl, fn, s) in IMPORTS}
# API -> primer slot
APISLOT = {}
for (dl, fn, s) in IMPORTS:
    if fn not in APISLOT:
        APISLOT[fn] = (dl, IB + s)

# ---------------- exports .edata ----------------
def parse_exports():
    exp_rva = dd(0)
    eo = r2o(exp_rva)
    if eo is None:
        return [], {}
    base = u32(d, eo + 16)
    nfuncs = u32(d, eo + 20); nnames = u32(d, eo + 24)
    aof = r2o(u32(d, eo + 28)); aon = r2o(u32(d, eo + 32)); aoo = r2o(u32(d, eo + 36))
    by_rva = {}
    for i in range(nnames):
        name_rva = u32(d, aon + i*4)
        no = r2o(name_rva)
        end = d.index(b"\0", no)
        nm = d[no:end].decode("latin1")
        ord_idx = u16(d, aoo + i*2)
        by_rva[u32(d, aof + ord_idx*4)] = (base + ord_idx, nm)
    # funciones solo-ordinal
    for i in range(nfuncs):
        rva = u32(d, aof + i*4)
        if rva not in by_rva:
            by_rva[rva] = (base + i, "")
    return by_rva, base

EXPORTS, EXPBASE = parse_exports()  # rva -> (ordinal, name)

# ---------------- CODE ----------------
CODE = [s for s in secs if s[0] == "CODE"][0]
cname, cva, cvs, cro, crs = CODE
code = d[cro:cro + crs]
md = Cs(CS_ARCH_X86, CS_MODE_32)
md.detail = True

# cabeza de CODE en VA absoluto
def va_of(rva): return IB + rva

def linear_sweep():
    """Desensamblado lineal de TODO CODE; devuelve lista de (va, insn) con
    resync de 1 byte si capstone falla."""
    insns = []
    a = va_of(cva)
    end = va_of(cva + len(code))
    while a < end:
        off = a - va_of(cva)
        try:
            ins = next(md.disasm(code[off:off + 15], a))
        except StopIteration:
            a += 1
            continue
        insns.append(ins)
        a += ins.size
    return insns

# thunk de imports: region RVA 0x6454..0x6634 (cada thunk: ff25 disp32 + 8b c0 = 8 B)
THUNK_RANGE = (0x6454, 0x6634)
def thunk_table():
    tab = {}
    blob = code[THUNK_RANGE[0] - cva: THUNK_RANGE[1] - cva + 8]
    for ins in md.disasm(blob, va_of(cva + THUNK_RANGE[0])):
        rva = ins.address - IB
        if ins.mnemonic == "jmp" and len(ins.operands) == 1 and ins.operands[0].type == 3:
            slot = ins.operands[0].mem.disp
            tab[rva] = (SLOT.get(slot), slot)
    return tab
THUNKS = thunk_table()

# call-sites: busqueda sobre lineal + pasadas puntuales por cada thunk candidato
def gather_sites():
    """Devuelve {rva: dict(tipo, api, target, slot)} tipo in {iat, thunk, func}."""
    sites = {}
    for ins in linear_sweep():
        if ins.mnemonic not in ("call", "jmp"):
            continue
        rva = ins.address - IB
        if THUNK_RANGE[0] <= rva < THUNK_RANGE[1]:
            continue                      # la propia jump-table no es caller
        ops = ins.operands
        if not ops:
            continue
        op = ops[0]
        if op.type == 3:                  # memoria -> slot IAT
            disp = op.mem.disp
            if disp in SLOT or (IB + 0x95000 <= disp < IB + 0x95400):
                sites[rva] = dict(tipo="iat", api=SLOT.get(disp), target=None, slot=disp)
        elif op.type == 2:                # inmediato -> thunk o funcion interna
            tgt = (ins.address + ins.size + op.imm) & 0xFFFFFFFF
            trva = tgt - IB
            if trva in THUNKS:
                api, slot = THUNKS[trva]
                sites[rva] = dict(tipo="thunk", api=api, target=trva, slot=slot)
            elif cva <= trva < cva + cvs:
                sites[rva] = dict(tipo="func", api=None, target=trva, slot=None)
    return sites

SITES = gather_sites()

# heads de funcion = exports + subfunciones conocidas del modelo + targets de call
KNOWN_HEADS = [
    0x136B8, 0x1526C, 0x14E50, 0x1561C, 0x158C4, 0x154E0, 0x153C8, 0x8638,
    0x864C, 0x8274, 0x15504, 0x1573A, 0x157C5, 0x157D0, 0x15810, 0x157F8,
    0x15348, 0x1519C, 0x14EE8, 0x14DB4, 0x14D60, 0x15846, 0x156BB, 0x2D1C,
    0x2D84, 0x48A0, 0xC338, 0x44DC, 0x3D04, 0x3E30, 0x3EE4, 0x3E68, 0xAF2C,
    0x7700, 0x153B8, 0x153C0,
]

def build_heads():
    heads = {}
    for rva, (ordn, nm) in EXPORTS.items():
        lab = "export#%d" % ordn
        if nm:
            lab = "export#%d[%s]" % (ordn, nm)
        heads[rva] = lab
    for rva in KNOWN_HEADS:
        heads.setdefault(rva, "model_sub_%X" % rva)
    # targets de call/jmp a funcion interna como heads (para contenedor fino)
    for rva, info in SITES.items():
        if info["tipo"] == "func":
            t = info["target"]
            if t not in heads:
                heads[t] = "calltgt_%X" % (t - IB)
    return heads
HEADS = build_heads()

def container_of(rva):
    """head previo mas cercano (inclusive)."""
    best = None
    for h in HEADS:
        if h <= rva and (best is None or h > best):
            best = h
    if best is None:
        return "? (rva 0x%X)" % rva
    return "%s @0x%X" % (HEADS[best], best)

def describe_site(rva, info):
    api = info["api"]
    if info["tipo"] == "func":
        return "0x%X  %-6s ->0x%X (call interno)  en %s" % (
            rva, info["tipo"], info["target"], container_of(rva))
    if api:
        return "0x%X  %-6s %-22s %-28s  en %s" % (
            rva, info["tipo"], api[0], api[1], container_of(rva))
    return "0x%X  %-6s slot 0x%X (IAT vacio/sin nombre)  en %s" % (
        rva, info["tipo"], info["slot"], container_of(rva))

def find_xrefs_imm(va):
    """busca push imm32 == va dentro de CODE (bytes 68 xx xx xx xx)."""
    pat = b"\x68" + struct.pack("<I", va)
    hits = []
    i = 0
    while True:
        j = code.find(pat, i)
        if j < 0:
            break
        hits.append(cva + j)   # rva de la instruccion push
        i = j + 1
    return hits

# ============================= MODOS =============================
def mode_iat():
    print("== imports .idata (slot RVA / VA) ==")
    seen = set()
    for dll, fn, s in IMPORTS:
        if (dll, fn) in seen:
            continue
        seen.add((dll, fn))
        print("%-24s %-28s slotRVA 0x%X  slotVA 0x%X" % (dll, fn, s, IB + s))
    print("\n== tabla thunks 0x6454-0x6634 (RVA -> API) ==")
    for rva in sorted(THUNKS):
        api, slot = THUNKS[rva]
        nm = ("%s!%s" % api) if api else "SLOT-VACIO 0x%X" % slot
        print("0x%X -> %s" % (rva, nm))

def mode_sites(want):
    apis = [a.strip() for a in want] or None
    print("== call-sites (IAT directos y via thunk) ==")
    by_api = {}
    holes = []
    for rva in sorted(SITES):
        info = SITES[rva]
        if info["api"] is None:
            if info["tipo"] != "func":
                holes.append(rva)
            continue
        key = info["api"]
        by_api.setdefault(key, []).append((rva, info["tipo"]))
    for key in sorted(by_api, key=lambda k: k[1]):
        if apis and key[1] not in apis:
            continue
        print("\n### %-24s %-28s n=%d" % (key[0], key[1], len(by_api[key])))
        for rva, tipo in sorted(by_api[key]):
            print("   0x%X %s  en %s" % (rva, tipo, container_of(rva)))
    if holes and not apis:
        print("\n### thunks a slot IAT vacio (nombre no recuperable) n=%d" % len(holes))
        for rva in holes:
            print("   0x%X %s slot 0x%X  en %s" % (
                rva, SITES[rva]["tipo"], SITES[rva]["slot"], container_of(rva)))

def mode_reach():
    # grafo dirigido por 'func' sites (call/jmp a codigo interno) y thunk/iat (leaf)
    import collections
    adj = collections.defaultdict(set)
    for rva, info in SITES.items():
        if info["tipo"] == "func":
            src = None
            for h in sorted(HEADS):
                if h <= rva:
                    src = h
            if src is not None:
                adj[src].add(info["target"])
    # BFS desde export #1 0x158C4
    seen = set(); q = [0x158C4, 0x1561C, 0x136B8]
    while q:
        cur = q.pop()
        for t in adj.get(cur, ()):
            if t not in seen:
                seen.add(t); q.append(t)
    print("== alcanzables desde export#1(0x158C4)/0x1561C/0x136B8: %d heads ==" % len(seen))
    for t in sorted(seen):
        print("  0x%X  %s" % (t, HEADS.get(t, "?")))
    # interesa: contenedores de los call-sites a APIs sensibles
    sens = ["VirtualProtect", "VirtualAlloc", "VirtualFree", "HeapAlloc",
            "LocalAlloc", "CreateFileMappingA", "MapViewOfFile", "UnmapViewOfFile",
            "WriteProcessMemory", "ReadProcessMemory", "OpenProcess",
            "WriteFile", "ReadFile", "ExitProcess"]
    print("\n== contenedores de call-sites sensibles y su alcanzabilidad ==")
    for rva in sorted(SITES):
        info = SITES[rva]
        if info["api"] is None or info["api"][1] not in sens:
            continue
        fn = info["api"][1]
        # contenedor
        c = None
        for h in sorted(HEADS):
            if h <= rva:
                c = h
        reach = c in seen
        print("  0x%X %-22s en %-16s alcanzableDesdeOrd1=%s" % (
            rva, fn, ("0x%X %s" % (c, HEADS[c])) if c else "?", reach))

def mode_funcs(rvas):
    for hrva in rvas:
        off = r2o(hrva)
        print("\n===== funcion RVA 0x%X (fileoff 0x%X) =====" % (hrva, off))
        if off is None:
            print("  fuera de secciones raw")
            continue
        # limite: hasta ret o 600 insns
        cnt = 0
        for ins in md.disasm(d[off:off + 0x900], va_of(hrva)):
            if cnt >= 700:
                print("   ...(cortado)")
                break
            print("  0x%X  %s %s" % (ins.address - IB, ins.mnemonic, ins.op_str))
            cnt += 1
            if ins.mnemonic == "ret":
                break

def mode_xref(vas):
    for va in vas:
        hits = find_xrefs_imm(va)
        print("VA 0x%X (RVA 0x%X) xrefs push imm32: %d" % (va, va - IB, len(hits)))
        for h in hits:
            print("   push en RVA 0x%X  (%s)" % (h, container_of(h)))

def mode_strdump(vas):
    for va in vas:
        rva = va - IB
        off = r2o(rva)
        print("\n=== VA 0x%X (RVA 0x%X, fileoff 0x%X, sec %s) ===" % (va, rva, off, sec_of_rva(rva)))
        if off is None:
            continue
        chunk = d[off - 96: off + 96]
        base = off - 96
        for i in range(0, len(chunk), 16):
            row = chunk[i:i+16]
            hxs = " ".join("%02x" % b for b in row)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
            fo = base + i
            print("  off 0x%05X rva 0x%05X  %-47s  %s" % (fo, fo - 0x400, hxs, asc))

def mode_mz():
    for nm, va, vs, ro, rs in secs:
        if rs == 0:
            continue
        blob = d[ro:ro + rs]
        hits = []
        i = 0
        while True:
            j = blob.find(b"MZ", i)
            if j < 0:
                break
            hits.append(j); i = j + 1
        p32 = []
        i = 0
        while True:
            j = blob.find(b"PE\x00\x00", i)
            if j < 0:
                break
            p32.append(j); i = j + 1
        print("sec %-8s MZ: %d PE00: %d" % (nm, len(hits), len(p32)))
        for j in hits[:6]:
            print("   MZ@roff 0x%X (rva 0x%X)" % (ro + j, va + j))
        for j in p32[:6]:
            print("   PE00@roff 0x%X (rva 0x%X)" % (ro + j, va + j))

def mode_strings_search(names):
    for nm in names:
        b = nm.encode("latin1")
        hits = []
        i = 0
        while True:
            j = d.find(b, i)
            if j < 0:
                break
            hits.append(j); i = j + 1
        print("string %-24s hits=%d" % (nm, len(hits)))
        for h in hits[:10]:
            print("   fileoff 0x%X -> rva 0x%X (sec %s)" % (h, h - 0x400, sec_of_rva(h - 0x400)))

if __name__ == "__main__":
    m = sys.argv[1] if len(sys.argv) > 1 else "iat"
    if m == "iat":
        mode_iat()
    elif m == "sites":
        mode_sites(sys.argv[2:])
    elif m == "reach":
        mode_reach()
    elif m == "funcs":
        mode_funcs([int(x, 16) for x in sys.argv[2:]])
    elif m == "xref":
        mode_xref([int(x, 16) for x in sys.argv[2:]])
    elif m == "strdump":
        mode_strdump([int(x, 16) for x in sys.argv[2:]])
    elif m == "mz":
        mode_mz()
    elif m == "str":
        mode_strings_search(sys.argv[2:])
