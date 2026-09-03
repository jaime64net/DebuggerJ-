#!/usr/bin/env python3
"""exports.py — resuelve direcciones absolutas de funciones exportadas.
Uso: exports.py <dll-path> <module-base-hex> [func1 func2 ...]  (si no se dan funcs, lista todas)
Ej:  exports.py "/mnt/c/Windows/SysWOW64/user32.dll" 0x75980000 MessageBoxA
El RVA de exportación + base del módulo = dirección absoluta en el proceso."""
import sys, struct

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def main():
    path, base = sys.argv[1], int(sys.argv[2], 16)
    want = sys.argv[3:]
    data = open(path, "rb").read()
    pe = u32(data, 0x3C)
    opt = pe + 24
    nsec = u16(data, pe + 6)
    magic = u16(data, opt)
    optsz = 224 if magic == 0x10B else 240
    exp_rva = u32(data, opt + 96)  # export directory rva (primer data directory)
    exp_sz = u32(data, opt + 116)
    if not exp_rva:
        print("sin exportaciones"); return
    # mapear rva -> offset de archivo
    secs = []
    off = opt + optsz
    for s in range(nsec):
        vaddr = u32(data, off + s*40 + 12); vsize = u32(data, off + s*40 + 8)
        roff = u32(data, off + s*40 + 20); rsize = u32(data, off + s*40 + 16)
        secs.append((vaddr, vsize, roff, rsize))
    def r2o(rva):
        for vaddr, vsize, roff, rsize in secs:
            if vaddr <= rva < vaddr + max(vsize, rsize):
                return roff + (rva - vaddr)
        return None
    eo = r2o(exp_rva)
    nfuncs = u32(data, eo + 20)
    nnames = u32(data, eo + 24)
    addr_of_funcs = r2o(u32(data, eo + 28))
    addr_of_names = r2o(u32(data, eo + 32))
    addr_of_ord = r2o(u32(data, eo + 36))
    funcs = {}
    for i in range(nnames):
        name_rva = u32(data, addr_of_names + i*4)
        no = r2o(name_rva)
        end = data.index(b"\0", no)
        name = data[no:end].decode("latin1")
        ord_idx = u16(data, addr_of_ord + i*2)
        funcs[name] = u32(data, addr_of_funcs + ord_idx*4)
    for name, rva in sorted(funcs.items()):
        if not want or name in want:
            print(f"{name:40} rva={rva:#08x}  abs={base + rva:#010x}")

if __name__ == "__main__":
    main()
