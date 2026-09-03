#!/usr/bin/env python3
"""peinfo.py — parsea un PE32 y extrae cadenas ASCII/UTF-16 por sección.
Uso: peinfo.py <archivo> [--strings-words "licencia,llave,key"] [--strings-min 5] [--section .rdata]
Imprime: cabecera PE, secciones (RVA/VOffset), entry, y cadenas que contengan las palabras clave."""
import sys, re, struct, os

def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u16(b, o): return struct.unpack_from("<H", b, o)[0]

def main():
    path = sys.argv[1]
    words = None
    section_filter = None
    minlen = 5
    args = sys.argv[2:]
    i = 0
    while i < len(args):
        if args[i] == "--strings-words":
            words = [w.lower() for w in args[i+1].split(",")]; i += 2
        elif args[i] == "--section":
            section_filter = args[i+1]; i += 2
        elif args[i] == "--strings-min":
            minlen = int(args[i+1]); i += 2
        else:
            i += 1
    data = open(path, "rb").read()
    if data[:2] != b"MZ": print("no PE"); return
    pe = u32(data, 0x3C)
    assert data[pe:pe+4] == b"PE\0\0"
    machine = u16(data, pe+4)
    nsec = u16(data, pe+6)
    opt = pe + 24
    magic = u16(data, opt)
    is_pe32 = magic == 0x10B
    entry_rva = u32(data, opt+16) if is_pe32 else u32(data, opt+16)
    image_base = u32(data, opt+28) if is_pe32 else u64(data, opt+24)
    print(f"=== {os.path.basename(path)} ===")
    print(f"machine={hex(machine)} pe32={is_pe32} sections={nsec} entry_rva={hex(entry_rva)} imageBase={hex(image_base)}")
    # directory: import table rva = opt+104 (PE32)
    imp_rva = u32(data, opt+104) if is_pe32 else 0
    secs = []
    off = opt + (224 if is_pe32 else 240)
    for s in range(nsec):
        name = data[off+s*40: off+s*40+8].rstrip(b"\0").decode("latin1")
        vsize = u32(data, off+s*40+8); vaddr = u32(data, off+s*40+12)
        rsize = u32(data, off+s*40+16); roff = u32(data, off+s*40+20)
        secs.append((name, vaddr, vsize, roff, rsize))
    print(f"{'sec':10} {'RVA':>10} {'VSize':>10} {'RawOff':>10} {'RawSz':>10}")
    for name, vaddr, vsize, roff, rsize in secs:
        print(f"{name:10} {vaddr:>#10x} {vsize:>10} {roff:>#10x} {rsize:>10}")
    print(f"import_dir_rva={hex(imp_rva)}")
    if not words: return
    # extraer cadenas
    print("\n=== strings ===")
    for name, vaddr, vsize, roff, rsize in secs:
        if section_filter and name != section_filter: continue
        raw = data[roff:roff+rsize]
        for enc in ("ascii", "utf16"):
            if enc == "ascii":
                found = [(m.start(), m.group().decode("latin1")) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, raw)]
            else:
                found = [(m.start(), m.group().decode("utf-16-le")) for m in re.finditer(rb"(?:[\x20-\x7e]\x00){%d,}" % minlen, raw)]
            for foff, s in found:
                low = s.lower()
                if any(w in low for w in words):
                    print(f"[{name}] {vaddr + (foff - roff):#010x} {enc:6} {s[:160]!r}")

if __name__ == "__main__":
    main()
