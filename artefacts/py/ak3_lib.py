#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ak3_lib.py — libreria comun de parseo PE + desensamblado lineal para AppKeyX.dll
y contabilidad_i.exe (solo lectura). Reutilizada por ak3_*.py."""
import struct
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

DLL = "/mnt/c/Program Files (x86)/Compac/Contabilidad/AppKeyX.dll"
EXE = "/mnt/c/Program Files (x86)/Compac/Contabilidad/contabilidad_i.exe"


class PE:
    def __init__(self, path):
        self.path = path
        self.d = open(path, "rb").read()
        assert self.d[:2] == b"MZ", path
        pe = struct.unpack_from("<I", self.d, 0x3C)[0]
        self.pe = pe
        self.nsec = struct.unpack_from("<H", self.d, pe + 6)[0]
        opt = pe + 24
        self.opt = opt
        magic = struct.unpack_from("<H", self.d, opt)[0]
        self.optsz = 224 if magic == 0x10B else 240
        self.is64 = magic == 0x20B
        self.imagebase = struct.unpack_from("<I", self.d, opt + 28)[0]
        self.entry = struct.unpack_from("<I", self.d, opt + 16)[0]
        secs = []
        off = opt + self.optsz
        for s in range(self.nsec):
            name = self.d[off + s*40: off + s*40 + 8].rstrip(b"\0").decode("latin1")
            vsize = struct.unpack_from("<I", self.d, off + s*40 + 8)[0]
            vaddr = struct.unpack_from("<I", self.d, off + s*40 + 12)[0]
            rsize = struct.unpack_from("<I", self.d, off + s*40 + 16)[0]
            roff = struct.unpack_from("<I", self.d, off + s*40 + 20)[0]
            secs.append((name, vaddr, vsize, roff, rsize))
        self.secs = secs

    def r2o(self, rva):
        for n, va, vs, ro, rs in self.secs:
            if va <= rva < va + max(vs, rs):
                return ro + (rva - va)
        return None

    def o2r(self, off):
        for n, va, vs, ro, rs in self.secs:
            if ro <= off < ro + max(vs, rs):
                return va + (off - ro)
        return None

    def sec_of(self, rva):
        for n, va, vs, ro, rs in self.secs:
            if va <= rva < va + max(vs, rs):
                return n
        return "?"

    def raw(self, rva, n):
        o = self.r2o(rva)
        if o is None:
            return None
        return self.d[o:o + n]

    def strz(self, rva, maxlen=200):
        o = self.r2o(rva)
        if o is None:
            return None
        end = self.d.find(b"\0", o)
        if end < 0:
            return None
        b = self.d[o:end][:maxlen]
        return b.decode("latin1", "replace")

    def u16z(self, rva, maxlen=200):
        o = self.r2o(rva)
        if o is None:
            return None
        end = o
        while end + 1 < len(self.d) and not (self.d[end] == 0 and self.d[end+1] == 0):
            end += 2
        b = self.d[o:end][:maxlen*2]
        try:
            return b.decode("utf-16-le")
        except Exception:
            return None

    def imports(self):
        """-> {name: (dll, slot_rva)} desde la dir table 1 (IAT/ILT)."""
        imp_rva = struct.unpack_from("<I", self.d, self.opt + 96 + 1*8)[0]
        out = {}
        if not imp_rva:
            return out
        off = self.r2o(imp_rva)
        if off is None:
            return out
        while True:
            ilt = struct.unpack_from("<I", self.d, off)[0]
            name_rva = struct.unpack_from("<I", self.d, off + 12)[0]
            ft = struct.unpack_from("<I", self.d, off + 16)[0]
            if name_rva == 0:
                break
            noff = self.r2o(name_rva)
            end = self.d.index(b"\0", noff)
            dll = self.d[noff:end].decode("latin1")
            iat_rva = ilt if self.r2o(ilt) is not None else ft
            io = self.r2o(iat_rva)
            if io is not None:
                idx = 0
                while True:
                    v = struct.unpack_from("<I", self.d, io)[0]
                    if v == 0:
                        break
                    if v & 0x80000000:
                        fname = "ord#%d" % (v & 0xFFFF)
                    else:
                        hn = self.r2o(v & 0x7FFFFFFF)
                        e2 = self.d.index(b"\0", hn + 2)
                        fname = self.d[hn+2:e2].decode("latin1")
                    out[fname] = (dll, ft + idx*4)
                    io += 4
                    idx += 1
            off += 20
        return out


def disasm(pe, rva, nins_max=4000, stop_at_ret=True):
    """Desensamblado lineal desde rva; corta en el primer ret (si stop_at_ret)
    o al llegar a nins_max. Devuelve lista de insn capstone."""
    off = pe.r2o(rva)
    if off is None:
        return []
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    code = pe.d[off:off + nins_max*16]
    out = []
    for ins in md.disasm(code, rva):
        out.append(ins)
        if stop_at_ret and ins.mnemonic in ("ret", "retn", "retf", "iret") and ins.bytes not in (b"\xc3", b"\xc2"):
            pass
        if stop_at_ret and ins.mnemonic in ("ret", "retf"):
            break
        if len(out) >= nins_max:
            break
    return out


def rel_target(pe, ins):
    """Devuelve RVA destino si la insn salta/cae a un RVA del archivo."""
    m, op = ins.mnemonic, ins.op_str
    if m == "call":
        if op.startswith("0x"):
            try:
                t = int(op, 16)
                return t if pe.r2o(t) is not None else None
            except ValueError:
                return None
    return None


def mem_imm(pe, ins):
    """Si la insn referencia una direccion absoluta (memoria) del archivo,
    devuelve el RVA (imagen base +? ya en formato VA...). Los operandos
    tipo 0x415860 son VA absolutos = imagebase + rva. Convertimos a RVA."""
    out = []
    m, op = ins.mnemonic, ins.op_str
    s = op
    # operandos [0x....]  o inmediatos 0x....
    import re
    for tok in re.findall(r"(?:\[)?(0x[0-9a-fA-F]{6,8})(?:\])?", s):
        v = int(tok, 16)
        rva = v - pe.imagebase
        if 0 <= rva < len(pe.d) and pe.r2o(rva) is not None:
            out.append((rva, m, op))
    return out
