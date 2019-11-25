#!/usr/bin/env python
"""
Convert an MCLF file to a fake elf file so we can use normal tools with it.
"""

import sys, struct
from mclf import *

def writefmt(f, fmt, *args) :
    f.write(struct.pack(fmt, *args))

class EHdr(object) :
    def __init__(self, entry, phnum) :
        self.e_ident = '\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.e_type = 0x2
        self.e_machine = 0x28
        self.e_version = 0x1
        self.e_entry = entry
        self.e_phoff = 0x34
        self.e_shoff = 0
        self.e_flags = 0x4000002
        self.e_ehsize = 0x34
        self.e_phentsize = 0x20
        self.e_phnum = phnum
        self.e_shentsize = 0x28
        self.e_shnum = 0
        self.e_shstrndx = 0

    def write(self, f) :
        f.write(self.e_ident) 
        writefmt(f, '<HHIIIIIHHHHHH', self.e_type, 
                self.e_machine, 
                self.e_version, 
                self.e_entry, 
                self.e_phoff, 
                self.e_shoff, 
                self.e_flags, 
                self.e_ehsize, 
                self.e_phentsize, 
                self.e_phnum, 
                self.e_shentsize, 
                self.e_shnum, 
                self.e_shstrndx)

class PHdr(object) :
    def __init__(self, typ, off, vaddr, paddr, sz, vsz, flags, align) :
        self.p_type = typ
        self.p_offset = off
        self.p_vaddr = vaddr
        self.p_paddr = paddr
        self.p_filesz = sz
        self.p_memsz = vsz
        self.p_flags = flags
        self.p_align = align
    def write(self, f) :
        return writefmt(f, '<IIIIIIII',
            self.p_type,
            self.p_offset,
            self.p_vaddr,
            self.p_paddr,
            self.p_filesz,
            self.p_memsz,
            self.p_flags,
            self.p_align)

class Elf(object) :
    def __init__(self, entry) :
        self.entry = entry
        self.phdrs = []
        self.data = []
        self.dOff = 0

    def addPhdr(self, typ, vaddr, vsz, dat, flags) :
        p = PHdr(typ, self.dOff, vaddr, vaddr, len(dat), vsz, flags, 1<<12)
        self.phdrs.append(p)
        self.data.append(dat)
        self.dOff += len(dat)

    def write(self, f) :
        e = EHdr(self.entry, len(self.phdrs))
        e.e_phoff = self.e_ehsize = 0x34
        e.write(f)

        off = e.e_ehsize + e.e_phentsize * len(self.phdrs)
        for p in self.phdrs :
            p.p_offset += off
            p.write(f)

        for d in self.data :
            f.write(d)
    
def proc(fn) :
    m = MCLF(fn)
    m.f.seek(0)
    e = Elf(m.entry)
    if m.text.len :
        d = m.f.read(m.text.len)
        e.addPhdr(1, m.text.start, m.text.len, d, 5)
    if m.data.len or m.bssLen :
        d = m.f.read(m.data.len)
        e.addPhdr(1, m.data.start, m.data.len + m.bssLen, d, 6)
    d = m.f.read(521)
    e.addPhdr(0, 0xffff0000, 521, d, 4)

    outFn = fn + '.elf'
    with file(outFn, 'wb') as f :
        e.write(f)

    pos = m.f.tell()
    m.f.seek(0, 2)
    delta = m.f.tell() - pos
    assert delta == 0  # no data left in original file!

for arg in sys.argv[1:] :
    proc(arg)