#!/usr/bin/env python
"""
Loader for TLBIN files (MCLF format)

Layout:
   [HDR + textsz] - text, mapped at txt addr
   [datasz]       - data, mapped at data addr
   [0 bytes]      - bss, mapped at data addr + datasz ?
   [521 bytes]    - sig, not mapped
"""
import struct

class Error(Exception) :
    pass

class Readable(object) :
    def get(self, fmt, pos=None) :
        if pos is not None :
            self.f.seek(pos)
        sz = struct.calcsize(fmt)
        dat = self.f.read(sz)
        if len(dat) != sz :
            raise Error("short read")
        return struct.unpack('<' + fmt, dat)
    def __str__(self) :
        def fmt(x) :
            if isinstance(x, int) :
                return '0x%x' % x
            else :
                return repr(x)
        nms = self.__fields__.split(',')
        fs = ','.join('%s=%s' % (nm, fmt(getattr(self, nm))) for nm in nms)
        return '[%s %s]' % (self.__class__.__name__, fs)
    __repr__ = __str__

class Segment(Readable) :
    __fields__ = 'start,len'
    def __init__(self, f) :
        self.f = f
        self.load()
    def load(self) :
        self.start, self.len = self.get('II')

class MCLF(Readable) :
    __fields__ = 'mag,vmag,vmin,flags,memType,serviceType,ninstances,uuid,driverId,numThreads,text,data,bssLen,entry,serviceVersion'
    MAG = 'MCLF'

    def __init__(self, fn) :
        self.f = file(fn, 'rb')
        self.load()

    def getSegment(self) :
        return Segment(self.f)

    def loadV1(self) :
        self.flags,self.memType,self.serviceType,self.ninstances = self.get('IIII')
        self.uuid = self.get('16s')[0].encode('hex')
        self.driverId,self.numThreads = self.get('II')
        self.text = self.getSegment()
        self.data = self.getSegment()
        self.bssLen,self.entry = self.get('II')
        self.serviceVersion = None

    def loadV2(self) :
        self.serviceVersion = self.get('I')[0]

    def load(self) :
        self.mag,self.vmin,self.vmag = self.get("4sHH")
        if self.mag != self.MAG :
            raise Error("bad magic")
        if self.vmag < 1 :
            raise Error("unsupported version")
        if self.vmag >= 1 :
            self.loadV1()
        if self.vmag >= 2 :
            self.loadV2()

def test() :
    import sys
    def sz(f) :
        f.seek(0, 2)
        return f.tell()
    for fn in sys.argv[1:] :
        print fn
        m = MCLF(fn) 
        print m
        #print 'sz=%x xtra=%x' % (sz(m.f), sz(m.f) - (m.text.len + m.data.len))
        print

if __name__ == '__main__' :
    test()