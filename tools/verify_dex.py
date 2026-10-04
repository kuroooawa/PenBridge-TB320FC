"""Verify the patched Hook dex: checksum/signature, patch sites, and device gate code."""
import hashlib
import os
import struct
import sys
import zipfile
import zlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = sys.argv[1] if len(sys.argv) > 1 else \
    os.path.join(ROOT, "module", "hook", "PenBridge-Hook.apk")

d = zipfile.ZipFile(APK).read("classes.dex")

# header checksum / signature
adler = struct.unpack_from("<I", d, 8)[0]
sha = d[12:32]
print("file_size field = %d, actual = %d" % (struct.unpack_from("<I", d, 32)[0], len(d)))
print("adler32 stored   = 0x%08x, computed = 0x%08x  %s"
      % (adler, zlib.adler32(d[12:]) & 0xFFFFFFFF, "OK" if adler == (zlib.adler32(d[12:]) & 0xFFFFFFFF) else "BAD"))
print("sha1 stored      = %s, computed = %s  %s"
      % (sha.hex()[:16], hashlib.sha1(d[32:]).hexdigest()[:16],
         "OK" if sha == hashlib.sha1(d[32:]).digest() else "BAD"))

# string table sanity (sortedness preserved)
SIZE, SOFF = struct.unpack_from("<II", d, 56)
TSIZE, TOFF = struct.unpack_from("<II", d, 64)
MSIZE, MOFF = struct.unpack_from("<II", d, 88)


def uleb(buf, off):
    r = 0
    s = 0
    while True:
        b = buf[off]
        off += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            return r, off
        s += 7


strings = []
for i in range(SIZE):
    off = struct.unpack_from("<I", d, SOFF + 4 * i)[0]
    n, p = uleb(d, off)
    strings.append(d[p:p + n].decode("utf-8", "replace"))
types = [strings[struct.unpack_from("<I", d, TOFF + 4 * i)[0]] for i in range(TSIZE)]
methods = []
for i in range(MSIZE):
    c, p, n = struct.unpack_from("<HHI", d, MOFF + 8 * i)
    methods.append((types[c], strings[n]))
bad = [(i, strings[i - 1], strings[i]) for i in range(1, len(strings)) if strings[i - 1] > strings[i]]
print("string_ids sorted: %s (%d violations)" % ("OK" if not bad else "VIOLATED", len(bad)))
for i, prev, cur in bad[:6]:
    print("   idx %d: %s > %s" % (i, prev.encode('unicode_escape'), cur.encode('unicode_escape')))
print("strings[703] = %r   strings[704] = %r" % (strings[703], strings[704]))

CSIZE, COFF = struct.unpack_from("<II", d, 96)
found = {}
for i in range(CSIZE):
    off = COFF + 32 * i
    cname = types[struct.unpack_from("<I", d, off)[0]]
    cdo = struct.unpack_from("<I", d, off + 24)[0]
    if cdo == 0:
        continue
    p = cdo
    sf, p = uleb(d, p)
    inf, p = uleb(d, p)
    dm, p = uleb(d, p)
    vm, p = uleb(d, p)
    for _ in range(sf + inf):
        _, p = uleb(d, p)
        _, p = uleb(d, p)
    for count in (dm, vm):
        midx = 0
        for _ in range(count):
            diff, p = uleb(d, p)
            midx += diff
            _, p = uleb(d, p)
            coff, p = uleb(d, p)
            key = (cname, methods[midx][1])
            if key[1] in ("supported", "refreshPenCard", "collectTextViews", "onUEvent"):
                found.setdefault(key, coff)

OPS = {0x12: "const/4", 0x0F: "return", 0x0E: "return-void", 0x1A: "const-string",
       0x6E: "invoke-virtual", 0x6F: "invoke-super", 0x70: "invoke-direct",
       0x71: "invoke-static", 0x72: "invoke-interface"}
for (cname, mname), coff in sorted(found.items(), key=lambda kv: kv[1]):
    units = struct.unpack_from("<8H", d, coff + 16)
    desc = []
    for u in units[:4]:
        op = u & 0xFF
        name = OPS.get(op, "op-0x%02x" % op)
        extra = ""
        if op == 0x1A:
            extra = "  ; %r" % strings[units[1]]
        if op in (0x6E, 0x6F, 0x70, 0x71, 0x72):
            extra = "  ; %s->%s" % methods[units[1]]
        desc.append("%s(%04x)%s" % (name, u, extra if extra else ""))
    print("%-28s %-18s code=0x%x" % (cname.split("/")[-1], mname, coff))
    for line in desc:
        print("      ", line)
