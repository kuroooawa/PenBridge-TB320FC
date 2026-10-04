import os, struct, zipfile, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = os.environ.get("DEX_APK", os.path.join(ROOT, "module", "hook", "PenBridge-Hook.apk"))
d = zipfile.ZipFile(APK).read('classes.dex')

def uleb128(buf, off):
    result = 0; shift = 0
    while True:
        b = buf[off]; off += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return result, off

SIZE, SOFF = struct.unpack_from('<II', d, 56)
TSIZE, TOFF = struct.unpack_from('<II', d, 64)
FSIZE, FOFF = struct.unpack_from('<II', d, 80)
MSIZE, MOFF = struct.unpack_from('<II', d, 88)
CSIZE, COFF = struct.unpack_from('<II', d, 96)

strings = []
for i in range(SIZE):
    off = struct.unpack_from('<I', d, SOFF + 4*i)[0]
    n, p = uleb128(d, off)
    strings.append(d[p:p+n].decode('utf-8', 'replace'))
types = [strings[struct.unpack_from('<I', d, TOFF + 4*i)[0]] for i in range(TSIZE)]
fields = []
for i in range(FSIZE):
    c, t, n = struct.unpack_from('<HHI', d, FOFF + 8*i)
    fields.append((types[c], strings[n]))
methods = []
for i in range(MSIZE):
    c, p, n = struct.unpack_from('<HHI', d, MOFF + 8*i)
    methods.append((types[c], strings[n]))

needle = sys.argv[1] if len(sys.argv) > 1 else 'LENOVO_PRODUCTS'
targets = {i for i, f in enumerate(fields) if needle in f[1]}
print("field indices:", {i: fields[i] for i in targets})

for i in range(CSIZE):
    off = COFF + 32*i
    class_idx = struct.unpack_from('<I', d, off)[0]
    cname = types[class_idx]
    class_data_off = struct.unpack_from('<I', d, off + 24)[0]
    if class_data_off == 0:
        continue
    p = class_data_off
    sf, p = uleb128(d, p); inf, p = uleb128(d, p); dm, p = uleb128(d, p); vm, p = uleb128(d, p)
    for _ in range(sf): _, p = uleb128(d, p); _, p = uleb128(d, p)
    for _ in range(inf): _, p = uleb128(d, p); _, p = uleb128(d, p)
    for kind, count in (('direct', dm), ('virtual', vm)):
        midx = 0
        for _ in range(count):
            diff, p = uleb128(d, p); midx += diff
            acc, p = uleb128(d, p)
            code_off, p = uleb128(d, p)
            if code_off == 0:
                continue
            insns_size = struct.unpack_from('<I', d, code_off + 12)[0]
            units = struct.unpack_from('<%dH' % insns_size, d, code_off + 16)
            hits = []
            for pc in range(len(units) - 1):
                op = units[pc] & 0xff
                if op in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
                          0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d):
                    idx = units[pc + 1]
                    if idx in targets:
                        hits.append((pc, op, idx))
            if hits:
                print("### %s :: %s (%s) code=0x%x" % (cname, methods[midx][1], kind, code_off))
                for pc, op, idx in hits:
                    print("      pc=%d op=0x%02x field=%s" % (pc, op, fields[idx]))
