import struct, zipfile, sys, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = os.environ.get("DEX_APK", os.path.join(ROOT, "module", "hook", "PenBridge-Hook-v4.1.3-TB320FC.apk"))
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
PSIZE, POFF = struct.unpack_from('<II', d, 72)
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
    fields.append((types[c], types[t], strings[n]))
methods = []
for i in range(MSIZE):
    c, p, n = struct.unpack_from('<HHI', d, MOFF + 8*i)
    methods.append((types[c], strings[n]))

FORMATS = {
    0x00: ('nop', '10x'), 0x01: ('move', '12x'), 0x02: ('move/from16', '22x'),
    0x03: ('move/16', '32x'), 0x04: ('move-wide', '12x'), 0x05: ('move-wide/from16', '22x'),
    0x06: ('move-wide/16', '32x'), 0x07: ('move-object', '12x'), 0x08: ('move-object/from16', '22x'),
    0x09: ('move-object/16', '32x'), 0x0a: ('move-result', '11x'), 0x0b: ('move-result-wide', '11x'),
    0x0c: ('move-result-object', '11x'), 0x0d: ('move-exception', '11x'),
    0x0e: ('return-void', '10x'), 0x0f: ('return', '11x'), 0x10: ('return-wide', '11x'),
    0x11: ('return-object', '11x'), 0x12: ('const/4', '11n'), 0x13: ('const/16', '21s'),
    0x14: ('const', '31i'), 0x15: ('const/high16', '21h'), 0x16: ('const-wide/16', '21s'),
    0x17: ('const-wide/32', '31i'), 0x18: ('const-wide', '51l'), 0x19: ('const-wide/high16', '21h'),
    0x1a: ('const-string', '21c'), 0x1b: ('const-string/jumbo', '31c'),
    0x1c: ('const-class', '21c'), 0x1d: ('monitor-enter', '11x'), 0x1e: ('monitor-exit', '11x'),
    0x1f: ('check-cast', '21c'), 0x20: ('instance-of', '22c'), 0x21: ('array-length', '12x'),
    0x22: ('new-instance', '21c'), 0x23: ('new-array', '22c'), 0x24: ('filled-new-array', '35c'),
    0x25: ('filled-new-array/range', '3rc'), 0x26: ('fill-array-data', '31t'),
    0x27: ('throw', '11x'), 0x28: ('goto', '10t'), 0x29: ('goto/16', '20t'),
    0x2a: ('goto/32', '30t'), 0x2b: ('packed-switch', '31t'), 0x2c: ('sparse-switch', '31t'),
    0x2d: ('cmpl-float', '23x'), 0x2e: ('cmpg-float', '23x'), 0x2f: ('cmpl-double', '23x'),
    0x30: ('cmpg-double', '23x'), 0x31: ('cmp-long', '23x'),
    0x32: ('if-eq', '22t'), 0x33: ('if-ne', '22t'), 0x34: ('if-lt', '22t'),
    0x35: ('if-ge', '22t'), 0x36: ('if-gt', '22t'), 0x37: ('if-le', '22t'),
    0x38: ('if-eqz', '21t'), 0x39: ('if-nez', '21t'), 0x3a: ('if-ltz', '21t'),
    0x3b: ('if-gez', '21t'), 0x3c: ('if-gtz', '21t'), 0x3d: ('if-lez', '21t'),
}
for i in range(0x3e, 0x6e):
    pass
for base, names in (
    (0x44, ['aget', 'aget-wide', 'aget-object', 'aget-boolean', 'aget-byte', 'aget-char', 'aget-short']),
    (0x4b, ['aput', 'aput-wide', 'aput-object', 'aput-boolean', 'aput-byte', 'aput-char', 'aput-short']),
    (0x52, ['iget', 'iget-wide', 'iget-object', 'iget-boolean', 'iget-byte', 'iget-char', 'iget-short']),
    (0x59, ['iput', 'iput-wide', 'iput-object', 'iput-boolean', 'iput-byte', 'iput-char', 'iput-short']),
    (0x60, ['sget', 'sget-wide', 'sget-object', 'sget-boolean', 'sget-byte', 'sget-char', 'sget-short']),
    (0x67, ['sput', 'sput-wide', 'sput-object', 'sput-boolean', 'sput-byte', 'sput-char', 'sput-short']),
):
    for k, nm in enumerate(names):
        FORMATS[base + k] = (nm, '22c')
    FORMATS[base + 7] = (names[0].replace('get', 'get') + '', '22c')  # placeholder, ignore
for base, names in (
    (0x6e, ['invoke-virtual', 'invoke-super', 'invoke-direct', 'invoke-static', 'invoke-interface']),
    (0x74, ['invoke-virtual/range', 'invoke-super/range', 'invoke-direct/range', 'invoke-static/range', 'invoke-interface/range']),
):
    for k, nm in enumerate(names):
        FORMATS[base + k] = (nm, '35c' if base == 0x6e else '3rc')
for k, nm in enumerate(['neg-int', 'not-int', 'neg-long', 'not-long', 'neg-float', 'neg-double',
                       'int-to-long', 'int-to-float', 'int-to-double', 'long-to-int', 'long-to-float',
                       'long-to-double', 'float-to-int', 'float-to-long', 'float-to-double',
                       'double-to-int', 'double-to-long', 'double-to-float', 'int-to-byte', 'int-to-char',
                       'int-to-short']):
    FORMATS[0x7b + k] = (nm, '12x')
for k, nm in enumerate(['add-int', 'sub-int', 'mul-int', 'div-int', 'rem-int', 'and-int', 'or-int', 'xor-int', 'shl-int', 'shr-int', 'ushr-int',
                       'add-long', 'sub-long', 'mul-long', 'div-long', 'rem-long', 'and-long', 'or-long', 'xor-long', 'shl-long', 'shr-long', 'ushr-long',
                       'add-float', 'sub-float', 'mul-float', 'div-float', 'rem-float',
                       'add-double', 'sub-double', 'mul-double', 'div-double', 'rem-double']):
    FORMATS[0x90 + k] = (nm, '23x')
for k, nm in enumerate(['add-int/2addr', 'sub-int/2addr', 'mul-int/2addr', 'div-int/2addr', 'rem-int/2addr', 'and-int/2addr', 'or-int/2addr', 'xor-int/2addr', 'shl-int/2addr', 'shr-int/2addr', 'ushr-int/2addr',
                       'add-long/2addr', 'sub-long/2addr', 'mul-long/2addr', 'div-long/2addr', 'rem-long/2addr', 'and-long/2addr', 'or-long/2addr', 'xor-long/2addr', 'shl-long/2addr', 'shr-long/2addr', 'ushr-long/2addr',
                       'add-float/2addr', 'sub-float/2addr', 'mul-float/2addr', 'div-float/2addr', 'rem-float/2addr',
                       'add-double/2addr', 'sub-double/2addr', 'mul-double/2addr', 'div-double/2addr', 'rem-double/2addr']):
    FORMATS[0xb0 + k] = (nm, '12x')
for k, nm in enumerate(['add-int/lit16', 'rsub-int', 'mul-int/lit16', 'div-int/lit16', 'rem-int/lit16', 'and-int/lit16', 'or-int/lit16', 'xor-int/lit16']):
    FORMATS[0xd0 + k] = (nm, '22s')
for k, nm in enumerate(['add-int/lit8', 'rsub-int/lit8', 'mul-int/lit8', 'div-int/lit8', 'rem-int/lit8', 'and-int/lit8', 'or-int/lit8', 'xor-int/lit8',
                       'shl-int/lit8', 'shr-int/lit8', 'ushr-int/lit8']):
    FORMATS[0xd8 + k] = (nm, '22b')
for k, nm in enumerate(['iget-quick', 'iget-wide-quick', 'iget-object-quick', 'iput-quick', 'iput-wide-quick', 'iput-object-quick',
                       'invoke-virtual-quick', 'invoke-virtual/range-quick']):
    FORMATS[0xf2 + k] = (nm, '22c')

def signed(v, bits):
    if v & (1 << (bits-1)):
        return v - (1 << bits)
    return v

def decode(units, start, end):
    pc = start
    out = []
    while pc < end:
        u = units[pc]
        op = u & 0xff
        name, fmt = FORMATS.get(op, ('op-0x%02x' % op, '10x'))
        hi = u >> 8
        txt = ''
        length = 1
        if fmt == '10x':
            pass
        elif fmt == '12x':
            txt = 'v%d, v%d' % (hi & 0xf, hi >> 4)
        elif fmt == '11n':
            txt = 'v%d, #%d' % (hi & 0xf, signed(hi >> 4, 4))
        elif fmt == '11x':
            txt = 'v%d' % hi
        elif fmt == '10t':
            txt = '-> %d' % (pc + signed(hi, 8))
        elif fmt == '20t':
            off = units[pc+1]
            txt = '-> %d' % (pc + signed(off, 16)); length = 2
        elif fmt == '30t':
            off = units[pc+1] | (units[pc+2] << 16)
            txt = '-> %d' % (pc + signed(off, 32)); length = 3
        elif fmt == '21s':
            txt = 'v%d, #%d' % (hi, signed(units[pc+1], 16)); length = 2
        elif fmt == '21h':
            txt = 'v%d, #0x%x' % (hi, signed(units[pc+1], 16) << 16); length = 2
        elif fmt == '21c':
            idx = units[pc+1]
            extra = ''
            if name in ('const-string',):
                extra = '  ; "%s"' % strings[idx] if idx < len(strings) else ''
            elif name in ('const-class', 'check-cast', 'new-instance', 'instance-of'):
                extra = '  ; %s' % (types[idx] if idx < len(types) else idx)
            txt = 'v%d, @%d%s' % (hi, idx, extra); length = 2
        elif fmt == '22c':
            idx = units[pc+1]
            ref = ''
            if idx < len(fields):
                ref = '  ; %s->%s:%s' % fields[idx]
            txt = 'v%d, v%d, @%d%s' % (hi & 0xf, hi >> 4, idx, ref); length = 2
        elif fmt == '22x':
            txt = 'v%d, v%d' % (hi, units[pc+1]); length = 2
        elif fmt == '32x':
            v = units[pc+1] | (units[pc+2] << 16)
            txt = 'v%d, v%d' % (hi, v); length = 3
        elif fmt == '31i':
            v = units[pc+1] | (units[pc+2] << 16)
            txt = 'v%d, #%d' % (hi, signed(v, 32)); length = 3
        elif fmt == '51l':
            v = units[pc+1] | (units[pc+2] << 16) | (units[pc+3] << 32) | (units[pc+4] << 48)
            txt = 'v%d, #%dL' % (hi, signed(v, 64)); length = 5
        elif fmt == '31c':
            idx = units[pc+1] | (units[pc+2] << 16)
            extra = '  ; "%s"' % strings[idx] if idx < len(strings) else ''
            txt = 'v%d, @%d%s' % (hi, idx, extra); length = 3
        elif fmt == '31t':
            v = units[pc+1] | (units[pc+2] << 16)
            txt = 'v%d, -> %d' % (hi, pc + signed(v, 32)); length = 3
        elif fmt == '22t':
            txt = 'v%d, v%d, -> %d' % (hi & 0xf, hi >> 4, pc + signed(units[pc+1], 16)); length = 2
        elif fmt == '21t':
            txt = 'v%d, -> %d' % (hi, pc + signed(units[pc+1], 16)); length = 2
        elif fmt == '23x':
            txt = 'v%d, v%d, v%d' % (hi, units[pc+1] & 0xff, units[pc+1] >> 8); length = 2
        elif fmt == '22s':
            txt = 'v%d, v%d, #%d' % (hi & 0xf, hi >> 4, signed(units[pc+1], 16)); length = 2
        elif fmt == '22b':
            txt = 'v%d, v%d, #%d' % (hi, units[pc+1] & 0xff, signed(units[pc+1] >> 8, 8)); length = 2
        elif fmt in ('35c', '3rc'):
            idx = units[pc+1]
            if fmt == '35c':
                count = hi >> 4
                regs = [hi & 0xf, units[pc+2] & 0xf, units[pc+2] >> 4, units[pc+3] & 0xf, units[pc+3] >> 4][:count]
                txt = '{%s}, @%d  ; %s' % (', '.join('v%d' % r for r in regs), idx,
                                           (methods[idx] if idx < len(methods) else ''))
                length = 3
            else:
                count = hi
                start_reg = units[pc+2]
                txt = '{v%d..v%d}, @%d  ; %s' % (start_reg, start_reg + count - 1, idx,
                                                 (methods[idx] if idx < len(methods) else ''))
                length = 3
        out.append((pc, name, txt))
        pc += length
    return out

TARGET = sys.argv[1] if len(sys.argv) > 1 else 'DeviceGate'

def iter_class_methods():
    for i in range(CSIZE):
        off = COFF + 32 * i
        class_idx = struct.unpack_from('<I', d, off)[0]
        cname = types[class_idx]
        class_data_off = struct.unpack_from('<I', d, off + 24)[0]
        if class_data_off == 0:
            continue
        p = class_data_off
        sf, p = uleb128(d, p); inf, p = uleb128(d, p)
        dm, p = uleb128(d, p); vm, p = uleb128(d, p)
        for _ in range(sf):
            _, p = uleb128(d, p); _, p = uleb128(d, p)
        for _ in range(inf):
            _, p = uleb128(d, p); _, p = uleb128(d, p)
        for kind, count in (('direct', dm), ('virtual', vm)):
            midx = 0
            for _ in range(count):
                diff, p = uleb128(d, p); midx += diff
                acc, p = uleb128(d, p)
                code_off, p = uleb128(d, p)
                yield cname, kind, midx, code_off

if TARGET == '@callers':
    needle = sys.argv[2]
    for cname, kind, midx, code_off in iter_class_methods():
        if code_off == 0:
            continue
        regs, ins, outs, tries, dbg, insns_size = struct.unpack_from('<HHHHII', d, code_off)
        units = struct.unpack_from('<%dH' % insns_size, d, code_off + 16)
        hits = [(pc, name, txt) for pc, name, txt in decode(units, 0, insns_size)
                if name.startswith('invoke') and needle in txt]
        if hits:
            print("### %s :: %s (%s)" % (cname, methods[midx][1], kind))
            for pc, name, txt in hits:
                print("      %5d %s %s" % (pc, name, txt))
    raise SystemExit(0)

if TARGET == '@refs':
    needle = sys.argv[2].lower()
    for cname, kind, midx, code_off in iter_class_methods():
        if code_off == 0:
            continue
        regs, ins, outs, tries, dbg, insns_size = struct.unpack_from('<HHHHII', d, code_off)
        units = struct.unpack_from('<%dH' % insns_size, d, code_off + 16)
        hits = [(pc, name, txt) for pc, name, txt in decode(units, 0, insns_size)
                if name in ('const-string', 'const-string/jumbo') and needle in txt.lower()]
        if hits:
            print("### %s :: %s (%s)" % (cname, methods[midx][1], kind))
            for pc, name, txt in hits:
                print("      %5d %s" % (pc, txt))
    raise SystemExit(0)

for i in range(CSIZE):
    off = COFF + 32*i
    class_idx = struct.unpack_from('<I', d, off)[0]
    cname = types[class_idx]
    if TARGET not in cname:
        continue
    class_data_off = struct.unpack_from('<I', d, off + 24)[0]
    static_values_off = struct.unpack_from('<I', d, off + 28)[0]
    print("### class", cname, "static_values_off=0x%x" % static_values_off)
    if static_values_off:
        raw = d[static_values_off:static_values_off + 60]
        print("    static values raw:", raw.hex())
        print("    ascii:", "".join(chr(c) if 32 <= c < 127 else '.' for c in raw))
    if class_data_off == 0:
        continue
    p = class_data_off
    sf, p = uleb128(d, p); inf, p = uleb128(d, p); dm, p = uleb128(d, p); vm, p = uleb128(d, p)
    for kind, count in (('static-field', sf), ('instance-field', inf)):
        fidx = 0
        for _ in range(count):
            diff, p = uleb128(d, p); fidx += diff
            acc, p = uleb128(d, p)
    for kind, count in (('direct', dm), ('virtual', vm)):
        midx = 0
        for _ in range(count):
            diff, p = uleb128(d, p); midx += diff
            acc, p = uleb128(d, p)
            code_off, p = uleb128(d, p)
            mc, mn = methods[midx]
            print(f"--- method {kind} {mn} code=0x{code_off:x}")
            if code_off == 0:
                continue
            regs, ins, outs, tries, dbg, insns_size = struct.unpack_from('<HHHHII', d, code_off)
            base = code_off + 16
            units = struct.unpack_from('<%dH' % insns_size, d, base)
            for pc, name, txt in decode(units, 0, insns_size):
                print(f"    {pc:5d}: {name:24s} {txt}")
