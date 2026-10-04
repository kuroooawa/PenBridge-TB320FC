import struct, zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = os.environ.get("DEX_APK", os.path.join(ROOT, "module", "hook", "PenBridge-Hook-v4.1.3-TB320FC.apk"))
z = zipfile.ZipFile(APK)
d = z.read('classes.dex')
print("xposed_init:", z.read('assets/xposed_init').decode('utf-8','replace'))
try:
    print("scope.list:", z.read('META-INF/xposed/scope.list').decode('utf-8','replace'))
except KeyError:
    pass

def uleb128(buf, off):
    result = 0; shift = 0
    while True:
        b = buf[off]; off += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80): break
        shift += 7
    return result, off

def uleb128p1(buf, off):
    v, off = uleb128(buf, off)
    return v - 1, off

string_ids_size, string_ids_off = struct.unpack_from('<II', d, 56)
type_ids_size, type_ids_off = struct.unpack_from('<II', d, 64)
class_defs_size, class_defs_off = struct.unpack_from('<II', d, 96)
map_off = struct.unpack_from('<I', d, 52)[0]

strings = []
for i in range(string_ids_size):
    off = struct.unpack_from('<I', d, string_ids_off + 4*i)[0]
    n, p = uleb128(d, off)
    strings.append(d[p:p+n].decode('utf-8','replace'))
types = [strings[struct.unpack_from('<I', d, type_ids_off + 4*i)[0]] for i in range(type_ids_size)]

print("\n== classes ==")
for i in range(class_defs_size):
    off = class_defs_off + 32*i
    print("  ", types[struct.unpack_from('<I', d, off)[0]])

def read_encoded_value(buf, off, depth=0):
    """returns (value, newoff) where value is a python object"""
    b = buf[off]; off += 1
    vtype = b & 0x1f
    varg = b >> 5
    if vtype == 0x00:  # byte
        v = buf[off]; off += 1
    elif vtype == 0x02:
        v = int.from_bytes(buf[off:off+2], 'little', signed=True); off += 2
    elif vtype == 0x03:
        v = int.from_bytes(buf[off:off+2], 'little', signed=False); off += 2
    elif vtype == 0x04:
        n = varg + 1
        v = int.from_bytes(buf[off:off+n], 'little', signed=True); off += n
    elif vtype == 0x06:
        n = varg + 1
        v = int.from_bytes(buf[off:off+n], 'little', signed=True); off += n
    elif vtype == 0x10:
        n = varg + 1
        v = struct.unpack('<I', buf[off:off+4].ljust(4, b'\0'))[0]; off += n
    elif vtype == 0x11:
        n = varg + 1
        v = struct.unpack('<Q', buf[off:off+8].ljust(8, b'\0'))[0]; off += n
    elif vtype in (0x17, 0x18, 0x19, 0x1a, 0x15, 0x16):
        n = varg + 1
        v = int.from_bytes(buf[off:off+n], 'little', signed=False); off += n
        kind = {0x17: 'string', 0x18: 'type', 0x19: 'field', 0x1a: 'method',
                0x15: 'method_type', 0x16: 'method_handle'}[vtype]
        if kind == 'string' and v < len(strings):
            v = ('string', strings[v])
        else:
            v = (kind, v)
    elif vtype == 0x1b:  # array
        size, off = uleb128(buf, off)
        arr = []
        for _ in range(size):
            item, off = read_encoded_value(buf, off, depth+1)
            arr.append(item)
        v = arr
    elif vtype == 0x1c:  # annotation
        tidx, off = uleb128(buf, off)
        size, off = uleb128(buf, off)
        elems = {}
        for _ in range(size):
            nidx, off = uleb128(buf, off)
            val, off = read_encoded_value(buf, off, depth+1)
            elems[strings[nidx]] = val
        v = {'type': types[tidx] if tidx < len(types) else tidx, 'elems': elems}
    elif vtype == 0x1d:
        v = None
    elif vtype == 0x1e:
        v = bool(varg)
    elif vtype == 0x1f:
        v = None
    else:
        raise ValueError("unknown value type 0x%x at 0x%x" % (vtype, off-1))
    return v, off

# walk map
map_size = struct.unpack_from('<I', d, map_off)[0]
items = []
for i in range(map_size):
    t, unused, size, off = struct.unpack_from('<HHII', d, map_off + 4 + 12*i)
    items.append((t, size, off))
print("\n== map types ==")
for t, size, off in items:
    print("   type=0x%04x size=%d off=0x%x" % (t, size, off))
