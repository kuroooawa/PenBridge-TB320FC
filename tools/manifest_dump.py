"""Dump the binary AndroidManifest.xml of an APK (package, versionCode, sdk levels, etc.)."""
import os
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
paths = sys.argv[1:] or [
    os.path.join(ROOT, "module", "hook", "PenBridge-Hook.apk"),
    os.path.join(ROOT, "dist", "PenBridge-Hook-v4.1.3-TB320FC.apk"),
]

ATTR_TYPES = {0x00: "null", 0x01: "ref", 0x02: "attr", 0x03: "string", 0x04: "float",
              0x05: "dim", 0x06: "frac", 0x10: "int", 0x11: "hex", 0x12: "bool"}


def parse(buf):
    xml_type, xml_hdr, xml_size = struct.unpack_from("<HHI", buf, 0)
    assert xml_type == 0x0003, "not AXML"
    p = xml_hdr
    ptype, phdr, psize = struct.unpack_from("<HHI", buf, p)
    assert ptype == 0x0001, "expected string pool"
    scount, stycount, flags, sstart, stystart = struct.unpack_from("<IIIII", buf, p + 8)
    utf8 = bool(flags & (1 << 8))
    offsets = [struct.unpack_from("<I", buf, p + phdr + 4 * i)[0] for i in range(scount)]
    strings = []
    for off in offsets:
        q = p + sstart + off
        if utf8:
            n = buf[q]; q += 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | buf[q]; q += 1
            m = buf[q]; q += 1
            if m & 0x80:
                m = ((m & 0x7F) << 8) | buf[q]; q += 1
            strings.append(buf[q:q + m].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", buf, q)[0]; q += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, q)[0]; q += 2
            strings.append(buf[q:q + 2 * n].decode("utf-16-le", "replace"))

    tags = []
    q = p + psize
    while q < len(buf) - 8:
        ctype, chdr, csize = struct.unpack_from("<HHI", buf, q)
        if ctype == 0x0102:  # START_ELEMENT
            name_idx = struct.unpack_from("<I", buf, q + 20)[0]
            attr_start, attr_size, attr_count = struct.unpack_from("<HHH", buf, q + 24)
            attrs = []
            for k in range(attr_count):
                a = q + 16 + attr_start + k * attr_size
                aname, araw, atyped, adata = struct.unpack_from("<IIII", buf, a + 4)
                key = strings[aname] if aname < len(strings) else "?%d" % aname
                if atyped == 0x03 and araw != 0xFFFFFFFF and araw < len(strings):
                    val = strings[araw]
                elif atyped == 0x12:
                    val = bool(adata)
                elif atyped == 0x10:
                    val = adata if adata < 0x80000000 else adata - (1 << 32)
                elif atyped == 0x01:
                    val = "ref(0x%08x)" % adata
                else:
                    val = "%s:%s" % (ATTR_TYPES.get(atyped, atyped), adata)
                attrs.append((key, val))
            tags.append((strings[name_idx] if name_idx < len(strings) else "?", attrs))
        if csize == 0:
            break
        q += csize
    return tags


for path in paths:
    axml = zipfile.ZipFile(path).read("AndroidManifest.xml")
    print("=" * 78)
    print(path.split("\\")[-1], "(%d bytes manifest)" % len(axml))
    for tag, attrs in parse(axml):
        if tag in ("manifest", "application", "uses-sdk"):
            print("  <%s" % tag)
            for k, v in attrs:
                print("      %s=%r" % (k, v))
            print("  >")
