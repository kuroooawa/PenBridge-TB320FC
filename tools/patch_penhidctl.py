"""Rename PenHidCtl.apk's app label and re-sign it (APK Signature Scheme v2).

Unlike the Hook APK, PenHidCtl's label is a literal string inside the (deflated) binary
AndroidManifest.xml, so the entry cannot be rewritten in place without shifting the following
entries. The APK is therefore repacked: same entry order, same compression method, stored entries
re-aligned to 4 bytes (classic zipalign rule), then signed with the v2 scheme.

Only the manifest differs from the upstream APK; every other entry is copied byte for byte.
"""
import hashlib
import importlib.util
import io
import os
import struct
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = os.environ.get("PENBRIDGE_UPSTREAM", os.path.join(ROOT, "upstream"))
DIST = os.environ.get("PENBRIDGE_DIST", os.path.join(ROOT, "dist"))
BUILD = os.environ.get("PENBRIDGE_BUILD", os.path.join(ROOT, "build"))
SRC_APK = os.environ.get("PENBRIDGE_SRC_HIDCTL", os.path.join(UPSTREAM, "PenHidCtl.apk"))
OUT_APK = os.environ.get("PENBRIDGE_OUT_HIDCTL",
                         os.path.join(DIST, "PenHidCtl-v4.1.3-TB320FC.apk"))

NEW_LABEL = "TB320FC - 手写笔系统服务"      # 上游槽位 21 个 UTF-16 字符
EXPECT_LABEL_PREFIX = "联想平板 Pro GT"
ALIGN = 4                                   # 对齐 ID：zipalign 使用的 0xD935
ALIGN_ID = 0xD935


import apk_v2 as ph


def repack(zin, patched):
    """Rebuild the zip with the same entry order/compression and 4-byte aligned stored entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zout:
        for info in zin.infolist():
            data = patched.get(info.filename)
            if data is None:
                data = zin.read(info.filename)
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = info.compress_type
            zi.external_attr = info.external_attr
            zi.internal_attr = info.internal_attr
            zi.create_system = info.create_system
            extra = info.extra
            if info.compress_type == zipfile.ZIP_STORED:
                pos = zout.fp.tell()
                base = pos + 30 + len(info.filename.encode("utf-8")) + len(extra)
                needed = (ALIGN - base % ALIGN) % ALIGN
                if needed:
                    extra = extra + struct.pack("<HH", ALIGN_ID, needed) + b"\x00" * needed
            zi.extra = extra
            zout.writestr(zi, data)
    return buf.getvalue()


def main():
    if not os.path.isfile(SRC_APK):
        raise SystemExit("upstream PenHidCtl.apk not found at %s" % SRC_APK)
    zin = zipfile.ZipFile(SRC_APK)

    manifest = bytearray(zin.read("AndroidManifest.xml"))
    slots, meta = ph.string_pool_slots(manifest, 8)
    print("AndroidManifest.xml string pool: %d strings, utf8=%s, sorted=%s"
          % (meta["count"], meta["utf8"], bool(meta["flags"] & 1)))
    hits = [i for i, s in enumerate(slots) if s["text"].startswith(EXPECT_LABEL_PREFIX)]
    if len(hits) != 1:
        raise SystemExit("expected exactly one upstream label string, found %d" % len(hits))
    idx = hits[0]
    written = ph.rewrite_pool_string(manifest, slots[idx], NEW_LABEL, "app label")
    print("P1 app label: pool[%d] %r (%d bytes) -> %r (%d bytes, slot %d)"
          % (idx, slots[idx]["text"], slots[idx]["data_len"], NEW_LABEL, written,
             slots[idx]["data_len"]))

    patched = {"AndroidManifest.xml": bytes(manifest)}
    raw = repack(zin, patched)

    # every other entry must be byte-identical to upstream
    with zipfile.ZipFile(io.BytesIO(raw)) as znew:
        names = znew.namelist()
        assert names == zin.namelist(), "entry order/name changed"
        for n in names:
            same = znew.read(n) == zin.read(n)
            print("   %-38s %s" % (n, "identical" if same else "patched"))
            if n != "AndroidManifest.xml" and not same:
                raise SystemExit("unexpected content change in %s" % n)

    # stored entries must be 4-byte aligned
    eocd_repacked = ph.find_eocd(raw)
    cd_size_r, cd_off_r = struct.unpack_from("<II", raw, eocd_repacked + 12)
    for e in ph.central_entries(raw, cd_off_r, cd_size_r):
        lh = ph.local_header(raw, e["local_off"])
        if lh["csize"] == lh["usize"]:       # stored
            print("   %-38s data_off=0x%-6x align4=%s" % (e["name"], lh["data_off"], lh["data_off"] % 4 == 0))
            if lh["data_off"] % 4:
                raise SystemExit("%s is not 4-byte aligned" % e["name"])

    # ---- v2 signing (the repacked APK has no signing block yet: block goes right before the CD)
    n, d, e, cert_der, spki_der = ph.load_keys(BUILD)

    eocd = ph.find_eocd(raw)
    cd_size, cd_off = struct.unpack_from("<II", raw, eocd + 12)
    block_start = cd_off                      # end of the entries = where the block goes
    prefix = raw[:block_start]
    cd = raw[cd_off:cd_off + cd_size]
    eocd_virtual = bytearray(raw[eocd:])
    struct.pack_into("<I", eocd_virtual, 16, block_start)
    digest = ph.apk_content_digest([prefix, cd, bytes(eocd_virtual)])
    signers = ph.build_v2_signers_block(digest, cert_der, spki_der, n, d)
    block = ph.build_signing_block(signers)
    eocd_real = bytearray(raw[eocd:])
    struct.pack_into("<I", eocd_real, 16, block_start + len(block))
    out = prefix + block + cd + bytes(eocd_real)

    os.makedirs(os.path.dirname(OUT_APK), exist_ok=True)
    open(OUT_APK, "wb").write(out)
    print("v2 block: %d bytes; output %d bytes (repacked %d, upstream %d)"
          % (len(block), len(out), len(raw), os.path.getsize(SRC_APK)))

    ph.verify(OUT_APK, n, e, cert_der, spki_der)
    with zipfile.ZipFile(OUT_APK) as z:
        assert z.testzip() is None
        man = z.read("AndroidManifest.xml")
    assert NEW_LABEL.encode("utf-16-le") in man and EXPECT_LABEL_PREFIX.encode("utf-16-le") not in man
    dex = zipfile.ZipFile(OUT_APK).read("classes.dex")
    import zlib
    adler = struct.unpack_from("<I", dex, 8)[0]
    print("classes.dex adler32 %s" % ("OK" if adler == zlib.adler32(dex[12:]) & 0xFFFFFFFF else "BAD"))
    print("app label inside manifest renamed: True")
    print("wrote %s (sha256 %s)" % (OUT_APK, hashlib.sha256(open(OUT_APK, "rb").read()).hexdigest()))


if __name__ == "__main__":
    main()
