"""Patch PenBridge-Hook.apk for TB320FC + AP501U and re-sign it (APK Signature Scheme v2).

What it changes inside classes.dex:
  P1 DeviceGate.supported()            -> always true (device gating moves to the Root module,
                                          which enforces the TB320FC model check; a compiled dex
                                          cannot gain a new prop-name string safely).
  P2 CardBatteryHooks.refreshPenCard   -> pen card title search string "Lenovo Tab Pen Pro" ->
                                          "Lenovo Tab Pen Plus" (AP501U == Lenovo Tab Pen Plus).
  P3 CardBatteryHooks.collectTextViews -> String.equals -> String.contains so a card title such as
                                          "Lenovo Tab Pen Plus (AP501U)" still matches.
  P4 LenovoPenUEventBridge.onUEvent    -> repoint the "name" extra key of the kernel-uevent
                                          snapshot so the Root service owns the published pen name
                                          ("Lenovo Tab Pen Plus (AP501U)").

No string data is added or resized, so the dex layout (and therefore the APK layout) is preserved;
only the dex checksum/signature and the ZIP CRC change. The APK is then signed with APK Signature
Scheme v2 using the key in build/keys.
"""

import hashlib
import os
import struct
import sys
import zipfile

from apk_v2 import (APK_SIG_BLOCK_MAGIC, SIG_ALG_RSA_PKCS1_SHA256, V2_BLOCK_ID,
                   apk_content_digest, build_signing_block, build_v2_signers_block,
                   central_entries, find_eocd, load_keys, local_header,
                   rewrite_pool_string, string_pool_slots, verify)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get("PENBRIDGE_BUILD", os.path.join(ROOT, "build"))
UPSTREAM = os.environ.get("PENBRIDGE_UPSTREAM", os.path.join(ROOT, "upstream"))
DIST = os.environ.get("PENBRIDGE_DIST", os.path.join(ROOT, "dist"))
# 输入必须是上游未打补丁的 hook/PenBridge-Hook.apk（放到 upstream/ 下）
SRC_APK = os.environ.get("PENBRIDGE_SRC_APK", os.path.join(UPSTREAM, "PenBridge-Hook.apk"))
OUT_APK = os.environ.get("PENBRIDGE_OUT_APK",
                        os.path.join(DIST, "PenBridge-Hook-v4.1.3-TB320FC.apk"))


# P5 目标文案：显示名（app label）与模块说明（description）。上游槽位容量为
# label 37 字节 / description 235 字节（UTF-8），脚本会断言不超限。
HOOK_LABEL = "TB320FC - 手写笔桥接 (AP501U)"
HOOK_DESC = ("手写笔桥接（TB320FC/AP501U）：笔身状态与按键、便签工具、书写触感。"
             "挂住 SystemUI 与便签里判断笔状态的几处，接入桥接服务上报的状态；"
             "触感页只保留这支笔真能驱动的控件。")


# ----------------------------------------------------------------------------- dex parsing
def uleb128(buf, off):
    result = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, off


class Dex:
    def __init__(self, data):
        self.d = bytearray(data)
        (self.string_ids_size, self.string_ids_off, self.type_ids_size, self.type_ids_off,
         self.proto_ids_size, self.proto_ids_off, self.field_ids_size, self.field_ids_off,
         self.method_ids_size, self.method_ids_off, self.class_defs_size,
         self.class_defs_off) = struct.unpack_from("<12I", data, 56)
        self.strings = []
        for i in range(self.string_ids_size):
            off = struct.unpack_from("<I", data, self.string_ids_off + 4 * i)[0]
            n, p = uleb128(data, off)
            self.strings.append(data[p:p + n].decode("utf-8", "replace"))
        self.types = [self.strings[struct.unpack_from("<I", data, self.type_ids_off + 4 * i)[0]]
                      for i in range(self.type_ids_size)]
        self.methods = []
        for i in range(self.method_ids_size):
            c, p, n = struct.unpack_from("<HHI", data, self.method_ids_off + 8 * i)
            self.methods.append((self.types[c], self.strings[n]))

    def find_method_index(self, class_desc, name):
        for i, (c, n) in enumerate(self.methods):
            if c == class_desc and n == name:
                return i
        raise KeyError("%s->%s not found" % (class_desc, name))

    def find_method_index_containing(self, class_part, name):
        for i, (c, n) in enumerate(self.methods):
            if class_part in c and n == name:
                return i
        raise KeyError("%s->%s not found" % (class_part, name))

    def iter_methods(self):
        """Yield (class_desc, method_index, code_off)."""
        for i in range(self.class_defs_size):
            off = self.class_defs_off + 32 * i
            class_idx = struct.unpack_from("<I", self.d, off)[0]
            class_data_off = struct.unpack_from("<I", self.d, off + 24)[0]
            if class_data_off == 0:
                continue
            p = class_data_off
            sf, p = uleb128(self.d, p)
            inf, p = uleb128(self.d, p)
            dm, p = uleb128(self.d, p)
            vm, p = uleb128(self.d, p)
            for _ in range(sf):
                _, p = uleb128(self.d, p)
                _, p = uleb128(self.d, p)
            for _ in range(inf):
                _, p = uleb128(self.d, p)
                _, p = uleb128(self.d, p)
            for count in (dm, vm):
                midx = 0
                for _ in range(count):
                    diff, p = uleb128(self.d, p)
                    midx += diff
                    _, p = uleb128(self.d, p)
                    code_off, p = uleb128(self.d, p)
                    if code_off:
                        yield self.types[struct.unpack_from("<I", self.d, off)[0]], midx, code_off

    def code_off_of(self, class_part, method_name):
        for cname, midx, code_off in self.iter_methods():
            if class_part in cname and self.methods[midx][1] == method_name:
                return code_off
        raise KeyError("code for %s::%s not found" % (class_part, method_name))

    def read_unit(self, code_off, pc):
        return struct.unpack_from("<H", self.d, code_off + 16 + 2 * pc)[0]

    def write_unit(self, code_off, pc, value):
        struct.pack_into("<H", self.d, code_off + 16 + 2 * pc, value)

    def write_code_bytes(self, code_off, raw):
        self.d[code_off + 16:code_off + 16 + len(raw)] = raw

    def finish(self):
        # Dex header: signature (SHA-1 over bytes[32:]) then checksum (Adler-32 over bytes[12:]).
        # The checksum must be computed last because it covers the signature field.
        self.d[12:32] = hashlib.sha1(bytes(self.d[32:])).digest()
        struct.pack_into("<I", self.d, 8, zlib_adler32(bytes(self.d[12:])))
        return bytes(self.d)


def zlib_adler32(data):
    import zlib
    return zlib.adler32(data) & 0xFFFFFFFF


# ----------------------------------------------------------------------------- zip helpers
def main():
    data = bytearray(open(SRC_APK, "rb").read())
    eocd = find_eocd(data)
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    magic_pos = data.find(APK_SIG_BLOCK_MAGIC)
    if magic_pos < 0:
        raise SystemExit("source APK has no APK Signing Block; refusing")
    block_size = struct.unpack_from("<Q", data, magic_pos - 8)[0]
    block_start = magic_pos + 16 - block_size - 8
    print("source: cd_off=0x%x cd_size=%d signing block=[0x%x,0x%x) eocd=0x%x"
          % (cd_off, cd_size, block_start, magic_pos + 16, eocd))

    entries = {e["name"]: e for e in central_entries(bytes(data), cd_off, cd_size)}
    dex_ce = entries["classes.dex"]
    dex_lh = local_header(bytes(data), dex_ce["local_off"])
    dex_off = dex_lh["data_off"]
    dex_len = dex_lh["usize"]
    assert dex_ce["usize"] == dex_len and dex_lh["csize"] == dex_len, "classes.dex must be stored"

    dex = Dex(data[dex_off:dex_off + dex_len])
    contains_idx = dex.find_method_index("Ljava/lang/String;", "contains")
    print("String.contains method idx = %d" % contains_idx)

    # ---- P1: DeviceGate.supported() -> return true
    gate_off = dex.code_off_of("DeviceGate;", "supported")
    before = [hex(dex.read_unit(gate_off, i)) for i in range(4)]
    dex.write_code_bytes(gate_off, struct.pack("<HH", 0x1012, 0x000F))  # const/4 v0,#1 ; return v0
    after = [hex(dex.read_unit(gate_off, i)) for i in range(4)]
    print("P1 DeviceGate.supported code=0x%x units %s -> %s" % (gate_off, before, after))

    # ---- P2: CardBatteryHooks.refreshPenCard search string 704 -> 703
    card_off = dex.code_off_of("CardBatteryHooks;", "refreshPenCard")
    old = dex.read_unit(card_off, 17)
    dex.write_unit(card_off, 17, 703)
    print("P2 refreshPenCard const-string @pc16: %d (%r) -> 703 (%r)"
          % (old, dex.strings[old], dex.strings[703]))

    # ---- P3: collectTextViews String.equals -> String.contains
    ctv_off = dex.code_off_of("CardBatteryHooks;", "collectTextViews")
    old = dex.read_unit(ctv_off, 21)
    dex.write_unit(ctv_off, 21, contains_idx)
    print("P3 collectTextViews invoke @pc20: %s -> %s"
          % (dex.methods[old], dex.methods[contains_idx]))

    # ---- P4: the kernel-uevent snapshot no longer publishes a pen display name, so the
    #          Root service's published name (Lenovo Tab Pen Plus (AP501U)) is authoritative.
    ue_off = dex.code_off_of("LenovoPenUEventBridge;", "onUEvent")
    old = dex.read_unit(ue_off, 421)
    dex.write_unit(ue_off, 421, 882)
    print("P4 onUEvent intent extra key @pc420: %d (%r) -> 882 (%r)"
          % (old, dex.strings[old], dex.strings[882]))

    new_dex = dex.finish()
    assert len(new_dex) == dex_len
    data[dex_off:dex_off + dex_len] = new_dex
    new_crc = zlib_adler32(new_dex)
    import zlib
    new_crc = zlib.crc32(new_dex) & 0xFFFFFFFF
    struct.pack_into("<I", data, dex_lh["off"] + 14, new_crc)
    struct.pack_into("<I", data, dex_ce["off"] + 16, new_crc)
    print("classes.dex patched, new crc32=0x%08x" % new_crc)

    # ---- P5: display name (app label) + module description inside resources.arsc.
    #          resources.arsc is STORED and the replacement keeps the entry's byte length,
    #          so every entry offset in the APK stays unchanged; only the entry CRC changes.
    arsc_ce = entries["resources.arsc"]
    arsc_lh = local_header(bytes(data), arsc_ce["local_off"])
    arsc_off = arsc_lh["data_off"]
    arsc_len = arsc_lh["usize"]
    assert arsc_lh["csize"] == arsc_len and arsc_ce["usize"] == arsc_len, \
        "resources.arsc must be stored"
    arsc = bytearray(data[arsc_off:arsc_off + arsc_len])
    slots, meta = string_pool_slots(arsc, 12)
    print("resources.arsc string pool: %d strings, utf8=%s, sorted=%s, size=%d"
          % (meta["count"], meta["utf8"], bool(meta["flags"] & 1), meta["size"]))
    for idx, new_text, expected_prefix, what in (
            (9, HOOK_LABEL, "联想平板 Pro GT", "app label"),
            (8, HOOK_DESC, "手写笔的框架层部分", "module description")):
        slot = slots[idx]
        if not slot["text"].startswith(expected_prefix):
            raise SystemExit("unexpected upstream %s at pool index %d: %r"
                             % (what, idx, slot["text"]))
        written = rewrite_pool_string(arsc, slot, new_text, what)
        print("P5 %s: pool[%d] %d -> %d bytes (slot %d)  %r"
              % (what, idx, slot["data_len"], written, slot["data_len"], new_text))
    new_arsc = bytes(arsc)
    assert len(new_arsc) == arsc_len
    data[arsc_off:arsc_off + arsc_len] = new_arsc
    import zlib
    arsc_crc = zlib.crc32(new_arsc) & 0xFFFFFFFF
    struct.pack_into("<I", data, arsc_lh["off"] + 14, arsc_crc)
    struct.pack_into("<I", data, arsc_ce["off"] + 16, arsc_crc)
    print("resources.arsc patched, new crc32=0x%08x" % arsc_crc)

    # ---- re-sign (v2)
    n, d, e, cert_der, spki_der = load_keys(BUILD)

    prefix = bytes(data[:block_start])
    cd = bytes(data[cd_off:cd_off + cd_size])
    # Digest computation uses the EOCD with its CD-offset field pointing at the signing block,
    # while the APK itself keeps the real CD offset (block_start + block size) in the EOCD.
    eocd_virtual = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_virtual, 16, block_start)
    content = [prefix, cd, bytes(eocd_virtual)]
    digest = apk_content_digest(content)
    signers = build_v2_signers_block(digest, cert_der, spki_der, n, d)
    block = build_signing_block(signers)

    eocd_real = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_real, 16, block_start + len(block))
    out = prefix + block + cd + bytes(eocd_real)
    print("v2 block: %d bytes (was %d); output %d bytes (was %d)"
          % (len(block), magic_pos + 16 - block_start, len(out), len(data)))

    os.makedirs(os.path.dirname(OUT_APK), exist_ok=True)
    open(OUT_APK, "wb").write(out)

    # ---- verify
    verify(OUT_APK, n, e, cert_der, spki_der)
    print("wrote %s" % OUT_APK)


if __name__ == "__main__":
    main()
