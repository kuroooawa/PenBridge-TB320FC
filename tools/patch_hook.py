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

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BUILD = os.environ.get("PENBRIDGE_BUILD", os.path.join(ROOT, "build"))
UPSTREAM = os.environ.get("PENBRIDGE_UPSTREAM", os.path.join(ROOT, "upstream"))
DIST = os.environ.get("PENBRIDGE_DIST", os.path.join(ROOT, "dist"))
# 输入必须是上游未打补丁的 hook/PenBridge-Hook.apk（放到 upstream/ 下）
SRC_APK = os.environ.get("PENBRIDGE_SRC_APK", os.path.join(UPSTREAM, "PenBridge-Hook.apk"))
OUT_APK = os.environ.get("PENBRIDGE_OUT_APK",
                        os.path.join(DIST, "PenBridge-Hook-v4.1.3-TB320FC.apk"))
CERT_DER = os.path.join(BUILD, "keys", "cert.der")
SPKI_DER = os.path.join(BUILD, "keys", "spki.der")
PARAMS = os.path.join(BUILD, "keys", "params.txt")

SIG_ALG_RSA_PKCS1_SHA256 = 0x0103
V2_BLOCK_ID = 0x7109871A
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"

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
def find_eocd(data):
    i = data.rfind(b"PK\x05\x06")
    if i < 0:
        raise ValueError("EOCD not found")
    return i


def local_header(data, off):
    (sig, ver, flags, method, mtime, mdate, crc, csize, usize, nlen, elen) = \
        struct.unpack_from("<IHHHHHIIIHH", data, off)
    assert sig == 0x04034B50, "bad local header at %d" % off
    name = data[off + 30:off + 30 + nlen].decode("utf-8")
    return {"off": off, "crc": crc, "csize": csize, "usize": usize, "nlen": nlen,
            "elen": elen, "name": name, "data_off": off + 30 + nlen + elen}


def central_entries(data, cd_off, cd_size):
    p = cd_off
    end = cd_off + cd_size
    out = []
    while p < end:
        (sig, vmade, vneed, flags, method, mtime, mdate, crc, csize, usize, nlen, elen, clen,
         disk, iattr, eattr, lho) = struct.unpack_from("<IHHHHHHIIIHHHHHII", data, p)
        assert sig == 0x02014B50, "bad central entry at %d" % p
        name = data[p + 46:p + 46 + nlen].decode("utf-8")
        out.append({"off": p, "crc": crc, "csize": csize, "usize": usize, "nlen": nlen,
                    "elen": elen, "clen": clen, "name": name, "local_off": lho})
        p += 46 + nlen + elen + clen
    return out


# ----------------------------------------------------------------------------- v2 signing
def lp32(b):
    return struct.pack("<I", len(b)) + b


def apk_content_digest(sections):
    """sections: ordered list of bytes objects (APK content, central directory, EOCD).

    Chunking restarts at every section boundary (apksig computeOneMbChunkContentDigests).
    """
    chunk = 1024 * 1024
    chunk_digests = []
    for section in sections:
        for i in range(0, len(section), chunk):
            part = section[i:i + chunk]
            chunk_digests.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(part)) + part).digest())
    h = hashlib.sha256()
    h.update(b"\x5a" + struct.pack("<I", len(chunk_digests)))
    for d in chunk_digests:
        h.update(d)
    return h.digest()


def rsa_pkcs1_sha256_sign(msg, n, d):
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + \
        hashlib.sha256(msg).digest()
    k = (n.bit_length() + 7) // 8
    if len(digest_info) + 11 > k:
        raise ValueError("key too small")
    em = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")


def build_v2_signers_block(digest, cert_der, spki_der, n, d):
    digest_entry = lp32(struct.pack("<I", SIG_ALG_RSA_PKCS1_SHA256) + lp32(digest))
    digests_seq = lp32(digest_entry)
    certs_seq = lp32(lp32(cert_der))
    attrs_seq = lp32(b"")
    signed_data = digests_seq + certs_seq + attrs_seq
    signature = rsa_pkcs1_sha256_sign(signed_data, n, d)
    sig_seq = lp32(lp32(struct.pack("<I", SIG_ALG_RSA_PKCS1_SHA256) + lp32(signature)))
    signer = lp32(signed_data) + sig_seq + lp32(spki_der)
    return lp32(lp32(signer))  # signers sequence of length-prefixed signers


def build_signing_block(pair_value):
    pair = struct.pack("<Q", 4 + len(pair_value)) + struct.pack("<I", V2_BLOCK_ID) + pair_value
    size = 8 + len(pair) + 16
    return struct.pack("<Q", size) + pair + struct.pack("<Q", size) + APK_SIG_BLOCK_MAGIC


def string_pool_slots(buf, off):
    """Parse a ResStringPool chunk (resources.arsc global pool at offset 12, AXML pool at 8).

    Returns (slots, meta); each slot carries the *byte* offset/length of the string data so a
    same-or-shorter replacement can be written in place (trailing bytes are zero padding).
    """
    ptype, phdr, psize = struct.unpack_from("<HHI", buf, off)
    assert ptype == 0x0001, "no string pool at 0x%x (type 0x%x)" % (off, ptype)
    count, style_count, flags, sstart, stystart = struct.unpack_from("<IIIII", buf, off + 8)
    utf8 = bool(flags & (1 << 8))
    assert not (flags & 1), "string pool is sorted: in-place rewrite would break ordering"
    offsets = [struct.unpack_from("<I", buf, off + phdr + 4 * i)[0] for i in range(count)]
    slots = []
    for i, o in enumerate(offsets):
        q = off + sstart + o
        if utf8:
            n = buf[q]
            plen = 1
            if n & 0x80:
                n = ((n & 0x7F) << 8) | buf[q + 1]
                plen = 2
            q += plen
            m = buf[q]
            llen = 1
            if m & 0x80:
                m = ((m & 0x7F) << 8) | buf[q + 1]
                llen = 2
            q += llen
            slots.append({"data_start": q, "data_len": m,
                          "text": buf[q:q + m].decode("utf-8", "replace"),
                          "prefix": plen + llen, "term": 1})
        else:
            n = struct.unpack_from("<H", buf, q)[0]
            plen = 2
            q += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", buf, q)[0]
                plen = 4
                q += 2
            slots.append({"data_start": q, "data_len": 2 * n,
                          "text": buf[q:q + 2 * n].decode("utf-16-le", "replace"),
                          "prefix": plen, "term": 2})
    meta = {"utf8": utf8, "count": count, "size": psize, "flags": flags}
    return slots, meta


def rewrite_pool_string(buf, slot, new_text, label):
    """Rewrite one string pool slot in place; the string must fit into the existing slot."""
    encoding = "utf-8" if slot["term"] == 1 else "utf-16-le"
    new_bytes = new_text.encode(encoding)
    if len(new_bytes) > slot["data_len"]:
        raise SystemExit("%s: %d bytes needed, only %d available in the slot"
                         % (label, len(new_bytes), slot["data_len"]))
    start = slot["data_start"]
    buf[start:start + slot["data_len"]] = new_bytes + b"\x00" * (slot["data_len"] - len(new_bytes))
    return len(new_bytes)


# ----------------------------------------------------------------------------- main
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
    params = {}
    for line in open(PARAMS):
        if "=" in line:
            k, v = line.strip().split("=", 1)
            params[k] = v
    n = int(params["modulus"], 16)
    d = int(params["privateExponent"], 16)
    e = int(params["publicExponent"], 16)
    cert_der = open(CERT_DER, "rb").read()
    spki_der = open(SPKI_DER, "rb").read()

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
    verify(OUT_APK, n, e)
    print("wrote %s" % OUT_APK)


def verify(path, n, e):
    data = open(path, "rb").read()
    eocd = data.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    magic_pos = data.rfind(APK_SIG_BLOCK_MAGIC)
    size2 = struct.unpack_from("<Q", data, magic_pos - 8)[0]
    block_start = magic_pos + 16 - size2 - 8
    size1 = struct.unpack_from("<Q", data, block_start)[0]
    assert size1 == size2, "signing block size mismatch"
    assert cd_off == magic_pos + 16, \
        "EOCD must point at the real central directory (0x%x vs 0x%x)" % (cd_off, magic_pos + 16)

    # Digest input: prefix + real CD + EOCD whose CD offset is replaced by the signing block start.
    eocd_virtual = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_virtual, 16, block_start)
    content = [data[:block_start], data[cd_off:cd_off + cd_size], bytes(eocd_virtual)]
    digest = apk_content_digest(content)

    u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
    p = block_start + 8
    pair_len = struct.unpack_from("<Q", data, p)[0]
    pid = u32(data, p + 8)
    assert pid == V2_BLOCK_ID, "unexpected block id 0x%x" % pid
    val = data[p + 12:p + 8 + pair_len]

    o = 0
    signers_len = u32(val, o); o += 4
    assert signers_len == len(val) - 4, "signers length mismatch"
    signer_len = u32(val, o); o += 4
    sd_len = u32(val, o); o += 4
    signed_data = val[o:o + sd_len]
    o += sd_len

    sigs_len = u32(val, o); o += 4
    sigs_end = o + sigs_len
    entry_len = u32(val, o)
    alg = u32(val, o + 4)
    dl = u32(val, o + 8)
    sig = val[o + 12:o + 12 + dl]
    o = sigs_end
    pk_len = u32(val, o); o += 4
    pub = val[o:o + pk_len]
    o += pk_len
    assert o == len(val), "trailing bytes in signer block"
    assert alg == SIG_ALG_RSA_PKCS1_SHA256, "sig alg 0x%x" % alg
    assert pub == open(SPKI_DER, "rb").read(), "public key mismatch"

    # signed data: digests / certificates / additional attributes
    s = 0
    dgs_len = u32(signed_data, s); s += 4
    dgs_end = s + dgs_len
    d_entry_len = u32(signed_data, s)
    d_alg = u32(signed_data, s + 4)
    d_len = u32(signed_data, s + 8)
    d_val = signed_data[s + 12:s + 12 + d_len]
    s = dgs_end
    certs_len = u32(signed_data, s); s += 4
    c_len = u32(signed_data, s)
    cert = signed_data[s + 4:s + 4 + c_len]
    s += certs_len
    attrs_len = u32(signed_data, s); s += 4
    assert s == len(signed_data), "trailing bytes in signed data"
    assert d_alg == SIG_ALG_RSA_PKCS1_SHA256, "digest alg 0x%x" % d_alg
    assert d_val == digest, "embedded content digest mismatch"
    assert cert == open(CERT_DER, "rb").read(), "certificate mismatch"

    k = (n.bit_length() + 7) // 8
    m = pow(int.from_bytes(sig, "big"), e, n).to_bytes(k, "big")
    digest_info = bytes.fromhex("3031300d060960864801650304020105000420") + \
        hashlib.sha256(signed_data).digest()
    em = b"\x00\x01" + b"\xff" * (k - len(digest_info) - 3) + b"\x00" + digest_info
    assert m == em, "RSA signature verify FAILED"
    print("verify: v2 signature OK (block [0x%x,0x%x), cd_size=%d, sig=%d bytes, cert=%d bytes)"
          % (block_start, magic_pos + 16, cd_size, len(sig), len(cert)))
    with zipfile.ZipFile(path) as z:
        bad = z.testzip()
        assert bad is None, "zip corrupt at %s" % bad
        names = z.namelist()
        extra = ""
        if "META-INF/xposed/scope.list" in names:
            extra = ", scope.list=%d bytes" % z.getinfo("META-INF/xposed/scope.list").file_size
        print("verify: zip OK, %d entries, classes.dex=%d bytes%s"
              % (len(names), z.getinfo("classes.dex").file_size, extra))


if __name__ == "__main__":
    main()
