"""Shared APK helpers for this repo: zip/EOCD access, APK Signature Scheme v2 signing and
verification, and resources.arsc / AndroidManifest string-pool rewriting.

Used by tools/patch_hook.py (Hook APK) and tools/patch_penhidctl.py (priv-app APK).
The v2 content-digest implementation is cross-checked against real apksigner output
(tools/validate_digest_algo.py): chunks restart at each section boundary
(entries content / central directory / EOCD with the CD offset pointing at the signing block).
"""
import hashlib
import os
import struct
import zipfile

SIG_ALG_RSA_PKCS1_SHA256 = 0x0103
V2_BLOCK_ID = 0x7109871A
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def load_keys(build_dir):
    """Read build/keys/{params.txt,cert.der,spki.der} as written by tools/gen_key.ps1."""
    params = {}
    with open(os.path.join(build_dir, "keys", "params.txt")) as fh:
        for line in fh:
            if "=" in line:
                k, v = line.strip().split("=", 1)
                params[k] = v
    return (int(params["modulus"], 16), int(params["privateExponent"], 16),
            int(params["publicExponent"], 16),
            open(os.path.join(build_dir, "keys", "cert.der"), "rb").read(),
            open(os.path.join(build_dir, "keys", "spki.der"), "rb").read())


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
def verify(path, n, e, cert_der, spki_der):
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
    assert pub == spki_der, "public key mismatch"

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
    assert cert == cert_der, "certificate mismatch"

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
