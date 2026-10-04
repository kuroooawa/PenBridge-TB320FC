"""Cross-check the v2 content-digest implementation against real, properly signed APKs.

The chunked-digest algorithm must restart chunking at each section boundary
(entries content / central directory / EOCD). If a recomputed digest equals the digest
embedded in an APK's v2 signer, our implementation matches apksigner's.
"""
import hashlib
import struct
import sys

MAGIC = b"APK Sig Block 42"


def apk_content_digest(sections):
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


def check(path, block_id):
    data = open(path, "rb").read()
    eocd = data.rfind(b"PK\x05\x06")
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    magic = data.rfind(MAGIC)
    if magic < 0:
        return "no APK Signing Block"
    size2 = struct.unpack_from("<Q", data, magic - 8)[0]
    start = magic + 16 - size2 - 8
    eocd_virtual = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_virtual, 16, start)
    digest = apk_content_digest([data[:start], data[cd_off:cd_off + cd_size], bytes(eocd_virtual)])

    p = start + 8
    val = None
    ids = []
    while p < magic - 8:
        pair_len = struct.unpack_from("<Q", data, p)[0]
        pid = struct.unpack_from("<I", data, p + 8)[0]
        ids.append(hex(pid))
        if pid == block_id and val is None:
            val = data[p + 12:p + 8 + pair_len]
        p += 8 + pair_len
    if val is None:
        return "ids=%s (no 0x%x)" % (ids, block_id)

    u32 = lambda b, o: struct.unpack_from("<I", b, o)[0]
    sd_len = u32(val, 8)
    sd = val[12:12 + sd_len]
    d_alg = u32(sd, 8)
    d_len = u32(sd, 12)
    embedded = sd[16:16 + d_len]
    return "ids=%s alg=0x%x %s" % (ids, d_alg, "MATCH" if embedded == digest else
                                   "MISMATCH (recomputed %s, embedded %s)" % (digest.hex()[:20], embedded.hex()[:20]))


for path in sys.argv[1:]:
    print(path)
    print("   v2:", check(path, 0x7109871A))
    print("   v3:", check(path, 0xF05368C0))
