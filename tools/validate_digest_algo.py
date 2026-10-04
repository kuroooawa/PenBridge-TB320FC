"""Recompute the v2 content digest of signed APKs and compare it with the digest embedded in
their signing block. Used to cross-check apk_v2 against real apksigner output.

    python tools/validate_digest_algo.py dist/PenBridge-Hook-v4.1.3-TB320FC.apk [more.apk ...]
"""
import struct
import sys
import zipfile

import apk_v2


def check(path, block_id):
    data = open(path, "rb").read()
    eocd = apk_v2.find_eocd(data)
    cd_size, cd_off = struct.unpack_from("<II", data, eocd + 12)
    magic = data.rfind(apk_v2.APK_SIG_BLOCK_MAGIC)
    if magic < 0:
        return "no APK Signing Block"
    size2 = struct.unpack_from("<Q", data, magic - 8)[0]
    start = magic + 16 - size2 - 8
    eocd_virtual = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_virtual, 16, start)
    digest = apk_v2.apk_content_digest(
        [data[:start], data[cd_off:cd_off + cd_size], bytes(eocd_virtual)])

    p = start + 8
    ids, val = [], None
    while p < magic - 8:
        pair_len = struct.unpack_from("<Q", data, p)[0]
        pid = struct.unpack_from("<I", data, p + 8)[0]
        ids.append(hex(pid))
        if pid == block_id and val is None:
            val = data[p + 12:p + 8 + pair_len]
        p += 8 + pair_len
    if val is None:
        return "ids=%s (no 0x%x)" % (ids, block_id)

    sd = val[12:12 + struct.unpack_from("<I", val, 8)[0]]
    d_alg = struct.unpack_from("<I", sd, 8)[0]
    d_len = struct.unpack_from("<I", sd, 12)[0]
    embedded = sd[16:16 + d_len]
    return "ids=%s alg=0x%x %s" % (ids, d_alg, "MATCH" if embedded == digest else
                                   "MISMATCH (recomputed %s, embedded %s)"
                                   % (digest.hex()[:20], embedded.hex()[:20]))


for path in sys.argv[1:]:
    print(path)
    print("   v2:", check(path, 0x7109871A))
    print("   v3:", check(path, 0xF05368C0))
