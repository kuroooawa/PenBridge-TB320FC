import os
import struct

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APK = os.environ.get("PENBRIDGE_SRC_APK",
                    os.path.join(ROOT, "module", "hook", "PenBridge-Hook-v4.1.3-TB320FC.apk"))
data = open(APK, 'rb').read()

i = data.rfind(b'PK\x05\x06')
cd_size, cd_off = struct.unpack_from('<II', data, i + 12)
magic_pos = data.find(b'APK Sig Block 42')
print("cd_off=0x%x cd_size=%d magic at 0x%x" % (cd_off, cd_size, magic_pos))
block_end = magic_pos + 16
size2 = struct.unpack_from('<Q', data, magic_pos - 8)[0]
block_start = block_end - size2 - 8
size1 = struct.unpack_from('<Q', data, block_start)[0]
print("block_start=0x%x size1=%d size2=%d block_len=%d" % (block_start, size1, size2, block_end - block_start))

p = block_start + 8
while p < magic_pos - 8:
    pair_len = struct.unpack_from('<Q', data, p)[0]
    pid = struct.unpack_from('<I', data, p + 8)[0]
    print("  pair at 0x%x len=%d id=0x%08x value_len=%d" % (p, pair_len, pid, pair_len - 4))
    if pid == 0x7109871a:
        val = data[p + 12: p + 8 + pair_len]
        print("     v2 signer block first 24 bytes:", val[:24].hex())
        # signers sequence
        n = struct.unpack_from('<I', val, 0)[0]
        print("     signers len=%d" % n)
        q = 4
        sl = struct.unpack_from('<I', val, q)[0]
        print("     signer block len=%d" % sl)
        q += 4
        sdl = struct.unpack_from('<I', val, q)[0]
        print("     signed data len=%d" % sdl)
        q += 4
        dgl = struct.unpack_from('<I', val, q)[0]
        print("     digests len=%d" % dgl)
        q += 4
        alg = struct.unpack_from('<I', val, q)[0]
        dl = struct.unpack_from('<I', val, q + 4)[0]
        print("     digest alg=0x%08x digest len=%d" % (alg, dl))
    if pid == 0xf05368c0:
        print("     (v3 signer block present)")
    p += 8 + pair_len

print("\nfile tail:", data[magic_pos + 16:magic_pos + 16 + 40].hex())
