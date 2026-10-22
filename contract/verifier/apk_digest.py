"""Signing-independent content digest for APK files.

The APK is split into four parts (as in APK Signature Scheme v2):
  1. ZIP entries (offset 0 up to the APK Signing Block)
  2. APK Signing Block (skipped)
  3. ZIP Central Directory
  4. ZIP End of Central Directory (EOCD)
The digest is SHA-256 over parts 1, 3 and 4. In part 4 the Central Directory
offset is replaced by the offset of the signing block, so the digest does not
change when a different key signs the same APK.
"""
import hashlib
import struct

EOCD_SIG = b"PK\x05\x06"
SIG_BLOCK_MAGIC = b"APK Sig Block 42"


def _find_eocd(data: bytes) -> int:
    pos = data.rfind(EOCD_SIG, max(0, len(data) - 65557))
    if pos < 0:
        raise ValueError("not a ZIP/APK file: EOCD not found")
    return pos


def content_digest(data: bytes) -> str:
    eocd = _find_eocd(data)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    sig_start = cd_offset
    if cd_offset >= 24 and data[cd_offset - 16:cd_offset] == SIG_BLOCK_MAGIC:
        block_size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
        sig_start = cd_offset - (block_size + 8)
    part1 = data[:sig_start]
    part3 = data[cd_offset:eocd]
    part4 = bytearray(data[eocd:])
    struct.pack_into("<I", part4, 16, sig_start)
    h = hashlib.sha256()
    h.update(part1)
    h.update(part3)
    h.update(bytes(part4))
    return h.hexdigest()


def content_digest_file(path: str) -> str:
    with open(path, "rb") as f:
        return content_digest(f.read())
