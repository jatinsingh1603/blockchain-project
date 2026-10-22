"""Checks digest behaviour on synthetic APK-like files and times it.

No real APK is used. Each test file is a ZIP with random payload entries; a
fake APK Signing Block is inserted before the Central Directory, in the same
layout Android uses. This tests the digest logic and its speed only.
"""
import io
import json
import os
import platform
import statistics
import struct
import sys
import time
import zipfile

sys.path.insert(0, os.path.dirname(__file__))
from apk_digest import content_digest, SIG_BLOCK_MAGIC, EOCD_SIG  # noqa: E402


def make_zip(size_mb: int, seed: int = 1) -> bytes:
    rnd = __import__("random").Random(seed)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_STORED) as z:
        z.writestr("AndroidManifest.xml", b"<manifest package='com.example.wallet'/>")
        z.writestr("classes.dex", b"dex\n035\0" + b"code" * 1000)
        remaining = size_mb * 1024 * 1024
        i = 0
        while remaining > 0:
            n = min(remaining, 1024 * 1024)
            z.writestr(f"res/raw/blob{i}.bin", rnd.randbytes(n))
            remaining -= n
            i += 1
    return buf.getvalue()


def insert_signing_block(data: bytes, payload: bytes) -> bytes:
    eocd = data.rfind(EOCD_SIG)
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    pair = struct.pack("<Q", len(payload) + 4) + struct.pack("<I", 0x7109871A) + payload
    size = len(pair) + 8 + 16  # pairs + trailing size + magic
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + SIG_BLOCK_MAGIC
    new_cd = cd_offset + len(block)
    eocd_rec = bytearray(data[eocd:])
    struct.pack_into("<I", eocd_rec, 16, new_cd)
    return data[:cd_offset] + block + data[cd_offset:eocd] + bytes(eocd_rec)


def main():
    results = {"machine": f"{platform.processor() or platform.machine()}, Python {platform.python_version()}, {os.cpu_count()} vCPU (cloud sandbox)"}

    base = make_zip(2)
    unsigned = content_digest(base)
    signed_a = content_digest(insert_signing_block(base, b"SIGNATURE-BY-KEY-A" * 50))
    signed_b = content_digest(insert_signing_block(base, b"different-key-B" * 90))
    tampered_zip = bytearray(base)
    idx = tampered_zip.find(b"code")
    tampered_zip[idx:idx + 4] = b"evil"
    tampered = content_digest(insert_signing_block(bytes(tampered_zip), b"SIGNATURE-BY-KEY-A" * 50))
    results["correctness"] = {
        "unsigned_equals_signed_by_A": unsigned == signed_a,
        "signed_by_A_equals_signed_by_B": signed_a == signed_b,
        "one_changed_byte_changes_digest": tampered != signed_a,
    }

    timing = []
    for mb in [5, 25, 50, 100]:
        data = insert_signing_block(make_zip(mb, seed=mb), b"S" * 2000)
        runs = []
        for _ in range(7):
            t0 = time.perf_counter()
            content_digest(data)
            runs.append((time.perf_counter() - t0) * 1000)
        timing.append({"size_mb": mb, "median_ms": round(statistics.median(runs), 1),
                       "min_ms": round(min(runs), 1), "max_ms": round(max(runs), 1)})
    results["timing"] = timing
    os.makedirs("results", exist_ok=True)
    with open("results/digest.json", "w") as f:
        json.dump(results, f, indent=2)
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
