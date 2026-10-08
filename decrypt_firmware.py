#!/usr/bin/env python3
"""
Decrypt and validate a legacy Nikon firmware image using recovered XOR tables.

    python3 decrypt_firmware.py --key key.json \
        --firmware Z_8_0311.bin --out Z_8_0311.dec

The header and space label remain plaintext. The directory, module CRCs and
package CRC must pass validation before output is written. Existing outputs
require --force. See README.md for supported models and the container format.

Requires NumPy.
"""

import argparse
import binascii
import hashlib
import json
import os
import re
import struct
import sys

import numpy as np

HDR = 0x20          # bytes of plaintext header before the body
SEC = 256           # sector size == T1 period
TABLE = 0x20        # module directory offset within the body
NEW_SCHEME = 0x260  # space-label offset in newer packaging
NAME_RE = re.compile(rb"[0-9A-Za-z_][0-9A-Za-z_.]{2,15}\Z")
TRAILER = 16       # BE16 body CRC followed by 14 zero bytes

EX_USAGE = 2        # bad arguments or unreadable input
EX_KEY = 3          # key file rejected
EX_SCHEME = 4       # input is not a legacy-scheme image
EX_SANITY = 5       # decrypted structure or checksums invalid


def die(code, msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(code)


def refuse_clobber(path, force):
    """Reject an existing output unless replacement is explicitly enabled."""
    if path and os.path.exists(path) and not force:
        die(EX_USAGE, "%s already exists; pass --force to replace it." % path)


def load_key(path):
    """Load three 256-byte tables and verify their recorded SHA-256 hashes."""
    try:
        with open(path) as fh:
            key = json.load(fh)
    except (OSError, ValueError) as exc:
        die(EX_KEY, "cannot read key file %s: %s" % (path, exc))

    check = key.get("self_check") or {}
    tables = []
    for name in ("T1", "T2", "T3"):
        if name not in key:
            die(EX_KEY, "key file has no %s table" % name)
        try:
            raw = bytes.fromhex(key[name])
        except ValueError:
            die(EX_KEY, "%s is not valid hex" % name)
        if len(raw) != 256:
            die(EX_KEY, "%s is %d bytes, expected 256" % (name, len(raw)))
        if name not in check:
            die(EX_KEY, "key file has no self_check entry for %s" % name)
        got = hashlib.sha256(raw).hexdigest()
        if check[name] != got:
            die(EX_KEY, "%s fails its own self_check\n  recorded %s\n  actual   %s"
                % (name, check[name], got))
        tables.append(np.frombuffer(raw, dtype=np.uint8))
    return tables


def check_scheme(raw, path):
    """Exit unless this is a legacy-scheme image."""
    if raw[HDR:HDR + 32] == b" " * 32:
        return
    if raw[NEW_SCHEME:NEW_SCHEME + 32] == b" " * 32:
        die(EX_SCHEME,
            "%s uses the newer Nikon scheme (32 spaces at 0x%x, not 0x%x).\n"
            "       That is the Z 5II / Z 50II / Z 6III / ZR packaging: the header is\n"
            "       plaintext but the payload cipher is not broken. Nothing to decrypt."
            % (path, NEW_SCHEME, HDR))
    die(EX_SCHEME, "%s is not a recognised Nikon firmware image (no 32-space label "
                   "at 0x%x or 0x%x)." % (path, HDR, NEW_SCHEME))


def decrypt(raw, t1, t2, t3):
    """Apply the XOR cipher to the body, preserving the header and space label."""
    body = raw[HDR:]
    pad = -len(body) % SEC
    sectors = np.frombuffer(body + b"\0" * pad, dtype=np.uint8).reshape(-1, SEC)
    j = np.arange(sectors.shape[0])
    plain = (sectors ^ t1 ^ (t2[j & 0xFF] ^ t3[(j >> 8) & 0xFF])[:, None])
    out = plain.tobytes()[:len(body)]
    # The first 32 body bytes are a plaintext space label.
    return raw[:HDR] + raw[HDR:HDR + 32] + out[32:]


def parse_table(plain_body, limit=64):
    """Read the complete directory or raise ValueError.

    Body 0x20: [BE32 count][BE32 directory size][8 zero bytes]
    Body 0x30: count × [16-byte name][BE32 offset][BE32 length][8 zero bytes]

    Names are NUL-padded or occupy all 16 bytes. Offsets are body-relative;
    lengths include the two-byte CRC. Extents must chain from the directory
    end (48 + 32 * count) to the final 16-byte checksum trailer.
    """
    if len(plain_body) < TABLE + 32 + 16 + TRAILER:
        raise ValueError("truncated module directory or checksum trailer")
    count, dirsize = struct.unpack_from(">II", plain_body, 0x20)
    if not 0 < count <= limit:
        raise ValueError("invalid module count %d (expected 1..%d)" % (count, limit))
    if dirsize != 48 + 32 * count:
        raise ValueError("directory size %d does not match module count %d"
                         % (dirsize, count))
    payload_end = len(plain_body) - TRAILER
    if dirsize + 2 * count > payload_end:
        raise ValueError("directory/modules extend beyond the checksum trailer")

    def read_name(raw, label):
        raw = bytes(raw).rstrip(b"\0")
        if not NAME_RE.fullmatch(raw):
            raise ValueError("invalid %s name or NUL padding" % label)
        return raw.decode("ascii")

    if plain_body[TABLE + 8:TABLE + 16] != b"\0" * 8:
        raise ValueError("nonzero directory reserved bytes")

    mods = []
    expected_start = dirsize
    for i in range(count):
        off = TABLE + 16 + i * 32
        name = read_name(plain_body[off:off + 16], "module %d" % (i + 1))
        start, length = struct.unpack_from(">II", plain_body, off + 16)
        if plain_body[off + 24:off + 32] != b"\0" * 8:
            raise ValueError("module %d (%s) has nonzero reserved bytes"
                             % (i + 1, name))
        if start != expected_start:
            raise ValueError("module %d (%s) starts at 0x%x, expected 0x%x"
                             % (i + 1, name, start, expected_start))
        if length < 2:
            raise ValueError("module %d (%s) is too short for its CRC" % (i + 1, name))
        if start + length > payload_end:
            raise ValueError("module %d (%s) extends beyond the checksum trailer"
                             % (i + 1, name))
        mods.append((name, start, length))
        expected_start = start + length
    if expected_start != payload_end:
        raise ValueError("last module ends at 0x%x, expected 0x%x"
                         % (expected_start, payload_end))
    return mods


def validate_firmware(plain_body):
    """Validate the directory, padding and both CRC levels; return modules.

    CRC16 uses polynomial 0x1021, initial value zero and no final XOR.
    Stored CRCs are big-endian. The package CRC covers body[:-16], including
    module CRCs. These checks establish integrity, not authenticity.
    """
    body = memoryview(plain_body)
    mods = parse_table(body)
    if body[:TABLE] != b" " * TABLE:
        raise ValueError("invalid space label")
    if body[-TRAILER + 2:] != b"\0" * (TRAILER - 2):
        raise ValueError("nonzero checksum trailer padding")
    for i, (name, start, length) in enumerate(mods, 1):
        module = body[start:start + length]
        stored = struct.unpack_from(">H", module, length - 2)[0]
        actual = binascii.crc_hqx(module[:-2], 0)
        if actual != stored:
            raise ValueError("module %d (%s) CRC mismatch: stored 0x%04x, computed 0x%04x"
                             % (i, name, stored, actual))
    stored = struct.unpack_from(">H", body, len(body) - TRAILER)[0]
    actual = binascii.crc_hqx(body[:-TRAILER], 0)
    if actual != stored:
        raise ValueError("package CRC mismatch: stored 0x%04x, computed 0x%04x"
                         % (stored, actual))
    return mods


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 2 usage, 3 bad key, 4 wrong scheme, 5 invalid structure/checksums.")
    ap.add_argument("--key", required=True, help="key JSON from extract_key.py")
    ap.add_argument("--firmware", required=True, help="encrypted .bin image")
    ap.add_argument("--out", required=True, help="decrypted output file")
    ap.add_argument("--force", action="store_true",
                    help="replace --out if it already exists")
    args = ap.parse_args()
    refuse_clobber(args.out, args.force)

    t1, t2, t3 = load_key(args.key)
    try:
        raw = open(args.firmware, "rb").read()
    except OSError as exc:
        die(EX_USAGE, str(exc))
    if len(raw) <= HDR + 32:
        die(EX_SCHEME, "%s is only %d bytes" % (args.firmware, len(raw)))
    check_scheme(raw, args.firmware)

    plain = decrypt(raw, t1, t2, t3)
    try:
        mods = validate_firmware(memoryview(plain)[HDR:])
    except ValueError as exc:
        die(EX_SANITY, "%s; nothing written." % exc)
    zero = plain.count(0) / len(plain)

    print("module table:")
    for name, off, length in mods:
        print("   %-18s off=0x%08x len=0x%08x" % (name, off, length))

    # Warn if the filename's version appears in no module name; component
    # versions can lag the release, so this is advisory.
    want = re.findall(r"\d+", args.firmware.rsplit("/", 1)[-1])
    want = want[-1] if want else ""
    if want and mods and not any(want in name for name, _, _ in mods):
        print("warning: no module name contains the version digits %r from the "
              "input filename" % want)

    with open(args.out, "wb") as fh:
        fh.write(plain)
    print("\nwrote %s" % args.out)
    print("  size          %d bytes" % len(plain))
    print("  zero bytes    %.1f%%" % (100 * zero))
    print("  modules       %d (%s)" % (len(mods), ", ".join(m[0] for m in mods)))
    print("  checksums     %d module CRCs + package CRC verified" % len(mods))
    return 0


if __name__ == "__main__":
    sys.exit(main())
