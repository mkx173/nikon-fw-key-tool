#!/usr/bin/env python3
"""
Decrypt a Nikon "legacy scheme" firmware image with a recovered key file.

    python3 decrypt_firmware.py --key tables/key.json \
        --firmware Z_fc_0181.bin --out Z_fc_0181.dec

Every parameter is named: there are no positional arguments, so no ordering
mistake can put an input path where the output goes. An existing --out is
refused unless --force.

The file keeps a 32-byte plaintext header and a plaintext 32-space label;
everything after them is XORed with a three-table keystream of period 2^24
(16 MB). i is the body offset (file offset - 0x20) and still counts the label:

    plain[0x20 + i] = cipher[0x20 + i] ^ T1[i & 0xFF] ^ T2[(i>>8) & 0xFF] ^ T3[(i>>16) & 0xFF]   (i >= 0x20)

T1/T2/T3 are generation-wide constants shared by the Z 5, Z 6, Z 6II, Z 7,
Z 7II, Z 8, Z 30, Z 50 and Z fc; extract_key.py recovers them into the JSON
key file this script consumes.

Scheme discriminator: a legacy image has 32 ASCII spaces at file offset 0x20.
The newer bodies (Z 5II, Z 50II, Z 6III, ZR) put them at 0x260 and use a
different, unbroken scheme -- those are rejected here.

Decrypted layout: a 32-byte header, space label, module directory and payloads.
Every descriptor is 32 bytes and the name comes first, before the extent.
Module extents must chain exactly. Each module and the complete body carry
CRC16 checksums which are verified before any output is written.

Requires numpy.
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
NEW_SCHEME = 0x260  # where the newer, unbroken bodies put their 32 spaces
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
    """Never silently replace a file. Inputs here are large and hard to re-fetch,
    and a mistyped --out used to be able to land on one."""
    if path and os.path.exists(path) and not force:
        die(EX_USAGE, "%s already exists; pass --force to replace it." % path)


def load_key(path):
    """Load the three tables, refusing anything that fails its own self_check."""
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
    """Whole body, trailing partial sector included."""
    body = raw[HDR:]
    pad = -len(body) % SEC
    sectors = np.frombuffer(body + b"\0" * pad, dtype=np.uint8).reshape(-1, SEC)
    j = np.arange(sectors.shape[0])
    plain = (sectors ^ t1 ^ (t2[j & 0xFF] ^ t3[(j >> 8) & 0xFF])[:, None])
    out = plain.tobytes()[:len(body)]
    # body[0x00:0x20] is a literal 32-space label in the container, not
    # ciphertext; XORing it would emit 32 bytes of junk. Pass it through.
    return raw[:HDR] + raw[HDR:HDR + 32] + out[32:]


def parse_table(plain_body, limit=64):
    """Read a complete module directory, rejecting invalid extents/names.

    At body+0x20 sits a 16-byte header, then `count` 32-byte descriptors in
    which THE NAME COMES FIRST:

        0x20   [BE32 count][BE32 dirsize][8 pad]
        0x30   `count` x [16-byte module name][BE32 offset][BE32 length][8 pad]

    dirsize == 48 + 32 * count == 0x30 + 0x20 * count, which is where the
    first module starts, so the directory closes exactly with no leftover.

    This ordering is what the camera's own reader walks: on an EXPEED 7 body
    0x4101dee0 -> 0x41016b24 copies body[0x30:dirsize], case-folds the first
    0x10 bytes of each 0x20-byte record (the name) and byte-swaps the two BE32
    words at record+0x10/+0x14 (offset and length).

    An earlier version of this function read the extent at descriptor+0x00 and
    the name at descriptor+0x10, treating body+0x30 as a "package name" and
    the last descriptor as 16 bytes and unnamed. Every byte position happens to
    coincide, so extents and CRCs were unaffected and no checksum ever caught
    it -- but each module was reported under the PREVIOUS descriptor's name.
    That mislabelled the main application as "vr", the Linux image as unnamed,
    and the body micro as "_tpj01"; a --patch aimed by name hit the wrong
    module entirely.

    Names are NUL-padded and truncated at 16 characters, so a long one loses
    its extension ("eg1850_mas_01700"); do not require one. Offsets are
    relative to the body. Lengths include the module CRC. Raises ValueError
    rather than returning a partial directory.
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
    """Verify structure and image-supplied CRC16s; return the module table.

    CRC16 uses polynomial 0x1021, seed 0, no final XOR; stored values are BE16.
    The package CRC covers the entire body except its final 16-byte trailer,
    including the space label, directory, and each module's own CRC.
    These are integrity checks, not vendor signature/authenticity checks.
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

    # the module names carry the firmware version, e.g. eg1985_018100.bi for 1.81
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
