#!/usr/bin/env python3
"""
Decrypt a Nikon "legacy scheme" firmware image with a recovered key file.

    python3 decrypt_firmware.py tables/key.json Z_fc_0181.bin Z_fc_0181.dec

The file keeps a 32-byte plaintext header; everything after it is XORed with a
three-table keystream of period 2^24 (16 MB):

    plain[i] = cipher[0x20 + i] ^ T1[i & 0xFF] ^ T2[(i>>8) & 0xFF] ^ T3[(i>>16) & 0xFF]

T1/T2/T3 are generation-wide constants shared by the Z 5, Z 6, Z 6II, Z 7,
Z 7II, Z 8, Z 30, Z 50 and Z fc; extract_key.py recovers them into the JSON
key file this script consumes.

Scheme discriminator: a legacy image has 32 ASCII spaces at file offset 0x20.
The newer bodies (Z 5II, Z 50II, Z 6III, ZR) put them at 0x260 and use a
different, unbroken scheme -- those are rejected here.

Decrypted layout: the 32-byte header, then a module directory of 32-byte
entries `[BE32 offset][BE32 length][8 pad][16-byte NUL-padded ASCII name]`,
chained so that offset + length == the next offset.

Requires numpy.
"""

import argparse
import hashlib
import json
import re
import struct
import sys

import numpy as np

HDR = 0x20          # bytes of plaintext header before the body
SEC = 256           # sector size == T1 period
TABLE = 0x20        # module directory offset within the body
NEW_SCHEME = 0x260  # where the newer, unbroken bodies put their 32 spaces
NAME_RE = re.compile(rb"[0-9A-Za-z_][0-9A-Za-z_.]{2,15}\Z")
MIN_ZERO_FRACTION = 0.20

EX_USAGE = 2        # bad arguments or unreadable input
EX_KEY = 3          # key file rejected
EX_SCHEME = 4       # input is not a legacy-scheme image
EX_SANITY = 5       # decrypted, but the result does not look like firmware


def die(code, msg):
    print("error: " + msg, file=sys.stderr)
    sys.exit(code)


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
    """Read the module directory.

    At body+0x20 sits a header record, then `count` 32-byte descriptors:

        0x20          [BE32 count][BE32 dirsize][8 pad][16-byte package name]
        0x20+32*(i+1) [BE32 offset][BE32 length][8 pad][16-byte module name]

    dirsize == 48 + 32 * count. Descriptors chain exactly
    (offset + length == next offset) from the first one and close 16 bytes
    before end-of-body. Names are NUL-padded and truncated at 16 characters,
    so a long one loses its extension ("eg1850_mas_01700"); do not require
    one. The final descriptor is the trailing payload and carries no name.
    """
    mods = []
    if len(plain_body) < 0x40:
        return mods
    count, dirsize = struct.unpack_from(">II", plain_body, 0x20)
    if not 0 < count <= limit or dirsize != 48 + 32 * count:
        return mods
    for i in range(1, count + 1):
        off = 0x20 + i * 32
        if off + 32 > len(plain_body):
            break
        start, length = struct.unpack_from(">II", plain_body, off)
        raw = plain_body[off + 16:off + 32].rstrip(b"\0")
        name = raw.decode() if NAME_RE.match(raw) else "(trailer)"
        mods.append((name, start, length))
    return mods

def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 2 usage, 3 bad key, 4 wrong scheme, 5 failed sanity check.")
    ap.add_argument("key", help="key JSON from extract_key.py")
    ap.add_argument("firmware", help="encrypted .bin image")
    ap.add_argument("out", help="decrypted output file")
    args = ap.parse_args()

    t1, t2, t3 = load_key(args.key)
    try:
        raw = open(args.firmware, "rb").read()
    except OSError as exc:
        die(EX_USAGE, str(exc))
    if len(raw) <= HDR + 32:
        die(EX_SCHEME, "%s is only %d bytes" % (args.firmware, len(raw)))
    check_scheme(raw, args.firmware)

    plain = decrypt(raw, t1, t2, t3)
    mods = parse_table(plain[HDR:])
    zero = plain.count(0) / len(plain)

    print("module table:")
    for name, off, length in mods:
        print("   %-18s off=0x%08x len=0x%08x" % (name, off, length))
    if not mods:
        print("   (none)")

    # the module names carry the firmware version, e.g. eg1985_018100.bi for 1.81
    want = re.findall(r"\d+", args.firmware.rsplit("/", 1)[-1])
    want = want[-1] if want else ""
    if want and mods and not any(want in name for name, _, _ in mods):
        print("warning: no module name contains the version digits %r from the "
              "input filename" % want)

    if not mods:
        die(EX_SANITY, "no module name parsed -- the key or the image is wrong; "
                       "nothing written.")
    if zero < MIN_ZERO_FRACTION:
        die(EX_SANITY, "only %.1f%% zero bytes (expected > %.0f%%) -- decryption is "
                       "wrong; nothing written."
                       % (100 * zero, 100 * MIN_ZERO_FRACTION))

    with open(args.out, "wb") as fh:
        fh.write(plain)
    print("\nwrote %s" % args.out)
    print("  size          %d bytes" % len(plain))
    print("  zero bytes    %.1f%%" % (100 * zero))
    print("  modules       %d (%s)" % (len(mods), ", ".join(m[0] for m in mods)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
