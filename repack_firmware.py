#!/usr/bin/env python3
"""Repack a legacy-scheme Nikon image, recomputing both CRCs and the header SHA-1.

    python3 repack_firmware.py key.json sig.json Z_8_0311.bin Z_8_0312.bin \
        --patch vr2070:0x1000:deadbeef

Editing a decrypted body invalidates three things, and all three are fixed here:

    module CRC16    BE16 at the end of each module, over module[:-2]
    package CRC16   BE16 at body[-16:], over body[:-16]
    header SHA-1    header[0:20] == SHA1(body || K8)      -- see solve_signature_e7.py

The signature covers the body after every CRC is settled, so the order matters:
modules, then package, then header. header[20:32] is not covered by the digest
and is passed through untouched.

Encryption is the same XOR as decryption, so decrypt_firmware.decrypt() is its
own inverse -- including the detail that the 32-space label at body 0x00 is
literal and must NOT be enciphered, which a from-scratch packer gets wrong.

Patches are length-preserving on purpose. Module extents chain exactly and the
directory stores absolute body offsets, so resizing a module means rewriting
every following descriptor; refusing that keeps this tool honest about what it
verifies. A patch may not touch a module's own 2 CRC bytes -- those are output,
not input.

Every run re-reads its own output and re-validates it with the same code
decrypt_firmware.py uses. The file is written to a temporary name and renamed
into place, so a failure -- a full disk, a bad path, a failed check -- leaves no
output behind rather than a truncated image with a plausible header.

What `--selftest` does and does not prove: with no edits the recomputed digest
necessarily equals the stored one, so a bit-identical round trip does NOT show
the digest was recomputed at all -- a repacker that simply copied the vendor
header would pass it. It proves the cipher, the CRC pass and the container
walk are faithful. What proves the digest is really recomputed is a patched run
(the digest must change) and the stock pre-check below (a wrong construction
cannot reproduce the vendor header).

The camera also matches the package FILENAME against a wildcard pattern before
it looks inside, so keep the vendor shape (e.g. Z_8_0312.bin, not
Z_8_0311_mod.bin) or the file is invisible rather than rejected.

Requires numpy (via decrypt_firmware).
"""

import argparse
import binascii
import hashlib
import json
import os
import struct
import sys

import decrypt_firmware as fw

EX_PATCH = 7        # a patch could not be applied as given
EX_VERIFY = 8       # our own output failed re-validation


def load_sig(path):
    """Load K8, refusing a file that fails its own self_check."""
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except (OSError, ValueError) as exc:
        fw.die(fw.EX_KEY, "cannot read signature key %s: %s" % (path, exc))
    if "K8" not in doc:
        fw.die(fw.EX_KEY, "%s has no K8" % path)
    try:
        k8 = bytes.fromhex(doc["K8"])
    except ValueError:
        fw.die(fw.EX_KEY, "K8 is not valid hex")
    if len(k8) != 8:
        fw.die(fw.EX_KEY, "K8 is %d bytes, expected 8" % len(k8))
    if "self_check" in doc:
        got = hashlib.sha256(k8).hexdigest()
        if doc["self_check"] != got:
            fw.die(fw.EX_KEY, "K8 fails its own self_check\n  recorded %s\n  actual   %s"
                   % (doc["self_check"], got))
    return k8


def sign(body, k8):
    """The header digest for this body."""
    h = hashlib.sha1()
    h.update(body)
    h.update(k8)
    return h.digest()


def find_module(mods, want):
    """Exact module name, or an unambiguous prefix of one."""
    hit = [m for m in mods if m[0] == want] or [m for m in mods if m[0].startswith(want)]
    if not hit:
        fw.die(EX_PATCH, "no module named %r; have %s"
               % (want, ", ".join(m[0] for m in mods)))
    if len(hit) > 1:
        fw.die(EX_PATCH, "%r matches %d modules: %s"
               % (want, len(hit), ", ".join(m[0] for m in hit)))
    return hit[0]


def apply_patch(body, mods, spec):
    """MODULE:OFFSET:HEXBYTES, offset relative to the module start."""
    parts = spec.split(":")
    if len(parts) != 3:
        fw.die(EX_PATCH, "--patch wants MODULE:OFFSET:HEXBYTES, got %r" % spec)
    name, off_s, hex_s = parts
    try:
        off = int(off_s, 0)
    except ValueError:
        fw.die(EX_PATCH, "%r is not a number" % off_s)
    try:
        data = bytes.fromhex(hex_s)
    except ValueError:
        fw.die(EX_PATCH, "%r is not valid hex" % hex_s)
    if not data:
        fw.die(EX_PATCH, "empty patch for %s" % name)

    mod_name, start, length = find_module(mods, name)
    payload = length - 2                      # the last 2 bytes are the CRC
    if off < 0:
        fw.die(EX_PATCH, "patch offset into %s is negative (%d)" % (mod_name, off))
    if off + len(data) > payload:
        fw.die(EX_PATCH, "patch at %s+0x%x..0x%x leaves the module payload "
               "(0x0..0x%x; its last 2 bytes are the CRC)"
               % (mod_name, off, off + len(data), payload))
    body[start + off:start + off + len(data)] = data
    return mod_name, off, len(data)


def apply_replace(body, mods, spec):
    """MODULE=PATH, replacing the whole payload. Length must be unchanged."""
    if "=" not in spec:
        fw.die(EX_PATCH, "--replace wants MODULE=PATH, got %r" % spec)
    name, path = spec.split("=", 1)
    mod_name, start, length = find_module(mods, name)
    payload = length - 2
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        fw.die(EX_PATCH, str(exc))
    if len(data) != payload:
        fw.die(EX_PATCH, "%s is %d bytes but %s's payload is %d. Module extents chain "
               "exactly, so a replacement must be the same size."
               % (path, len(data), mod_name, payload))
    body[start:start + payload] = data
    return mod_name, 0, len(data)


def reseal(body, mods, k8):
    """Recompute every module CRC, then the package CRC, then the header digest."""
    for _, start, length in mods:
        crc = binascii.crc_hqx(bytes(body[start:start + length - 2]), 0)
        struct.pack_into(">H", body, start + length - 2, crc)
    struct.pack_into(">H", body, len(body) - fw.TRAILER,
                     binascii.crc_hqx(bytes(body[:-fw.TRAILER]), 0))
    return sign(bytes(body), k8)


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 2 usage, 3 bad key, 4 wrong scheme, 5 invalid structure, "
               "7 bad patch, 8 output failed verification.")
    ap.add_argument("key", help="key JSON from extract_key.py")
    ap.add_argument("sig", help="signature key JSON from solve_signature_e7.py")
    ap.add_argument("firmware", help="stock encrypted .bin to start from")
    ap.add_argument("out", help="repacked encrypted .bin to write")
    ap.add_argument("--patch", action="append", default=[], metavar="MODULE:OFF:HEX",
                    help="patch bytes in a module, repeatable")
    ap.add_argument("--replace", action="append", default=[], metavar="MODULE=PATH",
                    help="replace a module payload from a file, repeatable")
    ap.add_argument("--selftest", action="store_true",
                    help="repack with no edits; the output must be bit-identical to the input")
    args = ap.parse_args()

    if os.path.realpath(args.out) == os.path.realpath(args.firmware):
        fw.die(fw.EX_USAGE,
               "output is the same file as the input; that would destroy the stock\n"
               "       image, which is the only thing a bad repack can be compared against.")

    key = fw.load_key(args.key)
    k8 = load_sig(args.sig)
    try:
        raw = open(args.firmware, "rb").read()
    except OSError as exc:
        fw.die(fw.EX_USAGE, str(exc))
    if len(raw) <= fw.HDR + 32:
        fw.die(fw.EX_SCHEME, "%s is only %d bytes" % (args.firmware, len(raw)))
    fw.check_scheme(raw, args.firmware)

    plain = fw.decrypt(raw, *key)
    try:
        mods = fw.validate_firmware(memoryview(plain)[fw.HDR:])
    except ValueError as exc:
        fw.die(fw.EX_SANITY, "%s: %s; refusing to start from a broken image."
               % (args.firmware, exc))

    # K8 belongs to one camera. If it does not verify the stock header, it is the
    # wrong key and every signature we write would be wrong too.
    stock = sign(plain[fw.HDR:], k8)
    if stock != plain[:20]:
        fw.die(fw.EX_KEY,
               "this K8 does not verify %s\n  header   %s\n  computed %s\n"
               "       Wrong camera, or the image is already modified."
               % (args.firmware, plain[:20].hex(), stock.hex()))
    print("stock signature verified with the given K8")

    body = bytearray(plain[fw.HDR:])
    edits = [apply_patch(body, mods, s) for s in args.patch]
    edits += [apply_replace(body, mods, s) for s in args.replace]
    if args.selftest and edits:
        fw.die(fw.EX_USAGE, "--selftest makes no edits; drop --patch/--replace")

    digest = reseal(body, mods, k8)
    out = digest + plain[20:fw.HDR] + bytes(body)   # header[20:32] uncovered, kept
    cipher = fw.decrypt(out, *key)            # XOR, so the same call re-encrypts

    # Verify our own output the way the real tool would, before writing it.
    check = fw.decrypt(cipher, *key)
    if check != out:
        fw.die(EX_VERIFY, "re-encryption did not round-trip; nothing written.")
    try:
        fw.validate_firmware(memoryview(check)[fw.HDR:])
    except ValueError as exc:
        fw.die(EX_VERIFY, "our own output fails validation (%s); nothing written." % exc)
    if sign(check[fw.HDR:], k8) != check[:20]:
        fw.die(EX_VERIFY, "our own output fails its signature; nothing written.")
    if args.selftest and cipher != raw:
        fw.die(EX_VERIFY, "selftest: output differs from the input in %d byte(s)."
               % sum(a != b for a, b in zip(cipher, raw)))

    # Write via a temp file and rename. A short write straight to the destination
    # would leave a truncated 100 MB file sitting there named like firmware.
    tmp = args.out + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(cipher)
        os.replace(tmp, args.out)
    except OSError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        fw.die(fw.EX_USAGE, "cannot write %s: %s; nothing left behind." % (args.out, exc))

    print("\nwrote %s" % args.out)
    print("  size          %d bytes" % len(cipher))
    for name, off, n in edits:
        print("  patched       %s +0x%x, %d byte(s)" % (name, off, n))
    print("  header SHA-1  %s" % digest.hex())
    print("  checksums     %d module CRCs + package CRC recomputed" % len(mods))
    print("  cipher bytes  %d differ from the input"
          % sum(a != b for a, b in zip(cipher, raw)))
    if args.selftest:
        print("  selftest      output is bit-identical to the input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
