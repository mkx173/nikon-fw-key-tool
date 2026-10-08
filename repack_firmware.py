#!/usr/bin/env python3
"""Repack a legacy Nikon image with updated CRCs and header digest.

    python3 repack_firmware.py --key key.json --sig sig.json \
        --firmware Z_8_0311.bin --out Z_8_0312.bin \
        --patch-module eg:0x1000:deadbeef

Edits preserve module lengths and exclude CRC bytes. Resealing runs in order:
module CRCs, package CRC, then SHA1(body || K8). Header bytes 20:32 are preserved.
The input signature and rebuilt image must verify before an atomic output rename.
Existing outputs require --force; output must differ from the input path.

--selftest requires a bit-identical round trip without edits. It checks the
container round trip but alone cannot prove digest recomputation. Keep the
vendor filename pattern so the camera recognises the package.

Requires NumPy via decrypt_firmware. See README.md for formats and migration.
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
EX_DEPRECATED = 9   # old module selectors require migration


# Old selectors paired name[i+1] with extent[i]. Migrate by directory position;
# prefix mappings fail when modules share a prefix (e.g. eg master/slave).

# Component descriptions use the corrected module names.
DESCRIBES = [
    ("ex", "the external body-control micro"),
    ("_tpj01", "a second micro"),
    ("eg", "the main application"),
    ("vr", "the vibration-reduction unit (NikonBVR)"),
    ("li", "the Linux image (NISI)"),
]


def describe(name):
    for prefix, what in DESCRIBES:
        if name.startswith(prefix):
            return what
    return "unidentified"


def old_pairing(mods):
    """Pair extent[i] with name[i+1], leaving the last extent unnamed."""
    return [((mods[i + 1][0] if i + 1 < len(mods) else "(unnamed)"),
             mods[i][1], mods[i][2]) for i in range(len(mods))]


def resolve_as_old(mods, want):
    """Resolve an old selector to (current_name, error_note)."""
    old = old_pairing(mods)
    hit = [m for m in old if m[0] == want] or [m for m in old if m[0].startswith(want)]
    if not hit:
        return None, "%r matched no module under the old naming either" % want
    if len(hit) > 1:
        return None, ("%r matched %d modules under the old naming, so the old "
                      "tool refused it too" % (want, len(hit)))
    start = hit[0][1]
    now = [m for m in mods if m[1] == start]
    if len(now) != 1:
        return None, "could not identify the module at body 0x%x" % start
    return now[0][0], None


def translate_specs(mods, specs, sep):
    """[(spec, new_spec_or_None, note_or_None)] for one deprecated flag."""
    out = []
    for spec in specs:
        name = spec.split(sep, 1)[0]
        new_name, note = resolve_as_old(mods, name)
        if new_name is None:
            out.append((spec, None, note))
        else:
            out.append((spec, new_name + spec[len(name):],
                        "%r selected the extent now named %r (%s)"
                        % (name, new_name, describe(new_name))))
    return out


def deprecation_notice(mods, patches, replaces):
    """Print directory-based flag migrations and exit; do not guess unresolved selectors."""
    out = [
        "--patch and --replace are deprecated because module names changed meaning.",
        "",
        "This tool used to pair each module with the PREVIOUS descriptor's name, so",
        "the name you typed selected a different module than it does now. Decryption",
        "and checksums were never affected, and packages built with the old naming are",
        "self-consistent -- but a command line written against it now resolves to the",
        "wrong module and would still succeed.",
        "",
        "For THIS image, old selector -> the module it actually chose:",
        "",
    ]
    old = old_pairing(mods)
    w0 = max([len(m[0]) for m in old] + [len("old name")])
    w1 = max([len(m[0]) for m in mods] + [len("is now named")])
    out.append("  %-*s  %-*s  %s" % (w0, "old name", w1, "is now named", "which is"))
    out.append("  %s  %s  %s" % ("-" * w0, "-" * w1, "-" * 24))
    for (old_name, start, _), now in zip(old, mods):
        out.append("  %-*s  %-*s  %s" % (w0, old_name, w1, now[0], describe(now[0])))

    rewrites, blocked = [], []
    for flag, specs, sep in (("--patch-module", patches, ":"),
                             ("--replace-module", replaces, "=")):
        for spec, fixed, note in translate_specs(mods, specs, sep):
            if fixed:
                rewrites.append("  %s %s" % (flag, fixed))
                rewrites.append("      (%s)" % note)
            else:
                blocked.append("  %s %s" % (flag, spec))
                blocked.append("      CANNOT VERIFY: %s." % note)
                blocked.append("      Re-aim it yourself against the table above.")
    if rewrites:
        out += ["", "Re-aim it and use the new flags, which have the corrected "
                    "semantics:", ""] + rewrites
    if blocked:
        out += ["", "No rewrite offered for:", ""] + blocked
    out += [
        "",
        "Then CHECK the 'module at body 0x...' line the repacker prints before you",
        "flash anything. See 'Migrating old commands' in README.md.",
    ]
    fw.die(EX_DEPRECATED, "\n".join(out))


def load_sig(path):
    """Load the eight-byte K8 and verify its SHA-256 hash if present."""
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
    """Return SHA1(body || K8)."""
    h = hashlib.sha1()
    h.update(body)
    h.update(k8)
    return h.digest()


def find_module(mods, want):
    """Resolve an exact module name or an unambiguous prefix."""
    hit = [m for m in mods if m[0] == want] or [m for m in mods if m[0].startswith(want)]
    if not hit:
        fw.die(EX_PATCH, "no module named %r; have %s"
               % (want, ", ".join(m[0] for m in mods)))
    if len(hit) > 1:
        fw.die(EX_PATCH, "%r matches %d modules: %s"
               % (want, len(hit), ", ".join(m[0] for m in hit)))
    return hit[0]


def apply_patch(body, mods, spec):
    """Apply MODULE:OFFSET:HEXBYTES within the payload; offset is module-relative."""
    parts = spec.split(":")
    if len(parts) != 3:
        fw.die(EX_PATCH, "--patch-module wants MODULE:OFFSET:HEXBYTES, got %r" % spec)
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
    """Apply MODULE=PATH; replacement must match the payload size without CRC bytes."""
    if "=" not in spec:
        fw.die(EX_PATCH, "--replace-module wants MODULE=PATH, got %r" % spec)
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
               "7 bad patch, 8 output failed verification, 9 deprecated flag.")
    ap.add_argument("--key", required=True, help="key JSON from extract_key.py")
    ap.add_argument("--sig", required=True,
                    help="signature key JSON from solve_signature_e7.py")
    ap.add_argument("--firmware", required=True,
                    help="stock encrypted .bin to start from")
    ap.add_argument("--out", required=True, help="repacked encrypted .bin to write")
    ap.add_argument("--force", action="store_true",
                    help="replace --out if it already exists")
    ap.add_argument("--patch-module", action="append", default=[],
                    metavar="MODULE:OFF:HEX",
                    help="patch bytes in a module, repeatable")
    ap.add_argument("--replace-module", action="append", default=[],
                    metavar="MODULE=PATH",
                    help="replace a module payload from a file, repeatable")
    ap.add_argument("--patch", action="append", default=[], metavar="MODULE:OFF:HEX",
                    help="DEPRECATED, exits 9: module names changed meaning; "
                         "use --patch-module")
    ap.add_argument("--replace", action="append", default=[], metavar="MODULE=PATH",
                    help="DEPRECATED, exits 9: use --replace-module")
    ap.add_argument("--selftest", action="store_true",
                    help="repack with no edits; the output must be bit-identical to the input")
    args = ap.parse_args()
    fw.refuse_clobber(args.out, args.force)

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

    # Migration advice requires a validated directory.
    if args.patch or args.replace:
        deprecation_notice(mods, args.patch, args.replace)

    # Confirm the model-specific K8 against the input before editing.
    stock = sign(plain[fw.HDR:], k8)
    if stock != plain[:20]:
        fw.die(fw.EX_KEY,
               "this K8 does not verify %s\n  header   %s\n  computed %s\n"
               "       Wrong camera, or the image is already modified."
               % (args.firmware, plain[:20].hex(), stock.hex()))
    print("stock signature verified with the given K8")

    body = bytearray(plain[fw.HDR:])
    edits = [apply_patch(body, mods, s) for s in args.patch_module]
    edits += [apply_replace(body, mods, s) for s in args.replace_module]
    if args.selftest and edits:
        fw.die(fw.EX_USAGE, "--selftest makes no edits; drop --patch-module/--replace-module")

    digest = reseal(body, mods, k8)
    out = digest + plain[20:fw.HDR] + bytes(body)   # header[20:32] uncovered, kept
    cipher = fw.decrypt(out, *key)            # XOR, so the same call re-encrypts

    # Check the cipher round trip, container integrity and digest before writing.
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

    # Rename only after a complete write; remove the temporary file on failure.
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
    extents = {m[0]: (m[1], m[2]) for m in mods}
    for name, off, n in edits:
        start, length = extents[name]
        # Report the resolved extent so users can confirm the patch target.
        print("  patched       %s +0x%x, %d byte(s)" % (name, off, n))
        print("                module at body 0x%x, 0x%x bytes; wrote body 0x%x"
              % (start, length, start + off))
    print("  header SHA-1  %s" % digest.hex())
    print("  checksums     %d module CRCs + package CRC recomputed" % len(mods))
    print("  cipher bytes  %d differ from the input"
          % sum(a != b for a, b in zip(cipher, raw)))
    if args.selftest:
        print("  selftest      output is bit-identical to the input")
    return 0


if __name__ == "__main__":
    sys.exit(main())
