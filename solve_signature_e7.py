#!/usr/bin/env python3
"""Recover the 8-byte signature key an EXPEED 7 legacy body appends before hashing.

    python3 solve_signature_e7.py key.json Z_8_0311.bin Z_8_0300.bin -o sig.json

The 32-byte plaintext header is not opaque. Its first 20 bytes are a SHA-1:

    header[0:20] == SHA1( decrypt(image)[0x20:] || K8 )

The hashed message is the whole DECRYPTED body -- label, directory, every
module and the checksum trailer, to end of file -- followed by 8 key bytes that
are never stored in the image. header[20:32] is not covered and is not checked.

K8 is a per-body constant, not per-version: the same 8 bytes verify every
firmware revision of one camera. It is built in the camera from an 8-byte seed
XORed with a short keystream,

    k[i] = (b + a * ((i + 1) * M + i * (i + 1) // 2)) & 0xFF

so only (a, b, M) vary -- a cheap exhaustive search once the seed is known. The
seed is a constant in the body itself, 24 bytes before the SHA-1 initialisation
vector (stored little-endian, so `01 23 45 67 89 ab cd ef`), which is the anchor
searched for here.

## Scope: EXPEED 7 only -- the Z 8 and Z 9

Those bodies hold the seed in a literal pool, so it can be read out of the image
the user already supplied and nothing has to ship with this tool.

The EXPEED 6 bodies -- Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 30, Z 50, Z fc -- are
refused up front, by the model id in the package name. They build the seed with
`movz`/`movk` immediates instead, so there is no literal to find, and most of
them do not use this keystream family at all. Recovering theirs needs a
different method and belongs in its own script; this one says so rather than
guessing. The id is checked directly because the IV literal alone does not
distinguish the two: EXPEED 6 bodies contain one too, just not with a seed in
front of it, so keying the test on the anchor misreports them as modified.

No key material ships here. Recovering K8 needs one image whose header
signature is intact -- a stock image, or one repack_firmware.py signed -- exactly
as extract_key.py needs real images to recover T1/T2/T3. Give two or more images of the same camera and each is
required to agree, which is what makes a hit trustworthy rather than lucky.

Requires numpy (via decrypt_firmware).
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time

import decrypt_firmware as fw

IV = bytes.fromhex("0123456789abcdef")  # SHA-1 H0,H1 as stored, little-endian
SEED_DELTA = 24                 # the seed sits this far before the IV literal
MULTIPLIERS = (0x260, 0xD3)     # the two keystream variants present in shipped code

# Model id from the package name, e.g. "ex2070_030000.bi" -> 2070. The legacy
# scheme's EXPEED 7 bodies are exactly these two.
E7_MODELS = {"2070": "Z 8", "1990": "Z 9"}
PACKAGE_RE = re.compile(r"[A-Za-z]{2}(\d{4})")

EX_UNSOLVED = 6     # no candidate keystream reproduced the header digest
EX_SCOPE = 9        # not an EXPEED 7 body
EX_DISAGREE = 10    # two images of one camera solved to different keys
EX_NOSEED = 11      # the seed literal could not be located


def keystream(a, b, mul, n=8):
    out = bytearray()
    acc = b
    step = (a * mul) & 0xFFFFFFFF
    for _ in range(n):
        acc = (acc + step) & 0xFFFFFFFF
        out.append(acc & 0xFF)
        step = (step + a) & 0xFFFFFFFF
    return bytes(out)


def candidates():
    """Every (a, b, mul) keystream, built once and reused for each image."""
    return [(keystream(a, b, mul), a, b, mul)
            for mul in MULTIPLIERS for a in range(256) for b in range(256)]


def package_name(plain):
    """The 16-byte package name from the directory header record."""
    return bytes(plain[fw.HDR + 0x30:fw.HDR + 0x40]).rstrip(b"\0").decode(
        "ascii", "replace")


def require_expeed7(plain, path):
    """Refuse anything but a Z 8 or Z 9, naming what was seen."""
    package = package_name(plain)
    found = PACKAGE_RE.match(package)
    model = found.group(1) if found else None
    if model not in E7_MODELS:
        fw.die(EX_SCOPE,
               "%s is model id %s (package %r), which this tool does not handle.\n"
               "       Only the EXPEED 7 legacy bodies are supported: %s.\n"
               "       The EXPEED 6 bodies -- Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 30,\n"
               "       Z 50, Z fc -- build the seed from immediates instead of a\n"
               "       literal, so recovering theirs needs a different method and\n"
               "       belongs in its own script."
               % (os.path.basename(path), model or "unknown", package,
                  ", ".join("%s (%s)" % (n, i) for i, n in sorted(E7_MODELS.items()))))
    return E7_MODELS[model]


def seed_offsets(plain, path):
    """Where the seed literal sits, from the IV anchor."""
    offsets, pos = [], plain.find(IV)
    while pos >= 0:
        if pos - SEED_DELTA >= 0:
            offsets.append(pos - SEED_DELTA)
        pos = plain.find(IV, pos + 1)
    if not offsets:
        fw.die(EX_NOSEED,
               "%s has no SHA-1 initialisation vector literal, so the seed constant\n"
               "       cannot be located even though this is an EXPEED 7 body."
               % os.path.basename(path))
    return offsets


def load_image(key, path):
    """Decrypt, insist the structure is intact, and return (header, plaintext)."""
    try:
        raw = open(path, "rb").read()
    except OSError as exc:
        fw.die(fw.EX_USAGE, str(exc))
    if len(raw) <= fw.HDR + 32:
        fw.die(fw.EX_SCHEME, "%s is only %d bytes" % (path, len(raw)))
    fw.check_scheme(raw, path)
    plain = fw.decrypt(raw, *key)
    try:
        fw.validate_firmware(memoryview(plain)[fw.HDR:])
    except ValueError as exc:
        fw.die(fw.EX_SANITY, "%s: %s.\n"
               "       Solving needs an image whose container is intact; a corrupt one\n"
               "       has no valid signature to solve against." % (path, exc))
    return raw[:32], plain


def solve(hdr, plain, cands, path):
    """Find the K8 whose digest reproduces header[0:20]. None if nothing fits."""
    want = hdr[:20]
    base = hashlib.sha1(memoryview(plain)[fw.HDR:])
    for off in seed_offsets(plain, path):
        seed = plain[off:off + 8]
        for ks, a, b, mul in cands:
            k8 = bytes(s ^ k for s, k in zip(seed, ks))
            h = base.copy()
            h.update(k8)
            if h.digest() == want:
                return {"K8": k8.hex(), "a": a, "b": b, "multiplier": mul,
                        "seed": seed.hex(), "seed_offset": off}
    return None


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes: 2 usage, 3 bad key, 4 wrong scheme, 5 invalid structure, "
               "6 unsolved, 9 not an EXPEED 7 body, 10 images disagree, "
               "11 seed not found.")
    ap.add_argument("key", help="key JSON from extract_key.py")
    ap.add_argument("firmware", nargs="+",
                    help="one or more UNMODIFIED Z 8 or Z 9 images of the SAME camera")
    ap.add_argument("-o", "--out", help="write the recovered key to this JSON file")
    args = ap.parse_args()

    key = fw.load_key(args.key)
    cands = candidates()
    print("searching %d keystreams per seed offset" % len(cands))

    result, agreed = None, []
    for path in args.firmware:
        hdr, plain = load_image(key, path)
        name = os.path.basename(path)
        model = require_expeed7(plain, path)
        t0 = time.time()
        got = solve(hdr, plain, cands, path)
        if got is None:
            fw.die(EX_UNSOLVED,
                   "%s: no keystream reproduced header[0:20].\n"
                   "       The seed was found, so this is an EXPEED 7 body, but its\n"
                   "       keystream is not one of the two known variants -- or the\n"
                   "       image has been modified since Nikon signed it." % name)
        print("  %-18s %-4s K8=%s  a=0x%02x b=0x%02x mul=0x%x  seed @ body 0x%x  (%.1fs)"
              % (name, model, got["K8"], got["a"], got["b"], got["multiplier"],
                 got["seed_offset"], time.time() - t0))
        if result is None:
            result = got
            result["model"] = model
        elif got["K8"] != result["K8"]:
            fw.die(EX_DISAGREE,
                   "%s solved to K8=%s but %s solved to K8=%s.\n"
                   "       Two images of one camera must agree. Are these different models?"
                   % (name, got["K8"], agreed[0], result["K8"]))
        agreed.append(name)

    print("\nK8 = %s" % result["K8"])
    print("  agreed by     %d image(s): %s" % (len(agreed), ", ".join(agreed)))
    if len(agreed) == 1:
        print("  NOTE          a single image cannot cross-check itself; pass a second\n"
              "                firmware revision of the same camera to confirm.")

    if args.out:
        doc = dict(result)
        doc["scheme"] = "legacy-sha1-suffix"
        doc["signature"] = "header[0:20] == SHA1(decrypt(image)[0x20:] || K8)"
        doc["sources"] = agreed
        doc["self_check"] = hashlib.sha256(bytes.fromhex(result["K8"])).hexdigest()
        with open(args.out, "w") as fh:
            json.dump(doc, fh, indent=2)
            fh.write("\n")
        print("  wrote         %s" % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
