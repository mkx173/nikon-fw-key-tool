#!/usr/bin/env python3
"""Recover the eight-byte header-digest key for legacy Z 8 / Z 9 images.

    python3 solve_signature_e7.py --key key.json \
        --firmware Z_8_0300.bin Z_8_0311.bin --out sig.json

The digest is SHA1(decrypted_body || K8), including the checksum trailer.
K8 = seed XOR k, where the seed is an eight-byte model-specific constant and:

    k[i] = (b + a * ((i + 1) * M + i * (i + 1) // 2)) & 0xFF

Seed candidates sit 24 bytes before a SHA-1 initialisation-vector literal.
Search all supported (a, b, M) combinations against each image's header;
multiple revisions must agree on K8. Other models require a different seed
recovery method and are rejected by model ID.

Requires NumPy via decrypt_firmware. See README.md for scope and verification.
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

# Model ID from the first module name, e.g. ex2070_030000.bi -> 2070.
E7_MODELS = {"2070": "Z 8", "1990": "Z 9"}
MODEL_RE = re.compile(r"[A-Za-z]{2}(\d{4})")

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


def first_module_name(plain):
    """Read the first module name at body 0x30 for model identification."""
    return bytes(plain[fw.HDR + 0x30:fw.HDR + 0x40]).rstrip(b"\0").decode(
        "ascii", "replace")


def require_expeed7(plain, path):
    """Refuse anything but a Z 8 or Z 9, naming what was seen."""
    module = first_module_name(plain)
    found = MODEL_RE.match(module)
    model = found.group(1) if found else None
    if model not in E7_MODELS:
        fw.die(EX_SCOPE,
               "%s is model id %s (module %r), which this tool does not handle.\n"
               "       Only the EXPEED 7 legacy bodies are supported: %s.\n"
               "       The EXPEED 6 bodies -- Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 30,\n"
               "       Z 50, Z fc -- build the seed from immediates instead of a\n"
               "       literal, so recovering theirs needs a different method and\n"
               "       belongs in its own script."
               % (os.path.basename(path), model or "unknown", module,
                  ", ".join("%s (%s)" % (n, i) for i, n in sorted(E7_MODELS.items()))))
    return E7_MODELS[model]


def seed_offsets(plain, path):
    """Return candidate seed offsets 24 bytes before each SHA-1 IV literal."""
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
    """Decrypt and validate an image; return (header, plaintext)."""
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
    """Return a key matching header[:20], or None if no candidate matches."""
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
    ap.add_argument("--key", required=True, help="key JSON from extract_key.py")
    ap.add_argument("--firmware", required=True, nargs="+",
                    help="one or more UNMODIFIED Z 8 or Z 9 images of the SAME camera")
    ap.add_argument("--out", help="write the recovered key to this JSON file")
    ap.add_argument("--force", action="store_true",
                    help="replace --out if it already exists")
    args = ap.parse_args()
    fw.refuse_clobber(args.out, args.force)

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
