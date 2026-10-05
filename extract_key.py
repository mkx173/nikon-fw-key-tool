#!/usr/bin/env python3
"""
Recover the generation-wide Nikon "legacy scheme" keystream tables.

    python3 extract_key.py firmware/expeed6 tables/key.json

The legacy scheme (Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 8, Z 30, Z 50, Z fc) is a
three-table XOR keystream over the file body, which starts at offset 0x20:

    plain[i] = cipher[0x20 + i] ^ T1[i & 0xFF] ^ T2[(i>>8) & 0xFF] ^ T3[(i>>16) & 0xFF]

T1/T2/T3 are 256 bytes each and identical across all nine bodies, so the
keystream period is 2^24 (16 MB). A "sector" is 256 body bytes; sector index
j = i // 256 selects a = j & 0xFF in T2 and b = (j >> 8) & 0xFF in T3, so one
whole sector shares the single constant T2[a] ^ T3[b].

Recovery, in five stages:

 1. T1 up to a global constant. Each image holds thousands of constant-filled
    plaintext sectors, whose ciphertexts are the family {T1 ^ c}. Normalising
    every repeated sector value by its own first byte collapses that family to
    one value, T1 ^ T1[0]; the largest such group is it. All images agree.

 2. The global constant, via the module table. Only the right constant makes
    the directory at body+0x20 parse into ASCII module names with a
    self-consistent offset chain. This fixes the gauge T2[0] = T3[0] = 0.

 3. Ground truth for T2 ^ T3. XOR every sector by T1; whatever becomes
    constant-valued is padding, giving an observation (a, b) -> T2[a] ^ T3[b].
    Pooled across all nine images, majority vote per cell.

 4. T2 and T3 by bipartite majority propagation over those observations.

 5. A 0x00/0xFF correction pass. Padding is ambiguous between zero-fill and
    ff-fill, so whole b-classes can come out complemented. Padding is
    non-printable under *both* choices, so only genuine text breaks the tie:
    score each T3[b] against T3[b] ^ 0xFF by counting varied printable windows
    in the decrypted b-class. About 17 classes need the flip.

Requires numpy.
"""

import argparse
import collections
import datetime
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
NAME_RE = re.compile(rb"[0-9A-Za-z_][0-9A-Za-z_.]*\.(?:bi|bin)\Z")

# The nine images needed for a complete T3. Fewer leaves holes in T3.
# A sufficient set is decided by coverage, not by a fixed file list: every one
# of the 256 T3 blocks needs at least one image carrying constant-fill padding
# at that keystream offset. Four images can do it -- exactly one of the 126
# four-subsets of the nine known images does, so MINIMAL names it for the
# error hint. Any other set that reaches full coverage works just as well.
MINIMAL = ("Z_8_0311.bin", "Z7_2_0170.bin", "Z_6_0380.bin", "Z_50_0260.bin")

KNOWN = {
    "efc0ce70dcafdd96c64e95d8d50f6b7f0509fc0c2840b28d12b6f9e4877ee776": "Z_5_0150.bin",
    "ff978ffdf77c58c0b861a06e16d432d5886969f3cdd05d62f6c8e82e8a4cea54": "Z_6_0380.bin",
    "07cf19513ada5b770caec4cfc3531a6734c48aede28dcec037f0f8374ef441a2": "Z_7_0380.bin",
    "d67413c2ede6b9ce8887175f20700bd9fbad2a973a4820968c45503d15d80d96": "Z_8_0311.bin",
    "5a9640b4c07abe1ecbf5a52655cbec6b893bba045bb2a1a1d21055b9f8f9d06d": "Z6_2_0170.bin",
    "fc0e94f57500a1f0e287c6b9a036c81a5ffceccb8432a377d645b3fa35a19b6a": "Z7_2_0170.bin",
    "1a5449ef505f1f347ed4e066a6a3f588ea542240680e83f4ebcae3b16da3434a": "Z_30_0120.bin",
    "69745c9e8f3156e936918e62a4a1fad18e7078e9ea3b95d8b8e08144b1542e49": "Z_50_0260.bin",
    "e4cd838a215c113659416983b31dbdba8896591caacf7309170d4cc3c60bd1b6": "Z_fc_0181.bin",
}

# Regression check: SHA-256 prefixes of the known-correct tables.
EXPECTED_SHA = {
    "T1": "29d2e34239fc33bf0a1054fd3558536a",
    "T2": "6e87de5da7e42df91db31fae4a899a04",
    "T3": "3617957facf8b21a5a3de0f3a1f6f27c",
}

# Cribs that must survive decryption in every image. The missing "m" in
# "[commnad]" is a genuine typo in Nikon's firmware -- do not fix it.
CRIBS = [
    b"Copyright Nikon Corp.",
    b"memdump [MemAddr]",
    b"stackdump [StackBaseAddr]",
    b"command list:",
    b"logoutputchg",
    b"[commnad] [param1]",
]

MIN_ZERO_FRACTION = 0.20

# Correction-pass tuning: a 12-byte window counts as text when every byte is
# printable and at least 7 of its 11 adjacent pairs differ.
WIN = 12
MIN_VARIED = 7
FLIP_RATIO = 1.25
FLIP_MARGIN = 50


# --------------------------------------------------------------------------
# input


def load_images(dirname):
    """Return [(name, sha, sectors)] for every legacy-scheme .bin in dirname."""
    images = []
    for fn in sorted(os.listdir(dirname)):
        if not fn.lower().endswith(".bin"):
            continue
        path = os.path.join(dirname, fn)
        raw = open(path, "rb").read()
        if raw[HDR:HDR + 32] != b" " * 32:
            where = "0x260 (newer scheme)" if raw[0x260:0x280] == b" " * 32 else "nowhere"
            print("  skip %-16s 32 spaces at %s" % (fn, where))
            continue
        sha = hashlib.sha256(raw).hexdigest()
        known = KNOWN.get(sha)
        if known is None:
            print("  WARNING: %s has unknown hash %s -- using it anyway" % (fn, sha))
        elif known != fn:
            print("  %-16s renamed copy of %s" % (fn, known))
        body = raw[HDR:]
        n = len(body) // SEC
        sectors = np.frombuffer(body[:n * SEC], dtype=np.uint8).reshape(n, SEC)
        images.append((fn, sha, sectors))
        print("  %-16s %10d bytes, %7d sectors  %s"
              % (fn, len(raw), n, "verified" if known else "unverified"))
    return images


# --------------------------------------------------------------------------
# stage 1 + 2: T1


def recover_family(sectors):
    """Stage 1: T1 ^ T1[0], from the repeated constant-filled sectors."""
    blob = sectors.tobytes()
    values = [blob[i:i + SEC] for i in range(0, len(blob), SEC)]
    repeated = (s for s, c in collections.Counter(values).items() if c > 1)
    groups = collections.Counter(bytes(b ^ s[0] for b in s) for s in repeated)
    if not groups:
        return None
    norm, size = groups.most_common(1)[0]
    return norm if size >= 64 else None


def parse_table(plain_body, limit=64):
    """Read the module directory; stops at the first entry that does not parse."""
    mods = []
    for off in range(TABLE, TABLE + 32 * limit, 32):
        if off + 32 > len(plain_body):
            break
        start, length = struct.unpack_from(">II", plain_body, off)
        name = plain_body[off + 16:off + 32].rstrip(b"\0")
        if not name or not NAME_RE.match(name):
            break
        mods.append((name.decode(), start, length))
    return mods


def chain_score(mods):
    """How many consecutive entries satisfy off + len == next off."""
    return sum(1 for a, b in zip(mods, mods[1:]) if a[1] + a[2] == b[1])


def fix_constant(sectors, norm):
    """Stage 2: pick the global constant that makes the module table parse."""
    head = sectors[:2].tobytes()[:TABLE + 32 * 8]
    best, table, rank = None, [], (-1, -1)
    for g in range(256):
        t1 = bytes(b ^ g for b in norm)
        plain = bytes(b ^ t1[i % SEC] for i, b in enumerate(head))
        mods = parse_table(plain)
        here = (len(mods), chain_score(mods[1:]))
        if here > rank:
            best, table, rank = t1, mods, here
    if rank[0] < 2:
        return None, []
    return np.frombuffer(best, dtype=np.uint8), table


# --------------------------------------------------------------------------
# stage 3 + 4: T2 and T3


def collect_observations(images, t1):
    """Stage 3: majority (a, b) -> T2[a] ^ T3[b] over every padding sector."""
    keys = []
    for _, _, sectors in images:
        xored = sectors ^ t1
        const = (xored == xored[:, :1]).all(axis=1)
        j = np.nonzero(const)[0]
        a = (j & 0xFF).astype(np.uint32)
        b = ((j >> 8) & 0xFF).astype(np.uint32)
        keys.append((a << 16) | (b << 8) | xored[j, 0].astype(np.uint32))
    keys = np.concatenate(keys)
    uniq, counts = np.unique(keys, return_counts=True)
    # within each (a, b) cell the last entry after this sort is the majority
    order = np.lexsort((counts, uniq >> 8))
    uniq, counts = uniq[order], counts[order]
    cell = uniq >> 8
    winner = np.nonzero(np.r_[cell[1:] != cell[:-1], True])[0]
    obs = {}
    for i in winner:
        obs[(int(uniq[i]) >> 16, (int(uniq[i]) >> 8) & 0xFF)] = int(uniq[i]) & 0xFF
    return obs


def majority(values):
    return collections.Counter(values).most_common(1)[0][0]


def solve_tables(obs):
    """Stage 4: bipartite majority propagation with the gauge T2[0] = 0."""
    by_a = collections.defaultdict(list)
    by_b = collections.defaultdict(list)
    for (a, b), v in obs.items():
        by_a[a].append((b, v))
        by_b[b].append((a, v))

    t2 = {0: 0}
    t3 = {}
    for _ in range(64):
        before = (dict(t2), dict(t3))
        for b, pairs in by_b.items():
            seen = [v ^ t2[a] for a, v in pairs if a in t2]
            if seen:
                t3[b] = majority(seen)
        for a, pairs in by_a.items():
            seen = [v ^ t3[b] for b, v in pairs if b in t3]
            if seen:
                t2[a] = majority(seen)
        if (t2, t3) == before:
            break
    return t2, t3


# --------------------------------------------------------------------------
# stage 5: the 0x00 / 0xFF correction pass


def text_windows(plain):
    """Count all-printable, varied WIN-byte windows inside each row of plain."""
    rows = plain.shape[0]
    zero = np.zeros((rows, 1), dtype=np.int32)

    printable = (plain >= 0x20) & (plain <= 0x7E)
    cp = np.concatenate([zero, np.cumsum(printable, axis=1, dtype=np.int32)], axis=1)
    all_printable = (cp[:, WIN:] - cp[:, :-WIN]) == WIN

    differs = plain[:, 1:] != plain[:, :-1]
    cd = np.concatenate([zero, np.cumsum(differs, axis=1, dtype=np.int32)], axis=1)
    varied = (cd[:, WIN - 1:] - cd[:, :-(WIN - 1)]) >= MIN_VARIED

    return int((all_printable & varied).sum())


def correct_t3(images, t1, t2, t3):
    """Re-derive each T3[b] directly from the data.

    The majority solve can land on a constant offset by an arbitrary byte when
    some other fill value dominates a block's padding, so do not trust it and
    do not merely test the complement. For each block score every candidate by
    cnt[c] + cnt[c ^ 0xFF]; that sum is symmetric under complement, so it picks
    the correct {c, c^0xFF} pair without being able to prefer one over the
    other. Then take whichever member yields more 0x00.

    Deliberately NOT scored on printable text: UTF-16LE strings are
    (char, 0x00) pairs, and XORing those with a printable constant produces a
    run that is both printable and highly varied, so a text metric reliably
    picks the wrong constant in localised-string blocks.
    """
    base = t1 ^ t2[:, None]             # base[a] = T1 ^ T2[a]; still needs ^ T3[b]
    changed = []
    flip = np.arange(256) ^ 0xFF
    for b in range(256):
        runs = [chunk ^ base[:chunk.shape[0]]
                for _, _, sectors in images
                for start in range(b * SEC, sectors.shape[0], 1 << 16)
                for chunk in [sectors[start:start + SEC]]]
        if not runs:
            continue
        cnt = np.bincount(np.concatenate(runs).ravel(), minlength=256).astype(np.int64)
        c = int((cnt + cnt[flip]).argmax())
        if cnt[c] < cnt[c ^ 0xFF]:
            c ^= 0xFF
        if c != int(t3[b]):
            changed.append((b, int(t3[b]), c))
            t3[b] = c
    return changed


# --------------------------------------------------------------------------
# validation and output


def decrypt(sectors, t1, t2, t3):
    j = np.arange(sectors.shape[0])
    return (sectors ^ t1 ^ (t2[j & 0xFF] ^ t3[(j >> 8) & 0xFF])[:, None])


def validate(images, t1, t2, t3):
    """Every image must show all cribs and be mostly zero padding."""
    ok = True
    for name, _, sectors in images:
        plain = decrypt(sectors, t1, t2, t3)
        zero = float((plain == 0).mean())
        blob = plain.tobytes()
        missing = [c.decode("latin1") for c in CRIBS if c not in blob]
        mods = parse_table(blob[:TABLE + 32 * 64])
        status = "ok"
        if missing:
            status = "MISSING " + ", ".join(repr(m) for m in missing)
            ok = False
        elif zero < MIN_ZERO_FRACTION:
            status = "zero fraction too low"
            ok = False
        print("  %-16s zero=%5.1f%%  modules=%2d  cribs=%d/%d  %s"
              % (name, 100 * zero, len(mods), len(CRIBS) - len(missing), len(CRIBS), status))
    return ok


def main():
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n")[1],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Needs all nine legacy-scheme images; fewer leaves holes in T3.")
    ap.add_argument("firmware_dir", help="directory of encrypted .bin images")
    ap.add_argument("out_key", help="JSON key file to write")
    args = ap.parse_args()

    if not os.path.isdir(args.firmware_dir):
        sys.exit("error: %s is not a directory" % args.firmware_dir)

    print("scanning %s" % args.firmware_dir)
    images = load_images(args.firmware_dir)
    if not images:
        sys.exit("error: no legacy-scheme images found")

    have = {sha for _, sha, _ in images}
    recognised = sum(1 for sha in have if sha in KNOWN)
    print("%d image(s): %d recognised by SHA-256, %d unrecognised (used anyway)"
          % (len(images), recognised, len(images) - recognised))

    print("\nstage 1: T1 up to a global constant")
    norms = {}
    for name, _, sectors in images:
        norm = recover_family(sectors)
        if norm is None:
            sys.exit("error: %s has no constant-XOR sector family" % name)
        norms.setdefault(norm, []).append(name)
    if len(norms) != 1:
        sys.exit("error: images disagree on T1 ^ T1[0]: %s"
                 % {k.hex()[:16]: v for k, v in norms.items()})
    norm = next(iter(norms))
    print("  all %d images agree on T1 ^ T1[0] = %s..." % (len(images), norm.hex()[:32]))

    print("\nstage 2: the global constant, via the module table")
    t1, table = fix_constant(images[0][2], norm)
    if t1 is None:
        sys.exit("error: no global constant makes the module table parse")
    print("  fixed from %s: %d entries, %d chained"
          % (images[0][0], len(table), chain_score(table[1:])))
    for name, off, length in table[:4]:
        print("    %-18s off=0x%08x len=0x%08x" % (name, off, length))

    print("\nstage 3: padding observations")
    obs = collect_observations(images, t1)
    covered = {b for _, b in obs}
    print("  %d of 65536 (a, b) cells observed, %d of 256 T3 blocks covered"
          % (len(obs), len(covered)))
    if len(covered) != 256:
        gaps = [b for b in range(256) if b not in covered]
        sys.exit("error: only %d of 256 T3 blocks are covered; %d missing: %s\n"
                 "       Add more images. A known-sufficient set is: %s"
                 % (len(covered), len(gaps),
                    ", ".join(str(b) for b in gaps[:24])
                    + (" ..." if len(gaps) > 24 else ""),
                    ", ".join(MINIMAL)))

    print("\nstage 4: bipartite majority propagation")
    t2d, t3d = solve_tables(obs)
    print("  T2 %d/256, T3 %d/256" % (len(t2d), len(t3d)))
    if len(t2d) != 256 or len(t3d) != 256:
        sys.exit("error: tables incomplete -- not enough distinct images")
    t2 = np.array([t2d[i] for i in range(256)], dtype=np.uint8)
    t3 = np.array([t3d[i] for i in range(256)], dtype=np.uint8)

    print("\nstage 5: per-block constant re-derivation")
    flipped = correct_t3(images, t1, t2, t3)
    for b, here, alt in flipped:
        print("    T3[%3d] 0x%02x -> 0x%02x" % (b, here, alt))
    print("    %d of 256 entries corrected" % len(flipped))

    print("\nvalidation")
    if not validate(images, t1, t2, t3):
        sys.exit("error: validation failed -- no key file written")

    tables = {"T1": t1.tobytes(), "T2": t2.tobytes(), "T3": t3.tobytes()}
    self_check = {k: hashlib.sha256(v).hexdigest() for k, v in tables.items()}
    print("\ntable hashes")
    drift = False
    for k in ("T1", "T2", "T3"):
        got = self_check[k][:32]
        match = got == EXPECTED_SHA[k]
        drift |= not match
        print("  %s %s  %s" % (k, got, "ok" if match else
                               "WARNING: expected " + EXPECTED_SHA[k]))
    if drift:
        print("  WARNING: tables differ from the known-good regression values.")

    key = {
        "scheme": "plain[i] = cipher[0x20 + i] ^ T1[i&0xFF] ^ T2[(i>>8)&0xFF] "
                  "^ T3[(i>>16)&0xFF]",
        "body_offset": HDR,
        "period_bytes": 1 << 24,
        "T1": tables["T1"].hex(),
        "T2": tables["T2"].hex(),
        "T3": tables["T3"].hex(),
        "sources": [{"file": name, "sha256": sha} for name, sha, _ in images],
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
                                 .replace(microsecond=0).isoformat(),
        "self_check": self_check,
    }
    with open(args.out_key, "w") as fh:
        json.dump(key, fh, indent=1)
        fh.write("\n")
    print("\nwrote %s" % args.out_key)
    return 1 if drift else 0


if __name__ == "__main__":
    sys.exit(main())
