# nikon-fw-key-tool

Recovers the keys used by Nikon's legacy firmware packaging and works with the
images: decrypt them, and — on the Z 8 and Z 9 — repack an edited image with a
valid header signature. Derive a key once, then use it.

Applies to **Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 8, Z 9, Z 30, Z 50, Z fc**.

Does **not** apply to Z f, Z 5II, Z 50II, Z 6III or ZR — those use a
different, unbroken scheme. `decrypt_firmware.py` detects them and refuses
rather than emitting garbage.

Note that the split is **not** by EXPEED generation. The Z 8 and Z 9 are
EXPEED 7 and use this legacy packaging, while the Z f is contemporary with the
Z 8 and already uses the newer scheme. Check the discriminator, not the body.

## Notice

These scripts are original work. They contain no Nikon code and no key
material: the tables are recovered at runtime from firmware images the user
supplies, and so is the 8-byte header-signature key. Nikon firmware images are
not redistributed here.

## The scheme

```
plain[0x00:0x40] = cipher[0x00:0x40]                                   # header + space label
plain[0x20 + i]  = cipher[0x20 + i] ^ T1[i & 0xFF] ^ T2[(i>>8) & 0xFF] ^ T3[(i>>16) & 0xFF]   # i >= 0x20
```

`i` is the offset into the body (file offset minus `0x20`). The first `0x20`
bytes are a plaintext header, and body bytes `0x00`–`0x1F` are a plaintext
32-space label; both pass through untouched. The keystream index still counts
the label, so the first XORed byte (body `0x20`) uses `i = 0x20`. Keystream period is 2^24
(16 MB). T1, T2 and T3 are 256 bytes each and are **generation-wide
constants** — identical across all ten bodies — so the whole key is 768
bytes. It is the same construction as the much older `Xor_Ord1/2/3` scheme in
nikon-firmware-tools, with different tables.

Legacy images are identified by 32 ASCII spaces at file offset `0x20`. The
newer scheme puts them at `0x260`.

## The header signature

The 32-byte plaintext header is not opaque. Its first 20 bytes are a SHA-1 over
the **decrypted** body plus 8 key bytes that appear nowhere in the image:

```
header[0:20] == SHA1( decrypt(image)[0x20:] || K8 )
```

The message is the whole decrypted body — space label, directory, every module
and the 16-byte checksum trailer, to end of file — and the camera appends K8 in
memory before hashing. Because the hash covers plaintext, no amount of searching
the ciphertext finds it; because of the 8-byte suffix, no range of the plaintext
matches either.

`header[20:32]` is **not** covered by the digest and is not checked. What it
holds is still unidentified; curiously, two unrelated images can share it
exactly (`Z_50_0260.bin` and `Z_8_0210.bin` do), so it is not a per-build
random value.

K8 is a per-camera constant, not per-version: one value verifies every firmware
revision of one body. It is a fixed 8-byte seed in the body XORed with a short
keystream `k[i] = (b + a * ((i + 1) * M + i * (i + 1) // 2)) & 0xFF`, so once
the seed is read out of the image only `(a, b, M)` vary and the search is
exhaustive and instant.

**Scope: the Z 8 and Z 9 only.** Those two EXPEED 7 bodies keep the seed in a
literal pool, 24 bytes before the SHA-1 initialisation vector, so it can be read
from the image you already supplied. The EXPEED 6 bodies — Z 5, Z 6, Z 6II,
Z 7, Z 7II, Z 30, Z 50, Z fc — build it from `movz`/`movk` immediates instead,
and most do not use this keystream family at all; `solve_signature_e7.py`
refuses them by model id (exit 9) rather than guessing. Recovering theirs needs a
different method and belongs in its own script.

The construction was read out of the body's own firmware-manager code, and the
repacker's `--selftest` reproduces a vendor image bit-for-bit, header digest
included (see [Verification](#verification)).

## Usage

```sh
python3 extract_key.py --firmware-dir <dir> --out <key.json>
python3 decrypt_firmware.py --key <key.json> --firmware <fw.bin> --out <out.dec>

# Z 8 / Z 9 only: recover the signature key, then repack with a valid header
python3 solve_signature_e7.py --key <key.json> --firmware <stock.bin> [...] \
    --out <sig.json>
python3 repack_firmware.py --key <key.json> --sig <sig.json> \
    --firmware <in.bin> --out <out.bin> \
    --patch-module <module>:<offset>:<hexbytes>
```

**Every parameter is named.** There are no positional arguments anywhere, so no
ordering slip can put an input path where the output goes — the failure that
would otherwise overwrite an irreplaceable vendor image with a decrypted body.
A missing flag is a usage error naming the flag, not a file written to the wrong
place. For the same reason an `--out` that already exists is refused unless
`--force` is given, and `repack_firmware.py` additionally refuses an `--out`
that resolves to the same file as its `--firmware`.

No key material ships in this repo. `extract_key.py` derives the tables and
`solve_signature_e7.py` the signature key, both from firmware images you supply;
`.gitignore` keeps images, keys and output out of git.

Pass `solve_signature_e7.py` two or more revisions of the same camera and each
is required to agree on K8 — a single image cannot cross-check itself. The
repacker re-reads and re-validates its own output, and refuses to leave a file
behind that fails. Patches are length-preserving: module extents chain exactly
and the directory stores absolute offsets, so resizing a module would mean
rewriting every following descriptor.

## How many images do you need?

Four. Every one of the 256 T3 blocks needs at least one image with
constant-fill padding at that keystream offset, and no three images span all
256. The tool checks coverage directly and names the missing blocks if short,
so any sufficient set works — but exactly one of the 126 four-subsets of the
first nine known images is sufficient:

```
Z_8_0311.bin  Z7_2_0170.bin  Z_6_0380.bin  Z_50_0260.bin
```

Four images and all nine produce byte-identical tables. The Z 9 was added
afterwards and needs no re-derivation: the existing tables decrypt it with
every checksum passing (below), which is itself a check that the tables are
generation-wide.

## How it works

1. **T1, up to a global constant.** Split the body into 256-byte sectors; find
   sector *values* occurring more than once and normalise each by XOR with its
   own first byte. The largest resulting group is `T1 ^ T1[0]`. All images must
   agree. (Padding sectors are constant-filled, so their ciphertexts differ
   only by a constant — which is also what proves the layer is XOR.)
2. **The global constant.** Try all 256; keep the one that makes the module
   directory at body `0x20` parse into valid names, tie-broken on how many
   entries satisfy `offset + length == next offset`.
3. **Observations.** Any sector that becomes constant after XOR with T1 is
   padding and yields `(a, b) -> T2[a] ^ T3[b]`, pooled across images by
   majority.
4. **T2 and T3** by bipartite majority propagation, gauge `T2[0] = 0`.
5. **Per-block re-derivation of T3** (see below).
6. **Validation.** Every image must pass the decrypter's directory and CRC
   checks (see [Verification](#verification)), or no key file is written.

### Why stage 5 does not score printable text

Padding is ambiguous between `0x00`-fill and `0xFF`-fill, so the majority solve
can land on a complemented — or arbitrarily offset — constant. The obvious fix
is to pick whichever constant yields more readable text. **That is wrong**, and
it silently corrupted five T3 entries during development.

UTF-16LE strings are `(char, 0x00)` pairs. XOR them with a printable constant
and every byte lands in the printable range with high variation, so a
"looks like text" metric scores the *wrong* constant far higher than the right
one. Block 136 decrypts to Serbian UI strings under the correct constant:

```
correct 0x9f  |i.k.l.a. .z.a. ...u.v.a.n.j.e.P.r.o.m.e.n.i. .i.m.e.|
wrong   0xa8  |^7\7[7V7.7M7V7.7:6B7A7V7Y7]7R7g7E7X7...|
```

Instead, for each block pick `c` maximising `cnt[c] + cnt[c ^ 0xFF]`. That sum
is symmetric under complement, so it selects the correct *pair* without being
able to prefer one member; then take whichever of `c` / `c ^ 0xFF` yields more
`0x00`. Order-independent, and no text heuristic anywhere.

Correctness was confirmed by disassembly, not by the metric: the repaired
blocks decode to valid ARM64 (`f96302a9 f75b03a9 f55304a9` — consecutive STP
prologues; `9f070071 01190054 e0031f2a` — cmp / b.ne / mov wzr).

## Output format

File layout is `[0x20 header][0x20 ASCII-space label][encrypted payload]`.
The space label is literal plaintext in the container, so it is passed through
rather than XORed. The header is plaintext too, and its first 20 bytes are the
SHA-1 described in [The header signature](#the-header-signature); the remaining
12 are unidentified and unchecked.

> **Module names changed meaning in this revision.** Earlier versions paired
> every module with the *previous* descriptor's name, so what they listed as
> `vr` was the main application, what they listed as `eg` was a 57 KB micro,
> and the Linux image had no name at all. Decryption, validation and
> checksums were never affected — the extents were always read correctly — and
> packages built with the old naming were self-consistent, because the name you
> typed matched the module the tool had just listed next to it.
>
> **`--patch` and `--replace` are therefore deprecated and now refuse to run.**
> They exit `9` and print the rename table with your own flags rewritten, rather
> than silently resolving to a different module: `--patch vr:0x1000` used to land
> in the main application and would now land in the vibration-reduction unit, and
> it would still succeed. Use `--patch-module` and `--replace-module`, which have
> the corrected semantics, and check the `module at body 0x…` line the repacker
> prints before you flash anything built from an old command line.
>
> | old name | was really | now called |
> | --- | --- | --- |
> | `_tpj01` | the external body-control micro | `ex` |
> | `eg` | the second micro | `_tpj01` |
> | `vr` | the main application | `eg` |
> | `li` | the vibration-reduction unit (`NikonBVR`) | `vr` |
> | `(unnamed)` | the Linux image | `li` |

The decrypted body opens with a module directory at body `0x20`: a 16-byte
header, then `count` descriptors of 32 bytes each, in which **the name comes
first**, before the extent.

```
0x20            [BE32 count][BE32 dirsize][8 pad]
0x30            count x [16-byte module name][BE32 offset][BE32 length][8 pad]
```

This is the order the camera's own reader uses: on an EXPEED 7 body
`0x4101dee0` -> `0x41016b24` copies `body[0x30:dirsize]`, case-folds the first
`0x10` bytes of each `0x20`-byte record to match it against patterns like
`EG2010_?????????`, and byte-swaps the two BE32 words at `record+0x10` and
`record+0x14`.

Earlier versions of this tool read the extent at `descriptor+0x00` and the name
at `descriptor+0x10`, treating `body+0x30` as a package name and the last
descriptor as a 16-byte unnamed one. Every byte position coincides between the
two readings, so extents and checksums were unaffected and no validation ever
caught it — but each module was reported under the *previous* descriptor's
name, which mislabelled the main application as `vr`, the Linux image as
unnamed, and the body micro as `_tpj01`.

The decrypter requires a complete directory with valid names and zero reserved
bytes. Module lengths include their two-byte CRC and must be at least two.
Offsets are relative to the body, all extents must be in bounds, and:

- `dirsize == 48 + 32 * count`
- the first module starts at `dirsize`
- descriptors chain exactly, `offset + length == next offset`, from the first
- the last descriptor ends exactly 16 bytes before end-of-body

Names are NUL-padded and truncated at 16 characters, so a long one loses its
extension (`eg1850_mas_01700`). Names encode the version, e.g.
`eg1985_018100.bi` in `Z_fc_0181.bin`; the Z 6II/Z 7II carry `_mas_`/`_sla_` pairs matching their
dual-EXPEED hardware. The four-digit field is a model id, not a version —
`1985` is the Z fc, `1990` the Z 9, `2070` the Z 8 — so `Z_9_0532.bin` holds
`eg1990_053200.bi`, `vr1990_010200.bi` and `li1990_053200.bi`. Some
package/component names retain older versions, so filename version matching is
advisory.

The prefix identifies the component, and with the directory read correctly the
names line up with what each module demonstrably is:

| prefix | typical size | component |
| --- | --- | --- |
| `ex` | `0x80002` | the external body-control micro ("ExMCU") |
| `_tpj01` | `0xe002` | a second micro |
| `eg` | tens of MB | the main application — the camera's "Engine" image |
| `vr` | `0xccc08` | the vibration-reduction / IBIS unit, magic `NikonBVR` |
| `li` | MB | the Linux image for the second core, magic `NISI` |

`eg` is the big one: it is the module whose name version tracks the release, it
is byte-identical to what the body executes, and it carries a `Ver.MM.mm.xx`
trailer in its last 15 bytes. Bodies without a Linux core, such as the Z 6,
have no `li` module at all.

Each module ends in a big-endian CRC16 of all preceding bytes in that module.
The body ends in a 16-byte trailer: a big-endian CRC16 of the body excluding
that trailer, followed by 14 zero bytes. This package CRC covers the space
label, directory and all modules, including their CRCs. Both levels use
polynomial `0x1021`, initial value zero, no reflection and no final XOR
(`binascii.crc_hqx(data, 0)`).

Note what the package CRC does **not** buy. With initial value zero and no final
XOR, CRC16 is self-annihilating: `crc(module ‖ crc(module)) == 0`, which is
`0x0000` for all five Z 8 modules. So once every module CRC is correct, the
package CRC is a function of the space label, the directory and the module
extents only — not of any module payload. Patch a byte inside a module, fix that
module's CRC, and the package CRC is unchanged (`0xc811` before and after on
`Z_8_0311.bin`). It catches a damaged directory, not a damaged payload.

## Exit codes

`extract_key.py` — 0 ok, 1 any failure (no images, disagreeing T1, incomplete
coverage, failed validation).

`decrypt_firmware.py` — 0 ok, 2 usage or unreadable input, 3 bad key file,
4 wrong scheme, 5 invalid structure or checksums. Nothing is written unless
the checks pass. Exit 2 includes a missing flag and an `--out` that already
exists without `--force`, which is checked before any work is done.

`solve_signature_e7.py` — as above, plus 6 no keystream reproduced the header
digest, 9 not an EXPEED 7 body, 10 two images of one camera disagreed on K8,
11 the seed literal could not be located.

`repack_firmware.py` — as `decrypt_firmware.py`, plus 7 a patch could not be
applied as given, 8 its own output failed re-validation. Exit 3 also covers a
signature key that does not verify the input, which means the wrong camera or
an already-modified image; exit 2 covers an output path that cannot be written
and an output that is the same file as the input. Output goes to a temporary
name and is renamed into place, so a failure of any kind — including a full disk
— leaves no file behind rather than a truncated image with a valid header.

## Verification

Correctness is judged by the CRC16s the images carry, nothing else. Both
scripts verify directory structure, every module CRC, the package CRC and
trailer padding: `decrypt_firmware.py` before writing output (exit 5 on the
first failure), `extract_key.py` for every image before writing a key.

The nine images the key was derived from give 36/36 module CRCs and 9/9
package CRCs. `Z_9_0532.bin`, decrypted with those same tables, adds 6/6
module CRCs and its package CRC, for 42/42 and 10/10 overall. Wrong keys
fail: a random key, 8 flipped T2 bytes, or `T1[0] ^= 1` match none, and a
single bad T3 entry (`T3[136] ^= 0x37`) fails all nine package CRCs. CRC16
detects corruption and is not a signature of any kind.

The header SHA-1 is a signature in the sense that it is checked before a flash,
but it establishes no authenticity: the key is symmetric and sits in the image,
so anyone who can read the body can also sign one. There is no asymmetric
crypto in this packaging. (The newer scheme the Z f, Z 5II, Z 50II, Z 6III and
ZR use does carry a 256-byte per-image field, which this tool does not touch.)

Three checks stand behind the signature work, all reproducible without trusting
any of the analysis above. They are listed with what each one actually proves,
because it is easy to credit the wrong one:

- **A unique search hit.** `solve_signature_e7.py` tests 131072 candidate
  keystreams against a 160-bit target and exactly one survives, for the Z 8 and
  for the Z 9 alike. A wrong construction does not produce a hit at all.
- **Prediction on an image the solver never read.** Recover K8 from
  `Z_8_0210.bin` and `Z_8_0300.bin` only, then check `Z_8_0311.bin` by hand: its
  header follows. That is the test that rules out circularity — the key is fixed
  before the image it predicts is opened. All three bodies are distinct, and
  `Z_8_0210.bin` is not even the same length. Flip any single byte of K8 and the
  prediction fails.
- **A patched run.** The digest must change when the body changes, and the
  repacker's stock pre-check must still reproduce the vendor header from the
  recovered key before it will touch anything.

`--selftest` is deliberately **not** on that list. With no edits the recomputed
digest necessarily equals the stored one, so a bit-identical round trip cannot
show that the digest was recomputed at all: a repacker that copied the vendor
header verbatim would pass it, and so would one that skipped the package CRC
(see the self-annihilation note above). What it does prove is that the cipher,
the CRC pass and the container walk are faithful — worth having, but it is not
evidence for the signature construction.

An independent re-implementation sharing no code with these scripts reproduces
the cipher, the CRC16s and the header relation: with the two further Z 8
revisions added to the ten above, the same tables give 52/52 module CRCs and
12/12 package CRCs.

`extract_key.py` also reports known table SHA-256 prefixes and warns on drift:

```
T1 29d2e34239fc33bf0a1054fd3558536a
T2 6e87de5da7e42df91db31fae4a899a04
T3 3617957facf8b21a5a3de0f3a1f6f27c
```

These regression constants are not a correctness criterion. Loading a key
checks its recorded SHA-256 values for file consistency only.

Run the regression tests with:

```sh
python3 -m unittest discover -s tests -v
```

Tests use small synthetic containers with an independent bitwise CRC
implementation; no firmware images or derived keys are needed.

Requires Python 3 and numpy.
