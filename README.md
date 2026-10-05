# nikon-fw-key-tool

Recovers the keystream tables used by Nikon's legacy firmware packaging and
decrypts images with them. Two steps: derive the key once, then use it.

Applies to **Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 8, Z 30, Z 50, Z fc**.

Does **not** apply to Z 5II, Z 50II, Z 6III or ZR — those use a different,
unbroken scheme. `decrypt_firmware.py` detects them and refuses rather than
emitting garbage.

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
constants** — identical across all nine bodies — so the whole key is 768
bytes. It is the same construction as the much older `Xor_Ord1/2/3` scheme in
nikon-firmware-tools, with different tables.

Legacy images are identified by 32 ASCII spaces at file offset `0x20`. The
newer scheme puts them at `0x260`.

## Usage

```sh
python3 extract_key.py <firmware_dir> <key.json>
python3 decrypt_firmware.py <key.json> <firmware.bin> <out.dec>
```

No key material ships in this repo. `extract_key.py` derives it from firmware
images you supply; `.gitignore` keeps images, keys and output out of git.

## How many images do you need?

Four. Every one of the 256 T3 blocks needs at least one image with
constant-fill padding at that keystream offset, and no three images span all
256. The tool checks coverage directly and names the missing blocks if short,
so any sufficient set works — but exactly one of the 126 four-subsets of the
nine known images is sufficient:

```
Z_8_0311.bin  Z7_2_0170.bin  Z_6_0380.bin  Z_50_0260.bin
```

Four images and all nine produce byte-identical tables.

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
rather than XORed.

The decrypted body opens with a module directory at body `0x20`: a 32-byte
header record, then `count - 1` named descriptors of 32 bytes and a final
unnamed descriptor of 16 bytes.

```
0x20            [BE32 count][BE32 dirsize][8 pad][16-byte package name]
named record    [BE32 offset][BE32 length][8 pad][16-byte module name]
final record    [BE32 offset][BE32 length][8 pad]
```

The decrypter requires a complete directory with valid names and zero reserved
bytes. Module lengths include their two-byte CRC and must be at least two.
Offsets are relative to the body, all extents must be in bounds, and:

- `dirsize == 48 + 32 * count`
- the first module starts at `dirsize`
- descriptors chain exactly, `offset + length == next offset`, from the first
- the last descriptor ends exactly 16 bytes before end-of-body

Names are NUL-padded and truncated at 16 characters, so a long one loses its
extension (`eg1850_mas_01700`). The final descriptor points to an ordinary
checksummed module and carries no name. Names encode the version, e.g.
`eg1985_018100.bi` in `Z_fc_0181.bin`; the Z 6II/Z 7II carry `_mas_`/`_sla_` pairs matching their
dual-EXPEED hardware. Some package/component names retain older versions, so
filename version matching is advisory.

Each module ends in a big-endian CRC16 of all preceding bytes in that module.
The body ends in a 16-byte trailer: a big-endian CRC16 of the body excluding
that trailer, followed by 14 zero bytes. This package CRC covers the space
label, directory and all modules, including their CRCs. Both levels use
polynomial `0x1021`, initial value zero, no reflection and no final XOR
(`binascii.crc_hqx(data, 0)`).

## Exit codes

`extract_key.py` — 0 ok, 1 any failure (no images, disagreeing T1, incomplete
coverage, failed validation).

`decrypt_firmware.py` — 0 ok, 2 usage or unreadable input, 3 bad key file,
4 wrong scheme, 5 invalid structure or checksums. Nothing is written unless
the checks pass.

## Verification

Correctness is judged by the CRC16s the images carry, nothing else. Both
scripts verify directory structure, every module CRC, the package CRC and
trailer padding: `decrypt_firmware.py` before writing output (exit 5 on the
first failure), `extract_key.py` for every image before writing a key.

The nine supplied images give 36/36 module CRCs and 9/9 package CRCs. Wrong
keys fail: a random key, 8 flipped T2 bytes, or `T1[0] ^= 1` match none, and
a single bad T3 entry (`T3[136] ^= 0x37`) fails all nine package CRCs. CRC16
detects corruption; it is not a vendor signature and does not establish
authenticity.

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
