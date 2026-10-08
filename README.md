# nikon-fw-key-tool

Recover Nikon's legacy firmware XOR tables, decrypt images, and repack edited
Z 8 / Z 9 images with valid checksums and header digests.

| Operation | Supported models |
| --- | --- |
| Key recovery and decryption | Z 5, Z 6, Z 6II, Z 7, Z 7II, Z 8, Z 9, Z 30, Z 50, Z fc |
| Signature-key recovery and repacking | Z 8, Z 9 |

Z f, Z 5II, Z 50II, Z 6III and ZR use a newer scheme that this tool does not
support. Packaging is not determined by EXPEED generation: the Z 8 and Z 9
use the legacy scheme despite having EXPEED 7 processors.

Requires Python 3 and NumPy. The repository contains original scripts and no
Nikon firmware or derived keys. Supply your own images; firmware, outputs and
key JSON files are excluded from Git.

## Usage

### Recover the XOR tables

Put legacy `.bin` images in a directory, then run:

```sh
python3 extract_key.py --firmware-dir firmware --out key.json
```

The images must collectively contain constant-fill padding at all 256 T3
block indices. This known set of four images is sufficient:

```text
Z_8_0311.bin  Z7_2_0170.bin  Z_6_0380.bin  Z_50_0260.bin
```

Other sets work if they provide full coverage. The extractor reports missing
blocks and validates every image before writing the key. Recover the tables
once; the same tables work across all supported models.

### Decrypt an image

```sh
python3 decrypt_firmware.py --key key.json \
    --firmware Z_8_0311.bin --out Z_8_0311.dec
```

The output retains the plaintext header and space label. The tool prints the
module directory and verifies its structure, module CRCs and package CRC
before writing.

### Recover a signature key and repack (Z 8 / Z 9)

Use stock images from the same model. One image is sufficient; two or more
revisions cross-check the recovered key:

```sh
python3 solve_signature_e7.py --key key.json \
    --firmware Z_8_0300.bin Z_8_0311.bin --out sig.json

python3 repack_firmware.py --key key.json --sig sig.json \
    --firmware Z_8_0311.bin --out Z_8_0312.bin \
    --patch-module eg:0x1000:deadbeef
```

The patch above illustrates syntax only. Choose bytes and offsets appropriate
to the module you intend to edit.

- `--patch-module MODULE:OFFSET:HEXBYTES` overwrites bytes at a module-relative
  offset. Offsets accept decimal or `0x` notation.
- `--replace-module MODULE=PATH` replaces a module's payload with a file
  exactly as long as that payload (module length minus the two CRC bytes).
- Select a module by its full name or an unambiguous prefix. Both flags are
  repeatable; byte patches run before replacements.
- `--selftest` repacks without edits and requires output identical to the input.

The repacker checks the input signature, recomputes module CRCs, package CRC
and header digest, then decrypts and validates the result before writing it
through a temporary file. Check the printed module name and body offset to
confirm the selected extent. Keep the vendor filename pattern, such as
`Z_8_0312.bin`; the camera may ignore filenames outside that pattern.

All scripts use named arguments. Existing outputs require `--force`; the
repacker also rejects an output path that resolves to its input file.

### Migrating old commands

Earlier versions shifted module names by one descriptor while reading extents
correctly, so an old selector would now silently hit a different module (old
`vr` was the main application). Old `--patch` and `--replace` commands therefore
exit **9** and show a mapping and rewritten flags for the supplied image. Use
that advice to migrate to `--patch-module` and `--replace-module`.

The mapping depends on descriptor order, including models with two `eg`
modules. Do not rename selectors using a fixed prefix table. Ambiguous or
unmatched old selectors receive no automatic rewrite.

## Firmware format

The file starts with a 32-byte plaintext header, followed by the body:

```text
File 0x00:  [20-byte SHA-1 digest][12 unidentified bytes]
File 0x20:  body begins
Body 0x00:  [32 ASCII spaces, plaintext]
Body 0x20:  [BE32 module count][BE32 directory size][8 zero bytes]
Body 0x30:  count × [16-byte name][BE32 offset][BE32 length][8 zero bytes]
            [modules, each ending in a BE16 CRC]
            [BE16 package CRC][14 zero bytes]
```

`BE16` and `BE32` are big-endian integers. Module names occupy up to 16 bytes,
with NUL padding for shorter names; long names may lose their extension.
Offsets are relative to the body, and lengths include the two-byte module CRC.
The directory size is `48 + 32 * count`. Modules start immediately after the
directory, chain without gaps, and end immediately before the 16-byte trailer.
Reserved bytes and trailer padding must be zero.

| Prefix | Component |
| --- | --- |
| `ex` | External body-control microcontroller (ExMCU) |
| `_tpj01` | Second microcontroller |
| `eg` | Main application (Engine) |
| `vr` | Vibration-reduction / IBIS unit (`NikonBVR`) |
| `li` | Linux image for the second core (`NISI`), where present |

Names contain model IDs and component versions. For example, `2070` identifies
the Z 8, `1990` the Z 9 and `1985` the Z fc. Z 6II / Z 7II images include
`eg..._mas_...` and `eg..._sla_...` modules. Component versions may differ from
the package release, so filename-version matching is advisory.

### XOR encryption

The header and space label pass through unchanged. For body offset `i >= 0x20`:

```text
plain[0x20 + i] = cipher[0x20 + i]
                 XOR T1[i & 0xFF]
                 XOR T2[(i >> 8) & 0xFF]
                 XOR T3[(i >> 16) & 0xFF]
```

Each table has 256 bytes; the keystream repeats every 2^24 bytes (16 MiB).
The index includes the space label. Encryption and decryption use the same
operation. Legacy images have the space label at file offset `0x20`; newer
images place it at `0x260` and are rejected.

### Checksums and header digest

Both CRC levels use polynomial `0x1021`, initial value zero, no reflection and
no final XOR. Each module CRC covers its payload. The package CRC covers the
body except the final 16-byte trailer, including the label, directory and
module CRCs.

With these CRC parameters, `CRC(payload || CRC(payload)) == 0`: the CRC over
a whole module, including its stored CRC, is zero. Consequently, changing a
payload and repairing its module CRC leaves the package CRC unchanged. Both CRC
levels must be checked; the package CRC alone cannot validate payloads.

The first 20 header bytes satisfy:

```text
header[0:20] == SHA1(decrypted_body || K8)
```

The hash includes the entire decrypted body through the checksum trailer,
followed by K8, an eight-byte key specific to the camera model. The CLI calls
this digest the signature and K8 the signature key. The remaining 12 header
bytes are unidentified, are not checked by the analysed verifier, and are
preserved by the repacker. This is a keyed digest, not an asymmetric
signature: recovering K8 allows edited images to be signed.

On the Z 8 and Z 9, K8 = seed XOR k, where the seed is an eight-byte constant
in the firmware and:

```text
k[i] = (b + a * ((i + 1) * M + i * (i + 1) // 2)) & 0xFF
```

The solver locates seed candidates 24 bytes before a SHA-1 initialisation-vector
literal and searches 131,072 `(a, b, M)` combinations per candidate. EXPEED 6
models construct seeds from instruction immediates and need a different
recovery method; this solver rejects them.

## Key recovery and verification

The extractor works from constant-filled padding sectors, in five stages:

1. **T1, up to a constant.** Padding sectors encrypt to `T1 ^ c` for varying
   `c`; normalising each repeated sector by its first byte yields `T1 ^ T1[0]`.
2. **The constant.** Of the 256 choices, keep the one that makes the module
   directory parse into valid names with chained extents.
3. **Observations.** A sector that becomes constant after removing T1 is
   padding and gives one value of `T2[a] ^ T3[b]`.
4. **T2 and T3.** Majority propagation over those observations, with
   `T2[0] = 0`.
5. **T3 repair.** Re-derive each T3 entry by maximising
   `count[c] + count[c ^ 0xFF]`, then take the member that produces more zero
   bytes. Printable-text scoring is unreliable here: XORed UTF-16LE strings can
   look more printable than the correct plaintext.

Every input must then pass full directory and CRC checks before the key is
written. The key file records each table's SHA-256 so loaders can detect a
damaged file; the extractor also compares them with known values to catch
regressions, but that comparison does not replace firmware validation.

An independent implementation verified the shared tables against 12 images:
52 module CRCs and 12 package CRCs passed. Signature verification included a
Z 8 revision withheld from key recovery, plus edited-body checks. A bit-identical
`--selftest` verifies the container round trip but alone does not prove digest
recomputation: copying the original header would also pass.

Run the synthetic regression tests without firmware images or keys:

```sh
python3 -m unittest discover -s tests -v
```

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | Extractor recovery/validation failure or table-hash drift |
| 2 | Invalid arguments, unreadable input, or refused output path |
| 3 | Invalid key file; repacker also uses this for an input signature mismatch |
| 4 | Unsupported or unrecognised packaging |
| 5 | Invalid directory, checksums or padding |
| 6 | Signature solver found no matching key |
| 7 | Invalid patch, selector or replacement |
| 8 | Repacked output failed verification |
| 9 | Solver: unsupported model; repacker: deprecated flag |
| 10 | Signature keys from supplied images disagree |
| 11 | Signature seed literal not found |

The extractor uses 1 for recovery failures and writes no key if validation
fails. Table-hash drift returns 1 **after writing** the validated key. Its
argument parser and output-existence check use 2.
