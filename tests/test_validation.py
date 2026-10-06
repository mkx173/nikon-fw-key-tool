"""Small synthetic containers; no firmware images or recovered keys required."""
import contextlib
import hashlib
import io
import json
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

import decrypt_firmware as fw


def reference_crc(data):
    """Independent bitwise CRC implementation used only to build fixtures."""
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ (0x1021 if crc & 0x8000 else 0)) & 0xffff
    return crc.to_bytes(2, "big")


def package_crc(body):
    body[-16:-14] = reference_crc(body[:-16])
    return body


def make_body(payloads=None):
    if payloads is None:
        payloads = [b"\xff" * 1024, bytes(range(1, 256)) * 8]
    count = len(payloads)
    directory_size = 48 + 32 * count
    body = bytearray(b" " * 32)
    body += struct.pack(">II8x16s", count, directory_size, b"package_0120.bin")
    modules = [payload + reference_crc(payload) for payload in payloads]
    start = directory_size
    for i, module in enumerate(modules):
        body += struct.pack(">II8x", start, len(module))
        if i < count - 1:
            body += ("module%d.bin" % (i + 1)).encode().ljust(16, b"\0")
        start += len(module)
    for module in modules:
        body += module
    body += b"\0" * 16
    return package_crc(body)


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.body = make_body()

    def test_independent_crc_fixture(self):
        self.assertEqual(reference_crc(b"123456789"), bytes.fromhex("31c3"))

    def test_valid_low_zero_image_and_unnamed_final_descriptor(self):
        self.assertLess(self.body.count(0) / len(self.body), 0.20)
        mods = fw.validate_firmware(self.body)
        self.assertEqual(len(mods), 2)
        self.assertEqual(mods[0], ("module1.bin", 112, 1026))
        self.assertEqual(mods[-1][0], "(unnamed)")
        # These are payload bytes, not a name for the final descriptor.
        self.assertEqual(self.body[112:128], b"\xff" * 16)

    def test_single_unnamed_module_with_empty_payload(self):
        self.assertEqual(fw.validate_firmware(make_body([b""])),
                         [("(unnamed)", 80, 2)])

    def test_module_data_or_checksum_corruption_even_with_valid_package_crc(self):
        for index in (112, 112 + 1025, 1138, len(self.body) - 17):
            with self.subTest(index=index):
                body = self.body.copy()
                body[index] ^= 1
                package_crc(body)
                with self.assertRaisesRegex(ValueError, r"module .* CRC mismatch"):
                    fw.validate_firmware(body)

    def test_package_crc_covers_directory(self):
        body = self.body.copy()
        body[80] = ord("n")  # Valid new name; extents/module CRCs remain valid.
        with self.assertRaisesRegex(ValueError, "package CRC mismatch"):
            fw.validate_firmware(body)

    def test_package_checksum_corruption(self):
        self.body[-16] ^= 1
        with self.assertRaisesRegex(ValueError, "package CRC mismatch"):
            fw.validate_firmware(self.body)

    def test_unprotected_trailer_padding_is_checked(self):
        self.body[-1] = 1
        with self.assertRaisesRegex(ValueError, "trailer padding"):
            fw.validate_firmware(self.body)

    def test_invalid_directory_even_with_recomputed_package_crc(self):
        cases = [(32, 0), (32, 65), (36, 111), (36, 112 + 32),
                 (64, 111), (64, 113), (68, 1),
                 (96, 1137), (96, 1139),
                 (100, 1), (100, 2049), (100, 2051)]
        for position, value in cases:
            with self.subTest(position=position, value=value):
                body = self.body.copy()
                struct.pack_into(">I", body, position, value)
                package_crc(body)
                with self.assertRaises(ValueError):
                    fw.validate_firmware(body)

    def test_reserved_bytes_names_and_space_label(self):
        for position in (0, 40, 72, 104, 48, 80, 91):
            with self.subTest(position=position):
                body = self.body.copy()
                body[position] = 0xff
                package_crc(body)
                with self.assertRaises(ValueError):
                    fw.validate_firmware(body)

    def test_truncation_and_out_of_bounds_directory(self):
        for end in (0, 63, 79, 95, 112, len(self.body) - 1):
            with self.subTest(end=end):
                with self.assertRaises(ValueError):
                    fw.validate_firmware(self.body[:end])
        # Correct size formula for count 64, but not enough descriptor bytes.
        body = self.body[:128]
        struct.pack_into(">II", body, 32, 64, 48 + 32 * 64)
        with self.assertRaises(ValueError):
            fw.validate_firmware(body)

    def run_cli(self, key, source, destination, force=False):
        argv = ["decrypt_firmware.py", "--key", str(key),
                "--firmware", str(source), "--out", str(destination)]
        if force:
            argv.append("--force")
        with mock.patch.object(sys, "argv", argv), \
                contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()) as errors:
            try:
                code = fw.main()
            except SystemExit as exc:
                code = exc.code
        return code, errors.getvalue()

    def test_cli_rejects_wrong_key_without_creating_or_overwriting_output(self):
        with tempfile.TemporaryDirectory() as folder:
            root = pathlib.Path(folder)
            key = {name: bytes(256).hex() for name in ("T1", "T2", "T3")}
            key["self_check"] = {name: hashlib.sha256(bytes(256)).hexdigest()
                                 for name in ("T1", "T2", "T3")}
            keyfile = root / "key.json"
            keyfile.write_text(json.dumps(key))
            source = root / "firmware.bin"
            source.write_bytes(bytes(32) + self.body)
            destination = root / "output.dec"
            self.assertEqual(self.run_cli(keyfile, source, destination)[0], 0)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
            # Still internally self-consistent as a key file, but incorrect.
            bad = bytearray(256)
            bad[0] = 1
            key["T1"] = bad.hex()
            key["self_check"]["T1"] = hashlib.sha256(bad).hexdigest()
            keyfile.write_text(json.dumps(key))
            destination.write_bytes(b"existing output")
            # An existing output is refused outright, before any work.
            code, message = self.run_cli(keyfile, source, destination)
            self.assertEqual(code, fw.EX_USAGE)
            self.assertIn("already exists", message)
            self.assertEqual(destination.read_bytes(), b"existing output")
            # And even when replacing is allowed, validation still runs first.
            code, message = self.run_cli(keyfile, source, destination, force=True)
            self.assertEqual(code, fw.EX_SANITY)
            self.assertIn("CRC mismatch", message)
            self.assertEqual(destination.read_bytes(), b"existing output")
            destination.unlink()
            self.assertEqual(self.run_cli(keyfile, source, destination)[0], fw.EX_SANITY)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
