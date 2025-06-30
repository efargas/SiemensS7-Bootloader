import unittest
from dump_analyzer_core import find_sha1_pattern, load_dump_from_bytes

class TestFindSha1Pattern(unittest.TestCase):

    def setUp(self):
        # SHA1 of "test": a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
        # SHA1 of empty string: da39a3ee5e6b4b0d3255bfef95601890afd80709
        # SHA1 of "test": a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
        # SHA1 of empty string: da39a3ee5e6b4b0d3255bfef95601890afd80709
        # Original sample_data structure:
        # b"PREFIX_DATA" (11 bytes)
        # sha1_test_full (20 bytes) @ offset 11
        # b"MIDDLE_DATA" (11 bytes) @ offset 31
        # sha1_empty_full (20 bytes) @ offset 42
        # b"DA39A3_SUFFIX" (13 bytes) @ offset 62 <- This was the issue for partial
        # b"POST_DATA" (9 bytes) @ offset 75
        # bytes.fromhex("a94a8f") (3 bytes) @ offset 84
        # Total length = 11+20+11+20+13+9+3 = 87

        self.sample_data = load_dump_from_bytes(
            b"PREFIX_DATA" + # 11 bytes
            bytes.fromhex("a94a8fe5ccb19ba61c4c0873d391e987982fbbd3") +  # 20 bytes, Full "test" SHA1 at offset 11
            b"MIDDLE_DATA" + # 11 bytes
            bytes.fromhex("da39a3ee5e6b4b0d3255bfef95601890afd80709") +  # 20 bytes, Full "" SHA1 at offset 11+20+11 = 42
            bytes.fromhex("da39a3") + # 3 bytes, Corrected partial "" SHA1 at offset 42+20 = 62
            b"_SUFFIX_AFTER_PARTIAL" + # 22 bytes
            b"POST_DATA" + # 9 bytes
            bytes.fromhex("a94a8f") # 3 bytes, Partial "test" SHA1 at offset 62+3+22+9 = 96
        )
        # Recalculate offsets based on corrected sample_data:
        # sha1_test_full: 11
        # sha1_empty_full: 11 + 20 + 11 = 42
        # "da39a3" (partial from empty_full): 11+20+11 = 42
        # "da39a3" (explicit partial): (11+20+11) + 20 = 62
        # "a94a8f" (partial from test_full): 11
        # "a94a8f" (explicit partial): (11+20+11+20) + 3 + 22 + 9 = 96

        self.empty_data = load_dump_from_bytes(b"")
        self.sha1_test_full = "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3"
        self.sha1_empty_full = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

    def test_full_sha1_present(self):
        """Test finding a full SHA1 hash that is present."""
        self.assertEqual(find_sha1_pattern(self.sample_data, self.sha1_test_full), [11])
        self.assertEqual(find_sha1_pattern(self.sample_data, self.sha1_empty_full), [42])

    def test_partial_sha1_present(self):
        """Test finding a partial SHA1 hash that is present."""
        self.assertEqual(find_sha1_pattern(self.sample_data, "da39a3"), [42, 62])

        pattern_to_find_hex = "a94a8f"
        # Based on debug output, the data constructed results in this pattern
        # also being found at offset 95.
        # self.sample_data[95:98] was b'\xa9J\x8f'
        self.assertEqual(find_sha1_pattern(self.sample_data, pattern_to_find_hex), [11, 95])

    def test_pattern_not_present(self):
        """Test with a pattern that is not present in the data."""
        self.assertEqual(find_sha1_pattern(self.sample_data, "001122334455aabbccddeeff"), [])
        self.assertEqual(find_sha1_pattern(self.sample_data, "123456"), [])

    def test_empty_dump_data(self):
        """Test with empty dump data."""
        self.assertEqual(find_sha1_pattern(self.empty_data, "da39a3"), [])
        self.assertEqual(find_sha1_pattern(self.empty_data, self.sha1_empty_full), [])

    def test_empty_pattern(self):
        """Test with an empty pattern string."""
        # Current behavior is to return [], could also be a ValueError.
        self.assertEqual(find_sha1_pattern(self.sample_data, ""), [])

    def test_pattern_longer_than_data(self):
        """Test when the pattern is longer than the data itself."""
        short_data = load_dump_from_bytes(b"\x01\x02\x03\x04\x05")
        self.assertEqual(find_sha1_pattern(short_data, "010203040506"), []) # 6 bytes pattern vs 5 bytes data

    def test_pattern_at_beginning(self):
        """Test when the pattern is at the beginning of the data."""
        data = load_dump_from_bytes(bytes.fromhex(self.sha1_test_full) + b"SOME_OTHER_DATA")
        self.assertEqual(find_sha1_pattern(data, self.sha1_test_full), [0])
        self.assertEqual(find_sha1_pattern(data, "a94a8f"), [0])

    def test_pattern_at_end(self):
        """Test when the pattern is at the end of the data."""
        # len(b"SOME_OTHER_DATA") is 15
        data = load_dump_from_bytes(b"SOME_OTHER_DATA" + bytes.fromhex(self.sha1_empty_full))
        self.assertEqual(find_sha1_pattern(data, self.sha1_empty_full), [15])
        self.assertEqual(find_sha1_pattern(data, "afd80709"), [15 + 20 - 4]) # last 4 bytes of sha1_empty_full

    def test_multiple_occurrences(self):
        """Test multiple occurrences of the same pattern."""
        pattern = "abab" # b'\xab\xab'
        # b'\xab\xab' (0) + b"CDCD" (2,3,4,5) + b'\xab\xab' (6) + b'\xab\xab' (7) + b'\xab\xab' (8)
        # Data: b'\xab\xab\x43\x44\x43\x44\xab\xab\xab\xab'
        # Correct expectation for overlapping patterns:
        data = load_dump_from_bytes(bytes.fromhex(pattern) + b"CDCD" + bytes.fromhex(pattern) + bytes.fromhex(pattern))
        self.assertEqual(find_sha1_pattern(data, pattern), [0, 6, 7, 8])

    def test_invalid_hex_pattern_chars(self):
        """Test pattern with non-hexadecimal characters."""
        with self.assertRaisesRegex(ValueError, "Pattern contains non-hexadecimal characters."):
            find_sha1_pattern(self.sample_data, "ggHhIiJj")
        with self.assertRaisesRegex(ValueError, "Pattern contains non-hexadecimal characters."):
            find_sha1_pattern(self.sample_data, "da39a3xx") # xx are not hex

    def test_invalid_hex_pattern_odd_length(self):
        """Test pattern with an odd number of characters."""
        with self.assertRaisesRegex(ValueError, "Hex pattern must have an even number of characters."):
            find_sha1_pattern(self.sample_data, "da39a") # 5 chars
        with self.assertRaisesRegex(ValueError, "Hex pattern must have an even number of characters."):
            find_sha1_pattern(self.sample_data, "123")

    def test_invalid_hex_pattern_too_long(self):
        """Test pattern that is too long for a SHA1 hash ( > 40 chars)."""
        long_pattern = self.sha1_test_full + "00" # 42 chars
        with self.assertRaisesRegex(ValueError, "SHA1 hex pattern should not exceed 40 characters"):
            find_sha1_pattern(self.sample_data, long_pattern)

if __name__ == '__main__':
    unittest.main()
