import json
import unittest
from io import StringIO

from azul_plugin_lookback.lookback_search.main import (
    build_lookback_regex,
    compare_lookbacks,
    compute_lookback,
    locate_lookback,
    locate_pattern,
    locate_patterns,
    nearly_plaintext,
    normalize_lookback,
    string_pattern_to_binary,
)


class TestLookbackSearch(unittest.TestCase):
    def test_compute_lookback(self):
        """
        Test that compute_look_back() correctly maps patterns into their
        look-back form.
        """
        examples = [
            (b"abcdabcd", b"\x00\x00\x00\x00\x04\x04\x04\x04"),
            (b"abcddcba", b"\x00\x00\x00\x00\x01\x03\x05\x07"),
            (b"a1a2a3a4", b"\x00\x00\x02\x00\x02\x00\x02\x00"),
            (b"aaaaaaaa", b"\x00\x01\x01\x01\x01\x01\x01\x01"),
            (bytes(i % 256 for i in range(512)), b"\x00" * 512),
        ]
        for pattern, lookback in examples:
            self.assertEqual(lookback, compute_lookback(pattern))

    def test_build_look_back_regex(self):
        """
        Test that lookbacks are correctly converted into regexes.
        Zeroes must become periods, every other value must become hex escaped.
        And then this is all wrapped inside a zero-width look ahead assertion.
        """
        examples = [
            (b"\x00\x00\x00\x02\x01\x01", b"(?=(...\\x02\\x01\\x01))"),
            (b"\x00\x01\x01\x01\x00", b"(?=(.\\x01\\x01\\x01.))"),
        ]

        for lookback, regex in examples:
            self.assertEqual(regex, build_lookback_regex(lookback))

    def test_normalize_lookback(self):
        """
        Test that lookbacks are correctly normalized to remove any references
        to data past their beginning.
        """
        examples = [
            (b"\x00\x01\x02\x03\x04", b"\x00\x01\x02\x03\x04"),
            (b"\x01\x02\x03\x04\x05", b"\x00\x00\x00\x00\x00"),
            (b"\xff\x00\xff\x02\xff", b"\x00\x00\x00\x02\x00"),
            (b"\x00\xee\x02\xdd\x02", b"\x00\x00\x02\x00\x02"),
            (b"\x04\x03\x02\x01\x00", b"\x00\x00\x02\x01\x00"),
        ]

        for lookback, normalized in examples:
            self.assertEqual(normalized, normalize_lookback(lookback))

    def test_compare_lookbacks(self):
        """
        When searching for a given lookback, there will be matches which are not
        identical due to the data which preceded the match. Test that
        compare_lookbacks() correctly validates / rejects matches which are
        consistent / inconsistent with the original pattern.
        """
        # Targets and matches which should be declared equivalent.
        consistent = [
            (b"\x00\x01\x00\x01\x01", b"\x00\x01\x00\x01\x01"),
            (b"\x00\x01\x00\x01\x01", b"\x03\x01\x03\x01\x01"),
            (b"\x00\x01\x00\x01\x01", b"\xff\x01\xff\x01\x01"),
        ]

        # Targets and matches which are not equivalent.
        inconsistent = [
            (b"\x00\x01\x00\x01\x01", b"\x00\x02\x00\x01\x01"),
            (b"\x00\x01\x00\x01\x01", b"\x00\x01\x01\x01\x01"),
            (b"\x00\x01\x00\x01\x01", b"\x00\x01\x02\x01\x01"),
        ]

        for lookback, match in consistent:
            self.assertTrue(compare_lookbacks(lookback, match))

        for lookback, match in inconsistent:
            self.assertFalse(compare_lookbacks(lookback, match))

    def test_locate_lookback(self):
        """
        Test that locate_lookback() correctly locates a lookback within a
        larger body of lookback data.
        """
        # Lookback pattern should be found at offset 1 byte into the given test data.
        lookback = b"\x00\x01\x00\x01\x03\x01\x03\x01"
        data = b"\xff\xff\x01\xee\x01\x03\x01\x03\x01\xff"

        offset = list(locate_lookback(lookback, data))
        self.assertEqual(offset, [1])

        # Patterns should be found at multiple offsets within the given test data. This includes overlapping matches.
        lookback = b"\x00\x01\x00\x01"
        data = b"\xaa\x01\xbb\x01\xff\xcc\x01\xdd\x01\x01\xee\x01\xff\x01"

        offset = list(locate_lookback(lookback, data))
        self.assertEqual(offset, [0, 5, 8, 10])

    def test_locate_pattern(self):
        """
        Test locating a given pattern after an arbitrary substitution cipher has been applied.
        """
        # Generate data including an obfuscated version of the DOS stub string
        # and a plaintext version of the same string, separated by some filler.
        pattern = "This program cannot be run in DOS mode."
        obfuscated = bytes(ord(pattern[i]) ^ 0xFF for i in range(len(pattern)))
        filler = bytes(range(256))
        data = filler + obfuscated + filler + bytes(pattern, encoding="utf-8")

        # Obfuscated pattern should be detected at offset 256.
        # No other offsets are expected, as locate_patterns() should ignore any plaintext matches.
        expected = [(obfuscated, 256)]
        results = list(locate_pattern(pattern, data))
        self.assertEqual(expected, results)

    def test_locate_patterns(self):
        """
        Test locating patterns described by a config structure within data after an arbitrary substitution cipher
        has been applied.
        """
        # Build a configuration structure containing two patterns.
        # Need to process these as if read from config.
        pat1 = string_pattern_to_binary("WaggaWaggaWally")
        pat2 = string_pattern_to_binary("BubbleRubble")
        config = {"silly": [pat1, pat2]}

        # Build some data containing obfuscated versions of both patterns.
        obf1 = bytes(pat1[i] ^ 0x42 for i in range(len(pat1)))
        obf2 = bytes((pat2[i] - 0x42) & 0xFF for i in range(len(pat2)))
        filler = bytes(range(256))
        data = obf1 + filler + obf2 + filler

        # "Ensure both patterns are located within this data.
        expected = [("silly", pat1, obf1, 0), ("silly", pat2, obf2, 271)]
        results = list(locate_patterns(config, data))
        self.assertEqual(results, expected)

        # Ensure the same results when the same search, but
        # on data which only contains plaintext versions of the patterns.
        plaintext = pat1 + pat2
        results = list(locate_patterns(config, plaintext))
        self.assertEqual(results, [])

        # Verify no results with the same search on data which only
        # contains a minor variation on the plaintext pattern.
        sim1 = pat1.replace(b"l", b"t")
        sim2 = pat2.replace(b"l", b"t")
        nearly_plaintext = sim1 + sim2
        results = list(locate_patterns(config, nearly_plaintext))

    def test_string_pattern_to_binary(self):
        """
        Test converting patterns containing escape sequences in them to binary data.
        Note as this data is orginally JSON, it requires doubl escaping backslashes.
        Plus, in the examples array, the input strings look like they would in the JSON,
        but only because raw python strings are being used.
        """
        # Inputs are raw strings, representing the strings as they would
        # appear within a JSON config, including the double quotes around them.
        # The expect results are binary strings produced after:
        #   - JSON decoding
        #   - string_pattern_to_binary()
        examples = [
            (r'"Simple string."', b"Simple string."),
            (r'"Hex\\x20Escaped"', b"Hex Escaped"),
            (r'"\\x55\\x8b\\xec"', b"\x55\x8b\xec"),
            (r'"\\x00\\x01ABC\\xfe\\xff"', b"\x00\x01ABC\xfe\xff"),
            (r'"C:\\\\Users"', b"C:\\Users"),
            (r'"C:\\\\Users\\\\xavier"', b"C:\\Users\\xavier"),
            (r'"\\\\"', b"\\"),
        ]

        for json_string, expected in examples:
            # JSON parse the string value.
            string_pattern = json.load(StringIO(json_string))

            # Run the string -> binary routine.
            binary_pattern = string_pattern_to_binary(string_pattern)

            # Ensure that it matches the expected result.
            self.assertEqual(binary_pattern, expected)

    def test_nearly_plaintext(self):
        """
        Test detecting when a pattern is too similar.
        """
        pattern1 = b"This program cannot be run in DOS mode."

        pattern2 = b"This program cannot be run in DOG mode!"
        self.assertTrue(nearly_plaintext(pattern1, pattern2))

        pattern3 = b"This program must NOT! run in DOS mode."
        self.assertTrue(nearly_plaintext(pattern1, pattern3))

        pattern4 = b"Yeah this is completely different......"
        self.assertFalse(nearly_plaintext(pattern1, pattern4))


if __name__ == "__main__":
    unittest.main()
