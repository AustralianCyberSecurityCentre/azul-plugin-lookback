import unittest

from azul_runner import FV, Event, Filepath, JobResult, State, Uri, test_template

from azul_plugin_lookback.search import AzulPluginLookbackSearch


class TestLookbackSearch(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginLookbackSearch

    def test_pattern_detection(self):
        """
        Test detecting pattern under a variety of substitution schemes.
        """
        pattern = "This program cannot be run in DOS mode."

        # Obfuscate with an XOR
        obfuscated1 = bytearray(pattern, encoding="utf-8")
        for i in range(len(obfuscated1)):
            obfuscated1[i] ^= 0x99

        # Obuscate with a subtract
        obfuscated2 = bytearray(pattern, encoding="utf-8")
        for i in range(len(obfuscated2)):
            obfuscated2[i] = (obfuscated2[i] - 0xAA) & 0xFF

        # Make some background data, and drop the obfuscated patterns in at offset 100 and 200.
        data = bytearray([i % 256 for i in range(300)])
        data[100 : 100 + len(obfuscated1)] = obfuscated1
        data[200 : 200 + len(obfuscated2)] = obfuscated2

        result = self.do_execution(feats_in=[], data_in=[("content", bytes(data))])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="9c0e4e7a226c6ef95eb399ba46cb086a751a0eb56cb93b2608fb0f7fcac1c840",
                        features={
                            "lookback_match_data": [
                                FV(
                                    b"\xaa\xbe\xbf\xc9v\xc6\xc8\xc5\xbd\xc8\xb7\xc3v\xb9\xb7\xc4\xc4\xc5\xcav\xb8\xbbv\xc8\xcb\xc4v\xbf\xc4v\x9a\xa5\xa9v\xc3\xc5\xba\xbb\x84",
                                    label="generic_pe",
                                    offset=200,
                                    size=39,
                                ),
                                FV(
                                    b"\xcd\xf1\xf0\xea\xb9\xe9\xeb\xf6\xfe\xeb\xf8\xf4\xb9\xfa\xf8\xf7\xf7\xf6\xed\xb9\xfb\xfc\xb9\xeb\xec\xf7\xb9\xf0\xf7\xb9\xdd\xd6\xca\xb9\xf4\xf6\xfd\xfc\xb7",
                                    label="generic_pe",
                                    offset=100,
                                    size=39,
                                ),
                            ],
                            "lookback_pattern": [
                                FV(
                                    b"This program cannot be run in DOS mode.", label="generic_pe", offset=100, size=39
                                ),
                                FV(
                                    b"This program cannot be run in DOS mode.", label="generic_pe", offset=200, size=39
                                ),
                            ],
                        },
                    )
                ],
            ),
        )

    def test_no_plaintext_detection(self):
        """Ensure plaintext isn't detected by the pattern."""
        pattern = b"This program cannot be run in DOS mode."

        # Make some background data, and place the plaintext pattern in at offset 100.
        data = bytearray([i % 256 for i in range(300)])
        data[100 : 100 + len(pattern)] = pattern

        result = self.do_execution(feats_in=[], data_in=[("content", bytes(data))])
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

    def test_no_nearly_plaintext_detection(self):
        """
        "Test no results for plaintext that almost matches the pattern.
        These are more likely to be modifications to standard patterns, rather than attempts at obfuscation.
        These are ignored as it would generate too many feature values.
        """
        # A pattern very close to one of the default search patterns.
        nearly_pattern = b"This program cannot be run in DOG mode!"

        # Make some background data, and drop the pattern in at offset 100.
        data = bytearray([i % 256 for i in range(300)])
        data[100 : 100 + len(nearly_pattern)] = nearly_pattern

        result = self.do_execution(feats_in=[], data_in=[("content", bytes(data))])
        self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))


if __name__ == "__main__":
    unittest.main()
