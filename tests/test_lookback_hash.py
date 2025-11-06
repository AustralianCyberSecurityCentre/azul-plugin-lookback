import random
import unittest

import ssdeep
from azul_runner import FV, Event, Filepath, JobResult, State, Uri, test_template

from azul_plugin_lookback.hash import AzulPluginLookbackHash


class TestLookbackHash(test_template.TestPlugin):
    PLUGIN_TO_TEST = AzulPluginLookbackHash

    @classmethod
    def setUpClass(cls) -> None:
        """
        Generate test data for multiple tests by obfuscating the same
        piece of data with a variety of substitution ciphers.
        """
        super().setUpClass()
        cls.data_samples = []

        # First sample is the plaintext data.
        plaintext = b"Arbitrary data to be hashed:" + bytes(range(256))
        cls.data_samples.append(plaintext)

        # Obfuscate with an XOR.
        cls.data_samples.append(bytes([c ^ 0x11 for c in plaintext]))

        # Obfuscate with a subtraction.
        cls.data_samples.append(bytes([(c - 0x22) & 0xFF for c in plaintext]))

        # Obfuscate with a few different random sboxes.
        random.seed(0)
        for i in range(5):
            sbox = list(range(256))
            random.shuffle(sbox)
            cls.data_samples.append(bytes([sbox[c] for c in plaintext]))

        # All generated samples should produce this hash.
        cls.expected_hash = FV(value="f770bd1959d397e68c89e02b9ccbf1de41831756226d6bceb4151c971e9ac6e0")

        # All generated samples should produce this ssdeep hash.
        cls.expected_ssdeep = FV(value="3:+jWlmx//PllMl/D8y1:Oe3")

    def test_lookback_hash_identical(self):
        """
        Ensure that identical data obfuscated with a variety of substitution
        ciphers will generate an identical lookback_hash feature.
        """
        # Verify that test data was generated.
        self.assertTrue(len(self.data_samples) > 2)

        # Enumerate through different data samples and ensure that they all produce the same lookback_hash.
        result = self.do_execution(data_in=[("content", self.data_samples[0])])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="575a7ba2bb1ccb3210ab374a2c464a3d5ccb396a9aeff1cdfb9ec7487429cff3",
                        features={
                            "lookback_hash": [FV("f770bd1959d397e68c89e02b9ccbf1de41831756226d6bceb4151c971e9ac6e0")],
                            "lookback_ssdeep": [FV("3:+jWlmx//PllMl/D8y1:Oe3")],
                        },
                    )
                ],
            ),
        )
        for sample in self.data_samples:
            result = self.do_execution(data_in=[("content", sample)])
            # Ensure that the plugin completed succesfully.
            self.assertEqual(result.state, State(State.Label.COMPLETED))
            # Ensure that the expected lookback_hash feature was produced.
            self.assertEqual(result.events[0].features["lookback_hash"][0], self.expected_hash)

    def test_lookback_hash_different(self):
        """
        Test that different data will generate different lookback hashes.
        """
        # Ensure that hashing some other data produces a different result.
        alternate = b"This is some different data:" + bytes(range(100, 200))
        result = self.do_execution(data_in=[("content", alternate)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="c29900042f887f63ad47c57004425a95f1fe0289c0da0abaeadd7968155139fe",
                        features={
                            "lookback_hash": [FV("5c08ff73ae3b78462b061eef810e6b4ff90d7ff2cb7a2799b82c413107ae7b74")],
                            "lookback_ssdeep": [FV("3:wlpli9hlqrzc3tt:QptnS")],
                        },
                    )
                ],
            ),
        )

    def test_lookback_ssdeep_identical(self):
        """
        Ensure that identical data obfuscated with different substitution ciphers
        will generate an identical lookback_ssdeep feature.
        """
        # Verify that test data was generated.
        self.assertTrue(len(self.data_samples) > 2)
        result = self.do_execution(data_in=[("content", self.data_samples[0])])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="575a7ba2bb1ccb3210ab374a2c464a3d5ccb396a9aeff1cdfb9ec7487429cff3",
                        features={
                            "lookback_hash": [FV("f770bd1959d397e68c89e02b9ccbf1de41831756226d6bceb4151c971e9ac6e0")],
                            "lookback_ssdeep": [FV("3:+jWlmx//PllMl/D8y1:Oe3")],
                        },
                    )
                ],
            ),
        )

        # Enumerate through different data samples and ensure that they
        # all produce the same lookback_hash.
        for sample in self.data_samples:
            result = self.do_execution(data_in=[("content", sample)])
            # Ensure that the plugin completed succesfully.
            self.assertEqual(result.state, State(State.Label.COMPLETED))
            # Ensure that the expected lookback_hash feature was produced.
            self.assertEqual(result.events[0].features["lookback_ssdeep"][0], self.expected_ssdeep)

    def test_lookback_ssdeep_similar(self):
        """
        Ensure that similar data, obfuscated with different substitution ciphers
        will generate similar lookback_ssdeep features.
        """
        filler = b"Some filler data we can wrap around our samples."
        similar1 = filler + b"This is the first of two pieces!" + filler
        similar2 = filler + b"They're a bit different in the middle though!" + filler

        # Ensure that with under standard ssdeep they generate different, but
        # similar digests.
        digest1 = ssdeep.hash(similar1)
        digest2 = ssdeep.hash(similar2)
        self.assertNotEqual(digest1, digest2)
        self.assertTrue(ssdeep.compare(digest1, digest2) > 40)

        # Obfuscate both samples with different substitution ciphers and ensure that
        # under standard ssdeep they generate digests that are not similar.
        sbox1 = list(range(256))
        random.shuffle(sbox1)
        sbox2 = list(range(256))
        random.shuffle(sbox2)
        self.assertNotEqual(sbox1, sbox2)

        obfuscated1 = bytes(sbox1[c] for c in similar1)
        obfuscated2 = bytes(sbox2[c] for c in similar2)

        digest1 = ssdeep.hash(obfuscated1)
        digest2 = ssdeep.hash(obfuscated2)
        self.assertTrue(ssdeep.compare(digest1, digest2) < 1)

        # Ensure that the lookback ssdeep features generated by the plugin DO
        # show these obfuscated samples as being similar.
        result = self.do_execution(data_in=[("content", similar1)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="295bf4e8b52373490a718d8b78d555ffb96ccf881ccde292a02d491c8b7ea3a5",
                        features={
                            "lookback_hash": [FV("c6a3ca5a89d890ae1def2762f1eebc558ca902a27f7d9d8117027418acb67ce2")],
                            "lookback_ssdeep": [FV("3:n4TZslchMgpj1KWoEUR7AuUxLFiQQicspj1e1n:ngZ9hMYO1R7AuU7lt41")],
                        },
                    )
                ],
            ),
        )
        digest1 = result.events[0].features["lookback_ssdeep"][0].value

        result = self.do_execution(data_in=[("content", similar2)])
        self.assertJobResult(
            result,
            JobResult(
                state=State(State.Label.COMPLETED),
                events=[
                    Event(
                        entity_type="binary",
                        entity_id="1fa187276ceb1675e37006917b81067aba4e7f002cdcb6b28e796682652f7d4c",
                        features={
                            "lookback_hash": [FV("0c0355be82a89269352b3070d89e77df2375b7ed2d458b5b910a221135ce9c3d")],
                            "lookback_ssdeep": [
                                FV("3:n4TZslchMgpj1KvgQfeThIDh8ROjZiyvHEiMgmRPg+j1nn:ngZ9hMYzQfe+aOjcyvAgEPjj1nn")
                            ],
                        },
                    )
                ],
            ),
        )
        digest2 = result.events[0].features["lookback_ssdeep"][0].value

        self.assertTrue(ssdeep.compare(digest1, digest2) > 30)


if __name__ == "__main__":
    unittest.main()
