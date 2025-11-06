"""Create features for correlation of content under single-byte substitution ciphers.

Create normalised hashes of content regardless of substitution cipher.
This should allow correlation of content that has been seen under different,
single-byte substitution ciphers and/or with plaintext input.
"""

from hashlib import sha256

import ssdeep
from azul_runner import BinaryPlugin, Feature, Job, add_settings, cmdline_run

from .lookback_search.main import compute_lookback


class AzulPluginLookbackHash(BinaryPlugin):
    """Create features for correlation of content under different substitution ciphers."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.03.18"
    SETTINGS = add_settings(filter_max_content_size=(int, 10 * 1024 * 1024), filter_data_types={"content": []})
    # The following are hashes of the normalised "symbol independent" content
    FEATURES = [
        Feature("lookback_hash", "SHA256 hash digest unaffected by substitution ciphers"),
        Feature("lookback_ssdeep", "Fuzzy digest unaffected by substitution ciphers"),
    ]

    def sha256_digest(self, data):
        """Return hex SHA256 digest of supplied data."""
        return sha256(data).hexdigest()

    def ssdeep_digest(self, data):
        """Return the SSDeep fuzzyhash of supplied data."""
        return ssdeep.hash(data)

    def execute(self, job: Job):
        """Hash data of any file type and return hash features."""
        # Read in the sample data.
        sample_data = job.get_data().read()
        # Compute the "lookback-form" of this data.
        lookback = compute_lookback(sample_data)
        # Compute the SHA256 digest of the result.
        digest = self.sha256_digest(lookback)
        # Compute an ssdeep digest of the result.
        fuzzy = self.ssdeep_digest(bytes(lookback))
        self.add_feature_values("lookback_hash", digest)
        self.add_feature_values("lookback_ssdeep", fuzzy)


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginLookbackHash)


if __name__ == "__main__":
    main()
