"""Find patterns under any single-byte substitution cipher."""

from os import path

from azul_runner import (
    FV,
    BinaryPlugin,
    Feature,
    Job,
    add_settings,
    cmdline_run,
    settings,
)

from .lookback_search.main import load_config, locate_patterns

# Use this (non-default) config to configure the plugin search patterns.
LOOKBACK_PLUGIN_CONFIG_PATH = path.join(path.dirname(__file__), "lookback_config.json")


class AzulPluginLookbackSearch(BinaryPlugin):
    """Find patterns under any single-byte substitution cipher."""

    CONTACT = "ASD's ACSC"
    VERSION = "2025.03.18"
    SETTINGS = add_settings(
        filter_data_types={"content": []},
        filter_max_content_size=(int, 5 * 1024 * 1024),
    )
    # Feature both the plaintext patterns detected, and the obfuscated
    # data which matched on the pattern.
    FEATURES = [
        Feature("lookback_pattern", "Plaintext pattern detected underneath obfuscation", type=bytes),
        Feature("lookback_match_data", "Obfuscated data which matched on the pattern", type=bytes),
    ]

    def __init__(self, config: settings.Settings | dict = None) -> None:
        """Preload config."""
        super().__init__(config)
        # Load in patterns the plugin is configured to search for.
        self.config = load_config(LOOKBACK_PLUGIN_CONFIG_PATH)

    def execute(self, job: Job):
        """Scan data for any file type, looking for patterns."""
        # Use the "look-back" module to search for instances of data which
        # match these patterns.
        for match in locate_patterns(self.config, job.get_data().read()):
            category, pattern, match_data, offset = match
            # Label our pattern and match_data features with the
            # categories of each pattern as per the config file.
            self.add_feature_values("lookback_pattern", FV(pattern, label=category, offset=offset, size=len(pattern)))
            self.add_feature_values(
                "lookback_match_data", FV(match_data, label=category, offset=offset, size=len(match_data))
            )


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginLookbackSearch)


if __name__ == "__main__":
    main()
