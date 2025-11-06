"""Search for patterns under any single-byte substitution cipher."""

import argparse
import codecs
import json
import re
from os import path

DEFAULT_CONFIG_PATH = path.join(path.dirname(__file__), "config.json")


def compute_lookback(data):
    """Return a lookback byte string for the supplied data.

    The return value will be the same size as the input,
    but each byte will be replaced with the distance you must look backwards to find a byte with the same value.
    If the "lookback" distance is > 255 it is set to 0 which is considered too far.
    """
    output = bytearray(len(data))

    # Track the last observed index for each byte value.
    last_seen = dict()

    for index in range(len(data)):
        # Find the distance between this byte, and the last place this byte occurred in the input data.
        # The first instance of any given byte will have a distance of 0.
        distance = index - last_seen.get(data[index], index)

        # If the lookback distance is more than 256 bytes, it is considered out of range, so use a distance of 0.
        if distance >= 256:
            distance = 0

        # Update the last_seen dict and output data.
        last_seen[data[index]] = index
        output[index] = distance

    return output


def build_lookback_regex(target_lb):
    """Build a regex which can look for a target lookback pattern.

    This pattern can be used to search a larger body of lookback transformed
    data. Positions within a lookback pattern with value 0 must be wildcarded
    as these could have arbitrary values depending on the data which preceded
    the pattern in the search data.

    Matches on this regex must be further validated using compare_lookbacks().
    """
    regex = b""
    for index in range(len(target_lb)):
        # Wilcard positions where the lookback distance was zero.
        if target_lb[index] == 0:
            regex += b"."
        # Hex encode all other values to avoid forming an invalid regex.
        else:
            regex += b"\\x%02X" % target_lb[index]

    # Wrap inside a "zero-width lookahead assertion" to ensure overlapping matches.
    regex = b"(?=(%s))" % regex

    return regex


def normalize_lookback(lookback):
    """Given a lookback, zero any references before the start of buffer.

    This will create a new lookback as if it was computed with no data
    preceding it.

    Making this its own function will be useful if we want to normalize a
    lookback for purposes other than comparing it.
    """
    # Make a copy of the lookback to modify and return.
    normalized = bytearray(lookback)

    # Replaced any references back past the beginning with 0.
    for index in range(len(normalized)):
        if normalized[index] > index:
            normalized[index] = 0

    return normalized


def compare_lookbacks(target_lb, candidate_lb):
    """Normalise and compare the candidate lookback against the target."""
    return target_lb == normalize_lookback(candidate_lb)


def locate_lookback(target_lb, data_lb):
    """Search for a target lookback within a larger body of lookback data.

    Yields offsets consistent with target_lb.
    """
    # Build a regex for the target lookback.
    target_lb_regex = build_lookback_regex(target_lb)

    # Use the regex to search for candidate matches.
    for match in re.finditer(target_lb_regex, data_lb, flags=re.DOTALL):
        # The result is just a candidate which must be validated by calling
        # compare_lookbacks().
        candidate_lb = match.group(1)
        if not compare_lookbacks(target_lb, candidate_lb):
            continue

        # Yield the offsets of any matches.
        offset = match.start()
        yield offset

    return


def nearly_plaintext(pattern, match_data):
    """Compare a plaintext pattern with the data that it matched on.

    If the matched data is not sufficiently different to the plaintext
    pattern it is rejected. The goal is to find obfuscated patterns, not
    minor variations of common patterns.
    """
    # Compute the percentage of the string which is identical.
    identical = 0
    for i in range(len(pattern)):
        if pattern[i] == match_data[i]:
            identical += 1

    similarity = identical / float(len(pattern))

    # Return true if the match was similar to the plaintext.
    return similarity > 0.5


def locate_pattern(pattern, data):
    """Search for the given pattern in the data.

    Converts supplied pattern into its lookback form and searches within
    the body of data, also converted into its lookback form
    """
    # Process any escape sequences and convert the pattern to binary, just like
    # when reading them from the config.
    processed_pattern = string_pattern_to_binary(pattern)
    pattern_structure = {"blank": [processed_pattern]}

    for _, _, data_match, offset in locate_patterns(pattern_structure, data):
        yield (data_match, offset)

    return


def locate_patterns(pattern_structure, data):
    """Search for the patterns, from the supplied structure, in the data.

    Convert patterns from a data structure into their lookback forms and
    search for them within a body of data, also converted into its lookback
    form.
    """
    # Convert the input data into a lookback.
    data_lb = compute_lookback(data)

    # Iterate through all patterns, searching for them within the given data.
    for category, patterns in pattern_structure.items():
        for pattern in patterns:
            # Convert the pattern into a lookback.
            pattern_lb = compute_lookback(pattern)

            # Search for this lookback pattern within our lookback data.
            for offset in locate_lookback(pattern_lb, data_lb):
                # Carve the actual data which the lookback pattern matched on.
                data_match = data[offset : offset + len(pattern)]

                # Ignore any plaintext matches / near-plaintext matches.
                if nearly_plaintext(pattern, data_match):
                    continue

                # Yield successful matches.
                yield (category, pattern, data_match, offset)
    return


def string_pattern_to_binary(pattern):
    """Convert pattern from JSON config file to bytes.

    Any escape sequences in the pattern are handled automatically.
    """
    return codecs.escape_decode(pattern.encode("utf-8"))[0]


def load_config(config_path):
    """Load config file that describes the patterns and their categories."""
    with open(config_path) as f:
        config = json.load(f)

    # JSON doesn't handle binary data, so process escape chars in strings to allow for hex-escape patterns etc.
    # to represent non-printable data
    processed_config = dict()
    for category, patterns in config.items():
        processed_patterns = [string_pattern_to_binary(s) for s in patterns]
        processed_config[category] = processed_patterns

    return processed_config


def main():
    """Search for supplied byte pattern/s in the specified file."""
    # Use argparse to provide a user interface and collect arguments.
    description = "Scan for patterns under arbitrary substitution ciphers."
    examples = """
Usage examples:

Scan a file using the default configuration:
    main.py file.exe

Scan a file using a custom configuration file:
    main.py --config myconfig.json file.exe

Scan a file using a custom pattern instead of a configuration file:
    main.py --pattern "This program cannot be run in DOS mode." file.exe
"""
    parser = argparse.ArgumentParser(
        description=description, epilog=examples, formatter_class=argparse.RawDescriptionHelpFormatter
    )

    # Only required argument is a file to scan
    parser.add_argument("filepath", help="File containing data to scan.")

    # Mutually exclusive optional arguments to provide either a custom
    # configuration file or to directly provide a pattern to search for.
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--config", dest="config_path", default=DEFAULT_CONFIG_PATH, help="Use patterns from a specific config file."
    )
    group.add_argument("--pattern", dest="pattern", help="Directly provide a pattern to scan for.")

    args = parser.parse_args()

    # Read in the data to be scanned from the provided filepath.
    with open(args.filepath, "rb") as f:
        file_data = f.read()

    # If a pattern is directly provided then search for that.
    if args.pattern:
        print("\nSearching for pattern in %s..." % args.filepath)

        for match in locate_pattern(args.pattern, file_data):
            match_data, offset = match
            print("\n\tPattern: %s" % args.pattern)
            print("\tData: %s" % match_data)
            print("\tOffset: 0x%X" % offset)

    # Otherwise, load patterns from a configuration file.
    else:
        # Load in configured search patterns.
        config = load_config(args.config_path)

        # Perform a lookback search to locate these patterns in the given data.
        print("\nSearching for patterns in %s..." % args.filepath)
        for match in locate_patterns(config, file_data):
            category, pattern, match_data, offset = match
            print("\n\tCategory: %s" % category)
            print("\tPattern: %s" % repr(pattern))
            print("\tData: %s" % match_data)
            print("\tOffset: 0x%08X" % offset)


if __name__ == "__main__":
    main()
