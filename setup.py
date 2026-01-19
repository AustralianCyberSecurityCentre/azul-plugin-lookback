#!/usr/bin/env python3
"""Setup script."""

import os

from setuptools import setup


def open_file(fname):
    """Open and return a file-like object for the relative filename."""
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name="azul-plugin-lookback",
    description="Find patterns under any single-byte substitution cipher.",
    author="Azul",
    author_email="azul@asd.gov.au",
    url="https://www.asd.gov.au/",
    packages=["azul_plugin_lookback"],
    include_package_data=True,
    python_requires=">=3.12",
    classifiers=[],
    entry_points={
        "console_scripts": [
            "azul-plugin-lookback-hash = azul_plugin_lookback.hash:main",
            "azul-plugin-lookback-search = azul_plugin_lookback.search:main",
            "lookback-search = azul_plugin_lookback.lookback_search.main:main",
            "lookback-config = azul_plugin_lookback.lookback_search.stats:main",
        ]
    },
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[r.strip() for r in open_file("requirements.txt") if not r.startswith("#")],
)
