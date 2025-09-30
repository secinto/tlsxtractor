"""
Setup configuration for TLSXtractor.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path) as f:
        requirements = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith("#")
        ]

setup(
    name="tlsxtractor",
    version="1.0.0",
    author="TLSXtractor Team",
    description="TLS certificate and domain extraction tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/tlsxtractor",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "tlsxtractor=tlsxtractor.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.9",
)