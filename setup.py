"""IronVeil — Casino and iGaming Security Audit Framework."""

from setuptools import setup, find_packages
import os
import re


def read_version():
    """Read version from ironveil/__init__.py without importing."""
    init_path = os.path.join(os.path.dirname(__file__), "ironveil", "__init__.py")
    with open(init_path, "r", encoding="utf-8") as fh:
        content = fh.read()
    match = re.search(r'__version__\s*=\s*"([^"]+)"', content)
    if not match:
        raise RuntimeError("Unable to find version string.")
    return match.group(1)


def read_requirements():
    """Read requirements.txt and return a list of dependencies."""
    req_path = os.path.join(os.path.dirname(__file__), "requirements.txt")
    if not os.path.exists(req_path):
        return []
    with open(req_path, "r", encoding="utf-8") as fh:
        return [
            line.strip()
            for line in fh
            if line.strip() and not line.startswith("#")
        ]


def read_long_description():
    """Read README.md for PyPI long description."""
    readme_path = os.path.join(os.path.dirname(__file__), "README.md")
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as fh:
            return fh.read()
    return ""


setup(
    name="ironveil",
    version=read_version(),
    author="BypassCore Labs",
    author_email="labs@bypasscore.com",
    description="Casino and iGaming security audit framework",
    long_description=read_long_description(),
    long_description_content_type="text/markdown",
    url="https://github.com/bypasscore/ironveil",
    project_urls={
        "Bug Tracker": "https://github.com/bypasscore/ironveil/issues",
        "Documentation": "https://github.com/bypasscore/ironveil/tree/main/docs",
        "Source": "https://github.com/bypasscore/ironveil",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    python_requires=">=3.9",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "ruff>=0.1.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ironveil=cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    keywords="casino igaming security audit bot-detection fingerprint",
)
