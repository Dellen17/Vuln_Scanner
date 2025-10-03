from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="mini-vulnerability-scanner",
    version="2.0.0",
    author="Vulnerability Scanner Team",
    description="A modular mini vulnerability scanner for educational purposes",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Education",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
        "rich>=10.0.0",
        "cryptography>=3.4.0",
    ],
    extras_require={
        "screenshots": ["playwright>=1.30.0"],
    },
    entry_points={
        "console_scripts": [
            "vulnscan=scanner.cli:main",
        ],
    },
)