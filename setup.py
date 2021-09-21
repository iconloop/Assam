from setuptools import setup, find_packages

req_tests = ["pytest"]
req_lint = ["flake8", "flake8-docstrings"]
req_dev = req_tests + req_lint

setup_options = {
    "name": "Assam",
    "version": "2.0.0",
    "description": "Cryptographic library for Lite Vault servers.",
    "packages": find_packages(),
    "python_requires": ">=3.7.3",
    "install_requires": [
        "jwcrypto @ git+https://github.com/iconloop/jwcrypto.git",
        "iconsdk",
        "python-jwt"
    ],
    "extras_require": {
        "tests": req_tests,
        "lint": req_lint,
        "dev": req_dev
    },
    "package_dir": {"": "."},
}

setup(**setup_options)
