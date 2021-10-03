# Assam
Cryptographic library for Lite Vault servers.

It heavily depends on [JWCrypto] library to achieve its main purposes:
- Create JWE token and decrypt it
- Create JWS token and verify its signature
- ...

## Prerequisite
- Python 3.7.x
- jwcrypto (must use a modified version) https://github.com/iconloop/jwcrypto.git
  - Origin(https://github.com/latchset/jwcrypto) does not work with Assam.
  (It doesn't suport P-256K and outside epk)

## Installation
1. **Install Python interpreter (3.7+)**
```
$ virtualenv -p python3 venv
$ source venv/bin/activate
```

2. **Install dependencies**
```
$ pip install -e .
```


[JWCrypto]: https://github.com/latchset/jwcrypto