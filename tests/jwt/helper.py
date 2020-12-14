from typing import Tuple

# Types
PublicKey = str
PrivateKey = str


def ec_key_pair() -> Tuple[PublicKey, PrivateKey]:
    from jwcrypto import jwk
    key_pair = jwk.JWK.generate(kty="EC", crv="P-256")
    return key_pair.export_public(), key_pair.export_private()
