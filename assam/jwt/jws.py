from typing import Tuple

import python_jwt
from jwcrypto import jwk

_verification_alg = {
    "P-256": "ES256",
    "secp256k1": "ES256K"
}


def encrypt_jws(signer_key: jwk.JWK, payload: dict) -> str:
    """Encrypt JWS token.

    **JWS format**:
        - Base64Url(JWS Protected Header)
        - Base64Url(Payload)
        - Base64Url(Signature)
    .. note:: and all of these values are concatenate by `.`

    :param signer_key: Private key of Signer
    :param payload: Contents of being signed
    :return: JWE Token
    """
    alg = _verification_alg[signer_key.key_curve]
    return python_jwt.generate_jwt(
        payload, signer_key, alg
    )


def decrypt_jws(token: str, signer_pub_key: jwk.JWK) -> Tuple[dict, dict]:
    """Decrypt given JWS token.

    Note that payload always bytes.

    :param token: Compact JWS token to be verified
    :param signer_pub_key: Signer's public key
    :return Tuple[dict, dict]: JOSE Header, Payload

    :raise ValueError  # TODO: Exc type?
    """
    try:
        jose_header, payload = python_jwt.verify_jwt(
            token,
            signer_pub_key,
            allowed_algs=["ES256", "ES256K"],
            checks_optional=True
        )
    except Exception as e:  # TODO: Exc type?
        raise ValueError("Failed to verify JWS.") from e

    return jose_header, payload
