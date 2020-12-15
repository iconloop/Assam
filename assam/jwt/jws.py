import json
from typing import Tuple

from jwcrypto import jwk, jws


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
    protected_header = {
        "alg": "ES256",
        "typ": "JWS",
        "kid": signer_key.thumbprint()
    }

    if isinstance(payload, dict):
        payload = json.dumps(payload)

    jws_obj = jws.JWS(payload)
    jws_obj.add_signature(
        signer_key,
        None,
        protected_header,
        None
    )
    return jws_obj.serialize(compact=True)


def decrypt_jws(token: str, signer_pub_key: jwk.JWK) -> Tuple[dict, dict]:
    """Decrypt given JWS token.

    Note that payload always bytes.

    :param token: Compact JWS token to be verified
    :param signer_pub_key: Signer's public key
    :return Tuple[dict, dict]: JOSE Header, Payload

    :raise jwcrypto.jws.InvalidJWSSignature
    """
    jws_obj = jws.JWS()
    jws_obj.deserialize(token)
    jws_obj.verify(signer_pub_key)  # raises jwcrypto.jws.InvalidJWSSignature if failed

    return jws_obj.jose_header, json.loads(jws_obj.payload)
