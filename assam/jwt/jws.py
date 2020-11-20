import json
from typing import Union, Tuple

from jwcrypto import jwk, jws


def encrypt_jws(pri_key: str, payload: Union[str, bytes, dict]) -> str:
    """Encrypt JWS token.

    **JWS format**:
        - Base64Url(JWS Protected Header)
        - Base64Url(Payload)
        - Base64Url(Signature)
    .. note:: and all of these values are concatenate by `.`

    :param pri_key: Private key of Signer
    :param payload: Contents of being signed
    :return: JWE Token
    """
    sign_key = jwk.JWK.from_json(pri_key)
    protected_header = {
        "alg": "ES256",
        "typ": "JWS",
        "kid": sign_key.thumbprint()
    }

    if isinstance(payload, dict):
        payload = json.dumps(payload)

    jws_obj = jws.JWS(payload)
    jws_obj.add_signature(
        sign_key,
        None,
        protected_header,
        None
    )
    return jws_obj.serialize(compact=True)


def decrypt_jws(token: str, pub_key: str) -> Tuple[dict, bytes]:
    """Decrypt given JWS token.

    Note that payload always bytes.

    :param token: Compact JWS token to be verified
    :param pub_key: Signer's public key
    :return Tuple[dict, bytes]: JOSE Header, Payload

    :raise jwcrypto.jws.InvalidJWSSignature
    """
    signer_pub_key = jwk.JWK.from_json(pub_key)
    jws_obj = jws.JWS()
    jws_obj.deserialize(token)
    jws_obj.verify(signer_pub_key)  # raises jwcrypto.jws.InvalidJWSSignature if failed

    return jws_obj.jose_header, jws_obj.payload
