import json
from typing import Union, Tuple

from jwcrypto import jwk, jwe


def encrypt_jwe(pub_key: str, payload: Union[str, bytes, dict]) -> str:
    """Encrypt JWE token.

    **JWE format**:
        - Base64Url(Protected Header)
        - Base64Url(Encrypted Key)
        - Base64Url(IV)
        - Base64Url(CipherText)
        - Base64Url(AuthTag)
    .. note:: and all of these values are concatenate by `.`

    :param pub_key: Peer's public key.  # FIXME: follows JWK format currently.
    :param payload: Payload to be sent
    :return str: serialized JWE token
    """
    peer_pub_key = jwk.JWK.from_json(pub_key)
    protected_header = {
        "alg": "ECDH-ES+A128KW",
        "enc": "A128GCM",
        "typ": "JWE",
    }

    if isinstance(payload, dict):
        payload = json.dumps(payload)

    jwe_obj = jwe.JWE(
        payload,
        recipient=peer_pub_key,
        protected=protected_header
    )
    return jwe_obj.serialize(compact=True)


def decrypt_jwe(token: str, pri_key: str) -> Tuple[dict, bytes]:
    """Decrypt given JWE token.

    :param token: JWE Token to be decrypted  # FIXME: follows JWK format currently.
    :param pri_key: Matched private key to be used in JWE creation.
    :return Tuple[dict, bytes]: JOSE Header, Payload

    :raises:
        InvalidJWEData: if failed in token decryption, normally in case of wrong private key supplied.
    """
    pri_key = jwk.JWK.from_json(pri_key)
    jwe_obj = jwe.JWE()
    jwe_obj.deserialize(
        token,
        key=pri_key
    )
    return jwe_obj.jose_header, jwe_obj.payload
