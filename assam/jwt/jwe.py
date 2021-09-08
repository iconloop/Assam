import json
from typing import Tuple, Optional

from jwcrypto import jwk, jwe

from ._helper import extract_cek


def encrypt_jwe(pub_key: jwk.JWK, payload: dict, kid: Optional[str] = None) -> Tuple[str, jwk.JWK]:
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
    :param kid: ECDH key identifier
    :return Tuple[str, jwcrypto.jwk.JWK]: serialized JWE token, CEK  # TODO: CEK type could be changed.
    """
    protected_header = {
        "alg": "ECDH-ES+A128KW",
        "enc": "A128GCM",
        "typ": "JWE",
    }
    if kid:
        protected_header["kid"] = kid

    if isinstance(payload, dict):
        payload = json.dumps(payload)

    jwe_obj = jwe.JWE(
        payload,
        recipient=pub_key,
        protected=protected_header
    )
    cek = extract_cek(jwe_obj)

    return jwe_obj.serialize(compact=True), cek


def decrypt_jwe(token: str, pri_key: jwk.JWK) -> Tuple[dict, dict, jwk.JWK]:
    """Decrypt given JWE token.

    :param token: JWE Token to be decrypted  # FIXME: follows JWK format currently.
    :param pri_key: Matched private key to be used in JWE creation.
    :return Tuple[dict, dict, jwcrypto.jwk.JWK]: JOSE Header, Payload  # TODO: CEK type could be changed.

    :raises:
        InvalidJWEData: if failed in token decryption, normally in case of wrong private key supplied.
    """
    jwe_obj = jwe.JWE()
    jwe_obj.deserialize(
        token,
        key=pri_key
    )
    cek = extract_cek(jwe_obj)

    return jwe_obj.jose_header, json.loads(jwe_obj.payload), cek


def encrypt_jwe_with_cek(cek, payload: dict, kid: Optional[str] = None) -> str:
    """Encrypt JWE token with given key.

    If you successfully exchanged CEK by using encrypt_jwe / decrypt_jwe,
    then no longer need to generate CEK and its KEK.

    :param cek: Content Encryption Key extracted from JWE token enc/dec process.
    :param payload: Content to be encrypted by CEK.
    :param kid: A Token which indicates CEK. It is passed to recipient as a `kid` in JOSE header.
    :return: JWE token
    """
    protected_header = {
        "alg": "dir",
        "enc": "A128GCM",
        "typ": "JWE",
    }
    if kid:
        protected_header["kid"] = kid

    if isinstance(payload, dict):
        payload = json.dumps(payload)

    jwe_obj = jwe.JWE(
        payload,
        recipient=cek,
        protected=protected_header
    )
    return jwe_obj.serialize(compact=True)


def decrypt_jwe_with_cek(token, cek) -> Tuple[dict, dict]:
    """Decrypt JWE token with given key.

    If you successfully exchanged CEK by using encrypt_jwe / decrypt_jwe,
    then no longer need to generate CEK and its KEK.

    :param token: JWE token to be decrypted
    :param cek: Content Encryption Key extracted from JWE token enc/dec process.
    :return Tuple[dict, bytes]: JOSE Header, Payload
    """
    jwe_obj = jwe.JWE()
    jwe_obj.deserialize(
        token,
        key=cek
    )
    return jwe_obj.jose_header, json.loads(jwe_obj.payload)


def get_kid_from_jwe_header(token: str) -> Optional[str]:
    """Extract kid from JWE token.

    If you successfully exchanged CEK by using encrypt_jwe / decrypt_jwe,
    then sender may encrypt the payload using exchanged CEK, with alg key in header is set as **DIR**.

    In this case, sender must contain a hint for recipient to identify the sender's encryption key.
    This function is for extracting the hint (kid) from the message, in order to know how to decrypt the message.

    .. note:
    If no **kid** exist, then JWE must contain **epk** for exchanging CEK.

    :param token: JWE token which is expected to contain kid
    :return: kid. If no kid is found, then returns None
    """
    import base64
    import json

    header = token.split(".")[0]
    deserialized_header = base64.urlsafe_b64decode(header + "===")
    jose_header = json.loads(deserialized_header)

    return jose_header.get("kid")
