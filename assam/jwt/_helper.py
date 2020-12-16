from jwcrypto import jwk
from jwcrypto.common import base64url_encode


def extract_cek(jwe_object) -> jwk.JWK:
    cek = jwk.JWK()
    k = base64url_encode(jwe_object.cek)
    cek.import_key(k=k, kty="oct")

    return cek
