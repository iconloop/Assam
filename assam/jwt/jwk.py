from jwcrypto.jwk import JWK


possible_curves = [
    "P-256", "secp256k1", "P-256K"
]


def generate_jwk(curve: str = "P-256") -> JWK:
    """Generate JWK.

    .. Note:
    You can extract public and private key from returned key type by `extract_*(as_dict=True)` API.
    See more: https://jwcrypto.readthedocs.io/en/latest/jwk.html#jwcrypto.jwk.JWK

    # TODO: key from client could be `P-256K`, not `secp256k1`

    :param curve: Curve name. One of [possible_curves]
    :return: jwcrypto.jwk.JWK  # TODO: Possible type change.
    """
    if curve not in possible_curves:
        raise ValueError(f"Curves must be one of {possible_curves}.")

    return JWK.generate(kty="EC", crv=curve)
