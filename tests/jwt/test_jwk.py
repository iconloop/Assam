import pytest

from assam.jwt import generate_jwk


class TestJWK:
    @pytest.mark.parametrize("curve", ["P-256", "secp256k1"])
    def test_generate_key(self, curve):
        # WHEN I generate Key Pair
        k = generate_jwk(curve)
        pub_key, pri_key = k.export_public(as_dict=True), k.export_private(as_dict=True)

        # THEN Key type must EC
        assert "EC" == pub_key["kty"]
        assert "EC" == pri_key["kty"]

        # AND ECurve type must be desired one
        assert curve == pub_key["crv"]
        assert curve == pri_key["crv"]

        # AND All key params should exist
        for param in ["x", "y"]:
            assert param in pub_key.keys()
            assert param in pri_key.keys()
        assert "d" in pri_key.keys()
