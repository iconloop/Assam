import pytest

from assam.jwt import encrypt_jws, decrypt_jws, generate_jwk

payload = {
    "claim": "testing."
}


@pytest.mark.parametrize("curve", ["P-256", "P-256K", "secp256k1"])
class TestEncryptJWS:
    def test_encrypt(self, curve):
        key_pair = generate_jwk(curve)

        # WHEN I created token
        token = encrypt_jws(key_pair, payload)

        # THEN It must have three parts
        each_parts = token.split(".")
        assert len(each_parts) == 3

        # AND None of them is empty
        for part in each_parts:
            assert part


@pytest.mark.parametrize("curve", ["P-256", "P-256K", "secp256k1"])
class TestDecryptJWS:
    def test_decrypt(self, curve):
        signer_key_pair = generate_jwk(curve)

        jws_token = encrypt_jws(signer_key_pair, payload)

        header, actual_payload = decrypt_jws(jws_token, signer_key_pair)

        assert actual_payload["claim"] == payload["claim"]

    def test_signature_tempered(self, curve):
        signer_key_pair = generate_jwk(curve)
        jws_token = encrypt_jws(signer_key_pair, payload)

        # WHEN I decrypt normally, THEN succeeded in verification.
        decrypt_jws(jws_token, signer_key_pair)

        header_enc, payload_enc, sign_enc = jws_token.split(".")

        # WHEN I tempered signature by reversing its order
        sign_enc = sign_enc[::-1]
        token_tempered = ".".join([header_enc, payload_enc, sign_enc])
        assert not jws_token == token_tempered

        # THEN failed in verification
        with pytest.raises(ValueError, match="Failed to verify JWS"):  # TODO: Exc type
            decrypt_jws(token_tempered, signer_key_pair)
