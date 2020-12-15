import pytest

from assam.jwt import encrypt_jws, decrypt_jws, generate_jwk


class TestEncryptJWS:
    def test_encrypt(self):
        key_pair = generate_jwk()

        # GIVEN I have a payload
        payload = b"hello?"

        # WHEN I created token
        token = encrypt_jws(key_pair, payload)

        # THEN It must have three parts
        each_parts = token.split(".")
        assert len(each_parts) == 3

        # AND None of them is empty
        for part in each_parts:
            assert part

    @pytest.mark.parametrize("payload", [
        "this is string",
        b"this is bytes",
        {"type": "this is dict"}
    ], ids=["string", "bytes", "dict"])
    def test_various_payload_types(self, payload):
        key_pair = generate_jwk()
        jws_token = encrypt_jws(key_pair, payload)

        # THEN It must have three parts
        each_parts = jws_token.split(".")
        assert len(each_parts) == 3

        # AND None of them is empty
        for part in each_parts:
            assert part


class TestDecryptJWS:
    def test_decrypt(self):
        signer_key_pair = generate_jwk()

        payload = b"hello?"
        jws_token = encrypt_jws(signer_key_pair, payload)

        header, actual_payload = decrypt_jws(jws_token, signer_key_pair)

        assert actual_payload == payload

    def test_signature_tempered(self):
        signer_key_pair = generate_jwk()
        payload = b"hello?"
        jws_token = encrypt_jws(signer_key_pair, payload)

        # WHEN I decrypt normally, THEN succeeded in verification.
        decrypt_jws(jws_token, signer_key_pair)

        header_enc, payload_enc, sign_enc = jws_token.split(".")

        # WHEN I tempered signature by reversing its order
        sign_enc = sign_enc[::-1]
        token_tempered = ".".join([header_enc, payload_enc, sign_enc])
        assert not jws_token == token_tempered

        # THEN failed in verification
        from jwcrypto.jws import InvalidJWSSignature
        with pytest.raises(InvalidJWSSignature):
            decrypt_jws(token_tempered, signer_key_pair)
