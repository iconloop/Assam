import pytest
from jwcrypto import jwk
from jwcrypto.jwe import InvalidJWEData

from assam.jwt import (
    encrypt_jwe, encrypt_jwe_with_cek,
    decrypt_jwe, decrypt_jwe_with_cek, generate_jwk
)
from assam.jwt.jwe import get_kid_from_jwe_header

payload = {
    "claim": "testing."
}


class TestEncryptJWE:
    @pytest.mark.parametrize("curve", ["P-256", "secp256k1"])
    def test_encrypt(self, curve):
        key_pair = generate_jwk(curve)

        # WHEN I created token
        jwe_token, cek = encrypt_jwe(key_pair, payload)

        # THEN It must have prefer form
        each_parts = jwe_token.split(".")
        assert len(each_parts) == 5

        # AND None of them is empty
        for part in each_parts:
            assert part


class TestDecryptJWE:
    def test_decrypt(self):
        recipient_key_pair = generate_jwk()

        # GIVEN The Sender created token by using the recipient's public key
        jwe_token, cek = encrypt_jwe(recipient_key_pair, payload)

        # WHEN The recipient decrypt it with the recipient's own private key
        header, actual_payload, cek = decrypt_jwe(jwe_token, recipient_key_pair)

        # THEN It should be readable
        assert actual_payload == payload

    def test_decrypt_with_wrong_key(self):
        recipient_key_pair = generate_jwk()
        another_key_pair = generate_jwk()
        assert recipient_key_pair.export_public() != another_key_pair.export_public()
        assert recipient_key_pair.export_private() != another_key_pair.export_private()

        # GIVEN The Sender created token by using the recipient's public key
        token, cek = encrypt_jwe(recipient_key_pair, payload)

        # WHEN The recipient tries to decrypt with the wrong private key
        # THEN Exception must be raised
        with pytest.raises(InvalidJWEData):
            header, actual_payload, cek = decrypt_jwe(token, another_key_pair)


class TestSample:
    def test_scenario(self):
        recipient_key_pair = generate_jwk()

        # GIVEN The Sender created token by using the recipient's public key
        _jwe_token, cek_sender = encrypt_jwe(recipient_key_pair, payload)

        # WHEN Recipient derives CEK
        _header, _decrypted_payload, derived_cek = decrypt_jwe(_jwe_token, recipient_key_pair)
        # THEN CEK both sides must equal
        assert cek_sender.export() == derived_cek.export()

        # ==========REPLY==========
        # GIVEN Recipient encrypts payload using CEK, to reply ACK message or something.
        ack_message = {"msg": "ACK!"}
        jwe_token = encrypt_jwe_with_cek(derived_cek, ack_message, kid="TOKEN")

        # WHEN Sender decrypts JWE token using CEK
        header, actual_payload = decrypt_jwe_with_cek(jwe_token, cek_sender)

        # THEN The payload should be decrypted without any problem
        assert actual_payload == ack_message

    def test_get_token_from_header(self):
        # GIVEN I have a CEK, which is derived through key exchange.
        derived_cek = jwk.JWK.generate(kty="oct", size=128)
        import base64
        key_for_aes_enc = derived_cek.export_symmetric(as_dict=True)["k"]
        key_for_aes_enc = key_for_aes_enc + "==="
        assert len(base64.urlsafe_b64decode(key_for_aes_enc)) == 16  # A128GCM key

        # AND I have a payload and token
        auth_token = "GENERATED_AUTH_TOKEN"

        # WHEN I encrypt payload using CEK
        jwe_token = encrypt_jwe_with_cek(derived_cek, payload, kid=auth_token)

        # THEN Recipient can retrieve a token
        extracted_auth_token = get_kid_from_jwe_header(jwe_token)
        # AND The token must be same with sender's one
        assert auth_token == extracted_auth_token
