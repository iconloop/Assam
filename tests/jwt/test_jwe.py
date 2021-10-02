import base64
import json

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


@pytest.mark.parametrize("curve", ["P-256", "P-256K", "secp256k1"])
class TestEncryptJWE:
    def test_encrypted_is_valid_jwe_spec(self, curve):
        key_pair = generate_jwk(curve)

        # WHEN I created token
        jwe_token, cek = encrypt_jwe(key_pair, payload)

        # THEN It must have prefer form
        each_parts = jwe_token.split(".")
        assert len(each_parts) == 5

        # AND None of them is empty
        for part in each_parts:
            assert part

    def test_header_has_proper_epk(self, curve):
        # GIVEN I created a key pair
        key_pair = generate_jwk(curve)

        # WHEN I created token
        jwe_token, cek = encrypt_jwe(key_pair, payload)

        # THEN It must have epk in header
        header = jwe_token.split(".")[0]
        header = base64.urlsafe_b64decode(header + "===")
        header = json.loads(header)
        assert "epk" in header

        # AND it should contain valid key curve
        epk: dict = header["epk"]
        assert epk["kty"] == "EC"
        assert epk["crv"] == curve

        # AND It should contain public params of EC key
        assert "x" in epk
        assert "y" in epk


class TestEncryptWithCEK:
    def _get_jose_header_from_token(self, token) -> dict:
        # Helper
        header = token.split(".")[0]
        deserialized_header = base64.urlsafe_b64decode(header + "===")
        return json.loads(deserialized_header)

    def test_kid_check_in_encrypt_with_cek(self):
        expected_kid = "ThisIsMyHint"
        cek = jwk.JWK.generate(kty="oct")
        payload = {
            "testing": "value!"
        }

        # WHEN I encrypt payload using cek
        # AND Supply kid
        jwe_token = encrypt_jwe_with_cek(cek, payload, kid=expected_kid)

        # THEN the kid in header should be equal to supplied kid
        assert get_kid_from_jwe_header(jwe_token) == expected_kid

    def test_kid_should_be_optional_in_encrypt_with_cek(self):
        cek = jwk.JWK.generate(kty="oct")
        payload = {
            "testing": "value!"
        }

        # WHEN I encrypt payload using cek
        # AND no kid is supplied
        jwe_token = encrypt_jwe_with_cek(cek, payload)

        # THEN the kid in header does not exist
        jose_header = self._get_jose_header_from_token(jwe_token)
        assert "kid" not in jose_header

        # AND neither the kid value does not
        assert get_kid_from_jwe_header(jwe_token) is None


@pytest.mark.parametrize("curve", ["P-256", "secp256k1"])
class TestDecryptJWE:
    def test_decrypt(self, curve):
        recipient_key_pair = generate_jwk(curve)

        # GIVEN The Sender created token by using the recipient's public key
        jwe_token, cek = encrypt_jwe(recipient_key_pair, payload)

        # WHEN The recipient decrypt it with the recipient's own private key
        header, actual_payload, cek = decrypt_jwe(jwe_token, recipient_key_pair)

        # THEN It should be readable
        assert actual_payload == payload

    def test_decrypt_with_wrong_key(self, curve):
        recipient_key_pair = generate_jwk(curve)
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
    @pytest.mark.parametrize("curve", ["P-256", "P-256K", "secp256k1"])
    def test_scenario(self, curve):
        recipient_key_pair = generate_jwk(curve)

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
