import pytest
from jwcrypto.jwe import InvalidJWEData

from assam.jwt import (
    encrypt_jwe, encrypt_jwe_with_cek,
    decrypt_jwe, decrypt_jwe_with_cek
)
from .helper import ec_key_pair


class TestEncryptJWE:
    def test_encrypt(self):
        public_key, private_key = ec_key_pair()

        # GIVEN I have a payload
        payload = b"hello?"  # Could be json serialized obj

        # WHEN I created token
        jwe_token, cek = encrypt_jwe(public_key, payload)

        # THEN It must have prefer form
        each_parts = jwe_token.split(".")
        assert len(each_parts) == 5

        # AND None of them is empty
        for part in each_parts:
            assert part

    @pytest.mark.parametrize("payload", [
        "this is string",
        b"this is bytes",
        {"type": "this is dict"}
    ], ids=["string", "bytes", "dict"])
    def test_various_payload_types(self, payload):
        public_key, private_key = ec_key_pair()

        # WHEN I created token
        jwe_token, cek = encrypt_jwe(public_key, payload)

        # THEN It must have prefer form
        each_parts = jwe_token.split(".")
        assert len(each_parts) == 5


class TestDecryptJWE:
    def test_decrypt(self):
        recipient_pub_key, recipient_pri_key = ec_key_pair()

        # GIVEN The Sender created token by using the recipient's public key
        payload = b"hello?"
        jwe_token, cek = encrypt_jwe(recipient_pub_key, payload)

        # WHEN The recipient decrypt it with the recipient's own private key
        header, actual_payload, cek = decrypt_jwe(jwe_token, recipient_pri_key)

        # THEN It should be readable
        assert actual_payload == payload

    def test_decrypt_with_wrong_key(self):
        recipient_pub_key, recipient_pri_key = ec_key_pair()
        another_pub_key, another_pri_key = ec_key_pair()
        assert not recipient_pub_key == another_pub_key
        assert not recipient_pri_key == another_pri_key

        # GIVEN The Sender created token by using the recipient's public key
        payload = b"hello?"
        token, cek = encrypt_jwe(recipient_pub_key, payload)

        # WHEN The recipient tries to decrypt with the wrong private key
        # THEN Exception must be raised
        with pytest.raises(InvalidJWEData):
            header, actual_payload, cek = decrypt_jwe(token, another_pri_key)


class TestSample:
    def test_scenario(self):
        recipient_pub_key, recipient_pri_key = ec_key_pair()

        # GIVEN The Sender created token by using the recipient's public key
        payload = b"hello?"
        _jwe_token, cek_sender = encrypt_jwe(recipient_pub_key, payload)

        # WHEN Recipient derives CEK
        _header, _decrypted_payload, derived_cek = decrypt_jwe(_jwe_token, recipient_pri_key)
        # THEN CEK both sides must equal
        assert cek_sender.export() == derived_cek.export()

        # ==========REPLY==========
        # GIVEN Recipient encrypts payload using CEK, to reply ACK message or something.
        ack_message = b"ACK!"
        jwe_token = encrypt_jwe_with_cek(derived_cek, ack_message)

        # WHEN Sender decrypts JWE token using CEK
        header, actual_payload = decrypt_jwe_with_cek(jwe_token, cek_sender)

        # THEN The payload should be decrypted without any problem
        assert actual_payload == ack_message
