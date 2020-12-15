import json

import pytest
from iconsdk.wallet.wallet import KeyWallet
from iconsdk.icon_service import IconService
from iconsdk.providers.http_provider import HTTPProvider

from assam.did.score_client import DidScoreClient

did_holder_key = {
    "did": "did:icon:02:e8622b85c9af6f51456f64e96ff3c8a1d11fc1ebbc9179e8",
    "keyId": "kkkk-key",
    "type": "ES256K",
    "crypto": {
        "cipher": "aes-128-ctr",
        "ciphertext": "c86fb0b75e258a6f096b8f68f1a77d4e7e622f6c7dbca5473611a345377fb1b3",
        "cipherparams": {
            "iv": "0ea9b89b3494464824f4dce4f6e29d33"
        },
        "kdf": "scrypt",
        "kdfparams": {
            "dklen": 32,
            "n": 16384,
            "p": 1,
            "r": 8,
            "salt": "ac3b05ec18b516e2491e2446b770a4eaae1daf136beac81538931cb7524ac87e"
        },
        "mac": "7b99b836888d6d1aff0dac8154059a50c935ff3804abecb63b8396d90308094e"
    },
    "id": "dbc79ead-64bc-404c-a186-a1c2fb258aca",
    "version": 3
}


@pytest.mark.skip("contract call!")
class TestDidScoreInterface:
    key_path: str = None

    # FIXME: scope...
    @pytest.fixture
    def init_holder_key(self, tmp_path):
        key_path = tmp_path / "holder_key.json"
        with open(key_path, "w") as f:
            f.write(json.dumps(did_holder_key))

        self.key_path = str(key_path)

    @pytest.fixture
    def did_score_client(self, init_holder_key):
        key_password = "P@ssw0rd"
        wallet = KeyWallet.load(self.key_path, key_password)

        zzeung_testbed_endpoint = "https://testwallet.icon.foundation/api/v3"  # 을지로 테스트넷
        icon_service = IconService(HTTPProvider(zzeung_testbed_endpoint))

        did_score_addr = "cx8b19bdb4e1ad3e10b599d8887dd256e02995f340"
        return DidScoreClient(
            icon_service=icon_service,
            score_addr=did_score_addr,
            wallet=wallet
        )

    def test_did_score_call(self, did_score_client):
        res = did_score_client.get_context()
        assert res == "https://w3id.org/did/v1"

    def test_get_did(self, did_score_client):
        with open(self.key_path) as f:
            keyfile = json.load(f)
            did: str = keyfile["did"]
        res = did_score_client.read(did)
        print("RES?: ", res)
