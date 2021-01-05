from typing import Dict
from unittest.mock import MagicMock

import pytest

from assam.did.score_client import DidScoreClient
from assam.did.verifier import ZzeungVerifier


def create_vp() -> dict:
    # TODO: VC as dataclass..?
    # https://resource-test.zzeung.id/sdkguide/guide/myid/vcp_message.html#presentation
    return {
        "version": "2.0",
        "type": ["PRESENTATION"],
        "iss": "did:icon:01:0000...2",
        "sub": "did:icon:01:c07bbcf24b7d9c7a1202e8ed0a64d17eee956aa48561bc93",
        "iat": 1578445403,
        "nonce": "b0f184df3f4e92ea9496d9a0aad259ae",
        "vc": "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6aWNvbjowMToyZmRhN2Y1MTYzZWM"
              "xNDU3ZDQ3MTE2N2JhMmRlMjQ2MTZlMTBhODA3OWE0ZjFhYmYjaXNzLWtleS0xIn0",
        "param": {
            "claim": {
                "name": {
                    "claimValue": "이제니",
                    "salt": "a1341c4b0cbff6bee9118da10d6e85a5"
                },
                "birthDate": {
                    "claimValue": "1985-02-28",
                    "salt": "65341c4b0cbff6bee9118da10d6e85a5"
                },
                "gender": {
                    "claimValue": "female",
                    "salt": "12341c4b0cbff6bee9118da10d6e85a5",
                    "displayValue": "여성"
                },
                "telco": {
                    "claimValue": "SKT",
                    "salt": "91341c4b0cbff6bee9118da10d6e85a5"
                },
                "phoneNumber": {
                    "claimValue": "01034561029",
                    "salt": "e2341c4b0cbff6bee9118da10d6e85a5",
                    "displayValue": "010-3456-1029"
                },
                "connectingInformation": {
                    "claimValue": "E21AEIDOW6",
                    "salt": "ff341c4b0cbff6bee9118da10d6e85a5"
                },
                "citizenship": {
                    "claimValue": True,
                    "salt": "f2341c4b0cbff6bee9118da10d6e85a5",
                    "displayValue": "내국인"
                }
            },
            "displayLayout": ["name", "birthDate", "gender", "telco", "phoneNumber", "citizenship"],
            "proofType": "hash",
            "hashAlgorithm": "SHA-256"
        }
    }


# FIXME: MOCKED CONTRACT DB!
DID = str  # FIXME: Need more realistic sample
DidDocument = dict  # FIXME: Need more realistic sample
did_storage: Dict[DID, DidDocument] = {
    "hi:i:m:issuer": {"did": "did"}
}


class TestVerifier:
    @pytest.fixture
    def did_score_client(self):
        mock_did_score: DidScoreClient = MagicMock(DidScoreClient)
        mock_did_score.get_context.return_value = "bulbulbulbubl"
        mock_did_score.read = lambda did: did_storage.get(did)

        return mock_did_score

    @pytest.fixture
    def verifier(self, did_score_client):
        return ZzeungVerifier(did_service=did_score_client)  # FIXME: VcSCORE Needed, even if Verifier does not need it.

    def test_verify_presentation(self, verifier: ZzeungVerifier):
        # Given I have a VP from Client
        vp = create_vp()

        # WHEN I verify
        is_verified = verifier.verify_vp(vp)

        # THEN It should be passed
        assert is_verified is True

    def test_verify_did(self, verifier: ZzeungVerifier):
        # Given I have a DID to be verified
        issuer_did = "hi:i:m:issuer"

        # WHEN I verify
        is_verified = verifier.verify_did(issuer_did)

        # THEN It should be passed
        assert is_verified is True

    def test_verify_did_not_exist(self, verifier: ZzeungVerifier):
        # Given I have a DID to be verified, but expected it is invalid one
        issuer_did = "unknown:entity"

        # WHEN I verify
        is_verified = verifier.verify_did(issuer_did)

        # THEN It should be failed
        assert is_verified is False
