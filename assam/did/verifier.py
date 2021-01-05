import abc
from typing import TYPE_CHECKING, Type

if TYPE_CHECKING:
    from assam.did.score_client import DidScoreClient


class Verifier(abc.ABC):
    def __init__(self, did_service: "DidScoreClient", **kwargs):
        self._did_service: "DidScoreClient" = did_service

    @abc.abstractmethod
    def verify(self, presentation: dict) -> bool:
        """Verify VP.

        .. note: This is responsible for verification of VP, not for JWT HMAC verification

        :param presentation:
        :return:
        """
        pass

    def _verify_vc(self, credential):
        # FIXME: Avoid network call at every VC verification. Check batch request to SCORE.
        self._verify_vc_issuer(credential)
        self._verify_vc_subject(credential)

    def _verify_vc_issuer(self, credential) -> bool:  # TODO: signature type
        issuer_did = credential.get("iss")
        issuer_doc = self._did_service.read(issuer_did)
        if not issuer_doc:
            raise ValueError

        return True

    def _verify_vc_subject(self, credential):
        subject_did = credential.get("sub")
        subject_doc = self._did_service.read(subject_did)
        if not subject_doc:
            raise ValueError

        return True

    @classmethod
    def get_verifier(cls, verifier_type=None) -> Type["Verifier"]:
        return ZzeungVerifier


class ZzeungVerifier(Verifier):
    def verify(self, presentation: dict) -> bool:
        # FIXME:
        # try:
        #     credentials = presentation.get("credentials")
        #     for credential in credentials:
        #         self._verify_vc(credential)
        # except:
        #     return False
        #
        return True
