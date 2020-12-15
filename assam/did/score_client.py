import abc
from typing import TYPE_CHECKING

from iconsdk.builder.call_builder import CallBuilder
from iconsdk.wallet.wallet import KeyWallet

if TYPE_CHECKING:
    from iconsdk.icon_service import IconService


class ScoreClient(abc.ABC):
    """Loopchain Contract Interface"""

    def __init__(self, icon_service: "IconService", score_addr: str, wallet: KeyWallet):
        self._icon_service: "IconService" = icon_service
        self._addr: str = score_addr
        self._wallet = wallet

    def _create_call(self) -> CallBuilder:
        return CallBuilder().\
            from_(self._wallet.get_address()).\
            to(self._addr)


class DidScoreClient(ScoreClient):
    """DID SCORE Interface"""

    def get_context(self):
        call = self._create_call().\
            method("getContext").\
            build()

        return self._icon_service.call(call)

    def read(self, did: str):
        call = self._create_call().\
            method("read").\
            params({"did": did}).\
            build()

        return self._icon_service.call(call)


class VcScoreClient:
    """VC SCORE Interface"""

    def __init__(self, icon_service: "IconService", score_addr: str, wallet: KeyWallet):
        self._icon_service: "IconService" = icon_service
        self._addr: str = score_addr
        self._wallet = wallet

    def register(self, credential_jwt: str):
        """register"""
        pass
