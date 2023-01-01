from dataclasses import dataclass
from typing import Generic, List, TypeVar, Dict

from minaombud.crypto.jwk import Jwk

K = TypeVar("K", bound=Jwk)


@dataclass
class CryptoFamily(Generic[K]):
    kty: str
    algorithms: List[str]

    def prepare_key(self, alg: str, key: Jwk) -> K:
        raise NotImplementedError()

    def verify(self, signature: bytes, data: bytes, alg: str, key: K) -> bool:
        raise NotImplementedError()

    def sign(self, data: bytes, alg: str, key: K) -> bytes:
        raise NotImplementedError()


CRYPTO_FAMILIES: Dict[str, CryptoFamily] = {}


def register_crypto_family(family: CryptoFamily):
    CRYPTO_FAMILIES[family.kty] = family
