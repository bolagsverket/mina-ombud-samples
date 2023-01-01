from dataclasses import dataclass
from typing import Optional, List

from minaombud.serialization import IdentityCaseJSONClass


@dataclass
class RSAKeyOthParams(IdentityCaseJSONClass):
    r: str
    d: str
    t: str


_PRIVATE_KEY_PARAMS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")


@dataclass
class Jwk(IdentityCaseJSONClass):
    kty: str
    kid: str
    use: Optional[str] = None
    key_ops: Optional[List[str]] = None
    alg: Optional[str] = None
    x5u: Optional[str] = None
    x5c: Optional[List[str]] = None
    x5t: Optional[str] = None
    # Retrieve with: get_extra()['x5t#S256']
    # 'x5t#S256': Optional[str] = None

    # RSA public key parameters
    # See https://www.rfc-editor.org/rfc/rfc7518#section-6.3
    n: Optional[str] = None
    e: Optional[str] = None
    # RSA private key parameters
    d: Optional[str] = None
    p: Optional[str] = None
    q: Optional[str] = None
    dp: Optional[str] = None
    dq: Optional[str] = None
    qi: Optional[str] = None
    oth: Optional[List[RSAKeyOthParams]] = None

    # EC public key parameters
    # See https://www.rfc-editor.org/rfc/rfc7518#section-6.2
    crv: Optional[str] = None
    x: Optional[str] = None
    y: Optional[str] = None
    # EC private key parameters
    # d: Optional[str] = None  # duplicates RSA key parameter

    # Symmetric key parameters
    # See https://www.rfc-editor.org/rfc/rfc7518#section-6.4
    k: Optional[str] = None

    def __contains__(self, item):
        return self.__dict__.get(item, None) is not None

    def __getitem__(self, item):
        v = self.__dict__.get(item)
        if v is None:
            raise KeyError(item)
        return v

    def __iter__(self):
        return iter(self.__dict__)

    def is_private_key(self) -> bool:
        return any(p in self for p in _PRIVATE_KEY_PARAMS)

    def to_public_key(self) -> "Jwk":
        params = {k: v for k, v in self if k not in _PRIVATE_KEY_PARAMS}
        return Jwk(**params)
