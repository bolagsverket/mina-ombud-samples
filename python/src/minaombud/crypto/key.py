import copy
import dataclasses
import typing
from datetime import datetime
from typing import Generic, List, Optional, TypeVar, Union

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import Certificate

from minaombud.crypto.family import CryptoFamily, CRYPTO_FAMILIES
from minaombud.crypto.jwk import Jwk
from minaombud.util import base64_encode_urlsafe

PVK = TypeVar("PVK")
PUB = TypeVar("PUB")


class ParsedJwk(Generic[PUB, PVK], Jwk):
    def __init__(
        self,
        public_key: PUB,
        private_key: Optional[PVK],
        *,
        jwk: Optional[Jwk] = None,
        not_valid_after: Optional[datetime] = None,
        not_valid_before: Optional[datetime] = None,
        certificates: Optional[List[Certificate]] = None,
        **kwargs,
    ):
        self.public_key = public_key
        self.private_key = private_key
        self.not_valid_after = not_valid_after
        self.not_valid_before = not_valid_before
        self.certificates = certificates
        if jwk:
            args = dataclasses.asdict(jwk)
            args.update(kwargs)
        else:
            args = kwargs
        super(ParsedJwk, self).__init__(**args)
        if jwk:
            self.get_extra().update(copy.deepcopy(jwk.get_extra()))

        if not self.private_key:
            # Clear private key parameters
            self.d = None
            self.p = None
            self.q = None
            self.dp = None
            self.dq = None
            self.qi = None
            self.oth = None
            self.k = None

        if self.certificates:
            cert = self.certificates[0]
            if not self.not_valid_before:
                self.not_valid_before = cert.not_valid_before
            if not self.not_valid_after:
                self.not_valid_after = cert.not_valid_after
            if not self.x5t:
                sha1 = hashes.SHA1()
                self.x5t = base64_encode_urlsafe(cert.fingerprint(sha1)).decode("ascii")
            extra = self.get_extra()
            if "x5t#S256" not in extra:
                sha256 = hashes.SHA256()
                extra["x5t#S256"] = base64_encode_urlsafe(
                    cert.fingerprint(sha256)
                ).decode("ascii")
            if not self.x5c:
                self.x5c = []
                for c in self.certificates:
                    cert_bytes = c.public_bytes(Encoding.DER)
                    cert_b64url = base64_encode_urlsafe(cert_bytes).decode("ascii")
                    self.x5c.append(cert_b64url)

        if not self.kid:
            self.kid = self.get_extra().get("x5t#S256", self.x5t)

    def is_private_key(self) -> bool:
        return self.private_key is not None

    def to_public_key(self) -> "ParsedJwk[PUB, PVK]":
        if not self.private_key:
            return self

        return type(self)(self.public_key, None, jwk=self)

    @property
    def crypto_family(self) -> CryptoFamily:
        raise NotImplementedError()

    @staticmethod
    def parse(jwk: Jwk) -> "ParsedJwk":
        if isinstance(jwk, ParsedJwk):
            return typing.cast(ParsedJwk, jwk)

        kty = jwk.kty
        try:
            family = CRYPTO_FAMILIES[kty]
        except KeyError:
            raise ValueError(f"Unsupported key type: {kty}")

        alg = jwk.alg
        if alg is None:
            alg = next(a for a in family.algorithms)

        if alg not in family.algorithms:
            raise ValueError(f"Unsupported algorithm for '{kty}' key type: {alg}")

        return family.prepare_key(alg, jwk)

    @staticmethod
    def load(
        data: Union[str, bytes],
        password: Optional[Union[str, bytes]] = None,
        kid: Optional[str] = None,
    ) -> "ParsedJwk":
        from minaombud.crypto.jwkset import JwkSet

        return ParsedJwk._from_jwks(JwkSet.load(data, password), kid)

    @staticmethod
    def from_pem(
        pem: Union[str, bytes],
        password: Optional[Union[str, bytes]] = None,
        kid: Optional[str] = None,
    ) -> "ParsedJwk":
        from minaombud.crypto.jwkset import JwkSet

        return ParsedJwk._from_jwks(JwkSet.from_pem(pem, password), kid)

    @staticmethod
    def from_pkcs12(
        data: bytes,
        password: Optional[Union[str, bytes]] = None,
        kid: Optional[str] = None,
    ) -> "ParsedJwk":
        from minaombud.crypto.jwkset import JwkSet

        return ParsedJwk._from_jwks(JwkSet.from_pkcs12(data, password), kid)

    @staticmethod
    def from_json(data: Union[str, bytes], kid: Optional[str] = None) -> "ParsedJwk":
        from minaombud.crypto.jwkset import JwkSet

        return ParsedJwk._from_jwks(JwkSet.from_json(data), kid)

    @staticmethod
    def from_file(
        path: Union[str, bytes],
        password: Optional[Union[str, bytes]] = None,
        kid: Optional[str] = None,
    ) -> "ParsedJwk":
        from minaombud.crypto.jwkset import JwkSet

        return ParsedJwk._from_jwks(JwkSet.from_file(path, password), kid)

    @staticmethod
    def _from_jwks(jwks, kid: Optional[str] = None):
        n = len(jwks)
        if n > 1:
            raise ValueError("Key Set contains multiple keys")
        elif not n:
            raise ValueError("Key Set is empty")

        key = next(iter(jwks.all_keys))
        if kid:
            key.kid = kid
        return key
