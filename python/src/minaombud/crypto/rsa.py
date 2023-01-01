import typing
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey,
    RSAPrivateKey,
    rsa_recover_prime_factors,
    RSAPrivateNumbers,
    rsa_crt_dmp1,
    rsa_crt_dmq1,
    rsa_crt_iqmp,
    RSAPublicNumbers,
)
from cryptography.x509 import Certificate

from minaombud.crypto.cryptutil import (
    base64_decode_uint,
    base64_encode_uint,
    compute_thumbprint,
)
from minaombud.crypto.family import CryptoFamily, register_crypto_family
from minaombud.crypto.key import Jwk, ParsedJwk


class RSAKey(ParsedJwk[RSAPublicKey, RSAPrivateKey]):
    def __init__(
        self,
        public_key: RSAPublicKey,
        private_key: Optional[RSAPrivateKey] = None,
        *,
        jwk: Optional[Jwk] = None,
        **kwargs,
    ):
        super(RSAKey, self).__init__(public_key, private_key, jwk=jwk, **kwargs)
        if self.kty != "RSA":
            raise ValueError("Not an RSA KEY")
        if not self.kid:
            self.kid = compute_thumbprint(e=self.e, n=self.n)

    @property
    def crypto_family(self) -> "RSACryptoFamily":
        return RSA_CRYPTO_FAMILY

    @staticmethod
    def from_public_key(
        public_key: RSAPublicKey,
        certificates: Optional[List[Certificate]] = None,
        kid: Optional[str] = None,
    ) -> "RSAKey":
        public_numbers = public_key.public_numbers()
        e = base64_encode_uint(public_numbers.e)
        n = base64_encode_uint(public_numbers.n)
        return RSAKey(
            public_key, kty="RSA", e=e, n=n, kid=kid, certificates=certificates
        )

    @staticmethod
    def from_private_key(
        private_key: RSAPrivateKey,
        *,
        certificates: Optional[List[Certificate]] = None,
        kid: Optional[str] = None,
    ) -> "RSAKey":
        private_numbers = private_key.private_numbers()
        public_numbers = private_numbers.public_numbers
        e = base64_encode_uint(public_numbers.e)
        n = base64_encode_uint(public_numbers.n)
        d = base64_encode_uint(private_numbers.d)
        p = base64_encode_uint(private_numbers.p)
        q = base64_encode_uint(private_numbers.q)
        dp = base64_encode_uint(private_numbers.dmp1)
        dq = base64_encode_uint(private_numbers.dmq1)
        qi = base64_encode_uint(private_numbers.iqmp)

        return RSAKey(
            private_key.public_key(),
            private_key,
            kty="RSA",
            e=e,
            n=n,
            d=d,
            p=p,
            q=q,
            dp=dp,
            dq=dq,
            qi=qi,
            kid=kid,
            certificates=certificates,
        )


class RSACryptoFamily(CryptoFamily[RSAKey]):
    SHA256 = hashes.SHA256
    SHA384 = hashes.SHA384
    SHA512 = hashes.SHA512

    HASH_ALGORITHMS = {"RS256": SHA256, "RS384": SHA384, "RS512": SHA512}

    def __init__(self):
        super(RSACryptoFamily, self).__init__(
            kty="RSA", algorithms=sorted(self.HASH_ALGORITHMS.keys())
        )

    def prepare_key(self, alg: str, key: Jwk) -> RSAKey:
        if isinstance(key, RSAKey):
            return typing.cast(RSAKey, key)

        if any(p not in key for p in ("n", "e")):
            raise ValueError(
                f"RSA key {key.kid} is missing required public key parameters"
            )

        assert key.e is not None
        assert key.n is not None

        e = base64_decode_uint(key.e)
        n = base64_decode_uint(key.n)
        pub = RSAPublicNumbers(e, n)
        prv = None

        if key.d:
            # This is a private key
            if key.oth:
                raise ValueError(f"RSA key {key.kid} uses more than two primes")
            d = base64_decode_uint(key.d)
            optional_pvk_params = ("p", "q", "dp", "dq", '"q"i')
            if any(p in key for p in optional_pvk_params):
                if not all(p in key for p in optional_pvk_params):
                    raise ValueError(
                        f"RSA key {key.kid} must include all private key parameters if any are present"
                    )
                prv = RSAPrivateNumbers(
                    d=d,
                    p=base64_decode_uint(key.p),
                    q=base64_decode_uint(key.q),
                    dmp1=base64_decode_uint(key.dp),
                    dmq1=base64_decode_uint(key.dq),
                    iqmp=base64_decode_uint(key.qi),
                    public_numbers=pub,
                )
            else:
                p, q = rsa_recover_prime_factors(pub.n, d, pub.e)
                prv = RSAPrivateNumbers(
                    d=d,
                    p=p,
                    q=q,
                    dmp1=rsa_crt_dmp1(d, p),
                    dmq1=rsa_crt_dmq1(d, q),
                    iqmp=rsa_crt_iqmp(p, q),
                    public_numbers=pub,
                )

        return RSAKey(pub.public_key(), prv.private_key() if prv else None, jwk=key)

    def verify(self, signature: bytes, data: bytes, alg: str, key: RSAKey) -> bool:
        try:
            hash_alg = self.HASH_ALGORITHMS[alg]()
            public_key = key.public_key
            public_key.verify(signature, data, padding.PKCS1v15(), hash_alg)
            return True
        except InvalidSignature:
            return False

    def sign(self, data: bytes, alg: str, key: RSAKey) -> bytes:
        hash_alg = self.HASH_ALGORITHMS[alg]()
        private_key = key.private_key
        if not private_key:
            raise ValueError("Private required for signing")
        return private_key.sign(data, padding.PKCS1v15(), hash_alg)


RSA_CRYPTO_FAMILY = RSACryptoFamily()
register_crypto_family(RSA_CRYPTO_FAMILY)
