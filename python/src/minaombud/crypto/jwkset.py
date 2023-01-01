import cgi
import json
import os.path
import re
import time
import urllib.parse
from dataclasses import dataclass
from typing import Mapping, Optional, List, Dict, Iterable, Union

import requests
from cryptography.hazmat.primitives._serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import load_pkcs12
from cryptography.x509 import (
    load_pem_x509_certificate,
    Certificate,
    AuthorityKeyIdentifier,
    ExtensionNotFound,
    SubjectKeyIdentifier,
)
from requests import HTTPError

from minaombud.crypto.key import ParsedJwk, Jwk
from minaombud.serialization import IdentityCaseJSONClass
from minaombud.util import ensure_bytes


@dataclass
class _JwkSet(IdentityCaseJSONClass):
    keys: List[Jwk]


class JwkSet(Mapping[str, Jwk]):
    def __init__(self, keys: Optional[Iterable[Jwk]] = None):
        self._keys: Dict[str, ParsedJwk] = {}
        if keys:
            self.add_keys(keys)

    def _get_keys(self, kid: Optional[str] = None) -> Dict[str, ParsedJwk]:
        return self._keys

    def replace_keys(self, keys: Iterable[Jwk]):
        self._keys.clear()
        self.add_keys(keys)

    def add_keys(self, keys: Iterable[Jwk]):
        for k in keys:
            try:
                jwk = ParsedJwk.parse(k)
                self._keys[jwk.kid] = jwk
            except ValueError:
                pass

    def update(self):
        pass

    @property
    def all_keys(self) -> Iterable[ParsedJwk]:
        return self._get_keys().values()

    @property
    def private_keys(self) -> Iterable[ParsedJwk]:
        for k in self.all_keys:
            if k.is_private_key():
                yield k

    @property
    def public_keys(self) -> Iterable[ParsedJwk]:
        for k in self.all_keys:
            try:
                yield k.to_public_key()
            except (ValueError, TypeError):
                pass

    def __bool__(self):
        return len(self._get_keys()) > 0

    def __len__(self):
        return len(self._get_keys())

    def __iter__(self):
        return iter(self._get_keys())

    def __contains__(self, kid):
        return kid in self._get_keys(kid)

    def __getitem__(self, kid: str):
        return self._get_keys(kid)[kid]

    @staticmethod
    def from_dir(path: Union[str, bytes], recursive=False) -> "JwkSet":
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        sets = []
        for f in os.listdir(path):
            full_path = os.path.join(path, f)
            if os.path.isfile(full_path):
                name, ext = os.path.splitext(f)
                ext = ext.lower()
                if ext in (
                    ".p12",
                    ".pfx",
                    ".pem",
                    ".key",
                    ".cer",
                    ".crt",
                    ".jwk",
                    ".jwks",
                    ".json",
                ):
                    try:
                        sets.append(JwkSet.from_file(full_path))
                    except (ValueError, TypeError):
                        pass
            elif recursive and os.path.isdir(full_path):
                sets.append(JwkSet.from_dir(full_path, recursive=True))

        if len(sets) == 1:
            return sets[0]
        else:
            merged = JwkSet()
            for s in sets:
                merged.add_keys(s.all_keys)
            return merged

    @staticmethod
    def from_file(
        path: Union[str, bytes], password: Optional[Union[str, bytes]] = None
    ) -> "JwkSet":
        if isinstance(path, bytes):
            path = path.decode("utf-8")

        name, ext = os.path.splitext(path)
        ext = ext.lower()
        with open(path, "rb") as f:
            data = f.read()
        if ext in (".p12", ".pfx"):
            return JwkSet.from_pkcs12(data, password)
        elif ext in (".jwk", ".jwks", ".json"):
            return JwkSet.from_json(data)
        elif ext == ".pem":
            return JwkSet.from_pem(data, password)

        if data.startswith(b"{") or data.startswith(b"["):
            return JwkSet.from_json(data)
        elif b"-----BEGIN " in data:
            return JwkSet.from_pem(data, password)

        raise ValueError(f"Unsupported file format: {path}")

    @staticmethod
    def load(
        k: Union[str, bytes, Iterable[Union[str, bytes]]],
        password: Optional[Union[bytes, str]] = None,
    ) -> "JwkSet":
        if not isinstance(k, (str, bytes)):
            sets = [JwkSet.load(s, password=password) for s in k]
            if len(sets) == 1:
                return sets[0]
            else:
                merged = JwkSet()
                for s in sets:
                    merged.add_keys(s.all_keys)
                return merged

        if isinstance(k, str):
            if k.startswith("http:") or k.startswith("https:"):
                return RemoteJwkSet(k)
            elif k.startswith("file:"):
                if k.startswith("file://"):
                    k = k[7:]
                else:
                    k = k[5:]
                path = urllib.parse.unquote(k)
                if os.path.isdir(path):
                    return JwkSet.from_dir(path)
                else:
                    return JwkSet.from_file(path, password=password)
            elif re.match("(^[{[])|-----BEGIN ", k):
                data = k.encode("utf-8")
            elif os.path.isdir(k):
                return JwkSet.from_dir(k)
            else:
                return JwkSet.from_file(k, password)
        else:
            data = k

        if data.startswith(b"{") or data.startswith(b"["):
            return JwkSet.from_json(data)
        elif b"-----BEGIN " in data:
            return JwkSet.from_pem(data, password)

        raise ValueError("Unsupported key")

    @staticmethod
    def from_json(data: Union[bytes, str]) -> "JwkSet":
        parsed = json.loads(data)
        if isinstance(parsed, list):
            return JwkSet(keys=(Jwk.from_dict(jwk) for jwk in parsed))
        if len(parsed) == 1 and isinstance(parsed.get("keys"), list):
            return JwkSet(keys=_JwkSet.from_dict(parsed).keys)
        else:
            return JwkSet(keys=[Jwk.from_dict(parsed)])

    @staticmethod
    def from_pem(
        data: Union[bytes, str], password: Optional[Union[bytes, str]] = None
    ) -> "JwkSet":
        if isinstance(data, bytes):
            pemstr = data.decode("utf-8")
        else:
            pemstr = data

        passbytes = ensure_bytes(password)
        pattern = re.compile(
            r"-----BEGIN (.+)-----(\r?\n)[A-Za-z0-9+/\r\n]+=*(\r?\n)-----END \1-----"
        )
        objects = [(m[1], m[0].encode("ascii")) for m in pattern.finditer(pemstr)]

        if len(objects) >= 2:
            if objects[0][0].endswith("PRIVATE KEY") and all(
                k.endswith("CERTIFICATE") for k, v in objects[1:]
            ):
                # Private key and certificate chain
                private_key = load_pem_private_key(objects[0][1], passbytes)
                certs = [load_pem_x509_certificate(v) for k, v in objects[1:]]
                if not _is_certificate_chain(certs):
                    raise ValueError("PEM does not contain a valid certificate chain")
                if not _same_public_key(
                    private_key.public_key(), certs[0].public_key()
                ):
                    raise ValueError(
                        "PEM private key and certificate chain are not related"
                    )
                return JwkSet(keys=[_from_private_key(private_key, certificates=certs)])

        if all(o[0].endswith("CERTIFICATE") for o in objects):
            certs = [load_pem_x509_certificate(o[1]) for o in objects]
            if _is_certificate_chain(certs):
                jwk = _from_public_key(certs[0].public_key(), certs)
                return JwkSet([jwk])

            reversed_certs = list(certs)
            reversed_certs.reverse()
            if _is_certificate_chain(reversed_certs):
                jwk = _from_public_key(reversed_certs[0].public_key(), reversed_certs)
                return JwkSet([jwk])

            return JwkSet(keys=[_from_public_key(c.public_key(), [c]) for c in certs])

        keys = []
        for o in objects:
            marker, pem = o
            if marker.endswith("CERTIFICATE"):
                cert = load_pem_x509_certificate(pem)
                jwk = _from_public_key(cert.public_key(), certificates=[cert])
            elif marker.endswith("PRIVATE KEY"):
                jwk = _from_private_key(load_pem_private_key(pem, passbytes))
            elif marker.endswith("PUBLIC KEY"):
                jwk = _from_public_key(load_pem_public_key(pem))
            else:
                raise ValueError(f"Unsupported PEM object: {marker}")
            keys.append(jwk)

        if len(keys) == 2:
            keys = _merge_key_pair(keys[0], keys[1])

        return JwkSet(keys=keys)

    @staticmethod
    def from_pkcs12(
        data: bytes, password: Optional[Union[str, bytes]] = None
    ) -> "JwkSet":
        keystore = load_pkcs12(data, ensure_bytes(password))
        if keystore.cert:
            cert = keystore.cert.certificate
            kid = None  # keystore.cert.friendly_name
            certificates = [cert]
            certificates.extend(c.certificate for c in keystore.additional_certs)
        else:
            cert = None
            certificates = None
            kid = None

        key = keystore.key
        if key:
            return JwkSet(
                keys=[_from_private_key(key, certificates=certificates, kid=kid)]
            )
        elif cert:
            return JwkSet(
                keys=[
                    _from_public_key(
                        cert.public_key(), certificates=certificates, kid=kid
                    )
                ]
            )

        raise ValueError("PKCS#12 contains no keys or certificates")


def _same_public_key(k1: PUBLIC_KEY_TYPES, k2: PUBLIC_KEY_TYPES):
    if type(k1) != type(k2):
        return False
    b1 = k1.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    b2 = k2.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return b1 == b2


class RemoteJwkSet(JwkSet):
    """JWK Set fetching from a remote URL.

    The JWK Set is updated when an unknown key is requested
    or manually by calling the `update` method.
    """

    def __init__(
        self,
        url: str,
        session: Optional[requests.Session] = None,
        update_every=0.0,
        throttle=5.0 * 60,
        keys: Optional[List[Jwk]] = None,
    ):
        """Create RemoteJwkSet.

        Args:
            url:        Fetch keys from this URL.
            session:    A session to use for all requests (default will allocate a session
                        for this JWK Set).
            keys:       Initial set of keys.
            update_every: Attempt to refresh keys at this interval even if no new key is requested (seconds).
                        This feature is disabled if <= 0.
            throttle:   Don't refresh keys more frequently than this (seconds).
                        Throttling is disabled if <= 0.
        """
        super(RemoteJwkSet, self).__init__(keys)
        self.url = url
        if session:
            self.session = session
        else:
            self.session = requests.Session()
        self.update_every = update_every
        self.throttle = throttle
        self._last_update: Optional[float] = None

    def _get_keys(self, kid: Optional[str] = None):
        update = (not self._keys and self._last_update is None) or (
            kid and kid not in self._keys
        )
        if update or self.update_every > 0:
            now = time.monotonic()
            update = update or now - self._last_update >= self.update_every
            if update and (
                self._last_update is None or now - self._last_update >= self.throttle
            ):
                self.update()
        return self._keys

    def update(self):
        jwks = self._fetch()
        self.replace_keys(jwks.keys)
        self._last_update = time.monotonic()

    def _fetch(self) -> _JwkSet:
        jwk_set_media_type = "application/jwk-set+json"
        json_media_type = "application/json"
        headers = {"accept": f"{jwk_set_media_type}, {json_media_type}"}
        response = self.session.get(self.url, headers=headers, allow_redirects=False)
        content_type, _ = cgi.parse_header(response.headers.get("content-type", ""))
        if content_type.lower() not in (jwk_set_media_type, json_media_type):
            raise HTTPError(
                f"Invalid content type for JWK Set: {content_type}", response=response
            )

        response.raise_for_status()
        return _JwkSet.from_dict(response.json())


def _from_private_key(
    private_key: PRIVATE_KEY_TYPES,
    certificates: Optional[List[Certificate]] = None,
    kid: Optional[str] = None,
) -> ParsedJwk:
    if isinstance(private_key, RSAPrivateKey):
        from minaombud.crypto.rsa import RSAKey

        return RSAKey.from_private_key(private_key, certificates=certificates, kid=kid)

    raise ValueError(f"Unsupported private key type: {type(private_key)}")


def _from_public_key(
    public_key: PUBLIC_KEY_TYPES,
    certificates: Optional[List[Certificate]] = None,
    kid: Optional[str] = None,
) -> ParsedJwk:
    if isinstance(public_key, RSAPublicKey):
        from minaombud.crypto.rsa import RSAKey

        return RSAKey.from_public_key(public_key, certificates=certificates, kid=kid)
    raise ValueError(f"Unsupported public key type: {type(public_key)}")


def _is_certificate_chain(certs: List[Certificate]) -> bool:
    if not certs:
        return False

    c = certs[0]
    for parent in certs[1:]:
        try:
            akid = c.extensions.get_extension_for_class(
                AuthorityKeyIdentifier
            ).value.key_identifier
        except ExtensionNotFound:
            akid = None
        if akid:
            try:
                skid = parent.extensions.get_extension_for_class(
                    SubjectKeyIdentifier
                ).value.key_identifier
                if akid != skid:
                    return False
            except ExtensionNotFound:
                return False
        elif c.issuer != parent.subject:
            return False
        c = parent
    return True


def _merge_key_pair(k1: ParsedJwk, k2: ParsedJwk) -> List[ParsedJwk]:
    if type(k1) != type(k2) or k1.kty != k2.kty or k1.kid != k2.kid or k1.alg != k2.alg:
        return [k1, k2]

    if k1.is_private_key() and k2.is_private_key():
        k1, k2 = k2, k1

    if not k1.is_private_key() and k2.is_private_key():
        params = k1.to_dict()
        params.update(k2.to_dict())
        cert = k1.certificates or k2.certificates
        not_valid_after = k1.not_valid_after
        not_valid_before = k1.not_valid_before

        merged = type(k1)(
            k1.public_key,
            k2.private_key,
            certificates=cert,
            not_valid_after=not_valid_after,
            not_valid_before=not_valid_before,
            **params,
        )
        return [merged]

    return [k1, k2]
