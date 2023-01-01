import json
from dataclasses import dataclass
from typing import Optional, List, Union, Mapping, Any

from minaombud.crypto.family import CRYPTO_FAMILIES
from minaombud.crypto.jwk import Jwk
from minaombud.crypto.jwkset import JwkSet
from minaombud.crypto.key import ParsedJwk
from minaombud.model import JwsSig
from minaombud.serialization import IdentityCaseJSONClass, encode_json, canonical_dumps
from minaombud.util import base64_encode_urlsafe, base64_decode_urlsafe


@dataclass
class JOSEHeader(IdentityCaseJSONClass):
    alg: str
    kid: str
    jku: Optional[str] = None
    jwk: Optional[Jwk] = None
    x5u: Optional[str] = None
    x5c: Optional[List[bytes]] = None
    x5t: Optional[str] = None
    # Retrieve with: get_extra()['x5t#S256']
    # 'x5t#S256': Optional[str] = None
    typ: Optional[str] = None
    cty: Optional[str] = None
    crit: Optional[List[str]] = None

    b64: Optional[str] = None

    def __post_init__(self):
        if self.b64 is not None:
            raise ValueError("b64 parameter must not be set")

    def get_base64(self) -> Union[str, bytes]:
        if self.b64:
            return self.b64

        data = self.to_json(canonical=True)
        return base64_encode_urlsafe(data.encode("utf-8"))

    def get_base64_string(self) -> str:
        b64 = self.get_base64()
        return b64.decode("ascii") if isinstance(b64, bytes) else b64

    def get_base64_bytes(self) -> bytes:
        b64 = self.get_base64()
        return b64.encode("ascii") if isinstance(b64, str) else b64

    @staticmethod
    def from_base64(b64: Union[str, bytes]):
        data = base64_decode_urlsafe(b64)
        hdr = JOSEHeader.from_json(data)
        hdr.b64 = b64 if isinstance(b64, str) else b64.decode("ascii")
        return hdr


def _verify_jws(
    header: Union[str, JOSEHeader],
    payload: Union[str, bytes],
    signature: Union[str, bytes],
    jwk: Jwk,
) -> bool:
    """Verify a JSON Web Signature with provided key.

    Args:
        header: JOSE header in base64url-encoded or parsed format.
        payload: Base64url-encoded payload.
        signature: Base64url-encoded signature.
        jwk: The key used to verify the signature.

    Returns:
        True if the signature is valid
    """
    jwk = ParsedJwk.parse(jwk)
    crypto_family = jwk.crypto_family

    jose_header = JOSEHeader.from_base64(header) if isinstance(header, str) else header
    alg = jose_header.alg
    if alg is None:
        alg = jwk.alg
    elif alg not in crypto_family.algorithms:
        raise ValueError(f"{alg} is not a valid algorithm for {jwk.kty} keys")

    if jose_header.kid is not None and jose_header.kid != jwk.kid:
        raise ValueError(f"Key ID {jose_header.kid} does not match key {jwk.kid}")

    if isinstance(payload, str):
        payload = payload.encode("ascii")

    if isinstance(signature, str):
        signature = signature.encode("ascii")

    data = jose_header.get_base64_bytes() + b"." + payload
    sigdata = base64_decode_urlsafe(signature)
    return crypto_family.verify(sigdata, data, alg, jwk)


def verify_jws(
    payload: Union[str, bytes], signature: JwsSig, jwks: Mapping[str, Jwk]
) -> bool:
    """Verify a JSON Web Signature with key lookup.

    Keys are looked up based in the JOSE header.

    Args:
        payload: Base64url-encoded detached payload.
        signature: Detached signature.
        jwks: Key provider.

    Returns:
          True if signature is valid.
    """
    header = JOSEHeader.from_base64(signature.protected)
    jwk = jwks[header.kid]
    return _verify_jws(header, payload, signature.signature, jwk)


def verify_embedded_jws(obj, jwks: Mapping[str, Jwk]) -> bool:
    """Verify an embedded JSON Web Signature.

    Keys are looked up based in the JOSE header.

    Args:
        obj: JSON data, JSON object (dict) or JSON-serializable object.
        jwks: Key provider.

    Returns:
          True if signature is valid.
    """

    if isinstance(obj, str):
        obj = json.loads(obj)

    sig: Union[JwsSig, Mapping[str, str]]
    if isinstance(obj, Mapping):
        sig = obj["_sig"]
    else:
        sig = getattr(obj, "_sig")

    if isinstance(sig, Mapping):
        sig = JwsSig.from_dict(sig)

    kvs = encode_json(obj)
    del kvs["_sig"]
    json_payload = canonical_dumps(kvs)
    payload = base64_encode_urlsafe(json_payload.encode("utf-8"))
    return verify_jws(payload, sig, jwks)


def sign_bytes(
    payload: Any,
    key: Union[Jwk, JwkSet],
    header: Optional[JOSEHeader] = None,
    encoding: Optional[str] = None,
) -> bytes:
    if isinstance(payload, str):
        if encoding:
            payload = base64_encode_urlsafe(payload.encode(encoding))
        else:
            payload = payload.encode("ascii")
    elif not isinstance(payload, bytes):
        payload = encode_json(payload)
        payload = canonical_dumps(payload)
        payload = base64_encode_urlsafe(payload.encode(encoding or "utf-8"))

    if isinstance(key, JwkSet):
        key_set = key
        try:
            if header:
                jwk = next(
                    (k for k in key_set.private_keys if header.kid == k.kid), None
                )
                if not jwk:
                    jwk = next(
                        k
                        for k in key_set.private_keys
                        if header.alg in k.crypto_family.algorithms
                    )
            else:
                jwk = next(k for k in key_set.private_keys if k.kty in CRYPTO_FAMILIES)
        except StopIteration:
            raise ValueError("No matching signing keys")
    else:
        jwk = ParsedJwk.parse(key)

    if not header:
        alg = jwk.alg
        if not alg:
            alg = next(iter(jwk.crypto_family.algorithms))
        header = JOSEHeader(alg=alg, kid=jwk.kid)

    signing_input = header.get_base64_bytes() + b"." + payload
    sig_data = jwk.crypto_family.sign(signing_input, header.alg, jwk)
    return signing_input + b"." + base64_encode_urlsafe(sig_data)


def sign(
    payload: Any,
    key: Union[Jwk, JwkSet],
    header: Optional[JOSEHeader] = None,
    encoding: Optional[str] = None,
) -> str:
    return sign_bytes(payload, key, header, encoding).decode("ascii")
