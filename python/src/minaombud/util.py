import base64
from typing import Union, Optional


def base64_decode_urlsafe(b: Union[str, bytes]) -> bytes:
    if isinstance(b, str):
        b = b.encode("ascii")
    missing_padding = len(b) % 4
    if missing_padding and not b.endswith(b"="):
        b += b"=" * (4 - missing_padding)
    return base64.urlsafe_b64decode(b)


def base64_encode_urlsafe(b: bytes, padding=False) -> bytes:
    encoded = base64.urlsafe_b64encode(b)
    return encoded if padding else encoded.rstrip(b"=")


def ensure_string(s: Optional[Union[str, bytes]], encoding="utf-8") -> Optional[str]:
    if isinstance(s, bytes):
        return s.decode(encoding)
    return s


def ensure_bytes(s: Optional[Union[str, bytes]], encoding="utf-8") -> Optional[bytes]:
    if isinstance(s, str):
        return s.encode(encoding)
    return s
