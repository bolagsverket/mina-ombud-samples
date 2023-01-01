import hashlib
from typing import Any, Optional, Union, Mapping, Dict

from minaombud.serialization import canonical_dumps
from minaombud.util import base64_decode_urlsafe, base64_encode_urlsafe


def base64_decode_uint(b: Union[str, bytes]) -> int:
    data = base64_decode_urlsafe(b)
    return int.from_bytes(data, byteorder="big")


def base64_encode_uint(i: int) -> str:
    nb = (i.bit_length() + 7) // 8
    b = i.to_bytes(nb, byteorder="big")
    return base64_encode_urlsafe(b).decode("ascii")


def compute_thumbprint(
    params: Optional[Mapping[str, Any]] = None, alg="sha256", **kwargs
):
    obj: Dict[str, Any] = {}
    if params:
        obj.update(params)
    obj.update(kwargs)
    data = canonical_dumps(obj).encode("utf-8")
    m = hashlib.sha256() if alg == "sha256" else hashlib.new(alg)
    m.update(data)
    return base64_encode_urlsafe(m.digest()).decode("ascii")
