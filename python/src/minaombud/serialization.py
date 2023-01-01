"""Module with support for encoding/decoding dataclasses as JSON.

This module is only meant to make the sample code free from third party dependencies.

There are plenty of options out there, for example marshmallow, as well as options
for validating against and generating from schemas. Choose whatever suits your environment.

By default, fields are serialized to/from camel case and fields that are `None` are not
included in the serialized form.

Fields typed :class:`bytes` or :class:`bytearray` are Base64 encoded.

>>> from dataclasses import dataclass
>>> from typing import Optional
>>> @dataclass
>>> class MyModel(JSONClass):
>>>     foo_bar: Optional[str]  # serialized as fooBar if not None
>>> model = MyModel(foo_bar="baz")
>>> model.to_json()
'{"fooBar": "baz"}'
"""
import abc
import base64
import copy
import dataclasses
import inspect
import json
import re
import sys
import typing
from datetime import datetime, date
from decimal import Decimal
from enum import Enum
from typing import (
    Any,
    Collection,
    Dict,
    Mapping,
    Optional,
    Type,
    TypeVar,
    Union,
    get_type_hints,
)
from uuid import UUID

from minaombud.util import base64_decode_urlsafe

A = TypeVar("A", bound="JSONClass")
T = TypeVar("T")


def identity_case(k: str) -> str:
    return k


def camel_case(k: str) -> str:
    prefix = k[:1]
    tail = k[1:]
    camel = re.sub(r"_([a-z])", lambda m: m.group(1).upper(), tail)
    return prefix + camel


class Case(Enum):
    IDENTITY = staticmethod(identity_case)
    CAMEL = staticmethod(camel_case)


def canonical_dumps(v) -> str:
    return json.dumps(
        v, separators=(",", ":"), sort_keys=True, ensure_ascii=False, allow_nan=False
    )


def asdict(obj, skip_none: Optional[bool] = None, encode=False) -> Any:
    """Convert an object to a dictionary including nested objects.

    Nest
    In addition to collection types, `dataclasses` and :class:`JSONClass`
    objects are converted to their :class:`dict` representation.

    :class:`datetime` is ISO formatted.

    :class:`UUID` and :class:`Decimal` are string formatted.

    :class:`Enum` types are converted to their encoded value.

    :class:`bytes` and :class:`bytearray` are Base 64-encoded to an ASCII string.

    :class:`Mapping`, :class:`JSONClass` and :class:`dataclass` are converted to
    their dict representation.

    :class:`Collection` are converted to their :class:`list` or :class:`tuple`
    representation.

    Args:
        skip_none:  `True/False` to force including/excluding `None`-valued fields.
                    If set to None, the default behavior decided per class is used.
        encode:     `True` converts values to JSON-compatible types.

    Returns:
        A deep copy of the object as a dictionary.
    """

    def apply(o):
        if isinstance(o, JSONClass):
            return o.to_dict(skip_none=skip_none, encode=encode)
        elif dataclasses.is_dataclass(o):
            pairs = []
            for f in dataclasses.fields(o):
                v = getattr(o, f.name)
                if v is not None or not skip_none:
                    pairs.append((f.name, apply(v)))
            return dict(pairs)
        elif isinstance(o, (tuple, list)):
            return type(o)(apply(v) for v in o)
        elif isinstance(o, str):
            return o
        elif isinstance(o, bytes):
            return base64.standard_b64encode(o).decode("ascii") if encode else o
        elif isinstance(o, bytearray):
            return base64.standard_b64encode(bytes(o)).decode("ascii") if encode else o
        elif isinstance(o, Mapping):
            return dict(
                (k, apply(v)) for k, v in o.items() if v is not None or not skip_none
            )
        elif isinstance(o, Collection):
            return list(apply(v) for v in o)
        elif encode:
            if isinstance(o, datetime):
                iso = o.isoformat()
                if o.tzinfo or iso.endswith("Z") or "+" in iso:
                    return iso
                return iso + "Z"
            elif isinstance(o, date):
                return o.isoformat()
            elif isinstance(o, UUID):
                return str(o)
            elif isinstance(o, Enum):
                return asdict(o.value)
            elif isinstance(o, Decimal):
                return str(o)
            elif isinstance(o, Enum):
                return apply(o.value)

        return copy.deepcopy(o)

    return apply(obj)


def encode_json(o, skip_none=None):
    return asdict(o, skip_none=skip_none, encode=True)


class JSONClass(abc.ABC):
    """JSON serializable class.

    Can be used as base class for a `dataclass` in which case it
    uses the dataclass fields.

    It can be also used as a base class for other classes in which
    case it serializes the object attributes.
    """

    CASE = Case.CAMEL
    SKIP_NULL_FIELDS: Optional[bool] = True

    _unknown: Optional[Dict[str, Any]] = None

    def get_extra(self) -> Dict[str, Any]:
        unknown = self._unknown
        if unknown is None:
            unknown = {}
            self._unknown = unknown
        return unknown

    def to_json(
        self, *, canonical: bool = False, indent: Optional[Union[int, str]] = None
    ) -> str:
        """Serialize object to a JSON formatted :class:`str`.

        See RFC 8785 https://www.rfc-editor.org/rfc/rfc8785.html for
        a description of canonical JSON.

        Args:
            canonical: Canonicalize JSON according to RFC 8785.
            indent: See json.dumps.

        Returns:
            JSON string.
        """
        data = self.to_dict(encode=True)
        if canonical:
            return canonical_dumps(data)
        else:
            return json.dumps(data, ensure_ascii=False, allow_nan=False, indent=indent)

    @classmethod
    def from_json(cls: Type[A], s: Union[str, bytes]) -> A:
        """Deserialize object from JSON.

        Args:
            s: JSON string.
        Returns:
             Decoded class instance.
        """
        json_data = json.loads(s)
        if not isinstance(json_data, dict):
            raise TypeError(f"Not a JSON object: {type(json_data)}")
        return cls.from_dict(json_data)

    @classmethod
    def from_dict(cls: Type[A], o: Mapping[str, Any]) -> A:
        """Construct object from a JSON object.

        Args:
            o: A dictionary with string keys.
        Returns:
             Decoded class instance.
        """
        if dataclasses.is_dataclass(cls):
            return _dataclass_from_dict(cls, o)
        return _json_class_from_dict(cls, o)

    def to_dict(self, skip_none: Optional[bool] = None, encode=False) -> Dict[str, Any]:
        """Converts the object to a dict.

        The conversion is recursive and the returned dictionary
        contains a deep copy of all attributes.

        Returns:
              A dictionary containing a deep copy of the objects fields.
        """
        kvs: Dict[str, Any]
        do_skip_none = self.SKIP_NULL_FIELDS if skip_none is None else skip_none
        convert_case = type(self).CASE
        if dataclasses.is_dataclass(self):
            pairs = []
            for f in dataclasses.fields(self):
                v = getattr(self, f.name)
                if not do_skip_none or v is not None:
                    k = convert_case(f.name)
                    pairs.append((k, v))

            kvs = dict(pairs)
        else:
            if self._unknown or do_skip_none or convert_case is not identity_case:
                pairs = []
                for k, v in self.__dict__.items():
                    if not do_skip_none or v is not None:
                        k = convert_case(k)
                        pairs.append((k, v))
                kvs = dict(pairs)
            else:
                kvs = self.__dict__

        if self._unknown:
            kvs.update(self._unknown)

        return asdict(kvs, skip_none=skip_none, encode=encode)


class IdentityCaseJSONClass(JSONClass):
    CASE = Case.IDENTITY


try:
    _get_type_args = typing.get_args
except AttributeError:

    def _get_type_args(tp):
        try:
            return tp.__args__
        except AttributeError:
            return ()


try:
    _get_type_origin = typing.get_origin
except AttributeError:

    def _get_type_origin(tp):
        try:
            return tp.__origin__
        except AttributeError:
            if tp is typing.Generic:
                return typing.Generic
            if sys.version_info.minor == 6 and hasattr(tp, "__extra__"):
                return tp.__extra__
            return None


def _dataclass_from_dict(cls: Type[T], o: Mapping[str, Any]) -> T:
    if isinstance(o, cls):
        return o

    if not isinstance(o, Mapping):
        raise TypeError(f"Cannot decode {cls.__name__} from {type(o)}")

    types_per_field = get_type_hints(cls)
    fields = dataclasses.fields(cls)
    used_keys = set()
    kwargs = {}
    non_init = {}
    convert_case = cls.CASE if hasattr(cls, "CASE") else identity_case
    for f in fields:
        k = convert_case(f.name)
        if k in o:
            used_keys.add(k)
            v = o[k]
            t = types_per_field[f.name]
            ut = _type_union(t)
            fv = _convert_field(cls, f, ut, v)
            if f.init:
                kwargs[f.name] = fv
            else:
                non_init[f.name] = fv

    instance = cls(**kwargs)
    for k, v in non_init.items():
        setattr(instance, k, v)

    if len(used_keys) != len(o) and isinstance(instance, JSONClass):
        unknown = instance.get_extra()
        for k, v in o.items():
            if k not in used_keys:
                unknown[k] = v

    return instance


def _json_class_from_dict(cls: Type[A], o: Mapping[str, Any]) -> A:
    if not isinstance(o, Mapping):
        raise TypeError(f"Cannot decode {cls.__name__} from {type(o)}")

    instance = cls()
    slots = cls.__slots__
    if slots and len(slots):
        convert_case = cls.CASE
        for f in slots:
            k = convert_case(f)
            if k in o:
                setattr(instance, f, o[k])
    else:
        for k, v in o.items():
            setattr(instance, k, v)

    return instance


def _type_union(t):
    if _get_type_origin(t) is Union:
        return t.__args__
    return (t,)


def _dict_constructor(t):
    cons = _get_type_origin(t) or t
    return dict if inspect.isabstract(cons) else cons


def _collection_constructor(t):
    cons = _get_type_origin(t) or t
    if inspect.isabstract(cons):
        if _issubclass(t, typing.Tuple):
            return tuple
        elif _issubclass(t, typing.Set):
            return set
        return list
    return cons


def _issubclass(t, types):
    try:
        return issubclass(t, types)
    except TypeError:
        return False


def _convert_field(cls, f: dataclasses.Field, types, o):
    if type(o) in types:
        return o
    elif isinstance(o, (str, bytes, bytearray)):
        return _decode_scalar(o, types, cls, f)
    elif isinstance(o, Mapping):
        for t in types:
            if dataclasses.is_dataclass(t):
                return _dataclass_from_dict(t, o)
            elif _issubclass(t, JSONClass):
                return _json_class_from_dict(t, o)
            elif _issubclass(_get_type_origin(t) or t, Mapping):
                return _convert_dict(o, t, cls, f)
    elif isinstance(o, Collection):
        for t in types:
            if (
                _issubclass(_get_type_origin(t) or t, Collection)
                and not _issubclass(t, (str, bytes, bytearray))
                and not _issubclass(_get_type_origin(t), Mapping)
            ):
                return _convert_collection(o, t, cls, f)

    return _decode_scalar(o, types, cls, f)


def _convert_dict(
    o: Mapping, t: Type[Mapping], cls=None, f: Optional[dataclasses.Field] = None
):
    kt, vt = _get_type_args(t) or (Any, Any)
    cons = _dict_constructor(t)
    if dataclasses.is_dataclass(vt):
        return cons((k, _dataclass_from_dict(vt, v)) for k, v in o.items())
    elif issubclass(vt, JSONClass) and (kt is Any or issubclass(kt, str)):
        return cons((k, _json_class_from_dict(vt, v)) for k, v in o.items())
    else:
        pairs = []
        kt = (kt,)
        vt = (vt,)
        ks = f"key of {cls.__name__}"
        vs = f"value of {cls.__name__}"
        for k, v in o.items():
            kv = _decode_scalar(k, kt, cls=ks, f=f)
            vv = _decode_scalar(v, vt, cls=vs, f=f)
            pairs.append((kv, vv))
        return cons(pairs)


def _convert_collection(
    o: Collection, t: Type[Collection], cls=None, f: Optional[dataclasses.Field] = None
):
    (vt,) = _get_type_args(t) or (Any,)
    cons = _collection_constructor(t)
    if dataclasses.is_dataclass(vt):
        return cons(_dataclass_from_dict(vt, v) for v in o)
    elif _issubclass(vt, JSONClass):
        return cons(_json_class_from_dict(vt, v) for v in o)
    else:
        vt = (vt,)
        return cons(_decode_scalar(v, vt, cls=cls, f=f, i=i) for i, v in enumerate(o))


def _decode_scalar(o, types, cls=None, f=None, i=None):
    if type(o) in types:
        return o

    for t in types:
        if t is int and isinstance(o, (float, Decimal)) and int(o) == o:
            return int(o)
        elif issubclass(t, Enum):
            for k, e in t.__members__.items():
                if e.value == o:
                    return e
            if isinstance(o, str) and o in t.__members__:
                return t[o]
        elif issubclass(t, UUID) and isinstance(o, str):
            return UUID(o)
        elif issubclass(t, datetime) and isinstance(o, str):
            # datetime only handes microsecond precision and not Z
            o = re.sub(r"([.,]\d+)Z?$", lambda m: m.group(1)[:7], o).rstrip("Z")
            return datetime.fromisoformat(o)
        elif issubclass(t, date) and isinstance(o, str):
            return date.fromisoformat(o)
        elif issubclass(t, (bytes, bytearray)) and isinstance(o, str):
            b = base64_decode_urlsafe(o)
            if issubclass(t, bytearray):
                b = t(b)
            return b
        elif t is Decimal and isinstance(o, (str, int, float)):
            return Decimal(o)
        elif t is float and isinstance(o, (int, Decimal)) and float(o) == o:
            return float(o)

    if not any(t is Any or isinstance(o, t) for t in types):
        t = types[0] if len(types) == 1 else types
        i = "" if i is None else f"[{i}]"
        cls = getattr(cls, "__name__", cls) if cls else ""
        if f is None:
            f = ""
        if cls and f:
            f = f".{f}"
        raise TypeError(f"Cannot decode {cls}{f}{i} from {o} as {t}")

    return o
