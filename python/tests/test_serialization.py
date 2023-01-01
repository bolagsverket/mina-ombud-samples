from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from enum import Enum
from typing import Optional, Dict, Collection
from uuid import UUID

from minaombud.serialization import camel_case, encode_json, JSONClass


def test_camelcase():
    assert camel_case("_") == "_"
    assert camel_case("_x") == "_x"
    assert camel_case("x") == "x"
    assert camel_case("xx") == "xx"
    assert camel_case("x_") == "x_"
    assert camel_case("X_") == "X_"
    assert camel_case("a_bb_ccc") == "aBbCcc"
    assert camel_case("A_bB_CCc") == "ABB_CCc"


class TestEncodeJson:
    def test_datetime(self):
        iso = '2022-11-12T13:14:15.123456Z'
        dt = datetime.fromisoformat(iso.replace("Z", ""))
        assert encode_json(dt) == iso

    def test_uuid(self):
        uuid = UUID("urn:uuid:ca2ab3e6-2383-43dd-8a39-785c599899b2")
        assert encode_json(uuid) == "ca2ab3e6-2383-43dd-8a39-785c599899b2"

    def test_enum(self):
        class FooBarBazEnum(Enum):
            FOO = 'foo'
            BAR = 1
            BAZ = {"a": "b"}

        for e in FooBarBazEnum:
            assert encode_json(e) == e.value

    def test_decimal(self):
        assert encode_json(Decimal("1.3")) == "1.3"

    def test_bytes(self):
        assert encode_json(b"ABC") == "QUJD"
        assert encode_json(b"ABC" * 27) == "QUJD" * 27

    def test_bytearray(self):
        assert encode_json(bytearray(b"ABC")) == "QUJD"
        assert encode_json(bytearray(b"ABC" * 27)) == "QUJD" * 27

    def test_dataclass(self):
        @dataclass
        class Dc:
            i: int
            d: Optional[dict] = None
            dc: Optional["Dc"] = None

        dc = Dc(i=1, d={"x": Dc(i=2, dc=Dc(i=3))})
        expected = {
            "i": 1,
            "d": {
                "x": {
                    "i": 2,
                    "d": None,
                    "dc": {
                        "i": 3,
                        "d": None,
                        "dc": None
                    }
                }
            },
            "dc": None
        }
        assert encode_json(dc) == expected


@dataclass
class DcJson(JSONClass):
    i: int
    d: Optional[Dict[str, "DcJson"]] = None
    dc: Optional["DcJson"] = None
    l: Optional[Collection["DcJson"]] = None


class TestJSONClass:

    def test_decode(self):
        expected = {
            "i": 1,
            "d": {
                "x": {
                    "i": 2,
                    "dc": {
                        "i": 3
                    }
                }
            },
            "l": [
                {
                    "i": 4,
                    "dc": {
                        "i": 5
                    }
                }
            ],
            "_sig": "xyz"
        }
        o = DcJson.from_dict(expected)
        assert o.to_dict() == expected

    def test_skip_none(self):
        dc = DcJson(i=1, d={"x": DcJson(i=2, dc=DcJson(i=3))})
        expected = {
            "i": 1,
            "d": {
                "x": {
                    "i": 2,
                    "dc": {
                        "i": 3
                    }
                }
            }
        }
        assert encode_json(dc) == expected

    def test_no_skip_none(self):
        dc = DcJson(i=1, d={"x": DcJson(i=2, dc=DcJson(i=3))})
        expected = {
            "i": 1,
            "d": {
                "x": {
                    "i": 2,
                    "d": None,
                    "dc": {
                        "i": 3,
                        "d": None,
                        "dc": None,
                        "l": None
                    },
                    "l": None
                }
            },
            "dc": None,
            "l": None
        }
        assert encode_json(dc, skip_none=False) == expected
