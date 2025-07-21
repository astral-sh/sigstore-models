import json

import pytest

from sigstore_models._core import Base, ProtoU64


class TestBase:
    """
    Sanity tests for our base model.
    """

    def test_camelcase(self):
        """
        Ensure that the alias generator works as expected.
        """

        class TestModel(Base):
            some_field: str

        instance = TestModel(some_field="test")
        assert instance.to_dict() == {"someField": "test"}

    def test_strict(self):
        """
        Ensure that the strict mode is enforced.
        """

        class TestModel(Base):
            some_field: str

        with pytest.raises(ValueError):
            TestModel(some_field=123)  # type: ignore

    def test_extra_forbid(self):
        """
        Ensure that extra fields are forbidden.
        """

        class TestModel(Base):
            some_field: str

        with pytest.raises(ValueError):
            TestModel(some_field="test", extra_field="should_not_be_allowed")  # type: ignore


class TestU64:
    """
    Sanity tests for our Protobuf uint64 type.
    """

    def test_serde(self):
        """
        Ensure that we can ser/de without losing our int type.
        """

        class Foo(Base):
            value: ProtoU64

        foo = {"value": "12345678901234567890"}

        instance = Foo.from_dict(foo)
        assert instance.value == 12345678901234567890
        assert instance.to_dict() == foo

        instance = Foo.from_json(json.dumps(foo))
        assert instance.value == 12345678901234567890
        assert instance.to_dict() == foo

    @pytest.mark.parametrize(
        "tc",
        (-2, -1, 0, 1, 2, "-1", "-01", "lol", ["lol"], "0xdeadbeef", 2**64, str(2**64)),
    )
    def test_invalid(self, tc: object):
        """
        Ensure that invalid values raise ValueError.

        In particular, ensure that we reject non-string encoded integers,
        non-integer strings, and integers/strings outside the uint64 range.
        """

        class Foo(Base):
            value: ProtoU64

        foo = {"value": tc}

        with pytest.raises(ValueError):
            Foo.from_dict(foo)

        foo_json = json.dumps(foo)

        with pytest.raises(ValueError):
            Foo.from_json(foo_json)
