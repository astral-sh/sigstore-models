from __future__ import annotations

import base64
import typing as t

import typing_extensions as te
from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer
from pydantic.alias_generators import to_camel


class Base(BaseModel):
    model_config = ConfigDict(
        alias_generator=to_camel,
        strict=True,
        extra="forbid",
        validate_by_name=True,
        validate_by_alias=True,
    )

    @classmethod
    def from_json(cls, json: str | bytes) -> te.Self:
        return cls.model_validate_json(json)

    @classmethod
    def from_dict(cls, data: dict) -> te.Self:
        return cls.model_validate(data)

    def to_json(self) -> str:
        return self.model_dump_json(
            exclude_none=True,
            exclude_unset=True,
            by_alias=True,
        )

    def to_dict(self) -> dict:
        return self.model_dump(
            mode="json", exclude_none=True, exclude_unset=True, by_alias=True
        )


def _validate_proto_u64(value: object) -> int:
    if not isinstance(value, str):
        raise ValueError(
            f"Expected protobuf uint64 as string, got {type(value).__name__}"
        )

    n = int(value)
    if n < 0 or n > 2**64 - 1:
        raise ValueError(f"Value exceeds uint64 domain: {value}")

    return n


def _serialize_proto_u64(value: int) -> str:
    if value < 0 or value > 2**64 - 1:
        raise ValueError(f"Value exceeds uint64 domain: {value}")

    return str(value)


ProtoU64 = t.Annotated[
    int,
    BeforeValidator(_validate_proto_u64),
    PlainSerializer(_serialize_proto_u64, return_type=str),
]


def _validate_proto_bytes(value: object) -> bytes:
    if not isinstance(value, (bytes, str)):
        raise ValueError(
            f"Expected protobuf bytes as string or bytes, got {type(value).__name__}"
        )

    return base64.b64decode(value)


def _serialize_proto_bytes(value: bytes) -> bytes:
    return base64.b64encode(value)


ProtoBytes = t.Annotated[
    bytes,
    BeforeValidator(_validate_proto_bytes),
    PlainSerializer(_serialize_proto_bytes, return_type=bytes),
]
