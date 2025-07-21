import typing as t

from sigstore_models._core import Base, ProtoBytes


class Envelope(Base):
    payload: ProtoBytes
    payload_type: str
    signatures: list["Signature"]


class Signature(Base):
    sig: ProtoBytes
    keyid: t.Optional[str] = None
