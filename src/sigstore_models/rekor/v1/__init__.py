import typing as t

import typing_extensions as te
from pydantic import model_validator

from sigstore_models._core import Base, ProtoBytes, ProtoU64
from sigstore_models.common.v1 import LogId


class KindVersion(Base):
    kind: str
    version: str


class Checkpoint(Base):
    envelope: str


class InclusionProof(Base):
    log_index: ProtoU64
    root_hash: ProtoBytes
    tree_size: ProtoU64
    hashes: list[ProtoBytes]
    checkpoint: t.Optional[Checkpoint] = None

    @model_validator(mode="after")
    def validate_log_index_in_tree_size(self) -> te.Self:
        if self.tree_size <= self.log_index:
            raise ValueError(
                f"logIndex {self.log_index} must be less than treeSize {self.tree_size}"
            )
        return self


class InclusionPromise(Base):
    signed_entry_timestamp: ProtoBytes


class TransparencyLogEntry(Base):
    log_index: ProtoU64
    log_id: LogId
    kind_version: KindVersion
    # NOTE: protobuf-specs claims this is mandatory, but in practice
    # it's optional.
    integrated_time: t.Optional[ProtoU64] = None
    inclusion_promise: t.Optional[InclusionPromise] = None
    inclusion_proof: InclusionProof
    # NOTE: Technically optional in protobuf-specs, but
    # de facto required by sigstore-python.
    canonicalized_body: ProtoBytes
