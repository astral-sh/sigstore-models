"""
Models for `dev.sigstore.bundle.v2` (Sigstore Bundle v2).

NOTE: This module mirrors `sigstore_bundle_v2.proto`, which is currently
unstable in `sigstore/protobuf-specs` and may change in breaking ways.
See https://github.com/sigstore/architecture-docs/blob/main/pqc-design.md.
"""

from typing import Literal, Self

from pydantic import Field, model_validator

from sigstore_models._core import Base, ProtoBytes
from sigstore_models.common.v1 import (
    RFC3161SignedTimestamp,
    X509Certificate,
    X509CertificateChain,
)


class TimestampVerificationData(Base):
    rfc3161_timestamps: list[RFC3161SignedTimestamp] = Field(default_factory=list)


class Signature(Base):
    signature: ProtoBytes


class Payload(Base):
    payload_type: str
    payload: ProtoBytes


class TransparencyLogProof(Base):
    proof: ProtoBytes
    signature: Signature | None = None


class PublicKey(Base):
    timestamps: TimestampVerificationData | None = None
    signature: Signature


class Certificate(Base):
    certificate: X509Certificate
    intermediates: X509CertificateChain | None = None
    timestamps: TimestampVerificationData
    signature: Signature


class VerificationMaterial(Base):
    public_key: PublicKey | None = None
    certificate: Certificate | None = None
    transparency_log_proof: TransparencyLogProof | None = None

    @model_validator(mode="after")
    def check_content_oneof(self) -> Self:
        fields = [self.public_key, self.certificate, self.transparency_log_proof]
        if sum(f is not None for f in fields) != 1:
            raise ValueError(
                "Exactly one of publicKey, certificate, or transparencyLogProof must be set"
            )
        return self


BUNDLE_MEDIA_TYPES = Literal["application/vnd.dev.sigstore.bundle.v2.0+json"]


class Bundle(Base):
    """
    Sigstore Bundle v2 (`dev.sigstore.bundle.v2.Bundle`).

    NOTE: Bundle v2 is currently unstable in `sigstore/protobuf-specs` and may
    change in breaking ways.
    """

    media_type: BUNDLE_MEDIA_TYPES
    verification_material: VerificationMaterial
    payload: Payload | None = None
