from typing import Literal, Self

from pydantic import Field, model_validator

from sigstore_models._core import Base, ProtoBytes
from sigstore_models.common.v1 import (
    PublicKeyIdentifier,
    RFC3161SignedTimestamp,
    X509Certificate,
    X509CertificateChain,
)


class TimestampVerificationData(Base):
    rfc3161_timestamps: list[RFC3161SignedTimestamp] = Field(default_factory=list)


class Signature(Base):
    signature: ProtoBytes


class Embedded(Base):
    payload_type: str
    payload: ProtoBytes
    signature: Signature | None = None


class MessageSignature(Base):
    signature: Signature | None = None


class TlogProof(Base):
    proof: ProtoBytes


class PublicKey(Base):
    public_key: PublicKeyIdentifier | None = None
    timestamps: TimestampVerificationData | None = None


class Cert(Base):
    certificate: X509Certificate
    intermediates: X509CertificateChain | None = None
    timestamps: TimestampVerificationData


class VerificationMaterial(Base):
    public_key: PublicKey | None = None
    cert: Cert | None = None
    tlog_proof: TlogProof | None = None

    @model_validator(mode="after")
    def check_content_oneof(self) -> Self:
        fields = [self.public_key, self.cert, self.tlog_proof]
        if sum(f is not None for f in fields) != 1:
            raise ValueError("Exactly one of publicKey, cert, or tlogProof must be set")
        return self


BUNDLE_MEDIA_TYPES = Literal["application/vnd.dev.sigstore.bundle.v2.0+json"]


class Bundle(Base):
    media_type: BUNDLE_MEDIA_TYPES
    verification_material: VerificationMaterial

    message_signature: MessageSignature | None = None
    embedded_data: Embedded | None = None

    @model_validator(mode="after")
    def check_content_oneof(self) -> Self:
        fields = [self.message_signature, self.embedded_data]
        if sum(f is not None for f in fields) != 1:
            raise ValueError(
                "Exactly one of messageSignature or embeddedData must be set"
            )
        return self
