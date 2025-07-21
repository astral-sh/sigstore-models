import typing as t

import typing_extensions as te
from pydantic import model_validator

from sigstore_models._core import Base
from sigstore_models.common.v1 import (
    MessageSignature,
    PublicKeyIdentifier,
    RFC3161SignedTimestamp,
    X509Certificate,
    X509CertificateChain,
)
from sigstore_models.intoto import Envelope
from sigstore_models.rekor.v1 import TransparencyLogEntry


class TimestampVerificationData(Base):
    rfc3161_timestamps: list[RFC3161SignedTimestamp] = []


class VerificationMaterial(Base):
    public_key: t.Optional[PublicKeyIdentifier] = None
    x509_certificate_chain: t.Optional[X509CertificateChain] = None
    certificate: t.Optional[X509Certificate] = None

    tlog_entries: list[TransparencyLogEntry]  # TODO
    timestamp_verification_data: t.Optional[TimestampVerificationData] = None

    @model_validator(mode="after")
    def check_content_oneof(self) -> te.Self:
        fields = [self.public_key, self.x509_certificate_chain, self.certificate]
        if sum(bool(f) for f in fields) != 1:
            raise ValueError(
                "Exactly one of publicKey, x509CertificateChain, or certificate must be set"
            )
        return self


BUNDLE_MEDIA_TYPES = t.Literal[
    "application/vnd.dev.sigstore.bundle+json;version=0.1",
    "application/vnd.dev.sigstore.bundle+json;version=0.2",
    "application/vnd.dev.sigstore.bundle+json;version=0.3",
    "application/vnd.dev.sigstore.bundle.v0.3+json",
]


class Bundle(Base):
    media_type: BUNDLE_MEDIA_TYPES
    verification_material: VerificationMaterial

    message_signature: t.Optional[MessageSignature] = None
    dsse_envelope: t.Optional[Envelope] = None

    @model_validator(mode="after")
    def check_content_oneof(self) -> te.Self:
        fields = [self.message_signature, self.dsse_envelope]
        if sum(bool(f) for f in fields) != 1:
            raise ValueError(
                "Exactly one of messageSignature or dsseEnvelope must be set"
            )
        return self
