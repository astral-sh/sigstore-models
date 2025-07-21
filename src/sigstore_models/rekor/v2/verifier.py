import typing as t

import typing_extensions as te
from pydantic import model_validator

from sigstore_models._core import Base, ProtoBytes
from sigstore_models.common.v1 import PublicKeyDetails, X509Certificate


class PublicKey(Base):
    raw_bytes: ProtoBytes


class Verifier(Base):
    public_key: t.Optional[PublicKey] = None
    x509_certificate: t.Optional[X509Certificate] = None

    key_details: PublicKeyDetails

    @model_validator(mode="after")
    def check_verifier_oneof(self) -> te.Self:
        fields = [self.public_key, self.x509_certificate]
        if sum(bool(f) for f in fields) != 1:
            raise ValueError("Exactly one of publicKey or x509Certificate must be set")
        return self


class Signature(Base):
    content: ProtoBytes
    verifier: Verifier
