from typing import Self

from pydantic import model_validator

from sigstore_models._core import Base, ProtoBytes


class PublicKeyCredential(Base):
    public_key: ProtoBytes
    signature: ProtoBytes
    context: ProtoBytes | None = None


class OidcCredential(Base):
    token: str


class IdentityRequestV001(Base):
    public_key: PublicKeyCredential | None = None
    oidc: OidcCredential | None = None
    message: ProtoBytes

    @model_validator(mode="after")
    def check_credential_oneof(self) -> Self:
        fields = [self.public_key, self.oidc]
        if sum(f is not None for f in fields) != 1:
            raise ValueError("Exactly one of publicKey or oidc must be set")
        return self
