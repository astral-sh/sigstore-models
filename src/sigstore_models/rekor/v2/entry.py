import typing as t

import typing_extensions as te
from pydantic import model_validator

from sigstore_models._core import Base
from sigstore_models.rekor.v2 import dsse, hashedrekord


class Entry(Base):
    kind: str
    api_version: str
    spec: "Spec"


class Spec(Base):
    hashed_rekord_v002: t.Optional[hashedrekord.HashedRekordLogEntryV002] = None
    dsse_v002: t.Optional[dsse.DSSELogEntryV002] = None

    @model_validator(mode="after")
    def check_spec_oneof(self) -> te.Self:
        fields = [self.hashed_rekord_v002, self.dsse_v002]
        if sum(bool(f) for f in fields) != 1:
            raise ValueError("Exactly one of hashedRekordV002 or dsseV002 must be set")
        return self


class CreateEntryRequest(Base):
    hashed_rekord_request_v002: t.Optional[hashedrekord.HashedRekordRequestV002] = None
    dsse_request_v002: t.Optional[dsse.DSSERequestV002] = None

    @model_validator(mode="after")
    def check_request_oneof(self) -> te.Self:
        fields = [self.hashed_rekord_request_v002, self.dsse_request_v002]
        if sum(bool(f) for f in fields) != 1:
            raise ValueError(
                "Exactly one of hashedRekordRequestV002 or dsseRequestV002 must be set"
            )
        return self
