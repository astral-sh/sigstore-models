from sigstore_models._core import Base, ProtoBytes
from sigstore_models.common.v1 import HashOutput
from sigstore_models.rekor.v2 import verifier


class HashedRekordRequestV002(Base):
    digest: ProtoBytes
    signature: verifier.Signature


class HashedRekordLogEntryV002(Base):
    data: HashOutput
    signature: verifier.Signature
