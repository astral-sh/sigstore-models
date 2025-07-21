from sigstore_models._core import Base
from sigstore_models.common.v1 import HashOutput
from sigstore_models.intoto import Envelope
from sigstore_models.rekor.v2 import verifier


class DSSERequestV002(Base):
    envelope: Envelope
    verifiers: list[verifier.Verifier]


class DSSELogEntryV002(Base):
    payload_hash: HashOutput
    signatures: list[verifier.Signature]
