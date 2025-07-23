import enum
import typing as t

from sigstore_models._core import Base
from sigstore_models.common.v1 import (
    DistinguishedName,
    HashAlgorithm,
    LogId,
    PublicKey,
    TimeRange,
    X509CertificateChain,
)


class TransparencyLogInstance(Base):
    base_url: str
    hash_algorithm: HashAlgorithm
    public_key: PublicKey
    log_id: LogId
    checkpoint_key_id: t.Optional[LogId] = None
    operator: t.Optional[str] = None


class CertificateAuthority(Base):
    subject: DistinguishedName
    uri: t.Optional[str] = None
    cert_chain: X509CertificateChain
    valid_for: TimeRange
    operator: t.Optional[str] = None


TRUSTED_ROOT_MEDIA_TYPES = t.Literal[
    "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "application/vnd.dev.sigstore.trustedroot.v0.2+json",
]


class TrustedRoot(Base):
    media_type: TRUSTED_ROOT_MEDIA_TYPES
    tlogs: list[TransparencyLogInstance]
    certificate_authorities: list[CertificateAuthority]
    ctlogs: list[TransparencyLogInstance]
    timestamp_authorities: list[CertificateAuthority] = []


SIGNING_CONFIG_MEDIA_TYPES = t.Literal[
    "application/vnd.dev.sigstore.signingconfig.v0.1+json",
    "application/vnd.dev.sigstore.signingconfig.v0.2+json",
]


class SigningConfig(Base):
    media_type: SIGNING_CONFIG_MEDIA_TYPES
    ca_urls: list["Service"] = []
    oidc_urls: list["Service"] = []
    rekor_tlog_urls: list["Service"] = []
    rekor_tlog_config: t.Optional["ServiceConfiguration"] = None
    tsa_urls: list["Service"] = []
    tsa_config: t.Optional["ServiceConfiguration"] = None


class Service(Base):
    url: str
    major_api_version: int
    valid_for: t.Optional[TimeRange] = None
    operator: str


class ServiceSelector(str, enum.Enum):
    ALL = "ALL"
    ANY = "ANY"
    EXACT = "EXACT"


class ServiceConfiguration(Base):
    selector: ServiceSelector
    count: t.Optional[int] = None


class ClientTrustConfig(Base):
    media_type: t.Literal["application/vnd.dev.sigstore.clienttrustconfig.v0.1+json"]

    trusted_root: TrustedRoot
    signing_config: SigningConfig
