import enum
import typing as t
from datetime import datetime

from sigstore_models._core import Base, ProtoBytes


class HashAlgorithm(str, enum.Enum):
    # NOTE: We don't include HASH_ALGORITHM_UNSPECIFIED
    # because it's a protobuf-level hack, and not a valid hash algorithm.
    SHA2_256 = "SHA2_256"
    SHA2_384 = "SHA2_384"
    SHA2_512 = "SHA2_512"
    SHA3_256 = "SHA3_256"
    SHA3_384 = "SHA3_384"


class PublicKeyDetails(str, enum.Enum):
    # TODO: Figure out a good way to encode deprecated variants.
    # RSA
    PKCS1_RSA_PKCS1V5 = "PKCS1_RSA_PKCS1V5"  # deprecated
    PKCS1_RSA_PSS = "PKCS1_RSA_PSS"  # deprecated
    PKIX_RSA_PKCS1V5 = "PKIX_RSA_PKCS1V5"  # deprecated
    PKIX_RSA_PSS = "PKIX_RSA_PSS"  # deprecated

    # RSA public key in PKIX format, PKCS#1v1.5 signature
    PKIX_RSA_PKCS1V15_2048_SHA256 = "PKIX_RSA_PKCS1V15_2048_SHA256"
    PKIX_RSA_PKCS1V15_3072_SHA256 = "PKIX_RSA_PKCS1V15_3072_SHA256"
    PKIX_RSA_PKCS1V15_4096_SHA256 = "PKIX_RSA_PKCS1V15_4096_SHA256"

    # RSA public key in PKIX format, RSASSA-PSS signature
    PKIX_RSA_PSS_2048_SHA256 = "PKIX_RSA_PSS_2048_SHA256"  # See RFC4055
    PKIX_RSA_PSS_3072_SHA256 = "PKIX_RSA_PSS_3072_SHA256"
    PKIX_RSA_PSS_4096_SHA256 = "PKIX_RSA_PSS_4096_SHA256"

    # ECDSA
    PKIX_ECDSA_P256_HMAC_SHA_256 = (
        "PKIX_ECDSA_P256_HMAC_SHA_256"  # deprecated - See RFC6979
    )
    PKIX_ECDSA_P256_SHA_256 = "PKIX_ECDSA_P256_SHA_256"  # See NIST FIPS 186-4
    PKIX_ECDSA_P384_SHA_384 = "PKIX_ECDSA_P384_SHA_384"
    PKIX_ECDSA_P521_SHA_512 = "PKIX_ECDSA_P521_SHA_512"

    # Ed 25519
    PKIX_ED25519 = "PKIX_ED25519"  # See RFC8032
    PKIX_ED25519_PH = "PKIX_ED25519_PH"

    # These algorithms are deprecated and should not be used, but they
    # were/are being used by most Sigstore clients implementations.
    PKIX_ECDSA_P384_SHA_256 = "PKIX_ECDSA_P384_SHA_256"  # deprecated
    PKIX_ECDSA_P521_SHA_256 = "PKIX_ECDSA_P521_SHA_256"  # deprecated

    # LMS and LM-OTS
    #
    # These algorithms are deprecated and should not be used.
    # Keys and signatures MAY be used by private Sigstore
    # deployments, but will not be supported by the public
    # good instance.
    #
    # USER WARNING: LMS and LM-OTS are both stateful signature schemes.
    # Using them correctly requires discretion and careful consideration
    # to ensure that individual secret keys are not used more than once.
    # In addition, LM-OTS is a single-use scheme, meaning that it
    # MUST NOT be used for more than one signature per LM-OTS key.
    # If you cannot maintain these invariants, you MUST NOT use these
    # schemes.
    LMS_SHA256 = "LMS_SHA256"  # deprecated
    LMOTS_SHA256 = "LMOTS_SHA256"  # deprecated

    # ML-DSA
    #
    # These ML_DSA_65 and ML-DSA_87 algorithms are the pure variants that
    # take data to sign rather than the prehash variants (HashML-DSA), which
    # take digests.  While considered quantum-resistant, their usage
    # involves tradeoffs in that signatures and keys are much larger, and
    # this makes deployments more costly.
    #
    # USER WARNING: ML_DSA_65 and ML_DSA_87 are experimental algorithms.
    # In the future they MAY be used by private Sigstore deployments, but
    # they are not yet fully functional.  This warning will be removed when
    # these algorithms are widely supported by Sigstore clients and servers,
    # but care should still be taken for production environments.
    ML_DSA_65 = "ML_DSA_65"  # See NIST FIPS 204
    ML_DSA_87 = "ML_DSA_87"


class HashOutput(Base):
    """HashOutput captures a digest of a 'message' (generic octet sequence)
    and the corresponding hash algorithm used."""

    algorithm: HashAlgorithm
    digest: ProtoBytes  # Raw octets of the message digest


class MessageSignature(Base):
    """MessageSignature stores the computed signature over a message."""

    message_digest: t.Optional[HashOutput] = None  # For artifact identification only
    signature: ProtoBytes  # Raw signature bytes (required)


class LogId(Base):
    """LogId captures the identity of a transparency log."""

    key_id: ProtoBytes  # Unique identity of the log (required)


class RFC3161SignedTimestamp(Base):
    """This message holds a RFC 3161 timestamp."""

    signed_timestamp: ProtoBytes  # DER encoded TimeStampResponse (required)


class PublicKey(Base):
    """Public key with encoding details and optional validity period."""

    raw_bytes: t.Optional[bytes] = None  # DER-encoded public key
    key_details: PublicKeyDetails  # Key encoding and signature algorithm
    valid_for: t.Optional["TimeRange"] = None  # Optional validity period


class PublicKeyIdentifier(Base):
    """PublicKeyIdentifier can be used to identify an (out of band) delivered
    key, to verify a signature."""

    hint: t.Optional[str]  # Optional unauthenticated hint on which key to use


class ObjectIdentifier(Base):
    """An ASN.1 OBJECT IDENTIFIER"""

    id: list[int]  # Required list of integers


class ObjectIdentifierValuePair(Base):
    """An OID and the corresponding (byte) value."""

    oid: ObjectIdentifier
    value: ProtoBytes


class DistinguishedName(Base):
    """Distinguished name with organization and common name."""

    organization: str
    common_name: str


class X509Certificate(Base):
    """X.509 certificate container."""

    raw_bytes: ProtoBytes  # DER-encoded X.509 certificate (required)


class SubjectAlternativeNameType(str, enum.Enum):
    EMAIL = "EMAIL"
    URI = "URI"
    OTHER_NAME = "OTHER_NAME"


class SubjectAlternativeName(Base):
    """Subject Alternative Name with type and identity."""

    type: SubjectAlternativeNameType
    # Using Union for the oneof identity field
    regexp: t.Optional[str] = None  # Regular expression for expected value
    value: t.Optional[str] = None  # Exact value to match against


class X509CertificateChain(Base):
    """A collection of X.509 certificates.

    This "chain" can be used in multiple contexts, such as providing a root CA
    certificate within a TUF root of trust or multiple untrusted certificates for
    the purpose of chain building."""

    certificates: list[X509Certificate]  # One or more DER-encoded certificates


class TimeRange(Base):
    """The time range is closed and includes both the start and end times,
    (i.e., [start, end]). End is optional to be able to capture a period
    that has started but has no known end."""

    start: datetime
    end: t.Optional[datetime] = None
