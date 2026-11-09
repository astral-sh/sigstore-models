import base64
import json

import pytest
from sigstore_models.bundle import v2 as bundle_v2
from sigstore_models.common import v1 as common_v1
from sigstore_models.rekor import v2 as rekor_v2
from sigstore_models.trustroot import v1 as trustroot_v1


class TestTrustedRootV2:
    def test_tlog_only_trusted_root_with_ml_dsa_44(self) -> None:
        raw = {
            "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
            "tlogs": [
                {
                    "baseUrl": "https://pqc27-a1.us-east4.rekor.sigstage.dev",
                    "hashAlgorithm": "SHA2_256",
                    "publicKey": {
                        "rawBytes": base64.b64encode(b"mldsa44-spki-der").decode(),
                        "keyDetails": "ML_DSA_44",
                        "validFor": {"start": "2026-04-06T19:03:00Z"},
                    },
                    "logId": {
                        "keyId": "yamUXBf/d5QJ2jHB8HmHqxX+zHV201aClKtJnFuN5/0=",
                    },
                }
            ],
        }
        tr = trustroot_v1.TrustedRoot.from_json(json.dumps(raw))
        assert (
            tr.tlogs[0].public_key.key_details == common_v1.PublicKeyDetails.ML_DSA_44
        )
        assert tr.certificate_authorities == []
        assert tr.ctlogs == []
        assert tr.timestamp_authorities == []


class TestRekorV2Identity:
    def test_identity_request_oidc_and_public_key(self) -> None:
        msg = base64.b64encode(b"\x11" * 32).decode()
        oidc_req = rekor_v2.identity.IdentityRequestV001.from_dict(
            {
                "oidc": {"token": "eyJ..."},
                "message": msg,
            }
        )
        assert oidc_req.oidc is not None
        assert oidc_req.oidc.token == "eyJ..."
        assert oidc_req.public_key is None
        assert oidc_req.message == b"\x11" * 32

        pk_req = rekor_v2.identity.IdentityRequestV001.from_dict(
            {
                "publicKey": {
                    "publicKey": base64.b64encode(b"pub").decode(),
                    "signature": base64.b64encode(b"sig").decode(),
                    "context": base64.b64encode(b"\x22" * 32).decode(),
                },
                "message": msg,
            }
        )
        assert pk_req.public_key is not None
        assert pk_req.public_key.public_key == b"pub"
        assert pk_req.public_key.signature == b"sig"
        assert pk_req.public_key.context == b"\x22" * 32

        with pytest.raises(
            ValueError, match="Exactly one of publicKey or oidc must be set"
        ):
            rekor_v2.identity.IdentityRequestV001.from_dict({"message": msg})


class TestBundleV2:
    def test_bundle_v2_keyless_artifact(self) -> None:
        proof_b64 = base64.b64encode(b"c2sp.org/tlog-proof@v1\n").decode()
        raw = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
            "verificationMaterial": {
                "tlogProof": {"proof": proof_b64},
            },
            "messageSignature": {},
        }
        bundle = bundle_v2.Bundle.from_dict(raw)
        assert bundle.verification_material.tlog_proof is not None
        assert (
            bundle.verification_material.tlog_proof.proof == b"c2sp.org/tlog-proof@v1\n"
        )
        assert bundle.message_signature is not None
        assert bundle.message_signature.signature is None
        assert bundle.to_dict() == raw

    def test_bundle_v2_embedded_data_and_oneof_validation(self) -> None:
        proof_b64 = base64.b64encode(b"c2sp.org/tlog-proof@v1\n").decode()
        payload_b64 = base64.b64encode(
            b'{"_type":"https://in-toto.io/Statement/v1"}'
        ).decode()
        sig_b64 = base64.b64encode(b"sig-bytes").decode()
        raw = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
            "verificationMaterial": {
                "tlogProof": {"proof": proof_b64},
            },
            "embeddedData": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": payload_b64,
                "signature": {"signature": sig_b64},
            },
        }
        bundle = bundle_v2.Bundle.from_dict(raw)
        assert bundle.embedded_data is not None
        assert bundle.embedded_data.signature is not None
        assert bundle.embedded_data.signature.signature == b"sig-bytes"
        assert bundle.to_dict() == raw

        with pytest.raises(
            ValueError,
            match="Exactly one of publicKey, cert, or tlogProof must be set",
        ):
            bundle_v2.VerificationMaterial.from_dict({})

        with pytest.raises(
            ValueError,
            match="Exactly one of messageSignature or embeddedData must be set",
        ):
            bundle_v2.Bundle.from_dict(
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
                    "verificationMaterial": {"tlogProof": {"proof": proof_b64}},
                }
            )
