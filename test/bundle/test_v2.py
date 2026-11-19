import base64
import json

import pytest

from sigstore_models.bundle import v2 as bundle_v2


class TestBundleV2:
    def test_keyless_artifact_bundle(self) -> None:
        proof_b64 = base64.b64encode(b"c2sp.org/tlog-proof@v1\n").decode()
        raw = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
            "verificationMaterial": {
                "transparencyLogProof": {"proof": proof_b64},
            },
        }

        bundle = bundle_v2.Bundle.from_dict(raw)
        assert bundle.verification_material.transparency_log_proof is not None
        assert (
            bundle.verification_material.transparency_log_proof.proof
            == b"c2sp.org/tlog-proof@v1\n"
        )
        assert bundle.verification_material.transparency_log_proof.signature is None
        assert bundle.payload is None
        assert bundle.to_dict() == raw
        assert bundle_v2.Bundle.from_json(bundle.to_json()) == bundle

    def test_logged_public_key_dsse_bundle(self) -> None:
        proof_b64 = base64.b64encode(b"c2sp.org/tlog-proof@v1\n").decode()
        sig_b64 = base64.b64encode(b"sig-bytes").decode()
        payload_b64 = base64.b64encode(
            b'{"_type":"https://in-toto.io/Statement/v1"}'
        ).decode()
        raw = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
            "verificationMaterial": {
                "transparencyLogProof": {
                    "proof": proof_b64,
                    "signature": {"signature": sig_b64},
                },
            },
            "payload": {
                "payloadType": "application/vnd.in-toto+json",
                "payload": payload_b64,
            },
        }

        bundle = bundle_v2.Bundle.from_json(json.dumps(raw))
        tlog_proof = bundle.verification_material.transparency_log_proof
        assert tlog_proof is not None
        assert tlog_proof.signature is not None
        assert tlog_proof.signature.signature == b"sig-bytes"
        assert bundle.payload is not None
        assert bundle.payload.payload_type == "application/vnd.in-toto+json"
        assert bundle.payload.payload == b'{"_type":"https://in-toto.io/Statement/v1"}'
        assert bundle.to_dict() == raw

    def test_unlogged_public_key_bundle(self) -> None:
        sig_b64 = base64.b64encode(b"pk-sig").decode()
        ts_b64 = base64.b64encode(b"rfc3161-ts").decode()
        raw = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
            "verificationMaterial": {
                "publicKey": {
                    "timestamps": {
                        "rfc3161Timestamps": [{"signedTimestamp": ts_b64}],
                    },
                    "signature": {"signature": sig_b64},
                },
            },
        }

        bundle = bundle_v2.Bundle.from_dict(raw)
        pk = bundle.verification_material.public_key
        assert pk is not None
        assert pk.signature.signature == b"pk-sig"
        assert pk.timestamps is not None
        assert len(pk.timestamps.rfc3161_timestamps) == 1
        assert pk.timestamps.rfc3161_timestamps[0].signed_timestamp == b"rfc3161-ts"
        assert bundle.to_dict() == raw

        # PublicKey without optional timestamps is valid.
        minimal_pk = bundle_v2.PublicKey.from_dict(
            {"signature": {"signature": sig_b64}}
        )
        assert minimal_pk.timestamps is None
        assert minimal_pk.signature.signature == b"pk-sig"

        # Removed publicKey hint field is forbidden.
        with pytest.raises(ValueError):
            bundle_v2.PublicKey.from_dict(
                {
                    "publicKey": {"hint": "deprecated"},
                    "signature": {"signature": sig_b64},
                }
            )

    def test_certificate_bundle(self) -> None:
        cert_b64 = base64.b64encode(b"leaf-cert").decode()
        inter_b64 = base64.b64encode(b"inter-cert").decode()
        ts_b64 = base64.b64encode(b"rfc3161-ts").decode()
        sig_b64 = base64.b64encode(b"cert-sig").decode()
        raw = {
            "mediaType": "application/vnd.dev.sigstore.bundle.v2.0+json",
            "verificationMaterial": {
                "certificate": {
                    "certificate": {"rawBytes": cert_b64},
                    "intermediates": {"certificates": [{"rawBytes": inter_b64}]},
                    "timestamps": {
                        "rfc3161Timestamps": [{"signedTimestamp": ts_b64}],
                    },
                    "signature": {"signature": sig_b64},
                },
            },
        }

        bundle = bundle_v2.Bundle.from_dict(raw)
        cert = bundle.verification_material.certificate
        assert cert is not None
        assert cert.certificate.raw_bytes == b"leaf-cert"
        assert cert.intermediates is not None
        assert cert.intermediates.certificates[0].raw_bytes == b"inter-cert"
        assert cert.timestamps.rfc3161_timestamps[0].signed_timestamp == b"rfc3161-ts"
        assert cert.signature.signature == b"cert-sig"
        assert bundle.to_dict() == raw

    def test_verification_material_oneof_validation(self) -> None:
        proof_b64 = base64.b64encode(b"proof").decode()
        sig_b64 = base64.b64encode(b"sig").decode()

        with pytest.raises(
            ValueError,
            match="Exactly one of publicKey, certificate, or transparencyLogProof must be set",
        ):
            bundle_v2.VerificationMaterial.from_dict({})

        with pytest.raises(
            ValueError,
            match="Exactly one of publicKey, certificate, or transparencyLogProof must be set",
        ):
            bundle_v2.VerificationMaterial.from_dict(
                {
                    "transparencyLogProof": {"proof": proof_b64},
                    "publicKey": {"signature": {"signature": sig_b64}},
                }
            )

    def test_invalid_media_type(self) -> None:
        proof_b64 = base64.b64encode(b"proof").decode()
        with pytest.raises(ValueError):
            bundle_v2.Bundle.from_dict(
                {
                    "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
                    "verificationMaterial": {
                        "transparencyLogProof": {"proof": proof_b64},
                    },
                }
            )
