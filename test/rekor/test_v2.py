import base64
import json

import pytest
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
