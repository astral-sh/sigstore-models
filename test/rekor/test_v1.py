import base64

import pytest

import sigstore_models.rekor.v1 as v1


class TestInclusionProof:
    def test_validate_log_index_in_tree_size(self):
        proof = {
            "logIndex": "12345",
            "rootHash": base64.b64encode(b"some nonsense").decode(),
            "treeSize": "1234",
            "hashes": [],
            "checkpoint": None,
        }

        with pytest.raises(
            ValueError, match="logIndex 12345 must be less than treeSize 1234"
        ):
            v1.InclusionProof.from_dict(proof)
