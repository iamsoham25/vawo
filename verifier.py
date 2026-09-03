import hashlib
import json

from datetime import datetime, timezone

from pydantic import BaseModel

from signing import (
    NonceTracker,
    verify_signature
)

class VerificationResult(BaseModel):
    """
    Stores the result of a VAWO verification process.
    """

    accepted: bool
    reason: str
    checks_passed: list[str]
    checks_failed: list[str]


class Verifier:
    """
    Verifies Work Orders and Worker execution claims.

    The Verifier checks:

    Work Order:
        1. Ed25519 signature
        2. Nonce and expiry

    Execution:
        1. Manifest signature
        2. Merkle root
        3. Tool allowlist
        4. Receipt chain integrity
        5. Independent re-execution
    """

    def __init__(
        self,
        nonce_tracker: NonceTracker,
        agent_public_keys: dict[str, bytes]
    ):
        """
        Initialize the Verifier.

        Args:
            nonce_tracker:
                NonceTracker used for replay protection.

            agent_public_keys:
                Dictionary mapping agent IDs to Ed25519
                public keys.

                Example:
                    {
                        "requester-001": requester_public_key,
                        "worker-001": worker_public_key
                    }
        """

        self.nonce_tracker = nonce_tracker
        self.agent_public_keys = agent_public_keys

    # ==========================================================
    # INTERNAL HASHING HELPERS
    # ==========================================================

    @staticmethod
    def _canonical_json(data) -> str:
        """
        Convert data into deterministic JSON.

        This matches the canonical JSON approach used by
        gateway.py and signing.py.
        """

        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            default=str
        )


    @classmethod
    def _hash_data(cls, data) -> str:
        """
        Return SHA-256 hash of canonical JSON data.
        """

        json_data = cls._canonical_json(data)

        return hashlib.sha256(
            json_data.encode("utf-8")
        ).hexdigest()

    


    