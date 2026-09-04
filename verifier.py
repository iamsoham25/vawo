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


    @classmethod
    def _receipt_hash(cls, receipt) -> str:
        """
        Calculate the hash of a Receipt.

        This matches ToolGateway._get_receipt_hash().
        """

        if hasattr(receipt, "model_dump"):
            receipt_data = receipt.model_dump(
                mode="json"
            )
        else:
            receipt_data = receipt

        return cls._hash_data(receipt_data)


    # ==========================================================
    # MERKLE ROOT
    # ==========================================================

    @classmethod
    def _calculate_merkle_root(
        cls,
        receipt_chain: list
    ):
        """
        Calculate the Merkle root of a receipt chain.

        The algorithm is identical to ToolGateway:

        1. Hash every receipt.
        2. Pair adjacent hashes.
        3. Hash each pair.
        4. Duplicate the final hash if the number is odd.
        5. Continue until one hash remains.
        """

        if not receipt_chain:
            return None

        # Create leaf hashes
        hashes = []

        for receipt in receipt_chain:
            receipt_hash = cls._receipt_hash(
                receipt
            )

            hashes.append(receipt_hash)

        # Build the Merkle tree
        while len(hashes) > 1:

            # Duplicate last hash when odd
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            new_level = []

            for i in range(
                0,
                len(hashes),
                2
            ):
                left = hashes[i]
                right = hashes[i + 1]

                combined = left + right

                parent_hash = hashlib.sha256(
                    combined.encode("utf-8")
                ).hexdigest()

                new_level.append(parent_hash)

            hashes = new_level

        return hashes[0]


    # ==========================================================
    # RECEIPT CHAIN INTEGRITY
    # ==========================================================

    @classmethod
    def _verify_receipt_chain(
        cls,
        receipt_chain: list
    ) -> bool:
        """
        Verify the parent hash relationship between receipts.

        The first receipt must have no parent.

        Every following receipt must contain the SHA-256
        hash of the immediately previous receipt.
        """

        # Empty chain cannot prove execution integrity
        if not receipt_chain:
            return False

        # First receipt must not have a parent
        first_receipt = receipt_chain[0]

        if first_receipt.parent_event_hash is not None:
            return False

        # Check every subsequent receipt
        for i in range(
            1,
            len(receipt_chain)
        ):
            previous_receipt = receipt_chain[i - 1]
            current_receipt = receipt_chain[i]

            expected_parent_hash = cls._receipt_hash(
                previous_receipt
            )

            if (
                current_receipt.parent_event_hash
                != expected_parent_hash
            ):
                return False

        return True


    # ==========================================================
    # VERIFY WORK ORDER
    # ==========================================================

    def verify_work_order(
        self,
        work_order_dict: dict,
        requester_agent_id: str
    ) -> VerificationResult:
        """
        Verify a signed Work Order.

        Checks are performed in order:

            1. Signature
            2. Nonce and expiry

        Verification stops at the first failure.
        """

        checks_passed = []
        checks_failed = []

        # ------------------------------------------------------
        # CHECK 1: REQUESTER SIGNATURE
        # ------------------------------------------------------

        if requester_agent_id not in self.agent_public_keys:

            checks_failed.append(
                "requester public key lookup"
            )

            return VerificationResult(
                accepted=False,
                reason=(
                    "unknown requester agent: "
                    f"{requester_agent_id}"
                ),
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        public_key = self.agent_public_keys[
            requester_agent_id
        ]

        signature = work_order_dict.get(
            "signature"
        )

        if not signature:

            checks_failed.append(
                "work order signature"
            )

            return VerificationResult(
                accepted=False,
                reason="work order signature is missing",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        # Remove signature before verification
        data_to_verify = work_order_dict.copy()

        data_to_verify.pop(
            "signature",
            None
        )

        signature_valid = verify_signature(
            public_key,
            data_to_verify,
            signature
        )

        if not signature_valid:

            checks_failed.append(
                "work order signature"
            )

            return VerificationResult(
                accepted=False,
                reason="invalid Work Order signature",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        