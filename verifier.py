from datetime import datetime, timezone

from pydantic import BaseModel

from gateway import ToolGateway
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

    Work Order checks:
        1. Signature
        2. Nonce and expiry

    Execution checks:
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
                Dictionary mapping agent IDs to public keys.
        """

        self.nonce_tracker = nonce_tracker
        self.agent_public_keys = agent_public_keys

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

        Stops at the first failure.
        """

        checks_passed = []
        checks_failed = []

        # ------------------------------------------------------
        # CHECK 1: REQUESTER SIGNATURE
        # ------------------------------------------------------

        if requester_agent_id not in self.agent_public_keys:

            checks_failed.append(
                "requester signature"
            )

            return VerificationResult(
                accepted=False,
                reason=(
                    f"unknown requester agent: "
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
                "requester signature"
            )

            return VerificationResult(
                accepted=False,
                reason="Work Order signature is missing",
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
                "requester signature"
            )

            return VerificationResult(
                accepted=False,
                reason="invalid Work Order signature",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        checks_passed.append(
            "requester signature"
        )

        # ------------------------------------------------------
        # CHECK 2: NONCE AND EXPIRY
        # ------------------------------------------------------

        nonce = work_order_dict.get(
            "nonce"
        )

        expiry = work_order_dict.get(
            "expiry"
        )

        if not nonce:

            checks_failed.append(
                "nonce and expiry"
            )

            return VerificationResult(
                accepted=False,
                reason="Work Order nonce is missing",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        if not expiry:

            checks_failed.append(
                "nonce and expiry"
            )

            return VerificationResult(
                accepted=False,
                reason="Work Order expiry is missing",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        # Convert ISO datetime string to datetime
        if isinstance(expiry, str):

            expiry = datetime.fromisoformat(
                expiry.replace(
                    "Z",
                    "+00:00"
                )
            )

        # Handle naive datetime
        if expiry.tzinfo is None:

            expiry = expiry.replace(
                tzinfo=timezone.utc
            )

        nonce_valid = self.nonce_tracker.is_valid(
            nonce,
            expiry
        )

        if not nonce_valid:

            checks_failed.append(
                "nonce and expiry"
            )

            if expiry <= datetime.now(
                timezone.utc
            ):

                reason = (
                    "Work Order has expired"
                )

            else:

                reason = (
                    "Work Order nonce has "
                    "already been used"
                )

            return VerificationResult(
                accepted=False,
                reason=reason,
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        checks_passed.append(
            "nonce and expiry"
        )

        # Mark nonce as used only after all checks
        # performed so far have passed.
        self.nonce_tracker.mark_used(
            nonce
        )

        return VerificationResult(
            accepted=True,
            reason="Work Order verification successful",
            checks_passed=checks_passed,
            checks_failed=checks_failed
        )

    # ==========================================================
    # VERIFY EXECUTION
    # ==========================================================

    def verify_execution(
        self,
        manifest_dict: dict,
        receipt_chain: list,
        worker_agent_id: str,
        tool_allowlist: list[str],
        reexecution_fn: callable
    ) -> VerificationResult:
        """
        Verify a Worker's claimed execution.

        Checks are performed in order:

            1. Manifest signature
            2. Merkle root
            3. Tool allowlist
            4. Receipt chain integrity
            5. Independent re-execution

        Stops at the first failure.
        """

        checks_passed = []
        checks_failed = []

        # ------------------------------------------------------
        # CHECK 1: MANIFEST SIGNATURE
        # ------------------------------------------------------

        if worker_agent_id not in self.agent_public_keys:

            checks_failed.append(
                "manifest signature"
            )

            return VerificationResult(
                accepted=False,
                reason=(
                    f"unknown worker agent: "
                    f"{worker_agent_id}"
                ),
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        worker_public_key = self.agent_public_keys[
            worker_agent_id
        ]

        signature = manifest_dict.get(
            "signature"
        )

        if not signature:

            checks_failed.append(
                "manifest signature"
            )

            return VerificationResult(
                accepted=False,
                reason="Execution Manifest signature is missing",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        # Remove signature before verification
        manifest_to_verify = manifest_dict.copy()

        manifest_to_verify.pop(
            "signature",
            None
        )

        signature_valid = verify_signature(
            worker_public_key,
            manifest_to_verify,
            signature
        )

        if not signature_valid:

            checks_failed.append(
                "manifest signature"
            )

            return VerificationResult(
                accepted=False,
                reason="invalid Execution Manifest signature",
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        checks_passed.append(
            "manifest signature"
        )

        # ------------------------------------------------------
        # CHECK 2: MERKLE ROOT
        # ------------------------------------------------------

        claimed_merkle_root = manifest_dict.get(
            "merkle_root"
        )

        # IMPORTANT:
        # Use the exact ToolGateway implementation.
        #
        # This avoids having two different Merkle algorithms
        # in the project.

        gateway_for_verification = ToolGateway()

        gateway_for_verification.receipt_chain = (
            receipt_chain
        )

        calculated_merkle_root = (
            gateway_for_verification.get_merkle_root()
        )

        if (
            claimed_merkle_root
            != calculated_merkle_root
        ):

            checks_failed.append(
                "merkle root"
            )

            return VerificationResult(
                accepted=False,
                reason=(
                    "Merkle root mismatch: "
                    "manifest root does not match "
                    "the supplied receipt chain"
                ),
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        checks_passed.append(
            "merkle root"
        )

        # ------------------------------------------------------
        # CHECK 3: TOOL ALLOWLIST
        # ------------------------------------------------------

        for receipt in receipt_chain:

            if receipt.tool_name not in tool_allowlist:

                checks_failed.append(
                    "tool allowlist"
                )

                return VerificationResult(
                    accepted=False,
                    reason=(
                        f"unauthorized tool: "
                        f"'{receipt.tool_name}' "
                        f"is not in the tool allowlist"
                    ),
                    checks_passed=checks_passed,
                    checks_failed=checks_failed
                )

        checks_passed.append(
            "tool allowlist"
        )

        # ------------------------------------------------------
        # CHECK 4: RECEIPT CHAIN INTEGRITY
        # ------------------------------------------------------

        # Again, use the exact implementation from
        # ToolGateway instead of duplicating the logic.

        chain_valid = (
            gateway_for_verification
            .verify_chain_integrity()
        )

        if not chain_valid:

            checks_failed.append(
                "receipt chain integrity"
            )

            return VerificationResult(
                accepted=False,
                reason=(
                    "receipt chain integrity "
                    "verification failed"
                ),
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        checks_passed.append(
            "receipt chain integrity"
        )

        # ------------------------------------------------------
        # CHECK 5: INDEPENDENT RE-EXECUTION
        # ------------------------------------------------------

        independent_result = reexecution_fn()

        claimed_result = manifest_dict.get(
            "result_artifact"
        )

        if independent_result != claimed_result:

            checks_failed.append(
                "independent re-execution"
            )

            return VerificationResult(
                accepted=False,
                reason=(
                    "re-execution mismatch: "
                    "claimed result does not match "
                    "independent execution"
                ),
                checks_passed=checks_passed,
                checks_failed=checks_failed
            )

        checks_passed.append(
            "independent re-execution"
        )

        # ------------------------------------------------------
        # ALL CHECKS PASSED
        # ------------------------------------------------------

        return VerificationResult(
            accepted=True,
            reason="execution verification successful",
            checks_passed=checks_passed,
            checks_failed=checks_failed
        )