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

    