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


