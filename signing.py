import json
from datetime import datetime, timezone

from nacl import exceptions
from nacl.signing import SigningKey, VerifyKey


def _canonical_json(data: dict) -> str:
    """
    Convert dictionary data into deterministic JSON.

    Sorting keys and removing extra whitespace ensures
    the same data always produces the same JSON string.
    """

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        default=str
    )


def generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate an Ed25519 private and public keypair.

    Returns:
        private_key_bytes,
        public_key_bytes
    """

    private_key = SigningKey.generate()

    private_key_bytes = bytes(private_key)

    public_key_bytes = bytes(
        private_key.verify_key
    )

    return private_key_bytes, public_key_bytes


def sign_data(
    private_key_bytes: bytes,
    data: dict
) -> str:
    """
    Sign dictionary data using an Ed25519 private key.

    Returns:
        Signature as a hexadecimal string.
    """

    private_key = SigningKey(
        private_key_bytes
    )

    canonical_data = _canonical_json(
        data
    )

    signed_message = private_key.sign(
        canonical_data.encode("utf-8")
    )

    signature = signed_message.signature

    return signature.hex()


def verify_signature(
    public_key_bytes: bytes,
    data: dict,
    signature_hex: str
) -> bool:
    """
    Verify an Ed25519 signature.

    Returns:
        True if valid.
        False if invalid or tampered.
    """

    try:
        public_key = VerifyKey(
            public_key_bytes
        )

        canonical_data = _canonical_json(
            data
        )

        signature = bytes.fromhex(
            signature_hex
        )

        public_key.verify(
            canonical_data.encode("utf-8"),
            signature
        )

        return True

    except (
        exceptions.BadSignatureError,
        ValueError,
        TypeError
    ):
        return False


class NonceTracker:
    """
    Provides basic replay protection.
    """

    def __init__(self):
        self.used_nonces = set()

    def is_valid(
        self,
        nonce: str,
        expiry: datetime
    ) -> bool:
        """
        Check if a nonce is unused and not expired.
        """

        current_time = datetime.now(
            timezone.utc
        )

        # Treat naive datetime as UTC
        if expiry.tzinfo is None:
            expiry = expiry.replace(
                tzinfo=timezone.utc
            )

        # Reject expired Work Orders
        if expiry <= current_time:
            return False

        # Reject reused nonces
        if nonce in self.used_nonces:
            return False

        return True

    def mark_used(
        self,
        nonce: str
    ):
        """
        Mark a nonce as used.
        """

        self.used_nonces.add(nonce)