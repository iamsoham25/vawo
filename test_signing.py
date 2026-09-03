from datetime import (
    datetime,
    timedelta,
    timezone
)

from signing import (
    NonceTracker,
    generate_keypair,
    sign_data,
    verify_signature
)


# ==================================================
# GENERATE REQUESTER KEYPAIR
# ==================================================

print("\n")
print("=" * 60)
print("GENERATING REQUESTER ED25519 KEYPAIR")
print("=" * 60)

private_key, public_key = generate_keypair()

print("Private key generated successfully.")
print("Public key generated successfully.")


# ==================================================
# CREATE SAMPLE WORK ORDER
# ==================================================

print("\n")
print("=" * 60)
print("CREATING SAMPLE WORK ORDER")
print("=" * 60)

expiry_time = (
    datetime.now(timezone.utc)
    + timedelta(minutes=5)
)

work_order_data = {
    "task_id": "task-001",

    "nonce": "unique-nonce-001",

    "input_digest": "abc123inputdigest",

    "tool_allowlist": [
        "python-calculator",
        "python-string-tool"
    ],

    "max_runtime_sec": 30,

    "expiry": expiry_time,

    "expected_output_schema": {
        "type": "object",

        "properties": {
            "result": {
                "type": "string"
            }
        }
    }
}

print("Work Order created successfully.")


# ==================================================
# SIGN WORK ORDER
# ==================================================

print("\n")
print("=" * 60)
print("SIGNING WORK ORDER")
print("=" * 60)

signature = sign_data(
    private_key,
    work_order_data
)

# Attach signature to Work Order
work_order_data["signature"] = signature

print("Work Order signed successfully.")

print("\nSignature:")
print(signature)


# ==================================================
# VERIFY ORIGINAL WORK ORDER
# ==================================================

print("\n")
print("=" * 60)
print("VERIFYING ORIGINAL WORK ORDER")
print("=" * 60)

# Copy Work Order data
data_to_verify = work_order_data.copy()

# Remove signature because it was not part
# of the original signed data
data_to_verify.pop("signature")

is_valid = verify_signature(
    public_key,
    data_to_verify,
    signature
)

print(
    "Original signature valid:",
    is_valid
)

assert is_valid is True


# ==================================================
# TAMPER WITH WORK ORDER
# ==================================================

print("\n")
print("=" * 60)
print("TAMPERING WITH WORK ORDER")
print("=" * 60)

tampered_data = data_to_verify.copy()

# Change a signed field
tampered_data["max_runtime_sec"] = 999

print(
    "Changed max_runtime_sec "
    "from 30 to 999"
)


# ==================================================
# VERIFY TAMPERED WORK ORDER
# ==================================================

print("\n")
print("=" * 60)
print("VERIFYING TAMPERED WORK ORDER")
print("=" * 60)

tampered_is_valid = verify_signature(
    public_key,
    tampered_data,
    signature
)

print(
    "Signature valid after tampering:",
    tampered_is_valid
)

assert tampered_is_valid is False


# ==================================================
# TEST NONCE REPLAY PROTECTION
# ==================================================

print("\n")
print("=" * 60)
print("TESTING NONCE REPLAY PROTECTION")
print("=" * 60)

nonce_tracker = NonceTracker()

test_nonce = work_order_data["nonce"]


# Test fresh nonce
fresh_nonce_valid = nonce_tracker.is_valid(
    test_nonce,
    expiry_time
)

print(
    "Fresh nonce valid:",
    fresh_nonce_valid
)

assert fresh_nonce_valid is True


# Mark nonce as used
nonce_tracker.mark_used(
    test_nonce
)

print("Nonce marked as used.")


# Try to reuse the nonce
reused_nonce_valid = nonce_tracker.is_valid(
    test_nonce,
    expiry_time
)

print(
    "Reused nonce valid:",
    reused_nonce_valid
)

assert reused_nonce_valid is False


# ==================================================
# TEST EXPIRED WORK ORDER
# ==================================================

print("\n")
print("=" * 60)
print("TESTING EXPIRED WORK ORDER")
print("=" * 60)

expired_time = (
    datetime.now(timezone.utc)
    - timedelta(minutes=5)
)

expired_nonce_valid = nonce_tracker.is_valid(
    "expired-nonce-001",
    expired_time
)

print(
    "Expired Work Order valid:",
    expired_nonce_valid
)

assert expired_nonce_valid is False


# ==================================================
# FINAL RESULT
# ==================================================

print("\n")
print("=" * 60)
print("ALL PHASE 2 TESTS PASSED")
print("=" * 60)

print("\n1. Ed25519 keypair generation: PASSED")
print("2. Work Order signing: PASSED")
print("3. Signature verification: PASSED")
print("4. Tampering detection: PASSED")
print("5. Nonce replay protection: PASSED")
print("6. Expiry validation: PASSED")