from datetime import datetime, timedelta, timezone

from gateway import ToolGateway
from signing import (
    NonceTracker,
    generate_keypair,
    sign_data
)
from verifier import Verifier

# ==========================================================
# HELPER FUNCTION
# ==========================================================

def print_result(
    scenario_name,
    result
):
    """
    Print a VerificationResult in a readable format.
    """

    print("\n")
    print("=" * 70)
    print(scenario_name)
    print("=" * 70)

    print(
        f"\nAccepted: {result.accepted}"
    )

    print(
        f"Reason: {result.reason}"
    )

    print("\nChecks Passed:")

    for check in result.checks_passed:
        print(f"  ✓ {check}")

    print("\nChecks Failed:")

    if result.checks_failed:

        for check in result.checks_failed:
            print(f"  ✗ {check}")

    else:
        print("  None")


# ==========================================================
# STEP 1: CREATE REQUESTER AND WORKER KEYPAIRS
# ==========================================================

print("\n")
print("=" * 70)
print("STEP 1: CREATING REQUESTER AND WORKER")
print("=" * 70)

requester_private_key, requester_public_key = (
    generate_keypair()
)

worker_private_key, worker_public_key = (
    generate_keypair()
)

print("Requester keypair generated.")
print("Worker keypair generated.")


# ==========================================================
# STEP 2: CREATE NONCE TRACKER
# ==========================================================

nonce_tracker = NonceTracker()

# ==========================================================
# STEP 3: CREATE VERIFIER
# ==========================================================

agent_public_keys = {
    "requester-001": requester_public_key,
    "worker-001": worker_public_key
}

verifier = Verifier(
    nonce_tracker=nonce_tracker,
    agent_public_keys=agent_public_keys
)

# ==========================================================
# STEP 4: CREATE AND SIGN WORK ORDER
# ==========================================================

print("\n")
print("=" * 70)
print("STEP 2: CREATING SIGNED WORK ORDER")
print("=" * 70)

work_order_expiry = (
    datetime.now(timezone.utc)
    + timedelta(minutes=5)
)

work_order = {
    "task_id": "task-001",

    "nonce": "nonce-task-001",

    "input_digest": "input-digest-123",

    "tool_allowlist": [
        "calculator"
    ],

    "max_runtime_sec": 10,

    "expiry": work_order_expiry,

    "expected_output_schema": {
        "type": "object",
        "properties": {
            "result": {
                "type": "integer"
            }
        }
    }
}


# Sign Work Order
work_order_signature = sign_data(
    requester_private_key,
    work_order
)

work_order["signature"] = (
    work_order_signature
)

print("Work Order signed by Requester.")


# ==========================================================
# STEP 5: VERIFY WORK ORDER
# ==========================================================

