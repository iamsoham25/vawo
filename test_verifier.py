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