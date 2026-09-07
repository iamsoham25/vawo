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

