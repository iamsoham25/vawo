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

work_order_verification = (
    verifier.verify_work_order(
        work_order,
        "requester-001"
    )
)

print_result(
    "WORK ORDER VERIFICATION",
    work_order_verification
)

assert work_order_verification.accepted is True

# ==========================================================
# STEP 6: CREATE REAL TOOL CODE
# ==========================================================


code = """
import json
import sys

data = json.load(sys.stdin)

result = data["a"] + data["b"]

print(result)
"""


input_data = {
    "a": 10,
    "b": 20
}

# ==========================================================
# SCENARIO A: HONEST WORKER
# ==========================================================

print("\n")
print("=" * 70)
print("SCENARIO A: HONEST WORKER")
print("=" * 70)

honest_gateway = ToolGateway(
    timeout_sec=5
)


# Worker executes through ToolGateway
execution_result = honest_gateway.execute(
    tool_name="calculator",
    code=code,
    input_data=input_data
)

print(
    "\nGateway execution result:"
)

print(execution_result)

# The actual answer produced by the task
honest_result_artifact = {
    "result": 30
}


# Get real Merkle root
honest_merkle_root = (
    honest_gateway.get_merkle_root()
)


# Create manifest
honest_manifest = {
    "task_id": "task-001",

    "result_artifact": honest_result_artifact,

    "merkle_root": honest_merkle_root,

    "receipts": honest_gateway.receipt_chain
}

# Sign manifest with Worker private key
honest_manifest_signature = sign_data(
    worker_private_key,
    honest_manifest
)

honest_manifest["signature"] = (
    honest_manifest_signature
)


# Independent re-execution function
def honest_reexecution():
    """
    Independently calculate the expected result.
    """

    result = (
        input_data["a"]
        + input_data["b"]
    )

    return {
        "result": result
    }

# Verify honest execution
honest_verification = (
    verifier.verify_execution(
        manifest_dict=honest_manifest,
        receipt_chain=honest_gateway.receipt_chain,
        worker_agent_id="worker-001",
        tool_allowlist=[
            "calculator"
        ],
        reexecution_fn=honest_reexecution
    )
)

print_result(
    "HONEST WORKER RESULT",
    honest_verification
)

assert honest_verification.accepted is True

# ==========================================================
# SCENARIO B: CHEATING WORKER - FABRICATED RESULT
# ==========================================================

print("\n")
print("=" * 70)
print("SCENARIO B: CHEATING WORKER - FABRICATED RESULT")
print("=" * 70)


# Worker does NOT actually use the gateway.
# There are no real receipts.

fabricated_receipt_chain = []


# Worker invents a Merkle root
fabricated_merkle_root = (
    "fabricated-merkle-root"
)


fabricated_manifest = {
    "task_id": "task-001",

    "result_artifact": {
        "result": 30
    },

    "merkle_root": fabricated_merkle_root,

    "receipts": []
}


# Worker signs the fabricated manifest
fabricated_signature = sign_data(
    worker_private_key,
    fabricated_manifest
)

fabricated_manifest["signature"] = (
    fabricated_signature
)


# Re-execution would produce 30
def fabricated_reexecution():
    return {
        "result": 30
    }


fabricated_verification = (
    verifier.verify_execution(
        manifest_dict=fabricated_manifest,
        receipt_chain=fabricated_receipt_chain,
        worker_agent_id="worker-001",
        tool_allowlist=[
            "calculator"
        ],
        reexecution_fn=fabricated_reexecution
    )
)

print_result(
    "CHEATING WORKER - FABRICATED RESULT",
    fabricated_verification
)

assert fabricated_verification.accepted is False

assert (
    "Merkle root mismatch"
    in fabricated_verification.reason
)

# ==========================================================
# SCENARIO C: CHEATING WORKER - UNAUTHORIZED TOOL
# ==========================================================

print("\n")
print("=" * 70)
print("SCENARIO C: CHEATING WORKER - UNAUTHORIZED TOOL")
print("=" * 70)


unauthorized_gateway = ToolGateway(
    timeout_sec=5
)


# Worker actually executes code,
# but uses an unauthorized tool name.
unauthorized_gateway.execute(
    tool_name="dangerous-tool",
    code=code,
    input_data=input_data
)


unauthorized_merkle_root = (
    unauthorized_gateway.get_merkle_root()
)


unauthorized_manifest = {
    "task_id": "task-001",

    "result_artifact": {
        "result": 30
    },

    "merkle_root": unauthorized_merkle_root,

    "receipts": unauthorized_gateway.receipt_chain
}


# Sign the real manifest
unauthorized_signature = sign_data(
    worker_private_key,
    unauthorized_manifest
)

unauthorized_manifest["signature"] = (
    unauthorized_signature
)


def unauthorized_reexecution():
    return {
        "result": 30
    }


unauthorized_verification = (
    verifier.verify_execution(
        manifest_dict=unauthorized_manifest,
        receipt_chain=unauthorized_gateway.receipt_chain,
        worker_agent_id="worker-001",
        tool_allowlist=[
            "calculator"
        ],
        reexecution_fn=unauthorized_reexecution
    )
)

print_result(
    "CHEATING WORKER - UNAUTHORIZED TOOL",
    unauthorized_verification
)

assert unauthorized_verification.accepted is False

assert (
    "unauthorized tool"
    in unauthorized_verification.reason
)


# ==========================================================
# SCENARIO D: CHEATING WORKER - RE-EXECUTION MISMATCH
# ==========================================================

print("\n")
print("=" * 70)
print("SCENARIO D: CHEATING WORKER - RE-EXECUTION MISMATCH")
print("=" * 70)


lying_gateway = ToolGateway(
    timeout_sec=5
)


# Worker performs a genuine execution.
lying_gateway.execute(
    tool_name="calculator",
    code=code,
    input_data=input_data
)


lying_merkle_root = (
    lying_gateway.get_merkle_root()
)


# The execution really produced 30,
# but Worker claims the result was 999.
lying_manifest = {
    "task_id": "task-001",

    "result_artifact": {
        "result": 999
    },

    "merkle_root": lying_merkle_root,

    "receipts": lying_gateway.receipt_chain
}


# Worker signs the false claim.
lying_signature = sign_data(
    worker_private_key,
    lying_manifest
)

lying_manifest["signature"] = (
    lying_signature
)


# Independent execution knows the real answer.
def lying_reexecution():
    return {
        "result": 30
    }


lying_verification = (
    verifier.verify_execution(
        manifest_dict=lying_manifest,
        receipt_chain=lying_gateway.receipt_chain,
        worker_agent_id="worker-001",
        tool_allowlist=[
            "calculator"
        ],
        reexecution_fn=lying_reexecution
    )
)

print_result(
    "CHEATING WORKER - RE-EXECUTION MISMATCH",
    lying_verification
)

assert lying_verification.accepted is False

assert (
    "re-execution mismatch"
    in lying_verification.reason
)


# ==========================================================
# FINAL RESULT
# ==========================================================

print("\n")
print("=" * 70)
print("ALL PHASE 3 VERIFIER TESTS PASSED")
print("=" * 70)

print("\n✓ Requester identity verification: PASSED")
print("✓ Work Order signature verification: PASSED")
print("✓ Honest Worker verification: PASSED")
print("✓ Fabricated result detection: PASSED")
print("✓ Unauthorized tool detection: PASSED")
print("✓ Re-execution mismatch detection: PASSED")
