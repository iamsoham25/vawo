import asyncio
import hashlib
import json

from datetime import (
    datetime,
    timedelta,
    timezone
)

from a2a.client import (
    A2ACardResolver,
    ClientConfig,
    create_client
)

from a2a.helpers import (
    get_data_parts,
    new_data_message
)

from a2a.types import (
    Role,
    SendMessageRequest
)

from schemas import Receipt
from signing import (
    NonceTracker,
    generate_keypair,
    sign_data
)
from verifier import Verifier


# ==========================================================
# CONFIGURATION
# ==========================================================

WORKER_URL = (
    "http://127.0.0.1:9999"
)

WORKER_AGENT_ID = (
    "worker-001"
)

WORKER_PUBLIC_KEY_FILE = (
    "worker_public_key.hex"
)


# ==========================================================
# INPUT
# ==========================================================

INPUT_DATA = {
    "a": 10,
    "b": 20
}


# ==========================================================
# CANONICAL INPUT HASH
# ==========================================================

def calculate_input_digest(
    input_data: dict
) -> str:
    """
    Calculate SHA-256 digest of the actual input data.

    Uses the same canonical JSON approach used
    by the VAWO trust layer.
    """

    canonical_json = json.dumps(
        input_data,
        sort_keys=True,
        separators=(",", ":"),
        default=str
    )

    return hashlib.sha256(
        canonical_json.encode("utf-8")
    ).hexdigest()


# ==========================================================
# LOAD WORKER PUBLIC KEY
# ==========================================================

def load_worker_public_key() -> bytes:
    """
    Load the Worker public key from the local
    Phase 4 trust-anchor file.
    """

    with open(
        WORKER_PUBLIC_KEY_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        public_key_hex = (
            file.read().strip()
        )

    return bytes.fromhex(
        public_key_hex
    )


# ==========================================================
# EXTRACT MANIFEST FROM A2A TASK
# ==========================================================

def extract_manifest_from_task(task) -> dict:
    if not task.artifacts:
        raise RuntimeError("A2A Task contains no artifacts.")

    for artifact in task.artifacts:
        data_parts = get_data_parts(artifact.parts)
        for data in data_parts:
            if isinstance(data, dict) and "manifest_json" in data:
                return json.loads(data["manifest_json"])  # exact values preserved

    raise RuntimeError("VAWO Execution Manifest was not found in the A2A Task artifacts.")


# ==========================================================
# MAIN REQUESTER FLOW
# ==========================================================

async def main():
    """
    Run the complete Requester → Worker A2A flow.
    """

    # ======================================================
    # STEP 1: REQUESTER KEYPAIR
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 1: INITIALIZING REQUESTER")
    print("=" * 70)

    (
        requester_private_key,
        requester_public_key
    ) = generate_keypair()

    print(
        "Requester Ed25519 keypair generated."
    )


    # ======================================================
    # STEP 2: DISCOVER WORKER AGENT CARD
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 2: DISCOVERING WORKER AGENT CARD")
    print("=" * 70)

    async with __import__(
        "httpx"
    ).AsyncClient() as httpx_client:

        resolver = A2ACardResolver(
            httpx_client=httpx_client,
            base_url=WORKER_URL
        )

        worker_card = (
            await resolver.get_agent_card()
        )

    print(
        "Agent Card successfully discovered."
    )

    print(
        f"\nAgent name: "
        f"{worker_card.name}"
    )

    print(
        f"Agent version: "
        f"{worker_card.version}"
    )

    print(
        "\nDiscovered skills:"
    )

    for skill in worker_card.skills:

        print(
            f"  - {skill.name}"
        )

    print(
        "\nWorker Agent Card confirms "
        "calculator-transform skill."
    )


    # ======================================================
    # STEP 3: LOAD WORKER TRUST ANCHOR
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 3: LOADING WORKER PUBLIC KEY")
    print("=" * 70)

    worker_public_key = (
        load_worker_public_key()
    )

    print(
        "Worker public key loaded."
    )

    print(
        f"Public key: "
        f"{worker_public_key.hex()}"
    )


    # ======================================================
    # STEP 4: CREATE WORK ORDER
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 4: CREATING WORK ORDER")
    print("=" * 70)

    task_id = (
        "vawo-task-001"
    )

    nonce = (
        "vawo-nonce-001"
    )

    expiry = (
        datetime.now(timezone.utc)
        + timedelta(minutes=5)
    )

    input_digest = (
        calculate_input_digest(
            INPUT_DATA
        )
    )

    work_order = {
        "task_id": task_id,

        "nonce": nonce,

        "input_digest": input_digest,

        "tool_allowlist": [
            "calculator"
        ],

        "max_runtime_sec": 10,

        "expiry": expiry.isoformat(),

        "expected_output_schema": {
            "type": "object",

            "properties": {
                "result": {
                    "type": "integer"
                }
            }
        }
    }

    print(
        "Work Order created:"
    )

    print(
        json.dumps(
            work_order,
            indent=2
        )
    )


    # ======================================================
    # STEP 5: SIGN WORK ORDER
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 5: SIGNING WORK ORDER")
    print("=" * 70)

    work_order_signature = sign_data(
        requester_private_key,
        work_order
    )

    work_order["signature"] = (
        work_order_signature
    )

    print(
        "Work Order signed successfully."
    )

    print(
        f"Signature: "
        f"{work_order_signature}"
    )


    # ======================================================
    # STEP 6: CREATE NONCE TRACKER
    # ======================================================

    nonce_tracker = NonceTracker()


    # ======================================================
    # STEP 7: CREATE VERIFIER
    # ======================================================

    agent_public_keys = {
        WORKER_AGENT_ID: worker_public_key
    }

    verifier = Verifier(
        nonce_tracker=nonce_tracker,
        agent_public_keys=agent_public_keys
    )


    # ======================================================
    # STEP 8: CREATE A2A CLIENT
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 6: CREATING A2A CLIENT")
    print("=" * 70)

    client_config = ClientConfig(
        streaming=False,
        accepted_output_modes=[
            "application/json"
        ]
    )

    client = await create_client(
        agent=worker_card,
        client_config=client_config
    )

    print(
        "A2A client created from discovered Agent Card."
    )


    # ======================================================
    # STEP 9: BUILD A2A MESSAGE
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 7: SENDING A2A TASK")
    print("=" * 70)

    a2a_payload = {
        "work_order": work_order,

        "input_data": INPUT_DATA
    }

    print(
        "Sending:"
    )

    print(
        json.dumps(
            a2a_payload,
            indent=2
        )
    )

    message = new_data_message(
        a2a_payload,
        media_type="application/json",
        role=Role.ROLE_USER
    )

    request = SendMessageRequest(
        message=message
    )


    # ======================================================
    # STEP 10: WAIT FOR A2A TASK COMPLETION
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 8: WAITING FOR WORKER")
    print("=" * 70)

    final_task = None

    async for response in client.send_message(
        request
    ):

        if response.HasField(
            "task"
        ):

            final_task = response.task

            print(
                f"Received A2A Task: "
                f"{final_task.id}"
            )

    await client.close()

    if final_task is None:

        raise RuntimeError(
            "Worker did not return an A2A Task."
        )

    print()
    print(
        "A2A Task completed."
    )

    print(
        f"Task state: "
        f"{final_task.status.state}"
    )


    # ======================================================
    # STEP 11: EXTRACT EXECUTION MANIFEST
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 9: RECEIVING EXECUTION MANIFEST")
    print("=" * 70)

    manifest_dict = (
        extract_manifest_from_task(
            final_task
        )
    )

    print(
        "Signed Execution Manifest received."
    )

    print(
        json.dumps(
            manifest_dict,
            indent=2
        )
    )


    # ======================================================
    # STEP 12: CONVERT RECEIPTS
    # ======================================================

    receipt_chain = []

    for receipt_data in (
        manifest_dict["receipts"]
    ):

        receipt = Receipt.model_validate(
            receipt_data
        )

        receipt_chain.append(
            receipt
        )

    print()
    print(
        f"Received "
        f"{len(receipt_chain)} receipt(s)."
    )


    # ======================================================
    # STEP 13: INDEPENDENT RE-EXECUTION
    # ======================================================

    def reexecution_fn():
        """
        Independently calculate the expected answer.

        This does NOT use the Worker's Gateway.
        """

        result = (
            INPUT_DATA["a"]
            + INPUT_DATA["b"]
        )

        return {
            "result": result
        }


    # ======================================================
    # STEP 14: VERIFY EXECUTION
    # ======================================================

    print()
    print("=" * 70)
    print("STEP 10: VERIFYING WORKER EXECUTION")
    print("=" * 70)

    verification_result = (
        verifier.verify_execution(
            manifest_dict=manifest_dict,

            receipt_chain=receipt_chain,

            worker_agent_id=WORKER_AGENT_ID,

            tool_allowlist=[
                "calculator"
            ],

            reexecution_fn=reexecution_fn
        )
    )


    # ======================================================
    # STEP 15: PRINT FINAL RESULT
    # ======================================================

    print()
    print("=" * 70)
    print("FINAL VAWO VERIFICATION RESULT")
    print("=" * 70)

    print(
        f"\nAccepted: "
        f"{verification_result.accepted}"
    )

    print(
        f"\nReason:"
    )

    print(
        verification_result.reason
    )

    print(
        "\nChecks Passed:"
    )

    for check in (
        verification_result.checks_passed
    ):

        print(
            f"  ✓ {check}"
        )

    print(
        "\nChecks Failed:"
    )

    if verification_result.checks_failed:

        for check in (
            verification_result.checks_failed
        ):

            print(
                f"  ✗ {check}"
            )

    else:

        print(
            "  None"
        )

    print()
    print("=" * 70)

    if verification_result.accepted:

        print(
            "VAWO TRUST DECISION: ACCEPTED"
        )

    else:

        print(
            "VAWO TRUST DECISION: REJECTED"
        )

    print("=" * 70)


# ==========================================================
# ENTRY POINT
# ==========================================================

if __name__ == "__main__":
    asyncio.run(
        main()
    )