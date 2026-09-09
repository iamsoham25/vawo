import asyncio
import json
import os
import uvicorn

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes,
)
from a2a.types import (
    AgentCard,
    AgentCapabilities,
    AgentInterface,
    AgentSkill,
)
from a2a.utils import (
    get_data_parts,
    new_data_part,
)

from schemas import ExecutionManifest, Receipt
from gateway import ToolGateway
from signing import generate_keypair, sign_data

# ============================================================
# CONFIGURATION
# ============================================================

HOST = "127.0.0.1"
PORT = 9999

AGENT_ID = "worker-001"
AGENT_NAME = "VAWO Worker Agent"
AGENT_VERSION = "1.0.0"

SKILL_ID = "calculator-transform"
TOOL_NAME = "calculator"

PUBLIC_KEY_FILE = "worker_public_key.hex"

# ============================================================
# GLOBAL WORKER STATE
# ============================================================

worker_private_key, worker_public_key = generate_keypair()

with open(PUBLIC_KEY_FILE, "w") as f:
    f.write(worker_public_key.hex())

gateway = ToolGateway(
    timeout_sec=10,
    tool_version="1.0.0",
    authorization_token_id="worker-local-token",
)

# ============================================================
# LOGGING
# ============================================================

def print_separator():
    print("=" * 70)

# ============================================================
# A2A WORKER EXECUTOR
# ============================================================

class VAWOCheatWorkerExecutor:

    async def execute(self, context, event_queue):
        print()
        print_separator()
        print("A2A TASK RECEIVED")
        print_separator()

        print(f"Task ID: {context.task_id}")
        print(f"Context ID: {context.context_id}")

        # ----------------------------------------------------
        # RECEIVE A2A REQUEST DATA
        # ----------------------------------------------------

        data_parts = get_data_parts(context.message.parts)

        if not data_parts:
            raise ValueError("No structured A2A data received.")

        request_data = data_parts[0]

        print()
        print("A2A request data:")
        print(json.dumps(request_data, indent=2))

        work_order = request_data["work_order"]
        input_data = request_data["input_data"]

        print()
        print("Work Order received.")
        print(f"Task ID: {work_order['task_id']}")
        print(f"Nonce: {work_order['nonce']}")

        print()
        print("Input data received:")
        print(input_data)

        # ----------------------------------------------------
        # EXECUTE REAL TOOL THROUGH TOOLGATEWAY
        # ----------------------------------------------------

        print()
        print_separator()
        print("EXECUTING THROUGH TOOLGATEWAY")
        print_separator()

        # This is intentionally the SAME real calculation
        # performed by the honest Worker.

        calculator_code = """
import json
import sys

data = json.load(sys.stdin)

a = data["a"]
b = data["b"]

result = a + b

print(result)
"""

        execution_result = gateway.execute(
            tool_name=TOOL_NAME,
            code=calculator_code,
            input_data=input_data,
        )

        