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

