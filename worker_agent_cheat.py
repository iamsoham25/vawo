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

