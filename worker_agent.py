import json
import uvicorn

from a2a.helpers import (
    get_data_parts,
    new_data_part,
    new_data_message,
    new_task_from_user_message
)

from a2a.server.agent_execution import (
    AgentExecutor,
    RequestContext
)

from a2a.server.events import EventQueue

from a2a.server.request_handlers import (
    DefaultRequestHandler
)

from a2a.server.routes import (
    create_agent_card_routes,
    create_jsonrpc_routes
)

from a2a.server.tasks import (
    InMemoryTaskStore,
    TaskUpdater
)

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    TaskState
)

from starlette.applications import Starlette

from gateway import ToolGateway
from schemas import ExecutionManifest
from signing import generate_keypair, sign_data


HOST = "127.0.0.1"
PORT = 9999

AGENT_ID = "worker-001"

PUBLIC_KEY_FILE = "worker_public_key.hex"


class VAWOWorkerExecutor(AgentExecutor):

    def __init__(self):
        print()
        print("=" * 70)
        print("INITIALIZING VAWO WORKER")
        print("=" * 70)

        (self.private_key, self.public_key) = generate_keypair()

        print("Worker Ed25519 keypair generated.")

        with open(PUBLIC_KEY_FILE, "w", encoding="utf-8") as file:
            file.write(self.public_key.hex())

        print(f"Worker public key saved to: {PUBLIC_KEY_FILE}")

        self.gateway = ToolGateway(
            timeout_sec=10,
            tool_version="1.0.0",
            authorization_token_id="worker-local-token"
        )

        print("ToolGateway initialized.")

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        print()
        print("=" * 70)
        print("A2A TASK RECEIVED")
        print("=" * 70)

        if context.current_task:
            task = context.current_task
        else:
            task = new_task_from_user_message(context.message)
            await event_queue.enqueue_event(task)

        print(f"Task ID: {task.id}")
        print(f"Context ID: {task.context_id}")

        task_updater = TaskUpdater(
            event_queue=event_queue,
            task_id=task.id,
            context_id=task.context_id
        )

        await task_updater.start_work(
            message=new_data_message({"status": "Worker received the task"}, media_type="application/json")
        )

        if context.message is None:
            await task_updater.failed(
                message=new_data_message({"error": "No A2A message received"}, media_type="application/json")
            )
            return

        data_parts = get_data_parts(context.message.parts)

        if not data_parts:
            await task_updater.failed(
                message=new_data_message(
                    {"error": "Expected structured JSON data in A2A message"},
                    media_type="application/json"
                )
            )
            return

        request_data = data_parts[0]

        print()
        print("A2A request data:")
        print(json.dumps(request_data, indent=2, default=str))

        work_order = request_data.get("work_order")
        input_data = request_data.get("input_data")

        if not work_order or not input_data:
            await task_updater.failed(
                message=new_data_message(
                    {"error": "A2A request must contain work_order and input_data"},
                    media_type="application/json"
                )
            )
            return

        print()
        print("Work Order received.")
        print(f"Task ID: {work_order.get('task_id')}")
        print(f"Nonce: {work_order.get('nonce')}")

        print()
        print("Input data received:")
        print(input_data)

        print()
        print("=" * 70)
        print("EXECUTING THROUGH TOOLGATEWAY")
        print("=" * 70)

        tool_name = "calculator"

        code = """
import json
import sys
data = json.load(sys.stdin)
result = int(data["a"]) + int(data["b"])
print(result)
"""

        execution_result = self.gateway.execute(
            tool_name=tool_name,
            code=code,
            input_data=input_data
        )

        print()
        print("ToolGateway execution result:")
        print(execution_result)

        stdout = execution_result["stdout"].strip()
        try:
            result_value = int(stdout.strip())
        except ValueError:
            result_value = stdout

        result_artifact = {"result": result_value}

        print()
        print("Result artifact:")
        print(result_artifact)

        merkle_root = self.gateway.get_merkle_root()

        print()
        print("Merkle root:")
        print(merkle_root)

        manifest = ExecutionManifest(
            task_id=work_order["task_id"],
            result_artifact=result_artifact,
            merkle_root=merkle_root,
            receipts=self.gateway.receipt_chain
        )

        manifest_data = manifest.model_dump(mode="json", exclude={"signature"})

        print()
        print("=" * 70)
        print("EXECUTION MANIFEST BUILT")
        print("=" * 70)

        print(json.dumps(manifest_data, indent=2))

        signature = sign_data(self.private_key, manifest_data)

        manifest_data["signature"] = signature

        manifest_json_str = json.dumps(manifest_data, sort_keys=True, separators=(",", ":"))

        print()
        print("Execution Manifest signed.")
        print(f"Signature: {signature}")

        response_payload = {
            "worker_agent_id": AGENT_ID,
            "manifest_json": manifest_json_str
        }

        print()
        print("=" * 70)
        print("RETURNING SIGNED MANIFEST THROUGH A2A")
        print("=" * 70)

        print(json.dumps(response_payload, indent=2))

        await task_updater.add_artifact(
            parts=[new_data_part(response_payload, media_type="application/json")],
            name="vawo-execution-manifest",
            last_chunk=True
        )

        await task_updater.complete(
            message=new_data_message(
                {"status": "VAWO execution manifest returned successfully"},
                media_type="application/json"
            )
        )

        print()
        print("=" * 70)
        print("A2A TASK COMPLETED")
        print("=" * 70)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        print("A2A cancellation requested.")
        raise Exception("VAWO Worker does not support cancellation in this Phase 4 demo.")


def create_agent_card():
    skill = AgentSkill(
        id="calculator-transform",
        name="calculator-transform",
        description="Accepts JSON containing integer values a and b and returns their sum through the VAWO ToolGateway.",
        tags=["calculator", "arithmetic", "vawo"],
        examples=['{"a": 10, "b": 20}'],
        input_modes=["application/json"],
        output_modes=["application/json"]
    )

    agent_card = AgentCard(
        name="VAWO Worker Agent",
        description="A VAWO Worker agent that executes calculator tasks through ToolGateway and returns cryptographically signed Execution Manifests.",
        version="1.0.0",
        default_input_modes=["application/json"],
        default_output_modes=["application/json"],
        capabilities=AgentCapabilities(streaming=True),
        supported_interfaces=[
            AgentInterface(
                protocol_binding="JSONRPC",
                url=f"http://{HOST}:{PORT}",
                protocol_version="1.0"
            )
        ],
        skills=[skill]
    )

    return agent_card


def main():
    agent_card = create_agent_card()
    executor = VAWOWorkerExecutor()

    request_handler = DefaultRequestHandler(
        agent_executor=executor,
        task_store=InMemoryTaskStore(),
        agent_card=agent_card
    )

    routes = []
    routes.extend(create_agent_card_routes(agent_card))
    routes.extend(create_jsonrpc_routes(request_handler, "/"))

    app = Starlette(routes=routes)

    print()
    print("=" * 70)
    print("VAWO WORKER A2A SERVER")
    print("=" * 70)
    print(f"Agent ID: {AGENT_ID}")
    print(f"Agent Card: http://{HOST}:{PORT}/.well-known/agent-card.json")
    print(f"A2A JSON-RPC endpoint: http://{HOST}:{PORT}/")
    print("Skill: calculator-transform")
    print("Waiting for A2A tasks...")
    print("=" * 70)

    uvicorn.run(app, host=HOST, port=PORT)


if __name__ == "__main__":
    main()