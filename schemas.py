from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class Receipt(BaseModel):
    """Represents one tool execution event."""

    event_id: str
    parent_event_hash: Optional[str] = None
    tool_name: str
    tool_version: str
    request_hash: str
    response_hash: str
    timestamp: datetime
    authorization_token_id: str


class WorkOrder(BaseModel):
    """Represents a work order for an AI agent."""

    task_id: str
    nonce: str
    input_digest: str
    tool_allowlist: list[str]
    max_runtime_sec: int
    expiry: datetime
    expected_output_schema: dict


class ExecutionManifest(BaseModel):
    """Represents the final execution result and verification data."""

    task_id: str
    result_artifact: dict
    merkle_root: str
    receipts: list[Receipt]