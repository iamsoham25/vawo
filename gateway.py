import hashlib
import json
import subprocess
import sys
import uuid

from datetime import datetime, timezone

from schemas import Receipt


class ToolGateway:
    """
    Executes Python code locally and creates a tamper-evident
    receipt chain.
    """

    def __init__(
        self,
        timeout_sec=10,
        tool_version="1.0.0",
        authorization_token_id="local-token"
    ):
        self.timeout_sec = timeout_sec
        self.tool_version = tool_version
        self.authorization_token_id = authorization_token_id

        # Stores all execution receipts
        self.receipt_chain = []

    def _hash_data(self, data):
        """
        Convert data into consistent JSON and return SHA-256 hash.
        """

        json_data = json.dumps(
            data,
            sort_keys=True,
            default=str
        )

        return hashlib.sha256(
            json_data.encode("utf-8")
        ).hexdigest()

    def _get_receipt_hash(self, receipt):
        """
        Return the SHA-256 hash of a receipt.
        """

        receipt_data = receipt.model_dump(mode="json")

        return self._hash_data(receipt_data)

    def execute(self, tool_name, code, input_data):
        """
        Execute Python code in a subprocess.

        input_data is provided to the subprocess through stdin.

        A receipt is automatically created after execution.
        """

        # --------------------------------------------------
        # 1. Create request hash
        # --------------------------------------------------

        request_data = {
            "tool_name": tool_name,
            "code": code,
            "input_data": input_data
        }

        request_hash = self._hash_data(request_data)

        # --------------------------------------------------
        # 2. Get previous receipt hash
        # --------------------------------------------------

        if len(self.receipt_chain) == 0:
            parent_event_hash = None
        else:
            previous_receipt = self.receipt_chain[-1]

            parent_event_hash = self._get_receipt_hash(
                previous_receipt
            )

        # --------------------------------------------------
        # 3. Run the Python code
        # --------------------------------------------------

        try:
            result = subprocess.run(
                [sys.executable, "-c", code],
                input=json.dumps(input_data),
                text=True,
                capture_output=True,
                timeout=self.timeout_sec
            )

            stdout = result.stdout
            stderr = result.stderr
            exit_code = result.returncode

        except subprocess.TimeoutExpired:

            stdout = ""
            stderr = (
                f"Execution timed out after "
                f"{self.timeout_sec} seconds."
            )
            exit_code = -1

        # --------------------------------------------------
        # 4. Create response hash
        # --------------------------------------------------

        response_data = {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code
        }

        response_hash = self._hash_data(response_data)

        # --------------------------------------------------
        # 5. Create receipt
        # --------------------------------------------------

        receipt = Receipt(
            event_id=str(uuid.uuid4()),
            parent_event_hash=parent_event_hash,
            tool_name=tool_name,
            tool_version=self.tool_version,
            request_hash=request_hash,
            response_hash=response_hash,
            timestamp=datetime.now(timezone.utc),
            authorization_token_id=self.authorization_token_id
        )

        # Add receipt to the chain
        self.receipt_chain.append(receipt)

        # --------------------------------------------------
        # 6. Return execution result
        # --------------------------------------------------

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code
        }

    def get_merkle_root(self):
        """
        Calculate a binary Merkle root for all receipts.
        """

        # No receipts
        if not self.receipt_chain:
            return None

        # Create hashes for all receipts
        hashes = []

        for receipt in self.receipt_chain:
            receipt_hash = self._get_receipt_hash(receipt)
            hashes.append(receipt_hash)

        # Build the Merkle tree
        while len(hashes) > 1:

            # If odd number of hashes,
            # duplicate the last one
            if len(hashes) % 2 != 0:
                hashes.append(hashes[-1])

            new_level = []

            # Combine pairs of hashes
            for i in range(0, len(hashes), 2):

                left = hashes[i]
                right = hashes[i + 1]

                combined = left + right

                parent_hash = hashlib.sha256(
                    combined.encode("utf-8")
                ).hexdigest()

                new_level.append(parent_hash)

            hashes = new_level

        return hashes[0]

    def verify_chain_integrity(self):
        """
        Verify that every receipt correctly points to
        the previous receipt.
        """

        # Empty chain is valid
        if not self.receipt_chain:
            return True

        # First receipt must not have a parent
        if self.receipt_chain[0].parent_event_hash is not None:
            return False

        # Check every receipt after the first one
        for i in range(1, len(self.receipt_chain)):

            previous_receipt = self.receipt_chain[i - 1]
            current_receipt = self.receipt_chain[i]

            # Calculate expected parent hash
            expected_hash = self._get_receipt_hash(
                previous_receipt
            )

            # Compare with stored parent hash
            if current_receipt.parent_event_hash != expected_hash:
                return False

        return True