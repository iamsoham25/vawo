from gateway import ToolGateway


# Create ToolGateway
gateway = ToolGateway()


# ==================================================
# EXECUTION 1
# ==================================================

code_1 = """
import json
import sys

data = json.load(sys.stdin)

result = data["a"] + data["b"]

print("Result:", result)
"""

result_1 = gateway.execute(
    tool_name="calculator",
    code=code_1,
    input_data={
        "a": 10,
        "b": 20
    }
)

print("\nExecution 1:")
print(result_1)


# ==================================================
# EXECUTION 2
# ==================================================

code_2 = """
import json
import sys

data = json.load(sys.stdin)

text = data["text"]

print(text.upper())
"""

result_2 = gateway.execute(
    tool_name="string_tool",
    code=code_2,
    input_data={
        "text": "hello vawo"
    }
)

print("\nExecution 2:")
print(result_2)


# ==================================================
# EXECUTION 3
# ==================================================

code_3 = """
import json
import sys

data = json.load(sys.stdin)

numbers = data["numbers"]

print("Sum:", sum(numbers))
"""

result_3 = gateway.execute(
    tool_name="list_tool",
    code=code_3,
    input_data={
        "numbers": [10, 20, 30]
    }
)

print("\nExecution 3:")
print(result_3)


# ==================================================
# PRINT RECEIPT CHAIN
# ==================================================

print("\n")
print("=" * 60)
print("FULL RECEIPT CHAIN")
print("=" * 60)

for index, receipt in enumerate(
    gateway.receipt_chain,
    start=1
):
    print(f"\nReceipt {index}")
    print(receipt.model_dump_json(indent=2))


# ==================================================
# PRINT MERKLE ROOT
# ==================================================

print("\n")
print("=" * 60)
print("MERKLE ROOT")
print("=" * 60)

merkle_root = gateway.get_merkle_root()

print(merkle_root)


# ==================================================
# VERIFY ORIGINAL CHAIN
# ==================================================

print("\n")
print("=" * 60)
print("VERIFY ORIGINAL CHAIN")
print("=" * 60)

is_valid = gateway.verify_chain_integrity()

print("Chain integrity:", is_valid)

assert is_valid is True


# ==================================================
# TAMPER WITH RECEIPT
# ==================================================

print("\n")
print("=" * 60)
print("TAMPERING WITH RECEIPT 2")
print("=" * 60)

# Change the response hash manually
gateway.receipt_chain[1].response_hash = "FAKE_HASH"


# ==================================================
# VERIFY TAMPERED CHAIN
# ==================================================

print("\n")
print("=" * 60)
print("VERIFY TAMPERED CHAIN")
print("=" * 60)

is_valid_after_tampering = (
    gateway.verify_chain_integrity()
)

print(
    "Chain integrity after tampering:",
    is_valid_after_tampering
)

assert is_valid_after_tampering is False


print("\nSUCCESS!")
print("Tampering was detected successfully.")