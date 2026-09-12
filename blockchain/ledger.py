"""
blockchain/ledger.py

A simple, self-contained blockchain implementation used to give ESG
climate reports tamper-evident cryptographic tracking metadata. This is
NOT a distributed / consensus blockchain - it is a local, hash-chained
audit ledger (a common lightweight pattern for tamper-evidence in
regulated reporting pipelines).

Each Block contains:
    - index: position in the chain
    - timestamp: ISO8601 UTC creation time
    - data: arbitrary string payload (e.g. a serialized ESG report)
    - previous_hash: SHA-256 hash of the previous block
    - hash: SHA-256 hash of this block's own contents
"""

import hashlib
import json
from datetime import datetime, timezone


class Block:
    def __init__(self, index: int, timestamp: str, data: str, previous_hash: str):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.compute_hash()

    def compute_hash(self) -> str:
        block_string = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self) -> dict:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


class Blockchain:
    def __init__(self):
        self.chain = []
        self._create_genesis_block()

    def _create_genesis_block(self):
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data="GENESIS_BLOCK::EcoCaptureOS::LedgerInitialized",
            previous_hash="0" * 64,
        )
        self.chain.append(genesis)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, data: str) -> Block:
        previous_block = self.get_latest_block()
        new_block = Block(
            index=previous_block.index + 1,
            timestamp=datetime.now(timezone.utc).isoformat(),
            data=data,
            previous_hash=previous_block.hash,
        )
        self.chain.append(new_block)
        return new_block

    def is_chain_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.compute_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

    def to_list(self) -> list:
        return [block.to_dict() for block in self.chain]

    def __len__(self):
        return len(self.chain)


# A single module-level ledger instance shared across the running
# Streamlit process, so ESG report signatures accumulate into one
# continuous chain for the lifetime of the app session/process.
_global_ledger = Blockchain()


def get_global_ledger() -> Blockchain:
    return _global_ledger


def sign_payload(payload: str) -> dict:
    """
    Convenience helper: appends `payload` as a new block on the global
    ledger and returns the resulting block's tracking metadata, suitable
    for embedding into an ESG report as a cryptographic signature.
    """
    block = _global_ledger.add_block(payload)
    return block.to_dict()
