"""
PiranhaDB — Store protocols.

Defines the interface that all store implementations must satisfy.
Routers import from store/__init__.py — never from concrete implementations.

Upgrade path:
    Phase 1: file-based (current)   — no env vars needed
    Phase 2: PostgreSQL              — set DATABASE_URL
    Phase 3: PostgreSQL + Redis      — set DATABASE_URL + REDIS_URL

Zero router changes at any phase.
"""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class RecordsStoreProtocol(Protocol):
    def get_all(self) -> dict[str, dict]: ...
    def get_one(self, ave_id: str) -> Optional[dict]: ...
    def reload(self) -> int: ...
    def count(self) -> int: ...


@runtime_checkable
class ScanStoreProtocol(Protocol):
    def save_scan(self, source: str, data: dict) -> None: ...
    def get_latest(self, source: str) -> Optional[dict]: ...
    def get_history(self, source: str, limit: int) -> list[dict]: ...
    def save_submission(self, content: str, result: dict) -> str: ...
    def get_submission(self, sid: str) -> Optional[dict]: ...
    