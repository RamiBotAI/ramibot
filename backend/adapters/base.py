from abc import ABC, abstractmethod
from typing import AsyncGenerator


class BaseAdapter(ABC):
    provider_name: str = ""

    @abstractmethod
    async def capabilities(self) -> dict:
        """Return dict with keys: streaming, tool_calling, reasoning, models."""
        ...

    @abstractmethod
    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict:
        """Non-streaming generation. Return dict with keys: content, role, token_usage, tool_calls."""
        ...

    @abstractmethod
    async def stream(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        """Streaming generation. Yield dicts with type: token|tool_call|usage|done|error."""
        ...

    @abstractmethod
    async def list_models(self) -> list[dict]:
        """Return list of dicts with keys: name, id."""
        ...
