import json
import httpx
from typing import AsyncGenerator
from .base import BaseAdapter


class OllamaAdapter(BaseAdapter):
    provider_name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434"):
        self.base_url = base_url.rstrip("/")

    async def capabilities(self) -> dict:
        return {
            "streaming": True,
            "tool_calling": False,
            "reasoning": False,
            "models": [],
        }

    async def list_models(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.base_url}/api/tags")
            resp.raise_for_status()
            data = resp.json()
        models_list = data.get("models", [])
        return [{"name": m["name"], "id": m["name"]} for m in models_list]

    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict:
        payload = {"model": model, "messages": messages, "stream": False}
        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        message = data.get("message", {})
        eval_count = data.get("eval_count", 0)
        prompt_eval_count = data.get("prompt_eval_count", 0)
        return {
            "content": message.get("content", ""),
            "role": "assistant",
            "token_usage": {
                "prompt_tokens": prompt_eval_count,
                "completion_tokens": eval_count,
                "total_tokens": prompt_eval_count + eval_count,
            },
            "tool_calls": None,
        }

    async def stream(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        payload = {"model": model, "messages": messages, "stream": True}
        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/api/chat",
                json=payload,
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if chunk.get("done"):
                        eval_count = chunk.get("eval_count", 0)
                        prompt_eval_count = chunk.get("prompt_eval_count", 0)
                        yield {
                            "type": "usage",
                            "data": {
                                "prompt_tokens": prompt_eval_count,
                                "completion_tokens": eval_count,
                                "total_tokens": prompt_eval_count + eval_count,
                            },
                        }
                        yield {"type": "done", "data": None}
                        return

                    message = chunk.get("message", {})
                    content = message.get("content", "")
                    if content:
                        yield {"type": "token", "data": content}
