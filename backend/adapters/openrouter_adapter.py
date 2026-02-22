import json
import httpx
from typing import AsyncGenerator
from .base import BaseAdapter


class OpenRouterAdapter(BaseAdapter):
    provider_name = "openrouter"

    def __init__(self, api_key: str = "", base_url: str = "https://openrouter.ai/api/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://ramibot.app",
            "X-Title": "RamiBot",
        }

    async def capabilities(self) -> dict:
        return {
            "streaming": True,
            "tool_calling": True,
            "reasoning": False,
            "models": [],
        }

    async def list_models(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{self.base_url}/models", headers=self._headers())
            resp.raise_for_status()
            data = resp.json().get("data", [])
        models = [{"name": m.get("name", m["id"]), "id": m["id"]} for m in data]
        models.sort(key=lambda m: m["name"])
        return models

    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict:
        tools = kwargs.get("tools")
        payload: dict = {"model": model, "messages": messages}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        message = choice["message"]
        tool_calls = None
        if message.get("tool_calls"):
            tool_calls = [
                {
                    "id": tc["id"],
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                }
                for tc in message["tool_calls"]
            ]

        usage = data.get("usage", {})
        return {
            "content": message.get("content", ""),
            "role": "assistant",
            "token_usage": {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            "tool_calls": tool_calls,
        }

    async def stream(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        tools = kwargs.get("tools")
        payload: dict = {"model": model, "messages": messages, "stream": True}
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as resp:
                resp.raise_for_status()
                current_tool_call = None
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        if current_tool_call:
                            yield {"type": "tool_call", "data": current_tool_call}
                            current_tool_call = None
                        yield {"type": "done", "data": None}
                        return

                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    if chunk.get("usage"):
                        usage = chunk["usage"]
                        yield {
                            "type": "usage",
                            "data": {
                                "prompt_tokens": usage.get("prompt_tokens", 0),
                                "completion_tokens": usage.get("completion_tokens", 0),
                                "total_tokens": usage.get("total_tokens", 0),
                            },
                        }

                    choices = chunk.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})

                    if delta.get("tool_calls"):
                        tc = delta["tool_calls"][0]
                        if tc.get("id"):
                            if current_tool_call:
                                yield {"type": "tool_call", "data": current_tool_call}
                            current_tool_call = {
                                "id": tc["id"],
                                "name": tc["function"]["name"],
                                "arguments": tc["function"].get("arguments", ""),
                            }
                        elif current_tool_call:
                            current_tool_call["arguments"] += tc["function"].get("arguments", "")
                    elif delta.get("content"):
                        yield {"type": "token", "data": delta["content"]}
