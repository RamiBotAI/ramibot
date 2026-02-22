import json
import httpx
from typing import AsyncGenerator
from .base import BaseAdapter

REASONING_MODELS = {"o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o4-mini"}


class OpenAIAdapter(BaseAdapter):
    provider_name = "openai"

    def __init__(self, api_key: str = "", base_url: str = "https://api.openai.com/v1"):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    async def capabilities(self) -> dict:
        return {
            "streaming": True,
            "tool_calling": True,
            "reasoning": True,
            "models": [],
        }

    async def list_models(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(f"{self.base_url}/models", headers=self._headers())
            resp.raise_for_status()
            data = resp.json().get("data", [])
        prefixes = ("gpt-", "o1", "o3", "o4")
        models = [
            {"name": m["id"], "id": m["id"]}
            for m in data
            if any(m["id"].startswith(p) for p in prefixes)
        ]
        models.sort(key=lambda m: m["name"])
        return models

    def _build_payload(self, messages: list[dict], model: str, stream: bool = False, **kwargs) -> dict:
        tools = kwargs.get("tools")
        reasoning_enabled = kwargs.get("reasoning_enabled", False)

        payload: dict = {"model": model, "messages": messages, "stream": stream}

        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        model_base = model.split("-")[0] if "-" in model else model
        if reasoning_enabled and model_base in REASONING_MODELS:
            payload["reasoning_effort"] = kwargs.get("reasoning_effort", "medium")

        if stream:
            payload["stream_options"] = {"include_usage": True}

        return payload

    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict:
        payload = self._build_payload(messages, model, stream=False, **kwargs)
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
        payload = self._build_payload(messages, model, stream=True, **kwargs)
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
