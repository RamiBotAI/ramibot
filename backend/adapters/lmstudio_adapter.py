import re
import json
import httpx
from typing import AsyncGenerator
from .base import BaseAdapter


class LMStudioAdapter(BaseAdapter):
    provider_name = "lmstudio"

    def __init__(self, base_url: str = "http://localhost:1234/v1"):
        base_url = base_url.rstrip("/")
        if not base_url.endswith("/v1"):
            base_url += "/v1"
        self.base_url = base_url

    def _headers(self) -> dict:
        return {"Content-Type": "application/json"}

    async def capabilities(self) -> dict:
        return {
            "streaming": True,
            "tool_calling": True,
            "reasoning": True,
            "models": [],
        }

    def _apply_no_think(self, messages: list[dict], reasoning_enabled: bool) -> list[dict]:
        if reasoning_enabled:
            return messages
        messages = [m.copy() for m in messages]
        for i in range(len(messages) - 1, -1, -1):
            if messages[i]["role"] == "user":
                messages[i]["content"] = messages[i]["content"] + " /no_think"
                break
        return messages

    async def list_models(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.base_url}/models", headers=self._headers())
            resp.raise_for_status()
            data = resp.json().get("data", [])
        return [{"name": m["id"], "id": m["id"]} for m in data]

    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict:
        messages = self._apply_no_think(messages, kwargs.get("reasoning_enabled", False))
        payload = {"model": model, "messages": messages}
        tools = kwargs.get("tools")
        if tools:
            payload["tools"] = tools
        async with httpx.AsyncClient(timeout=httpx.Timeout(300, connect=30)) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        choice = data["choices"][0]
        usage = data.get("usage", {})
        content = choice["message"].get("content", "") or ""
        if not kwargs.get("reasoning_enabled", False):
            content = re.sub(r"<think>[\s\S]*?</think>\s*", "", content)

        tool_calls = None
        if choice["message"].get("tool_calls"):
            tool_calls = [
                {
                    "id": tc.get("id", f"call_{i}"),
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                }
                for i, tc in enumerate(choice["message"]["tool_calls"])
            ]

        return {
            "content": content,
            "role": "assistant",
            "token_usage": {
                "prompt_tokens": usage.get("prompt_tokens", 0),
                "completion_tokens": usage.get("completion_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
            "tool_calls": tool_calls,
        }

    async def stream(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        reasoning_enabled = kwargs.get("reasoning_enabled", False)
        messages = self._apply_no_think(messages, reasoning_enabled)
        payload = {"model": model, "messages": messages, "stream": True}
        tools = kwargs.get("tools")
        if tools:
            payload["tools"] = tools
        in_think = False
        tool_calls_buf = {}  # index -> {name, arguments}
        async with httpx.AsyncClient(timeout=httpx.Timeout(300, connect=30)) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/chat/completions",
                headers=self._headers(),
                json=payload,
            ) as resp:
                resp.raise_for_status()
                async for line in resp.aiter_lines():
                    if not line.startswith("data: "):
                        continue
                    data_str = line[6:]
                    if data_str.strip() == "[DONE]":
                        # Emit any accumulated tool calls
                        for tc in tool_calls_buf.values():
                            yield {"type": "tool_call", "data": tc}
                        yield {"type": "done", "data": None}
                        return
                    try:
                        chunk = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    choices = chunk.get("choices", [])
                    if not choices:
                        continue
                    delta = choices[0].get("delta", {})

                    # Handle tool call deltas
                    if delta.get("tool_calls"):
                        for tc_delta in delta["tool_calls"]:
                            idx = tc_delta.get("index", 0)
                            if idx not in tool_calls_buf:
                                tool_calls_buf[idx] = {"id": tc_delta.get("id", f"call_{idx}"), "name": "", "arguments": ""}
                            if tc_delta.get("id"):
                                tool_calls_buf[idx]["id"] = tc_delta["id"]
                            if tc_delta.get("function", {}).get("name"):
                                tool_calls_buf[idx]["name"] = tc_delta["function"]["name"]
                            if tc_delta.get("function", {}).get("arguments"):
                                tool_calls_buf[idx]["arguments"] += tc_delta["function"]["arguments"]
                        continue

                    content = delta.get("content", "")
                    if not content:
                        continue

                    if not reasoning_enabled:
                        if "<think>" in content:
                            in_think = True
                            content = content.split("<think>")[0]
                            if content:
                                yield {"type": "token", "data": content}
                            continue
                        if in_think:
                            if "</think>" in content:
                                in_think = False
                                content = content.split("</think>", 1)[1]
                                if content:
                                    yield {"type": "token", "data": content}
                            continue

                    yield {"type": "token", "data": content}
