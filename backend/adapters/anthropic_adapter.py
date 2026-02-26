import json
import httpx
from typing import AsyncGenerator
from .base import BaseAdapter


def _sanitize_tool_schema(schema: dict) -> dict:
    """Remove oneOf/anyOf/allOf from root level of tool input schemas."""
    if not isinstance(schema, dict):
        return schema
    cleaned = {}
    for k, v in schema.items():
        if k in ("oneOf", "anyOf", "allOf") and isinstance(v, list):
            if v:
                cleaned.update(_sanitize_tool_schema(v[0]))
        else:
            cleaned[k] = v
    return cleaned


class AnthropicAdapter(BaseAdapter):
    provider_name = "anthropic"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.base_url = "https://api.anthropic.com/v1"

    def _headers(self) -> dict:
        return {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
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
        if not self.api_key:
            raise ValueError("Anthropic API key not configured")
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                f"{self.base_url}/models",
                headers=self._headers(),
            )
            resp.raise_for_status()
            data = resp.json()
        return [
            {"id": m["id"], "name": m.get("display_name", m["id"])}
            for m in data.get("data", [])
        ]

    def _convert_messages(self, messages: list[dict]) -> tuple[str | None, list[dict]]:
        """Split system message and convert to Anthropic format.

        Handles OpenAI-style tool_calls / role:'tool' messages produced by the
        follow-up flow in main.py, converting them to Anthropic's tool_use /
        tool_result block format.
        """
        system = None
        converted = []
        for msg in messages:
            role = msg["role"]

            if role == "system":
                system = msg["content"]
                continue

            # OpenAI-style assistant message with tool_calls → Anthropic tool_use blocks
            if role == "assistant" and msg.get("tool_calls"):
                content_blocks: list[dict] = []
                if msg.get("content"):
                    content_blocks.append({"type": "text", "text": msg["content"]})
                for tc in msg["tool_calls"]:
                    fn = tc.get("function", {})
                    try:
                        tool_input = (
                            json.loads(fn.get("arguments", "{}"))
                            if isinstance(fn.get("arguments"), str)
                            else fn.get("arguments", {})
                        )
                    except (json.JSONDecodeError, TypeError):
                        tool_input = {}
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": fn["name"],
                        "input": tool_input,
                    })
                converted.append({"role": "assistant", "content": content_blocks})
                continue

            # OpenAI-style role:'tool' → Anthropic tool_result inside a user message
            if role == "tool":
                result_block = {
                    "type": "tool_result",
                    "tool_use_id": msg.get("tool_call_id", ""),
                    "content": msg.get("content", ""),
                }
                # Consolidate consecutive tool results into one user message
                if (converted and converted[-1]["role"] == "user"
                        and isinstance(converted[-1]["content"], list)):
                    converted[-1]["content"].append(result_block)
                else:
                    converted.append({"role": "user", "content": [result_block]})
                continue

            # Regular user/assistant message
            converted.append({"role": role, "content": msg.get("content", "")})

        return system, converted

    def _build_tools(self, tools: list[dict] | None) -> list[dict] | None:
        if not tools:
            return None
        anthropic_tools = []
        for tool in tools:
            fn = tool.get("function", tool)
            input_schema = _sanitize_tool_schema(fn.get("parameters", {"type": "object", "properties": {}}))
            anthropic_tools.append({
                "name": fn["name"],
                "description": fn.get("description", ""),
                "input_schema": input_schema,
            })
        return anthropic_tools

    async def generate(self, messages: list[dict], model: str, **kwargs) -> dict:
        system, converted = self._convert_messages(messages)
        tools = kwargs.get("tools")
        reasoning_enabled = kwargs.get("reasoning_enabled", False)

        payload: dict = {
            "model": model,
            "messages": converted,
            "max_tokens": kwargs.get("max_tokens", 4096),
        }
        if system:
            payload["system"] = system

        built_tools = self._build_tools(tools)
        if built_tools:
            payload["tools"] = built_tools

        if reasoning_enabled:
            payload["thinking"] = {
                "type": "enabled",
                "budget_tokens": kwargs.get("budget_tokens", 2048),
            }

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/messages",
                headers=self._headers(),
                json=payload,
            )
            resp.raise_for_status()
            data = resp.json()

        content_text = ""
        tool_calls = []
        for block in data.get("content", []):
            if block["type"] == "text":
                content_text += block["text"]
            elif block["type"] == "tool_use":
                tool_calls.append({
                    "id": block["id"],
                    "name": block["name"],
                    "arguments": json.dumps(block["input"]),
                })

        usage = data.get("usage", {})
        return {
            "content": content_text,
            "role": "assistant",
            "token_usage": {
                "prompt_tokens": usage.get("input_tokens", 0),
                "completion_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
            },
            "tool_calls": tool_calls or None,
        }

    async def stream(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        system, converted = self._convert_messages(messages)
        tools = kwargs.get("tools")
        reasoning_enabled = kwargs.get("reasoning_enabled", False)

        payload: dict = {
            "model": model,
            "messages": converted,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "stream": True,
        }
        if system:
            payload["system"] = system

        built_tools = self._build_tools(tools)
        if built_tools:
            payload["tools"] = built_tools

        if reasoning_enabled:
            payload["thinking"] = {
                "type": "enabled",
                "budget_tokens": kwargs.get("budget_tokens", 2048),
            }

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream(
                "POST",
                f"{self.base_url}/messages",
                headers=self._headers(),
                json=payload,
            ) as resp:
                resp.raise_for_status()
                current_tool: dict | None = None
                event_type = None

                async for line in resp.aiter_lines():
                    if line.startswith("event: "):
                        event_type = line[7:].strip()
                        continue
                    if not line.startswith("data: "):
                        continue

                    try:
                        data = json.loads(line[6:])
                    except json.JSONDecodeError:
                        continue

                    if event_type == "content_block_start":
                        block = data.get("content_block", {})
                        if block.get("type") == "tool_use":
                            current_tool = {
                                "id": block["id"],
                                "name": block["name"],
                                "arguments": "",
                            }

                    elif event_type == "content_block_delta":
                        delta = data.get("delta", {})
                        if delta.get("type") == "text_delta":
                            yield {"type": "token", "data": delta["text"]}
                        elif delta.get("type") == "input_json_delta":
                            if current_tool is not None:
                                current_tool["arguments"] += delta.get("partial_json", "")

                    elif event_type == "content_block_stop":
                        if current_tool is not None:
                            yield {"type": "tool_call", "data": current_tool}
                            current_tool = None

                    elif event_type == "message_delta":
                        usage = data.get("usage", {})
                        if usage:
                            yield {
                                "type": "usage",
                                "data": {
                                    "prompt_tokens": usage.get("input_tokens", 0),
                                    "completion_tokens": usage.get("output_tokens", 0),
                                    "total_tokens": usage.get("input_tokens", 0) + usage.get("output_tokens", 0),
                                },
                            }

                    elif event_type == "message_start":
                        msg_usage = data.get("message", {}).get("usage", {})
                        if msg_usage:
                            yield {
                                "type": "usage",
                                "data": {
                                    "prompt_tokens": msg_usage.get("input_tokens", 0),
                                    "completion_tokens": msg_usage.get("output_tokens", 0),
                                    "total_tokens": msg_usage.get("input_tokens", 0) + msg_usage.get("output_tokens", 0),
                                },
                            }

                    elif event_type == "message_stop":
                        yield {"type": "done", "data": None}
                        return
