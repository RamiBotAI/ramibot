import base64
import json
import httpx
from typing import AsyncGenerator
from .base import BaseAdapter

REASONING_MODELS = {"o1", "o1-mini", "o1-preview", "o3", "o3-mini", "o4-mini"}
_CODEX_URL = "https://chatgpt.com/backend-api/codex/responses"

_CODEX_MODELS = [
    {"id": "gpt-5.2-codex",      "name": "GPT-5.2 Codex"},
    {"id": "gpt-5.1-codex-max",  "name": "GPT-5.1 Codex Max"},
    {"id": "gpt-5.1-codex",      "name": "GPT-5.1 Codex"},
    {"id": "gpt-5.1-codex-mini", "name": "GPT-5.1 Codex Mini"},
    {"id": "gpt-5.2",            "name": "GPT-5.2"},
    {"id": "gpt-5.1",            "name": "GPT-5.1"},
    {"id": "gpt-5",              "name": "GPT-5"},
]


def _extract_account_id(access_token: str) -> str:
    """Decode the JWT and pull chatgpt_account_id from the custom claim."""
    parts = access_token.split(".")
    if len(parts) < 2:
        raise ValueError("Invalid JWT format")
    payload = parts[1]
    padded = payload + "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))
    account_id = claims.get("https://api.openai.com/auth", {}).get("chatgpt_account_id", "")
    if not account_id:
        raise ValueError("chatgpt_account_id not found in token — make sure you're using the access_token from ~/.codex/auth.json")
    return account_id


def _codex_headers(access_token: str, account_id: str) -> dict:
    return {
        "Authorization": f"Bearer {access_token}",
        "chatgpt-account-id": account_id,
        "OpenAI-Beta": "responses=experimental",
        "originator": "ramibot",
        "accept": "text/event-stream",
        "content-type": "application/json",
    }


def _to_codex_tools(tools: list[dict]) -> list[dict]:
    out = []
    for tool in tools:
        fn = tool.get("function", tool)
        if fn.get("name"):
            out.append({
                "type": "function",
                "name": fn["name"],
                "description": fn.get("description", ""),
                "parameters": fn.get("parameters") or {"type": "object", "properties": {}},
            })
    return out


def _to_codex_body(messages: list[dict], model: str, tools: list[dict] | None = None) -> dict:
    """Translate Chat Completions messages to Responses API request body."""
    system_texts: list[str] = []
    input_items: list[dict] = []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "") or ""
        if isinstance(content, list):
            content = "\n".join(
                c.get("text", "") for c in content if isinstance(c, dict)
            )

        if role == "system":
            if content:
                system_texts.append(content)

        elif role == "user":
            input_items.append({
                "role": "user",
                "content": [{"type": "input_text", "text": content}],
            })

        elif role == "assistant":
            for tc in msg.get("tool_calls") or []:
                fn = tc.get("function", {})
                input_items.append({
                    "type": "function_call",
                    "call_id": tc.get("id", ""),
                    "name": fn.get("name", ""),
                    "arguments": fn.get("arguments", ""),
                })
            if content:
                input_items.append({
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": content, "annotations": []}],
                    "status": "completed",
                })

        elif role == "tool":
            input_items.append({
                "type": "function_call_output",
                "call_id": msg.get("tool_call_id", ""),
                "output": content,
            })

    body: dict = {
        "model": model,
        "stream": True,
        "store": False,
        "input": input_items,
        "instructions": "\n\n".join(system_texts) or "You are a helpful assistant.",
        "text": {"format": {"type": "text"}},
    }
    if tools:
        body["tools"] = _to_codex_tools(tools)
        body["tool_choice"] = "auto"
    return body


class OpenAIAdapter(BaseAdapter):
    provider_name = "openai"

    def __init__(self, api_key: str = "", base_url: str = "https://api.openai.com/v1", oauth_token: str = ""):
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.oauth_token = oauth_token.removeprefix("Bearer ").strip() if oauth_token else ""

    def _headers(self) -> dict:
        token = self.oauth_token or self.api_key
        return {
            "Authorization": f"Bearer {token}",
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
        if self.oauth_token and not self.api_key:
            return _CODEX_MODELS
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
        if self.oauth_token and not self.api_key:
            # Collect from codex stream
            content = ""
            tool_calls_map: dict[str, dict] = {}
            tool_calls_order: list[str] = []
            async for event in self.stream(messages, model, **kwargs):
                if event["type"] == "token":
                    content += event["data"]
                elif event["type"] == "tool_call":
                    tc = event["data"]
                    tool_calls_map[tc["id"]] = tc
                    tool_calls_order.append(tc["id"])
            tool_calls = [tool_calls_map[k] for k in tool_calls_order] or None
            return {
                "content": content,
                "role": "assistant",
                "token_usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
                "tool_calls": tool_calls,
            }

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

    async def _stream_codex(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        """Stream via ChatGPT backend Responses API using OAuth token."""
        account_id = _extract_account_id(self.oauth_token)
        headers = _codex_headers(self.oauth_token, account_id)
        body = _to_codex_body(messages, model, tools=kwargs.get("tools"))

        # Per-call tool tracking state
        tool_state: dict[str, dict] = {}   # item_id → {id, name, arguments, index}
        tool_counter = 0
        pending_tools: dict[int, dict] = {}  # index → tool call dict

        async with httpx.AsyncClient(timeout=120) as client:
            async with client.stream("POST", _CODEX_URL, headers=headers, json=body) as resp:
                resp.raise_for_status()
                event_type: str | None = None
                async for line in resp.aiter_lines():
                    if line.startswith("event:"):
                        event_type = line[6:].strip()
                        continue
                    if not line.startswith("data:"):
                        continue
                    raw = line[5:].strip()
                    if not raw:
                        continue
                    try:
                        data = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    if event_type == "response.output_text.delta":
                        yield {"type": "token", "data": data.get("delta", "")}

                    elif event_type == "response.output_item.added":
                        item = data.get("item", {})
                        if item.get("type") == "function_call":
                            item_id = str(item.get("id", ""))
                            call_id = str(item.get("call_id") or item_id)
                            name = item.get("name", "")
                            idx = tool_counter
                            tool_counter += 1
                            tool_state[item_id] = {"id": call_id, "name": name, "arguments": "", "index": idx}
                            pending_tools[idx] = tool_state[item_id]

                    elif event_type in ("response.function_call.arguments.delta",
                                        "response.function_call_arguments.delta"):
                        item_id = str(data.get("item_id", ""))
                        if item_id in tool_state:
                            tool_state[item_id]["arguments"] += data.get("delta", "")

                    elif event_type == "response.output_item.done":
                        item = data.get("item", {})
                        if item.get("type") == "function_call":
                            item_id = str(item.get("id", ""))
                            if item_id in tool_state:
                                tc = tool_state.pop(item_id)
                                yield {"type": "tool_call", "data": {
                                    "id": tc["id"],
                                    "name": tc["name"],
                                    "arguments": tc["arguments"],
                                }}

                    elif event_type == "response.completed":
                        resp_obj = data.get("response", {})
                        usage = resp_obj.get("usage", {})
                        if usage:
                            yield {
                                "type": "usage",
                                "data": {
                                    "prompt_tokens": usage.get("input_tokens", 0),
                                    "completion_tokens": usage.get("output_tokens", 0),
                                    "total_tokens": usage.get("total_tokens", 0),
                                },
                            }
                        # Flush any tool calls not yet emitted via output_item.done
                        for tc in tool_state.values():
                            yield {"type": "tool_call", "data": {
                                "id": tc["id"], "name": tc["name"], "arguments": tc["arguments"],
                            }}
                        yield {"type": "done", "data": None}
                        return

                    elif event_type in ("response.failed", "error"):
                        err = data.get("error", {})
                        msg = err.get("message") if isinstance(err, dict) else str(data)
                        yield {"type": "error", "data": msg or "Codex stream error"}
                        return

    async def stream(self, messages: list[dict], model: str, **kwargs) -> AsyncGenerator[dict, None]:
        if self.oauth_token and not self.api_key:
            async for event in self._stream_codex(messages, model, **kwargs):
                yield event
            return

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
