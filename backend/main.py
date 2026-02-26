import json
import time
import asyncio
import base64
import sys
import ipaddress
from pathlib import Path
from contextlib import asynccontextmanager

import yaml

# Windows: force ProactorEventLoop so asyncio.create_subprocess_exec works.
# uvicorn --reload uses SelectorEventLoop which does NOT support subprocesses.
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

from db.database import (
    init_db,
    create_conversation,
    get_conversations,
    get_conversation_with_messages,
    save_message,
    update_conversation,
    delete_conversation,
    create_finding,
    get_findings,
    delete_finding,
)
from adapters import ADAPTERS
from mcp.client import MCPClient, MCPServer
from skills import SkillPipeline
from terminal import (
    set_docker_container,
    get_docker_container,
    create_session,
    destroy_session,
    output_generator,
    send_input,
    resize_session,
    get_session,
    tor_start,
    tor_stop,
    tor_status,
)

SETTINGS_PATH = Path(__file__).parent / "settings.json"
CONFIG_PATH = Path(__file__).parent.parent / "rami-kali" / "config.yaml"

skill_pipeline = SkillPipeline()


def _format_tool_result(result) -> str:
    """Extract text from an MCP tool result for the LLM follow-up message.

    Strips [TACTICAL CONTEXT ...] blocks that MCP servers may prepend
    as reference material — the LLM doesn't need them to interpret results.
    """
    if isinstance(result, dict) and "content" in result:
        parts = []
        for item in result["content"]:
            if isinstance(item, dict) and item.get("type") == "text":
                text = item["text"]
                # Skip tactical context blocks (large reference material)
                if text.strip().startswith("[TACTICAL CONTEXT"):
                    continue
                parts.append(text)
        if parts:
            return "\n".join(parts)
    if isinstance(result, str):
        return result
    return json.dumps(result)


def _format_tool_content(trace: dict) -> str:
    """Return the content string to inject into the follow-up history.

    If the tool errored, return an explicit error notice so the LLM does NOT
    fabricate output. If it succeeded, return the formatted result.
    """
    if "error" in trace:
        return (
            f"[TOOL EXECUTION FAILED]: {trace['error']}\n"
            "The tool did not run successfully. "
            "Do NOT invent or fabricate output. "
            "Inform the user of the error and suggest how to fix it."
        )
    return _format_tool_result(trace.get("result", ""))

mcp_client = MCPClient()


def load_settings() -> dict:
    if SETTINGS_PATH.exists():
        return json.loads(SETTINGS_PATH.read_text())
    return {}


def save_settings_file(data: dict):
    current = load_settings()
    current.update(data)
    SETTINGS_PATH.write_text(json.dumps(current, indent=2))


def get_adapter(provider: str):
    settings = load_settings()
    adapter_cls = ADAPTERS.get(provider)
    if not adapter_cls:
        raise HTTPException(status_code=400, detail=f"Unknown provider: {provider}")

    provider_settings = settings.get(provider, {})

    if provider == "openai":
        return adapter_cls(
            api_key=provider_settings.get("api_key", ""),
            base_url=provider_settings.get("base_url", "https://api.openai.com/v1"),
        )
    elif provider == "anthropic":
        return adapter_cls(api_key=provider_settings.get("api_key", ""))
    elif provider == "openrouter":
        return adapter_cls(
            api_key=provider_settings.get("api_key", ""),
            base_url=provider_settings.get("base_url", "https://openrouter.ai/api/v1"),
        )
    elif provider == "lmstudio":
        return adapter_cls(
            base_url=provider_settings.get("base_url", "http://localhost:1234/v1"),
        )
    elif provider == "ollama":
        return adapter_cls(
            base_url=provider_settings.get("base_url", "http://localhost:11434"),
        )
    else:
        return adapter_cls()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()

    # Load docker container from settings
    settings = load_settings()
    docker_cfg = settings.get("docker", {})
    if docker_cfg.get("container"):
        set_docker_container(docker_cfg["container"])

    # Reconnect MCP servers saved in the DB
    try:
        servers = await mcp_client.list_servers()

        # Seed rami-kali MCP server on first run (before reconnect loop)
        RAMIKALI_NAME = "rami-kali"
        if not any(s["name"] == RAMIKALI_NAME for s in servers):
            try:
                ramikali_cfg = MCPServer(
                    name=RAMIKALI_NAME,
                    command="docker",
                    args=["exec", "-i", "rami-kali", "python3", "/opt/rami-kali/mcp_server.py"],
                )
                await mcp_client.add_server(ramikali_cfg)
                print(f"[MCP] Auto-configured rami-kali server '{RAMIKALI_NAME}'")
            except Exception as seed_err:
                print(f"[MCP] Warning: could not seed rami-kali server: {seed_err}")

        for srv in servers:
            config = MCPServer(
                name=srv["name"],
                command=srv.get("command", ""),
                args=srv.get("args", []),
                env=srv.get("env", {}),
                url=srv.get("url"),
            )
            await mcp_client.reconnect_server(config)
    except Exception as e:
        print(f"[MCP] Error reconnecting servers at startup: {e}")

    yield
    await mcp_client.shutdown()


app = FastAPI(title="RamiBot API", version="3.3", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic Models ---

class ConversationCreate(BaseModel):
    provider: str
    model: str
    title: str | None = None
    mcp_enabled: bool = False
    reasoning_enabled: bool = False
    team_mode: str = "red"


class ChatRequest(BaseModel):
    conversation_id: str
    message: str
    provider: str | None = None
    model: str | None = None
    mcp_enabled: bool = False
    reasoning_enabled: bool = False
    team_mode: str = "red"
    disabled_tools: list[str] = []


class MCPServerCreate(BaseModel):
    name: str
    command: str = ""
    args: list[str] = []
    env: dict[str, str] = {}
    url: str | None = None


class MCPCallRequest(BaseModel):
    server: str
    tool: str
    arguments: dict = {}


class ScopeUpdate(BaseModel):
    allowed_scope: list[str]
    require_scope_check: bool = True


class FindingCreate(BaseModel):
    conversation_id: str | None = None
    tool: str
    severity: str = "info"
    title: str
    description: str = ""
    target: str = ""


# --- Health ---

@app.get("/api/health")
async def health():
    return {"status": "ok"}


# --- Providers & Models ---

@app.get("/api/providers")
async def list_providers():
    providers = []
    for name, cls in ADAPTERS.items():
        adapter = get_adapter(name)
        caps = await adapter.capabilities()
        providers.append({"name": name, "capabilities": caps})
    return providers


@app.get("/api/models")
async def list_models(provider: str = Query(...)):
    adapter = get_adapter(provider)
    try:
        models = await adapter.list_models()
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    return models


# --- Conversations ---

@app.get("/api/conversations")
async def list_conversations():
    return await get_conversations()


@app.post("/api/conversations")
async def create_conv(body: ConversationCreate):
    conv = await create_conversation(
        provider=body.provider,
        model=body.model,
        title=body.title,
        mcp_enabled=body.mcp_enabled,
        reasoning_enabled=body.reasoning_enabled,
        team_mode=body.team_mode,
    )
    return conv


@app.get("/api/conversations/{conversation_id}")
async def get_conv(conversation_id: str):
    conv = await get_conversation_with_messages(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return conv


@app.delete("/api/conversations/{conversation_id}")
async def delete_conv(conversation_id: str):
    deleted = await delete_conversation(conversation_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Conversation not found")
    return {"status": "deleted"}


@app.get("/api/conversations/{conversation_id}/export")
async def export_conversation(conversation_id: str, format: str = Query("json")):
    conv = await get_conversation_with_messages(conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    if format == "markdown":
        lines = [f"# {conv['title']}\n"]
        lines.append(f"Provider: {conv['provider']} | Model: {conv['model']}\n")
        lines.append(f"Created: {conv['created_at']}\n\n---\n")
        for msg in conv.get("messages", []):
            role = msg["role"].capitalize()
            lines.append(f"## {role}\n\n{msg['content']}\n\n")
        return {"format": "markdown", "content": "\n".join(lines)}

    return {"format": "json", "content": conv}


# --- Chat ---

@app.post("/api/chat")
async def chat(body: ChatRequest):
    conv = await get_conversation_with_messages(body.conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    provider = body.provider or conv["provider"]
    model = body.model or conv["model"]
    adapter = get_adapter(provider)

    await save_message(body.conversation_id, "user", body.message)

    history = [{"role": m["role"], "content": m["content"]} for m in conv.get("messages", [])]
    history.append({"role": "user", "content": body.message})

    kwargs = {"reasoning_enabled": body.reasoning_enabled}

    if body.mcp_enabled:
        tools = await mcp_client.get_all_tools()
        if body.disabled_tools:
            tools = [t for t in tools if t["function"]["name"] not in body.disabled_tools]
        if tools:
            kwargs["tools"] = tools
            prompt, decision = skill_pipeline.build_prompt(body.message, body.team_mode, history)
            history.insert(0, {"role": "system", "content": prompt})

    start = time.time()
    try:
        result = await adapter.generate(history, model, **kwargs)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    latency = (time.time() - start) * 1000

    tool_calls_data = result.get("tool_calls")
    tool_traces = []

    if tool_calls_data and body.mcp_enabled:
        for tc in tool_calls_data:
            name = tc["name"]
            parts = name.split("__", 1)
            if len(parts) == 2:
                server_name, tool_name = parts
            else:
                server_name, tool_name = "", name
            try:
                args = json.loads(tc["arguments"]) if isinstance(tc["arguments"], str) else tc["arguments"]
                tool_result = await mcp_client.call_tool(server_name, tool_name, args)
                tool_traces.append({"tool": name, "arguments": args, "result": tool_result})
            except Exception as e:
                tool_traces.append({"tool": name, "error": str(e)})

        if tool_traces:
            # Build assistant message with tool_calls in OpenAI format
            assistant_msg = {"role": "assistant", "content": result["content"] or ""}
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.get("id", f"call_{i}"),
                    "type": "function",
                    "function": {
                        "name": tc["name"],
                        "arguments": tc["arguments"] if isinstance(tc["arguments"], str) else json.dumps(tc["arguments"]),
                    },
                }
                for i, tc in enumerate(tool_calls_data)
            ]
            history.append(assistant_msg)

            # Send tool results with role: "tool" and matching tool_call_id
            for i, trace in enumerate(tool_traces):
                tc_id = tool_calls_data[i].get("id", f"call_{i}") if i < len(tool_calls_data) else f"call_{i}"
                history.append({
                    "role": "tool",
                    "tool_call_id": tc_id,
                    "content": _format_tool_content(trace),
                })

            follow_kwargs = {k: v for k, v in kwargs.items() if k != "tools"}
            result = await adapter.generate(history, model, **follow_kwargs)
            latency = (time.time() - start) * 1000

    msg = await save_message(
        body.conversation_id,
        "assistant",
        result["content"],
        tool_calls=tool_calls_data,
        tool_traces=tool_traces or None,
        token_usage=result.get("token_usage"),
        latency_ms=latency,
    )

    return msg


@app.post("/api/chat/stream")
async def chat_stream(body: ChatRequest):
    conv = await get_conversation_with_messages(body.conversation_id)
    if not conv:
        raise HTTPException(status_code=404, detail="Conversation not found")

    provider = body.provider or conv["provider"]
    model = body.model or conv["model"]
    adapter = get_adapter(provider)

    await save_message(body.conversation_id, "user", body.message)

    history = [{"role": m["role"], "content": m["content"]} for m in conv.get("messages", [])]
    history.append({"role": "user", "content": body.message})

    kwargs = {"reasoning_enabled": body.reasoning_enabled}

    mcp_tools = []
    if body.mcp_enabled:
        mcp_tools = await mcp_client.get_all_tools()
        if body.disabled_tools:
            mcp_tools = [t for t in mcp_tools if t["function"]["name"] not in body.disabled_tools]
        if mcp_tools:
            kwargs["tools"] = mcp_tools
            prompt, decision = skill_pipeline.build_prompt(body.message, body.team_mode, history)
            history.insert(0, {"role": "system", "content": prompt})

    async def event_generator():
        start = time.time()
        content_parts = []
        token_usage = None
        tool_calls_collected = []
        tool_traces = []

        try:
            async for event in adapter.stream(history, model, **kwargs):
                etype = event["type"]

                if etype == "token":
                    content_parts.append(event["data"])
                    yield {"event": "token", "data": json.dumps({"token": event["data"]})}

                elif etype == "tool_call":
                    tc = event["data"]
                    tool_calls_collected.append(tc)
                    yield {"event": "tool_call", "data": json.dumps(tc)}

                    if body.mcp_enabled:
                        name = tc["name"]
                        parts = name.split("__", 1)
                        if len(parts) == 2:
                            server_name, tool_name = parts
                        else:
                            server_name, tool_name = "", name
                        try:
                            args = json.loads(tc["arguments"]) if isinstance(tc["arguments"], str) else tc["arguments"]
                            tool_result = await mcp_client.call_tool(server_name, tool_name, args)
                            trace = {"tool": name, "arguments": args, "result": tool_result}
                            tool_traces.append(trace)
                            yield {"event": "tool_result", "data": json.dumps(trace)}
                        except Exception as e:
                            trace = {"tool": name, "error": str(e)}
                            tool_traces.append(trace)
                            yield {"event": "tool_result", "data": json.dumps(trace)}

                elif etype == "usage":
                    token_usage = event["data"]
                    yield {"event": "usage", "data": json.dumps(token_usage)}

                elif etype == "error":
                    yield {"event": "error", "data": json.dumps({"error": str(event["data"])})}

                elif etype == "done":
                    pass

            if tool_calls_collected and tool_traces and body.mcp_enabled:
                follow_history = list(history)

                # Build assistant message with tool_calls in OpenAI format
                assistant_msg = {"role": "assistant", "content": "".join(content_parts) or ""}
                assistant_msg["tool_calls"] = [
                    {
                        "id": tc.get("id", f"call_{i}"),
                        "type": "function",
                        "function": {
                            "name": tc["name"],
                            "arguments": tc["arguments"] if isinstance(tc["arguments"], str) else json.dumps(tc["arguments"]),
                        },
                    }
                    for i, tc in enumerate(tool_calls_collected)
                ]
                follow_history.append(assistant_msg)

                # Send tool results with role: "tool" and matching tool_call_id
                for i, trace in enumerate(tool_traces):
                    tc_id = tool_calls_collected[i].get("id", f"call_{i}") if i < len(tool_calls_collected) else f"call_{i}"
                    follow_history.append({
                        "role": "tool",
                        "tool_call_id": tc_id,
                        "content": _format_tool_content(trace),
                    })

                content_parts.clear()
                # Tell frontend to discard initial text and show only tool follow-up
                yield {"event": "clear_content", "data": "{}"}
                follow_kwargs = {k: v for k, v in kwargs.items() if k != "tools"}
                async for event in adapter.stream(follow_history, model, **follow_kwargs):
                    if event["type"] == "token":
                        content_parts.append(event["data"])
                        yield {"event": "token", "data": json.dumps({"token": event["data"]})}
                    elif event["type"] == "usage":
                        token_usage = event["data"]
                        yield {"event": "usage", "data": json.dumps(token_usage)}

            latency = (time.time() - start) * 1000
            content = "".join(content_parts)

            await save_message(
                body.conversation_id,
                "assistant",
                content,
                tool_calls=tool_calls_collected or None,
                tool_traces=tool_traces or None,
                token_usage=token_usage,
                latency_ms=latency,
            )

            yield {
                "event": "done",
                "data": json.dumps({
                    "token_usage": token_usage,
                    "latency_ms": latency,
                }),
            }

        except Exception as e:
            yield {"event": "error", "data": json.dumps({"error": str(e)})}

    return EventSourceResponse(event_generator())


# --- Skills Log ---

@app.get("/api/skills/log")
async def get_skills_log(limit: int = Query(50)):
    log_path = Path(__file__).parent / "skill_decisions.log"
    if not log_path.exists():
        return []
    lines = log_path.read_text(encoding="utf-8").strip().splitlines()
    if not lines:
        return []
    # Read last `limit` lines (most recent at end of file)
    tail = lines[-limit:]
    entries = []
    for line in reversed(tail):
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries


@app.delete("/api/skills/log")
async def clear_skills_log():
    log_path = Path(__file__).parent / "skill_decisions.log"
    if log_path.exists():
        log_path.write_text("", encoding="utf-8")
    return {"status": "cleared"}


# --- MCP ---

@app.get("/api/mcp/servers")
async def list_mcp_servers():
    return await mcp_client.list_servers()


@app.post("/api/mcp/servers")
async def add_mcp_server(body: MCPServerCreate):
    config = MCPServer(
        name=body.name,
        command=body.command,
        args=body.args,
        env=body.env,
        url=body.url,
    )
    result = await mcp_client.add_server(config)
    return result


@app.delete("/api/mcp/servers/{server_name}")
async def delete_mcp_server(server_name: str):
    try:
        await mcp_client.remove_server(server_name)
    except Exception as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {"status": "deleted"}


@app.get("/api/mcp/all-tools")
async def list_all_mcp_tools():
    tools = await mcp_client.get_all_tools()
    return tools


@app.get("/api/mcp/tools")
async def list_mcp_tools(server: str = Query(...)):
    try:
        tools = await mcp_client.list_tools(server)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    return tools


@app.post("/api/mcp/call")
async def call_mcp_tool(body: MCPCallRequest):
    try:
        result = await mcp_client.call_tool(body.server, body.tool, body.arguments)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))
    return result


# --- Scope ---

@app.get("/api/scope")
async def get_scope():
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="rami-kali/config.yaml not found")
    cfg = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    security = cfg.get("security", {})
    return {
        "allowed_scope": security.get("allowed_scope", []),
        "require_scope_check": security.get("require_scope_check", True),
    }


@app.put("/api/scope")
async def update_scope(body: ScopeUpdate):
    if not CONFIG_PATH.exists():
        raise HTTPException(status_code=404, detail="rami-kali/config.yaml not found")

    # Validate each CIDR
    for cidr in body.allowed_scope:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid CIDR: {cidr}")

    cfg = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
    cfg.setdefault("security", {})
    cfg["security"]["allowed_scope"] = body.allowed_scope
    cfg["security"]["require_scope_check"] = body.require_scope_check
    CONFIG_PATH.write_text(yaml.dump(cfg, default_flow_style=False, allow_unicode=True), encoding="utf-8")

    # Restart the container to pick up new config.
    # Use run_in_executor + subprocess.run (same pattern as terminal.py —
    # asyncio.create_subprocess_exec is unreliable on Windows).
    container = get_docker_container() or "rami-kali"
    try:
        import subprocess as _sp
        loop = asyncio.get_event_loop()
        rc = await loop.run_in_executor(
            None,
            lambda: _sp.run(
                ["docker", "restart", container],
                stdout=_sp.DEVNULL,
                stderr=_sp.DEVNULL,
            ).returncode,
        )
        restart = "ok" if rc == 0 else "failed"
    except Exception as e:
        restart = f"failed: {e}"

    # Reconnect MCP server after container restart so tools remain available.
    if restart == "ok":
        await asyncio.sleep(3)  # wait for container to come up
        RAMIKALI_NAME = "rami-kali"
        existing_conn = mcp_client.servers.get(RAMIKALI_NAME)
        if existing_conn:
            await existing_conn.stop()
            await mcp_client.reconnect_server(existing_conn.config)

    return {"status": "saved", "restart": restart}


# --- Settings ---

# --- Terminal (SSE + POST) ---

class TerminalStartRequest(BaseModel):
    container: str | None = None

class TerminalInputRequest(BaseModel):
    session_id: str
    data: str  # base64-encoded bytes

class TerminalResizeRequest(BaseModel):
    session_id: str
    cols: int
    rows: int

class TerminalStopRequest(BaseModel):
    session_id: str


@app.post("/api/terminal/start")
async def terminal_start(body: TerminalStartRequest):
    container = body.container or get_docker_container()
    session_id, error, info = await create_session(container)
    if error:
        raise HTTPException(status_code=400, detail=error)
    return {"session_id": session_id, "info": info}


@app.get("/api/terminal/stream")
async def terminal_stream(session_id: str = Query(...)):
    session = get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return EventSourceResponse(output_generator(session_id))


@app.post("/api/terminal/input")
async def terminal_input(body: TerminalInputRequest):
    try:
        raw = base64.b64decode(body.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64")
    if not send_input(body.session_id, raw):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "ok"}


@app.post("/api/terminal/resize")
async def terminal_resize(body: TerminalResizeRequest):
    if not resize_session(body.session_id, body.cols, body.rows):
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "ok"}


@app.post("/api/terminal/stop")
async def terminal_stop(body: TerminalStopRequest):
    destroy_session(body.session_id)
    return {"status": "ok"}


class TorActionRequest(BaseModel):
    action: str  # "start" or "stop"


@app.get("/api/docker/tor")
async def docker_tor_status():
    container = get_docker_container()
    if not container:
        raise HTTPException(status_code=400, detail="No Docker container configured")
    result = await tor_status(container)
    return result


@app.post("/api/docker/tor")
async def docker_tor_action(body: TorActionRequest):
    container = get_docker_container()
    if not container:
        raise HTTPException(status_code=400, detail="No Docker container configured")
    if body.action == "start":
        result = await tor_start(container)
    elif body.action == "stop":
        result = await tor_stop(container)
    else:
        raise HTTPException(status_code=400, detail=f"Unknown action: {body.action}")
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/settings")
async def save_settings(request: Request):
    data = await request.json()
    save_settings_file(data)
    # Update docker container if provided
    docker_cfg = data.get("docker", {})
    if docker_cfg:
        set_docker_container(docker_cfg.get("container", ""))
    return {"status": "saved"}


# --- Findings ---

@app.post("/api/findings")
async def api_create_finding(body: FindingCreate):
    finding = await create_finding(
        conversation_id=body.conversation_id,
        tool=body.tool,
        severity=body.severity,
        title=body.title,
        description=body.description,
        target=body.target,
    )
    return finding


@app.get("/api/findings")
async def api_get_findings(
    conversation_id: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
):
    return await get_findings(conversation_id=conversation_id, severity=severity, limit=limit)


@app.delete("/api/findings/{finding_id}")
async def api_delete_finding(finding_id: str):
    deleted = await delete_finding(finding_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {"status": "deleted"}


@app.get("/api/findings/export")
async def api_export_findings(
    format: str = Query("json"),
    conversation_id: str | None = Query(None),
    severity: str | None = Query(None),
):
    from fastapi.responses import Response
    findings = await get_findings(conversation_id=conversation_id, severity=severity, limit=10000)

    if format == "csv":
        import io, csv
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["id", "created_at", "severity", "title", "tool", "target", "description", "conversation_id"])
        writer.writeheader()
        writer.writerows(findings)
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=findings.csv"})

    return Response(content=json.dumps(findings, indent=2), media_type="application/json",
                    headers={"Content-Disposition": "attachment; filename=findings.json"})
