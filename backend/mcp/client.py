import asyncio
import json
import sys
import uuid
import subprocess
import threading
from pathlib import Path
import httpx
from dataclasses import dataclass, field

# Ensure parent is on path for sibling package imports
_parent = str(Path(__file__).parent.parent)
if _parent not in sys.path:
    sys.path.insert(0, _parent)

from db.database import get_db, sync_server_tools


@dataclass
class MCPServer:
    name: str
    command: str = ""
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    url: str | None = None


class MCPServerConnection:
    def __init__(self, config: MCPServer):
        self.config = config
        self.process: subprocess.Popen | None = None
        self._request_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_thread: threading.Thread | None = None
        self._stderr_thread: threading.Thread | None = None
        self._initialized = False
        self._loop: asyncio.AbstractEventLoop | None = None

    async def start(self):
        if self.config.url:
            await self._initialize_http()
            return
        env = dict(self.config.env) if self.config.env else None
        full_cmd = [self.config.command] + self.config.args
        print(f"[MCP] Starting process: {' '.join(full_cmd)}")
        try:
            self.process = subprocess.Popen(
                full_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except Exception as e:
            print(f"[MCP] Process creation failed: {type(e).__name__}: {e}")
            raise
        print(f"[MCP] Process started, pid={self.process.pid}")

        self._loop = asyncio.get_event_loop()

        # Start reader threads
        self._reader_thread = threading.Thread(target=self._read_responses_sync, daemon=True)
        self._reader_thread.start()
        self._stderr_thread = threading.Thread(target=self._read_stderr_sync, daemon=True)
        self._stderr_thread.start()

        # Send MCP initialize handshake
        await self._initialize_stdio()

    def _read_responses_sync(self):
        """Read stdout in a background thread, resolve futures on the event loop."""
        if not self.process or not self.process.stdout:
            return
        for raw_line in self.process.stdout:
            decoded = raw_line.decode().rstrip()
            if not decoded:
                continue
            try:
                msg = json.loads(decoded)
            except (json.JSONDecodeError, UnicodeDecodeError):
                print(f"[MCP:{self.config.name}:stdout] {decoded}")
                continue
            req_id = msg.get("id")
            print(f"[MCP:{self.config.name}] Got JSON-RPC: id={req_id}")
            if req_id is not None and req_id in self._pending and self._loop:
                future = self._pending[req_id]
                self._loop.call_soon_threadsafe(future.set_result, msg)
        print(f"[MCP:{self.config.name}] stdout closed")

    def _read_stderr_sync(self):
        """Drain stderr so the process doesn't block."""
        if not self.process or not self.process.stderr:
            return
        for raw_line in self.process.stderr:
            decoded = raw_line.decode().rstrip()
            if decoded:
                print(f"[MCP:{self.config.name}:stderr] {decoded}")

    async def _initialize_stdio(self):
        try:
            print(f"[MCP] Sending initialize to '{self.config.name}'...")
            result = await self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ramibot", "version": "1.0.0"},
            })
            print(f"[MCP] Initialize response from '{self.config.name}': {result}")
            # Send initialized notification (no id, no response expected)
            notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
            self._write_stdin(json.dumps(notification) + "\n")
            self._initialized = True
            print(f"[MCP] Server '{self.config.name}' initialized successfully!")
        except Exception as e:
            print(f"[MCP] Failed to initialize '{self.config.name}': {type(e).__name__}: {e}")

    async def _initialize_http(self):
        try:
            request = {
                "jsonrpc": "2.0",
                "id": str(uuid.uuid4()),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "ramibot", "version": "1.0.0"},
                },
            }
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(self.config.url, json=request)
                resp.raise_for_status()

            # Send initialized notification
            notification = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }
            async with httpx.AsyncClient(timeout=30) as client:
                await client.post(self.config.url, json=notification)

            self._initialized = True
        except Exception as e:
            print(f"[MCP] Failed to initialize HTTP server '{self.config.name}': {e}")

    def _write_stdin(self, data: str):
        if self.process and self.process.stdin:
            self.process.stdin.write(data.encode())
            self.process.stdin.flush()

    async def _send_request(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        if self.config.url:
            return await self._send_http_request(method, params, timeout=timeout)

        if not self.process or not self.process.stdin:
            raise RuntimeError(f"MCP server '{self.config.name}' not running")

        self._request_id += 1
        req_id = self._request_id
        request = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
        }
        if params:
            request["params"] = params

        loop = asyncio.get_event_loop()
        future = loop.create_future()
        self._pending[req_id] = future

        data = json.dumps(request) + "\n"
        self._write_stdin(data)

        try:
            result = await asyncio.wait_for(future, timeout=timeout)
        finally:
            self._pending.pop(req_id, None)

        if "error" in result:
            raise RuntimeError(f"MCP error: {result['error']}")
        return result.get("result", {})

    async def _send_http_request(self, method: str, params: dict | None = None, timeout: float = 30.0) -> dict:
        request = {
            "jsonrpc": "2.0",
            "id": str(uuid.uuid4()),
            "method": method,
        }
        if params:
            request["params"] = params

        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(self.config.url, json=request)
            resp.raise_for_status()
            data = resp.json()

        if "error" in data:
            raise RuntimeError(f"MCP error: {data['error']}")
        return data.get("result", {})

    async def list_tools(self) -> list[dict]:
        if not self._initialized:
            raise RuntimeError(f"MCP server '{self.config.name}' not initialized")
        result = await self._send_request("tools/list")
        return result.get("tools", [])

    async def call_tool(self, tool_name: str, arguments: dict) -> dict:
        if not self._initialized:
            raise RuntimeError(f"MCP server '{self.config.name}' not initialized")
        # Use a long timeout: the MCP server enforces its own per-tool timeouts
        # (up to 1600 s for msf_console). We add 100 s of headroom.
        result = await self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments,
        }, timeout=1700.0)
        return result

    async def stop(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None
        self._initialized = False


class MCPClient:
    def __init__(self):
        self.servers: dict[str, MCPServerConnection] = {}

    async def add_server(self, config: MCPServer) -> dict:
        db = await get_db()
        server_id = str(uuid.uuid4())
        await db.execute(
            """INSERT OR REPLACE INTO mcp_servers (id, name, command, args, env_json, url, created_at)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'))""",
            (
                server_id,
                config.name,
                config.command,
                json.dumps(config.args),
                json.dumps(config.env),
                config.url,
            ),
        )
        await db.commit()

        conn = MCPServerConnection(config)
        try:
            await conn.start()
        except Exception as e:
            import traceback
            print(f"[MCP] Failed to start server '{config.name}': {type(e).__name__}: {e}")
            traceback.print_exc()
        self.servers[config.name] = conn
        await self.sync_tools(config.name)
        return {"name": config.name, "status": "added", "initialized": conn._initialized}

    async def reconnect_server(self, config: MCPServer):
        """Reconnect a server from DB without re-inserting. Used at startup."""
        conn = MCPServerConnection(config)
        try:
            await conn.start()
            print(f"[MCP] Server '{config.name}' reconnected successfully")
        except Exception as e:
            print(f"[MCP] Failed to reconnect server '{config.name}': {type(e).__name__}: {e}")
        self.servers[config.name] = conn
        await self.sync_tools(config.name)

    async def sync_tools(self, server_name: str) -> int:
        """Fetch tools from server and replace them in the DB.

        Removes stale tools that no longer exist on the server.
        Returns the number of tools synced (0 if server is not initialized).
        """
        conn = self.servers.get(server_name)
        if not conn or not conn._initialized:
            print(f"[MCP] sync_tools: '{server_name}' not initialized, skipping")
            return 0
        try:
            tools = await conn.list_tools()
            await sync_server_tools(server_name, tools)
            print(f"[MCP] Synced {len(tools)} tools for '{server_name}'")
            return len(tools)
        except Exception as e:
            print(f"[MCP] Failed to sync tools for '{server_name}': {e}")
            return 0

    async def remove_server(self, name: str):
        if name in self.servers:
            await self.servers[name].stop()
            del self.servers[name]
        db = await get_db()
        await db.execute("DELETE FROM mcp_servers WHERE name = ?", (name,))
        await db.execute("DELETE FROM mcp_tools WHERE server_name = ?", (name,))
        await db.commit()

    async def list_servers(self) -> list[dict]:
        db = await get_db()
        cursor = await db.execute("SELECT * FROM mcp_servers")
        rows = await cursor.fetchall()
        return [
            {
                "id": row["id"],
                "name": row["name"],
                "command": row["command"],
                "args": json.loads(row["args"]) if row["args"] else [],
                "env": json.loads(row["env_json"]) if row["env_json"] else {},
                "url": row["url"],
                "connected": row["name"] in self.servers and self.servers[row["name"]]._initialized,
            }
            for row in rows
        ]

    async def list_tools(self, server_name: str) -> list[dict]:
        conn = self.servers.get(server_name)
        if not conn:
            raise ValueError(f"Server '{server_name}' not found")
        return await conn.list_tools()

    async def call_tool(self, server_name: str, tool_name: str, arguments: dict) -> dict:
        conn = self.servers.get(server_name)
        if not conn:
            raise ValueError(f"Server '{server_name}' not found")
        return await conn.call_tool(tool_name, arguments)

    async def get_all_tools(self) -> list[dict]:
        """Get tools from all connected servers, formatted for LLM consumption."""
        all_tools = []
        for name, conn in self.servers.items():
            if not conn._initialized:
                continue
            try:
                tools = await conn.list_tools()
                for tool in tools:
                    all_tools.append({
                        "type": "function",
                        "function": {
                            "name": f"{name}__{tool['name']}",
                            "description": tool.get("description", ""),
                            "parameters": tool.get("inputSchema", {"type": "object", "properties": {}}),
                        },
                    })
            except Exception:
                continue
        return all_tools

    async def shutdown(self):
        for conn in self.servers.values():
            await conn.stop()
        self.servers.clear()
