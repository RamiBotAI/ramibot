import aiosqlite
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "ramibot.db"

_db_connection: aiosqlite.Connection | None = None


async def init_db():
    global _db_connection
    _db_connection = await aiosqlite.connect(str(DB_PATH))
    _db_connection.row_factory = aiosqlite.Row
    await _db_connection.execute("PRAGMA journal_mode=WAL")
    await _db_connection.execute("PRAGMA foreign_keys=ON")

    await _db_connection.executescript("""
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            title TEXT,
            provider TEXT,
            model TEXT,
            mcp_enabled BOOLEAN DEFAULT 0,
            reasoning_enabled BOOLEAN DEFAULT 0,
            team_mode TEXT DEFAULT 'red',
            created_at TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT,
            role TEXT,
            content TEXT,
            tool_calls TEXT,
            tool_traces TEXT,
            token_usage TEXT,
            latency_ms REAL,
            created_at TEXT,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS mcp_servers (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE,
            command TEXT,
            args TEXT,
            env_json TEXT,
            url TEXT,
            created_at TEXT
        );

        CREATE TABLE IF NOT EXISTS mcp_tools (
            server_name TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT,
            input_schema TEXT,
            synced_at TEXT,
            PRIMARY KEY (server_name, name)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id TEXT PRIMARY KEY,
            conversation_id TEXT,
            tool TEXT,
            severity TEXT DEFAULT 'info',
            title TEXT,
            description TEXT,
            target TEXT,
            created_at TEXT,
            FOREIGN KEY (conversation_id) REFERENCES conversations(id) ON DELETE SET NULL
        );
    """)
    await _db_connection.commit()

    # Migrate existing DBs: add team_mode column if missing
    try:
        await _db_connection.execute("ALTER TABLE conversations ADD COLUMN team_mode TEXT DEFAULT 'red'")
        await _db_connection.commit()
    except Exception:
        pass  # Column already exists


async def get_db() -> aiosqlite.Connection:
    if _db_connection is None:
        await init_db()
    return _db_connection


async def create_conversation(
    provider: str,
    model: str,
    title: str | None = None,
    mcp_enabled: bool = False,
    reasoning_enabled: bool = False,
    team_mode: str = "red",
) -> dict:
    db = await get_db()
    conv_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    title = title or "New conversation"
    await db.execute(
        """INSERT INTO conversations (id, title, provider, model, mcp_enabled, reasoning_enabled, team_mode, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (conv_id, title, provider, model, mcp_enabled, reasoning_enabled, team_mode, now, now),
    )
    await db.commit()
    return {
        "id": conv_id,
        "title": title,
        "provider": provider,
        "model": model,
        "mcp_enabled": mcp_enabled,
        "reasoning_enabled": reasoning_enabled,
        "team_mode": team_mode,
        "created_at": now,
        "updated_at": now,
    }


async def get_conversations() -> list[dict]:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM conversations ORDER BY updated_at DESC"
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def get_conversation_with_messages(conversation_id: str) -> dict | None:
    db = await get_db()
    cursor = await db.execute(
        "SELECT * FROM conversations WHERE id = ?", (conversation_id,)
    )
    conv = await cursor.fetchone()
    if conv is None:
        return None
    conv_dict = dict(conv)

    cursor = await db.execute(
        "SELECT * FROM messages WHERE conversation_id = ? ORDER BY created_at ASC",
        (conversation_id,),
    )
    rows = await cursor.fetchall()
    messages = []
    for row in rows:
        msg = dict(row)
        for field in ("tool_calls", "tool_traces", "token_usage"):
            if msg.get(field):
                try:
                    msg[field] = json.loads(msg[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        messages.append(msg)

    conv_dict["messages"] = messages
    return conv_dict


async def save_message(
    conversation_id: str,
    role: str,
    content: str,
    tool_calls: list | None = None,
    tool_traces: list | None = None,
    token_usage: dict | None = None,
    latency_ms: float | None = None,
) -> dict:
    db = await get_db()
    msg_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """INSERT INTO messages (id, conversation_id, role, content, tool_calls, tool_traces, token_usage, latency_ms, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            msg_id,
            conversation_id,
            role,
            content,
            json.dumps(tool_calls) if tool_calls else None,
            json.dumps(tool_traces) if tool_traces else None,
            json.dumps(token_usage) if token_usage else None,
            latency_ms,
            now,
        ),
    )
    # Auto-set title from first user message
    if role == "user":
        cursor = await db.execute(
            "SELECT title FROM conversations WHERE id = ?", (conversation_id,)
        )
        row = await cursor.fetchone()
        if row and row["title"] == "New conversation":
            snippet = content.strip().replace("\n", " ")[:60]
            await db.execute(
                "UPDATE conversations SET title = ?, updated_at = ? WHERE id = ?",
                (snippet, now, conversation_id),
            )
        else:
            await db.execute(
                "UPDATE conversations SET updated_at = ? WHERE id = ?",
                (now, conversation_id),
            )
    else:
        await db.execute(
            "UPDATE conversations SET updated_at = ? WHERE id = ?",
            (now, conversation_id),
        )
    await db.commit()
    return {
        "id": msg_id,
        "conversation_id": conversation_id,
        "role": role,
        "content": content,
        "tool_calls": tool_calls,
        "tool_traces": tool_traces,
        "token_usage": token_usage,
        "latency_ms": latency_ms,
        "created_at": now,
    }


async def update_conversation(conversation_id: str, **kwargs) -> dict | None:
    db = await get_db()
    allowed = {"title", "provider", "model", "mcp_enabled", "reasoning_enabled", "team_mode"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return None
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k} = ?" for k in updates)
    values = list(updates.values()) + [conversation_id]
    await db.execute(
        f"UPDATE conversations SET {set_clause} WHERE id = ?", values
    )
    await db.commit()
    cursor = await db.execute(
        "SELECT * FROM conversations WHERE id = ?", (conversation_id,)
    )
    row = await cursor.fetchone()
    return dict(row) if row else None


async def delete_conversation(conversation_id: str) -> bool:
    db = await get_db()
    cursor = await db.execute(
        "DELETE FROM conversations WHERE id = ?", (conversation_id,)
    )
    await db.commit()
    return cursor.rowcount > 0


async def sync_server_tools(server_name: str, tools: list[dict]) -> None:
    """Replace all tools for a server in the DB (no duplicates, removes stale entries)."""
    db = await get_db()
    now = datetime.now(timezone.utc).isoformat()
    await db.execute("DELETE FROM mcp_tools WHERE server_name = ?", (server_name,))
    for tool in tools:
        await db.execute(
            """INSERT INTO mcp_tools (server_name, name, description, input_schema, synced_at)
               VALUES (?, ?, ?, ?, ?)""",
            (
                server_name,
                tool["name"],
                tool.get("description", ""),
                json.dumps(tool.get("inputSchema", {})),
                now,
            ),
        )
    await db.commit()


# ── Findings ──────────────────────────────────────────────────────────────────

async def create_finding(
    conversation_id: str | None,
    tool: str,
    severity: str,
    title: str,
    description: str,
    target: str,
) -> dict:
    db = await get_db()
    finding_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    await db.execute(
        """INSERT INTO findings (id, conversation_id, tool, severity, title, description, target, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (finding_id, conversation_id, tool, severity, title, description, target, now),
    )
    await db.commit()
    return {
        "id": finding_id,
        "conversation_id": conversation_id,
        "tool": tool,
        "severity": severity,
        "title": title,
        "description": description,
        "target": target,
        "created_at": now,
    }


async def get_findings(
    conversation_id: str | None = None,
    severity: str | None = None,
    limit: int = 200,
) -> list[dict]:
    db = await get_db()
    conditions = []
    params: list = []
    if conversation_id:
        conditions.append("conversation_id = ?")
        params.append(conversation_id)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    params.append(limit)
    cursor = await db.execute(
        f"SELECT * FROM findings {where} ORDER BY created_at DESC LIMIT ?",
        params,
    )
    rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def delete_finding(finding_id: str) -> bool:
    db = await get_db()
    cursor = await db.execute("DELETE FROM findings WHERE id = ?", (finding_id,))
    await db.commit()
    return cursor.rowcount > 0
