# Engagement Rules — Operational Boundaries

## Scope Enforcement

```
BEFORE EVERY TOOL CALL:
  1. Is target in allowed_scope?      → NO = ABORT
  2. Is tool appropriate for stage?   → NO = WRONG ORDER
  3. Is risk level acceptable?        → HIGH = CONFIRM WITH USER
  4. Will this be excessively noisy?  → YES = FIND QUIETER APPROACH
```

## Risk Classification

| Level | Tools | Rule |
|---|---|---|
| LOW | whois, dig, whatweb, searchsploit | Run freely |
| MEDIUM | nmap, nikto, gobuster, dirb, enum4linux | Run with purpose, not blindly |
| HIGH | hydra, sqlmap, hashcat, john | Require clear justification |

## Abort Conditions

Immediately stop if:
- Target resolves outside allowed scope
- Scan returns results from unintended hosts
- User requests action against production without explicit authorization
- Tool behavior is unexpected (possible honeypot/IDS)

## Rate Limiting Awareness

```
Global concurrent:     3 max
Per-tool concurrent:   1 max
```

Do NOT queue multiple heavy scans. Serialize them.
Plan scan order to maximize info per time unit.

## Evidence Handling

- Log every tool invocation and result
- Preserve raw output before interpretation
- Track finding chain: discovery → enumeration → exploitation
- Timestamp everything

## Stealth Gradient

```
QUIET   ──────────────────────────────── LOUD
whois → whatweb → nmap-sS → gobuster → nikto → hydra → sqlmap
```

Start left. Move right only when needed.
