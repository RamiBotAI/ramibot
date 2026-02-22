from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class Skill:
    id: str                       # "recon", "exploit", "defense"
    name: str                     # "Reconnaissance"
    description: str              # para logging/debug
    teams: list[str]              # ["red"], ["blue"], ["red", "blue"]
    triggers: list[str]           # keywords/regex que activan este skill
    priority: int                 # orden al componer el prompt (menor = primero)
    prompt_section: str           # texto que contribuye al system prompt
    tool_hints: list[str] = field(default_factory=list)  # tools preferidos (prefijos MCP)
    risk_level: str = "medium"    # "low", "medium", "high", "critical"
    response_format: str = ""     # instrucciones de formato específicas


@dataclass
class SkillDecision:
    """Log de qué skills se activaron y por qué."""
    input_snippet: str            # primeros 100 chars del input
    team_mode: str
    matched_tags: list[str]       # tags del classifier
    activated_skills: list[str]   # skill IDs activados
    risk_level: str               # máximo risk_level de skills activos
    prompt_length: int            # chars del prompt ensamblado
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    dominant_skill: str = ""      # which skill was selected as dominant
    fallback_used: bool = False   # True if no triggers matched → default used
    phase_from_history: str = ""  # phase inferred from history ("recon", "exploit", etc.)
    last_target_used: str = ""    # target extracted from current input or history carry-over
    wants_execution: bool = False # True when user intent is to run a tool/action
