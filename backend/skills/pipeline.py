import json
import logging
import re
from pathlib import Path

from .base import SkillDecision
from .registry import SkillRegistry
from .classifier import InputClassifier
from .composer import PromptComposer

logger = logging.getLogger("ramibot.skills")

_LOG_FILE = Path(__file__).parent.parent / "skill_decisions.log"

# Default skill when no trigger matches and no history phase is known
TEAM_DEFAULTS = {
    "red": "recon",
    "blue": "analysis",
}

# Priority walk order: first match wins
TEAM_PRIORITY = {
    "red":  ["exploit", "recon", "analysis", "reporting"],
    "blue": ["defense", "analysis", "reporting", "recon"],
}

# Explicit phase-switch keywords (multi-word first, then single-word)
_PHASE_SWITCH_KEYWORDS: dict[str, list[str]] = {
    "reporting": [
        "generate report", "write report", "crear reporte", "write me a report",
        "informe", "reporte", "resumen ejecutivo",
    ],
    "defense": [
        "harden", "mitigate", "bloquear", "parche", "remediar",
        "defend", "patch",
    ],
    "exploit": [
        "privesc", "explotar",
        "exploit", "payload", "shell", "rce",
    ],
    "recon": [
        "escanear", "reconocimiento",
        "scan", "recon", "enumerate", "nmap",
    ],
}

# Markers in previous assistant messages that reveal the current phase
_PHASE_MARKERS: dict[str, list[str]] = {
    "recon":     ["[RECON]", "Nmap scan report", "nmap", "enumerat", "escaneo"],
    "exploit":   ["[VECTOR]", "[EXPLOIT]", "payload", "shell", "meterpreter", "privesc"],
    "defense":   ["[DEFENSE]", "[FIX]", "remediation", "patch", "mitigate"],
    "reporting": ["[REPORT]", "## Executive Summary", "## Findings", "CVSS"],
}

# Regexes used to detect targets (IPv4, URLs, host:port)
_TARGET_PATTERNS: list[re.Pattern] = [
    re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b'),        # IPv4 with optional port
    re.compile(r'https?://[^\s]+'),                               # URLs
    re.compile(r'\b[a-zA-Z0-9.-]{3,}\.[a-zA-Z]{2,}:\d{1,5}\b'), # host:port
]

# Verbs that signal "the user wants a tool to run right now"
_EXECUTION_VERBS: list[str] = [
    # Spanish imperatives
    "ejecuta", "escanea", "realiza", "haz", "lanza", "corre",
    "enumera", "enumeracion", "enumeración",
    "analiza", "comprueba", "verifica", "usa",
    # English
    "run", "execute", "scan", "enumerate", "analyze",
    "check", "launch", "do it",
]


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _extract_text(msg: dict) -> str:
    """Extract plain text from a message dict (handles str and list content)."""
    content = msg.get("content") or ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(
            part.get("text", "") for part in content if isinstance(part, dict)
        )
    return ""


def _extract_target_from_text(text: str) -> str:
    """Return the first target (IP / URL / host:port) found in `text`, or ''."""
    for pattern in _TARGET_PATTERNS:
        m = pattern.search(text)
        if m:
            return m.group(0)
    return ""


def _extract_last_target(history: list[dict]) -> str:
    """
    Search the last 10 history messages (newest first) for a target.
    Returns the most recent match or ''.
    """
    for msg in reversed(history[-10:]):
        t = _extract_target_from_text(_extract_text(msg))
        if t:
            return t
    return ""


def _wants_execution(user_input: str) -> bool:
    """
    Return True when the user's message contains an explicit imperative
    that signals they want a tool or action to run right now.
    """
    text = user_input.lower()
    for verb in _EXECUTION_VERBS:
        if re.search(r'\b' + re.escape(verb) + r'\b', text, re.UNICODE):
            return True
        # Substring fallback for accented / compound words longer than 4 chars
        if len(verb) > 4 and verb in text:
            return True
    return False


def _infer_phase(history: list[dict], team_mode: str) -> str:
    """
    Look at last 3 messages. Return current phase skill ID, or '' if unknown.
    Simple keyword heuristics only — no external deps.
    """
    if not history:
        return ""

    last_3 = history[-3:]
    text_blob = " ".join(_extract_text(m) for m in last_3).lower()

    # Check for explicit phase-switch keywords first (multi-word before single)
    for phase, keywords in _PHASE_SWITCH_KEYWORDS.items():
        for kw in keywords:
            if kw in text_blob:
                return phase

    # No explicit switch — infer from the most recent assistant message
    for m in reversed(last_3):
        if m.get("role") == "assistant":
            content = _extract_text(m)
            for phase, markers in _PHASE_MARKERS.items():
                for marker in markers:
                    if marker.lower() in content.lower():
                        return phase
            break  # only check the most recent assistant message

    return ""


def _append_decision(decision: SkillDecision) -> None:
    entry = {
        "timestamp": decision.timestamp,
        "team_mode": decision.team_mode,
        "input_snippet": decision.input_snippet,
        "matched_tags": decision.matched_tags,
        "activated_skills": decision.activated_skills,
        "risk_level": decision.risk_level,
        "prompt_length": decision.prompt_length,
        "dominant_skill": decision.dominant_skill,
        "fallback_used": decision.fallback_used,
        "phase_from_history": decision.phase_from_history,
        "last_target_used": decision.last_target_used,
        "wants_execution": decision.wants_execution,
    }
    try:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        logger.warning("Could not write skill log: %s", exc)


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

class SkillPipeline:
    def __init__(self, definitions_dir: Path | None = None):
        if definitions_dir is None:
            definitions_dir = Path(__file__).parent / "definitions"
        self.registry = SkillRegistry(definitions_dir)
        self.classifier = InputClassifier()
        self.composer = PromptComposer()

    def build_prompt(
        self,
        user_input: str,
        team_mode: str,
        history: list[dict] | None = None,
    ) -> tuple[str, SkillDecision]:
        history = history or []

        # 1. Get team skills from registry
        team_skills = self.registry.get_for_team(team_mode)

        # 2. Classify input → matched_tags
        matched_tags = self.classifier.classify(user_input, team_skills)

        # 3. Infer phase from history
        phase_from_history = _infer_phase(history, team_mode)

        # 4. Select dominant skill (always exactly 1)
        priority_list = TEAM_PRIORITY.get(team_mode, ["recon"])
        fallback_used = False
        dominant = ""

        if matched_tags:
            # Walk priority list, pick first match
            # Special rule: skip "reporting" if "exploit" or "defense" also matched
            reporting_suppressed = (
                "exploit" in matched_tags or "defense" in matched_tags
            )
            for candidate in priority_list:
                if candidate not in matched_tags:
                    continue
                if candidate == "reporting" and reporting_suppressed:
                    continue
                dominant = candidate
                break

            # If every match was suppressed (edge case), use first non-reporting match
            if not dominant:
                for candidate in priority_list:
                    if candidate in matched_tags and candidate != "reporting":
                        dominant = candidate
                        break

            # Last resort: first matched tag
            if not dominant:
                dominant = matched_tags[0]

            fallback_used = False

        elif phase_from_history:
            # No triggers matched but we know the current phase → continue it
            dominant = phase_from_history
            fallback_used = True

        else:
            # No triggers, no history → use team default
            dominant = TEAM_DEFAULTS.get(team_mode, "recon")
            fallback_used = True

        # 5. Activate exactly 1 skill
        active_skills = self.registry.get_by_ids([dominant])
        if not active_skills:
            active_skills = self.registry.get_by_ids([TEAM_DEFAULTS.get(team_mode, "recon")])
            if not active_skills:
                active_skills = team_skills

        # 6. Target carry-over
        #    Extract target from current input; if absent, look in history.
        #    Pass a carry-over target to the composer only when the current
        #    message does not already contain the target (avoids redundancy).
        current_target = _extract_target_from_text(user_input)
        history_target = _extract_last_target(history) if not current_target else ""
        # context_target is what we hand to the composer as carry-over context
        context_target = history_target  # "" when target is already in current input
        last_target_used = current_target or history_target

        # 7. Execution intent
        exec_intent = True

        # 8. Compose prompt
        prompt = self.composer.compose(
            team_mode,
            active_skills,
            context_target=context_target,
            exec_intent=exec_intent,
        )

        # 9. Determine max risk level
        risk_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        max_risk = max((risk_levels.get(s.risk_level, 1) for s in active_skills), default=1)
        risk_name = {v: k for k, v in risk_levels.items()}[max_risk]

        # 10. Log decision
        decision = SkillDecision(
            input_snippet=user_input[:100],
            team_mode=team_mode,
            matched_tags=matched_tags,
            activated_skills=[s.id for s in active_skills],
            risk_level=risk_name,
            prompt_length=len(prompt),
            dominant_skill=dominant,
            fallback_used=fallback_used,
            phase_from_history=phase_from_history,
            last_target_used=last_target_used,
            wants_execution=exec_intent,
        )
        logger.info(
            "Skill decision: dominant=%s fallback=%s phase_hist=%s "
            "target=%r exec=%s tags=%s skills=%s risk=%s",
            dominant, fallback_used, phase_from_history,
            last_target_used, exec_intent,
            matched_tags, decision.activated_skills, risk_name,
        )
        _append_decision(decision)

        return prompt, decision
