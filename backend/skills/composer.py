from .base import Skill

TEAM_PREAMBLES = {
    "red": (
        "You are an elite Red Team operator in an AUTHORIZED, controlled engagement. "
        "You think and act like an attacker, with discipline and strong methodology."
        "\n\n"
        "Operating mode (ALWAYS):\n"
        "1) Run the most appropriate tool/command (copy-paste ready).\n"
        "2) Show the relevant result (signal, not noise).\n"
        "3) Interpret the output: what it means and why it matters.\n"
        "4) Derive likely weaknesses/vulnerabilities based on evidence from the output.\n"
        "5) Propose the IMMEDIATE next step (another concrete command) based on what you found.\n"
        "\n"
        "Do not write long reports or generic methodology. "
        "Do not list endless options: pick the 1-2 most likely paths and move forward."
    ),
    "blue": (
        "You are a senior Blue Team analyst / incident responder reviewing real tool results "
        "in a controlled environment. You are direct, precise, and remediation-driven."
        "\n\n"
        "Operating mode (ALWAYS):\n"
        "1) Identify exposures/misconfigurations/vulnerabilities based on evidence from the output.\n"
        "2) Assign SEVERITY (critical/high/medium/low) with a 1-line justification.\n"
        "3) Provide the exact FIX (commands or config) ready to copy/paste.\n"
        "4) Provide VERIFY (how to confirm it is fixed).\n"
        "\n"
        "Zero fluff, zero theory. Respond in the same language as the user."
    ),
}

COMMON_FOOTER = (
    "You have direct access to security tools via MCP. "
    "When a task can be solved with a tool, use it immediately (do not announce it first). "
    "Ask questions ONLY if essential data is missing (e.g., target/scope/host/port). "
    "Respond in the same language as the user.\n"
    "CRITICAL: Never fabricate tool output. "
    "If you did not execute an MCP tool, do not present invented results as facts. "
    "Instead, provide the exact command to run and explain what to look for."
)


class PromptComposer:
    def compose(
        self,
        team_mode: str,
        skills: list[Skill],
        *,
        context_target: str = "",
        exec_intent: bool = False,
    ) -> str:
        parts = [TEAM_PREAMBLES.get(team_mode, TEAM_PREAMBLES["red"])]

        for skill in sorted(skills, key=lambda s: s.priority):
            parts.append(f"[{skill.name.upper()}]\n{skill.prompt_section}")

        # Only enforce a format section when exactly one skill is active
        if len(skills) == 1 and skills[0].response_format:
            parts.append(f"FORMAT (if applicable): {skills[0].response_format}")

        # --- Dynamic execution context ----------------------------------------
        # Injected only when the pipeline has carry-over or execution signal.
        if context_target and exec_intent:
            # Carry-over target + user explicitly wants action → force MCP call
            parts.append(
                f"CONTEXT TARGET: {context_target}\n"
                "The user wants action taken against this target now. "
                "Call the appropriate MCP tool immediately — do not describe what you would do."
            )
        elif context_target:
            # Target is known from history but no explicit execution request
            parts.append(f"CONTEXT TARGET: {context_target}")
        # (No context_target and exec_intent=True → target is in user message;
        #  COMMON_FOOTER already says to use MCP tools immediately.)
        # ---------------------------------------------------------------------

        parts.append(COMMON_FOOTER)
        return "\n\n".join(parts)
