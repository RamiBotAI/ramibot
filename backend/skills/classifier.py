import re

from .base import Skill


class InputClassifier:
    def classify(self, user_input: str, skills: list[Skill]) -> list[str]:
        """Retorna lista de tags (skill IDs) que matchean con el input."""
        text = user_input.lower()
        matched = []
        for skill in skills:
            if self._matches(text, skill.triggers):
                matched.append(skill.id)
        return matched

    def _matches(self, text: str, triggers: list[str]) -> bool:
        # Pass 1: strict word-boundary regex
        for t in triggers:
            if re.search(r'\b' + re.escape(t) + r'\b', text):
                return True
        # Pass 2: substring fallback — only for multi-word phrases or triggers > 4 chars
        # The len > 4 guard prevents short words like "log" matching "catalog"
        for t in triggers:
            if len(t) > 4 and t in text:
                return True
        return False
