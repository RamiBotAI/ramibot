import json
from pathlib import Path

from .base import Skill


class SkillRegistry:
    def __init__(self, definitions_dir: Path):
        self._skills: dict[str, Skill] = {}
        self._load(definitions_dir)

    def _load(self, path: Path):
        for f in path.glob("*.json"):
            data = json.loads(f.read_text(encoding="utf-8"))
            self._skills[data["id"]] = Skill(**data)

    def get_for_team(self, team_mode: str) -> list[Skill]:
        return [s for s in self._skills.values() if team_mode in s.teams]

    def get_by_ids(self, ids: list[str]) -> list[Skill]:
        return [self._skills[i] for i in ids if i in self._skills]

    def all_skills(self) -> list[Skill]:
        return list(self._skills.values())
