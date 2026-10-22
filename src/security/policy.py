"""Deterministic Role-Based Access Control (RBAC) Policy Engine.

SECURITY ARCHITECTURE NOTE:
- Strictly denies by default (fail-closed).
- Loads explicit permissions from a structured policy configuration (policies.yaml).
- No wildcards ('*') are permitted; every action must be explicitly enumerated.
- Never relies on an LLM for policy evaluation.
"""
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml


class PolicyEngine:
    """Evaluates whether an agent role is authorized to perform a specific action."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        if policy_path is None:
            # Default to config/policies.yaml relative to project root
            project_root = Path(__file__).resolve().parent.parent.parent
            self.policy_path = project_root / "config" / "policies.yaml"
        else:
            self.policy_path = Path(policy_path)

        self._role_permissions: Dict[str, Set[str]] = {}
        self.load_policies()

    def load_policies(self) -> None:
        """Load and parse the YAML policy file into in-memory role permission sets."""
        self._role_permissions.clear()

        if not self.policy_path.exists():
            # Fail-closed: empty permissions means all actions will be denied
            return

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                raw_data = yaml.safe_load(f) or {}

            roles_section = raw_data.get("roles", {})
            for role_name, role_data in roles_section.items():
                if not isinstance(role_data, dict):
                    continue

                allowed = role_data.get("allowed_actions", [])
                safe_actions: Set[str] = set()

                for act in allowed:
                    # Security check: Wildcards are prohibited
                    if act == "*" or not isinstance(act, str):
                        continue
                    safe_actions.add(act.strip())

                self._role_permissions[role_name] = safe_actions

        except Exception:
            # Fail-closed on parsing errors: leave permissions empty
            self._role_permissions.clear()

    def is_action_permitted(self, role: str, action: str) -> bool:
        """Determine if a role is permitted to execute a specific action.

        Returns True ONLY if role is known and action is explicitly present in its allowlist.
        Returns False (deny-by-default) in all other cases.
        """
        if not role or not action:
            return False

        allowed_actions = self._role_permissions.get(role)
        if allowed_actions is None:
            return False

        return action in allowed_actions

    def get_allowed_actions(self, role: str) -> List[str]:
        """Return list of allowed actions for an authorized role."""
        return sorted(list(self._role_permissions.get(role, set())))


# Global singleton policy engine instance
policy_engine = PolicyEngine()
