import yaml
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

REQUIRED_FIELDS = {"id", "title", "category", "command", "expected", "match_type"}
VALID_MATCH_TYPES = {"exact", "contains", "absent", "regex"}


class RulesLoader:
    def __init__(self, config_path):
        self.config_path = Path(config_path)
        self.rules = []

    def load(self):
        if not self.config_path.exists():
            raise FileNotFoundError(f"Rules config not found: {self.config_path}")

        with open(self.config_path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            raise ValueError("YAML config must have a top-level 'rules' key")

        raw_rules = data["rules"]
        if not isinstance(raw_rules, list):
            raise ValueError("'rules' must be a list")

        self.rules = []
        for i, rule in enumerate(raw_rules):
            if not isinstance(rule, dict):
                logger.warning("Rule at index %d is not a dict, skipping", i)
                continue

            missing = REQUIRED_FIELDS - set(rule.keys())
            if missing:
                logger.warning("Rule %s missing fields: %s", rule.get("id", i), missing)
                continue

            if rule["match_type"] not in VALID_MATCH_TYPES:
                logger.warning("Rule %s has bad match_type '%s'", rule["id"], rule["match_type"])
                continue

            self.rules.append(rule)

        logger.info("Loaded %d rules from %s", len(self.rules), self.config_path)
        return self.rules

    def get_rules_by_category(self, category):
        return [r for r in self.rules if r["category"].lower() == category.lower()]

    def get_categories(self):
        return sorted(set(r["category"] for r in self.rules))

    def get_rule_by_id(self, rule_id):
        for rule in self.rules:
            if rule["id"] == rule_id:
                return rule
        return None
