from pathlib import Path
import yaml


RULE_FILE = Path(__file__).resolve().parents[2] / "checks" / "cors_rules.yaml"


def load_rules():
    with RULE_FILE.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f)["rules"]


def get_rule(rule_id):
    for rule in load_rules():
        if rule["id"].lower() == rule_id.lower():
            return rule

    return None