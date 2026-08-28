from pathlib import Path
import yaml


DATA_DIR = Path(__file__).parent.parent


def load_payload(name):
    path = DATA_DIR / "payloads" / f"{name}.yaml"

    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)