from pathlib import Path
import yaml


DATA_DIR = Path(__file__).parent.parent


def load_template(name):
    path = DATA_DIR / "templates" / f"{name}.yaml"

    with path.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)