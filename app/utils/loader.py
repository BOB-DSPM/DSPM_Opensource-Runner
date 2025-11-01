import yaml
from functools import lru_cache
from pathlib import Path

CATALOG = Path(__file__).resolve().parents[2] / "app" / "data" / "oss_catalog.yaml"

@lru_cache(maxsize=1)
def load_catalog():
    with open(CATALOG, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)