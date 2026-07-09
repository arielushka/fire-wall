import json
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
CONFIG_DIR = BASE_DIR / "config"


def load_json_config(file_name, default=None):
    path = CONFIG_DIR / file_name

    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(f"Missing configuration file: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_app_settings():
    defaults = {
        "app_name": "Anti Virus Network Firewall",
        "version": "1.0.0",
        "packet_count": 200,
        "summary_interval": 200,
        "event_output_file": "data/events.json",
    }
    settings = load_json_config("app_settings.json", defaults)
    return {**defaults, **settings}


def resolve_project_path(path_text):
    return BASE_DIR / path_text
