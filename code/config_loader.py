import json
from pathlib import Path


CODE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = CODE_DIR.parent
JSON_DIR = PROJECT_DIR / "json"


def load_json_config(file_name, default=None):
    path = JSON_DIR / file_name

    if not path.exists():
        if default is not None:
            return default
        raise FileNotFoundError(f"Missing configuration file: {path}")

    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_app_settings():
    defaults = {
        "app_name": "Fire Wall",
        "packet_count": 200,
        "summary_interval": 200,
        "event_output_file": "json/events.json",
    }
    settings = load_json_config("app_settings.json", defaults)
    return {**defaults, **settings}


def resolve_project_path(path_text):
    return PROJECT_DIR / path_text
