from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator


_FREQ_RE = re.compile(r"^\s*(\d+)\s*([smhd])\s*$", re.IGNORECASE)


def parse_frequency(value: str | int) -> int:
    """Parse a frequency string like '1h', '30m', '45s' into seconds."""
    if isinstance(value, int):
        return value
    m = _FREQ_RE.match(str(value))
    if not m:
        raise ValueError(f"invalid frequency: {value!r}")
    n, unit = int(m.group(1)), m.group(2).lower()
    return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


class WebhookConfig(BaseModel):
    url: str
    priority_threshold: float = 0.0
    headers: dict[str, str] = Field(default_factory=dict)
    name: str | None = None


class ProgramConfig(BaseModel):
    name: str
    domains: list[str]
    inscope_config: str | None = None
    scan_frequency: str = "1h"
    webhooks: list[WebhookConfig] = Field(default_factory=list)
    enabled: bool = True

    @field_validator("domains")
    @classmethod
    def _strip_domains(cls, v: list[str]) -> list[str]:
        return [d.strip().lower() for d in v if d and d.strip()]

    @property
    def scan_interval_seconds(self) -> int:
        return parse_frequency(self.scan_frequency)


class GlobalConfig(BaseModel):
    database_url: str = "postgresql+psycopg://bb:bb@localhost:5432/bb_sentinel"
    redis_url: str | None = None
    concurrency: int = 4
    httpx_threads: int = 50
    nuclei_concurrency: int = 25
    tool_paths: dict[str, str] = Field(default_factory=dict)
    log_level: str = "INFO"
    user_agent: str = "bb-sentinel/0.1"
    crtsh_timeout: int = 30
    webhook_timeout: int = 15

    def tool(self, name: str) -> str:
        return self.tool_paths.get(name, name)


class AppConfig(BaseModel):
    global_: GlobalConfig = Field(default_factory=GlobalConfig, alias="global")
    programs: dict[str, ProgramConfig] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}

    @classmethod
    def load(cls, programs_path: str | Path, global_path: str | Path | None = None) -> "AppConfig":
        programs_doc = _load_yaml(programs_path) if Path(programs_path).exists() else {}
        global_doc: dict[str, Any] = {}
        if global_path and Path(global_path).exists():
            global_doc = _load_yaml(global_path) or {}
        _expand_env(global_doc)
        programs_raw = programs_doc.get("programs", {}) if isinstance(programs_doc, dict) else {}
        programs: dict[str, ProgramConfig] = {}
        for name, body in (programs_raw or {}).items():
            body = dict(body or {})
            body.setdefault("name", name)
            programs[name] = ProgramConfig(**body)
        return cls(**{"global": GlobalConfig(**global_doc), "programs": programs})


def _load_yaml(path: str | Path) -> dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


_ENV_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?::-(.*?))?\}")


def _expand_env(obj: Any) -> None:
    """Recursively expand ${ENV} and ${ENV:-default} in string values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, str):
                obj[k] = _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), v)
            else:
                _expand_env(v)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            if isinstance(v, str):
                obj[i] = _ENV_RE.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), v)
            else:
                _expand_env(v)
