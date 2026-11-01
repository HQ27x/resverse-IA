from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .db import init_db
from .util import ensure_dir, utc_now

PROFILES = ("ctf", "own", "interop", "malware", "analysis")
DEFAULT_PROFILE = "ctf"
DEFAULT_MODEL = "qwen2.5-coder:7b-instruct-q4_K_M"
CONFIG_VERSION = 1


class ReiaError(Exception):
    """User-facing error."""


def default_workspace_root() -> Path:
    env = os.environ.get("REIA_HOME")
    if env:
        return Path(env).expanduser().resolve()
    return (Path.home() / ".reia").resolve()


class Workspace:
    def __init__(self, root: str | Path | None = None) -> None:
        self.root = Path(root).expanduser().resolve() if root else default_workspace_root()

    @property
    def config_path(self) -> Path:
        return self.root / "config.json"

    @property
    def db_path(self) -> Path:
        return self.root / "reia.db"

    @property
    def projects_dir(self) -> Path:
        return self.root / "projects"

    @property
    def exports_dir(self) -> Path:
        return self.root / "exports"

    @property
    def patches_dir(self) -> Path:
        return self.root / "patches"

    @property
    def samples_dir(self) -> Path:
        return self.root / "samples"

    @property
    def logs_dir(self) -> Path:
        return self.root / "logs"

    def is_onedrive(self) -> bool:
        return "onedrive" in str(self.root).lower()

    def ensure(
        self,
        profile: str | None = None,
        *,
        allow_onedrive: bool = False,
        force: bool = False,
    ) -> "Workspace":
        profile = profile or DEFAULT_PROFILE
        if profile not in PROFILES:
            raise ReiaError(f"unknown profile: {profile}")
        if profile == "malware" and self.is_onedrive() and not allow_onedrive:
            raise ReiaError(
                "refusing to use a OneDrive-backed workspace for the malware profile; "
                "choose a local non-synced path with --workspace or pass --allow-onedrive"
            )

        for directory in (
            self.root,
            self.projects_dir,
            self.exports_dir,
            self.patches_dir,
            self.samples_dir,
            self.logs_dir,
        ):
            ensure_dir(directory)

        if self.config_path.exists() and not force:
            config = self.load_config()
            if profile and config.get("profile") != profile:
                config["profile"] = profile
                config["updated_at"] = utc_now()
                self.save_config(config)
        else:
            self.save_config(
                {
                    "version": CONFIG_VERSION,
                    "profile": profile,
                    "model": DEFAULT_MODEL,
                    "allow_cloud": False,
                    "created_at": utc_now(),
                    "updated_at": utc_now(),
                }
            )

        init_db(self.db_path)
        return self

    def load_config(self) -> dict[str, Any]:
        if not self.config_path.exists():
            raise ReiaError(f"workspace is not initialized: {self.root}")
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReiaError(f"cannot read workspace config: {exc}") from exc

    def save_config(self, config: dict[str, Any]) -> None:
        ensure_dir(self.root)
        self.config_path.write_text(
            json.dumps(config, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def require_initialized(self) -> "Workspace":
        if not self.db_path.exists() or not self.config_path.exists():
            raise ReiaError(
                f"workspace is not initialized at {self.root}; run: reia init --workspace \"{self.root}\""
            )
        return self
