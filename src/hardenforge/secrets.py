"""Provider credential storage.

Priority: environment variable > encrypted store.
The store is a Fernet-encrypted JSON file (0600). The master key comes from
HARDENFORGE_MASTER_KEY (env / OS secret manager) and is never written next to the data.
Keys are never returned in full: use mask().
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Mapping

from cryptography.fernet import Fernet, InvalidToken

PROVIDERS = ("gemini", "openai", "anthropic")


class SecretStoreError(Exception):
    pass


def mask(key: str | None) -> str | None:
    if not key:
        return None
    return "****" + key[-4:] if len(key) >= 12 else "****"


class SecretStore:
    def __init__(self, path: Path, environ: Mapping[str, str] | None = None):
        self.path = Path(path)
        self.environ = environ if environ is not None else os.environ

    @staticmethod
    def _check(provider: str) -> str:
        if provider not in PROVIDERS:
            raise SecretStoreError(f"unknown provider: {provider}")
        return provider

    def _fernet(self) -> Fernet:
        mk = self.environ.get("HARDENFORGE_MASTER_KEY")
        if not mk:
            raise SecretStoreError("HARDENFORGE_MASTER_KEY is not set; cannot use encrypted key store")
        try:
            return Fernet(mk.encode())
        except ValueError as e:
            raise SecretStoreError("HARDENFORGE_MASTER_KEY is not a valid Fernet key") from e

    def _load(self) -> dict[str, str]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text())

    def _save(self, data: dict[str, str]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    def get(self, provider: str) -> str | None:
        self._check(provider)
        env = self.environ.get(f"HARDENFORGE_{provider.upper()}_API_KEY")
        if env:
            return env
        token = self._load().get(provider)
        if not token:
            return None
        try:
            return self._fernet().decrypt(token.encode()).decode()
        except InvalidToken as e:
            raise SecretStoreError("stored key cannot be decrypted with the current master key") from e

    def set(self, provider: str, key: str) -> None:
        self._check(provider)
        if not key or len(key) < 8 or any(c.isspace() for c in key):
            raise SecretStoreError("API key format looks invalid")
        data = self._load()
        data[provider] = self._fernet().encrypt(key.encode()).decode()
        self._save(data)

    def delete(self, provider: str) -> bool:
        self._check(provider)
        data = self._load()
        existed = data.pop(provider, None) is not None
        self._save(data)
        return existed
