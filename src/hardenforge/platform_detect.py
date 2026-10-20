"""OS detection (read-only)."""
from __future__ import annotations

import platform
from pathlib import Path


def _os_release(root: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for rel in ("etc/os-release", "usr/lib/os-release"):
        p = root / rel
        if p.is_file():
            for line in p.read_text(errors="replace").splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    out[k.strip()] = v.strip().strip('"')
            break
    return out


def detect(root: Path = Path("/")) -> dict[str, str | None]:
    family = platform.system().lower()
    info: dict[str, str | None] = {
        "os_family": family, "distro": None, "version": None,
        "kernel": platform.release(), "arch": platform.machine(), "hostname": platform.node(),
    }
    if family == "linux":
        rel = _os_release(root)
        info["distro"], info["version"] = rel.get("ID"), rel.get("VERSION_ID")
    else:
        info["version"] = platform.version()
    return info
