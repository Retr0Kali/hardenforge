"""FastAPI backend. Token-authenticated; bind to 127.0.0.1 or put behind TLS."""
from __future__ import annotations

import os
import secrets as pysecrets
from pathlib import Path
from typing import Mapping

from fastapi import Depends, FastAPI, HTTPException
from fastapi import Response
from fastapi.responses import HTMLResponse
from . import report
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field, ConfigDict

from .ai.manager import AIManager
from .checks import Ctx
from .engine import load_rules, run_audit
from .platform_detect import detect
from .models import Result
from .scoring import summarize
from .storage import Store
from .secrets import PROVIDERS, SecretStore, SecretStoreError, mask


class KeyBody(BaseModel):
    api_key: str = Field(min_length=8, max_length=512)


class SystemIn(BaseModel):
    model_config = ConfigDict(extra="ignore")
    os_family: str = Field(max_length=32)
    hostname: str = Field(max_length=128)
    distro: str | None = Field(default=None, max_length=64)
    version: str | None = Field(default=None, max_length=128)


class IngestBody(BaseModel):
    system: SystemIn
    results: list[Result] = Field(max_length=5000)


def _profiles(results: list[Result]) -> dict:
    return {lvl: summarize([r for r in results if r.profile == lvl]) for lvl in ("L1", "L2")}


def create_app(environ: Mapping[str, str] | None = None) -> FastAPI:
    env = environ if environ is not None else os.environ
    token = env.get("HARDENFORGE_API_TOKEN", "")
    if len(token) < 16:
        raise RuntimeError("HARDENFORGE_API_TOKEN must be set (>=16 chars). Refusing to start unauthenticated.")
    data_dir = Path(env.get("HARDENFORGE_DATA_DIR", "./data"))
    rules_dir = Path(env.get("HARDENFORGE_RULES_DIR", "./rules"))  # server-side only; never client-supplied
    store = SecretStore(data_dir / "secrets.enc.json", environ=env)
    ai = AIManager.from_env(store, env)
    db = Store(data_dir / "hardenforge.db")
    bearer = HTTPBearer(auto_error=False)

    def auth(cred: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        if cred is None or not pysecrets.compare_digest(cred.credentials.encode(), token.encode()):
            raise HTTPException(status_code=401, detail="unauthorized")

    app = FastAPI(title="HardenForge", version="0.1.0")

    csp = ("default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; "
           "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def ui():
        return HTMLResponse((Path(__file__).parent / "dashboard.html").read_text(),
                            headers={"Content-Security-Policy": csp, "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store"})

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/system", dependencies=[Depends(auth)])
    def system():
        return detect()

    @app.post("/audit", dependencies=[Depends(auth)])
    def audit():
        info = detect()
        rules, load_errors = load_rules(rules_dir)
        results = run_audit(rules, Ctx(os_family=info["os_family"] or "", distro=info["distro"]))
        summary = summarize(results)
        dumped = [r.model_dump(mode="json") for r in results]
        scan_id = db.save({**info}, summary, dumped, "local")
        return {
            "scan_id": scan_id, "system": info, "summary": summary,
            "results": [r.model_dump(mode="json") for r in results],
            "rule_load_errors": [e.model_dump() for e in load_errors],
            "mode": "read-only",
        }

    @app.post("/ingest", dependencies=[Depends(auth)])
    def ingest(body: IngestBody):
        """Results produced by `hardenforge audit --format json` on another OS. Stored as unverified; summary is recomputed here."""
        summary = summarize(body.results)
        sid = db.save(body.system.model_dump(exclude={"hostname"}) | {"hostname": body.system.hostname}, summary,
                      [r.model_dump(mode="json") for r in body.results], "ingested (unverified)")
        return {"scan_id": sid, "summary": summary}

    @app.get("/scans", dependencies=[Depends(auth)])
    def scans():
        return db.latest_per_target()

    @app.get("/scans/{scan_id}", dependencies=[Depends(auth)])
    def scan(scan_id: int):
        s = db.get(scan_id)
        if not s:
            raise HTTPException(status_code=404, detail="scan not found")
        rs = [Result.model_validate(r) for r in s["results"]]
        s["profiles"] = _profiles(rs)
        s["history"] = db.history(s["host"], s["os_family"])
        return s

    @app.get("/scans/{scan_id}/report", dependencies=[Depends(auth)])
    def scan_report(scan_id: int, format: str = "html"):
        s = db.get(scan_id)
        if not s:
            raise HTTPException(status_code=404, detail="scan not found")
        if format == "csv":
            return Response(report.to_csv(s), media_type="text/csv")
        if format == "json":
            return Response(report.to_json(s), media_type="application/json")
        if format == "html":
            profs = _profiles([Result.model_validate(r) for r in s["results"]])
            return Response(report.to_html(s, profs), media_type="text/html", headers={"Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'"})
        raise HTTPException(status_code=400, detail="format must be html, csv or json")

    @app.get("/providers", dependencies=[Depends(auth)])
    def providers():
        out = []
        for p in PROVIDERS:
            try:
                k = store.get(p)
                err = None
            except SecretStoreError as e:
                k, err = None, str(e)
            out.append({"provider": p, "configured": bool(k), "key": mask(k), "model": ai.configs[p].model or None, "error": err})
        return {"providers": out, "usage": ai.usage_summary()}

    @app.put("/providers/{name}/key", dependencies=[Depends(auth)])
    def put_key(name: str, body: KeyBody):
        try:
            store.set(name, body.api_key)
        except SecretStoreError as e:
            raise HTTPException(status_code=400, detail=str(e))
        return {"provider": name, "key": mask(body.api_key)}

    @app.delete("/providers/{name}/key", dependencies=[Depends(auth)])
    def delete_key(name: str):
        try:
            return {"deleted": store.delete(name)}
        except SecretStoreError as e:
            raise HTTPException(status_code=400, detail=str(e))

    return app
