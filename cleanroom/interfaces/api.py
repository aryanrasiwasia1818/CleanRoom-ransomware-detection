"""FastAPI app backing the dashboard.

Two tiny JSON endpoints plus the static dashboard. The API is a pure adapter over
:class:`~cleanroom.app.CleanRoomApp`; all analysis happens in the core.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

from cleanroom.app import CleanRoomApp
from cleanroom.config import Config
from cleanroom.simulator import FAMILIES

_DASHBOARD_DIR = Path(__file__).parent / "dashboard"


def create_app(data_root: str = "data/demo", config: Config | None = None) -> FastAPI:
    app = FastAPI(title="CleanRoom", version="1.0.0")
    cleanroom = CleanRoomApp(config or Config.from_env())

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        index_file = _DASHBOARD_DIR / "index.html"
        return index_file.read_text(encoding="utf-8")

    @app.get("/api/analysis")
    def analysis() -> JSONResponse:
        repo = cleanroom.repository(data_root)
        if len(repo) == 0:
            raise HTTPException(
                status_code=404,
                detail=f"No snapshots in {data_root}. Run 'cleanroom demo' first.",
            )
        return JSONResponse(cleanroom.analyze(repo).to_dict())

    @app.get("/api/meta")
    def meta() -> dict:
        repo = cleanroom.repository(data_root)
        return {
            "data_root": data_root,
            "snapshot_count": len(repo),
            "families": {name: cls().description for name, cls in FAMILIES.items()},
            "version": app.version,
        }

    return app
