"""
FastAPI Application Factory and Static Workbench Entrypoint for SentinelGraph.
Automatically initializes migrations and serves both `/api/v1/*` and the Investigator Workbench UI.
"""
from pathlib import Path
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from backend.app.api.routes import router as api_router
from backend.app.core.config import settings
from backend.app.core.exceptions import SentinelGraphError
from backend.app.db.connection import default_db
from backend.app.ingestion.seeder import SyntheticCrimeSeeder


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Enterprise Anti-Money Laundering (AML), Shadow-Mode Rule Backtesting (RuleForge), "
            "Multi-Hop Graph Forensics, and Four-Eyes FinCEN SAR Compliance Platform."
        ),
    )

    @app.on_event("startup")
    def on_startup() -> None:
        SyntheticCrimeSeeder(default_db).seed_all()

    @app.exception_handler(SentinelGraphError)
    async def domain_exception_handler(_request: Request, exc: SentinelGraphError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.to_dict())

    app.include_router(api_router)

    @app.get("/health")
    def health_check() -> dict:
        return {"status": "healthy", "service": settings.app_name, "version": settings.app_version}

    @app.get("/", response_class=HTMLResponse)
    def serve_workbench_ui() -> HTMLResponse:
        ui_path = Path(__file__).resolve().parents[2] / "frontend" / "public" / "index.html"
        if ui_path.exists():
            return HTMLResponse(content=ui_path.read_text(encoding="utf-8"), status_code=200)
        return HTMLResponse(content="<h1>SentinelGraph API Server Running</h1>", status_code=200)

    return app


app = create_app()
