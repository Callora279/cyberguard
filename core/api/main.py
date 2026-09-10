"""CyberGuard AI - FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.api.middleware.logging import LoggingMiddleware
from core.api.middleware.rate_limit import RateLimitMiddleware
from core.api.routes import (
    ai_governance,
    alerts,
    auth,
    cyber_twin,
    fraud_detection,
    health,
    machine_identity,
    risk_score,
    security_debt,
    supply_chain,
    users,
)
from core.database.db import init_db
from core.services.ai_governance.real_time_enforcer import install as install_enforcer
from core.utils.config import settings
from core.utils.exceptions import CyberGuardError
from core.utils.logger import configure_logging, get_logger, report_to_liveguard

logger = get_logger("api.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    init_db()
    install_enforcer()  # route all AI calls through governance
    logger.info("%s %s started (env=%s)", settings.APP_NAME, settings.VERSION, settings.ENV)
    yield
    logger.info("shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Unified AI-era cyber risk platform: AI governance, security debt, "
    "supply chain, machine identity, fraud detection, predictive risk and a cyber twin.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.ENV == "dev" else [],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(LoggingMiddleware)


@app.exception_handler(CyberGuardError)
async def _cg_error_handler(request: Request, exc: CyberGuardError):
    if exc.status_code >= 500:
        report_to_liveguard(f"{type(exc).__name__}: {exc.message}", severity="error")
    return JSONResponse(status_code=exc.status_code, content=exc.to_dict())


@app.exception_handler(Exception)
async def _unhandled_handler(request: Request, exc: Exception):
    logger.exception("unhandled exception on %s", request.url.path)
    report_to_liveguard(f"unhandled: {exc}", severity="critical")
    return JSONResponse(status_code=500, content={"error": "internal_error", "message": "internal server error"})


API = "/api"
app.include_router(health.router, prefix=API)
app.include_router(auth.router, prefix=f"{API}/auth", tags=["auth"])
app.include_router(users.router, prefix=f"{API}/users", tags=["users"])
app.include_router(alerts.router, prefix=API, tags=["alerts"])
app.include_router(ai_governance.router, prefix=f"{API}/ai-governance", tags=["ai-governance"])
app.include_router(security_debt.router, prefix=f"{API}/security-debt", tags=["security-debt"])
app.include_router(supply_chain.router, prefix=f"{API}/supply-chain", tags=["supply-chain"])
app.include_router(machine_identity.router, prefix=f"{API}/machine-identity", tags=["machine-identity"])
app.include_router(fraud_detection.router, prefix=f"{API}/fraud-detection", tags=["fraud-detection"])

# risk-score + predictive-risk, cyber-twin and the Chakra internal endpoint
app.include_router(risk_score.router, prefix=f"{API}/risk-score", tags=["risk-score"])
app.include_router(cyber_twin.router, prefix=f"{API}/cyber-twin", tags=["cyber-twin"])
app.include_router(health.internal_router, prefix="/internal", tags=["internal"])


@app.get("/", include_in_schema=False)
async def root():
    return {"service": settings.APP_NAME, "version": settings.VERSION, "docs": "/docs"}
