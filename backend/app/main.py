"""
SecureMailScope X - FastAPI Main Application Entrypoint
Explainable AI-Driven Email Cryptographic Forensics with Post-Quantum Readiness and Blockchain-Backed Chain of Custody.
"""

import sys
import os
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Ensure backend root is on sys.path
BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from app.core.config import (
    API_TITLE,
    API_VERSION,
    API_DESCRIPTION,
    CORS_ORIGINS
)
from app.api.v1.router import api_v1_router
from app.schemas.api import ErrorResponse

# Initialize FastAPI Application
app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configure Cross-Origin Resource Sharing (CORS) for local frontend dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API Routers
app.include_router(api_v1_router)


# Global Exception Handlers
@app.exception_handler(ValueError)
async def value_error_handler(request: Request, exc: ValueError):
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content=ErrorResponse(
            status_code=400,
            error_code="BAD_REQUEST",
            message=str(exc)
        ).model_dump()
    )


@app.exception_handler(FileNotFoundError)
async def file_not_found_handler(request: Request, exc: FileNotFoundError):
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content=ErrorResponse(
            status_code=404,
            error_code="NOT_FOUND",
            message=str(exc)
        ).model_dump()
    )


@app.exception_handler(RuntimeError)
async def runtime_error_handler(request: Request, exc: RuntimeError):
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            status_code=500,
            error_code="INTERNAL_SERVER_ERROR",
            message=str(exc)
        ).model_dump()
    )


@app.get("/", tags=["Root"])
def root():
    return {
        "title": API_TITLE,
        "version": API_VERSION,
        "status": "online",
        "documentation": "/docs",
        "openapi_schema": "/openapi.json",
        "api_v1": "/api/v1"
    }


@app.get("/health", tags=["Root"])
def root_health():
    from app.core.tshark_detector import TSharkDetector
    from app.db.database import get_database_engine_type, get_db_connection
    tshark_ok, tshark_ver = TSharkDetector.get_version()
    db_engine = get_database_engine_type().lower()
    db_ok = True
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1;")
        cur.fetchone()
        conn.close()
    except Exception:
        db_ok = False

    return {
        "status": "healthy" if (tshark_ok and db_ok) else "degraded",
        "version": API_VERSION,
        "database_connected": db_ok,
        "database_engine": db_engine,
        "tshark_available": tshark_ok,
        "mode": "cloud_deployed" if db_engine == "postgresql" else "offline_first_local"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
