"""
SecureMailScope X - API Version 1 Router Aggregator
"""

from fastapi import APIRouter
from app.api.v1.endpoints import health, analyze, sessions, rules, enrichment, advanced, correlation, siem, rbac

api_v1_router = APIRouter(prefix="/api/v1")

# Mount sub-routers
api_v1_router.include_router(health.router, tags=["Health & System Diagnostics"])
api_v1_router.include_router(analyze.router, tags=["Forensic PCAP Analysis"])
api_v1_router.include_router(sessions.router, tags=["Session Forensics & Drill-Down"])
api_v1_router.include_router(rules.router, tags=["Cryptographic Rules & PQC Catalog"])
api_v1_router.include_router(enrichment.router, tags=["DNS Auth & EML Forensics"])
api_v1_router.include_router(advanced.router, tags=["Advanced Analysis & Cases"])
api_v1_router.include_router(correlation.router, tags=["Cross-Case Correlation & Threat Intel"])
api_v1_router.include_router(siem.router, tags=["SIEM / SOC Integration & Event Export"])
api_v1_router.include_router(rbac.router, tags=["Multi-Analyst RBAC & Peer Review"])
