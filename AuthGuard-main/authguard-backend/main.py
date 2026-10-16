

import json
import os
import re
from urllib.parse import urlsplit

from fastapi import FastAPI, Depends, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from sqlalchemy import func

from database import Base, engine, get_db
import models

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address


# Create database tables
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="AuthGuard AI Backend",
    version="1.0.0",
    description="Explainable website risk analysis API",
)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "FRONTEND_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)


ALLOWED_REPUTATIONS = {
    "unknown",
    "safe",
    "suspicious",
    "malicious",
}


class RiskRequest(BaseModel):
    hostname: str = Field(min_length=1, max_length=253)
    otp_field_detected: bool = False
    redirect_count: int = Field(default=0, ge=0, le=50)
    reputation: str = "unknown"

    @field_validator("hostname")
    @classmethod
    def validate_hostname(cls, value):
        value = value.strip().lower().rstrip(".")

        if not value:
            raise ValueError("Hostname cannot be empty.")

        if (
            "://" in value
            or "/" in value
            or "?" in value
            or "#" in value
            or "@" in value
            or any(ch.isspace() for ch in value)
        ):
            raise ValueError("Provide a hostname, not a full URL.")

        try:
            parsed = urlsplit("//" + value)
            if parsed.hostname != value or parsed.port is not None:
                raise ValueError("Invalid hostname.")
        except ValueError:
            raise ValueError("Invalid hostname.")

        labels = value.split(".")
        for label in labels:
            if (
                not label
                or len(label) > 63
                or not re.fullmatch(
                    r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?",
                    label,
                )
            ):
                raise ValueError("Invalid hostname format.")

        return value

    @field_validator("reputation")
    @classmethod
    def validate_reputation(cls, value):
        value = value.strip().lower()

        if value not in ALLOWED_REPUTATIONS:
            raise ValueError(
                "Use unknown, safe, suspicious, or malicious."
            )

        return value


def _rule_based_assessment(data: RiskRequest):
    """Existing explainable rule-based risk assessment."""
    score = 0
    reasons = []

    if data.redirect_count >= 3:
        score += 25
        reasons.append("Multiple redirects were reported.")

    if data.otp_field_detected:
        reasons.append(
            "An OTP-like field was detected; this alone is not suspicious."
        )

    if data.reputation == "malicious":
        score += 70
        reasons.append(
            "The supplied domain reputation is marked malicious."
        )
    elif data.reputation == "suspicious":
        score += 40
        reasons.append(
            "The supplied domain reputation is suspicious."
        )

    score = min(score, 100)

    if score >= 60:
        level = "high"
        decision = "block"
        action = (
            "Avoid entering an OTP; verify the website independently."
        )
    elif score >= 25:
        level = "medium"
        decision = "verify"
        action = (
            "Check the domain carefully before entering an OTP."
        )
    else:
        level = "low"
        decision = "allow"
        action = (
            "Continue cautiously; a low score does not guarantee safety."
        )

    if not reasons:
        reasons.append(
            "No configured risk indicators were reported."
        )

    return {
        "risk_score": score,
        "risk_level": level,
        "decision": decision,
        "reasons": reasons,
        "recommended_action": action,
    }


def assess_risk(data: RiskRequest):
    """Current primary assessment."""
    return _rule_based_assessment(data)


def fallback_assess_risk(data: RiskRequest):
    """Rule-based fallback entry point for future ML integration."""
    return _rule_based_assessment(data)


@app.get("/api/v1/health")
def health():
    return {
        "status": "ok",
        "service": "AuthGuard AI Backend",
    }


@app.post("/api/v1/risk/analyze")
@limiter.limit("6/minute")
def analyze_risk(
    data: RiskRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    try:
        result = assess_risk(data)
        analysis_mode = "rule_based"

    except Exception:
        try:
            result = fallback_assess_risk(data)
            analysis_mode = "fallback"
        except Exception:
            raise HTTPException(
                status_code=500,
                detail="Risk assessment and fallback both failed.",
            )

    event = models.RiskEvent(
        hostname=data.hostname,
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        decision=result["decision"],
        reasons=json.dumps(result["reasons"]),
    )

    try:
        db.add(event)
        db.commit()
        db.refresh(event)
    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Could not save risk event.",
        )

    return {
        **result,
        "analysis_mode": analysis_mode,
        "event_id": event.id,
        "created_at": event.created_at,
    }


@app.get("/api/v1/risk/events")
def list_risk_events(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
):
    events = (
        db.query(models.RiskEvent)
        .order_by(models.RiskEvent.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "items": [
            {
                "event_id": event.id,
                "hostname": event.hostname,
                "risk_score": event.risk_score,
                "risk_level": event.risk_level,
                "decision": event.decision,
                "reasons": json.loads(event.reasons),
                "created_at": event.created_at,
            }
            for event in events
        ],
        "limit": limit,
        "offset": offset,
    }


@app.delete("/api/v1/risk/events", status_code=204)
def clear_risk_events(db: Session = Depends(get_db)):
    db.query(models.RiskEvent).delete(synchronize_session=False)
    db.commit()
    return Response(status_code=204)


@app.get("/api/v1/risk/events/{event_id}")
def get_risk_event(
    event_id: int,
    db: Session = Depends(get_db),
):
    event = (
        db.query(models.RiskEvent)
        .filter(models.RiskEvent.id == event_id)
        .first()
    )

    if event is None:
        raise HTTPException(
            status_code=404,
            detail="Risk event not found.",
        )

    return {
        "event_id": event.id,
        "hostname": event.hostname,
        "risk_score": event.risk_score,
        "risk_level": event.risk_level,
        "decision": event.decision,
        "reasons": json.loads(event.reasons),
        "created_at": event.created_at,
    }


@app.get("/api/v1/dashboard/summary")
def dashboard_summary(db: Session = Depends(get_db)):
    total = (
        db.query(func.count(models.RiskEvent.id)).scalar() or 0
    )

    high_risk = (
        db.query(func.count(models.RiskEvent.id))
        .filter(models.RiskEvent.risk_level == "high")
        .scalar() or 0
    )

    medium_risk = (
        db.query(func.count(models.RiskEvent.id))
        .filter(models.RiskEvent.risk_level == "medium")
        .scalar() or 0
    )

    low_risk = (
        db.query(func.count(models.RiskEvent.id))
        .filter(models.RiskEvent.risk_level == "low")
        .scalar() or 0
    )

    blocked = (
        db.query(func.count(models.RiskEvent.id))
        .filter(models.RiskEvent.decision == "block")
        .scalar() or 0
    )

    return {
        "total_events": total,
        "high_risk_events": high_risk,
        "medium_risk_events": medium_risk,
        "low_risk_events": low_risk,
        "blocked_events": blocked,
    }
