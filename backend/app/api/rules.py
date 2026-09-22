"""Detection rule management endpoints.

Analysts can view the ruleset; administrators can author new rules, toggle
rules on and off, and reload the ruleset from the on-disk YAML bundles. Every
change is recorded in the audit log.
"""

import os
from typing import Annotated

import yaml
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_admin, require_analyst
from app.database import get_db
from app.detection.loader import _read_bundle, load_rules, resolve_rules_directory
from app.models.audit import AuditAction
from app.models.rule import DetectionRule
from app.models.user import User
from app.schemas.rule import (
    RuleCreate,
    RuleListResponse,
    RuleOut,
    RuleReloadResponse,
    RuleUpdate,
)
from app.services.audit import write_audit

router = APIRouter(prefix="/rules", tags=["rules"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=RuleListResponse, summary="List detection rules")
def list_rules(
    db: DbSession,
    _user: Annotated[User, Depends(require_analyst)],
    category: str | None = Query(default=None, max_length=60),
    enabled: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=200),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> RuleListResponse:
    """Searchable, filterable, paginated ruleset."""
    query = db.query(DetectionRule)
    if category:
        query = query.filter(DetectionRule.category == category)
    if enabled is not None:
        query = query.filter(DetectionRule.enabled.is_(enabled))
    if search:
        pattern = f"%{search}%"
        query = query.filter(DetectionRule.name.ilike(pattern))

    total = query.count()
    items = (
        query.order_by(DetectionRule.category, DetectionRule.name)
        .offset(skip)
        .limit(limit)
        .all()
    )
    return RuleListResponse(total=total, items=[RuleOut.model_validate(r) for r in items])


@router.post("", response_model=RuleOut, status_code=status.HTTP_201_CREATED, summary="Create a detection rule")
def create_rule(
    payload: RuleCreate,
    db: DbSession,
    user: Annotated[User, Depends(require_admin)],
) -> RuleOut:
    """Author a new detection rule and persist it to the rules directory.

    The rule is appended to ``rules/{category}.yaml`` so it survives restarts
    and participates in normal reloads. The ruleset is reloaded from disk
    immediately so the engine picks it up.
    """
    existing = db.query(DetectionRule).filter(DetectionRule.name == payload.name).first()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A rule with that name already exists.",
        )

    rules_dir = resolve_rules_directory()
    if rules_dir is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Rules directory not found; cannot persist the rule.",
        )

    bundle_path = rules_dir / f"{payload.category}.yaml"
    if bundle_path.is_file():
        try:
            bundle = _read_bundle(bundle_path)
        except (yaml.YAMLError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Existing rule bundle is invalid: {exc}",
            ) from exc
    else:
        bundle = {"category": payload.category, "rules": []}

    bundle.setdefault("rules", []).append(
        {
            "name": payload.name,
            "description": payload.description or "",
            "severity": payload.severity,
            "enabled": payload.enabled,
            "threshold": payload.threshold,
            "time_window": payload.time_window,
            "rule_definition": payload.rule_definition.model_dump(exclude_none=True),
        }
    )

    tmp_path = bundle_path.with_suffix(".yaml.tmp")
    tmp_path.write_text(
        yaml.safe_dump(bundle, sort_keys=False, allow_unicode=True),
        encoding="utf-8",
    )
    os.replace(tmp_path, bundle_path)

    load_rules(db)

    rule = db.query(DetectionRule).filter(DetectionRule.name == payload.name).first()
    if rule is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Rule was written to disk but failed to load.",
        )

    write_audit(
        db,
        user=user,
        action=AuditAction.RULE_CREATED,
        resource_type="rule",
        resource_id=rule.id,
        details={"rule": rule.name, "category": rule.category, "severity": rule.severity},
    )
    return RuleOut.model_validate(rule)


@router.patch("/{rule_id}", response_model=RuleOut, summary="Enable or disable a rule")
def update_rule(
    rule_id: int,
    payload: RuleUpdate,
    db: DbSession,
    user: Annotated[User, Depends(require_admin)],
) -> RuleOut:
    """Toggle a detection rule without touching its definition."""
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found.")

    rule.enabled = payload.enabled
    db.commit()
    db.refresh(rule)

    write_audit(
        db,
        user=user,
        action=AuditAction.RULE_ENABLED if payload.enabled else AuditAction.RULE_DISABLED,
        resource_type="rule",
        resource_id=rule.id,
        details={"rule": rule.name},
    )
    return RuleOut.model_validate(rule)


@router.post("/reload", response_model=RuleReloadResponse, summary="Reload rules from disk")
def reload_rules(
    db: DbSession,
    user: Annotated[User, Depends(require_admin)],
) -> RuleReloadResponse:
    """Reload the rule bundles from the rules directory (upsert by name)."""
    result = load_rules(db)
    write_audit(
        db,
        user=user,
        action=AuditAction.RULES_RELOADED,
        resource_type="rules",
        resource_id="disk",
        details=result,
    )
    return RuleReloadResponse(**result)