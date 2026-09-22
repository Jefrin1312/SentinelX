"""Detection rule management endpoints.

Analysts can view the ruleset; administrators can toggle rules on and off and
reload the ruleset from the on-disk YAML bundles. Every change is recorded in
the audit log.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.auth.dependencies import require_admin, require_analyst
from app.database import get_db
from app.detection.loader import load_rules
from app.models.audit import AuditAction
from app.models.rule import DetectionRule
from app.models.user import User
from app.schemas.rule import RuleListResponse, RuleOut, RuleReloadResponse, RuleUpdate
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