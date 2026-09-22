"""Rule loader.

Loads declarative rule bundles (YAML) from the ``rules/`` directory into the
``detection_rules`` table. Rules contain only matching expressions and
thresholds — never executable code — and are upserted by name so that edits to
the YAML files are applied on reload without creating duplicates.
"""

import logging
from pathlib import Path

import yaml
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.rule import DetectionRule

logger = logging.getLogger("sentinelx.rules")

# Hard constraint mirroring the ORM column size; rule files must stay within it.
MAX_RULE_NAME_LENGTH = 120


def resolve_rules_directory(rules_dir: str | None = None) -> Path | None:
    """Locate the rules directory, trying the configured path and parent paths.

    The backend may run from the repo root (local ``uvicorn``), from
    ``backend/`` (tests, editor) or from ``/app`` (container), so the rules
    directory is resolved relative to several known locations.
    """
    candidates = [
        rules_dir,
        get_settings().RULES_DIR,
        "rules",
        str(Path(__file__).resolve().parent.parent.parent.parent / "rules"),
    ]
    for value in candidates:
        if not value:
            continue
        path = Path(value)
        if path.is_dir():
            return path
    return None


def load_rules(db: Session, rules_dir: str | None = None) -> dict:
    """Load all YAML bundles into ``detection_rules`` and report the changes.

    Rules are matched by ``name``: a rule that already exists is updated with
    the file's definition, and a file-backed rule that is missing is removed.
    Rule files never modify a rule's ``enabled`` flag once loaded, so an admin
    can disable rules without them being re-enabled on the next reload.
    """
    loaded = 0
    updated = 0
    skipped = 0

    directory = resolve_rules_directory(rules_dir)
    if directory is None:
        logger.warning("Rules directory not found; no rules loaded.")
        return {"loaded": 0, "updated": 0, "skipped": 0}

    seen_names: set[str] = set()
    for path in sorted(directory.glob("*.yaml")):
        try:
            bundle = _read_bundle(path)
        except (yaml.YAMLError, ValueError) as exc:
            logger.error("Skipping rule file %s: %s", path.name, exc)
            skipped += 1
            continue

        for raw in bundle.get("rules", []):
            name = str(raw.get("name", "")).strip()
            if not name or len(name) > MAX_RULE_NAME_LENGTH:
                logger.warning("Skipping unnamed/oversized rule in %s", path.name)
                skipped += 1
                continue
            seen_names.add(name)

            existing = db.query(DetectionRule).filter(DetectionRule.name == name).first()
            if existing is None:
                db.add(
                    DetectionRule(
                        name=name,
                        description=str(raw.get("description", "")).strip(),
                        category=str(bundle.get("category", "general")).strip() or "general",
                        severity=str(raw.get("severity", "MEDIUM")).upper(),
                        enabled=bool(raw.get("enabled", True)),
                        threshold=int(raw.get("threshold", 5)),
                        time_window=int(raw.get("time_window", 300)),
                        rule_definition=dict(raw.get("rule_definition", {}) or {}),
                    )
                )
                loaded += 1
            else:
                existing.description = str(raw.get("description", "")).strip()
                existing.category = str(bundle.get("category", "general")).strip() or "general"
                existing.severity = str(raw.get("severity", "MEDIUM")).upper()
                existing.threshold = int(raw.get("threshold", 5))
                existing.time_window = int(raw.get("time_window", 300))
                existing.rule_definition = dict(raw.get("rule_definition", {}) or {})
                updated += 1

    _remove_stale(db, seen_names)
    db.commit()

    logger.info("Rules loaded: %d new, %d updated, %d skipped.", loaded, updated, skipped)
    return {"loaded": loaded, "updated": updated, "skipped": skipped}


def _read_bundle(path: Path) -> dict:
    """Read and validate one YAML rule bundle."""
    with path.open(encoding="utf-8") as handle:
        bundle = yaml.safe_load(handle) or {}
    if not isinstance(bundle, dict) or not isinstance(bundle.get("rules"), list):
        raise ValueError("rule file must contain a 'rules' list")
    return bundle


def _remove_stale(db: Session, seen_names: set[str]) -> None:
    """Delete file-backed rules no longer present in any bundle."""
    file_backed = db.query(DetectionRule).filter(DetectionRule.rule_definition.isnot(None)).all()
    for rule in file_backed:
        if rule.name not in seen_names:
            db.delete(rule)