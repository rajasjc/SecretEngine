"""
seckey.engines.rotation
=======================
Full 12-step rotation orchestrator + bulk rotation.
"""
from __future__ import annotations

import time
from datetime import datetime
from typing import List, Optional

from seckey.connectors.base import SecretStore, generate_secret
from seckey.engines import (
    AuditLogger,
    NotificationEngine,
    PolicyEngine,
    RollbackEngine,
    ValidationEngine,
)
from seckey.models import (
    AuditEventType,
    RotationResult,
    SecretMetadata,
    SecretType,
    ValidationType,
)


class RotationOptions:
    def __init__(
        self,
        force: bool = False,
        dry_run: bool = False,
        actor: str = "admin",
        approved_by: str = "",
        secret_len: int = 32,
        secret_type: SecretType = SecretType.PASSWORD,
        validation_type: ValidationType = ValidationType.NONE,
        validation_endpoint: str = "",
    ):
        self.force               = force
        self.dry_run             = dry_run
        self.actor               = actor
        self.approved_by         = approved_by
        self.secret_len          = secret_len
        self.secret_type         = secret_type
        self.validation_type     = validation_type
        self.validation_endpoint = validation_endpoint


class RotationEngine:
    """
    Orchestrates the complete 12-step secret rotation lifecycle.

    Steps:
      1.  Trigger (external call)
      2.  Read metadata
      3.  Validate eligibility (policy)
      4.  Generate new secret
      5.  Store new secret in vault
      6.  Update target application (hook)
      7.  Validation engine
      8.  Disable old secret / delete old version  [SUCCESS]
      9.  Update rotation timestamp + version
      10. Audit & compliance logging
      11. Send notification
      12. Rollback + incident generation           [FAILURE]
    """

    def __init__(
        self,
        store: SecretStore,
        policy: PolicyEngine,
        auditor: AuditLogger,
        notifier: NotificationEngine,
    ):
        self._store     = store
        self._policy    = policy
        self._auditor   = auditor
        self._notifier  = notifier
        self._validator = ValidationEngine()
        self._rollback  = RollbackEngine(store, auditor, notifier)

    # ── Single rotation ────────────────────────────────────────────────────

    def rotate(
        self,
        asset_id: str,
        secret_name: str,
        env: str,
        owner: str,
        opts: RotationOptions,
    ) -> RotationResult:
        start = time.time()

        # Step 2 — Read metadata
        try:
            meta: SecretMetadata = self._store.get_metadata(secret_name)
        except KeyError as exc:
            return self._fail(asset_id, secret_name, str(exc), start)

        # Step 3 — Validate eligibility
        try:
            self._policy.validate_eligibility(meta, force=opts.force)
        except ValueError as exc:
            return self._fail(asset_id, secret_name, str(exc), start)

        # Step 4 — Generate new secret
        try:
            new_value = generate_secret(opts.secret_len, opts.secret_type)
        except Exception as exc:
            return self._fail(asset_id, secret_name, f"generate failed: {exc}", start)

        # Dry-run — stop here
        if opts.dry_run:
            self._auditor.log_simple(
                AuditEventType.ROTATE,
                asset_id=asset_id, secret_name=secret_name,
                owner=owner, actor=opts.actor, env=env,
                old_version=meta.version, new_version=meta.version + 1,
                validation_status="SKIPPED", success=True,
                message="dry-run — no changes made",
            )
            return RotationResult(
                asset_id=asset_id, secret_name=secret_name, success=True,
                old_version=meta.version, new_version=meta.version + 1,
                timestamp=datetime.utcnow(),
                duration_ms=(time.time() - start) * 1000,
                message="[DRY-RUN] rotation simulated",
            )

        # Keep old value for rollback
        try:
            old_value = self._store.get_secret(secret_name)
        except Exception:
            old_value = ""

        # Step 5 — Store new secret
        try:
            self._store.rotate_secret(secret_name, new_value)
        except Exception as exc:
            self._auditor.log_simple(
                AuditEventType.ROTATE, asset_id=asset_id, secret_name=secret_name,
                owner=owner, actor=opts.actor, env=env,
                rollback_status="", validation_status="", success=False,
                message=f"store failed: {exc}",
            )
            return self._fail(asset_id, secret_name, f"store failed: {exc}", start)

        # Step 6 — Update target application hook (extend here)

        # Step 7 — Validation
        vresult = self._validator.validate(
            opts.validation_type, opts.validation_endpoint, new_value
        )

        if not vresult.success:
            # Step 12 — Rollback + incident
            rb = self._rollback.execute(
                secret_name, asset_id, env, owner, old_value,
                opts.actor, vresult.error or "validation failed",
            )
            result = RotationResult(
                asset_id=asset_id, secret_name=secret_name, success=False,
                old_version=meta.version, new_version=meta.version,
                timestamp=datetime.utcnow(),
                duration_ms=(time.time() - start) * 1000,
                message=rb.message,
                error=vresult.error,
                validation_status="FAILED",
                rollback_status="RESTORED" if rb.success else "FAILED",
            )
            self._store.append_history(secret_name, result)
            return result

        # Step 8 — Delete old version
        try:
            self._store.delete_old_version(secret_name)
        except Exception:
            pass

        # Step 9 — Updated metadata already written by rotate_secret()
        updated_meta: Optional[SecretMetadata] = None
        try:
            updated_meta = self._store.get_metadata(secret_name)
        except Exception:
            pass
        new_version = updated_meta.version if updated_meta else meta.version + 1

        result = RotationResult(
            asset_id=asset_id, secret_name=secret_name, success=True,
            old_version=meta.version, new_version=new_version,
            timestamp=datetime.utcnow(),
            duration_ms=(time.time() - start) * 1000,
            message=f"rotated by {opts.actor} — validation: {vresult.message}",
            validation_status="PASSED",
        )

        # Step 10 — Audit
        self._auditor.log_simple(
            AuditEventType.ROTATE,
            asset_id=asset_id, secret_name=secret_name,
            owner=owner, actor=opts.actor, approved_by=opts.approved_by,
            env=env, provider=self._store.provider_name(),
            old_version=meta.version, new_version=new_version,
            validation_status="PASSED", success=True,
            message=result.message,
        )
        self._store.append_history(secret_name, result)

        # Step 11 — Notify
        self._notifier.send(
            title="Secret rotated successfully",
            secret_name=secret_name, asset_id=asset_id,
            env=env, actor=opts.actor, success=True,
            message=result.message,
        )

        return result

    # ── Bulk rotation ──────────────────────────────────────────────────────

    def rotate_all(
        self, env: str, actor: str, opts: RotationOptions
    ) -> List[RotationResult]:
        secrets = self._store.list_secrets()
        results: List[RotationResult] = []
        for meta in secrets:
            if env and meta.environment != env:
                continue
            opts.actor = actor
            res = self.rotate(meta.asset_id, meta.name, meta.environment, meta.owner, opts)
            results.append(res)

        self._auditor.log_simple(
            AuditEventType.BULK_ROTATE,
            actor=actor, env=env,
            success=True,
            message=f"bulk rotate: {len(results)} secrets processed in env={env or 'all'}",
        )
        return results

    # ── Helpers ────────────────────────────────────────────────────────────

    def _fail(self, asset_id: str, secret_name: str, reason: str, start: float) -> RotationResult:
        return RotationResult(
            asset_id=asset_id, secret_name=secret_name, success=False,
            timestamp=datetime.utcnow(),
            duration_ms=(time.time() - start) * 1000,
            error=reason, message=reason,
        )
