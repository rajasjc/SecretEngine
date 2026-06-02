"""
seckey.engines
==============
All business-logic engines: CMDB, Policy, Audit, Approval, Validation,
Rollback, Notification, Health, Onboarding.
"""
from __future__ import annotations

import csv
import json
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

import requests  # only used where endpoint is non-empty; guarded by check

from seckey.models import (
    ApprovalRequest,
    AuditEvent,
    AuditEventType,
    CloudPlatform,
    RotationResult,
    SecretMetadata,
    SecretStatus,
    SecretType,
    ValidationType,
)

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# CMDB Validator
# ─────────────────────────────────────────────────────────────────────────────

class CMDBAsset:
    def __init__(self, asset_id: str, app_name: str, owner: str,
                 business_domain: str, environment: str, approved: bool = True):
        self.asset_id        = asset_id
        self.app_name        = app_name
        self.owner           = owner
        self.business_domain = business_domain
        self.environment     = environment
        self.approved        = approved


class CMDBValidator:
    """
    Validates IT asset numbers against the CMDB before any secret operation.
    Stub registry — replace with real CMDB REST API call.
    """

    def __init__(self, api_url: Optional[str] = None, api_key: Optional[str] = None):
        self._api_url  = api_url
        self._api_key  = api_key
        self._registry: Dict[str, CMDBAsset] = {}
        self._seed()

    def _seed(self) -> None:
        for a in [
            CMDBAsset("ITA-10234", "PaymentService",  "security-team", "payments",   "prod"),
            CMDBAsset("ITA-10235", "APIGateway",       "platform-team", "platform",   "prod"),
            CMDBAsset("ITA-10236", "KafkaCluster",     "infra-team",    "messaging",  "staging"),
            CMDBAsset("ITA-10237", "VaultCluster",     "vault-admin",   "security",   "prod"),
            CMDBAsset("ITA-10238", "TLSTerminator",    "netops-team",   "networking", "prod"),
        ]:
            self._registry[a.asset_id] = a

    def validate(self, asset_id: str, owner: str = "") -> CMDBAsset:
        if self._api_url:
            return self._validate_remote(asset_id, owner)
        asset_id = asset_id.upper()
        if asset_id not in self._registry:
            raise ValueError(f"CMDB: asset '{asset_id}' not registered — onboard before use")
        asset = self._registry[asset_id]
        if not asset.approved:
            raise ValueError(f"CMDB: asset '{asset_id}' is not approved")
        if owner and asset.owner.lower() != owner.lower():
            raise ValueError(f"CMDB: owner mismatch — registered='{asset.owner}' provided='{owner}'")
        return asset

    def _validate_remote(self, asset_id: str, owner: str) -> CMDBAsset:
        """Replace with real CMDB API call (ServiceNow, BMC Remedy, Jira CMDB, etc.)"""
        resp = requests.get(
            f"{self._api_url}/api/v1/assets/{asset_id}",
            headers={"X-API-Key": self._api_key or ""},
            timeout=10,
        )
        resp.raise_for_status()
        data = resp.json()
        return CMDBAsset(
            asset_id=data["asset_id"], app_name=data["app_name"],
            owner=data["owner"], business_domain=data["business_domain"],
            environment=data["environment"], approved=data.get("approved", True),
        )

    def register(self, asset: CMDBAsset) -> None:
        if asset.asset_id in self._registry:
            raise ValueError(f"CMDB: asset '{asset.asset_id}' already registered")
        self._registry[asset.asset_id] = asset


# ─────────────────────────────────────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────────────────────────────────────

_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{2,62}[a-z0-9]$")


class PolicyEngine:
    """
    Enforces naming standards, rotation frequencies, and eligibility rules.
    """

    def __init__(self, min_secret_length: int = 24, max_rotation_days: int = 180):
        self.min_secret_length = min_secret_length
        self.max_rotation_days = max_rotation_days

    def validate_name(self, name: str) -> None:
        if not _NAME_RE.match(name):
            raise ValueError(
                f"Policy: name '{name}' must be lowercase alphanumeric + hyphens, 4–64 chars"
            )

    def validate_rotation_freq(self, days: int) -> None:
        if days <= 0:
            raise ValueError(f"Policy: rotation frequency must be positive, got {days}")
        if days > self.max_rotation_days:
            raise ValueError(
                f"Policy: rotation freq {days}d exceeds max {self.max_rotation_days}d"
            )

    def validate_metadata(self, meta: SecretMetadata) -> None:
        self.validate_name(meta.name)
        self.validate_rotation_freq(meta.rotation_freq_days)
        if not meta.owner:
            raise ValueError("Policy: owner is required")
        if not meta.asset_id:
            raise ValueError("Policy: asset_id is required")

    def validate_eligibility(self, meta: SecretMetadata, force: bool = False) -> None:
        if meta.status == SecretStatus.DISABLED and not force:
            raise ValueError(
                f"Policy: '{meta.name}' is DISABLED — use --force to override"
            )
        if meta.status == SecretStatus.PENDING_APPROVAL and not force:
            raise ValueError(
                f"Policy: '{meta.name}' is PENDING_APPROVAL — approve first or use --force"
            )
        if not force and meta.next_rotation_at and datetime.utcnow() < meta.next_rotation_at:
            raise ValueError(
                f"Policy: '{meta.name}' not yet due "
                f"(next: {meta.next_rotation_at.strftime('%Y-%m-%d')}) — use --force"
            )

    def next_rotation_date(self, freq_days: int) -> datetime:
        return datetime.utcnow() + timedelta(days=freq_days)

    def apply_naming_standard(self, app_name: str, secret_type: str, env: str) -> str:
        return f"{app_name.lower()}-{secret_type.lower()}-{env.lower()}"


# ─────────────────────────────────────────────────────────────────────────────
# Audit Logger
# ─────────────────────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Immutable, append-only JSONL audit logger.
    Thread-safe. All events have UTC timestamps.
    Suitable for direct SIEM ingestion (Splunk, ELK, QRadar).
    """

    def __init__(self, path: str = "audit.jsonl"):
        self._path   = path
        self._lock   = threading.Lock()
        self._buffer: List[AuditEvent] = []
        # ensure file exists
        Path(path).touch()

    def log(self, event: AuditEvent) -> None:
        event.timestamp = datetime.utcnow()
        with self._lock:
            self._buffer.append(event)
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event.to_dict(), ensure_ascii=False) + "\n")

    def query(self, secret_name: str = "") -> List[AuditEvent]:
        with self._lock:
            if not secret_name:
                return list(self._buffer)
            return [e for e in self._buffer if e.secret_name == secret_name]

    def log_simple(
        self,
        event_type: AuditEventType,
        *,
        asset_id: str = "",
        secret_name: str = "",
        owner: str = "",
        actor: str = "",
        approved_by: str = "",
        env: str = "",
        provider: str = "",
        old_version: int = 0,
        new_version: int = 0,
        validation_status: str = "",
        rollback_status: str = "",
        success: bool = True,
        message: str = "",
    ) -> None:
        self.log(AuditEvent(
            event_type=event_type,
            asset_id=asset_id,
            secret_name=secret_name,
            owner=owner,
            actor=actor,
            requested_by=actor,
            environment=env,
            provider=provider,
            old_version=old_version,
            new_version=new_version,
            validation_status=validation_status,
            rollback_status=rollback_status,
            success=success,
            message=message,
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Approval Workflow
# ─────────────────────────────────────────────────────────────────────────────

class ApprovalWorkflow:
    """
    Two-person integrity approval workflow.
    PENDING_APPROVAL state gates rotation until explicitly approved.
    """

    def __init__(self) -> None:
        self._requests: Dict[str, ApprovalRequest] = {}
        self._lock = threading.Lock()

    def submit(self, secret_name: str, asset_id: str, env: str,
               requested_by: str, notes: str = "") -> ApprovalRequest:
        req = ApprovalRequest(
            secret_name=secret_name, asset_id=asset_id,
            environment=env, requested_by=requested_by, notes=notes,
        )
        with self._lock:
            self._requests[req.request_id] = req
        return req

    def approve(self, request_id: str, approver: str) -> ApprovalRequest:
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                raise KeyError(f"Approval request '{request_id}' not found")
            if req.status != "PENDING":
                raise ValueError(f"Request '{request_id}' is already {req.status}")
            req.status      = "APPROVED"
            req.approved_by = approver
            req.approved_at = datetime.utcnow()
        return req

    def reject(self, request_id: str, approver: str, reason: str = "") -> ApprovalRequest:
        with self._lock:
            req = self._requests.get(request_id)
            if not req:
                raise KeyError(f"Approval request '{request_id}' not found")
            req.status      = "REJECTED"
            req.approved_by = approver
            req.notes       = reason
        return req

    def list_pending(self) -> List[ApprovalRequest]:
        with self._lock:
            return [r for r in self._requests.values() if r.status == "PENDING"]

    def get(self, request_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(request_id)


# ─────────────────────────────────────────────────────────────────────────────
# Validation Engine
# ─────────────────────────────────────────────────────────────────────────────

class ValidationResult:
    def __init__(self, vtype: ValidationType, success: bool,
                 message: str = "", error: Optional[str] = None, duration_ms: float = 0.0):
        self.vtype       = vtype
        self.success     = success
        self.message     = message
        self.error       = error
        self.duration_ms = duration_ms


class ValidationEngine:
    """
    Validates new credentials before the old ones are revoked.
    Supports: DB connection, API auth, TLS cert, health check, key usage.
    """

    def __init__(self, timeout: int = 10, retries: int = 3):
        self.timeout = timeout
        self.retries = retries

    def validate(self, vtype: ValidationType,
                 endpoint: str = "", secret_value: str = "") -> ValidationResult:
        start = time.time()
        for attempt in range(1, self.retries + 1):
            try:
                if vtype == ValidationType.NONE:
                    return ValidationResult(vtype, True, "no validation required")
                if vtype == ValidationType.API_AUTH:
                    err = self._validate_api(endpoint, secret_value)
                elif vtype == ValidationType.HEALTH_CHECK:
                    err = self._validate_health(endpoint)
                elif vtype == ValidationType.TLS_CERT:
                    err = self._validate_tls(endpoint)
                elif vtype == ValidationType.DB_CONN:
                    err = self._validate_db(endpoint, secret_value)
                elif vtype == ValidationType.KEY_USAGE:
                    err = self._validate_key_usage(secret_value)
                else:
                    err = f"Unknown validation type '{vtype}'"

                if not err:
                    return ValidationResult(
                        vtype, True,
                        f"{vtype.value} passed (attempt {attempt})",
                        duration_ms=(time.time() - start) * 1000,
                    )
                if attempt < self.retries:
                    time.sleep(2)
            except Exception as exc:
                err = str(exc)
                if attempt < self.retries:
                    time.sleep(2)

        return ValidationResult(
            vtype, False,
            message=f"{vtype.value} FAILED after {self.retries} attempts",
            error=str(err),
            duration_ms=(time.time() - start) * 1000,
        )

    def _validate_api(self, endpoint: str, api_key: str) -> Optional[str]:
        if not endpoint:
            return None  # no endpoint configured → pass
        resp = requests.get(
            endpoint,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=self.timeout,
        )
        if resp.status_code >= 300:
            return f"HTTP {resp.status_code} from {endpoint}"
        return None

    def _validate_health(self, endpoint: str) -> Optional[str]:
        if not endpoint:
            return None
        url = endpoint.rstrip("/") + "/health"
        resp = requests.get(url, timeout=self.timeout)
        if resp.status_code >= 300:
            return f"Health check failed — HTTP {resp.status_code}"
        return None

    def _validate_tls(self, endpoint: str) -> Optional[str]:
        if not endpoint:
            return None
        import ssl, socket
        host, _, port_str = endpoint.partition(":")
        port = int(port_str) if port_str else 443
        ctx  = ssl.create_default_context()
        try:
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=self.timeout),
                                 server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                if not_after < datetime.utcnow() + timedelta(days=7):
                    return f"TLS cert expires soon: {not_after.isoformat()}"
        except ssl.SSLError as e:
            return f"TLS error: {e}"
        return None

    def _validate_db(self, dsn: str, _: str) -> Optional[str]:
        if not dsn:
            return None
        # Stub — real: import psycopg2; conn = psycopg2.connect(dsn); conn.cursor().execute("SELECT 1")
        return None

    def _validate_key_usage(self, key: str) -> Optional[str]:
        if not key:
            return "key is empty"
        # Stub — real: sign a test payload, verify signature
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Rollback Engine
# ─────────────────────────────────────────────────────────────────────────────

class RollbackResult:
    def __init__(self, success: bool, message: str):
        self.success = success
        self.message = message


class RollbackEngine:
    """
    Restores the previous secret value when validation fails,
    then generates an incident record.
    """

    def __init__(self, store, auditor: AuditLogger, notifier=None):
        self._store    = store
        self._auditor  = auditor
        self._notifier = notifier

    def execute(self, secret_name: str, asset_id: str, env: str,
                owner: str, old_value: str, actor: str, cause: str) -> RollbackResult:
        try:
            self._store.put_secret(secret_name, old_value)
            self._auditor.log_simple(
                AuditEventType.ROLLBACK,
                asset_id=asset_id, secret_name=secret_name,
                owner=owner, actor=actor, env=env,
                rollback_status="RESTORED",
                success=True,
                message=f"Rollback OK — cause: {cause}",
            )
            self._generate_incident(secret_name, asset_id, env, actor, cause)
            if self._notifier:
                self._notifier.send(
                    title="Secret rotation FAILED — rollback executed",
                    secret_name=secret_name, asset_id=asset_id,
                    env=env, actor=actor, success=False,
                    message=f"Cause: {cause} | Rollback: SUCCESS",
                )
            return RollbackResult(True, f"Rollback successful for '{secret_name}'")
        except Exception as exc:
            msg = f"Rollback FAILED: {exc}"
            self._auditor.log_simple(
                AuditEventType.ROLLBACK,
                asset_id=asset_id, secret_name=secret_name,
                rollback_status="FAILED", success=False, message=msg,
            )
            return RollbackResult(False, msg)

    def _generate_incident(self, secret_name, asset_id, env, actor, cause):
        self._auditor.log_simple(
            AuditEventType.INCIDENT,
            asset_id=asset_id, secret_name=secret_name,
            actor=actor, env=env, success=False,
            message=f"INCIDENT: rotation failed asset={asset_id} secret={secret_name} env={env} cause={cause}",
        )


# ─────────────────────────────────────────────────────────────────────────────
# Notification Engine
# ─────────────────────────────────────────────────────────────────────────────

class NotificationEngine:
    """
    Dispatches alerts to Slack, Microsoft Teams, email, SIEM, or stdout.
    """

    def __init__(self, channel: str = "stdout", webhook_url: str = ""):
        self._channel     = channel.lower()
        self._webhook_url = webhook_url

    def send(self, title: str, secret_name: str = "", asset_id: str = "",
             env: str = "", actor: str = "", success: bool = True,
             message: str = "") -> None:
        if self._channel == "slack":
            self._slack(title, secret_name, asset_id, env, message, success)
        elif self._channel == "teams":
            self._teams(title, secret_name, env, actor, message)
        elif self._channel == "siem":
            self._siem(title, secret_name, asset_id, env, message, success)
        else:
            icon = "✅" if success else "❌"
            print(f"[NOTIFY] {icon} {title} | secret={secret_name} asset={asset_id} env={env} | {message}")

    def _slack(self, title, secret_name, asset_id, env, message, success):
        if not self._webhook_url:
            log.info("[SLACK-STUB] %s secret=%s", title, secret_name)
            return
        icon = ":white_check_mark:" if success else ":x:"
        payload = {"text": f"{icon} *{title}*\n>Secret: `{secret_name}` | Asset: `{asset_id}` | Env: `{env}`\n>{message}"}
        try:
            requests.post(self._webhook_url, json=payload, timeout=5)
        except Exception as exc:
            log.warning("Slack notification failed: %s", exc)

    def _teams(self, title, secret_name, env, actor, message):
        if not self._webhook_url:
            log.info("[TEAMS-STUB] %s secret=%s", title, secret_name)
            return
        payload = {
            "@type": "MessageCard", "@context": "http://schema.org/extensions",
            "summary": title,
            "text": f"**{title}** | {secret_name} | env: {env} | actor: {actor}\n{message}",
        }
        try:
            requests.post(self._webhook_url, json=payload, timeout=5)
        except Exception as exc:
            log.warning("Teams notification failed: %s", exc)

    def _siem(self, title, secret_name, asset_id, env, message, success):
        if not self._webhook_url:
            log.info("[SIEM-STUB] CEF %s secret=%s", title, secret_name)
            return
        payload = {
            "title": title, "secret_name": secret_name, "asset_id": asset_id,
            "env": env, "success": success, "message": message,
            "timestamp": datetime.utcnow().isoformat(),
        }
        try:
            requests.post(self._webhook_url, json=payload, timeout=5)
        except Exception as exc:
            log.warning("SIEM notification failed: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# Health Checker
# ─────────────────────────────────────────────────────────────────────────────

class HealthStatus:
    HEALTHY  = "HEALTHY"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


class HealthReport:
    def __init__(self, meta: SecretMetadata):
        self.secret_name     = meta.name
        self.asset_id        = meta.asset_id
        self.environment     = meta.environment
        self.owner           = meta.owner
        self.overall_status  = HealthStatus.HEALTHY
        self.issues: List[str] = []
        self.days_until_expiry = 0

    def to_dict(self) -> dict:
        return {
            "secret_name":      self.secret_name,
            "asset_id":         self.asset_id,
            "environment":      self.environment,
            "owner":            self.owner,
            "overall_status":   self.overall_status,
            "issues":           self.issues,
            "days_until_expiry": self.days_until_expiry,
        }


class HealthChecker:
    """Scores each secret as HEALTHY / WARNING / CRITICAL."""

    def __init__(self, store, warn_days: int = 14, critical_days: int = 7):
        self._store        = store
        self.warn_days     = warn_days
        self.critical_days = critical_days

    def check_all(self) -> List[HealthReport]:
        return [self._check(m) for m in self._store.list_secrets()]

    def check_one(self, name: str) -> HealthReport:
        return self._check(self._store.get_metadata(name))

    def list_expiring(self, days: int) -> List[SecretMetadata]:
        cutoff = datetime.utcnow() + timedelta(days=days)
        return [
            m for m in self._store.list_secrets()
            if m.next_rotation_at and m.next_rotation_at < cutoff
        ]

    def _check(self, meta: SecretMetadata) -> HealthReport:
        r = HealthReport(meta)
        now  = datetime.utcnow()
        diff = (meta.next_rotation_at - now).days if meta.next_rotation_at else 9999
        r.days_until_expiry = diff

        if meta.status == SecretStatus.DISABLED:
            r.overall_status = HealthStatus.CRITICAL
            r.issues.append("secret is DISABLED")
        if diff < 0:
            self._set_worse(r, HealthStatus.CRITICAL)
            r.issues.append(f"rotation overdue by {-diff} days")
        elif diff <= self.critical_days:
            self._set_worse(r, HealthStatus.CRITICAL)
            r.issues.append(f"rotation due in {diff} days (critical ≤{self.critical_days}d)")
        elif diff <= self.warn_days:
            self._set_worse(r, HealthStatus.WARNING)
            r.issues.append(f"rotation due in {diff} days (warning ≤{self.warn_days}d)")
        if meta.rotation_count == 0:
            self._set_worse(r, HealthStatus.WARNING)
            r.issues.append("never been rotated")
        if not r.issues:
            r.issues.append("all checks passed")
        return r

    @staticmethod
    def _set_worse(report: HealthReport, proposed: str) -> None:
        order = {HealthStatus.HEALTHY: 0, HealthStatus.WARNING: 1, HealthStatus.CRITICAL: 2}
        if order[proposed] > order[report.overall_status]:
            report.overall_status = proposed


# ─────────────────────────────────────────────────────────────────────────────
# Onboarding Service
# ─────────────────────────────────────────────────────────────────────────────

class OnboardingService:
    """
    Orchestrates: CMDB validation → policy check → store write → audit.
    """

    def __init__(self, store, cmdb: CMDBValidator,
                 policy: PolicyEngine, auditor: AuditLogger):
        self._store   = store
        self._cmdb    = cmdb
        self._policy  = policy
        self._auditor = auditor

    def onboard(self, *, asset_id: str, app_name: str, secret_name: str,
                secret_type: SecretType = SecretType.PASSWORD,
                environment: str = "prod", business_domain: str = "",
                owner: str = "", cloud_platform: CloudPlatform = CloudPlatform.LOCAL,
                rotation_freq_days: int = 30, tags: Optional[List[str]] = None,
                actor: str = "admin") -> SecretMetadata:

        # 1 — CMDB validation
        asset = self._cmdb.validate(asset_id, owner)

        # 2 — Policy validation
        meta = SecretMetadata(
            name=secret_name, asset_id=asset_id,
            app_name=app_name or asset.app_name,
            secret_type=secret_type, environment=environment,
            business_domain=business_domain or asset.business_domain,
            owner=owner or asset.owner, cloud_platform=cloud_platform,
            provider="local", tags=tags or [],
            rotation_freq_days=rotation_freq_days,
            next_rotation_at=self._policy.next_rotation_date(rotation_freq_days),
            expires_at=datetime.utcnow() + timedelta(days=365),
        )
        self._policy.validate_metadata(meta)

        # 3 — Store
        self._store.put_secret(secret_name, "PLACEHOLDER_ROTATE_NOW")
        self._store.put_metadata(meta)

        # 4 — Audit
        self._auditor.log_simple(
            AuditEventType.ONBOARD,
            asset_id=asset_id, secret_name=secret_name,
            owner=owner, actor=actor, env=environment,
            success=True,
            message=f"onboarded: app={meta.app_name} type={secret_type.value} freq={rotation_freq_days}d",
        )
        return meta
