"""
seckey.context
==============
AppContext is the single shared dependency container for the entire CLI.
It is created once in the top-level argument-parser setup and passed
through every sub-command handler.
"""
from __future__ import annotations

from typing import Optional

from seckey.connectors.base import SecretStore, create_store
from seckey.engines import (
    AuditLogger,
    ApprovalWorkflow,
    CMDBValidator,
    HealthChecker,
    NotificationEngine,
    OnboardingService,
    PolicyEngine,
    RollbackEngine,
)
from seckey.engines.rotation import RotationEngine


class AppContext:
    def __init__(
        self,
        store: SecretStore,
        auditor: AuditLogger,
        notifier: NotificationEngine,
        policy: PolicyEngine,
        cmdb: CMDBValidator,
    ):
        self.store    = store
        self.auditor  = auditor
        self.notifier = notifier
        self.policy   = policy
        self.cmdb     = cmdb

        self.rotation = RotationEngine(store, policy, auditor, notifier)
        self.health   = HealthChecker(store)
        self.workflow = ApprovalWorkflow()
        self.onboard  = OnboardingService(store, cmdb, policy, auditor)

    @classmethod
    def from_config(cls, cfg: dict) -> "AppContext":
        store    = create_store(cfg.get("provider", "local"), cfg.get("provider_config", {}))
        auditor  = AuditLogger(cfg.get("audit_log", "audit.jsonl"))
        notifier = NotificationEngine(
            channel=cfg.get("notify", "stdout"),
            webhook_url=cfg.get("webhook", ""),
        )
        policy   = PolicyEngine()
        cmdb     = CMDBValidator(
            api_url=cfg.get("cmdb_url"),
            api_key=cfg.get("cmdb_api_key"),
        )
        return cls(store, auditor, notifier, policy, cmdb)
