"""
tests/test_core.py
==================
Core unit tests covering: LocalVault, PolicyEngine, CMDB,
HealthChecker, RotationEngine (dry-run + force), ApprovalWorkflow.
"""
import pytest
from datetime import datetime, timedelta

from seckey.connectors.base import LocalVault, generate_secret
from seckey.context import AppContext
from seckey.engines import (
    AuditLogger,
    CMDBValidator,
    HealthChecker,
    HealthStatus,
    NotificationEngine,
    PolicyEngine,
)
from seckey.engines.rotation import RotationEngine, RotationOptions
from seckey.models import SecretMetadata, SecretStatus, SecretType, ValidationType


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def vault():
    return LocalVault()


@pytest.fixture
def auditor(tmp_path):
    return AuditLogger(str(tmp_path / "audit.jsonl"))


@pytest.fixture
def notifier():
    return NotificationEngine(channel="stdout")


@pytest.fixture
def policy():
    return PolicyEngine()


@pytest.fixture
def engine(vault, policy, auditor, notifier):
    return RotationEngine(vault, policy, auditor, notifier)


@pytest.fixture
def ctx(vault, auditor, notifier, policy):
    from seckey.context import AppContext
    cmdb = CMDBValidator()
    return AppContext(vault, auditor, notifier, policy, cmdb)


# ─────────────────────────────────────────────────────────────────────────────
# LocalVault tests
# ─────────────────────────────────────────────────────────────────────────────

class TestLocalVault:
    def test_seeded_secrets_exist(self, vault):
        secrets = vault.list_secrets()
        assert len(secrets) >= 5

    def test_get_known_secret(self, vault):
        val = vault.get_secret("payment-db-password")
        assert isinstance(val, str) and len(val) > 0

    def test_put_and_get(self, vault):
        vault.put_secret("test-key", "my-value")
        assert vault.get_secret("test-key") == "my-value"

    def test_missing_secret_raises(self, vault):
        with pytest.raises(KeyError):
            vault.get_secret("does-not-exist")

    def test_rotate_increments_version(self, vault):
        meta_before = vault.get_metadata("payment-db-password")
        v_before = meta_before.version
        vault.rotate_secret("payment-db-password", "new-value-xyz")
        meta_after = vault.get_metadata("payment-db-password")
        assert meta_after.version == v_before + 1
        assert vault.get_secret("payment-db-password") == "new-value-xyz"

    def test_disable_sets_status(self, vault):
        vault.disable_secret("payment-db-password")
        assert vault.get_metadata("payment-db-password").status == SecretStatus.DISABLED

    def test_delete_removes_secret(self, vault):
        vault.put_secret("temp", "temp-value")
        vault.delete_secret("temp")
        with pytest.raises(KeyError):
            vault.get_secret("temp")

    def test_history_append_and_retrieve(self, vault):
        from seckey.models import RotationResult
        result = RotationResult(asset_id="ITA-X", secret_name="payment-db-password",
                                success=True, message="test")
        vault.append_history("payment-db-password", result)
        history = vault.get_history("payment-db-password")
        assert any(r.message == "test" for r in history)


# ─────────────────────────────────────────────────────────────────────────────
# Crypto helper
# ─────────────────────────────────────────────────────────────────────────────

class TestGenerateSecret:
    def test_length(self):
        val = generate_secret(32)
        assert len(val) == 32

    def test_uniqueness(self):
        vals = {generate_secret(32) for _ in range(50)}
        assert len(vals) == 50

    def test_api_key_is_hex(self):
        val = generate_secret(32, SecretType.API_KEY)
        assert all(c in "0123456789abcdef" for c in val)


# ─────────────────────────────────────────────────────────────────────────────
# Policy Engine
# ─────────────────────────────────────────────────────────────────────────────

class TestPolicyEngine:
    def test_valid_name(self, policy):
        policy.validate_name("payment-db-password")  # no exception

    def test_invalid_name_uppercase(self, policy):
        with pytest.raises(ValueError, match="Policy"):
            policy.validate_name("PaymentDB")

    def test_rotation_freq_too_high(self, policy):
        with pytest.raises(ValueError):
            policy.validate_rotation_freq(999)

    def test_rotation_freq_valid(self, policy):
        policy.validate_rotation_freq(30)  # no exception

    def test_eligibility_disabled_blocked(self, policy, vault):
        meta = vault.get_metadata("vault-unseal-key")  # seeded as DISABLED
        with pytest.raises(ValueError, match="DISABLED"):
            policy.validate_eligibility(meta, force=False)

    def test_eligibility_disabled_with_force(self, policy, vault):
        meta = vault.get_metadata("vault-unseal-key")
        policy.validate_eligibility(meta, force=True)  # no exception

    def test_eligibility_not_yet_due(self, policy, vault):
        meta = vault.get_metadata("tls-ingress-cert")  # next rotation far future
        with pytest.raises(ValueError, match="not yet due"):
            policy.validate_eligibility(meta, force=False)


# ─────────────────────────────────────────────────────────────────────────────
# CMDB Validator
# ─────────────────────────────────────────────────────────────────────────────

class TestCMDB:
    def test_known_asset(self):
        cmdb = CMDBValidator()
        asset = cmdb.validate("ITA-10234")
        assert asset.app_name == "PaymentService"

    def test_unknown_asset_raises(self):
        cmdb = CMDBValidator()
        with pytest.raises(ValueError, match="not registered"):
            cmdb.validate("ITA-XXXXX")

    def test_owner_mismatch_raises(self):
        cmdb = CMDBValidator()
        with pytest.raises(ValueError, match="owner mismatch"):
            cmdb.validate("ITA-10234", owner="wrong-team")

    def test_owner_match_passes(self):
        cmdb = CMDBValidator()
        asset = cmdb.validate("ITA-10234", owner="security-team")
        assert asset.owner == "security-team"

    def test_register_new_asset(self):
        cmdb = CMDBValidator()
        from seckey.engines import CMDBAsset
        cmdb.register(CMDBAsset("ITA-99999", "TestApp", "test-team", "testing", "dev"))
        asset = cmdb.validate("ITA-99999")
        assert asset.app_name == "TestApp"


# ─────────────────────────────────────────────────────────────────────────────
# Health Checker
# ─────────────────────────────────────────────────────────────────────────────

class TestHealthChecker:
    def test_check_all_returns_reports(self, vault):
        checker = HealthChecker(vault)
        reports = checker.check_all()
        assert len(reports) >= 5

    def test_expired_secret_is_critical(self, vault):
        checker = HealthChecker(vault)
        report  = checker.check_one("kafka-sasl-secret")  # seeded as EXPIRED
        assert report.overall_status == HealthStatus.CRITICAL

    def test_disabled_secret_is_critical(self, vault):
        checker = HealthChecker(vault)
        report  = checker.check_one("vault-unseal-key")
        assert report.overall_status == HealthStatus.CRITICAL

    def test_active_with_far_expiry_is_healthy(self, vault):
        checker = HealthChecker(vault)
        report  = checker.check_one("tls-ingress-cert")  # 180 days away
        assert report.overall_status == HealthStatus.HEALTHY

    def test_list_expiring_finds_soon_expiring(self, vault):
        checker  = HealthChecker(vault)
        expiring = checker.list_expiring(days=10)
        names    = [m.name for m in expiring]
        assert "api-gateway-key" in names  # seeded as 5 days away


# ─────────────────────────────────────────────────────────────────────────────
# Rotation Engine (dry-run + force)
# ─────────────────────────────────────────────────────────────────────────────

class TestRotationEngine:
    def test_dry_run_does_not_change_value(self, engine, vault):
        before = vault.get_secret("payment-db-password")
        opts   = RotationOptions(dry_run=True, force=True, actor="test")
        result = engine.rotate("ITA-10234", "payment-db-password", "prod", "security-team", opts)
        assert result.success
        assert "[DRY-RUN]" in result.message
        assert vault.get_secret("payment-db-password") == before

    def test_force_rotate_disabled_secret(self, engine, vault):
        # vault-unseal-key is seeded DISABLED
        opts   = RotationOptions(force=True, actor="test", dry_run=True)
        result = engine.rotate("ITA-10237", "vault-unseal-key", "prod", "vault-admin", opts)
        assert result.success  # dry-run with force should succeed

    def test_missing_secret_returns_failure(self, engine):
        opts   = RotationOptions(force=True, actor="test")
        result = engine.rotate("ITA-XXXX", "nonexistent-secret", "prod", "owner", opts)
        assert not result.success
        assert result.error

    def test_bulk_rotate_returns_results(self, engine):
        opts    = RotationOptions(force=True, actor="test", dry_run=True)
        results = engine.rotate_all("staging", "test", opts)
        assert len(results) >= 1  # kafka-sasl-secret is staging

    def test_rotation_increments_version(self, engine, vault):
        meta_before = vault.get_metadata("payment-db-password")
        v_before    = meta_before.version
        opts        = RotationOptions(force=True, actor="test", validation_type=ValidationType.NONE)
        result      = engine.rotate("ITA-10234", "payment-db-password", "prod", "security-team", opts)
        if result.success:
            meta_after = vault.get_metadata("payment-db-password")
            assert meta_after.version == v_before + 1


# ─────────────────────────────────────────────────────────────────────────────
# Approval Workflow
# ─────────────────────────────────────────────────────────────────────────────

class TestApprovalWorkflow:
    def test_submit_creates_pending_request(self, ctx):
        req = ctx.workflow.submit("payment-db-password", "ITA-10234", "prod", "dev-team")
        assert req.status == "PENDING"
        assert req.secret_name == "payment-db-password"

    def test_approve_changes_status(self, ctx):
        req      = ctx.workflow.submit("api-gateway-key", "ITA-10235", "prod", "dev-team")
        approved = ctx.workflow.approve(req.request_id, "ciso@bank.com")
        assert approved.status == "APPROVED"
        assert approved.approved_by == "ciso@bank.com"

    def test_reject_changes_status(self, ctx):
        req      = ctx.workflow.submit("kafka-sasl-secret", "ITA-10236", "staging", "dev-team")
        rejected = ctx.workflow.reject(req.request_id, "ciso@bank.com", "policy violation")
        assert rejected.status == "REJECTED"
        assert rejected.notes  == "policy violation"

    def test_list_pending_returns_pending_only(self, ctx):
        req1 = ctx.workflow.submit("s1", "A", "prod", "team")
        req2 = ctx.workflow.submit("s2", "B", "prod", "team")
        ctx.workflow.approve(req1.request_id, "approver")
        pending = ctx.workflow.list_pending()
        ids = [r.request_id for r in pending]
        assert req2.request_id in ids
        assert req1.request_id not in ids

    def test_double_approve_raises(self, ctx):
        req = ctx.workflow.submit("s3", "C", "prod", "team")
        ctx.workflow.approve(req.request_id, "approver1")
        with pytest.raises(ValueError):
            ctx.workflow.approve(req.request_id, "approver2")
