#!/usr/bin/env python3
"""
seckey.py
=============
Secret & Key Lifecycle Automation Platform — Python CLI
Cobra-style sub-command structure using argparse.

Usage
-----
  python seckey.py <command> [options]

Commands
--------
  onboard          Register a new application and create its initial secret record
  create-secret    Create and store a new secret with a generated cryptographic value
  rotate           Full 12-step rotation for a single secret
  rotate-all       Bulk-rotate every secret in an environment
  list-secrets     List all managed secrets
  get-secret       Show full metadata for a specific secret
  search-secret    Filter secrets by name, environment, or owner
  export-secrets   Export secret inventory to CSV or JSON
  list-expiring    List secrets expiring within N days
  secret-health    Compliance health check (HEALTHY / WARNING / CRITICAL)
  approve-rotation Approve or reject a pending rotation request
  disable-secret   Emergency disable — blocks all future rotations
  delete-secret    Permanently delete a secret
  secret-history   View rotation audit trail for a secret
  version          Show version information
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from typing import List, Optional

from seckey import __version__
from seckey.connectors.base import generate_secret
from seckey.context import AppContext
from seckey.engines import (
    AuditEventType,
    HealthStatus,
)
from seckey.engines.rotation import RotationOptions
from seckey.models import (
    CloudPlatform,
    SecretMetadata,
    SecretStatus,
    SecretType,
    ValidationType,
)
from seckey.output import (
    export_csv,
    export_json,
    print_bulk_results,
    print_health_table,
    print_rotation_result,
    print_secret_table,
)

logging.basicConfig(
    level=logging.WARNING,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("seckey")


# ─────────────────────────────────────────────────────────────────────────────
# Global context (initialised once from root-level flags)
# ─────────────────────────────────────────────────────────────────────────────

_ctx: Optional[AppContext] = None


def get_ctx() -> AppContext:
    if _ctx is None:
        raise RuntimeError("AppContext not initialised — this is a bug")
    return _ctx


# ─────────────────────────────────────────────────────────────────────────────
# Helper: print metadata detail
# ─────────────────────────────────────────────────────────────────────────────

def _print_meta_detail(m: SecretMetadata, fmt: str) -> None:
    if fmt == "json":
        print(json.dumps(m.to_dict(), indent=2, default=str))
        return
    rows = [
        ("Asset ID",          m.asset_id),
        ("App name",          m.app_name),
        ("Secret name",       m.name),
        ("Type",              m.secret_type.value),
        ("Environment",       m.environment),
        ("Business domain",   m.business_domain),
        ("Owner",             m.owner),
        ("Provider",          m.provider),
        ("Status",            m.status.value),
        ("Version",           f"v{m.version}"),
        ("Rotation count",    m.rotation_count),
        ("Rotation freq",     f"{m.rotation_freq_days} days"),
        ("Created at",        m.created_at.strftime("%Y-%m-%d %H:%M:%S UTC") if m.created_at else "—"),
        ("Last rotated",      m.last_rotated_at.strftime("%Y-%m-%d %H:%M:%S UTC") if m.last_rotated_at else "—"),
        ("Next rotation",     m.next_rotation_at.strftime("%Y-%m-%d") if m.next_rotation_at else "—"),
        ("Expires at",        m.expires_at.strftime("%Y-%m-%d") if m.expires_at else "—"),
        ("Tags",              ", ".join(m.tags) or "—"),
    ]
    for label, value in rows:
        print(f"  {label:<24} {value}")


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: onboard
# ─────────────────────────────────────────────────────────────────────────────

def cmd_onboard(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    try:
        meta = ctx.onboard.onboard(
            asset_id=args.asset_id,
            app_name=args.app_name or "",
            secret_name=args.secret_name,
            secret_type=SecretType(args.secret_type),
            environment=args.env,
            business_domain=args.domain or "",
            owner=args.owner or "",
            cloud_platform=CloudPlatform(args.cloud),
            rotation_freq_days=args.freq,
            tags=args.tags.split(",") if args.tags else [],
            actor=args.actor,
        )
        print(f"✅  Secret '{meta.name}' onboarded")
        print(f"    Asset: {meta.asset_id}  |  Env: {meta.environment}")
        print(f"    Next rotation: {meta.next_rotation_at.strftime('%Y-%m-%d') if meta.next_rotation_at else '—'}")
        print("⚠   Run 'rotate' to replace the placeholder value immediately.")
        return 0
    except Exception as exc:
        print(f"❌  onboard failed: {exc}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: create-secret
# ─────────────────────────────────────────────────────────────────────────────

def cmd_create_secret(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    try:
        val = generate_secret(args.secret_len, SecretType(args.secret_type))
        ctx.store.put_secret(args.secret_name, val)
        meta = SecretMetadata(
            name=args.secret_name, asset_id=args.asset_id,
            environment=args.env, owner=args.owner or "",
            secret_type=SecretType(args.secret_type),
            next_rotation_at=datetime.utcnow() + timedelta(days=30),
            expires_at=datetime.utcnow() + timedelta(days=365),
        )
        ctx.store.put_metadata(meta)
        ctx.auditor.log_simple(
            AuditEventType.CREATE,
            asset_id=args.asset_id, secret_name=args.secret_name,
            env=args.env, owner=args.owner or "", actor=args.actor,
            success=True, message=f"created with generated value (len={args.secret_len})",
        )
        print(f"✅  Secret '{args.secret_name}' created (asset={args.asset_id}, env={args.env})")
        return 0
    except Exception as exc:
        print(f"❌  create-secret failed: {exc}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: rotate
# ─────────────────────────────────────────────────────────────────────────────

def cmd_rotate(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    opts = RotationOptions(
        force=args.force,
        dry_run=args.dry_run,
        actor=args.actor,
        approved_by=args.approved_by or "",
        secret_len=args.secret_len,
        secret_type=SecretType(args.secret_type),
        validation_type=ValidationType(args.validation_type),
        validation_endpoint=args.validation_endpoint or "",
    )
    result = ctx.rotation.rotate(
        asset_id=args.asset_id,
        secret_name=args.secret_name,
        env=args.env,
        owner=args.owner or "",
        opts=opts,
    )
    print_rotation_result(result, fmt=args.output)
    return 0 if result.success else 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: rotate-all
# ─────────────────────────────────────────────────────────────────────────────

def cmd_rotate_all(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    if not args.actor:
        print("❌  --actor is required for rotate-all", file=sys.stderr)
        return 1
    print(f"⚙   Starting bulk rotation  |  env={args.env or 'all'}  force={args.force}  dry-run={args.dry_run}\n")
    opts = RotationOptions(force=args.force, dry_run=args.dry_run, actor=args.actor)
    results = ctx.rotation.rotate_all(env=args.env or "", actor=args.actor, opts=opts)
    print_bulk_results(results, fmt=args.output)
    failed = sum(1 for r in results if not r.success)
    return 0 if failed == 0 else 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: list-secrets
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list_secrets(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    secrets = ctx.store.list_secrets()
    ctx.auditor.log_simple(
        AuditEventType.LIST, actor=args.actor,
        success=True, message=f"listed {len(secrets)} secrets",
    )
    print_secret_table(secrets, fmt=args.output)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: get-secret
# ─────────────────────────────────────────────────────────────────────────────

def cmd_get_secret(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    try:
        meta = ctx.store.get_metadata(args.secret_name)
        _print_meta_detail(meta, fmt=args.output)
        if args.show_value:
            val = ctx.store.get_secret(args.secret_name)
            print(f"\n⚠   Secret value (AUDIT LOGGED): {val}")
            ctx.auditor.log_simple(
                AuditEventType.GET_VALUE,
                asset_id=meta.asset_id, secret_name=args.secret_name,
                env=meta.environment, owner=meta.owner, actor=args.actor,
                success=True, message="plaintext value accessed",
            )
        return 0
    except KeyError as exc:
        print(f"❌  {exc}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: search-secret
# ─────────────────────────────────────────────────────────────────────────────

def cmd_search_secret(args: argparse.Namespace) -> int:
    ctx   = get_ctx()
    all_s = ctx.store.list_secrets()
    matched = [
        m for m in all_s
        if (not args.query or args.query in m.name or args.query in m.asset_id)
        and (not args.env   or m.environment == args.env)
        and (not args.owner or m.owner.lower() == args.owner.lower())
        and (not args.domain or m.business_domain.lower() == args.domain.lower())
    ]
    print(f"Found {len(matched)} result(s) for query='{args.query}' env='{args.env}'\n")
    print_secret_table(matched, fmt=args.output)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: export-secrets
# ─────────────────────────────────────────────────────────────────────────────

def cmd_export_secrets(args: argparse.Namespace) -> int:
    ctx     = get_ctx()
    secrets = ctx.store.list_secrets()
    if args.format == "json":
        export_json(secrets, args.file)
    else:
        export_csv(secrets, args.file)
    ctx.auditor.log_simple(
        AuditEventType.EXPORT, actor=args.actor,
        success=True,
        message=f"exported {len(secrets)} secrets to {args.file} ({args.format})",
    )
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: list-expiring
# ─────────────────────────────────────────────────────────────────────────────

def cmd_list_expiring(args: argparse.Namespace) -> int:
    ctx      = get_ctx()
    expiring = ctx.health.list_expiring(args.days)
    if not expiring:
        print(f"✅  No secrets expiring within {args.days} days")
        return 0
    print(f"⚠   {len(expiring)} secret(s) expiring within {args.days} days:\n")
    print_secret_table(expiring, fmt=args.output)
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: secret-health
# ─────────────────────────────────────────────────────────────────────────────

def cmd_secret_health(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    if args.secret_name:
        try:
            reports = [ctx.health.check_one(args.secret_name)]
        except KeyError as exc:
            print(f"❌  {exc}", file=sys.stderr)
            return 1
    else:
        reports = ctx.health.check_all()
    print_health_table(reports, fmt=args.output)
    ctx.auditor.log_simple(
        AuditEventType.HEALTH_CHECK, actor="system",
        success=True, message=f"health check: {len(reports)} secrets evaluated",
    )
    critical = sum(1 for r in reports if r.overall_status == HealthStatus.CRITICAL)
    return 1 if critical > 0 else 0


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: approve-rotation
# ─────────────────────────────────────────────────────────────────────────────

def cmd_approve_rotation(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    try:
        if args.reject:
            req = ctx.workflow.reject(args.request_id, args.approver, args.reason or "")
            ctx.auditor.log_simple(
                AuditEventType.REJECT,
                secret_name=req.secret_name, asset_id=req.asset_id,
                env=req.environment, actor=args.approver,
                success=True, message=args.reason or "rejected",
            )
            print(f"🚫  Request {req.request_id} REJECTED by {req.approved_by}")
        else:
            req = ctx.workflow.approve(args.request_id, args.approver)
            ctx.auditor.log_simple(
                AuditEventType.APPROVE,
                secret_name=req.secret_name, asset_id=req.asset_id,
                env=req.environment, actor=args.approver,
                success=True, message="rotation approved",
            )
            print(f"✅  Request {req.request_id} APPROVED by {req.approved_by}")
            print(f"    Secret '{req.secret_name}' is now eligible for rotation.")
        return 0
    except (KeyError, ValueError) as exc:
        print(f"❌  {exc}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: disable-secret
# ─────────────────────────────────────────────────────────────────────────────

def cmd_disable_secret(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    try:
        ctx.store.disable_secret(args.secret_name)
        ctx.auditor.log_simple(
            AuditEventType.DISABLE,
            secret_name=args.secret_name, actor=args.actor,
            success=True, message="disabled by admin",
        )
        print(f"🚫  Secret '{args.secret_name}' is now DISABLED")
        return 0
    except Exception as exc:
        print(f"❌  {exc}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: delete-secret
# ─────────────────────────────────────────────────────────────────────────────

def cmd_delete_secret(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    if not args.confirm:
        print("❌  Deletion is irreversible. Add --confirm to proceed.", file=sys.stderr)
        return 1
    try:
        ctx.store.delete_secret(args.secret_name)
        ctx.auditor.log_simple(
            AuditEventType.DELETE,
            secret_name=args.secret_name, actor=args.actor,
            success=True, message="permanently deleted",
        )
        print(f"🗑   Secret '{args.secret_name}' permanently deleted")
        return 0
    except Exception as exc:
        print(f"❌  {exc}", file=sys.stderr)
        return 1


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: secret-history
# ─────────────────────────────────────────────────────────────────────────────

def cmd_secret_history(args: argparse.Namespace) -> int:
    ctx = get_ctx()
    history = ctx.store.get_history(args.secret_name)
    if not history:
        print(f"No rotation history found for '{args.secret_name}'")
        return 0
    if args.output == "json":
        print(json.dumps([r.to_dict() for r in history], indent=2, default=str))
        return 0
    print(f"{'TIMESTAMP':<22} {'STATUS':<10} {'OLD':>5} {'NEW':>5} {'DUR(ms)':>8}  MESSAGE")
    print("─" * 90)
    for r in history:
        status = "✅ OK" if r.success else "❌ FAIL"
        print(
            f"{r.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<22} {status:<10}"
            f" {r.old_version:>5} {r.new_version:>5} {r.duration_ms:>8.1f}  {r.message}"
        )
    ctx.auditor.log_simple(
        AuditEventType.GET_HISTORY, secret_name=args.secret_name,
        actor=args.actor, success=True, message="history accessed",
    )
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Sub-command: version
# ─────────────────────────────────────────────────────────────────────────────

def cmd_version(args: argparse.Namespace) -> int:
    print(f"seckey {__version__}")
    print("Secret & Key Lifecycle Automation Platform")
    print("Python edition — argparse CLI (Cobra-style)")
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# Argument parser builder
# ─────────────────────────────────────────────────────────────────────────────

PROVIDERS   = ["local", "aws", "azure", "hashicorp", "fortanix", "thales", "alibaba", "gcp", "oracle"]
ENVS        = ["prod", "staging", "uat", "dev"]
SECRET_TYPES = [t.value for t in SecretType]
VAL_TYPES    = [v.value for v in ValidationType]
CLOUDS       = [c.value for c in CloudPlatform]
FORMATS      = ["table", "json"]
NOTIFY_CHANS = ["stdout", "slack", "teams", "siem"]


def _add_global_flags(parser: argparse.ArgumentParser) -> None:
    """Flags available on every sub-command (equivalent to Cobra PersistentFlags)."""
    g = parser.add_argument_group("global flags")
    g.add_argument("--provider", default="local", choices=PROVIDERS,
                   help="Secret store provider (default: local)")
    g.add_argument("--provider-config", default="", metavar="JSON",
                   help="Provider config as JSON string")
    g.add_argument("--audit-log", default="audit.jsonl",
                   help="Append-only audit log file (default: audit.jsonl)")
    g.add_argument("--output", "-o", default="table", choices=FORMATS,
                   help="Output format (default: table)")
    g.add_argument("--notify", default="stdout", choices=NOTIFY_CHANS,
                   help="Notification channel (default: stdout)")
    g.add_argument("--webhook", default="",
                   help="Webhook URL for Slack / Teams / SIEM notifications")
    g.add_argument("--verbose", "-v", action="store_true",
                   help="Enable verbose logging")


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="seckey",
        description=(
            "╔══════════════════════════════════════════════════════════╗\n"
            "║  Secret & Key Lifecycle Automation Platform               ║\n"
            "║  Multi-cloud · HSM-aware · Audit-immutable · Python CLI   ║\n"
            "╚══════════════════════════════════════════════════════════╝\n\n"
            "Automates the full lifecycle of secrets, encryption keys,\n"
            "certificates and API credentials across AWS, Azure, GCP,\n"
            "HashiCorp Vault, Fortanix DSM, Thales CipherTrust,\n"
            "Alibaba KMS, and Oracle Vault."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  seckey onboard --asset-id ITA-10234 --secret-name payment-db-password --env prod\n"
            "  seckey rotate  --asset-id ITA-10234 --secret-name payment-db-password --env prod --force\n"
            "  seckey rotate-all --env prod --actor admin --force\n"
            "  seckey secret-health\n"
            "  seckey list-expiring --days 7\n"
            "  seckey approve-rotation --request-id REQ-00001 --approver ciso@bank.com\n"
        ),
    )
    root.add_argument("--version", action="version", version=f"seckey {__version__}")
    _add_global_flags(root)

    subs = root.add_subparsers(dest="command", metavar="<command>")

    # ── onboard ──────────────────────────────────────────────────────────────
    p = subs.add_parser("onboard", help="Register a new application and create initial secret record")
    p.add_argument("--asset-id",    required=True, help="CMDB IT asset ID")
    p.add_argument("--secret-name", required=True, help="Secret name (lowercase, hyphens)")
    p.add_argument("--app-name",    default="",    help="Application name")
    p.add_argument("--secret-type", default="password", choices=SECRET_TYPES)
    p.add_argument("--env",         default="prod",  choices=ENVS)
    p.add_argument("--domain",      default="",    help="Business domain")
    p.add_argument("--owner",       default="",    help="Owner team")
    p.add_argument("--cloud",       default="local", choices=CLOUDS)
    p.add_argument("--freq",        type=int, default=30, help="Rotation frequency in days")
    p.add_argument("--tags",        default="",    help="Comma-separated tags (e.g. pci,critical)")
    p.add_argument("--actor",       default="admin", help="User performing the action")
    _add_global_flags(p)

    # ── create-secret ─────────────────────────────────────────────────────────
    p = subs.add_parser("create-secret", help="Create and store a new secret with a generated value")
    p.add_argument("--asset-id",    required=True)
    p.add_argument("--secret-name", required=True)
    p.add_argument("--secret-type", default="password", choices=SECRET_TYPES)
    p.add_argument("--env",         default="prod", choices=ENVS)
    p.add_argument("--owner",       default="")
    p.add_argument("--secret-len",  type=int, default=32)
    p.add_argument("--actor",       default="admin")
    _add_global_flags(p)

    # ── rotate ────────────────────────────────────────────────────────────────
    p = subs.add_parser("rotate", help="Full 12-step rotation for a single secret",
                        description=(
                            "Rotation flow:\n"
                            "  Read metadata → Validate eligibility → Generate new value →\n"
                            "  Store in vault → Update application → Validation engine →\n"
                            "  Disable old → Update metadata → Audit → Notify →\n"
                            "  Rollback + Incident (on failure)"
                        ),
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--asset-id",    required=True)
    p.add_argument("--secret-name", required=True)
    p.add_argument("--env",         default="prod", choices=ENVS)
    p.add_argument("--owner",       default="")
    p.add_argument("--actor",       default="admin")
    p.add_argument("--approved-by", default="")
    p.add_argument("--force",       action="store_true", help="Bypass eligibility / disabled check")
    p.add_argument("--dry-run",     action="store_true", help="Simulate — no changes made")
    p.add_argument("--secret-len",  type=int, default=32)
    p.add_argument("--secret-type", default="password", choices=SECRET_TYPES)
    p.add_argument("--validation-type",     default="none", choices=VAL_TYPES)
    p.add_argument("--validation-endpoint", default="", help="URL or DSN for validation")
    _add_global_flags(p)

    # ── rotate-all ────────────────────────────────────────────────────────────
    p = subs.add_parser("rotate-all", help="Bulk-rotate all secrets in an environment")
    p.add_argument("--env",     default="", choices=[""] + ENVS)
    p.add_argument("--actor",   required=True)
    p.add_argument("--force",   action="store_true")
    p.add_argument("--dry-run", action="store_true")
    _add_global_flags(p)

    # ── list-secrets ──────────────────────────────────────────────────────────
    p = subs.add_parser("list-secrets", help="List all managed secrets")
    p.add_argument("--actor", default="admin")
    _add_global_flags(p)

    # ── get-secret ────────────────────────────────────────────────────────────
    p = subs.add_parser("get-secret", help="Show full metadata for a specific secret")
    p.add_argument("--secret-name", required=True)
    p.add_argument("--actor",       default="admin")
    p.add_argument("--show-value",  action="store_true",
                   help="⚠  Print the actual secret value (written to audit log)")
    _add_global_flags(p)

    # ── search-secret ─────────────────────────────────────────────────────────
    p = subs.add_parser("search-secret", help="Filter secrets by name, environment, or owner")
    p.add_argument("--query",  default="", help="Substring in name or asset ID")
    p.add_argument("--env",    default="", choices=[""] + ENVS)
    p.add_argument("--owner",  default="")
    p.add_argument("--domain", default="")
    _add_global_flags(p)

    # ── export-secrets ────────────────────────────────────────────────────────
    p = subs.add_parser("export-secrets", help="Export secret inventory (metadata only)")
    p.add_argument("--file",   default="secret-inventory.csv", help="Output file path")
    p.add_argument("--format", default="csv", choices=["csv", "json"])
    p.add_argument("--actor",  default="admin")
    _add_global_flags(p)

    # ── list-expiring ─────────────────────────────────────────────────────────
    p = subs.add_parser("list-expiring", help="List secrets expiring within N days")
    p.add_argument("--days", type=int, default=30, help="Look-ahead window in days")
    _add_global_flags(p)

    # ── secret-health ─────────────────────────────────────────────────────────
    p = subs.add_parser("secret-health",
                        help="Compliance health check (HEALTHY / WARNING / CRITICAL)")
    p.add_argument("--secret-name", default="",
                   help="Check a single secret (default: all secrets)")
    _add_global_flags(p)

    # ── approve-rotation ──────────────────────────────────────────────────────
    p = subs.add_parser("approve-rotation", help="Approve or reject a pending rotation request")
    p.add_argument("--request-id", required=True, help="e.g. REQ-00001")
    p.add_argument("--approver",   required=True)
    p.add_argument("--reject",     action="store_true", help="Reject instead of approving")
    p.add_argument("--reason",     default="")
    _add_global_flags(p)

    # ── disable-secret ────────────────────────────────────────────────────────
    p = subs.add_parser("disable-secret",
                        help="Emergency disable — blocks all future rotations")
    p.add_argument("--secret-name", required=True)
    p.add_argument("--actor",       default="admin")
    _add_global_flags(p)

    # ── delete-secret ─────────────────────────────────────────────────────────
    p = subs.add_parser("delete-secret", help="Permanently delete a secret")
    p.add_argument("--secret-name", required=True)
    p.add_argument("--actor",       default="admin")
    p.add_argument("--confirm",     action="store_true",
                   help="Required — deletion is irreversible")
    _add_global_flags(p)

    # ── secret-history ────────────────────────────────────────────────────────
    p = subs.add_parser("secret-history", help="View rotation audit trail for a secret")
    p.add_argument("--secret-name", required=True)
    p.add_argument("--actor",       default="admin")
    _add_global_flags(p)

    # ── version ───────────────────────────────────────────────────────────────
    subs.add_parser("version", help="Show version information")

    return root


# ─────────────────────────────────────────────────────────────────────────────
# Dispatch table
# ─────────────────────────────────────────────────────────────────────────────

DISPATCH = {
    "onboard":          cmd_onboard,
    "create-secret":    cmd_create_secret,
    "rotate":           cmd_rotate,
    "rotate-all":       cmd_rotate_all,
    "list-secrets":     cmd_list_secrets,
    "get-secret":       cmd_get_secret,
    "search-secret":    cmd_search_secret,
    "export-secrets":   cmd_export_secrets,
    "list-expiring":    cmd_list_expiring,
    "secret-health":    cmd_secret_health,
    "approve-rotation": cmd_approve_rotation,
    "disable-secret":   cmd_disable_secret,
    "delete-secret":    cmd_delete_secret,
    "secret-history":   cmd_secret_history,
    "version":          cmd_version,
}


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    global _ctx
    parser = build_parser()
    args   = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Build AppContext from root-level global flags
    provider_config: dict = {}
    if args.provider_config:
        try:
            provider_config = json.loads(args.provider_config)
        except json.JSONDecodeError:
            print("❌  --provider-config must be valid JSON", file=sys.stderr)
            return 1

    _ctx = AppContext.from_config({
        "provider":        args.provider,
        "provider_config": provider_config,
        "audit_log":       args.audit_log,
        "notify":          args.notify,
        "webhook":         args.webhook,
    })

    handler = DISPATCH.get(args.command)
    if not handler:
        print(f"❌  Unknown command '{args.command}'", file=sys.stderr)
        return 1

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
