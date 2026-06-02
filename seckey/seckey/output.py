"""
seckey.output
=============
Pretty-print helpers for table and JSON output modes.
"""
from __future__ import annotations

import csv
import json
import sys
from io import StringIO
from typing import List

from seckey.engines import HealthReport, HealthStatus
from seckey.models import RotationResult, SecretMetadata, SecretStatus


def _status_icon(status: SecretStatus) -> str:
    icons = {
        SecretStatus.ACTIVE:           "✅ ACTIVE",
        SecretStatus.EXPIRING:         "⚠  EXPIRING",
        SecretStatus.EXPIRED:          "🔴 EXPIRED",
        SecretStatus.DISABLED:         "🚫 DISABLED",
        SecretStatus.PENDING_APPROVAL: "⏳ PENDING",
        SecretStatus.DELETED:          "🗑  DELETED",
    }
    return icons.get(status, str(status))


def _health_icon(status: str) -> str:
    return {"HEALTHY": "✅ HEALTHY", "WARNING": "⚠  WARNING", "CRITICAL": "🔴 CRITICAL"}.get(status, status)


def _col(value: str, width: int) -> str:
    return str(value)[:width].ljust(width)


# ─────────────────────────────────────────────────────────────────────────────
# Secret table
# ─────────────────────────────────────────────────────────────────────────────

def print_secret_table(secrets: List[SecretMetadata], fmt: str = "table") -> None:
    if fmt == "json":
        print(json.dumps([m.to_dict() for m in secrets], indent=2, default=str))
        return

    HDR = f"{'ASSET ID':<14} {'NAME':<32} {'TYPE':<18} {'ENV':<9} {'OWNER':<18} {'STATUS':<14} {'NEXT ROTATION':<14} VER"
    SEP = "─" * len(HDR)
    print(HDR)
    print(SEP)
    for m in secrets:
        nr = m.next_rotation_at.strftime("%Y-%m-%d") if m.next_rotation_at else "—"
        print(
            f"{_col(m.asset_id,14)} {_col(m.name,32)} {_col(m.secret_type.value,18)}"
            f" {_col(m.environment,9)} {_col(m.owner,18)} {_col(_status_icon(m.status),14)}"
            f" {_col(nr,14)} v{m.version}"
        )
    print(f"\nTotal: {len(secrets)} secret(s)")


# ─────────────────────────────────────────────────────────────────────────────
# Rotation result
# ─────────────────────────────────────────────────────────────────────────────

def print_rotation_result(r: RotationResult, fmt: str = "table") -> None:
    if fmt == "json":
        print(json.dumps(r.to_dict(), indent=2, default=str))
        return
    print()
    print(f"  {'Asset ID':<22} {r.asset_id}")
    print(f"  {'Secret':<22} {r.secret_name}")
    print(f"  {'Version':<22} v{r.old_version} → v{r.new_version}")
    print(f"  {'Timestamp':<22} {r.timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"  {'Duration':<22} {r.duration_ms:.1f}ms")
    print(f"  {'Validation':<22} {r.validation_status or '—'}")
    print(f"  {'Message':<22} {r.message}")
    print()
    print("✅  Rotation completed" if r.success else f"❌  Rotation FAILED: {r.error}")


def print_bulk_results(results: List[RotationResult], fmt: str = "table") -> None:
    if fmt == "json":
        print(json.dumps([r.to_dict() for r in results], indent=2, default=str))
        return
    ok, fail = 0, 0
    HDR = f"{'SECRET':<32} {'ASSET ID':<14} {'STATUS':<10} MESSAGE"
    print(HDR)
    print("─" * 90)
    for r in results:
        status = "✅ OK" if r.success else "❌ FAIL"
        msg    = r.message if r.success else (r.error or r.message)
        print(f"{_col(r.secret_name,32)} {_col(r.asset_id,14)} {_col(status,10)} {msg}")
        if r.success:
            ok += 1
        else:
            fail += 1
    print(f"\nTotal: {len(results)}  ✅ {ok}  ❌ {fail}")


# ─────────────────────────────────────────────────────────────────────────────
# Health table
# ─────────────────────────────────────────────────────────────────────────────

def print_health_table(reports: List[HealthReport], fmt: str = "table") -> None:
    if fmt == "json":
        print(json.dumps([r.to_dict() for r in reports], indent=2))
        return
    healthy = sum(1 for r in reports if r.overall_status == HealthStatus.HEALTHY)
    warn    = sum(1 for r in reports if r.overall_status == HealthStatus.WARNING)
    crit    = sum(1 for r in reports if r.overall_status == HealthStatus.CRITICAL)
    HDR = f"{'SECRET':<32} {'ENV':<9} {'OWNER':<18} {'STATUS':<14} {'DAYS':>5}  ISSUE"
    print(HDR)
    print("─" * 100)
    for r in reports:
        issue = r.issues[0] if r.issues else ""
        print(
            f"{_col(r.secret_name,32)} {_col(r.environment,9)} {_col(r.owner,18)}"
            f" {_col(_health_icon(r.overall_status),14)} {r.days_until_expiry:>5}  {issue}"
        )
    print(f"\nTotal: {len(reports)}  ✅ Healthy: {healthy}  ⚠  Warning: {warn}  🔴 Critical: {crit}")


# ─────────────────────────────────────────────────────────────────────────────
# CSV export
# ─────────────────────────────────────────────────────────────────────────────

def export_csv(secrets: List[SecretMetadata], path: str) -> None:
    fields = [
        "asset_id", "app_name", "name", "secret_type", "environment",
        "owner", "provider", "status", "version", "rotation_count",
        "last_rotated_at", "next_rotation_at", "expires_at", "tags",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for m in secrets:
            d = m.to_dict()
            d["tags"] = "|".join(m.tags)
            writer.writerow({f: d.get(f, "") for f in fields})
    print(f"✅  Exported {len(secrets)} secrets → {path}")


def export_json(secrets: List[SecretMetadata], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([m.to_dict() for m in secrets], fh, indent=2, default=str)
    print(f"✅  Exported {len(secrets)} secrets → {path}")
