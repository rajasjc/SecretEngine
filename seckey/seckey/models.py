"""
seckey.models
=============
Core domain types shared across every module.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional


class SecretType(str, Enum):
    PASSWORD       = "password"
    API_KEY        = "api-key"
    TLS_CERT       = "tls-cert"
    SYMMETRIC_KEY  = "symmetric-key"
    OAUTH_TOKEN    = "oauth-token"
    DATABASE_CRED  = "database-credential"
    RSA_KEY        = "rsa-key"


class SecretStatus(str, Enum):
    ACTIVE           = "ACTIVE"
    EXPIRING         = "EXPIRING"
    EXPIRED          = "EXPIRED"
    DISABLED         = "DISABLED"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    DELETED          = "DELETED"


class CloudPlatform(str, Enum):
    LOCAL      = "local"
    AWS        = "aws"
    AZURE      = "azure"
    HASHICORP  = "hashicorp"
    FORTANIX   = "fortanix"
    THALES     = "thales"
    ALIBABA    = "alibaba"
    GCP        = "gcp"
    ORACLE     = "oracle"


class ValidationType(str, Enum):
    NONE         = "none"
    DB_CONN      = "db-connection"
    API_AUTH     = "api-auth"
    TLS_CERT     = "tls-cert"
    HEALTH_CHECK = "health-check"
    KEY_USAGE    = "key-usage"


class AuditEventType(str, Enum):
    ONBOARD        = "ONBOARD"
    CREATE         = "CREATE"
    ROTATE         = "ROTATE"
    BULK_ROTATE    = "BULK_ROTATE"
    VALIDATE       = "VALIDATE"
    ROLLBACK       = "ROLLBACK"
    DISABLE        = "DISABLE"
    DELETE         = "DELETE"
    APPROVE        = "APPROVE"
    REJECT         = "REJECT"
    EXPORT         = "EXPORT"
    HEALTH_CHECK   = "HEALTH_CHECK"
    GET_VALUE      = "GET_VALUE"
    INCIDENT       = "INCIDENT"
    LIST           = "LIST"
    GET_HISTORY    = "GET_HISTORY"


@dataclass
class SecretMetadata:
    name: str
    asset_id: str
    app_name: str                  = ""
    secret_type: SecretType        = SecretType.PASSWORD
    environment: str               = "prod"
    business_domain: str           = ""
    owner: str                     = ""
    cloud_platform: CloudPlatform  = CloudPlatform.LOCAL
    provider: str                  = "local"
    status: SecretStatus           = SecretStatus.ACTIVE
    tags: List[str]                = field(default_factory=list)
    rotation_freq_days: int        = 30
    version: int                   = 1
    rotation_count: int            = 0
    created_at: datetime           = field(default_factory=datetime.utcnow)
    last_rotated_at: Optional[datetime] = None
    next_rotation_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    def to_dict(self) -> dict:
        return {
            "name":               self.name,
            "asset_id":           self.asset_id,
            "app_name":           self.app_name,
            "secret_type":        self.secret_type.value,
            "environment":        self.environment,
            "business_domain":    self.business_domain,
            "owner":              self.owner,
            "cloud_platform":     self.cloud_platform.value,
            "provider":           self.provider,
            "status":             self.status.value,
            "tags":               self.tags,
            "rotation_freq_days": self.rotation_freq_days,
            "version":            self.version,
            "rotation_count":     self.rotation_count,
            "created_at":         self.created_at.isoformat(),
            "last_rotated_at":    self.last_rotated_at.isoformat() if self.last_rotated_at else None,
            "next_rotation_at":   self.next_rotation_at.isoformat() if self.next_rotation_at else None,
            "expires_at":         self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class RotationResult:
    asset_id: str
    secret_name: str
    success: bool
    old_version: int               = 0
    new_version: int               = 0
    timestamp: datetime            = field(default_factory=datetime.utcnow)
    duration_ms: float             = 0.0
    message: str                   = ""
    error: Optional[str]           = None
    validation_status: str         = ""
    rollback_status: str           = ""

    def to_dict(self) -> dict:
        return {
            "asset_id":         self.asset_id,
            "secret_name":      self.secret_name,
            "success":          self.success,
            "old_version":      self.old_version,
            "new_version":      self.new_version,
            "timestamp":        self.timestamp.isoformat(),
            "duration_ms":      round(self.duration_ms, 2),
            "message":          self.message,
            "error":            self.error,
            "validation_status": self.validation_status,
            "rollback_status":  self.rollback_status,
        }


@dataclass
class ApprovalRequest:
    request_id: str                = field(default_factory=lambda: f"REQ-{str(uuid.uuid4())[:8].upper()}")
    secret_name: str               = ""
    asset_id: str                  = ""
    environment: str               = ""
    requested_by: str              = ""
    requested_at: datetime         = field(default_factory=datetime.utcnow)
    status: str                    = "PENDING"
    approved_by: str               = ""
    approved_at: Optional[datetime] = None
    notes: str                     = ""

    def to_dict(self) -> dict:
        return {
            "request_id":   self.request_id,
            "secret_name":  self.secret_name,
            "asset_id":     self.asset_id,
            "environment":  self.environment,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at.isoformat(),
            "status":       self.status,
            "approved_by":  self.approved_by,
            "approved_at":  self.approved_at.isoformat() if self.approved_at else None,
            "notes":        self.notes,
        }


@dataclass
class AuditEvent:
    event_type: AuditEventType
    asset_id: str                  = ""
    secret_name: str               = ""
    owner: str                     = ""
    actor: str                     = ""
    requested_by: str              = ""
    approved_by: str               = ""
    environment: str               = ""
    provider: str                  = ""
    old_version: int               = 0
    new_version: int               = 0
    validation_status: str         = ""
    rollback_status: str           = ""
    success: bool                  = True
    message: str                   = ""
    timestamp: datetime            = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict:
        return {
            "timestamp":         self.timestamp.isoformat(),
            "event_type":        self.event_type.value,
            "asset_id":          self.asset_id,
            "secret_name":       self.secret_name,
            "owner":             self.owner,
            "actor":             self.actor,
            "requested_by":      self.requested_by,
            "approved_by":       self.approved_by,
            "environment":       self.environment,
            "provider":          self.provider,
            "old_version":       self.old_version,
            "new_version":       self.new_version,
            "validation_status": self.validation_status,
            "rollback_status":   self.rollback_status,
            "success":           self.success,
            "message":           self.message,
        }
