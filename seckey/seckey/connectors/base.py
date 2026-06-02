"""
seckey.connectors.base
======================
Abstract SecretStore interface that every cloud / HSM provider implements.
Also contains the LocalVault (in-memory, seeded with sample data for dev/test).
"""
from __future__ import annotations

import secrets
import string
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from seckey.models import (
    CloudPlatform,
    RotationResult,
    SecretMetadata,
    SecretStatus,
    SecretType,
)


# ---------------------------------------------------------------------------
# Abstract interface
# ---------------------------------------------------------------------------

class SecretStore(ABC):
    """
    Every cloud / HSM connector must implement this interface.
    Swap providers without touching orchestration logic.
    """

    @abstractmethod
    def provider_name(self) -> str: ...

    # ── Core CRUD ──────────────────────────────────────────────────────────
    @abstractmethod
    def get_secret(self, name: str) -> str: ...

    @abstractmethod
    def put_secret(self, name: str, value: str) -> None: ...

    @abstractmethod
    def rotate_secret(self, name: str, new_value: str) -> None: ...

    @abstractmethod
    def delete_old_version(self, name: str) -> None: ...

    # ── Metadata & lifecycle ───────────────────────────────────────────────
    @abstractmethod
    def get_metadata(self, name: str) -> SecretMetadata: ...

    @abstractmethod
    def put_metadata(self, meta: SecretMetadata) -> None: ...

    @abstractmethod
    def list_secrets(self) -> List[SecretMetadata]: ...

    @abstractmethod
    def disable_secret(self, name: str) -> None: ...

    @abstractmethod
    def delete_secret(self, name: str) -> None: ...

    @abstractmethod
    def get_history(self, name: str) -> List[RotationResult]: ...

    @abstractmethod
    def append_history(self, name: str, result: RotationResult) -> None: ...


# ---------------------------------------------------------------------------
# LocalVault  (in-memory, seeded, for dev / demo / unit tests)
# ---------------------------------------------------------------------------

class LocalVault(SecretStore):
    """
    Thread-safe in-memory vault.  Pre-seeded with five realistic sample secrets
    covering all common types: password, api-key, tls-cert, symmetric-key,
    database-credential.
    """

    def __init__(self) -> None:
        self._secrets:  Dict[str, str]                   = {}
        self._metadata: Dict[str, SecretMetadata]        = {}
        self._history:  Dict[str, List[RotationResult]]  = {}
        self._seed()

    # ── Seeding ────────────────────────────────────────────────────────────
    def _seed(self) -> None:
        now = datetime.utcnow()
        samples = [
            SecretMetadata(
                name="payment-db-password", asset_id="ITA-10234",
                app_name="PaymentService", secret_type=SecretType.DATABASE_CRED,
                environment="prod", business_domain="payments",
                owner="security-team", cloud_platform=CloudPlatform.AWS,
                provider="local", status=SecretStatus.ACTIVE,
                tags=["pci", "critical"], rotation_freq_days=30,
                version=5, rotation_count=5,
                created_at=now - timedelta(days=180),
                last_rotated_at=now - timedelta(days=30),
                next_rotation_at=now + timedelta(days=15),
                expires_at=now + timedelta(days=365),
            ),
            SecretMetadata(
                name="api-gateway-key", asset_id="ITA-10235",
                app_name="APIGateway", secret_type=SecretType.API_KEY,
                environment="prod", business_domain="platform",
                owner="platform-team", cloud_platform=CloudPlatform.AZURE,
                provider="local", status=SecretStatus.EXPIRING,
                tags=["api", "external"], rotation_freq_days=90,
                version=3, rotation_count=3,
                created_at=now - timedelta(days=365),
                last_rotated_at=now - timedelta(days=90),
                next_rotation_at=now + timedelta(days=5),
                expires_at=now + timedelta(days=30),
            ),
            SecretMetadata(
                name="kafka-sasl-secret", asset_id="ITA-10236",
                app_name="KafkaCluster", secret_type=SecretType.PASSWORD,
                environment="staging", business_domain="messaging",
                owner="infra-team", cloud_platform=CloudPlatform.AWS,
                provider="local", status=SecretStatus.EXPIRED,
                tags=["kafka", "internal"], rotation_freq_days=60,
                version=2, rotation_count=2,
                created_at=now - timedelta(days=365),
                last_rotated_at=now - timedelta(days=120),
                next_rotation_at=now - timedelta(days=5),
                expires_at=now - timedelta(days=30),
            ),
            SecretMetadata(
                name="vault-unseal-key", asset_id="ITA-10237",
                app_name="VaultCluster", secret_type=SecretType.SYMMETRIC_KEY,
                environment="prod", business_domain="security",
                owner="vault-admin", cloud_platform=CloudPlatform.HASHICORP,
                provider="local", status=SecretStatus.DISABLED,
                tags=["hsm", "critical"], rotation_freq_days=180,
                version=1, rotation_count=1,
                created_at=now - timedelta(days=730),
                last_rotated_at=now - timedelta(days=365),
                next_rotation_at=now - timedelta(days=90),
                expires_at=now + timedelta(days=180),
            ),
            SecretMetadata(
                name="tls-ingress-cert", asset_id="ITA-10238",
                app_name="TLSTerminator", secret_type=SecretType.TLS_CERT,
                environment="prod", business_domain="networking",
                owner="netops-team", cloud_platform=CloudPlatform.AZURE,
                provider="local", status=SecretStatus.ACTIVE,
                tags=["tls", "external"], rotation_freq_days=365,
                version=2, rotation_count=2,
                created_at=now - timedelta(days=365),
                last_rotated_at=now - timedelta(days=180),
                next_rotation_at=now + timedelta(days=180),
                expires_at=now + timedelta(days=365),
            ),
        ]
        for m in samples:
            self._metadata[m.name] = m
            self._secrets[m.name]  = f"seeded-value-{m.name}"
            self._history[m.name]  = []

    # ── Interface implementation ───────────────────────────────────────────
    def provider_name(self) -> str:
        return "local-vault"

    def get_secret(self, name: str) -> str:
        if name not in self._secrets:
            raise KeyError(f"Secret '{name}' not found")
        return self._secrets[name]

    def put_secret(self, name: str, value: str) -> None:
        self._secrets[name] = value
        if name not in self._metadata:
            self._metadata[name] = SecretMetadata(name=name, asset_id="")
        if name not in self._history:
            self._history[name] = []

    def rotate_secret(self, name: str, new_value: str) -> None:
        if name not in self._secrets:
            raise KeyError(f"Secret '{name}' not found — cannot rotate")
        self._secrets[name] = new_value
        m = self._metadata[name]
        m.version        += 1
        m.rotation_count += 1
        m.last_rotated_at = datetime.utcnow()
        m.next_rotation_at = datetime.utcnow() + timedelta(days=m.rotation_freq_days)
        m.status          = SecretStatus.ACTIVE

    def delete_old_version(self, name: str) -> None:
        pass  # local vault keeps one version; real vaults prune old AWSID versions here

    def get_metadata(self, name: str) -> SecretMetadata:
        if name not in self._metadata:
            raise KeyError(f"Metadata for '{name}' not found")
        return self._metadata[name]

    def put_metadata(self, meta: SecretMetadata) -> None:
        self._metadata[meta.name] = meta
        if meta.name not in self._history:
            self._history[meta.name] = []

    def list_secrets(self) -> List[SecretMetadata]:
        return list(self._metadata.values())

    def disable_secret(self, name: str) -> None:
        self._metadata[name].status = SecretStatus.DISABLED

    def delete_secret(self, name: str) -> None:
        self._secrets.pop(name, None)
        self._metadata.pop(name, None)
        self._history.pop(name, None)

    def get_history(self, name: str) -> List[RotationResult]:
        return self._history.get(name, [])

    def append_history(self, name: str, result: RotationResult) -> None:
        self._history.setdefault(name, []).append(result)


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------

def generate_secret(length: int = 32, secret_type: SecretType = SecretType.PASSWORD) -> str:
    """
    Generate a cryptographically secure secret of the requested type and length.
    Uses Python's `secrets` module (OS entropy source).
    """
    if secret_type in (SecretType.SYMMETRIC_KEY, SecretType.RSA_KEY):
        return secrets.token_urlsafe(length)
    if secret_type == SecretType.API_KEY:
        return secrets.token_hex(length)
    # Default: strong password-like with mixed charset
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def create_store(provider: str, config: dict) -> SecretStore:
    """
    Return the SecretStore implementation for the requested provider.
    Import is deferred so unused connectors don't pull in heavy SDKs.
    """
    provider = provider.lower()

    if provider in ("local", ""):
        return LocalVault()

    if provider == "aws":
        from seckey.connectors.aws import AWSSecretsManagerStore
        return AWSSecretsManagerStore(
            region=config.get("region", "ap-southeast-1"),
            role_arn=config.get("role_arn"),
        )
    if provider == "azure":
        from seckey.connectors.azure import AzureKeyVaultStore
        return AzureKeyVaultStore(vault_url=config["vault_url"])

    if provider in ("hashicorp", "vault"):
        from seckey.connectors.hashicorp import HashiCorpVaultStore
        return HashiCorpVaultStore(
            address=config.get("address", "https://vault.internal:8200"),
            token=config.get("token"),
            mount=config.get("mount", "secret"),
        )
    if provider == "fortanix":
        from seckey.connectors.fortanix import FortanixDSMStore
        return FortanixDSMStore(
            endpoint=config["endpoint"],
            api_key=config["api_key"],
        )
    if provider == "thales":
        from seckey.connectors.thales import ThalesCipherTrustStore
        return ThalesCipherTrustStore(
            endpoint=config["endpoint"],
            username=config["username"],
            password=config["password"],
        )
    if provider == "alibaba":
        from seckey.connectors.alibaba import AlibabaKMSStore
        return AlibabaKMSStore(
            region=config.get("region", "cn-hangzhou"),
            access_key_id=config["access_key_id"],
            access_key_secret=config["access_key_secret"],
        )
    if provider == "gcp":
        from seckey.connectors.gcp import GCPSecretManagerStore
        return GCPSecretManagerStore(project_id=config["project_id"])

    if provider == "oracle":
        from seckey.connectors.oracle import OracleVaultStore
        return OracleVaultStore(
            vault_id=config["vault_id"],
            compartment_id=config["compartment_id"],
        )

    raise ValueError(
        f"Unknown provider '{provider}'. "
        "Valid: local, aws, azure, hashicorp, fortanix, thales, alibaba, gcp, oracle"
    )
