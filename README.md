# Secret & Key Lifecycle Automation Platform
### Enterprise Python Edition — Multi-Cloud · HSM-aware · Audit-immutable

> **Banking / FinTech ready.** Designed for PCI-DSS, SOC 2, ISO 27001, and MAS TRM compliance environments.

---

## Table of Contents
1. [Purpose](#purpose)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Rotation Flow (12 Steps)](#rotation-flow)
5. [Supported Providers](#supported-providers)
6. [Quick Start](#quick-start)
7. [All Commands](#all-commands)
8. [Command Reference](#command-reference)
9. [Configuration](#configuration)
10. [Wiring Real Providers](#wiring-real-providers)
11. [Authentication & Authorization (v2 Roadmap)](#authentication--authorization-v2-roadmap)
12. [Security Architecture](#security-architecture)
13. [Compliance Mapping](#compliance-mapping)
14. [Running Tests](#running-tests)
15. [Deployment Guide](#deployment-guide)

---

## Purpose

The platform automates the **complete lifecycle** of secrets, encryption keys, certificates,
and API credentials across cloud and enterprise environments.

| Capability | Description |
|---|---|
| Secret onboarding | Register applications with CMDB validation before first use |
| Key creation | Generate cryptographically secure credentials via OS entropy |
| Secret rotation | 12-step orchestrated rotation with validation and automatic rollback |
| Validation | DB connection, API auth, TLS cert, health check, key-usage verification |
| Rollback | Restore previous value + incident generation on any failure |
| Expiry monitoring | HEALTHY / WARNING / CRITICAL scoring with configurable thresholds |
| Audit reporting | Immutable JSONL audit log with 14 event types — SIEM-ready |
| Compliance evidence | CSV/JSON export with full rotation history and version tracking |

---

## Architecture

```
User / App Team
      │
      ▼
┌─────────────────────────────────────────────────────────────┐
│              Python CLI (argparse, Cobra-style)             │
│  onboard · rotate · rotate-all · secret-health · export ... │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────────┐
│               Secret Lifecycle Orchestrator                 │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐    │
│  │   CMDB   │  │  Policy  │  │ Approval │  │  Rotation │    │
│  │Validator │  │ Engine   │  │ Workflow │  │  Engine   │    │
│  └──────────┘  └──────────┘  └──────────┘  └─────┬─────┘    │
│                                                   │         │
│  ┌──────────────────────────────────────────────┐ │         │
│  │          SecretStore Interface               │◄┘         │
│  │  AWS · Azure · GCP · HashiCorp · Fortanix    │           │
│  │  Thales · Alibaba · Oracle · Local           │           │
│  └──────────────────────────────────────────────┘           │
│                                                             │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────┐    │
│  │Validation│  │ Rollback │  │  Audit   │  │  Notify   │    │
│  │ Engine   │  │ Engine   │  │ Logger   │  │  Engine   │    │
│  └──────────┘  └──────────┘  └──────────┘  └───────────┘    │
└─────────────────────────────────────────────────────────────┘
                        │
                        ▼
        SIEM / Dashboard / Compliance Report
        (Splunk · ELK · Grafana · QRadar)
```

---

## Project Structure

```
seckey/
├── seckey.py                  ← Entry point — all 15 sub-commands
├── requirements.txt
├── configs/
│   └── config.yaml               ← Provider & IdP configuration
├── tests/
│   └── test_core.py              ← 38 unit tests (all passing)
└── seckey/
    ├── __init__.py               ← Version
    ├── models.py                 ← Domain types: SecretMetadata, RotationResult, AuditEvent …
    ├── context.py                ← AppContext — single dependency container
    ├── output.py                 ← Table / JSON / CSV rendering helpers
    ├── connectors/
    │   ├── base.py               ← SecretStore ABC + LocalVault + generate_secret + factory
    │   └── providers.py          ← AWS · Azure · HashiCorp · Fortanix · Thales
    │                               Alibaba · GCP · Oracle (stubs with SDK patterns)
    ├── engines/
    │   ├── __init__.py           ← CMDB · Policy · Audit · Approval · Validation
    │   │                           Rollback · Notification · Health · Onboarding
    │   └── rotation.py           ← 12-step rotation orchestrator + bulk rotation
    └── auth/
        └── __init__.py           ← IdP stubs: Entra ID · Keycloak · ForgeRock · AWS IAM
                                    + LocalAuthProvider + RBAC permission map
```

---

## Rotation Flow

The engine follows a strict 12-step flow. Every step is logged to the audit trail.

```
┌─────────────────────────────────┐
│  1. Trigger                     │  cron · API · EventBridge · --force
│     (Rotation Scheduler)        │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  2. Read Secret Metadata        │  asset_id · name · policy · expiry
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  3. Validate Rotation Eligibility│  active? · due? · approved?
└──────┬─────────────────┬────────┘
    YES│                 │NO
       │                 └──────────► skip (returns RotationResult skipped)
       ▼
┌─────────────────────────────────┐
│  4. Generate New Secret / Key   │  secrets.token_urlsafe / token_hex / mixed-charset
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  5. Store New Secret in Vault   │  AWS · Azure · GCP · HashiCorp · Fortanix
│                                 │  Thales · Alibaba · Oracle · Local
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  6. Update Target Application   │  DB password · k8s secret · API config (hook)
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  7. Validation Engine           │  DB conn · API auth · TLS · health-check · key-usage
└──────┬─────────────────┬────────┘
  SUCCESS                FAILURE
       │                 │
       │                 ▼
       │        ┌─────────────────┐
       │        │  12. Rollback   │  restore old value → PutSecret(old_value)
       │        │      Engine     │
       │        └────────┬────────┘
       │                 │
       │                 ▼
       │        ┌─────────────────┐
       │        │ Incident /      │  INCIDENT audit event → SIEM alert
       │        │ Alert           │
       │        └─────────────────┘
       │
       ▼
┌─────────────────────────────────┐
│  8. Disable Old Secret          │  delete_old_version → mark revoked
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  9. Update Rotation Timestamp   │  version++ · rotation_count++ · next_rotation_at
│     + Version                   │
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  10. Audit & Compliance Logging │  immutable JSONL · actor · approver · timestamps
└────────────────┬────────────────┘
                 │
                 ▼
┌─────────────────────────────────┐
│  11. Send Notification          │  Slack · Teams · SIEM · email · stdout
└─────────────────────────────────┘
```

---

## Supported Providers

### Secret Stores

| Provider | Flag | SDK | Notes |
|---|---|---|---|
| Local vault | `local` | built-in | In-memory; seeded with 5 sample secrets for dev/test |
| AWS Secrets Manager | `aws` | `boto3` | Supports cross-account role assumption |
| Azure Key Vault | `azure` | `azure-keyvault-secrets` | Uses `DefaultAzureCredential` |
| HashiCorp Vault | `hashicorp` | `hvac` | KV-v2 mount; AppRole + token auth |
| Fortanix DSM | `fortanix` | `sdkms` | HSM-backed key generation and wrapping |
| Thales CipherTrust | `thales` | REST / `pykmip` | KMIP + REST API |
| Alibaba Cloud KMS | `alibaba` | `aliyun-python-sdk-kms` | Supports ECS RAM roles |
| Google Cloud | `gcp` | `google-cloud-secret-manager` | Workload Identity supported |
| Oracle Cloud | `oracle` | `oci` | OCI Vault Secrets |

### Authentication & Authorization (v2 roadmap)

| IdP | Flag | SDK |
|---|---|---|
| Microsoft Entra ID | `entra` | `msal` |
| Keycloak | `keycloak` | `python-keycloak` |
| ForgeRock / PingAM | `forgerock` | `requests` (REST API) |
| AWS IAM Identity Center | `aws-iam` | `boto3` (STS / Cedar) |
| Local (dev only) | `local` | built-in |

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/org/seckey
cd seckey
pip install -r requirements.txt     # full install
# or for local-only testing:
pip install requests pytest
```

### 2. Run with the local vault (zero config)

```bash
# Show all seeded sample secrets
python seckey.py list-secrets

# Health check
python seckey.py secret-health

# Rotate a single secret (force — bypasses due-date check)
python seckey.py rotate \
  --asset-id ITA-10234 \
  --secret-name payment-db-password \
  --env prod \
  --owner security-team \
  --force

# Bulk rotate all prod secrets (dry-run)
python seckey.py rotate-all \
  --env prod \
  --actor admin \
  --dry-run \
  --force

# Secrets expiring within 7 days
python seckey.py list-expiring --days 7

# Export inventory
python seckey.py export-secrets --file inventory.csv --format csv
```

### 3. Run against AWS Secrets Manager

```bash
export AWS_PROFILE=my-banking-profile    # or use IAM role
python seckey.py rotate \
  --provider aws \
  --provider-config '{"region":"ap-southeast-1"}' \
  --asset-id ITA-10234 \
  --secret-name payment-db-password \
  --env prod
```

### 4. Run the test suite

```bash
pip install pytest
python -m pytest tests/ -v
```

---

## All Commands

| Command | Description |
|---|---|
| `onboard` | Register app with CMDB · validate policy · create metadata record |
| `create-secret` | Generate and store a new cryptographic secret immediately |
| `rotate` | Full 12-step rotation · generate · validate · rollback on failure |
| `rotate-all` | Bulk rotation for an environment with dry-run support |
| `list-secrets` | Tabular or JSON inventory of all managed secrets |
| `get-secret` | Full metadata for one secret (--show-value for audited plaintext) |
| `search-secret` | Filter by name substring, environment, owner, or domain |
| `export-secrets` | Export inventory to CSV or JSON (metadata only — no values) |
| `list-expiring` | Secrets whose rotation is due within N days |
| `secret-health` | HEALTHY / WARNING / CRITICAL compliance scoring |
| `approve-rotation` | Approve or reject a PENDING_APPROVAL rotation request |
| `disable-secret` | Emergency disable — blocks all future rotations |
| `delete-secret` | Permanently delete a secret (requires --confirm) |
| `secret-history` | Version-by-version rotation audit trail |
| `version` | Show version information |

---

## Command Reference

### Global flags (available on every command)

```
--provider         local|aws|azure|hashicorp|fortanix|thales|alibaba|gcp|oracle
--provider-config  JSON string with provider-specific config
--audit-log        Path to append-only audit log (default: audit.jsonl)
--output  -o       table|json
--notify           stdout|slack|teams|siem
--webhook          Webhook URL for notifications
--verbose  -v      Enable debug logging
```

### onboard

```
python seckey.py onboard \
  --asset-id    ITA-10234     \   # CMDB IT asset number (required)
  --secret-name payment-db-password  \
  --secret-type password      \   # password|api-key|tls-cert|symmetric-key|…
  --env         prod          \   # prod|staging|uat|dev
  --owner       security-team \
  --cloud       aws           \
  --freq        30            \   # rotation frequency in days
  --tags        pci,critical  \
  --actor       admin
```

### rotate

```
python seckey.py rotate \
  --asset-id              ITA-10234       \
  --secret-name           payment-db-password  \
  --env                   prod            \
  --owner                 security-team   \
  --actor                 admin           \
  --force                                 \   # bypass eligibility check
  --dry-run                               \   # simulate — no changes
  --validation-type       db-connection   \   # none|db-connection|api-auth|tls-cert|…
  --validation-endpoint   postgres://…    \
  --secret-len            32              \
  --approved-by           ciso@bank.com
```

### rotate-all

```
python seckey.py rotate-all \
  --env    prod   \   # empty = all environments
  --actor  admin  \
  --force         \
  --dry-run
```

### approve-rotation

```
# Approve
python seckey.py approve-rotation \
  --request-id REQ-00001 \
  --approver   ciso@bank.com

# Reject
python seckey.py approve-rotation \
  --request-id REQ-00001 \
  --approver   ciso@bank.com \
  --reject \
  --reason "pending quarterly risk review"
```

### secret-health

```
# Check all secrets
python seckey.py secret-health

# Check one secret
python seckey.py secret-health --secret-name payment-db-password
```

### export-secrets

```
python seckey.py export-secrets \
  --file    inventory.csv \
  --format  csv           \   # csv|json
  --actor   admin
```

---

## Configuration

### Environment variables

All flags can be set via environment variables with the `SECKEY_` prefix:

```bash
export SECKEY_PROVIDER=aws
export SECKEY_AUDIT_LOG=/var/log/seckey/audit.jsonl
export SECKEY_NOTIFY=slack
export SECKEY_WEBHOOK=https://hooks.slack.com/…

# Provider-specific
export AWS_REGION=ap-southeast-1
export VAULT_TOKEN=hvs.…
export AZURE_CLIENT_ID=…
export AZURE_TENANT_ID=…
```

### config.yaml

```yaml
provider: aws
audit_log: /var/log/seckey/audit.jsonl
notify: slack
webhook: https://hooks.slack.com/services/…

cmdb_url: https://cmdb.internal/api
cmdb_api_key: your-api-key

aws:
  region: ap-southeast-1

azure:
  vault_url: https://bank-vault.vault.azure.net
```

---

## Wiring Real Providers

### AWS Secrets Manager

```python
# seckey/connectors/providers.py → AWSSecretsManagerStore.get_secret
import boto3

def get_secret(self, name: str) -> str:
    client = boto3.client("secretsmanager", region_name=self.region)
    resp   = client.get_secret_value(SecretId=name)
    return resp.get("SecretString") or resp["SecretBinary"].decode()

def rotate_secret(self, name: str, new_value: str) -> None:
    client = boto3.client("secretsmanager", region_name=self.region)
    client.put_secret_value(SecretId=name, SecretString=new_value)
```

**IAM policy required:**
```json
{
  "Effect": "Allow",
  "Action": [
    "secretsmanager:GetSecretValue",
    "secretsmanager:PutSecretValue",
    "secretsmanager:UpdateSecret",
    "secretsmanager:DeleteSecret",
    "secretsmanager:ListSecrets",
    "secretsmanager:DescribeSecret",
    "secretsmanager:TagResource"
  ],
  "Resource": "arn:aws:secretsmanager:ap-southeast-1:*:secret:*"
}
```

### Azure Key Vault

```python
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

def get_secret(self, name: str) -> str:
    client = SecretClient(vault_url=self.vault_url, credential=DefaultAzureCredential())
    return client.get_secret(name).value

def rotate_secret(self, name: str, new_value: str) -> None:
    client = SecretClient(vault_url=self.vault_url, credential=DefaultAzureCredential())
    client.set_secret(name, new_value)
```

### HashiCorp Vault

```python
import hvac

def get_secret(self, name: str) -> str:
    client = hvac.Client(url=self.address, token=self.token)
    data   = client.secrets.kv.v2.read_secret_version(
        path=name, mount_point=self.mount)
    return data["data"]["data"]["value"]
```

### Google Cloud Secret Manager

```python
from google.cloud import secretmanager

def get_secret(self, name: str) -> str:
    client   = secretmanager.SecretManagerServiceClient()
    resource = f"projects/{self.project_id}/secrets/{name}/versions/latest"
    resp     = client.access_secret_version(request={"name": resource})
    return resp.payload.data.decode("utf-8")
```

### Alibaba Cloud KMS

```python
import json
from aliyunsdkcore.client import AcsClient
from aliyunsdkkms.request.v20160120.GetSecretValueRequest import GetSecretValueRequest

def get_secret(self, name: str) -> str:
    client = AcsClient(self.access_key_id, self.access_key_secret, self.region)
    req    = GetSecretValueRequest()
    req.set_SecretName(name)
    resp   = json.loads(client.do_action_with_exception(req))
    return resp["SecretData"]
```

### Oracle Cloud Vault

```python
import oci, base64

def get_secret(self, name: str) -> str:
    config = oci.config.from_file()
    client = oci.secrets.SecretsClient(config)
    resp   = client.get_secret_bundle_by_name(
        secret_name=name, vault_id=self.vault_id)
    return base64.b64decode(
        resp.data.secret_bundle_content.content).decode()
```

---

## Authentication & Authorization (v2 Roadmap)

The `seckey/auth/__init__.py` module contains complete integration stubs for four enterprise IdPs.
Wire these in v2 by calling `check_permission(principal, "secrets", "rotate")` in each CLI handler.

### Microsoft Entra ID (Azure AD)

```python
# pip install msal
from seckey.auth import EntraIDProvider, check_permission

idp       = EntraIDProvider(tenant_id="…", client_id="…", client_secret="…")
principal = idp.validate_token(bearer_token)           # from HTTP header
check_permission(principal, "secrets", "rotate")       # raises PermissionError if denied
```

**Azure AD App Role mapping:**
| Azure AD App Role | seckey role |
|---|---|
| `SecretAdmin` | `secret-admin` |
| `RotationOperator` | `rotation-operator` |
| `Approver` | `approver` |
| `Auditor` | `auditor` |

### Keycloak

```python
# pip install python-keycloak
from seckey.auth import KeycloakProvider

kc        = KeycloakProvider(server_url="https://keycloak.internal/auth",
                              realm="banking", client_id="seckey-cli", client_secret="…")
principal = kc.authenticate(username, password)
```

**Keycloak client role → seckey role mapping** is configured in the Keycloak admin console
under Client Roles for the `seckey-cli` client.

### ForgeRock AM / PingAM

```python
from seckey.auth import ForgeRockProvider

fr        = ForgeRockProvider(base_url="https://am.internal/openam",
                               realm="/banking", client_id="seckey-cli", client_secret="…")
principal = fr.validate_token(token)
```

ForgeRock policy evaluation uses `/json/realms/{realm}/policies?_action=evaluate`
with Cedar-like resource/action/application parameters.

### AWS IAM Identity Center

```bash
# 1. Login via IAM Identity Center SSO
aws sso login --profile banking-prod

# 2. The CLI then uses boto3.client("sts").get_caller_identity()
#    to prove identity, and maps the IAM role ARN to seckey roles
#    via a configurable role_map dict.
```

### RBAC permission table

| Command | Required role |
|---|---|
| `rotate` | `secret-admin`, `rotation-operator` |
| `rotate-all` | `secret-admin` |
| `onboard` | `secret-admin`, `onboarding-team` |
| `disable-secret` | `secret-admin` |
| `delete-secret` | `secret-admin` |
| `approve-rotation` | `approver`, `secret-admin` |
| `list-secrets` | any authenticated role |
| `get-secret --show-value` | `secret-admin` |
| `export-secrets` | `secret-admin`, `auditor` |
| `secret-health` | any authenticated role |
| `secret-history` | `secret-admin`, `auditor` |

---

## Security Architecture

| Control | Implementation |
|---|---|
| Cryptographically secure generation | Python `secrets` module (OS entropy, CSPRNG) |
| Immutable audit log | Append-only JSONL, chmod 600, suitable for WORM storage |
| Rollback on failure | Previous value restored before incident is created |
| Two-person integrity | Approval workflow with PENDING_APPROVAL state |
| Secret never logged | Values never appear in audit events or notifications |
| Minimum secret length | 24 bytes by default (policy engine enforced) |
| Rotation frequency cap | Max 180 days (policy engine enforced) |
| Naming standards | Lowercase alphanumeric + hyphens enforced by regex |
| CMDB gating | Every operation validated against IT asset registry |
| TLS validation | TLS cert expiry + chain verified before old cert revoked |
| Provider isolation | Deferred imports — unused cloud SDKs never loaded |
| Audit trail fields | actor · approver · asset_id · old/new version · validation_status |

### Audit event types

`ONBOARD` · `CREATE` · `ROTATE` · `BULK_ROTATE` · `VALIDATE` · `ROLLBACK` ·
`DISABLE` · `DELETE` · `APPROVE` · `REJECT` · `EXPORT` · `HEALTH_CHECK` ·
`GET_VALUE` · `INCIDENT` · `LIST` · `GET_HISTORY`

### SIEM integration

The audit log is newline-delimited JSON (JSONL) — one event per line.
Ingest into Splunk:
```
[monitor:///var/log/seckey/audit.jsonl]
sourcetype = seckey_audit
index      = security
```

---

## Compliance Mapping

| Standard | Control | How seckey addresses it |
|---|---|---|
| PCI-DSS v4 Req 8.3 | Credential rotation | Automated rotation with policy-enforced max frequency |
| PCI-DSS v4 Req 10 | Audit trail | Immutable JSONL log with actor, timestamp, old/new version |
| SOC 2 CC6.1 | Logical access controls | RBAC + approval workflow + CMDB validation |
| SOC 2 CC6.6 | Cryptographic key management | HSM connectors (Fortanix, Thales); key never leaves HSM |
| ISO 27001 A.9.4 | Secret management | Naming standards, expiry, rotation policy engine |
| MAS TRM 9.3 | Privileged access | Two-person approval, actor tracking, disable/delete audit |
| NIST SP 800-57 | Key lifecycle | Full lifecycle: create → rotate → revoke → audit |

---

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v

# With coverage
pip install pytest-cov
python -m pytest tests/ --cov=seckey --cov-report=term-missing
```

**Current test coverage: 38 tests across:**
- LocalVault CRUD + history
- Cryptographic secret generation (length, uniqueness, charset)
- PolicyEngine (name validation, frequency, eligibility)
- CMDBValidator (known/unknown assets, owner mismatch)
- HealthChecker (HEALTHY / WARNING / CRITICAL scoring, expiry listing)
- RotationEngine (dry-run, force, bulk, version increment, failure handling)
- ApprovalWorkflow (submit, approve, reject, list-pending, double-approve guard)

---

## Deployment Guide

### Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir requests pytest   # minimal; add SDK deps as needed
COPY . .
ENTRYPOINT ["python", "seckey.py"]
```

```bash
docker build -t seckey:1.0 .
docker run --rm \
  -e AWS_PROFILE=banking \
  -v ~/.aws:/root/.aws:ro \
  -v $(pwd)/audit.jsonl:/app/audit.jsonl \
  seckey:1.0 \
  rotate --provider aws --provider-config '{"region":"ap-southeast-1"}' \
         --asset-id ITA-10234 --secret-name payment-db-password --env prod --force
```

### Kubernetes CronJob (scheduled rotation)

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: seckey-rotation
  namespace: security
spec:
  schedule: "0 2 * * *"           # 02:00 UTC daily
  jobTemplate:
    spec:
      template:
        spec:
          serviceAccountName: seckey-sa  # IAM Role for Service Account (IRSA)
          containers:
          - name: seckey
            image: your-registry/seckey:1.0
            command:
            - python
            - seckey.py
            - rotate-all
            - --provider
            - aws
            - --provider-config
            - '{"region":"ap-southeast-1"}'
            - --env
            - prod
            - --actor
            - k8s-cron
            - --force
            - --notify
            - slack
            - --webhook
            - $(SLACK_WEBHOOK)
            envFrom:
            - secretRef:
                name: seckey-slack-webhook
          restartPolicy: OnFailure
```

### AWS Lambda (EventBridge trigger)

```python
import subprocess, json, os

def handler(event, context):
    secret_name = event.get("secret_name")
    asset_id    = event.get("asset_id")
    result = subprocess.run([
        "python", "seckey.py", "rotate",
        "--provider", "aws",
        "--provider-config", json.dumps({"region": os.environ["AWS_REGION"]}),
        "--asset-id", asset_id,
        "--secret-name", secret_name,
        "--env", "prod",
        "--force",
    ], capture_output=True, text=True)
    return {"stdout": result.stdout, "returncode": result.returncode}
```

---

## Version History

| Version | What changed |
|---|---|
| v1.0.0 | Initial release — 9 providers, 15 commands, 12-step rotation, 38 tests |
| v2.0.0 (planned) | Wire Entra ID / Keycloak / ForgeRock / AWS IAM auth module; add HTTP API server; WebUI dashboard |

---

*Maintained by the Security Engineering team.*
*For incidents: raise a P1 in ServiceNow against CI=secret-rotation-platform.*
