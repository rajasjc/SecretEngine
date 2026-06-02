"""
seckey.auth
===========
Authentication & Authorization module.

Current state : stubs with full integration patterns.
Next version  : wire these into every CLI command via PersistentPreRun.

Supported IdPs
--------------
- Microsoft Entra ID (Azure AD) — MSAL / OIDC
- Keycloak                      — python-keycloak / OIDC
- ForgeRock AM / PingAM         — OAuth2 / OIDC
- AWS IAM / IAM Identity Center — SigV4 / AssumeRole
"""
from __future__ import annotations

import base64
import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Optional

log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Token / Principal
# ─────────────────────────────────────────────────────────────────────────────

class Principal:
    """Represents an authenticated identity after token validation."""

    def __init__(self, subject: str, email: str, roles: List[str],
                 groups: List[str], provider: str, expires_at: datetime,
                 raw_token: str = ""):
        self.subject    = subject
        self.email      = email
        self.roles      = roles
        self.groups     = groups
        self.provider   = provider
        self.expires_at = expires_at
        self.raw_token  = raw_token

    def has_role(self, role: str) -> bool:
        return role in self.roles

    def has_any_role(self, *roles: str) -> bool:
        return any(r in self.roles for r in roles)

    def is_expired(self) -> bool:
        return datetime.utcnow() > self.expires_at

    def __repr__(self) -> str:
        return f"<Principal subject={self.subject} roles={self.roles} provider={self.provider}>"


# ─────────────────────────────────────────────────────────────────────────────
# Base IdP interface
# ─────────────────────────────────────────────────────────────────────────────

class IdentityProvider(ABC):
    """Every IdP connector implements this interface."""

    @abstractmethod
    def authenticate(self, username: str, password: str) -> Principal: ...

    @abstractmethod
    def validate_token(self, token: str) -> Principal: ...

    @abstractmethod
    def refresh_token(self, refresh_token: str) -> str: ...

    @abstractmethod
    def has_permission(self, principal: Principal, resource: str, action: str) -> bool: ...


# ─────────────────────────────────────────────────────────────────────────────
# RBAC permission map (resource → action → required roles)
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_RBAC: Dict[str, Dict[str, List[str]]] = {
    "secrets": {
        "rotate":       ["secret-admin", "rotation-operator"],
        "rotate-all":   ["secret-admin"],
        "onboard":      ["secret-admin", "onboarding-team"],
        "disable":      ["secret-admin"],
        "delete":       ["secret-admin"],
        "approve":      ["approver", "secret-admin"],
        "list":         ["secret-admin", "rotation-operator", "auditor", "readonly"],
        "get":          ["secret-admin", "rotation-operator", "auditor"],
        "get-value":    ["secret-admin"],
        "export":       ["secret-admin", "auditor"],
        "health":       ["secret-admin", "rotation-operator", "auditor", "readonly"],
        "history":      ["secret-admin", "auditor"],
    }
}


def check_permission(principal: Principal, resource: str, action: str,
                     rbac: Dict = None) -> None:
    """Raise PermissionError if the principal lacks the required role."""
    rbac = rbac or DEFAULT_RBAC
    required = rbac.get(resource, {}).get(action, [])
    if not required:
        return  # no RBAC entry → open
    if not principal.has_any_role(*required):
        raise PermissionError(
            f"'{principal.subject}' lacks required role for {resource}/{action}. "
            f"Required: {required}. Has: {principal.roles}"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Microsoft Entra ID (Azure Active Directory)
# ─────────────────────────────────────────────────────────────────────────────

class EntraIDProvider(IdentityProvider):
    """
    Microsoft Entra ID (Azure AD) connector via MSAL.

    Real implementation:
        pip install msal

        import msal
        app = msal.ConfidentialClientApplication(
            client_id=self.client_id,
            client_credential=self.client_secret,
            authority=f"https://login.microsoftonline.com/{self.tenant_id}",
        )
        result = app.acquire_token_for_client(scopes=[f"{self.resource}/.default"])

    Group-to-role mapping is done via Azure AD App Roles.
    Token validation uses public key from JWKS endpoint:
        https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys
    """

    def __init__(self, tenant_id: str, client_id: str, client_secret: str,
                 resource: str = "https://management.azure.com"):
        self.tenant_id     = tenant_id
        self.client_id     = client_id
        self.client_secret = client_secret
        self.resource      = resource

    def authenticate(self, username: str, password: str) -> Principal:
        """
        Resource Owner Password Credentials flow (legacy; prefer device-code or auth-code).
        Replace with MSAL:
            app = msal.PublicClientApplication(client_id=self.client_id, authority=...)
            result = app.acquire_token_by_username_password(username, password, scopes=[...])
        """
        raise NotImplementedError(
            "[EntraID] authenticate — integrate msal.ConfidentialClientApplication"
        )

    def validate_token(self, token: str) -> Principal:
        """
        Validate an Azure AD JWT bearer token.
        Real:
            import jwt, requests
            jwks_uri = f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"
            keys = requests.get(jwks_uri).json()["keys"]
            payload = jwt.decode(token, options={"verify_signature": True}, algorithms=["RS256"], ...)
            return Principal(subject=payload["oid"], email=payload.get("upn",""),
                             roles=payload.get("roles", []), ...)
        """
        raise NotImplementedError("[EntraID] validate_token — integrate PyJWT + JWKS")

    def refresh_token(self, refresh_token: str) -> str:
        raise NotImplementedError("[EntraID] refresh_token")

    def has_permission(self, principal: Principal, resource: str, action: str) -> bool:
        check_permission(principal, resource, action)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Keycloak
# ─────────────────────────────────────────────────────────────────────────────

class KeycloakProvider(IdentityProvider):
    """
    Keycloak OIDC connector.

    Real implementation:
        pip install python-keycloak

        from keycloak import KeycloakOpenID
        keycloak = KeycloakOpenID(
            server_url=self.server_url,
            client_id=self.client_id,
            realm_name=self.realm,
            client_secret_key=self.client_secret,
        )
        token = keycloak.token(username, password)
        user_info = keycloak.userinfo(token["access_token"])
        roles = keycloak.get_roles(token["access_token"])

    Role mapping: Keycloak client roles → seckey RBAC roles
    """

    def __init__(self, server_url: str, realm: str, client_id: str, client_secret: str):
        self.server_url    = server_url
        self.realm         = realm
        self.client_id     = client_id
        self.client_secret = client_secret

    def authenticate(self, username: str, password: str) -> Principal:
        """
        from keycloak import KeycloakOpenID
        kc = KeycloakOpenID(server_url=self.server_url, realm_name=self.realm,
                            client_id=self.client_id, client_secret_key=self.client_secret)
        token_data = kc.token(username, password)
        user_info  = kc.userinfo(token_data["access_token"])
        realm_roles = kc.get_roles(token_data["access_token"])
        return Principal(subject=user_info["sub"], email=user_info.get("email",""),
                         roles=realm_roles, groups=user_info.get("groups",[]),
                         provider="keycloak", expires_at=datetime.utcnow()+timedelta(seconds=token_data["expires_in"]))
        """
        raise NotImplementedError("[Keycloak] authenticate — integrate python-keycloak")

    def validate_token(self, token: str) -> Principal:
        raise NotImplementedError("[Keycloak] validate_token")

    def refresh_token(self, refresh_token: str) -> str:
        raise NotImplementedError("[Keycloak] refresh_token")

    def has_permission(self, principal: Principal, resource: str, action: str) -> bool:
        check_permission(principal, resource, action)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# ForgeRock AM / PingAM
# ─────────────────────────────────────────────────────────────────────────────

class ForgeRockProvider(IdentityProvider):
    """
    ForgeRock Access Management (AM) / PingAM connector.
    Uses ForgeRock's REST authentication API + OAuth2 token introspection.

    Real implementation:
        POST /json/realms/{realm}/authenticate  (username+password → tokenId)
        POST /oauth2/realms/{realm}/access_token  (Authorization Code / Client Credentials)
        POST /oauth2/realms/{realm}/introspect    (token validation)
    """

    def __init__(self, base_url: str, realm: str, client_id: str, client_secret: str):
        self.base_url      = base_url
        self.realm         = realm
        self.client_id     = client_id
        self.client_secret = client_secret

    def authenticate(self, username: str, password: str) -> Principal:
        raise NotImplementedError("[ForgeRock] authenticate — wire ForgeRock REST API")

    def validate_token(self, token: str) -> Principal:
        """
        import requests
        resp = requests.post(
            f"{self.base_url}/oauth2/realms/{self.realm}/introspect",
            data={"token": token},
            auth=(self.client_id, self.client_secret),
        )
        data = resp.json()
        return Principal(subject=data["sub"], ...)
        """
        raise NotImplementedError("[ForgeRock] validate_token")

    def refresh_token(self, refresh_token: str) -> str:
        raise NotImplementedError("[ForgeRock] refresh_token")

    def has_permission(self, principal: Principal, resource: str, action: str) -> bool:
        """
        ForgeRock policy evaluation:
        POST /json/realms/{realm}/policies?_action=evaluate
        body: {"subject": {"ssoToken": principal.raw_token}, "resources": [...], "application": "seckey"}
        """
        check_permission(principal, resource, action)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# AWS IAM / IAM Identity Center
# ─────────────────────────────────────────────────────────────────────────────

class AWSIAMProvider(IdentityProvider):
    """
    AWS IAM / IAM Identity Center connector.

    For machine-to-machine: use IAM roles + AssumeRole (already in AWSSecretsManagerStore).
    For human operators: use IAM Identity Center (SSO) with SAML/OIDC.

    Real token validation:
        import boto3
        sts = boto3.client("sts")
        identity = sts.get_caller_identity()
        # Parse ARN for role / user → map to seckey roles via tag or attribute
    """

    def __init__(self, region: str = "ap-southeast-1", role_map: Optional[Dict] = None):
        self.region   = region
        self.role_map = role_map or {}  # IAM role ARN → seckey role list

    def authenticate(self, username: str, password: str) -> Principal:
        """
        AWS does not support username+password programmatically.
        Use aws sso login + import boto3; sts.get_caller_identity() instead.
        """
        raise NotImplementedError("[AWS IAM] Use assume-role or IAM Identity Center SSO")

    def validate_token(self, token: str) -> Principal:
        """
        Decode an AWS presigned URL token or verify an OIDC token from IAM Identity Center.
        For SigV4: import boto3; sts.get_caller_identity() proves validity.
        """
        raise NotImplementedError("[AWS IAM] validate_token — wire sts.get_caller_identity")

    def refresh_token(self, refresh_token: str) -> str:
        raise NotImplementedError("[AWS IAM] refresh_token — use SSO token refresh")

    def has_permission(self, principal: Principal, resource: str, action: str) -> bool:
        """
        For fine-grained authorization use AWS Verified Permissions (Cedar policy engine).
        import boto3
        avp = boto3.client("verifiedpermissions", region_name=self.region)
        resp = avp.is_authorized(policyStoreId=..., principal=..., action=..., resource=...)
        return resp["decision"] == "ALLOW"
        """
        check_permission(principal, resource, action)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# No-op / local provider (dev / testing)
# ─────────────────────────────────────────────────────────────────────────────

class LocalAuthProvider(IdentityProvider):
    """
    Flat-file local auth for dev/test only.
    DO NOT use in production.
    """
    _USERS = {
        "admin":    {"password": "admin123",  "roles": ["secret-admin", "approver"]},
        "operator": {"password": "op123",     "roles": ["rotation-operator"]},
        "auditor":  {"password": "audit123",  "roles": ["auditor", "readonly"]},
    }

    def authenticate(self, username: str, password: str) -> Principal:
        user = self._USERS.get(username)
        if not user or user["password"] != password:
            raise ValueError(f"LocalAuth: invalid credentials for '{username}'")
        return Principal(
            subject=username, email=f"{username}@local",
            roles=user["roles"], groups=[],
            provider="local",
            expires_at=datetime.utcnow() + timedelta(hours=8),
        )

    def validate_token(self, token: str) -> Principal:
        # simple base64-encoded "username:roles" for local demo
        try:
            decoded = base64.b64decode(token).decode()
            parts   = decoded.split(":")
            return Principal(
                subject=parts[0], email=f"{parts[0]}@local",
                roles=parts[1].split(",") if len(parts) > 1 else [],
                groups=[], provider="local",
                expires_at=datetime.utcnow() + timedelta(hours=1),
            )
        except Exception as exc:
            raise ValueError(f"LocalAuth: invalid token — {exc}") from exc

    def refresh_token(self, refresh_token: str) -> str:
        return refresh_token

    def has_permission(self, principal: Principal, resource: str, action: str) -> bool:
        check_permission(principal, resource, action)
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────────────

def create_idp(provider: str, config: dict) -> IdentityProvider:
    provider = provider.lower()
    if provider in ("local", ""):
        return LocalAuthProvider()
    if provider == "entra":
        return EntraIDProvider(
            tenant_id=config["tenant_id"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
        )
    if provider == "keycloak":
        return KeycloakProvider(
            server_url=config["server_url"],
            realm=config["realm"],
            client_id=config["client_id"],
            client_secret=config["client_secret"],
        )
    if provider == "forgerock":
        return ForgeRockProvider(
            base_url=config["base_url"],
            realm=config.get("realm", "root"),
            client_id=config["client_id"],
            client_secret=config["client_secret"],
        )
    if provider in ("aws-iam", "aws"):
        return AWSIAMProvider(
            region=config.get("region", "ap-southeast-1"),
            role_map=config.get("role_map", {}),
        )
    raise ValueError(f"Unknown IdP provider '{provider}' — valid: local, entra, keycloak, forgerock, aws-iam")
