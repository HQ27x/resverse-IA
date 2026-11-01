from __future__ import annotations

from .config import PROFILES, ReiaError

PATCHABLE_PROFILES = frozenset({"ctf", "own", "interop"})
CLOUD_BLOCKED_PROFILES = frozenset({"malware"})
EXECUTION_BLOCKED_PROFILES = frozenset({"malware", "analysis"})


class PolicyError(ReiaError):
    """Raised when an action is outside the authorized profile."""


def require_profile(profile: str) -> None:
    if profile not in PROFILES:
        raise PolicyError(f"unknown profile: {profile}")


def can_patch(profile: str) -> bool:
    return profile in PATCHABLE_PROFILES


def can_cloud(profile: str) -> bool:
    return profile not in CLOUD_BLOCKED_PROFILES


def can_execute(profile: str) -> bool:
    return profile not in EXECUTION_BLOCKED_PROFILES


def can_mcp_external(profile: str) -> bool:
    return profile not in CLOUD_BLOCKED_PROFILES


def authorization_basis(profile: str) -> str:
    return {
        "ctf": "ctf-lab",
        "own": "owner",
        "interop": "interoperability",
        "malware": "authorized-static-analysis",
        "analysis": "authorized-analysis",
    }.get(profile, "authorized-analysis")


def require_patch_allowed(profile: str, authorization: str | None) -> None:
    require_profile(profile)
    if not can_patch(profile):
        raise PolicyError(
            f"profile '{profile}' is read-only; patching is allowed only for ctf, own or interop"
        )
    text = (authorization or "").strip()
    if len(text) < 6:
        raise PolicyError(
            "patch authorization is required; state the CTF/lab or ownership basis in --authorization"
        )
    lowered = text.lower()
    if profile == "interop" and not any(
        token in lowered
        for token in ("interop", "autoriz", "authorized", "permiso", "permission")
    ):
        raise PolicyError(
            "interop patching requires an explicit authorization statement mentioning interoperability or permission"
        )


def policy_snapshot(profile: str) -> dict[str, object]:
    require_profile(profile)
    return {
        "profile": profile,
        "patching": "copy-only" if can_patch(profile) else "disabled",
        "execution": "sandbox-only" if can_execute(profile) else "disabled",
        "cloud": "allowed-with-redaction" if can_cloud(profile) else "blocked",
        "mcp_external": "allowed" if can_mcp_external(profile) else "blocked",
        "authorization_basis": authorization_basis(profile),
    }
