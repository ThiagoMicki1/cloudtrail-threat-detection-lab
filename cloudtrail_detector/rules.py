from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from .detector import Alert


ACCESS_DENIED_THRESHOLD = 3
SUSPICIOUS_ASSUME_ROLE_IPS = {"198.51.100.77", "203.0.113.88"}


def run_rules(events: list[dict[str, Any]]) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        alerts.extend(_single_event_rules(event))
    alerts.extend(_access_denied_spike(events))
    return sorted(alerts, key=lambda alert: (alert.timestamp, alert.severity, alert.rule_name))


def _single_event_rules(event: dict[str, Any]) -> list[Alert]:
    event_name = event.get("eventName", "Unknown")
    checks = [
        _root_account_usage,
        _failed_console_login,
        _new_access_key_creation,
        _iam_policy_change,
        _security_group_open_to_world,
        _cloudtrail_stopped_or_deleted,
        _suspicious_assume_role,
        _console_login_without_mfa,
        _iam_user_created,
        _mfa_device_deactivated,
        _s3_public_policy_change,
    ]
    return [alert for check in checks if (alert := check(event, event_name))]


def _alert(
    event: dict[str, Any],
    severity: str,
    rule_name: str,
    evidence: str,
    mitre_attack: str,
    recommendation: str,
    event_name: str | None = None,
) -> Alert:
    return Alert(
        severity=severity,
        rule_name=rule_name,
        event_name=event_name or event.get("eventName", "Unknown"),
        actor=_actor(event),
        source_ip=event.get("sourceIPAddress", "Unknown"),
        aws_region=event.get("awsRegion", "Unknown"),
        timestamp=event.get("eventTime", "Unknown"),
        evidence=evidence,
        mitre_attack=mitre_attack,
        recommendation=recommendation,
    )


def _actor(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity", {})
    return (
        identity.get("userName")
        or identity.get("arn")
        or identity.get("principalId")
        or identity.get("type")
        or "Unknown"
    )


def _root_account_usage(event: dict[str, Any], event_name: str) -> Alert | None:
    if event.get("userIdentity", {}).get("type") != "Root":
        return None
    return _alert(
        event,
        "CRITICAL",
        "Root account usage",
        "CloudTrail event was performed by the AWS root identity.",
        "T1078 Valid Accounts - Initial Access / Privilege Escalation",
        "Avoid root account activity. Use named IAM roles/users with MFA and least privilege.",
    )


def _failed_console_login(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "ConsoleLogin":
        return None
    if event.get("responseElements", {}).get("ConsoleLogin") != "Failure":
        return None
    return _alert(
        event,
        "WARN",
        "Failed console login",
        "AWS ConsoleLogin returned Failure.",
        "T1110 Brute Force - Credential Access",
        "Review source IP, user, and failure volume. Enforce MFA and investigate repeated failures.",
    )


def _new_access_key_creation(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "CreateAccessKey":
        return None
    return _alert(
        event,
        "HIGH",
        "New access key creation",
        "CreateAccessKey was called for an IAM principal.",
        "T1098 Account Manipulation - Persistence",
        "Confirm the key is approved. Rotate or delete unexpected access keys immediately.",
    )


def _iam_policy_change(event: dict[str, Any], event_name: str) -> Alert | None:
    policy_events = {
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "CreatePolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
        "DeletePolicy",
        "DeletePolicyVersion",
    }
    if event_name not in policy_events:
        return None
    return _alert(
        event,
        "HIGH",
        "IAM policy attachment or policy change",
        f"{event_name} can change AWS permissions.",
        "T1098 Account Manipulation - Privilege Escalation / Persistence",
        "Review the policy diff, target principal, and change ticket. Revert unauthorized privilege changes.",
    )


def _security_group_open_to_world(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "AuthorizeSecurityGroupIngress":
        return None
    cidrs = _find_values(event.get("requestParameters", {}), {"cidrIp", "cidrIpv6"})
    risky = sorted(cidr for cidr in cidrs if cidr in {"0.0.0.0/0", "::/0"})
    if not risky:
        return None
    return _alert(
        event,
        "HIGH",
        "Security group opened to the world",
        f"Ingress rule includes public CIDR range(s): {', '.join(risky)}.",
        "T1562 Impair Defenses / Initial Access support",
        "Restrict inbound access to trusted CIDRs and confirm the exposed port is required.",
    )


def _cloudtrail_stopped_or_deleted(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name not in {"StopLogging", "DeleteTrail"}:
        return None
    return _alert(
        event,
        "CRITICAL",
        "CloudTrail stopped or deleted",
        f"{event_name} can reduce AWS audit visibility.",
        "T1562 Impair Defenses - Defense Evasion",
        "Re-enable logging, protect CloudTrail with least privilege, and investigate the actor immediately.",
    )


def _suspicious_assume_role(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "AssumeRole":
        return None
    role_arn = event.get("requestParameters", {}).get("roleArn", "")
    source_ip = event.get("sourceIPAddress", "")
    suspicious_role = any(word in role_arn.lower() for word in ["admin", "securityaudit", "breakglass"])
    if source_ip not in SUSPICIOUS_ASSUME_ROLE_IPS and not suspicious_role:
        return None
    return _alert(
        event,
        "HIGH",
        "Suspicious AssumeRole activity",
        f"AssumeRole targeted {role_arn or 'an unknown role'} from {source_ip}.",
        "T1078 Valid Accounts / T1098 Account Manipulation",
        "Validate the source IP, role target, session name, and business reason for the role assumption.",
    )


def _console_login_without_mfa(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "ConsoleLogin":
        return None
    if event.get("responseElements", {}).get("ConsoleLogin") != "Success":
        return None
    if event.get("additionalEventData", {}).get("MFAUsed") != "No":
        return None
    return _alert(
        event,
        "HIGH",
        "Console login without MFA",
        "Successful console login had MFAUsed=No.",
        "T1078 Valid Accounts - Initial Access",
        "Require MFA for console access and review whether this identity is exempt from MFA controls.",
    )


def _iam_user_created(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "CreateUser":
        return None
    user_name = event.get("requestParameters", {}).get("userName", "unknown user")
    return _alert(
        event,
        "WARN",
        "IAM user created",
        f"CreateUser created or attempted to create IAM user {user_name}.",
        "T1136.003 Create Account: Cloud Account - Persistence",
        "Confirm the user was approved. Prefer federated identities and remove unexpected IAM users.",
    )


def _mfa_device_deactivated(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name not in {"DeactivateMFADevice", "DeleteVirtualMFADevice"}:
        return None
    return _alert(
        event,
        "CRITICAL",
        "MFA device deactivated",
        f"{event_name} changed MFA protection for an identity.",
        "T1556.006 Modify Authentication Process: Multi-Factor Authentication",
        "Confirm the MFA removal was approved. Re-enable MFA and review recent activity for the identity.",
    )


def _s3_public_policy_change(event: dict[str, Any], event_name: str) -> Alert | None:
    if event_name != "PutBucketPolicy":
        return None
    policy = event.get("requestParameters", {}).get("bucketPolicy") or event.get("requestParameters", {}).get("policy")
    if isinstance(policy, str):
        try:
            policy = json.loads(policy)
        except json.JSONDecodeError:
            policy = {}
    if not _policy_allows_public_s3(policy if isinstance(policy, dict) else {}):
        return None
    bucket = event.get("requestParameters", {}).get("bucketName", "unknown bucket")
    return _alert(
        event,
        "CRITICAL",
        "S3 bucket policy changed to public-risky permissions",
        f"PutBucketPolicy made public-style access possible on bucket {bucket}.",
        "T1619 Cloud Storage Object Discovery - Discovery / Exfiltration risk",
        "Remove public principals, enable S3 Block Public Access, and review object access logs.",
    )


def _access_denied_spike(events: list[dict[str, Any]]) -> list[Alert]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        error = str(event.get("errorCode") or event.get("errorMessage") or "")
        if "AccessDenied" in error or "UnauthorizedOperation" in error:
            groups[(_actor(event), event.get("sourceIPAddress", "Unknown"))].append(event)

    alerts = []
    for (actor, source_ip), denied_events in groups.items():
        if len(denied_events) < ACCESS_DENIED_THRESHOLD:
            continue
        first = denied_events[0]
        event_names = sorted({event.get("eventName", "Unknown") for event in denied_events})
        alerts.append(
            _alert(
                first,
                "WARN",
                "AccessDenied spike",
                f"{len(denied_events)} denied API calls from actor {actor} at {source_ip}: {', '.join(event_names)}.",
                "T1087 Account Discovery / T1110 Brute Force - Discovery or Credential Access",
                "Review whether the actor is probing permissions, using stale credentials, or attempting unauthorized access.",
                event_name="AccessDeniedSpike",
            )
        )
    return alerts


def _find_values(value: Any, names: set[str]) -> list[str]:
    found: list[str] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            if key in names and isinstance(nested, str):
                found.append(nested)
            else:
                found.extend(_find_values(nested, names))
    elif isinstance(value, list):
        for item in value:
            found.extend(_find_values(item, names))
    return found


def _policy_allows_public_s3(policy: dict[str, Any]) -> bool:
    statements = policy.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for statement in statements:
        principal = statement.get("Principal")
        action = statement.get("Action", [])
        effect = statement.get("Effect")
        if isinstance(action, str):
            action = [action]
        public_principal = principal == "*" or principal == {"AWS": "*"}
        risky_action = any(item in {"s3:*", "s3:GetObject", "s3:ListBucket"} for item in action)
        if effect == "Allow" and public_principal and risky_action:
            return True
    return False
