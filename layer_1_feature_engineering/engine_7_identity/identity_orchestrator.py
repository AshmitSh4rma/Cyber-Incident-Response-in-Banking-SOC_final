from layer_1_feature_engineering.feature_accessors import get_int, get_str, has_field


def _contains_token(value: str | None, token: str) -> bool:
    if not value:
        return False
    return token.lower() in value.lower()


def run_identity(log: dict) -> dict:
    """
    Extract identity / cloud-auth related features from structured or normalized logs.

    Works for:
    - Azure AD style logs
    - Windows security auth logs
    - Any structured event carrying auth/risk/location fields
    """

    raw_source = get_str(log, "raw_source", "source", "log_source", default="unknown")
    event_type = get_str(log, "event_type", "Operation", "OperationName", default="unknown")
    risk_state = get_str(log, "RiskState", "risk_state")
    risk_level = get_str(log, "RiskLevel", "risk_level", "severity")
    risk_event_types = get_str(log, "RiskEventTypes", "risk_event_types")
    location = get_str(log, "Location", "location")
    client_app_used = get_str(log, "ClientAppUsed", "client_app_used")
    logon_type = get_int(log, "logon_type", "LogonType", default=None)
    auth_package = get_str(log, "auth_package", "AuthenticationPackageName")
    sub_status = get_str(log, "SubStatus", "sub_status")
    event_id = get_int(log, "EventID", "event_id", default=None)

    is_azure_identity = raw_source in {"azure_ad", "entra_id", "aad"}
    is_windows_auth = raw_source == "windows_security" or event_id in {4624, 4625, 4648, 4768, 4769, 4771, 4776}

    is_signin_activity = _contains_token(event_type, "sign-in")
    is_risky_signin = (
        is_signin_activity and (
            _contains_token(risk_state, "atrisk") or
            _contains_token(risk_level, "high") or
            bool(risk_event_types)
        )
    )

    has_unfamiliar_features = _contains_token(risk_event_types, "unfamiliarfeatures")
    has_suspicious_ip_flag = _contains_token(risk_event_types, "suspiciousipaddress")

    is_successful_login = event_id == 4624
    is_failed_login = event_id == 4625

    is_network_logon = logon_type == 3
    is_remote_interactive = logon_type == 10
    uses_ntlm = _contains_token(auth_package, "ntlm")

    identity_features = {
        "raw_source": raw_source,
        "event_type": event_type,
        "event_id": event_id,

        "is_identity_event": (
            is_azure_identity or
            is_windows_auth or
            is_signin_activity or
            has_field(log, "UserPrincipalName", "UserId", "logon_type", "RiskState", "RiskLevel")
        ),

        "is_azure_identity": is_azure_identity,
        "is_windows_auth": is_windows_auth,
        "is_signin_activity": is_signin_activity,

        "location": location,
        "client_app_used": client_app_used,

        "risk_state": risk_state,
        "risk_level": risk_level,
        "risk_event_types": risk_event_types,

        "is_risky_signin": is_risky_signin,
        "has_unfamiliar_features": has_unfamiliar_features,
        "has_suspicious_ip_flag": has_suspicious_ip_flag,

        "logon_type": logon_type,
        "is_successful_login": is_successful_login,
        "is_failed_login": is_failed_login,
        "is_network_logon": is_network_logon,
        "is_remote_interactive": is_remote_interactive,
        "uses_ntlm": uses_ntlm,
        "sub_status": sub_status,
    }

    return {**log, "identity_features": identity_features}
