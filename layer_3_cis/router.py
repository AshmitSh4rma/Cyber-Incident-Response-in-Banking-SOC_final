from layer_3_cis.engines.iot_engine import process_iot_event
from layer_3_cis.engines.network_engine import process_network_event
from layer_3_cis.engines.web_engine import process_web_event


def route_entry(event: dict) -> dict:
    """
    Send an event to the control-mapping engine for its domain.

    Auth events split on threat type: a suspicious sign-in is an application
    security concern (session handling, MFA, account lockout), so it goes to the
    web/OWASP engine; anything else authentication-related is about how the
    network authenticates access, which is the network engine's catalogue.
    """
    log_type = str(event.get("log_type", "") or "").lower()
    threat_type = str((event.get("detection") or {}).get("threat_type", "") or "").lower()

    if log_type == "web":
        return process_web_event(event)

    if log_type == "network":
        return process_network_event(event)

    if log_type == "iot":
        return process_iot_event(event)

    if log_type == "auth":
        if threat_type in {"suspicious_login_behavior", "risky_signin_detected"}:
            return process_web_event(event)
        return process_network_event(event)

    # An unrecognised log type passes through unmapped rather than being forced
    # into a catalogue that does not describe it.
    return event
