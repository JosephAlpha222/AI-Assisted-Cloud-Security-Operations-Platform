
from ingestion.event_model import SecurityEvent


def determine_severity(event: dict) -> str:
    action = event.get("action", "")
    event_name = action.lower() if isinstance(action, str) else ""

    result = event.get("result", "")
    result = result.lower() if isinstance(result, str) else ""

    high_risk_actions = {
        "createaccesskey",
        "deleteuser",
        "deleteaccesskey",
        "putrolepolicy",
        "attachuserpolicy",
        "attachrolepolicy",
        "putuserpolicy",
        "addusertogroup",
        "putbucketpolicy",
        "deletebucketpolicy",
        "putbucketacl",
        "authorizesecuritygroupingress",
        "modifysecuritygroup",
    }

    medium_risk_actions = {
        "createrole",
        "createuser",
        "updateassumerolepolicy",
        "consolelogin",
        "deletebucketpublicaccessblock",
        "createbucket",
        "putbucketversioning",
    }

    if event_name in high_risk_actions:
        return "high"

    if event_name == "consolelogin":
        if result in {"failure", "failed", "error"}:
            return "medium"
        return "low"

    if event_name in medium_risk_actions:
        return "medium"

    return "low"


def normalize_cloudtrail_event(event: dict) -> SecurityEvent:
    if not isinstance(event, dict):
        raise ValueError("Event must be a dictionary")

    for field in ("user", "source", "resource"):
        value = event.get(field, {})
        if not isinstance(value, dict):
            raise ValueError(f"{field} must be a dictionary")

    action = event.get("action", "")
    if not isinstance(action, str):
        raise ValueError("action must be a string")

    user = event.get("user", {})
    source = event.get("source", {})
    resource = event.get("resource", {})

    metadata = {
        "user_type": user.get("type"),
        "resource_type": resource.get("type"),
        "result": event.get("result"),
        "original_risk_score": event.get("risk_score", 0),
        "original_severity": event.get("severity", "low"),
        "detection": event.get("detection"),
    }

    # Preserve additional CloudTrail investigation context when available.
    for field in (
        "event_source",
        "event_category",
        "user_agent",
        "request_parameters",
        "response_elements",
        "error_code",
        "error_message",
    ):
        if field in event:
            metadata[field] = event[field]

    return SecurityEvent(
        event_id=event.get("event_id", "unknown"),
        timestamp=event.get("timestamp", ""),
        provider=event.get("cloud", "aws"),
        service=event.get("service", ""),
        event_type=event.get("event_type", "unknown"),
        action=action,
        severity=determine_severity(event),
        source_ip=source.get("ip"),
        region=event.get("region"),
        user=user.get("id"),
        resource=resource.get("id"),
        account_id=event.get("account_id"),
        metadata=metadata,
    )
