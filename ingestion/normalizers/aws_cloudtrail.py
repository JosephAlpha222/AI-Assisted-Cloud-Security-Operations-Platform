from ingestion.event_model import SecurityEvent


def determine_severity(event: dict) -> str:
    event_name = event.get("action", "").lower()

    high_risk_actions = {
        "createaccesskey",
        "deleteuser",
        "deleteaccesskey",
        "putrolepolicy",
        "attachuserpolicy",
        "attachrolepolicy",
        "putbucketpolicy",
    }

    medium_risk_actions = {
        "createrole",
        "createuser",
        "updateassumerolepolicy",
        "authorizesecuritygroupingress",
    }

    if event_name in high_risk_actions:
        return "high"

    if event_name in medium_risk_actions:
        return "medium"

    return "low"


def normalize_cloudtrail_event(event: dict) -> SecurityEvent:
    user = event.get("user", {})
    source = event.get("source", {})
    resource = event.get("resource", {})

    return SecurityEvent(
        event_id=event.get("event_id", "unknown"),
        timestamp=event.get("timestamp", ""),
        provider=event.get("cloud", "aws"),
        service=event.get("service", ""),
        event_type=event.get("event_type", "unknown"),
        action=event.get("action", ""),
        severity=determine_severity(event),
        source_ip=source.get("ip"),
        region=event.get("region"),
        user=user.get("id"),
        resource=resource.get("id"),
        account_id=event.get("account_id"),
        metadata={
            "user_type": user.get("type"),
            "resource_type": resource.get("type"),
            "result": event.get("result"),
            "original_risk_score": event.get("risk_score", 0),
            "original_severity": event.get("severity", "low"),
            "detection": event.get("detection"),
        },
    )
