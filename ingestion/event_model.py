from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: str
    provider: str
    service: str
    event_type: str
    action: str
    severity: str
    source_ip: Optional[str] = None
    region: Optional[str] = None
    user: Optional[str] = None
    resource: Optional[str] = None
    account_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "provider": self.provider,
            "service": self.service,
            "event_type": self.event_type,
            "action": self.action,
            "severity": self.severity,
            "source_ip": self.source_ip,
            "region": self.region,
            "user": self.user,
            "resource": self.resource,
            "account_id": self.account_id,
            "metadata": self.metadata,
        }
