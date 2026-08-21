from enum import Enum
from typing import List, Dict, Any, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field

class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"

class CVSSVector(BaseModel):
    AV: str
    AC: str
    PR: str
    UI: str
    C: str
    I: str
    A: str
    S: str

class CVSSData(BaseModel):
    vector: CVSSVector
    vector_string: str
    base_score: float
    severity: Severity

class PlaybookStatus(str, Enum):
    CANDIDATE = "candidate"
    ACTIVE = "active"
    PROVEN = "proven"
    RETIRED = "retired"

class Action(BaseModel):
    step: int
    action_type: str
    target: str
    timeout: int
    rollback_action: str
    critical: bool

class Playbook(BaseModel):
    id: str
    name: str
    trigger_conditions: Dict[str, Any]
    actions: List[Action]
    max_execution_time: int
    requires_approval: bool
    confidence_score: float = 0.0
    status: PlaybookStatus = PlaybookStatus.CANDIDATE
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    version: int = 1

class Incident(BaseModel):
    id: str
    summary: str
    cvss: CVSSData
    confidence: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_ip: str
    affected_user: str
    asset_id: str
    mitre_tactics: List[Dict[str, str]]
    anomaly_score: float
    similar_incidents: List[Dict[str, Any]] = Field(default_factory=list)
    asset_criticality: str

class ActionResult(BaseModel):
    action: Action
    success: bool
    details: str
    execution_time: float

class ExecutionResult(BaseModel):
    playbook_id: str
    incident_id: str
    success: bool
    actions_executed: List[ActionResult] = Field(default_factory=list)
    total_execution_time: float = 0.0
    error: Optional[str] = None
    rolled_back: bool = False

class Ticket(BaseModel):
    ticket_id: str
    incident_id: str
    status: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
