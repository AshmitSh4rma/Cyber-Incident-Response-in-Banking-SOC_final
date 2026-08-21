import pytest
from response_layer.models import Severity, Playbook, Action

from ._helpers import make_incident
from response_layer.workflow import SeverityWorkflowEngine, PlaybookMatcher
from response_layer.orchestrator import ActionOrchestrator
from response_layer.hitl import HITLInterface, DecisionAction, ApprovalResult
from response_layer.ticketing import SmartTicketingEngine
from response_layer.playbook_evolution import PlaybookRepository
from response_layer.interfaces import PostgreSQLClient, RedisClient, JiraClient, ElasticsearchClient

class MockHITL(HITLInterface):
    async def request_approval(self, execution_id, playbook, incident):
        return ApprovalResult(decision=DecisionAction.APPROVE, feedback_notes="Looks good")

@pytest.mark.asyncio
async def test_workflow_medium_severity():
    db = PostgreSQLClient()
    repo = PlaybookRepository(db)
    
    # Mocking PB
    pb = Playbook(
        id="PB-T", name="Test", trigger_conditions={"mitre_tactics": ["TA0001"]}, actions=[],
        max_execution_time=300, requires_approval=True
    )
    pb.confidence_score = 0.9
    await repo.save(pb)
    
    matcher = PlaybookMatcher(repo)
    orchestrator = ActionOrchestrator()
    hitl = MockHITL(RedisClient(), db)
    ticketing = SmartTicketingEngine(JiraClient(), ElasticsearchClient())
    
    engine = SeverityWorkflowEngine(matcher, orchestrator, hitl, ticketing)
    
    incident = make_incident(
        Severity.MEDIUM,
        id="INC-MED",
        summary="Test Medium",
        confidence=0.8,
        source_ip="2.2.2.2",
        affected_user="user",
        asset_id="asset",
        mitre_tactics=[{"id": "TA0001", "name": "Initial Access"}],
        anomaly_score=0.7,
        asset_criticality="Medium",
    )
    
    # Should flow through hitl Mock and execute playbook
    await engine.process_incident(incident)
    # The process implicitly completes without errors
