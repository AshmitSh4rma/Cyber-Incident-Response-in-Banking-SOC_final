import asyncio
import datetime
from response_layer.models import Incident, Severity, Playbook, Action, CVSSData, CVSSVector
from response_layer.interfaces import PostgreSQLClient, RedisClient, JiraClient, ElasticsearchClient, OllamaClient
from response_layer.playbook_evolution import PlaybookRepository, PlaybookEvolutionEngine
from response_layer.orchestrator import ActionOrchestrator
from response_layer.hitl import HITLInterface, ApprovalResult, DecisionAction
from response_layer.ticketing import SmartTicketingEngine
from response_layer.workflow import SeverityWorkflowEngine, PlaybookMatcher

async def main():
    print("--- Starting AI-Assisted Cyber Incident Response Run ---")
    
    # Init Interfaces
    db = PostgreSQLClient()
    redis = RedisClient()
    jira = JiraClient()
    es = ElasticsearchClient()
    ollama = OllamaClient()
    
    # Init Core Components
    repo = PlaybookRepository(db)
    pb_engine = PlaybookEvolutionEngine(ollama, es, repo)
    orchestrator = ActionOrchestrator()
    hitl = HITLInterface(redis, db)
    
    # Mock HITL approval for execution to bypass waiting
    hitl._mock_decision = ApprovalResult(decision=DecisionAction.APPROVE, feedback_notes="Auto approved via example")
    
    ticketing = SmartTicketingEngine(jira, es)
    matcher = PlaybookMatcher(repo)
    workflow = SeverityWorkflowEngine(matcher, orchestrator, hitl, ticketing)
    
    # 1. Create Mock Playbook
    playbook = Playbook(
        id="PB-001",
        name="Suspicious-Login-Isolation-v3",
        trigger_conditions={
            "mitre_tactics": ["TA0001"],
            "severity_threshold": "high",
            "confidence_min": 0.85
        },
        actions=[
            Action(
                step=1,
                action_type="iam_disable",
                target="{{affected_user}}",
                timeout=30,
                rollback_action="iam_enable",
                critical=True
            ),
            Action(
                step=2,
                action_type="edr_isolate",
                target="{{asset_id}}",
                timeout=45,
                rollback_action="edr_restore",
                critical=False
            )
        ],
        max_execution_time=600,
        requires_approval=False,
        confidence_score=0.87,
        status="proven",
        version=3
    )
    await repo.save(playbook)
    
    # 2. Simulate High Severity Incident triggering execution
    high_incident = Incident(
        id="INC-2024-001",
        summary="Suspicious login from Tor exit node",
        cvss=CVSSData(
            vector=CVSSVector(AV="N", AC="L", PR="N", UI="N", C="H", I="H", A="H", S="U"),
            vector_string="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            base_score=9.8,
            severity=Severity.CRITICAL
        ),
        confidence=0.89,
        timestamp=datetime.datetime.now(datetime.timezone.utc),
        source_ip="185.220.101.50",
        affected_user="john.doe@bank.com",
        asset_id="laptop-exec-42",
        mitre_tactics=[{"id": "TA0001", "name": "Initial Access"}],
        anomaly_score=0.92,
        similar_incidents=[],
        asset_criticality="HIGH"
    )
    print("\n[+] Processing HIGH severity incident")
    await workflow.process_incident(high_incident)
    
    # 3. Simulate Medium Severity Incident triggering HITL
    med_incident = Incident(
        id="INC-2024-002",
        summary="Unusual PowerShell activity",
        cvss=CVSSData(
            vector=CVSSVector(AV="N", AC="L", PR="N", UI="R", C="H", I="N", A="N", S="U"),
            vector_string="AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
            base_score=6.5,
            severity=Severity.MEDIUM
        ),
        confidence=0.75,
        source_ip="10.0.0.5",
        affected_user="alice.smith@bank.com",
        asset_id="desktop-hr-12",
        mitre_tactics=[{"id": "TA0001", "name": "Initial Access"}],
        anomaly_score=0.6,
        asset_criticality="MEDIUM"
    )
    print("\n[+] Processing MEDIUM severity incident (requires approval)")
    await workflow.process_incident(med_incident)

    print("\n--- Execution Finished ---")

if __name__ == "__main__":
    asyncio.run(main())
