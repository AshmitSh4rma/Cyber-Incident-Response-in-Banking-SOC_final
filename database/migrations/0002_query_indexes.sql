CREATE INDEX incidents_timestamp_idx ON incidents (timestamp DESC);
CREATE INDEX incidents_severity_idx ON incidents (severity);
CREATE INDEX incidents_status_idx ON incidents (status);

CREATE INDEX analyst_feedback_event_time_idx
    ON analyst_feedback (event_id, created_at DESC);
CREATE INDEX analyst_feedback_suppression_idx
    ON analyst_feedback (label)
    WHERE label = 'false_positive';

CREATE INDEX campaigns_progression_idx
    ON campaigns (progression_pct DESC, incident_count DESC);

CREATE INDEX response_approvals_state_idx
    ON response_approvals (state, approval_id DESC);
CREATE INDEX response_approvals_event_idx
    ON response_approvals (event_id, approval_id DESC);
