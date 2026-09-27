from cits_validator.core.models import Severity
from cits_validator.rules.r04_priority import PrioritySessionRule


def test_priority_4tuple_matching():
    rule = PrioritySessionRule(timeout_seconds=5.0)
    state = {}

    # SREM at t=10.0s
    srem_event = {
        "type": "SREM",
        "timestamp": 10.0,
        "intersectionId": 101,
        "requestId": 7,
        "sequenceNumber": 1,
        "requestorStationId": 99999,
        "role": "transit",
    }
    v_srem = rule.audit_event(srem_event, state)
    assert len(v_srem) == 0

    # SSEM at t=10.8s with matching 4-tuple
    ssem_event = {
        "type": "SSEM",
        "timestamp": 10.8,
        "intersectionId": 101,
        "requestId": 7,
        "sequenceNumber": 1,
        "requestorStationId": 99999,
        "status": "granted",
    }
    v_ssem = rule.audit_event(ssem_event, state)
    assert len(v_ssem) == 0


def test_detect_unclosed_srem_session_timeout():
    rule = PrioritySessionRule(timeout_seconds=5.0)
    state = {}

    # SREM at t=10.0s
    rule.audit_event(
        {
            "type": "SREM",
            "timestamp": 10.0,
            "intersectionId": 101,
            "requestId": 12,
            "sequenceNumber": 3,
            "requestorStationId": 8888,
        },
        state,
    )

    # Next event at t=16.5s (> 5.0s later) without SSEM
    v_timeout = rule.check_timeouts(current_timestamp=16.5, state=state)
    assert len(v_timeout) > 0
    assert any(v.rule_id == "R04" and v.severity == Severity.WARNING for v in v_timeout)
    assert any("timeout" in v.message.lower() for v in v_timeout)
