from cits_validator.core.models import Severity
from cits_validator.rules.r02_anti_fake import AntiHallucinationRule


def test_detect_sine_wave_coordinates_in_python_ast():
    bad_python_code = """
def generate_trajectory(t):
    import math
    lat = 52.52 + math.sin(t) * 0.22
    lon = 13.40 + math.cos(t) * 0.22
    return lat, lon
"""
    rule = AntiHallucinationRule()
    violations = rule.audit_code(bad_python_code, language="python")

    assert len(violations) > 0
    assert any(v.rule_id == "R02" and v.severity == Severity.ERROR for v in violations)
    assert any("synthetic GNSS" in v.message or "trigonometric" in v.message for v in violations)


def test_detect_modulo_signal_group_assignment():
    bad_python_code = """
def assign_signal_groups(lanes):
    result = {}
    for lane_id in lanes:
        result[lane_id] = (lane_id % 4) + 1
    return result
"""
    rule = AntiHallucinationRule()
    violations = rule.audit_code(bad_python_code, language="python")

    assert len(violations) > 0
    assert any("modulo signal group" in v.message.lower() for v in violations)
    assert any("connectsTo[].signalGroup" in v.remediation_hint for v in violations)


def test_detect_static_90s_cycle_loop():
    bad_js_code = """
const DEFAULT_CYCLE = 90; // Static 90-second cycle loop fallback
function getSignalPhase(timestamp) {
    const elapsed = timestamp % 90;
    return elapsed < 30 ? "GREEN" : "RED";
}
"""
    rule = AntiHallucinationRule()
    violations = rule.audit_code(bad_js_code, language="javascript")

    assert len(violations) > 0
    assert any("90-second" in v.message or "static cycle" in v.message.lower() for v in violations)


def test_clean_code_passes():
    clean_python_code = """
def extract_signal_group(connects_to):
    if not connects_to or "signalGroup" not in connects_to:
        return None
    return connects_to["signalGroup"]
"""
    rule = AntiHallucinationRule()
    violations = rule.audit_code(clean_python_code, language="python")

    assert len(violations) == 0
