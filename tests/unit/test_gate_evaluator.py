from pathlib import Path

import pytest

from core.gate import runner
from core.gate.evaluator import evaluate
from core.gate.policy import GatePolicy


def _finding(severity: str, title: str = "x") -> dict:
    return {"scanner": "security_debt", "type": "owasp", "title": title, "severity": severity,
            "file_path": "app.py", "line": 1}


# ---- evaluator ------------------------------------------------------------

def test_empty_findings_pass():
    d = evaluate([], GatePolicy())
    assert d.passed is True
    assert d.blocking == []
    assert d.decision == "passed"
    assert all(n == 0 for n in d.summary.values())


def test_high_does_not_block_on_critical_threshold():
    d = evaluate([_finding("high"), _finding("medium")], GatePolicy(fail_on="critical"))
    assert d.passed is True
    assert d.summary["high"] == 1


def test_critical_blocks_on_critical_threshold():
    findings = [_finding("critical"), _finding("high")]
    d = evaluate(findings, GatePolicy(fail_on="critical"))
    assert d.passed is False
    assert d.decision == "blocked"
    assert [f["severity"] for f in d.blocking] == ["critical"]
    assert "merge blocked" in d.short_description()


def test_high_blocks_on_high_threshold():
    findings = [_finding("critical"), _finding("high"), _finding("medium")]
    d = evaluate(findings, GatePolicy(fail_on="high"))
    assert d.passed is False
    assert sorted(f["severity"] for f in d.blocking) == ["critical", "high"]


def test_severity_aliases_are_normalised():
    d = evaluate([_finding("MODERATE")], GatePolicy(fail_on="medium"))
    assert d.passed is False
    assert d.summary["medium"] == 1


def test_scan_error_fail_closed_blocks():
    d = evaluate([], GatePolicy(fail_open=False), errors=["scanner 'supply_chain' failed: boom"])
    assert d.passed is False
    assert d.decision == "error"
    assert any("fail-closed" in r for r in d.reasons)


def test_scan_error_fail_open_passes_with_warning():
    d = evaluate([], GatePolicy(fail_open=True), errors=["scanner 'supply_chain' failed: boom"])
    assert d.passed is True
    assert d.decision == "error"
    assert any(r.startswith("warning:") for r in d.reasons)


def test_fail_open_still_blocks_on_findings():
    d = evaluate([_finding("critical")], GatePolicy(fail_open=True), errors=["scanner failed"])
    assert d.passed is False
    assert d.decision == "blocked"


def test_invalid_threshold_rejected():
    with pytest.raises(ValueError):
        GatePolicy(fail_on="severe")


# ---- runner (scanners mocked, no network) ---------------------------------

_MOCKED = ["supply_chain", "security_debt"]


def test_run_gate_aggregates_mocked_scanners(tmp_path: Path, monkeypatch):
    monkeypatch.setitem(runner.SCANNERS, "supply_chain", lambda p: [_finding("critical", "dep")])
    monkeypatch.setitem(runner.SCANNERS, "security_debt", lambda p: [_finding("low", "todo")])
    result = runner.run_gate(tmp_path, GatePolicy(scanners=_MOCKED))
    assert result.passed is False
    assert len(result.findings) == 2
    assert result.scanners_run == ["supply_chain", "security_debt"]


@pytest.mark.parametrize("fail_open,expected", [(False, False), (True, True)])
def test_run_gate_scanner_exception_honours_fail_open(tmp_path: Path, monkeypatch, fail_open, expected):
    def boom(_path):
        raise RuntimeError("OSV unreachable")

    monkeypatch.setitem(runner.SCANNERS, "supply_chain", boom)
    monkeypatch.setitem(runner.SCANNERS, "security_debt", lambda p: [])
    result = runner.run_gate(tmp_path, GatePolicy(scanners=_MOCKED, fail_open=fail_open))
    assert result.passed is expected
    assert result.errors and "OSV unreachable" in result.errors[0]
    assert result.scanners_run == ["security_debt"]
