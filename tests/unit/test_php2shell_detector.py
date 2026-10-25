from core.services.livescan.detectors import php2shell


def test_vulnerable_versions_flagged():
    for ver in ("8.5.11", "8.4.26", "8.3.35", "8.2.34"):
        f = php2shell.check(ver)
        assert f is not None, ver
        assert f["severity"] == "critical"
        assert f["status"] == "vulnerable-version"
        assert f["confidence"] == "medium"


def test_patched_versions_clear():
    for ver in ("8.5.12", "8.4.27", "8.3.36", "8.2.35", "8.5.20"):
        assert php2shell.check(ver) is None, ver


def test_eol_branches_low_confidence():
    for ver in ("8.1.33", "7.4.33", "5.6.40"):
        f = php2shell.check(ver)
        assert f is not None, ver
        assert f["confidence"] == "low"


def test_unknown_or_unparseable_not_guessed():
    assert php2shell.check("8.6.0") is None   # future branch — don't guess
    assert php2shell.check(None) is None
    assert php2shell.check("not-a-version") is None
