import json
import subprocess

import pytest

from core.gate import runner
from core.services.iac_scan import checkov_runner, normalizer, scanner, trivy_runner

TRIVY_CONFIG = {
    "Results": [
        {
            "Target": "infra/docker/Dockerfile.api",
            "Class": "config",
            "Type": "dockerfile",
            "Misconfigurations": [
                {
                    "ID": "DS002",
                    "AVDID": "AVD-DS-0002",
                    "Title": "Image user should not be 'root'",
                    "Resolution": "Add 'USER <non root user name>' line to the Dockerfile",
                    "Severity": "HIGH",
                    "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
                    "Status": "FAIL",
                    "CauseMetadata": {"Resource": "", "StartLine": 1, "EndLine": 1},
                },
                {"ID": "DS026", "AVDID": "AVD-DS-0026", "Title": "No HEALTHCHECK", "Severity": "LOW", "Status": "PASS"},
            ],
        },
        {
            "Target": "infra/terraform/main.tf",
            "Class": "config",
            "Type": "terraform",
            "Misconfigurations": [
                {
                    "ID": "AVD-AWS-0107",
                    "Title": "Security group allows ingress from public internet",
                    "Severity": "CRITICAL",
                    "CauseMetadata": {"Resource": "aws_security_group.api", "StartLine": 12},
                },
                {"ID": "X1", "Title": "Odd one", "Severity": "UNKNOWN", "Status": "FAIL"},
            ],
        },
    ]
}

TRIVY_IMAGE = {
    "ArtifactName": "python:3.12-slim",
    "Results": [
        {
            "Target": "python:3.12-slim (debian 12.5)",
            "Class": "os-pkgs",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2024-0001", "PkgName": "libc6", "InstalledVersion": "2.36-9",
                 "FixedVersion": "2.36-9+deb12u4", "Severity": "CRITICAL"},
                {"VulnerabilityID": "CVE-2024-0002", "PkgName": "zlib1g", "InstalledVersion": "1.2.13",
                 "FixedVersion": "", "Severity": "MEDIUM", "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2024-0002"},
            ],
        }
    ],
}

CHECKOV_TERRAFORM = {
    "check_type": "terraform",
    "results": {
        "passed_checks": [{"check_id": "CKV_AWS_1"}],
        "failed_checks": [
            {
                "check_id": "CKV_AWS_24",
                "check_name": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
                "file_path": "/infra/terraform/main.tf",
                "file_line_range": [10, 25],
                "resource": "aws_security_group.api",
                "severity": "HIGH",
                "guideline": "https://docs.prismacloud.io/policy/ckv_aws_24",
            },
            {
                "check_id": "CKV_AWS_8",
                "check_name": "Ensure EBS volumes are encrypted",
                "file_path": "/infra/terraform/modules/compute/main.tf",
                "file_line_range": [3, 9],
                "resource": "aws_instance.api",
                "severity": None,
                "guideline": None,
            },
        ],
    },
}
CHECKOV_K8S = {
    "check_type": "kubernetes",
    "results": {
        "failed_checks": [
            {"check_id": "CKV_K8S_20", "check_name": "Containers should not run with allowPrivilegeEscalation",
             "file_path": "/infra/k8s/deployments/api-deployment.yaml", "file_line_range": [1, 40],
             "resource": "Deployment.default.api", "severity": "MEDIUM"},
        ]
    },
}

GATE_KEYS = {"scanner", "type", "id", "title", "severity", "file_path", "line",
             "package", "version", "fixed_version"}


def _proc(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


@pytest.fixture()
def binaries_present(monkeypatch):
    monkeypatch.setattr(trivy_runner.shutil, "which", lambda name: f"/usr/local/bin/{name}")


# ---- normalizer -----------------------------------------------------------

def test_trivy_config_normalized():
    out = normalizer.from_trivy_config(TRIVY_CONFIG)
    assert len(out) == 3  # PASS result skipped
    assert all(GATE_KEYS <= f.keys() and f["scanner"] == "iac" for f in out)
    docker = out[0]
    assert docker["id"] == "AVD-DS-0002"
    assert docker["severity"] == "high"
    assert docker["file_path"] == "infra/docker/Dockerfile.api"
    assert docker["line"] == 1
    assert "USER" in docker["guidance"]
    tf = out[1]
    assert tf["severity"] == "critical"
    assert tf["resource"] == "aws_security_group.api"
    assert out[2]["severity"] == "info"  # UNKNOWN


def test_trivy_image_normalized():
    out = normalizer.from_trivy_image(TRIVY_IMAGE, "python:3.12-slim")
    assert [f["severity"] for f in out] == ["critical", "medium"]
    libc = out[0]
    assert libc["type"] == "container_vuln"
    assert (libc["package"], libc["version"], libc["fixed_version"]) == ("libc6", "2.36-9", "2.36-9+deb12u4")
    assert libc["resource"] == "python:3.12-slim"
    assert "Upgrade libc6" in libc["guidance"]
    assert out[1]["fixed_version"] is None
    assert out[1]["guidance"].startswith("https://")


def test_checkov_single_and_multi_framework():
    single = normalizer.from_checkov(CHECKOV_TERRAFORM)
    assert len(single) == 2
    sg = single[0]
    assert sg["id"] == "CKV_AWS_24"
    assert sg["severity"] == "high"
    assert sg["file_path"] == "infra/terraform/main.tf"  # leading slash stripped
    assert sg["line"] == 10
    assert sg["resource"] == "aws_security_group.api"
    # OSS checkov has no severity -> default, plus a fallback guidance string
    assert single[1]["severity"] == normalizer.CHECKOV_DEFAULT_SEVERITY
    assert "CKV_AWS_8" in single[1]["guidance"]

    multi = normalizer.from_checkov([CHECKOV_TERRAFORM, CHECKOV_K8S])
    assert {f["id"] for f in multi} == {"CKV_AWS_24", "CKV_AWS_8", "CKV_K8S_20"}


def test_checkov_empty_or_summary_only():
    assert normalizer.from_checkov([]) == []
    assert normalizer.from_checkov({"passed": 0, "failed": 0}) == []
    assert normalizer.from_checkov(None) == []


# ---- runners (subprocess mocked) -----------------------------------------

def test_trivy_config_runner_parses_output(monkeypatch, binaries_present):
    calls = []

    def fake_run(argv, **kw):
        calls.append(argv)
        return _proc(json.dumps(TRIVY_CONFIG))

    monkeypatch.setattr(trivy_runner.subprocess, "run", fake_run)
    out = trivy_runner.run_config_scan("infra")
    assert len(out) == 3
    assert calls[0][1:5] == ["config", "--quiet", "--format", "json"]
    assert calls[0][-1] == "infra"


def test_trivy_image_runner_parses_output(monkeypatch, binaries_present):
    monkeypatch.setattr(trivy_runner.subprocess, "run", lambda argv, **kw: _proc(json.dumps(TRIVY_IMAGE)))
    assert len(trivy_runner.run_image_scan("python:3.12-slim")) == 2


def test_checkov_runner_accepts_exit_1(monkeypatch, binaries_present):
    # checkov exits 1 when checks fail — that is a result, not an error
    monkeypatch.setattr(checkov_runner.subprocess, "run",
                        lambda argv, **kw: _proc(json.dumps(CHECKOV_TERRAFORM), returncode=1))
    assert len(checkov_runner.run("infra")) == 2


def test_missing_binaries_return_empty(monkeypatch):
    monkeypatch.setattr(trivy_runner.shutil, "which", lambda name: None)

    def must_not_run(*a, **kw):
        raise AssertionError("subprocess should not be called without a binary")

    monkeypatch.setattr(trivy_runner.subprocess, "run", must_not_run)
    assert trivy_runner.run_config_scan(".") == []
    assert trivy_runner.run_image_scan("alpine:3.20") == []
    assert checkov_runner.run(".") == []
    assert scanner.scan(".") == []


@pytest.mark.parametrize(
    "behaviour",
    [
        lambda argv, **kw: _proc("", returncode=2, stderr="fatal error"),
        lambda argv, **kw: _proc("not json"),
        lambda argv, **kw: (_ for _ in ()).throw(FileNotFoundError("trivy")),
        lambda argv, **kw: (_ for _ in ()).throw(subprocess.TimeoutExpired(argv, 1)),
    ],
    ids=["nonzero-exit", "bad-json", "oserror", "timeout"],
)
def test_runner_errors_return_empty(monkeypatch, binaries_present, behaviour):
    monkeypatch.setattr(trivy_runner.subprocess, "run", behaviour)
    assert trivy_runner.run_config_scan(".") == []
    assert checkov_runner.run(".") == []


def test_suspicious_image_ref_rejected(monkeypatch, binaries_present):
    monkeypatch.setattr(trivy_runner.subprocess, "run", lambda *a, **kw: pytest.fail("should not run"))
    assert trivy_runner.run_image_scan("--config=/etc/passwd") == []


# ---- scanner + gate wiring ------------------------------------------------

def test_scan_merges_and_dedupes(monkeypatch):
    dup = normalizer.from_checkov(CHECKOV_TERRAFORM)
    monkeypatch.setattr(trivy_runner, "run_config_scan", lambda p: normalizer.from_trivy_config(TRIVY_CONFIG))
    monkeypatch.setattr(checkov_runner, "run", lambda p: dup + dup)
    out = scanner.scan(".")
    assert len(out) == 3 + 2


def test_iac_registered_with_gate():
    assert "iac" in runner.SCANNERS
