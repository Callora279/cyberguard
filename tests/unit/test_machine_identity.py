from datetime import datetime, timedelta, timezone

from core.services.machine_identity import credential_rotation, identity_registry, zero_trust


def test_register_and_rotate(org_id):
    identity = identity_registry.register(
        org_id,
        identity_type="api_key",
        name="ci-deploy-key",
        owner="platform",
        scopes=["read", "write"],
        secret_material="super-secret-value",
        expires_at=datetime.now(timezone.utc) + timedelta(days=30),
    )
    assert identity["status"] == "active"
    fp_before = identity["fingerprint"]

    rotated = credential_rotation.rotate(identity["id"])
    assert rotated["old_fingerprint"] == fp_before
    assert rotated["new_fingerprint"] != fp_before
    assert rotated["new_secret"]

    refreshed = identity_registry.get(identity["id"])
    assert refreshed["fingerprint"] == rotated["new_fingerprint"]


def test_expiry_sweep_flags_past_due(org_id):
    identity_registry.register(
        org_id,
        identity_type="cert",
        name="expired-cert",
        scopes=["read"],
        expires_at=datetime.now(timezone.utc) - timedelta(days=1),
    )
    result = identity_registry.check_expiries(org_id)
    assert any(i["name"] == "expired-cert" for i in result["expired"])


def test_zero_trust_denies_privilege_escalation(org_id):
    identity = identity_registry.register(
        org_id, identity_type="oauth", name="readonly-bot", scopes=["read"]
    )
    decision = zero_trust.request_access(
        zero_trust.AccessRequest(
            identity_id=identity["id"],
            org_id=org_id,
            resource="/admin/users",
            action="admin",
        )
    )
    assert decision["decision"] == "deny"
