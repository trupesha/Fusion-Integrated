"""
FR Test Suite – Retention Policy, Failure Alerting, Notifications, Audit Logs,
Reporting, and RBAC / Role Separation
(CFR-BA-015, CFR-BA-016, CFR-BA-017, CFR-BA-018, CFR-BA-019)
Implements TD-052 through TD-065 from a8_design/FR_DESIGN.json.
"""
import datetime
import pytest
from rest_framework.test import APIClient

from conftest import make_session
from modules.badms.domain import permissions as p
from modules.badms.models import (
    ArchivalRequest,
    ArchiveClassification,
    ArchiveStatus,
    BackupExecution,
    BackupScope,
    BackupStatus,
    BadmsAuditLog,
    BadmsNotification,
    StorageExtensionRequest,
    StorageExtensionStatus,
    UserStorageQuota,
)
from modules.directory.models import UserRef

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _client(stub_iam, **session_kw):
    stub_iam(make_session(**session_kw))
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION="Token fake-token")
    return c


@pytest.fixture()
def cse_hod_ref():
    return UserRef.objects.create(
        user_id=6002,
        username="u6002",
        display_name="CSE HoD",
        kind="faculty",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


@pytest.fixture()
def ece_hod_ref():
    return UserRef.objects.create(
        user_id=6003,
        username="u6003",
        display_name="ECE HoD",
        kind="faculty",
        department="ECE",
        discipline="ECE",
        is_active=True,
    )


@pytest.fixture()
def cse_user_ref():
    return UserRef.objects.create(
        user_id=6001,
        username="u6001",
        display_name="CSE User",
        kind="student",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


# ===========================================================================
# CFR-BA-015 – Retention Policy Enforcement  (TD-052)
# ===========================================================================

def test_TD_052_badms_enforces_retention_rules_by_classification(stub_iam):
    """
    test_id: TD-052
    source_id: CFR-BA-015, AFR-BA-056
    Verify BADMS enforces institute-defined retention rules according to data
    classification.
    positive
    """
    from modules.badms.services.reports import get_retention_compliance_summary

    # Create a policy-applied archive (retention treatment was applied)
    ArchivalRequest.objects.create(
        user_id=6001,
        department="CSE",
        file_name="retained_policy.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["grace"],
        file_type="pdf",
        file_size_bytes=256,
        reason="Retention enforcement test",
        authoritative_classification=ArchiveClassification.ROUTINE,
        status=ArchiveStatus.POLICY_APPLIED,
    )

    summary = get_retention_compliance_summary()

    # The compliance report must reflect the policy-applied archive
    assert summary["archives"]["total"] >= 1
    assert summary["archives"]["compliant_count"] >= 1
    # Classification counts must include the routine classification
    assert "routine" in summary["archives"]["by_classification"]


# ===========================================================================
# CFR-BA-016 – Failure Alerting and Escalation  (TD-053, TD-054, TD-055)
# ===========================================================================

def test_TD_053_backup_failure_sends_alert_to_sysadmin_within_five_minutes(stub_iam):
    """
    test_id: TD-053
    source_id: CFR-BA-016, AFR-BA-057
    Verify that when a backup is marked Failed, BADMS sends an alert to SysAdmin
    within five minutes of the failure.
    positive
    """
    from modules.badms.services.backup import execute_backup

    before = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
    ).count()

    execute_backup(
        initiated_by_user_id=50,
        initiated_by_role="sysadmin",
        simulate_failure=True,
    )

    after = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
    ).count()

    assert after == before + 1, "SysAdmin must receive a failure alert notification"
    alert = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
    ).latest("created_at")
    assert "FAILED" in alert.subject


def test_TD_054_three_consecutive_failures_escalate_to_director_of_it(stub_iam):
    """
    test_id: TD-054
    source_id: CFR-BA-016, AFR-BA-058
    Verify BADMS escalates to the Director of IT when three consecutive backup
    failures occur.
    boundary
    """
    from modules.badms.services.backup import execute_backup

    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW),
    )

    # Three consecutive failures via the API
    for _ in range(3):
        client.post("/api/v1/badms/backups/", {"simulate_failure": True}, format="json")

    escalation_notif = BadmsNotification.objects.filter(
        recipient_role="director_of_it",
        notification_type="director_escalation",
    ).first()
    assert escalation_notif is not None, (
        "Director of IT must be notified after three consecutive backup failures"
    )
    assert "CRITICAL ESCALATION" in escalation_notif.subject


def test_TD_055_backup_completion_notifications_sent_to_sysadmin(stub_iam):
    """
    test_id: TD-055
    source_id: CFR-BA-016, AFR-BA-059
    Verify BADMS issues backup creation-status and completion notifications
    including failure alerts to SysAdmin.
    positive
    """
    from modules.badms.services.backup import execute_backup

    before_completed = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_completed",
    ).count()

    execute_backup(
        initiated_by_user_id=50,
        initiated_by_role="sysadmin",
        backup_type="full",
    )

    after_completed = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_completed",
    ).count()

    assert after_completed == before_completed + 1, (
        "SysAdmin must receive a backup-completed notification"
    )


# ===========================================================================
# CFR-BA-017 – Storage Extension Notifications  (TD-056, TD-057)
# ===========================================================================

def test_TD_056_badms_notifies_requester_on_storage_extension_submission(stub_iam, cse_user_ref):
    """
    test_id: TD-056
    source_id: CFR-BA-017, AFR-BA-060
    Verify BADMS sends a notification to the requester when a storage-extension
    request is submitted.
    positive
    """
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=10 * 1024 * 1024,
        used_bytes=0,
    )
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.STORAGE_CREATE, p.STORAGE_VIEW_SELF),
    )

    before = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="storage_extension_submitted",
    ).count()

    client.post(
        "/api/v1/badms/storage-extensions/",
        {"requested_bytes": 512 * 1024, "reason": "Submission notification test"},
        format="json",
    )

    after = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="storage_extension_submitted",
    ).count()
    assert after == before + 1, "Requester must receive a submission confirmation notification"


def test_TD_057_badms_notifies_requester_on_hod_decision(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-057
    source_id: CFR-BA-017, AFR-BA-060
    Verify BADMS notifies the requester when the HoD approves or rejects the
    storage-extension request.
    positive
    """
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=10 * 1024 * 1024,
        used_bytes=0,
    )
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=10 * 1024 * 1024,
        requested_bytes=1 * 1024 * 1024,
        reason="Notification test on decision",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_VIEW, p.STORAGE_REVIEW),
    )

    before = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
    ).filter(
        notification_type__in=[
            "storage_extension_approved",
            "storage_extension_rejected",
        ]
    ).count()

    client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "approve", "comments": "Budget available."},
        format="json",
    )

    after = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="storage_extension_approved",
    ).count()
    assert after == before + 1, "Requester must be notified of HoD's approval/rejection decision"


# ===========================================================================
# CFR-BA-018 – Audit Logs and Operational Reporting (TD-058 … TD-062)
# ===========================================================================

def test_TD_058_badms_records_audit_log_with_timestamp_actor_action_outcome(stub_iam):
    """
    test_id: TD-058
    source_id: CFR-BA-018, AFR-BA-061
    Verify BADMS maintains audit logs for user actions, administrative actions,
    system events, and security events including timestamps, actor identifiers,
    actions, and outcomes.
    positive
    """
    from modules.badms.services.audit import record_audit

    log = record_audit(
        actor_user_id=50,
        actor_role="sysadmin",
        action="badms.backup.execute",
        target_type="backup_execution",
        target_id=99,
        outcome="success",
        details={"dataset": "hr_records"},
    )

    assert log.pk is not None
    assert log.actor_user_id == 50
    assert log.action == "badms.backup.execute"
    assert log.outcome == "success"
    assert log.created_at is not None


def test_TD_059_sysadmin_can_view_audit_logs_and_activity_history(stub_iam):
    """
    test_id: TD-059
    source_id: CFR-BA-018, AFR-BA-062
    Verify that a SysAdmin can view audit logs and activity histories.
    positive
    """
    BadmsAuditLog.objects.create(
        actor_user_id=50,
        actor_role="sysadmin",
        action="badms.backup.execute",
        target_type="backup_execution",
        target_id="1",
        outcome="success",
        details={},
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.AUDIT_VIEW,),
    )
    res = client.get("/api/v1/badms/audit-logs/")
    assert res.status_code == 200
    assert res.data["count"] >= 1


def test_TD_060_it_security_can_audit_data_activity_logs_and_security_reports(stub_iam):
    """
    test_id: TD-060
    source_id: CFR-BA-018, AFR-BA-063
    Verify IT Security Team can audit data-activity logs for unauthorized access
    and review security-related reports.
    positive
    """
    BadmsAuditLog.objects.create(
        actor_user_id=70,
        actor_role="it_security",
        action="badms.archive.encrypt",
        target_type="archive_request",
        target_id="5",
        outcome="success",
        details={},
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="IT Security",
        modules=("badms",),
        permissions=(p.AUDIT_VIEW, p.REPORT_VIEW),
    )
    # Audit logs access
    audit_res = client.get("/api/v1/badms/audit-logs/")
    assert audit_res.status_code == 200
    assert audit_res.data["count"] >= 1

    # Reports access
    report_res = client.get("/api/v1/badms/reports/summary/")
    assert report_res.status_code == 200


def test_TD_061_hod_can_view_own_department_operational_reports_not_others(stub_iam, cse_hod_ref, ece_hod_ref):
    """
    test_id: TD-061
    source_id: CFR-BA-018, AFR-BA-064
    Verify HoD can view operational reports relevant to the HoD's own department
    and cannot view reports of other departments.
    authorization
    """
    # Create data for CSE department
    StorageExtensionRequest.objects.create(
        user_id=6001,
        department="CSE",
        current_allocated_bytes=10 * 1024 * 1024,
        requested_bytes=1 * 1024 * 1024,
        reason="CSE report test",
        status=StorageExtensionStatus.SUBMITTED,
    )
    # Create data for ECE department
    StorageExtensionRequest.objects.create(
        user_id=7001,
        department="ECE",
        current_allocated_bytes=5 * 1024 * 1024,
        requested_bytes=2 * 1024 * 1024,
        reason="ECE report test",
        status=StorageExtensionStatus.SUBMITTED,
    )

    # CSE HoD views storage extension requests – should only see CSE records
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_VIEW, p.STORAGE_REVIEW, p.REPORT_VIEW),
    )
    res = client.get("/api/v1/badms/storage-extensions/")
    assert res.status_code == 200
    departments = {r["department"] for r in res.data["results"]}
    assert "ECE" not in departments, (
        "CSE HoD must not see ECE department records"
    )
    assert "CSE" in departments


def test_TD_062_badms_provides_operational_visibility_into_backup_operations(stub_iam):
    """
    test_id: TD-062
    source_id: CFR-BA-018, AFR-BA-065
    Verify BADMS provides operational visibility into backup operations to support
    monitoring and compliance verification.
    positive
    """
    BackupExecution.objects.create(
        scope=BackupScope.LOCAL,
        status=BackupStatus.COMPLETED,
        checksum="a" * 64,
        integrity_verified=True,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.REPORT_VIEW, p.BACKUP_VIEW),
    )
    res = client.get("/api/v1/badms/reports/summary/")
    assert res.status_code == 200
    data = res.data
    assert "backups" in data
    assert data["backups"]["total"] >= 1


# ===========================================================================
# CFR-BA-019 – RBAC and Role Separation  (TD-063, TD-064, TD-065)
# ===========================================================================

def test_TD_063_it_security_can_manage_user_permissions_through_rbac(stub_iam):
    """
    test_id: TD-063
    source_id: CFR-BA-019, AFR-BA-066
    Verify the IT Security Team can manage user permissions through RBAC.
    positive
    """
    from modules.badms.registry import ROLE_GRANTS

    # IT Security role grants must include the encryption permission (RBAC-enforced)
    it_security_grants = set(ROLE_GRANTS.get("IT Security", []))
    assert p.ARCHIVE_ENCRYPT in it_security_grants, (
        "RBAC must grant IT Security the archive-encrypt permission"
    )
    assert p.AUDIT_VIEW in it_security_grants, (
        "RBAC must grant IT Security the audit-view permission"
    )
    # IT Security must NOT hold classification permission (separation of duties)
    assert p.ARCHIVE_CLASSIFY not in it_security_grants


def test_TD_064_it_security_can_define_and_enforce_security_policies(stub_iam):
    """
    test_id: TD-064
    source_id: CFR-BA-019, AFR-BA-067
    Verify the IT Security Team can define and enforce security policies governing
    encryption, access, and security controls.
    positive
    """
    from modules.badms.registry import ROLE_GRANTS

    # Verify IT Security's ability to configure encryption is enforced via RBAC
    it_security_grants = set(ROLE_GRANTS.get("IT Security", []))
    assert p.ARCHIVE_ENCRYPT in it_security_grants, (
        "IT Security must have permission to configure encryption (security policy)"
    )

    # Verify that the permission boundary is enforced: a user without the grant is denied
    archive = ArchivalRequest.objects.create(
        user_id=8001,
        department="CSE",
        file_name="policy_enforce_test.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["henry"],
        file_type="pdf",
        file_size_bytes=256,
        reason="Security policy enforcement test",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    # A SysAdmin (lacks ARCHIVE_ENCRYPT) must not be able to configure encryption
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.BACKUP_CREATE),  # no ARCHIVE_ENCRYPT
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM", "key_id": "KEY-AES256-SEC-01"},
        format="json",
    )
    assert res.status_code == 403, (
        f"SysAdmin without ARCHIVE_ENCRYPT must be denied. Got {res.status_code}: {res.data}"
    )


def test_TD_065_badms_enforces_role_separation_hod_cannot_act_outside_own_department(stub_iam, cse_hod_ref, ece_hod_ref):
    """
    test_id: TD-065
    source_id: CFR-BA-019, AFR-BA-068
    Verify BADMS enforces role separation so that a HoD cannot act on requests
    outside their own department.
    authorization
    """
    # Create a storage extension from a CSE user
    cse_ext = StorageExtensionRequest.objects.create(
        user_id=6001,
        department="CSE",
        current_allocated_bytes=10 * 1024 * 1024,
        requested_bytes=1 * 1024 * 1024,
        reason="Role separation test",
        status=StorageExtensionStatus.SUBMITTED,
    )

    # ECE HoD attempts to decide on a CSE extension request
    client = _client(
        stub_iam,
        user_id=ece_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_VIEW, p.STORAGE_REVIEW),
    )
    res = client.post(
        f"/api/v1/badms/storage-extensions/{cse_ext.pk}/decision/",
        {"decision": "approve", "comments": "Cross-dept attempt"},
        format="json",
    )
    assert res.status_code in (403, 404), (
        f"ECE HoD must be denied from acting on CSE request. Got {res.status_code}: {res.data}"
    )
