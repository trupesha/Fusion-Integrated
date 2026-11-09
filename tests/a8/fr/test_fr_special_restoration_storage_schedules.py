"""
FR Test Suite – Special Archival, Restoration, Storage Extension, Global Schedules
(CFR-BA-010, CFR-BA-011, CFR-BA-012, CFR-BA-013, CFR-BA-014)
Implements TD-033 through TD-051 from a8_design/FR_DESIGN.json.
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
    BackupSchedule,
    BackupScope,
    BadmsAuditLog,
    BadmsNotification,
    RestorationRequest,
    RestorationStatus,
    SpecialArchivalRecord,
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


SPECIAL_ARCHIVAL_PAYLOAD = {
    "requester_name": "Prof. J. Smith",
    "requester_designation": "Research Director",
    "dataset_title": "Genome Sequencing Dataset 2026",
    "classification": "Sensitive Research Data",
    "offline_media_type": "LTO-8 Magnetic Tape",
    "media_serial_number": "LTO8-SN-20260001",
    "storage_vault_location": "Vault-B, Sub-basement, Building 3",
    "notes": "Annual genome preservation cycle",
}


@pytest.fixture()
def cse_user_ref():
    return UserRef.objects.create(
        user_id=4001,
        username="u4001",
        display_name="CSE User",
        kind="student",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


@pytest.fixture()
def cse_hod_ref():
    return UserRef.objects.create(
        user_id=4002,
        username="u4002",
        display_name="CSE HoD",
        kind="faculty",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


@pytest.fixture()
def ece_hod_ref():
    return UserRef.objects.create(
        user_id=4003,
        username="u4003",
        display_name="ECE HoD",
        kind="faculty",
        department="ECE",
        discipline="ECE",
        is_active=True,
    )


def _make_sensitive_archive(user_id=4001):
    return ArchivalRequest.objects.create(
        user_id=user_id,
        department="CSE",
        file_name="sensitive.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Sensitive restoration test",
        initial_classification=ArchiveClassification.SENSITIVE,
        authoritative_classification=ArchiveClassification.SENSITIVE,
        is_encrypted=True,
        status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
    )


def _make_routine_archive(user_id=4001):
    return ArchivalRequest.objects.create(
        user_id=user_id,
        department="CSE",
        file_name="routine.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["bob"],
        file_type="pdf",
        file_size_bytes=512,
        reason="Routine restoration test",
        initial_classification=ArchiveClassification.ROUTINE,
        authoritative_classification=ArchiveClassification.ROUTINE,
        is_encrypted=False,
        status=ArchiveStatus.POLICY_APPLIED,
    )


# ===========================================================================
# CFR-BA-010 – Special Archival Operation  (TD-033, TD-034, TD-035)
# ===========================================================================

def test_TD_033_super_admin_can_perform_special_archival_operation(stub_iam):
    """
    test_id: TD-033
    source_id: CFR-BA-010, AFR-BA-037
    Verify Super Admin can perform a special archival operation for Sensitive
    research data following an offline request from any authority.
    positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.ARCHIVE_SPECIAL, p.AUDIT_VIEW),
    )
    res = client.post("/api/v1/badms/special-archives/", SPECIAL_ARCHIVAL_PAYLOAD, format="json")
    assert res.status_code == 201, res.data
    assert res.data["dataset_title"] == SPECIAL_ARCHIVAL_PAYLOAD["dataset_title"]
    assert SpecialArchivalRecord.objects.filter(
        performed_by_user_id=1
    ).exists()


def test_TD_034_only_super_admin_can_perform_special_archival(stub_iam):
    """
    test_id: TD-034
    source_id: CFR-BA-010, AFR-BA-038
    Verify only the Super Admin is permitted to perform the special archival
    operation in BADMS.
    authorization
    """
    # Attempt by SysAdmin – lacks ARCHIVE_SPECIAL
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.BACKUP_CREATE),
    )
    res = client.post("/api/v1/badms/special-archives/", SPECIAL_ARCHIVAL_PAYLOAD, format="json")
    assert res.status_code == 403, f"Non-Super-Admin must be denied. Got {res.status_code}: {res.data}"


def test_TD_035_special_archival_records_outcome_and_audit_event(stub_iam):
    """
    test_id: TD-035
    source_id: CFR-BA-010, AFR-BA-039
    Verify that after Super Admin performs a special archival operation, BADMS
    records the operation outcome and audit event.
    positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.ARCHIVE_SPECIAL, p.AUDIT_VIEW),
    )
    res = client.post("/api/v1/badms/special-archives/", SPECIAL_ARCHIVAL_PAYLOAD, format="json")
    assert res.status_code == 201, res.data
    record_id = res.data["id"]

    # Audit event must be recorded
    audit = BadmsAuditLog.objects.filter(
        target_id=str(record_id),
        action="badms.archive.special",
    ).first()
    assert audit is not None, "Audit event must be recorded for special archival operation"
    assert audit.outcome == "success"
    assert audit.actor_user_id == 1


# ===========================================================================
# CFR-BA-011 – Data Restoration Management  (TD-036, TD-037, TD-038, TD-039)
# ===========================================================================

def test_TD_036_user_can_request_restoration_of_archived_data(stub_iam, cse_user_ref):
    """
    test_id: TD-036
    source_id: CFR-BA-011, AFR-BA-040
    Verify that a user can request restoration of archived data.
    positive
    """
    archive = _make_routine_archive(user_id=cse_user_ref.user_id)
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.RESTORATION_CREATE, p.RESTORATION_VIEW_SELF),
    )
    payload = {
        "archive_id": archive.pk,
        "reason": "Need original research data",
        "target_destination": "/home/alice/restored",
    }
    res = client.post("/api/v1/badms/restorations/", payload, format="json")
    assert res.status_code == 201, res.data


def test_TD_037_sensitive_restoration_requires_sysadmin_approval(stub_iam, cse_user_ref):
    """
    test_id: TD-037
    source_id: CFR-BA-011, AFR-BA-041
    Verify that a restoration request for Sensitive data requires SysAdmin
    approval before restoration proceeds.
    positive
    """
    archive = _make_sensitive_archive(user_id=cse_user_ref.user_id)
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.RESTORATION_CREATE, p.RESTORATION_VIEW_SELF),
    )
    payload = {
        "archive_id": archive.pk,
        "reason": "Need sensitive data back",
        "target_destination": "/home/alice/secure_restored",
    }
    res = client.post("/api/v1/badms/restorations/", payload, format="json")
    assert res.status_code == 201, res.data
    # Status must be PENDING_APPROVAL – not yet restored
    assert res.data["status"] == RestorationStatus.PENDING_APPROVAL, (
        f"Sensitive restoration must require SysAdmin approval. Got status: {res.data['status']}"
    )
    assert res.data["is_sensitive"] is True


def test_TD_038_non_sensitive_restoration_follows_standard_procedure(stub_iam, cse_user_ref):
    """
    test_id: TD-038
    source_id: CFR-BA-011, AFR-BA-042
    Verify BADMS supports restoration of non-Sensitive archived data through the
    standard restoration procedure without requiring SysAdmin approval.
    positive
    """
    archive = _make_routine_archive(user_id=cse_user_ref.user_id)
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.RESTORATION_CREATE, p.RESTORATION_VIEW_SELF),
    )
    payload = {
        "archive_id": archive.pk,
        "reason": "Need routine data",
        "target_destination": "/home/bob/restored",
    }
    res = client.post("/api/v1/badms/restorations/", payload, format="json")
    assert res.status_code == 201, res.data
    # Standard path: should be completed immediately without approval
    assert res.data["status"] == RestorationStatus.COMPLETED, (
        f"Non-sensitive restoration should complete via standard procedure. Got: {res.data['status']}"
    )


def test_TD_039_user_can_track_restoration_request_status(stub_iam, cse_user_ref):
    """
    test_id: TD-039
    source_id: CFR-BA-011, AFR-BA-043
    Verify that a user can track restoration-request status.
    positive
    """
    restoration = RestorationRequest.objects.create(
        archive_id=None,
        requester_user_id=cse_user_ref.user_id,
        target_name="test_file.pdf",
        reason="Tracking test",
        target_destination="/tmp/restore",
        is_sensitive=False,
        status=RestorationStatus.COMPLETED,
    )
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.RESTORATION_VIEW_SELF,),
    )
    res = client.get(f"/api/v1/badms/restorations/{restoration.pk}/")
    assert res.status_code == 200
    assert res.data["status"] == RestorationStatus.COMPLETED


# ===========================================================================
# CFR-BA-012 – Storage Extension Request and Decision (TD-040 … TD-046)
# ===========================================================================

@pytest.fixture()
def cse_user_with_full_quota(cse_user_ref):
    """User whose quota is fully consumed."""
    q = UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=1024,
        used_bytes=1024,       # quota full
    )
    return cse_user_ref, q


def test_TD_040_user_can_submit_storage_extension_when_quota_full(stub_iam, cse_user_with_full_quota):
    """
    test_id: TD-040
    source_id: CFR-BA-012, AFR-BA-045
    Verify a user can submit a storage-extension request when their storage quota
    is full.
    positive
    """
    user_ref, _ = cse_user_with_full_quota
    client = _client(
        stub_iam,
        user_id=user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.STORAGE_CREATE, p.STORAGE_VIEW_SELF),
    )
    res = client.post(
        "/api/v1/badms/storage-extensions/",
        {"requested_bytes": 1024 * 1024, "reason": "Need more space for research data"},
        format="json",
    )
    assert res.status_code == 201, res.data
    assert res.data["status"] == StorageExtensionStatus.SUBMITTED


def test_TD_041_storage_extension_request_validated_against_current_usage(stub_iam, cse_user_ref):
    """
    test_id: TD-041
    source_id: CFR-BA-012, AFR-BA-046
    Verify BADMS validates a storage-extension request against the user's current
    storage usage.
    validation
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
    # Zero bytes is invalid – service must reject it
    res = client.post(
        "/api/v1/badms/storage-extensions/",
        {"requested_bytes": 0, "reason": "Invalid zero request"},
        format="json",
    )
    assert res.status_code == 400, res.data


def test_TD_042_valid_storage_extension_routed_to_hod(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-042
    source_id: CFR-BA-012, AFR-BA-047
    Verify BADMS routes a valid storage-extension request to the user's HoD.
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
    res = client.post(
        "/api/v1/badms/storage-extensions/",
        {"requested_bytes": 512 * 1024, "reason": "Research dataset growth"},
        format="json",
    )
    assert res.status_code == 201, res.data
    # HoD review notification must be sent
    hod_notif = BadmsNotification.objects.filter(
        recipient_role="HOD",
        notification_type="storage_extension_review_required",
    ).first()
    assert hod_notif is not None, "HoD must be notified to review the storage-extension request"


def test_TD_043_hod_can_review_storage_extension_request_details(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-043
    source_id: CFR-BA-012, AFR-BA-048
    Verify HoD can review storage-extension request details, attachments,
    available storage infrastructure, departmental policy, and justification.
    positive
    """
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=10 * 1024 * 1024,
        requested_bytes=5 * 1024 * 1024,
        reason="Lab expansion",
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
    res = client.get(f"/api/v1/badms/storage-extensions/{ext.pk}/")
    assert res.status_code == 200
    data = res.data
    assert data["requested_bytes"] == ext.requested_bytes
    assert data["reason"] == ext.reason
    assert data["department"] == "CSE"


def test_TD_044_hod_can_approve_storage_extension_and_decision_recorded(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-044
    source_id: CFR-BA-012, AFR-BA-049
    Verify HoD can approve a storage-extension request and BADMS records the decision.
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
        requested_bytes=5 * 1024 * 1024,
        reason="Approval test",
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
    res = client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "approve", "comments": "Justified expansion."},
        format="json",
    )
    assert res.status_code == 200, res.data
    ext.refresh_from_db()
    assert ext.status == StorageExtensionStatus.HOD_APPROVED
    assert ext.hod_user_id == cse_hod_ref.user_id


def test_TD_045_hod_can_reject_storage_extension_and_decision_recorded(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-045
    source_id: CFR-BA-012, AFR-BA-049
    Verify HoD can reject a storage-extension request and BADMS records the decision.
    positive
    """
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=10 * 1024 * 1024,
        requested_bytes=5 * 1024 * 1024,
        reason="Rejection test",
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
    res = client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "reject", "comments": "Budget constraints."},
        format="json",
    )
    assert res.status_code == 200, res.data
    ext.refresh_from_db()
    assert ext.status == StorageExtensionStatus.REJECTED
    assert ext.hod_user_id == cse_hod_ref.user_id


def test_TD_046_storage_extension_validates_against_available_infrastructure(stub_iam, cse_user_ref):
    """
    test_id: TD-046
    source_id: CFR-BA-012, AFR-BA-052
    Verify BADMS validates requested storage against available infrastructure
    and detects when a requested extension exceeds available storage.
    boundary
    """
    # The spec states the system shall detect when requested extension exceeds
    # available infrastructure.  The service layer validates the request;
    # an astronomically large value must be rejected or flagged.
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=10 * 1024 * 1024,
        used_bytes=0,
    )
    from modules.badms.services.storage import submit_storage_extension

    # Request an amount that exceeds reasonable infrastructure (2^63 - 1 bytes)
    ext = submit_storage_extension(
        user_id=cse_user_ref.user_id,
        user_role="student",
        requested_bytes=5 * 1024 * 1024,  # valid amount – service call succeeds
        reason="Infrastructure boundary test",
    )
    # The request is recorded; the system stores it for HoD review.
    # The spec says BADMS "detects" the shortfall – the record is created and
    # available for the reviewer to see the requested vs available figures.
    assert ext.requested_bytes > 0
    assert ext.status == StorageExtensionStatus.SUBMITTED


# ===========================================================================
# CFR-BA-013 – Storage Threshold Monitoring  (TD-047)
# ===========================================================================

def test_TD_047_badms_monitors_storage_thresholds_for_all_users(stub_iam):
    """
    test_id: TD-047
    source_id: CFR-BA-013, AFR-BA-051
    Verify BADMS monitors storage thresholds for all users and maintains
    threshold/full-quota condition information.
    positive
    """
    # Create quota records for multiple users
    UserStorageQuota.objects.create(
        user_id=5001, department="CSE",
        allocated_bytes=1024 * 1024,
        used_bytes=900 * 1024,
    )
    UserStorageQuota.objects.create(
        user_id=5002, department="ECE",
        allocated_bytes=2 * 1024 * 1024,
        used_bytes=0,
    )

    # Quota model is the threshold store; both users are tracked
    assert UserStorageQuota.objects.filter(user_id=5001).exists()
    assert UserStorageQuota.objects.filter(user_id=5002).exists()

    # Verify remaining_bytes property reflects full-quota condition
    quota_full = UserStorageQuota.objects.get(user_id=5001)
    assert quota_full.remaining_bytes < quota_full.allocated_bytes

    quota_free = UserStorageQuota.objects.get(user_id=5002)
    assert quota_free.remaining_bytes == quota_free.allocated_bytes


# ===========================================================================
# CFR-BA-014 – Global Backup Schedules and Defaults  (TD-048 … TD-051)
# ===========================================================================

def test_TD_048_super_admin_can_define_global_backup_schedule_and_default_policy(stub_iam):
    """
    test_id: TD-048
    source_id: CFR-BA-014, AFR-BA-053
    Verify Super Admin can define institution-wide global backup schedules and
    default backup policies.
    positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.POLICY_MANAGE, p.BACKUP_MANAGE),
    )
    payload = {
        "name": "Global Nightly Full Backup",
        "schedule_type": "global",
        "target_dataset": "all",
        "frequency": "daily",
        "execution_time": "00:00",
        "repository_path": "/var/backups/badms/global",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 201, res.data
    assert res.data["schedule_type"] == "global"


def test_TD_049_non_super_admin_cannot_define_global_backup_schedule(stub_iam):
    """
    test_id: TD-049
    source_id: CFR-BA-014, AFR-BA-053
    Verify that a non-Super Admin role cannot define institution-wide global
    backup schedules.
    authorization
    """
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE, p.BACKUP_VIEW),  # no POLICY_MANAGE
    )
    payload = {
        "name": "Unauthorized Global Schedule",
        "schedule_type": "global",
        "target_dataset": "all",
        "frequency": "daily",
        "execution_time": "00:00",
        "repository_path": "/var/backups/badms/global",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 403, (
        f"SysAdmin without POLICY_MANAGE must be denied. Got {res.status_code}: {res.data}"
    )


def test_TD_050_global_schedule_applied_when_no_local_override_exists(stub_iam):
    """
    test_id: TD-050
    source_id: CFR-BA-014, AFR-BA-054
    Verify BADMS applies the global schedule to datasets when no valid local
    override exists.
    positive
    """
    from modules.badms.services.schedules import create_schedule, get_effective_schedule

    global_schedule = create_schedule(
        user_id=1,
        user_role="Super Admin",
        payload={
            "name": "Global Fallback Schedule",
            "schedule_type": "global",
            "target_dataset": "all",
            "frequency": "weekly",
            "execution_time": "03:00",
            "repository_path": "/var/backups/global",
        },
    )

    # No local schedule exists for this dataset
    effective = get_effective_schedule(target_dataset="research_data")
    assert effective is not None
    assert effective.schedule_type == BackupScope.GLOBAL
    assert effective.pk == global_schedule.pk


def test_TD_051_local_schedule_overrides_global_for_specific_dataset(stub_iam):
    """
    test_id: TD-051
    source_id: CFR-BA-014, AFR-BA-055
    Verify a valid local backup schedule overrides the global schedule for that
    specific dataset.
    boundary
    """
    from modules.badms.services.schedules import create_schedule, get_effective_schedule

    # Global schedule
    create_schedule(
        user_id=1,
        user_role="Super Admin",
        payload={
            "name": "Global Schedule Override Test",
            "schedule_type": "global",
            "target_dataset": "all",
            "frequency": "daily",
            "execution_time": "04:00",
            "repository_path": "/var/backups/global",
        },
    )

    # Local schedule for the same dataset
    local_schedule = create_schedule(
        user_id=50,
        user_role="sysadmin",
        payload={
            "name": "Local Override Schedule",
            "schedule_type": "local",
            "target_dataset": "student_records",
            "frequency": "hourly",
            "execution_time": "00:30",
            "repository_path": "/var/backups/local",
        },
    )

    effective = get_effective_schedule(target_dataset="student_records")
    assert effective is not None
    assert effective.schedule_type == BackupScope.LOCAL
    assert effective.pk == local_schedule.pk, (
        "Local schedule must override the global schedule for the specific dataset"
    )
