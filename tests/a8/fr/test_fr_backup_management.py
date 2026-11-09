"""
FR Test Suite – Backup Management (CFR-BA-001, CFR-BA-002, CFR-BA-003, CFR-BA-004)
Implements TD-001 through TD-014 from a8_design/FR_DESIGN.json.

All tests use the existing Django test database (pytest-django) and the
stub_iam fixture defined in conftest.py.  No production files are modified.
"""
import pytest
from rest_framework.test import APIClient

from conftest import make_session
from modules.badms.domain import permissions as p
from modules.badms.models import (
    BackupExecution,
    BackupSchedule,
    BackupScope,
    BackupStatus,
    BackupFrequency,
    BadmsAuditLog,
    BadmsNotification,
)

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _client(stub_iam, **session_kw):
    stub_iam(make_session(**session_kw))
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION="Token fake-token")
    return c


# ---------------------------------------------------------------------------
# TD-001  CFR-BA-001 / AFR-BA-001  – SysAdmin can trigger manual backup
# ---------------------------------------------------------------------------

def test_TD_001_sysadmin_can_trigger_manual_backup(stub_iam):
    """
    test_id: TD-001
    source_id: CFR-BA-001, AFR-BA-001
    Verify that only a SysAdmin or Super Admin can trigger a manual backup.
    positive
    """
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW),
    )
    res = client.post("/api/v1/badms/backups/", {"backup_type": "full", "scope": "local"}, format="json")
    assert res.status_code == 201, res.data
    assert res.data["status"] == BackupStatus.COMPLETED


# ---------------------------------------------------------------------------
# TD-002  CFR-BA-001 / AFR-BA-001  – Non-authorised role cannot trigger backup
# ---------------------------------------------------------------------------

def test_TD_002_non_authorized_role_cannot_trigger_manual_backup(stub_iam):
    """
    test_id: TD-002
    source_id: CFR-BA-001, AFR-BA-001
    Verify that a non-authorized role cannot trigger a manual backup.
    authorization
    """
    client = _client(
        stub_iam,
        user_id=99,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),  # no BACKUP_CREATE
    )
    res = client.post("/api/v1/badms/backups/", {"backup_type": "full"}, format="json")
    assert res.status_code == 403


# ---------------------------------------------------------------------------
# TD-003  CFR-BA-001 / AFR-BA-002, AFR-BA-003
#         BADMS captures timestamp, artifacts, and database-state dump
# ---------------------------------------------------------------------------

def test_TD_003_manual_backup_captures_timestamp_and_database_dump(stub_iam):
    """
    test_id: TD-003
    source_id: CFR-BA-001, AFR-BA-002, AFR-BA-003
    Verify BADMS collects current timestamp and backup artifacts and saves a
    current-state database dump together with its timestamp.
    positive
    """
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW),
    )
    res = client.post(
        "/api/v1/badms/backups/",
        {"backup_type": "full", "scope": "local", "target_dataset": "hr_records"},
        format="json",
    )
    assert res.status_code == 201, res.data
    data = res.data
    # Timestamp present
    assert data["started_at"] is not None
    assert data["completed_at"] is not None
    # Dump artefacts: checksum and size
    assert len(data["checksum"]) == 64, "SHA-256 checksum must be 64 hex chars"
    assert data["size_bytes"] > 0


# ---------------------------------------------------------------------------
# TD-004  CFR-BA-001 / AFR-BA-004  – Outcome recorded as Success
# ---------------------------------------------------------------------------

def test_TD_004_successful_manual_backup_outcome_is_success(stub_iam):
    """
    test_id: TD-004
    source_id: CFR-BA-001, AFR-BA-004
    Verify BADMS records and communicates backup outcome as Success.
    positive
    """
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW),
    )
    res = client.post("/api/v1/badms/backups/", {"backup_type": "full"}, format="json")
    assert res.status_code == 201
    assert res.data["status"] == BackupStatus.COMPLETED


# ---------------------------------------------------------------------------
# TD-005  CFR-BA-001 / AFR-BA-004, AFR-BA-005
#         Failed backup recorded as Failed and SysAdmin alerted
# ---------------------------------------------------------------------------

def test_TD_005_failed_manual_backup_marked_failed_and_sysadmin_alerted(stub_iam):
    """
    test_id: TD-005
    source_id: CFR-BA-001, AFR-BA-004, AFR-BA-005
    Verify BADMS marks a failed backup as Failed and sends an alert to SysAdmin.
    negative
    """
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW),
    )
    res = client.post("/api/v1/badms/backups/", {"simulate_failure": True}, format="json")
    assert res.status_code == 200
    assert res.data["status"] == BackupStatus.FAILED

    # SysAdmin failure alert must be recorded
    failure_notif = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
    ).first()
    assert failure_notif is not None, "SysAdmin must receive a failure alert notification"
    assert "FAILED" in failure_notif.subject


# ---------------------------------------------------------------------------
# TD-006  CFR-BA-002 / AFR-BA-006  – Automatic backup executes at schedule time
# ---------------------------------------------------------------------------

def test_TD_006_automatic_backup_executes_at_scheduled_time_without_intervention(stub_iam):
    """
    test_id: TD-006
    source_id: CFR-BA-002, AFR-BA-006
    Verify BADMS executes automatic backups at scheduled times without user
    intervention.
    positive
    """
    from modules.badms.services.schedules import create_schedule, execute_scheduled_backup

    schedule = create_schedule(
        user_id=10,
        user_role="sysadmin",
        payload={
            "name": "TD-006 Auto Backup",
            "schedule_type": "local",
            "target_dataset": "research_data",
            "frequency": "daily",
            "execution_time": "03:00",
            "repository_path": "/var/backups/badms",
        },
    )
    # Trigger the scheduled backup (simulates scheduler calling without user)
    backup = execute_scheduled_backup(schedule.pk, user_id=0)
    assert backup.status == BackupStatus.COMPLETED
    assert backup.initiated_by_user_id == 0  # no human user


# ---------------------------------------------------------------------------
# TD-007  CFR-BA-002 / AFR-BA-007, AFR-BA-008
#         Automatic backup identifies datasets and transfers to recovery storage
# ---------------------------------------------------------------------------

def test_TD_007_automatic_backup_identifies_eligible_datasets_and_transfers(stub_iam):
    """
    test_id: TD-007
    source_id: CFR-BA-002, AFR-BA-007, AFR-BA-008
    Verify BADMS identifies eligible datasets and transfers them to backup
    recovery storage during automatic backup.
    positive
    """
    from modules.badms.services.schedules import create_schedule, execute_scheduled_backup

    schedule = create_schedule(
        user_id=10,
        user_role="sysadmin",
        payload={
            "name": "TD-007 Dataset Transfer",
            "schedule_type": "local",
            "target_dataset": "student_records",
            "frequency": "daily",
            "execution_time": "04:00",
            "repository_path": "/var/backups/badms",
        },
    )
    backup = execute_scheduled_backup(schedule.pk, user_id=0)
    assert backup.status == BackupStatus.COMPLETED
    assert backup.target_dataset == "student_records"
    assert backup.size_bytes > 0  # data was transferred


# ---------------------------------------------------------------------------
# TD-008  CFR-BA-002 / AFR-BA-009, AFR-BA-010
#         Automatic backup verifies integrity and logs timestamp/status
# ---------------------------------------------------------------------------

def test_TD_008_automatic_backup_verifies_integrity_and_logs(stub_iam):
    """
    test_id: TD-008
    source_id: CFR-BA-002, AFR-BA-009, AFR-BA-010
    Verify BADMS verifies backup integrity/consistency and logs the automatic
    backup with timestamp and status.
    positive
    """
    from modules.badms.services.schedules import create_schedule, execute_scheduled_backup

    schedule = create_schedule(
        user_id=10,
        user_role="sysadmin",
        payload={
            "name": "TD-008 Integrity Check",
            "schedule_type": "local",
            "target_dataset": "all",
            "frequency": "daily",
            "execution_time": "05:00",
            "repository_path": "/var/backups/badms",
        },
    )
    backup = execute_scheduled_backup(schedule.pk, user_id=0)
    assert backup.integrity_verified is True
    assert backup.started_at is not None
    assert backup.status == BackupStatus.COMPLETED

    # Audit log created with timestamp and status
    audit = BadmsAuditLog.objects.filter(
        target_id=str(backup.pk),
        action="badms.backup.execute",
    ).first()
    assert audit is not None
    assert audit.outcome == "success"


# ---------------------------------------------------------------------------
# TD-009  CFR-BA-002 / AFR-BA-011
#         Automatic backup does NOT execute when repository is unreachable
# ---------------------------------------------------------------------------

def test_TD_009_automatic_backup_not_executed_when_repository_unreachable(stub_iam):
    """
    test_id: TD-009
    source_id: CFR-BA-002, AFR-BA-011
    Verify BADMS does not execute a scheduled automatic backup when the relevant
    repository is unreachable.
    boundary
    """
    from modules.badms.services.schedules import create_schedule, execute_scheduled_backup

    schedule = create_schedule(
        user_id=10,
        user_role="sysadmin",
        payload={
            "name": "TD-009 Unreachable Repo",
            "schedule_type": "local",
            "target_dataset": "all",
            "frequency": "daily",
            "execution_time": "06:00",
            "repository_path": "/var/backups/badms",
        },
    )
    backup = execute_scheduled_backup(schedule.pk, user_id=0, simulate_unreachable=True)
    assert backup.status == BackupStatus.FAILED
    assert backup.repository_reachable is False


# ---------------------------------------------------------------------------
# TD-010  CFR-BA-003 / AFR-BA-012  – SysAdmin can view current backup schedules
# ---------------------------------------------------------------------------

def test_TD_010_sysadmin_can_view_current_backup_schedules(stub_iam):
    """
    test_id: TD-010
    source_id: CFR-BA-003, AFR-BA-012
    Verify that the current backup schedules are displayed to an authorised SysAdmin.
    positive
    """
    from modules.badms.services.schedules import create_schedule

    create_schedule(
        user_id=10,
        user_role="sysadmin",
        payload={
            "name": "Viewable Schedule",
            "schedule_type": "local",
            "target_dataset": "all",
            "frequency": "daily",
            "execution_time": "07:00",
            "repository_path": "/var/backups/badms",
        },
    )
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE, p.BACKUP_VIEW),
    )
    res = client.get("/api/v1/badms/schedules/")
    assert res.status_code == 200
    assert res.data["count"] >= 1


# ---------------------------------------------------------------------------
# TD-011  CFR-BA-003 / AFR-BA-013
#         SysAdmin can create/modify a local schedule with frequency, time, filters
# ---------------------------------------------------------------------------

def test_TD_011_sysadmin_can_create_local_schedule_with_frequency_time_filter(stub_iam):
    """
    test_id: TD-011
    source_id: CFR-BA-003, AFR-BA-013
    Verify SysAdmin can create or modify a local backup schedule by specifying
    frequency, execution time, and data-classification filters.
    positive
    """
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE, p.BACKUP_VIEW),
    )
    payload = {
        "name": "Weekly Classified Backup",
        "schedule_type": "local",
        "target_dataset": "classified_docs",
        "frequency": "weekly",
        "execution_time": "23:00",
        "classification_filter": "sensitive",
        "repository_path": "/var/backups/badms",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 201, res.data
    assert res.data["frequency"] == "weekly"
    assert res.data["classification_filter"] == "sensitive"
    assert res.data["schedule_type"] == "local"


# ---------------------------------------------------------------------------
# TD-012  CFR-BA-003 / AFR-BA-014
#         Invalid/conflicting schedule is rejected; no state change
# ---------------------------------------------------------------------------

def test_TD_012_invalid_schedule_config_rejected_without_state_change(stub_iam):
    """
    test_id: TD-012
    source_id: CFR-BA-003, AFR-BA-014
    Verify BADMS rejects an invalid or conflicting schedule configuration
    without applying it.
    validation
    """
    before_count = BackupSchedule.objects.count()
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE,),
    )
    # Missing required fields: no execution_time, no repository_path
    payload = {
        "name": "Bad Schedule",
        "schedule_type": "local",
        "frequency": "INVALID_FREQ",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code in (400, 422), res.data
    assert BackupSchedule.objects.count() == before_count, "No schedule must be created on validation failure"


# ---------------------------------------------------------------------------
# TD-013  CFR-BA-003 / AFR-BA-015, AFR-BA-016
#         Valid schedule is applied and configuration change is logged
# ---------------------------------------------------------------------------

def test_TD_013_valid_schedule_applied_and_config_change_logged(stub_iam):
    """
    test_id: TD-013
    source_id: CFR-BA-003, AFR-BA-015, AFR-BA-016
    Verify that after successful schedule validation BADMS applies the new
    schedule and logs the configuration change.
    positive
    """
    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE, p.BACKUP_VIEW),
    )
    payload = {
        "name": "Logged Schedule",
        "schedule_type": "local",
        "target_dataset": "audit_data",
        "frequency": "daily",
        "execution_time": "01:00",
        "repository_path": "/var/backups/badms",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 201, res.data
    schedule_id = res.data["id"]

    # Confirm schedule is persisted
    assert BackupSchedule.objects.filter(pk=schedule_id, is_active=True).exists()

    # Audit log must record the configuration change
    audit = BadmsAuditLog.objects.filter(
        target_id=str(schedule_id),
        action="badms.schedule.create",
    ).first()
    assert audit is not None, "Audit log entry for schedule creation must exist"
    assert audit.outcome == "success"


# ---------------------------------------------------------------------------
# TD-014  CFR-BA-004 / AFR-BA-017, AFR-BA-018
#         BADMS maintains backup history; authorized users can view it
# ---------------------------------------------------------------------------

def test_TD_014_backup_history_maintained_and_visible_to_authorized_users(stub_iam):
    """
    test_id: TD-014
    source_id: CFR-BA-004, AFR-BA-017, AFR-BA-018
    Verify BADMS maintains backup status and history and allows authorized users
    and administrators to view them within their authorized scope.
    positive
    """
    # Create a completed backup record
    backup = BackupExecution.objects.create(
        scope=BackupScope.LOCAL,
        status=BackupStatus.COMPLETED,
        checksum="a" * 64,
        integrity_verified=True,
        target_dataset="all",
    )

    client = _client(
        stub_iam,
        user_id=10,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_VIEW,),
    )
    res = client.get("/api/v1/badms/backups/")
    assert res.status_code == 200
    ids = [r["id"] for r in res.data["results"]]
    assert backup.pk in ids
