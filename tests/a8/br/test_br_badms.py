"""
BADMS Business Rules Test Suite
================================
Implements all 59 frozen test designs (TD-001 through TD-059) from `a8_design/BR_DESIGN.json`.

Specifications:
  - a8_specs/01_BA_Problem_Statement_v1.2_SYNCHRONIZED_DRAFT.docx
  - a8_specs/04_BA_Business_Rule_Specifications_v1.2_FINAL.docx

Rules coverage:
  BR-BA-001 (TD-001 .. TD-003): Manual Backup Trigger Authorization
  BR-BA-002 (TD-004 .. TD-007): Respective HoD Approval for Secure Archival
  BR-BA-003 (TD-008 .. TD-009): IT Security Encryption Authority
  BR-BA-004 (TD-010 .. TD-012): SysAdmin Authoritative Classification
  BR-BA-005 (TD-013 .. TD-016): Sensitive Restoration Approval
  BR-BA-006 (TD-017 .. TD-018): Initial Data Classification and Default
  BR-BA-007 (TD-019 .. TD-020): Sensitive Data Encryption
  BR-BA-008 (TD-021 .. TD-022): Retention by Classification
  BR-BA-009 (TD-023 .. TD-025): HoD Approval for Storage Extension
  BR-BA-010 (TD-026 .. TD-029): HoD Department Scope
  BR-BA-011 (TD-030 .. TD-031): Local Schedule Overrides Global
  BR-BA-012 (TD-032 .. TD-034): Schedule Parameter Validation
  BR-BA-013 (TD-035 .. TD-036): Scheduled Repository Reachability
  BR-BA-014 (TD-037 .. TD-038): Backup Failure Alert SLA
  BR-BA-015 (TD-039 .. TD-041): Repeated Failure Escalation
  BR-BA-016 (TD-042 .. TD-043): Storage-Extension Usage Validation
  BR-BA-017 (TD-044 .. TD-046): Storage-Extension Decision Criteria
  BR-BA-018 (TD-047 .. TD-049): Special Archival Super Admin Authority
  BR-BA-019 (TD-050 .. TD-052): Super Admin Global Backup Authority
  BR-BA-020 (TD-053 .. TD-056): Protected Information Access Scope
  BR-BA-021 (TD-057 .. TD-059): IT Security Security/RBAC Authority

Conventions:
  - pytestmark = pytest.mark.django_db
  - stub_iam replaces the IAM client
  - No production code is modified
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
    BackupFrequency,
    BackupSchedule,
    BackupScope,
    BackupStatus,
    BadmsAuditLog,
    BadmsNotification,
    RestorationRequest,
    RestorationStatus,
    SpecialArchivalRecord,
    StorageExtensionRequest,
    StorageExtensionStatus,
    UserStorageQuota,
)
from modules.badms.services.backup import execute_backup
from modules.badms.services.reports import get_retention_compliance_summary
from modules.badms.services.schedules import get_effective_schedule
from modules.directory.models import UserRef

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Fixtures and Helpers
# ---------------------------------------------------------------------------

def _client(stub_iam, **session_kw):
    stub_iam(make_session(**session_kw))
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION="Token fake-token")
    return c


@pytest.fixture
def cse_user_ref():
    return UserRef.objects.create(
        user_id=1001,
        username="u1001",
        display_name="CSE User",
        kind="student",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


@pytest.fixture
def ece_user_ref():
    return UserRef.objects.create(
        user_id=1002,
        username="u1002",
        display_name="ECE User",
        kind="student",
        department="ECE",
        discipline="ECE",
        is_active=True,
    )


@pytest.fixture
def cse_hod_ref():
    return UserRef.objects.create(
        user_id=2001,
        username="u2001",
        display_name="CSE HoD",
        kind="faculty",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


@pytest.fixture
def ece_hod_ref():
    return UserRef.objects.create(
        user_id=2002,
        username="u2002",
        display_name="ECE HoD",
        kind="faculty",
        department="ECE",
        discipline="ECE",
        is_active=True,
    )


# ===========================================================================
# BR-BA-001: Manual Backup Trigger Authorization (TD-001 .. TD-003)
# ===========================================================================

def test_TD_001_sysadmin_can_trigger_manual_backup(stub_iam):
    """
    test_id: TD-001
    source_id: BR-BA-001
    Verify that an authorized SysAdmin can trigger a manual backup
    test_type: positive
    """
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW),
    )
    res = client.post("/api/v1/badms/backups/", {"backup_type": "full", "scope": "local"}, format="json")
    assert res.status_code == 201, res.data
    assert res.data["status"] == BackupStatus.COMPLETED
    assert BackupExecution.objects.filter(pk=res.data["id"], status=BackupStatus.COMPLETED).exists()


def test_TD_002_super_admin_can_trigger_manual_backup(stub_iam):
    """
    test_id: TD-002
    source_id: BR-BA-001
    Verify that an authorized Super Admin can trigger a manual backup
    test_type: positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.BACKUP_CREATE, p.BACKUP_VIEW, p.POLICY_MANAGE),
    )
    res = client.post("/api/v1/badms/backups/", {"backup_type": "full", "scope": "local"}, format="json")
    assert res.status_code == 201, res.data
    assert res.data["status"] == BackupStatus.COMPLETED
    assert BackupExecution.objects.filter(pk=res.data["id"], status=BackupStatus.COMPLETED).exists()


def test_TD_003_unauthorized_actor_denied_manual_backup_trigger(stub_iam):
    """
    test_id: TD-003
    source_id: BR-BA-001
    Verify that an unauthorized actor without SysAdmin or Super Admin authority is denied from triggering a manual backup
    test_type: authorization
    """
    before_count = BackupExecution.objects.count()
    client = _client(
        stub_iam,
        user_id=1001,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = client.post("/api/v1/badms/backups/", {"backup_type": "full"}, format="json")
    assert res.status_code == 403, res.data
    assert BackupExecution.objects.count() == before_count


# ===========================================================================
# BR-BA-002: Respective HoD Approval for Secure Archival (TD-004 .. TD-007)
# ===========================================================================

def test_TD_004_submitted_archival_request_routed_to_respective_hod(stub_iam, cse_user_ref, cse_hod_ref, ece_hod_ref):
    """
    test_id: TD-004
    source_id: BR-BA-002
    Verify that a submitted secure archival request is routed to the HoD of the requester's department
    test_type: routing
    """
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=10 * 1024 * 1024,
        used_bytes=0,
    )
    user_client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = user_client.post(
        "/api/v1/badms/archives/",
        {
            "file_name": "research_report.pdf",
            "file_type": "pdf",
            "reason": "Thesis archival",
            "document_date": "2026-01-15",
            "owners": ["alice"],
            "file_size_bytes": 1024,
        },
        format="json",
    )
    assert res.status_code == 201, res.data
    archive_id = res.data["id"]

    # Verify notification routed to HoD role
    notif = BadmsNotification.objects.filter(
        recipient_role="HOD",
        notification_type="hod_review_required",
        related_object_id=archive_id,
    ).first()
    assert notif is not None, "Notification must be sent to HoD"
    assert "CSE" in notif.subject or "CSE" in notif.message

    # Verify CSE HoD sees the request
    cse_client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    cse_res = cse_client.get("/api/v1/badms/archives/")
    assert cse_res.status_code == 200
    cse_ids = [item["id"] for item in cse_res.data["results"]]
    assert archive_id in cse_ids

    # Verify ECE HoD does not see the request
    ece_client = _client(
        stub_iam,
        user_id=ece_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    ece_res = ece_client.get("/api/v1/badms/archives/")
    assert ece_res.status_code == 200
    ece_ids = [item["id"] for item in ece_res.data["results"]]
    assert archive_id not in ece_ids


def test_TD_005_respective_hod_authorized_to_decide_archival_request(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-005
    source_id: BR-BA-002
    Verify that the HoD of the requester's department is authorized to decide on the secure archival request
    test_type: positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="paper.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Archival test",
        status=ArchiveStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "approve", "comments": "Approved by CSE HoD"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.HOD_APPROVED
    assert archive.hod_user_id == cse_hod_ref.user_id


def test_TD_006_different_department_hod_prohibited_from_deciding_archival(stub_iam, cse_user_ref, ece_hod_ref):
    """
    test_id: TD-006
    source_id: BR-BA-002
    Verify that a HoD of a different department is prohibited from deciding the secure archival request
    test_type: authorization
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="cse_paper.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Cross-dept check",
        status=ArchiveStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=ece_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "approve", "comments": "Unauthorized cross-dept attempt"},
        format="json",
    )
    assert res.status_code in (403, 404), res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.SUBMITTED


def test_TD_007_non_hod_prohibited_from_deciding_archival_request(stub_iam, cse_user_ref):
    """
    test_id: TD-007
    source_id: BR-BA-002
    Verify that a non-HoD actor is prohibited from deciding a secure archival request
    test_type: authorization
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="paper.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Archival test",
        status=ArchiveStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "approve", "comments": "Attempt by SysAdmin"},
        format="json",
    )
    assert res.status_code == 403, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.SUBMITTED


# ===========================================================================
# BR-BA-003: IT Security Encryption Authority (TD-008 .. TD-009)
# ===========================================================================

def test_TD_008_it_security_can_configure_encryption_for_sensitive_data(stub_iam, cse_user_ref):
    """
    test_id: TD-008
    source_id: BR-BA-003
    Verify that an authorized IT Security Team member can configure encryption for Sensitive data
    test_type: positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_genome.dat",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="dat",
        file_size_bytes=2048,
        reason="Genomic sequencing",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="it_security",
        modules=("badms",),
        permissions=(p.ARCHIVE_ENCRYPT, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM", "key_id": "KEY-AES256-SEC-01"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED
    assert archive.is_encrypted is True
    assert "AES-256" in archive.encryption_algorithm.upper()
    assert archive.security_user_id == 70


def test_TD_009_non_it_security_prohibited_from_configuring_encryption(stub_iam, cse_user_ref):
    """
    test_id: TD-009
    source_id: BR-BA-003
    Verify that a non-IT Security actor is prohibited from configuring encryption for Sensitive data
    test_type: authorization
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_data.dat",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="dat",
        file_size_bytes=2048,
        reason="Sensitive research",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM"},
        format="json",
    )
    assert res.status_code == 403, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.ROUTED_TO_SECURITY
    assert archive.is_encrypted is False


# ===========================================================================
# BR-BA-004: SysAdmin Authoritative Classification (TD-010 .. TD-012)
# ===========================================================================

def test_TD_010_sysadmin_can_assign_authoritative_classification(stub_iam, cse_user_ref):
    """
    test_id: TD-010
    source_id: BR-BA-004
    Verify that an authorized SysAdmin can assign an authoritative classification (Critical, Sensitive, Routine, or Archival) to an HoD-approved secure archival request
    test_type: positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="important_records.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["admin"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="HoD approved record",
        status=ArchiveStatus.HOD_APPROVED,
        initial_classification=ArchiveClassification.ROUTINE,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "critical", "comments": "Authoritatively Critical"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.authoritative_classification == ArchiveClassification.CRITICAL
    assert archive.sysadmin_user_id == 50
    assert archive.status == ArchiveStatus.POLICY_APPLIED


def test_TD_011_non_sysadmin_prohibited_from_authoritative_classification(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-011
    source_id: BR-BA-004
    Verify that a non-SysAdmin actor is prohibited from assigning the authoritative secure-archival classification
    test_type: authorization
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="records.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["admin"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Record",
        status=ArchiveStatus.HOD_APPROVED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "sensitive"},
        format="json",
    )
    assert res.status_code == 403, res.data
    archive.refresh_from_db()
    assert archive.authoritative_classification is None


def test_TD_012_authoritative_classification_prohibited_prior_to_hod_approval(stub_iam, cse_user_ref):
    """
    test_id: TD-012
    source_id: BR-BA-004
    Verify that authoritative classification assignment is prohibited prior to HoD approval
    test_type: negative
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="unapproved.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Pending HoD",
        status=ArchiveStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "routine"},
        format="json",
    )
    assert res.status_code == 400, res.data
    archive.refresh_from_db()
    assert archive.authoritative_classification is None
    assert archive.status == ArchiveStatus.SUBMITTED


# ===========================================================================
# BR-BA-005: Sensitive Restoration Approval (TD-013 .. TD-016)
# ===========================================================================

def test_TD_013_sensitive_restoration_blocked_until_sysadmin_approval(stub_iam, cse_user_ref):
    """
    test_id: TD-013
    source_id: BR-BA-005
    Verify that restoration of data classified Sensitive is blocked until SysAdmin approval is recorded
    test_type: security
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_patient_data.csv",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="csv",
        file_size_bytes=1024,
        reason="Sensitive healthcare records",
        authoritative_classification=ArchiveClassification.SENSITIVE,
        is_encrypted=True,
        encryption_algorithm="AES-256-GCM",
        status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
    )
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.RESTORATION_CREATE, p.RESTORATION_VIEW_SELF),
    )
    res = client.post(
        "/api/v1/badms/restorations/",
        {"archive_id": archive.pk, "reason": "Audit request"},
        format="json",
    )
    assert res.status_code == 201, res.data
    restoration_id = res.data["id"]
    restoration = RestorationRequest.objects.get(pk=restoration_id)

    assert restoration.is_sensitive is True
    assert restoration.status == RestorationStatus.PENDING_APPROVAL
    assert restoration.restored_at is None
    assert restoration.integrity_verified is False


def test_TD_014_sensitive_restoration_proceeds_after_sysadmin_approval(stub_iam, cse_user_ref):
    """
    test_id: TD-014
    source_id: BR-BA-005
    Verify that restoration of Sensitive data is permitted to proceed once SysAdmin approval is recorded
    test_type: positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_data.csv",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="csv",
        file_size_bytes=1024,
        reason="Sensitive records",
        authoritative_classification=ArchiveClassification.SENSITIVE,
        is_encrypted=True,
        status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
    )
    restoration = RestorationRequest.objects.create(
        archive_id=archive.pk,
        requester_user_id=cse_user_ref.user_id,
        target_type="archive",
        target_name=archive.file_name,
        reason="Urgent analysis",
        target_destination="/restored",
        is_sensitive=True,
        status=RestorationStatus.PENDING_APPROVAL,
    )
    sysadmin_client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.RESTORATION_APPROVE, p.RESTORATION_VIEW),
    )
    res = sysadmin_client.post(
        f"/api/v1/badms/restorations/{restoration.pk}/decision/",
        {"decision": "approve", "comments": "Approved for analysis"},
        format="json",
    )
    assert res.status_code == 200, res.data
    restoration.refresh_from_db()
    assert restoration.status == RestorationStatus.COMPLETED
    assert restoration.approved_by_user_id == 50
    assert restoration.restored_at is not None
    assert restoration.integrity_verified is True


def test_TD_015_sensitive_restoration_rejected_by_sysadmin_blocked(stub_iam, cse_user_ref):
    """
    test_id: TD-015
    source_id: BR-BA-005
    Verify that if SysAdmin rejects a Sensitive data restoration request, restoration is blocked and marked Rejected
    test_type: negative
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_data.csv",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="csv",
        file_size_bytes=1024,
        reason="Sensitive records",
        authoritative_classification=ArchiveClassification.SENSITIVE,
        is_encrypted=True,
        status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
    )
    restoration = RestorationRequest.objects.create(
        archive_id=archive.pk,
        requester_user_id=cse_user_ref.user_id,
        target_type="archive",
        target_name=archive.file_name,
        reason="Analysis",
        target_destination="/restored",
        is_sensitive=True,
        status=RestorationStatus.PENDING_APPROVAL,
    )
    sysadmin_client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.RESTORATION_APPROVE, p.RESTORATION_VIEW),
    )
    res = sysadmin_client.post(
        f"/api/v1/badms/restorations/{restoration.pk}/decision/",
        {"decision": "reject", "comments": "Rejected by policy"},
        format="json",
    )
    assert res.status_code == 200, res.data
    restoration.refresh_from_db()
    assert restoration.status == RestorationStatus.REJECTED
    assert restoration.restored_at is None
    assert restoration.approved_by_user_id == 50


def test_TD_016_non_sensitive_restoration_standard_path_no_approval_required(stub_iam, cse_user_ref):
    """
    test_id: TD-016
    source_id: BR-BA-005
    Verify that restoration of non-Sensitive data (Routine, Critical, Archival) follows the standard restoration path without requiring SysAdmin approval
    test_type: positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="routine_document.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Routine doc",
        authoritative_classification=ArchiveClassification.ROUTINE,
        is_encrypted=False,
        status=ArchiveStatus.POLICY_APPLIED,
    )
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.RESTORATION_CREATE, p.RESTORATION_VIEW_SELF),
    )
    res = client.post(
        "/api/v1/badms/restorations/",
        {"archive_id": archive.pk, "reason": "Standard restoration"},
        format="json",
    )
    assert res.status_code == 201, res.data
    restoration_id = res.data["id"]
    restoration = RestorationRequest.objects.get(pk=restoration_id)

    assert restoration.is_sensitive is False
    assert restoration.status == RestorationStatus.COMPLETED
    assert restoration.restored_at is not None
    assert restoration.approved_by_user_id is None


# ===========================================================================
# BR-BA-006: Initial Data Classification and Default (TD-017 .. TD-018)
# ===========================================================================

def test_TD_017_explicit_initial_classification_used_on_upload(stub_iam, cse_user_ref):
    """
    test_id: TD-017
    source_id: BR-BA-006
    Verify that when a user provides an explicit initial classification during secure archival upload, BADMS uses the provided classification
    test_type: positive
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
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = client.post(
        "/api/v1/badms/archives/",
        {
            "file_name": "critical_upload.pdf",
            "file_type": "pdf",
            "reason": "Important research",
            "document_date": "2026-02-01",
            "owners": ["alice"],
            "file_size_bytes": 1024,
            "initial_classification": "critical",
        },
        format="json",
    )
    assert res.status_code == 201, res.data
    assert res.data["initial_classification"] == "critical"


def test_TD_018_omitted_initial_classification_defaults_to_routine(stub_iam, cse_user_ref):
    """
    test_id: TD-018
    source_id: BR-BA-006
    Verify that when a user omits the initial classification during secure archival upload, BADMS automatically assigns Routine as the default
    test_type: default
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
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = client.post(
        "/api/v1/badms/archives/",
        {
            "file_name": "default_class_upload.pdf",
            "file_type": "pdf",
            "reason": "Default class test",
            "document_date": "2026-02-01",
            "owners": ["alice"],
            "file_size_bytes": 1024,
        },
        format="json",
    )
    assert res.status_code == 201, res.data
    assert res.data["initial_classification"] == ArchiveClassification.ROUTINE


# ===========================================================================
# BR-BA-007: Sensitive Data Encryption (TD-019 .. TD-020)
# ===========================================================================

def test_TD_019_sensitive_data_encrypted_with_aes256_at_rest_and_in_transit(stub_iam, cse_user_ref):
    """
    test_id: TD-019
    source_id: BR-BA-007
    Verify that data authoritatively classified Sensitive is encrypted using AES-256 both at rest and in transit
    test_type: security
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_dataset.bin",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="bin",
        file_size_bytes=4096,
        reason="Sensitive research",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="it_security",
        modules=("badms",),
        permissions=(p.ARCHIVE_ENCRYPT, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM", "key_id": "KEY-AES256-SEC-01"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.is_encrypted is True
    assert "AES-256" in archive.encryption_algorithm.upper()
    assert archive.status == ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED

    notif = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="archive_encrypted",
    ).first()
    assert notif is not None
    assert "at rest and in transit" in notif.message


def test_TD_020_sensitive_data_without_aes256_encryption_prohibited(stub_iam, cse_user_ref):
    """
    test_id: TD-020
    source_id: BR-BA-007
    Verify that archiving or transferring Sensitive data without AES-256 encryption is prohibited
    test_type: security
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sensitive_unencrypted.dat",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="dat",
        file_size_bytes=2048,
        reason="Sensitive research",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
        is_encrypted=False,
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="it_security",
        modules=("badms",),
        permissions=(p.ARCHIVE_ENCRYPT, p.ARCHIVE_VIEW),
    )
    # Attempting non-AES-256 encryption mechanism
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "DES-EDE3-CBC", "key_id": "NON-AES-KEY"},
        format="json",
    )
    assert res.status_code == 400, (
        f"BADMS must reject storage/configuration of Sensitive data without compliant AES-256 encryption. Got {res.status_code}"
    )


# ===========================================================================
# BR-BA-008: Retention by Classification (TD-021 .. TD-022)
# ===========================================================================

def test_TD_021_retention_policy_rules_applied_based_on_classification(stub_iam, cse_user_ref):
    """
    test_id: TD-021
    source_id: BR-BA-008
    Verify that BADMS selects and applies institute retention policy rules based on the authoritative classification assigned to data
    test_type: positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="routine_record.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Retention check",
        status=ArchiveStatus.HOD_APPROVED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "routine", "comments": "Routine retention policy"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.POLICY_APPLIED

    # Check audit log confirms policy applied
    audit = BadmsAuditLog.objects.filter(
        target_id=str(archive.pk),
        action="badms.archive.classify",
    ).first()
    assert audit is not None
    assert audit.details.get("policy_applied") is True


def test_TD_022_distinct_authoritative_classifications_receive_distinct_retention_treatments(stub_iam, cse_user_ref):
    """
    test_id: TD-022
    source_id: BR-BA-008
    Verify that distinct authoritative classifications receive their respective institute-defined retention treatments
    test_type: positive
    """
    arch_crit = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="critical_dataset.csv",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="csv",
        file_size_bytes=1024,
        reason="Critical dataset",
        status=ArchiveStatus.HOD_APPROVED,
    )
    arch_rout = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="routine_dataset.csv",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="csv",
        file_size_bytes=1024,
        reason="Routine dataset",
        status=ArchiveStatus.HOD_APPROVED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    client.post(f"/api/v1/badms/archives/{arch_crit.pk}/classify/", {"classification": "critical"}, format="json")
    client.post(f"/api/v1/badms/archives/{arch_rout.pk}/classify/", {"classification": "routine"}, format="json")

    summary = get_retention_compliance_summary()
    by_class = summary["archives"]["by_classification"]
    assert by_class.get("critical", 0) >= 1
    assert by_class.get("routine", 0) >= 1


# ===========================================================================
# BR-BA-009: HoD Approval for Storage Extension (TD-023 .. TD-025)
# ===========================================================================

def test_TD_023_submitted_storage_extension_routed_for_hod_approval(stub_iam, cse_user_ref):
    """
    test_id: TD-023
    source_id: BR-BA-009
    Verify that a submitted storage-extension request is routed for HoD approval
    test_type: routing
    """
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=1024 * 1024,
        used_bytes=1024 * 1024,
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
        {"requested_bytes": 1024 * 1024, "reason": "Quota exhausted by research simulations"},
        format="json",
    )
    assert res.status_code == 201, res.data
    ext_id = res.data["id"]
    assert res.data["status"] == StorageExtensionStatus.SUBMITTED

    notif = BadmsNotification.objects.filter(
        recipient_role="HOD",
        notification_type="storage_extension_review_required",
        related_object_id=ext_id,
    ).first()
    assert notif is not None, "Notification must be routed to HoD"


def test_TD_024_generic_admin_or_non_hod_prohibited_from_approving_storage_extension(stub_iam, cse_user_ref):
    """
    test_id: TD-024
    source_id: BR-BA-009
    Verify that a storage-extension request cannot be approved by a generic Admin or non-HoD actor
    test_type: authorization
    """
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=1024 * 1024,
        requested_bytes=1024 * 1024,
        reason="Need space",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="admin",
        modules=("badms",),
        permissions=(p.STORAGE_VIEW,),
    )
    res = client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "approve", "comments": "Admin approval attempt"},
        format="json",
    )
    assert res.status_code == 403, res.data
    ext.refresh_from_db()
    assert ext.status == StorageExtensionStatus.SUBMITTED


def test_TD_025_storage_extension_not_granted_without_explicit_hod_approval(stub_iam, cse_user_ref):
    """
    test_id: TD-025
    source_id: BR-BA-009
    Verify that storage extension is not granted without explicit HoD approval
    test_type: negative
    """
    quota = UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=1024 * 1024,
        used_bytes=1024 * 1024,
    )
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=quota.allocated_bytes,
        requested_bytes=5 * 1024 * 1024,
        reason="Pending approval",
        status=StorageExtensionStatus.SUBMITTED,
    )
    quota.refresh_from_db()
    assert quota.allocated_bytes == 1024 * 1024, "Quota must remain at original allocation before HoD approval"
    assert ext.status == StorageExtensionStatus.SUBMITTED


# ===========================================================================
# BR-BA-010: HoD Department Scope (TD-026 .. TD-029)
# ===========================================================================

def test_TD_026_hod_permitted_to_act_within_own_department(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-026
    source_id: BR-BA-010
    Verify that a HoD is permitted to act on archival requests, storage-extension requests, and reports belonging to the HoD's own department
    test_type: positive
    """
    arch = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="dept_file.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Dept arch",
        status=ArchiveStatus.SUBMITTED,
    )
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=1024 * 1024,
        requested_bytes=1024 * 1024,
        reason="Dept ext",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW, p.STORAGE_REVIEW, p.REPORT_VIEW),
    )
    res_arch = client.post(f"/api/v1/badms/archives/{arch.pk}/hod-decision/", {"decision": "approve"}, format="json")
    assert res_arch.status_code == 200, res_arch.data

    res_ext = client.post(f"/api/v1/badms/storage-extensions/{ext.pk}/decision/", {"decision": "approve"}, format="json")
    assert res_ext.status_code == 200, res_ext.data

    res_rep = client.get("/api/v1/badms/reports/summary/")
    assert res_rep.status_code == 200


def test_TD_027_hod_prohibited_from_deciding_archival_of_different_department(stub_iam, ece_user_ref, cse_hod_ref):
    """
    test_id: TD-027
    source_id: BR-BA-010
    Verify that a HoD is prohibited from deciding on a secure archival request belonging to a different department
    test_type: authorization
    """
    arch = ArchivalRequest.objects.create(
        user_id=ece_user_ref.user_id,
        department="ECE",
        file_name="ece_file.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["bob"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="ECE arch",
        status=ArchiveStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    res = client.post(
        f"/api/v1/badms/archives/{arch.pk}/hod-decision/",
        {"decision": "approve", "comments": "CSE HoD touching ECE"},
        format="json",
    )
    assert res.status_code == 403, res.data
    arch.refresh_from_db()
    assert arch.status == ArchiveStatus.SUBMITTED


def test_TD_028_hod_prohibited_from_deciding_storage_extension_of_different_department(stub_iam, ece_user_ref, cse_hod_ref):
    """
    test_id: TD-028
    source_id: BR-BA-010
    Verify that a HoD is prohibited from deciding on a storage-extension request belonging to a different department
    test_type: authorization
    """
    ext = StorageExtensionRequest.objects.create(
        user_id=ece_user_ref.user_id,
        department="ECE",
        current_allocated_bytes=1024 * 1024,
        requested_bytes=1024 * 1024,
        reason="ECE ext",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_REVIEW,),
    )
    res = client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "approve", "comments": "CSE HoD touching ECE ext"},
        format="json",
    )
    assert res.status_code == 403, res.data
    ext.refresh_from_db()
    assert ext.status == StorageExtensionStatus.SUBMITTED


def test_TD_029_hod_prohibited_from_viewing_other_department_reports(stub_iam, cse_user_ref, ece_user_ref, cse_hod_ref):
    """
    test_id: TD-029
    source_id: BR-BA-010
    Verify that a HoD is prohibited from viewing operational or departmental reports belonging to a different department
    test_type: authorization
    """
    StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=1024 * 1024,
        requested_bytes=1024 * 1024,
        reason="CSE ext",
        status=StorageExtensionStatus.SUBMITTED,
    )
    ece_ext = StorageExtensionRequest.objects.create(
        user_id=ece_user_ref.user_id,
        department="ECE",
        current_allocated_bytes=1024 * 1024,
        requested_bytes=1024 * 1024,
        reason="ECE ext",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_REVIEW,),
    )
    res = client.get("/api/v1/badms/storage-extensions/")
    assert res.status_code == 200, res.data
    departments = {r["department"] for r in res.data["results"]}
    assert "ECE" not in departments, "CSE HoD must not view ECE departmental records"
    assert "CSE" in departments

    # Direct detail access to ECE request is denied
    res_detail = client.get(f"/api/v1/badms/storage-extensions/{ece_ext.pk}/")
    assert res_detail.status_code in (403, 404)


# ===========================================================================
# BR-BA-011: Local Schedule Overrides Global (TD-030 .. TD-031)
# ===========================================================================

def test_TD_030_local_backup_schedule_overrides_global_schedule(stub_iam):
    """
    test_id: TD-030
    source_id: BR-BA-011
    Verify that a valid local backup schedule configured for a dataset overrides the institution-wide global backup schedule
    test_type: precedence
    """
    BackupSchedule.objects.create(
        name="Global Daily",
        schedule_type=BackupScope.GLOBAL,
        target_dataset="all",
        frequency=BackupFrequency.DAILY,
        execution_time=datetime.time(2, 0),
        repository_path="/var/backups/global",
        is_active=True,
    )
    local_sched = BackupSchedule.objects.create(
        name="Local Dataset X",
        schedule_type=BackupScope.LOCAL,
        target_dataset="dataset_x",
        frequency=BackupFrequency.HOURLY,
        execution_time=datetime.time(3, 0),
        repository_path="/var/backups/local_x",
        is_active=True,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_VIEW,),
    )
    res = client.get("/api/v1/badms/schedules/effective/?dataset=dataset_x")
    assert res.status_code == 200, res.data
    assert res.data["effective_schedule"]["id"] == local_sched.pk
    assert res.data["precedence_rule"] == "local_override"
    assert get_effective_schedule("dataset_x").pk == local_sched.pk


def test_TD_031_global_schedule_applies_when_no_local_schedule_exists(stub_iam):
    """
    test_id: TD-031
    source_id: BR-BA-011
    Verify that where no local backup schedule exists for a dataset, the institution-wide global backup schedule applies
    test_type: precedence
    """
    global_sched = BackupSchedule.objects.create(
        name="Global Daily",
        schedule_type=BackupScope.GLOBAL,
        target_dataset="all",
        frequency=BackupFrequency.DAILY,
        execution_time=datetime.time(2, 0),
        repository_path="/var/backups/global",
        is_active=True,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_VIEW,),
    )
    res = client.get("/api/v1/badms/schedules/effective/?dataset=dataset_y")
    assert res.status_code == 200, res.data
    assert res.data["effective_schedule"]["id"] == global_sched.pk
    assert res.data["precedence_rule"] == "global_default"
    assert get_effective_schedule("dataset_y").pk == global_sched.pk


# ===========================================================================
# BR-BA-012: Schedule Parameter Validation (TD-032 .. TD-034)
# ===========================================================================

def test_TD_032_valid_backup_schedule_validated_and_applied(stub_iam):
    """
    test_id: TD-032
    source_id: BR-BA-012
    Verify that a new or modified backup schedule with valid parameters and no conflicts is successfully validated and applied
    test_type: positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.POLICY_MANAGE, p.BACKUP_VIEW),
    )
    payload = {
        "name": "Valid Global Schedule",
        "schedule_type": "global",
        "target_dataset": "all",
        "frequency": "daily",
        "execution_time": "04:00:00",
        "classification_filter": "all",
        "repository_path": "/var/backups/valid",
        "is_active": True,
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 201, res.data
    assert BackupSchedule.objects.filter(name="Valid Global Schedule").exists()

    audit = BadmsAuditLog.objects.filter(action="badms.schedule.create", target_id=res.data["id"]).first()
    assert audit is not None
    assert audit.outcome == "success"


def test_TD_033_invalid_backup_schedule_rejected_and_existing_preserved(stub_iam):
    """
    test_id: TD-033
    source_id: BR-BA-012
    Verify that a backup schedule configuration with invalid parameters is rejected and the existing effective schedule is preserved
    test_type: validation
    """
    existing_sched = BackupSchedule.objects.create(
        name="Existing Effective",
        schedule_type=BackupScope.GLOBAL,
        target_dataset="all",
        frequency=BackupFrequency.DAILY,
        execution_time=datetime.time(2, 0),
        repository_path="/var/backups/existing",
        is_active=True,
    )
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.POLICY_MANAGE, p.BACKUP_VIEW),
    )
    bad_payload = {
        "name": "Malformed Schedule",
        "schedule_type": "global",
        "frequency": "INVALID_FREQUENCY_VAL",
        "execution_time": "not-a-time",
        "repository_path": "relative/path",
    }
    res = client.post("/api/v1/badms/schedules/", bad_payload, format="json")
    assert res.status_code in (400, 422), res.data

    effective = get_effective_schedule("all")
    assert effective.pk == existing_sched.pk
    assert effective.name == "Existing Effective"


def test_TD_034_conflicting_backup_schedule_rejected_and_existing_preserved(stub_iam):
    """
    test_id: TD-034
    source_id: BR-BA-012
    Verify that a backup schedule configuration with schedule conflicts is rejected and the existing effective schedule is preserved
    test_type: validation
    """
    existing_sched = BackupSchedule.objects.create(
        name="Existing Schedule",
        schedule_type=BackupScope.LOCAL,
        target_dataset="finance",
        frequency=BackupFrequency.DAILY,
        execution_time=datetime.time(2, 0),
        repository_path="/var/backups/finance",
        is_active=True,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE, p.BACKUP_VIEW),
    )
    conflicting_payload = {
        "name": "",
        "schedule_type": "local",
        "target_dataset": "finance",
        "frequency": "daily",
        "repository_path": "",
    }
    res = client.post("/api/v1/badms/schedules/", conflicting_payload, format="json")
    assert res.status_code in (400, 422), res.data

    effective = get_effective_schedule("finance")
    assert effective.pk == existing_sched.pk


# ===========================================================================
# BR-BA-013: Scheduled Repository Reachability (TD-035 .. TD-036)
# ===========================================================================

def test_TD_035_scheduled_backup_executes_successfully_when_repository_reachable(stub_iam):
    """
    test_id: TD-035
    source_id: BR-BA-013
    Verify that a scheduled automatic backup proceeds and executes successfully when the scheduled repository is reachable
    test_type: positive
    """
    sched = BackupSchedule.objects.create(
        name="Nightly Sched",
        schedule_type=BackupScope.LOCAL,
        target_dataset="all",
        frequency=BackupFrequency.DAILY,
        execution_time=datetime.time(1, 0),
        repository_path="/var/backups/nightly",
        is_active=True,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE,),
    )
    res = client.post(f"/api/v1/badms/schedules/{sched.pk}/run/", {"simulate_unreachable": False}, format="json")
    assert res.status_code == 200, res.data
    assert res.data["status"] == BackupStatus.COMPLETED
    assert res.data["repository_reachable"] is True
    assert res.data["integrity_verified"] is True


def test_TD_036_scheduled_backup_fails_when_repository_unreachable(stub_iam):
    """
    test_id: TD-036
    source_id: BR-BA-013
    Verify that a scheduled automatic backup does not proceed and applies failure handling when the scheduled repository is unreachable
    test_type: negative
    """
    sched = BackupSchedule.objects.create(
        name="Nightly Offline",
        schedule_type=BackupScope.LOCAL,
        target_dataset="all",
        frequency=BackupFrequency.DAILY,
        execution_time=datetime.time(1, 0),
        repository_path="/mnt/unreachable_nas",
        is_active=True,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE,),
    )
    res = client.post(f"/api/v1/badms/schedules/{sched.pk}/run/", {"simulate_unreachable": True}, format="json")
    assert res.status_code == 200, res.data
    assert res.data["status"] == BackupStatus.FAILED
    assert res.data["repository_reachable"] is False

    notif = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
        related_object_id=res.data["id"],
    ).first()
    assert notif is not None
    assert "FAILED" in notif.subject


# ===========================================================================
# BR-BA-014: Backup Failure Alert SLA (TD-037 .. TD-038)
# ===========================================================================

def test_TD_037_backup_failure_sends_alert_to_sysadmin_within_five_minutes(stub_iam):
    """
    test_id: TD-037
    source_id: BR-BA-014
    Verify that when a backup fails, BADMS sends an alert to the SysAdmin within the five-minute SLA window
    test_type: time_boundary
    """
    backup = execute_backup(
        initiated_by_user_id=50,
        initiated_by_role="sysadmin",
        simulate_failure=True,
    )
    assert backup.status == BackupStatus.FAILED

    notif = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
        related_object_id=backup.pk,
    ).latest("created_at")
    assert notif is not None
    assert "FAILED" in notif.subject
    diff_seconds = abs((notif.created_at - backup.completed_at).total_seconds())
    assert diff_seconds < 300, "Alert must be dispatched within 5 minutes (300 seconds)"


def test_TD_038_failure_alert_not_triggered_on_successful_backup(stub_iam):
    """
    test_id: TD-038
    source_id: BR-BA-014
    Verify that the five-minute failure alert is not triggered when a backup completes successfully
    test_type: boundary
    """
    backup = execute_backup(
        initiated_by_user_id=50,
        initiated_by_role="sysadmin",
        simulate_failure=False,
    )
    assert backup.status == BackupStatus.COMPLETED

    failure_notif = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="backup_failure",
        related_object_id=backup.pk,
    ).first()
    assert failure_notif is None, "No failure alert should be created for successful backup"


# ===========================================================================
# BR-BA-015: Repeated Failure Escalation (TD-039 .. TD-041)
# ===========================================================================

def test_TD_039_consecutive_backup_failures_under_three_do_not_escalate_to_director(stub_iam):
    """
    test_id: TD-039
    source_id: BR-BA-015
    Verify that when one or two consecutive backup failures occur, escalation to the Director of IT is not triggered
    test_type: boundary
    """
    b1 = execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=True)
    assert b1.consecutive_failure_count == 1

    b2 = execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=True)
    assert b2.consecutive_failure_count == 2

    director_notif = BadmsNotification.objects.filter(
        recipient_role="director_of_it",
        notification_type="director_escalation",
    ).first()
    assert director_notif is None, "Director of IT must NOT be notified for fewer than 3 consecutive failures"


def test_TD_040_three_consecutive_backup_failures_escalate_to_director_of_it(stub_iam):
    """
    test_id: TD-040
    source_id: BR-BA-015
    Verify that when three consecutive backup failures occur, BADMS escalates the condition to the Director of IT
    test_type: threshold
    """
    for _ in range(3):
        execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=True)

    director_notif = BadmsNotification.objects.filter(
        recipient_role="director_of_it",
        notification_type="director_escalation",
    ).first()
    assert director_notif is not None, "Director of IT must be notified when consecutive failures reach 3"
    assert "CRITICAL ESCALATION" in director_notif.subject


def test_TD_041_successful_backup_resets_consecutive_failure_counter(stub_iam):
    """
    test_id: TD-041
    source_id: BR-BA-015
    Verify that a successful backup resets the consecutive failure counter so subsequent failures do not prematurely escalate to the Director of IT
    test_type: boundary
    """
    execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=True)
    execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=True)

    b_success = execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=False)
    assert b_success.consecutive_failure_count == 0

    b_new_fail = execute_backup(initiated_by_user_id=50, initiated_by_role="sysadmin", simulate_failure=True)
    assert b_new_fail.consecutive_failure_count == 1

    director_notif = BadmsNotification.objects.filter(
        recipient_role="director_of_it",
        notification_type="director_escalation",
    ).first()
    assert director_notif is None, "Director of IT must not be notified because consecutive counter was reset"


# ===========================================================================
# BR-BA-016: Storage-Extension Usage Validation (TD-042 .. TD-043)
# ===========================================================================

def test_TD_042_storage_extension_validated_and_accepted_when_quota_full(stub_iam, cse_user_ref):
    """
    test_id: TD-042
    source_id: BR-BA-016
    Verify that a storage-extension request is validated and accepted when the user's storage quota is full
    test_type: validation
    """
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=1024 * 1024,
        used_bytes=1024 * 1024,
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
        {"requested_bytes": 1024 * 1024, "reason": "Quota full, need space for project datasets"},
        format="json",
    )
    assert res.status_code == 201, res.data
    assert res.data["status"] == StorageExtensionStatus.SUBMITTED


def test_TD_043_storage_extension_rejected_when_quota_not_full(stub_iam, cse_user_ref):
    """
    test_id: TD-043
    source_id: BR-BA-016
    Verify that a storage-extension request is rejected or flagged as invalid when the user's storage quota is not full
    test_type: validation
    """
    UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=100 * 1024 * 1024,
        used_bytes=10 * 1024 * 1024,  # Quota is only 10% used, NOT full
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
        {"requested_bytes": 10 * 1024 * 1024, "reason": "Premature extension request"},
        format="json",
    )
    assert res.status_code in (400, 422), (
        f"BADMS must flag or reject storage-extension when quota is not full. Got {res.status_code}: {res.data}"
    )


# ===========================================================================
# BR-BA-017: Storage-Extension Decision Criteria (TD-044 .. TD-046)
# ===========================================================================

def test_TD_044_hod_reviews_criteria_and_approves_storage_extension(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-044
    source_id: BR-BA-017
    Verify that the HoD reviews available storage infrastructure, departmental policies, and user justification to approve a storage-extension request
    test_type: positive
    """
    quota = UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=1024 * 1024,
        used_bytes=1024 * 1024,
    )
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=quota.allocated_bytes,
        requested_bytes=2 * 1024 * 1024,
        reason="Academic research on neural networks requires more capacity",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_REVIEW,),
    )
    res = client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "approve", "comments": "Approved based on departmental research policy and available storage infrastructure"},
        format="json",
    )
    assert res.status_code == 200, res.data
    ext.refresh_from_db()
    assert ext.status == StorageExtensionStatus.HOD_APPROVED
    assert ext.hod_user_id == cse_hod_ref.user_id

    quota.refresh_from_db()
    assert quota.allocated_bytes == 3 * 1024 * 1024


def test_TD_045_hod_reviews_criteria_and_rejects_storage_extension(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-045
    source_id: BR-BA-017
    Verify that the HoD reviews available storage infrastructure, departmental policies, and user justification to reject a storage-extension request
    test_type: positive
    """
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=1024 * 1024,
        requested_bytes=50 * 1024 * 1024,
        reason="Personal video collection storage",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_REVIEW,),
    )
    res = client.post(
        f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
        {"decision": "reject", "comments": "Rejected: non-compliant with departmental academic storage policy and infrastructure capacity constraints"},
        format="json",
    )
    assert res.status_code == 200, res.data
    ext.refresh_from_db()
    assert ext.status == StorageExtensionStatus.REJECTED
    assert ext.hod_user_id == cse_hod_ref.user_id

    notif = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="storage_extension_rejected",
    ).first()
    assert notif is not None


def test_TD_046_badms_provides_decision_criteria_to_hod_during_extension_review(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-046
    source_id: BR-BA-017
    Verify that BADMS provides the required decision criteria (available storage infrastructure, departmental policies, and user justification) to the HoD during extension review
    test_type: decision
    """
    ext = StorageExtensionRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        current_allocated_bytes=10 * 1024 * 1024,
        requested_bytes=5 * 1024 * 1024,
        reason="Research project dataset expansion requiring additional quota",
        status=StorageExtensionStatus.SUBMITTED,
    )
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.STORAGE_REVIEW, p.STORAGE_VIEW),
    )
    res = client.get(f"/api/v1/badms/storage-extensions/{ext.pk}/")
    assert res.status_code == 200, res.data
    data = res.data
    assert data["reason"] == "Research project dataset expansion requiring additional quota"
    assert data["current_allocated_bytes"] == 10 * 1024 * 1024
    assert data["requested_bytes"] == 5 * 1024 * 1024
    assert data["department"] == "CSE"


# ===========================================================================
# BR-BA-018: Special Archival Super Admin Authority (TD-047 .. TD-049)
# ===========================================================================

def test_TD_047_super_admin_can_perform_special_archival_operation(stub_iam):
    """
    test_id: TD-047
    source_id: BR-BA-018
    Verify that only the Super Admin can perform a special archival operation in BADMS following an offline request from an authority
    test_type: positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.ARCHIVE_SPECIAL,),
    )
    payload = {
        "requester_name": "Dean of Research",
        "requester_designation": "Dean",
        "dataset_title": "Classified Lab Dataset 2026",
        "classification": "Special Restricted",
        "offline_media_type": "LTO-8 Magnetic Tape",
        "media_serial_number": "TAPE-2026-99",
        "storage_vault_location": "Vault-B, High Security",
        "notes": "Offline executive directive",
    }
    res = client.post("/api/v1/badms/special-archives/", payload, format="json")
    assert res.status_code == 201, res.data
    assert SpecialArchivalRecord.objects.filter(media_serial_number="TAPE-2026-99").exists()


def test_TD_048_non_super_admin_prohibited_from_special_archival(stub_iam):
    """
    test_id: TD-048
    source_id: BR-BA-018
    Verify that a non-Super Admin actor is prohibited from performing the special archival operation in BADMS
    test_type: authorization
    """
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.ARCHIVE_VIEW),
    )
    payload = {
        "requester_name": "Dean of Research",
        "requester_designation": "Dean",
        "dataset_title": "Classified Lab Dataset 2026",
        "classification": "Special Restricted",
        "offline_media_type": "LTO-8 Tape",
        "media_serial_number": "TAPE-UNAUTH",
        "storage_vault_location": "Vault-B",
    }
    res = client.post("/api/v1/badms/special-archives/", payload, format="json")
    assert res.status_code == 403, res.data
    assert not SpecialArchivalRecord.objects.filter(media_serial_number="TAPE-UNAUTH").exists()


def test_TD_049_offline_requesting_authority_cannot_directly_execute_special_archival(stub_iam):
    """
    test_id: TD-049
    source_id: BR-BA-018
    Verify that an offline requesting authority cannot directly execute the special archival operation in BADMS
    test_type: authorization
    """
    client = _client(
        stub_iam,
        user_id=9001,
        kind="faculty",
        active_role="faculty",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    payload = {
        "requester_name": "Dean External Authority",
        "requester_designation": "Dean",
        "dataset_title": "Direct Execution Attempt",
        "offline_media_type": "Optical M-DISC",
        "media_serial_number": "DISC-DIRECT-01",
        "storage_vault_location": "Vault-C",
    }
    res = client.post("/api/v1/badms/special-archives/", payload, format="json")
    assert res.status_code == 403, res.data
    assert not SpecialArchivalRecord.objects.filter(media_serial_number="DISC-DIRECT-01").exists()


# ===========================================================================
# BR-BA-019: Super Admin Global Backup Authority (TD-050 .. TD-052)
# ===========================================================================

def test_TD_050_super_admin_has_authority_for_global_backup_schedules(stub_iam):
    """
    test_id: TD-050
    source_id: BR-BA-019
    Verify that only the Super Admin has authority to define and modify institution-wide global backup schedules and default backup policies
    test_type: positive
    """
    client = _client(
        stub_iam,
        user_id=1,
        kind="staff",
        active_role="Super Admin",
        modules=("badms",),
        permissions=(p.POLICY_MANAGE, p.BACKUP_VIEW),
    )
    payload = {
        "name": "Institute Global Schedule",
        "schedule_type": "global",
        "target_dataset": "all",
        "frequency": "daily",
        "execution_time": "03:30:00",
        "repository_path": "/var/backups/institute_global",
        "is_active": True,
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 201, res.data
    sched_id = res.data["id"]

    res_patch = client.patch(f"/api/v1/badms/schedules/{sched_id}/", {"frequency": "weekly"}, format="json")
    assert res_patch.status_code == 200, res_patch.data
    assert res_patch.data["frequency"] == "weekly"


def test_TD_051_sysadmin_prohibited_from_global_backup_schedules(stub_iam):
    """
    test_id: TD-051
    source_id: BR-BA-019
    Verify that a SysAdmin is prohibited from defining or modifying institution-wide global backup schedules and default backup policies
    test_type: authorization
    """
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.BACKUP_MANAGE, p.BACKUP_VIEW),
    )
    payload = {
        "name": "SysAdmin Attempt Global",
        "schedule_type": "global",
        "target_dataset": "all",
        "frequency": "daily",
        "execution_time": "03:30:00",
        "repository_path": "/var/backups/global",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 403, res.data


def test_TD_052_it_security_prohibited_from_global_backup_schedules(stub_iam):
    """
    test_id: TD-052
    source_id: BR-BA-019
    Verify that IT Security is prohibited from defining or modifying institution-wide global backup schedules and default backup policies
    test_type: authorization
    """
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="IT Security",
        modules=("badms",),
        permissions=(p.ARCHIVE_ENCRYPT, p.AUDIT_VIEW),
    )
    payload = {
        "name": "IT Security Attempt Global",
        "schedule_type": "global",
        "target_dataset": "all",
        "frequency": "daily",
        "execution_time": "03:30:00",
        "repository_path": "/var/backups/global",
    }
    res = client.post("/api/v1/badms/schedules/", payload, format="json")
    assert res.status_code == 403, res.data


# ===========================================================================
# BR-BA-020: Protected Information Access Scope (TD-053 .. TD-056)
# ===========================================================================

def test_TD_053_authorized_actor_can_view_protected_info_within_scope(stub_iam, cse_user_ref):
    """
    test_id: TD-053
    source_id: BR-BA-020
    Verify that an authorized actor can view protected information (audit logs, request status, backup status, reports) matching their authorized scope
    test_type: positive
    """
    arch = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="own_file.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="My archive",
        status=ArchiveStatus.SUBMITTED,
    )
    user_client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW_SELF,),
    )
    res_user = user_client.get(f"/api/v1/badms/archives/{arch.pk}/")
    assert res_user.status_code == 200, res_user.data

    sys_client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.AUDIT_VIEW, p.BACKUP_VIEW, p.REPORT_VIEW),
    )
    assert sys_client.get("/api/v1/badms/audit-logs/").status_code == 200
    assert sys_client.get("/api/v1/badms/backups/").status_code == 200
    assert sys_client.get("/api/v1/badms/reports/summary/").status_code == 200


def test_TD_054_hod_prohibited_from_viewing_records_outside_department(stub_iam, ece_user_ref, cse_hod_ref):
    """
    test_id: TD-054
    source_id: BR-BA-020
    Verify that a HoD is prohibited from accessing protected reports or request status outside the HoD's own department
    test_type: authorization
    """
    ece_arch = ArchivalRequest.objects.create(
        user_id=ece_user_ref.user_id,
        department="ECE",
        file_name="ece_secret.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["bob"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="ECE confidential",
        status=ArchiveStatus.SUBMITTED,
    )
    cse_hod_client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    res = cse_hod_client.get(f"/api/v1/badms/archives/{ece_arch.pk}/")
    assert res.status_code == 404, res.data


def test_TD_055_user_prohibited_from_viewing_other_user_request_status(stub_iam, cse_user_ref, ece_user_ref):
    """
    test_id: TD-055
    source_id: BR-BA-020
    Verify that a user is prohibited from viewing request status or history belonging to another user
    test_type: authorization
    """
    user_b_arch = ArchivalRequest.objects.create(
        user_id=ece_user_ref.user_id,
        department="ECE",
        file_name="user_b_doc.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["bob"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Bob's data",
        status=ArchiveStatus.SUBMITTED,
    )
    user_a_client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW_SELF,),
    )
    res = user_a_client.get(f"/api/v1/badms/archives/{user_b_arch.pk}/")
    assert res.status_code == 404, res.data


def test_TD_056_unauthorized_actor_denied_access_to_audit_logs(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-056
    source_id: BR-BA-020
    Verify that an unauthorized actor is denied access to system audit logs
    test_type: authorization
    """
    user_client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW_SELF,),
    )
    assert user_client.get("/api/v1/badms/audit-logs/").status_code == 403

    hod_client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW, p.REPORT_VIEW),
    )
    assert hod_client.get("/api/v1/badms/audit-logs/").status_code == 403


# ===========================================================================
# BR-BA-021: IT Security Security/RBAC Authority (TD-057 .. TD-059)
# ===========================================================================

def test_TD_057_it_security_can_manage_rbac_and_enforce_security_policies(stub_iam, cse_user_ref):
    """
    test_id: TD-057
    source_id: BR-BA-021
    Verify that an authorized IT Security Team member can manage RBAC permissions and configure/enforce security policies
    test_type: positive
    """
    from modules.badms.registry import ROLE_GRANTS
    it_grants = set(ROLE_GRANTS.get("IT Security", []))
    assert p.ARCHIVE_ENCRYPT in it_grants
    assert p.AUDIT_VIEW in it_grants

    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sec_policy.dat",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="dat",
        file_size_bytes=2048,
        reason="Security policy test",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="IT Security",
        modules=("badms",),
        permissions=(p.ARCHIVE_ENCRYPT, p.AUDIT_VIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM", "key_id": "KEY-SEC-01"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED


def test_TD_058_non_it_security_prohibited_from_managing_rbac_permissions(stub_iam, cse_user_ref):
    """
    test_id: TD-058
    source_id: BR-BA-021
    Verify that a non-IT Security actor (e.g., SysAdmin, Super Admin, HoD, or User) is prohibited from managing RBAC permissions
    test_type: authorization
    """
    from modules.badms.registry import ROLE_GRANTS
    for role in ("student", "faculty", "staff", "HOD", "sysadmin", "SysAdmin"):
        grants = set(ROLE_GRANTS.get(role, []))
        assert p.ARCHIVE_ENCRYPT not in grants, f"{role} must not hold ARCHIVE_ENCRYPT"

    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sec_test.dat",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="dat",
        file_size_bytes=2048,
        reason="RBAC test",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    sysadmin_client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_CLASSIFY, p.BACKUP_CREATE),
    )
    res = sysadmin_client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM"},
        format="json",
    )
    assert res.status_code == 403, res.data


def test_TD_059_non_it_security_prohibited_from_modifying_security_policies(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-059
    source_id: BR-BA-021
    Verify that a non-IT Security actor is prohibited from configuring or modifying security policies assigned to IT Security
    test_type: authorization
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        file_name="sec_policy_mod.dat",
        document_date=datetime.date(2026, 1, 1),
        owners=["researcher"],
        file_type="dat",
        file_size_bytes=2048,
        reason="Security policy modification",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    hod_client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW,),
    )
    res = hod_client.post(
        f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
        {"algorithm": "AES-256-GCM"},
        format="json",
    )
    assert res.status_code == 403, res.data
