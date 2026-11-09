"""
BADMS Workflow Tests
====================
Implements all 53 frozen test designs (TD-001 through TD-053) from `a8_design/WF_DESIGN.json`.

Specifications:
  - a8_specs/01_BA_Problem_Statement_v1.2_SYNCHRONIZED_DRAFT.docx
  - a8_specs/05_BA_Workflow_Specifications_v1.1_FINAL.docx

Workflows covered:
  BW-BA-01 (TD-001 .. TD-005): Secure Archival - HoD Rejection
  BW-BA-02 (TD-006 .. TD-010): Secure Archival - Approved, Non-Sensitive Classification
  BW-BA-03 (TD-011 .. TD-015): Secure Archival - Approved, Sensitive Encryption
  CW-BA-01 (TD-016 .. TD-021): Secure Archival Request Processing (Composite)
  BW-BA-04 (TD-022 .. TD-026): Storage Extension - Rejected
  BW-BA-05 (TD-027 .. TD-031): Storage Extension - Approved
  CW-BA-02 (TD-032 .. TD-035): Storage-Extension Request Processing (Composite)
  BW-BA-06 (TD-036 .. TD-040): Restoration - Non-Sensitive Standard Path
  BW-BA-07 (TD-041 .. TD-047): Restoration - Sensitive SysAdmin Approval
  CW-BA-03 (TD-048 .. TD-053): Data Restoration Processing (Composite)

Conventions:
  - pytestmark = pytest.mark.django_db
  - stub_iam replaces the IAM client
  - Directory UserRef rows created for department scoping
  - No production code modified
"""

from __future__ import annotations

import datetime
import pytest
from rest_framework.test import APIClient

from conftest import make_session
from modules.badms.domain import permissions as p
from modules.badms.models import (
    ArchivalRequest,
    ArchiveClassification,
    ArchiveStatus,
    BadmsAuditLog,
    BadmsNotification,
    RestorationRequest,
    RestorationStatus,
    StorageExtensionRequest,
    StorageExtensionStatus,
    UserStorageQuota,
)
from modules.directory.models import UserRef

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Shared helpers and fixtures
# ---------------------------------------------------------------------------

def _client(stub_iam, **session_kw):
    """Build an APIClient with mocked IAM principal session."""
    stub_iam(make_session(**session_kw))
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION="Token fake-token")
    return c


@pytest.fixture(autouse=True)
def _setup_directory_refs():
    """Ensure directory projections exist for all participating test actors."""
    UserRef.objects.get_or_create(
        user_id=1001,
        defaults={
            "username": "u1001",
            "display_name": "CSE Student",
            "kind": "student",
            "department": "CSE",
            "discipline": "CSE",
            "is_active": True,
        },
    )
    UserRef.objects.get_or_create(
        user_id=1002,
        defaults={
            "username": "u1002",
            "display_name": "ECE Student",
            "kind": "student",
            "department": "ECE",
            "discipline": "ECE",
            "is_active": True,
        },
    )
    UserRef.objects.get_or_create(
        user_id=2001,
        defaults={
            "username": "u2001",
            "display_name": "CSE HoD",
            "kind": "faculty",
            "department": "CSE",
            "discipline": "CSE",
            "is_active": True,
        },
    )
    UserRef.objects.get_or_create(
        user_id=2002,
        defaults={
            "username": "u2002",
            "display_name": "ECE HoD",
            "kind": "faculty",
            "department": "ECE",
            "discipline": "ECE",
            "is_active": True,
        },
    )
    UserRef.objects.get_or_create(
        user_id=3001,
        defaults={
            "username": "u3001",
            "display_name": "SysAdmin",
            "kind": "staff",
            "department": "IT",
            "discipline": "IT",
            "is_active": True,
        },
    )
    UserRef.objects.get_or_create(
        user_id=4001,
        defaults={
            "username": "u4001",
            "display_name": "IT Security Specialist",
            "kind": "staff",
            "department": "SECURITY",
            "discipline": "SECURITY",
            "is_active": True,
        },
    )


def _user_client(stub_iam, user_id=1001):
    return _client(
        stub_iam,
        user_id=user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(
            p.ARCHIVE_CREATE,
            p.ARCHIVE_VIEW_SELF,
            p.STORAGE_CREATE,
            p.STORAGE_VIEW_SELF,
            p.RESTORATION_CREATE,
            p.RESTORATION_VIEW_SELF,
        ),
    )


def _cse_hod_client(stub_iam, user_id=2001):
    return _client(
        stub_iam,
        user_id=user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW, p.ARCHIVE_VIEW, p.STORAGE_REVIEW, p.STORAGE_VIEW),
    )


def _ece_hod_client(stub_iam, user_id=2002):
    return _client(
        stub_iam,
        user_id=user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_REVIEW, p.ARCHIVE_VIEW, p.STORAGE_REVIEW, p.STORAGE_VIEW),
    )


def _sysadmin_client(stub_iam, user_id=3001):
    return _client(
        stub_iam,
        user_id=user_id,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(
            p.ARCHIVE_CLASSIFY,
            p.ARCHIVE_VIEW,
            p.RESTORATION_APPROVE,
            p.RESTORATION_VIEW,
            p.BACKUP_CREATE,
            p.BACKUP_VIEW,
        ),
    )


def _it_security_client(stub_iam, user_id=4001):
    return _client(
        stub_iam,
        user_id=user_id,
        kind="staff",
        active_role="it_security",
        modules=("badms",),
        permissions=(p.ARCHIVE_ENCRYPT, p.ARCHIVE_VIEW),
    )


def _make_archive(
    user_id=1001,
    department="CSE",
    status=ArchiveStatus.SUBMITTED,
    classification=ArchiveClassification.ROUTINE,
    auth_classification=None,
    is_encrypted=False,
    file_name="report.pdf",
    file_size_bytes=1024,
):
    UserStorageQuota.objects.get_or_create(
        user_id=user_id,
        defaults={"department": department, "allocated_bytes": 1024 * 1024 * 1024, "used_bytes": 0},
    )
    return ArchivalRequest.objects.create(
        user_id=user_id,
        department=department,
        file_name=file_name,
        document_date=datetime.date(2026, 1, 1),
        owners=[f"u{user_id}"],
        file_type="pdf",
        file_size_bytes=file_size_bytes,
        reason="Archival test",
        initial_classification=classification,
        authoritative_classification=auth_classification,
        is_encrypted=is_encrypted,
        status=status,
    )


def _make_storage_extension(
    user_id=1001,
    department="CSE",
    requested_bytes=1073741824,
    reason="Need additional storage for thesis datasets",
    status=StorageExtensionStatus.SUBMITTED,
):
    quota, _ = UserStorageQuota.objects.get_or_create(
        user_id=user_id,
        defaults={"department": department, "allocated_bytes": 1073741824, "used_bytes": 1073741824},
    )
    return StorageExtensionRequest.objects.create(
        user_id=user_id,
        department=department,
        current_allocated_bytes=quota.allocated_bytes,
        requested_bytes=requested_bytes,
        reason=reason,
        status=status,
    )


# ===========================================================================
# BW-BA-01: Secure Archival - HoD Rejection (TD-001 .. TD-005)
# ===========================================================================

class TestBwBa01SecureArchivalHodRejection:
    """Tests for basis workflow BW-BA-01: User submits secure archival request and HoD rejects it."""

    def test_TD_001_bw_ba_01_complete_hod_rejection(self, stub_iam):
        """
        test_id: TD-001
        source_id: BW-BA-01
        Verify complete basis workflow BW-BA-01 execution where a user submits a secure archival
        request and the respective HoD rejects it.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "thesis_draft.pdf",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "pdf",
                "file_size_bytes": 2048,
                "reason": "Preservation of master thesis",
                "initial_classification": "routine",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.status == ArchiveStatus.SUBMITTED

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        dec_res = hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "reject", "comments": "Thesis draft does not meet archival criteria."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.REJECTED
        assert archive.hod_user_id == 2001
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="archive_rejected",
            related_object_id=str(archive_id),
        ).exists()

    def test_TD_002_bw_ba_01_transition_1_submission_routes_to_hod(self, stub_iam):
        """
        test_id: TD-002
        source_id: BW-BA-01
        Verify that valid submission of a secure archival request transitions state from Not
        Submitted to Submitted and routes to the requester's HoD (Transition 1).
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        payload = {
            "file_name": "lab_notes.pdf",
            "document_date": "2026-03-02",
            "owners": ["u1001"],
            "file_type": "pdf",
            "file_size_bytes": 1024,
            "reason": "CSE lab notes preservation",
            "initial_classification": "routine",
        }
        res = u_client.post("/api/v1/badms/archives/", payload, format="json")
        assert res.status_code == 201, res.data
        assert res.data["status"] == ArchiveStatus.SUBMITTED
        archive_id = res.data["id"]
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.department == "CSE"
        assert BadmsNotification.objects.filter(
            recipient_role="HOD",
            notification_type="hod_review_required",
            related_object_id=str(archive_id),
        ).exists()

    def test_TD_003_bw_ba_01_transition_2_hod_rejection_decision(self, stub_iam):
        """
        test_id: TD-003
        source_id: BW-BA-01
        Verify that the respective HoD's rejection decision transitions the request from
        Submitted to Rejected (Transition 2).
        test_type: decision
        """
        archive = _make_archive(user_id=1001, department="CSE", status=ArchiveStatus.SUBMITTED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
            {"decision": "reject", "comments": "Rejected due to lack of academic endorsement."},
            format="json",
        )
        assert res.status_code == 200, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.REJECTED
        assert BadmsAuditLog.objects.filter(
            action="badms.archive.hod_reject",
            target_type="archive_request",
            target_id=str(archive.pk),
            outcome="rejected",
        ).exists()
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="archive_rejected",
            related_object_id=str(archive.pk),
        ).exists()

    def test_TD_004_bw_ba_01_different_department_hod_cannot_reject(self, stub_iam):
        """
        test_id: TD-004
        source_id: BW-BA-01
        Verify department-scope enforcement where an HoD from a different department cannot
        reject the request.
        test_type: authorization
        """
        archive = _make_archive(user_id=1001, department="CSE", status=ArchiveStatus.SUBMITTED)
        ece_hod = _ece_hod_client(stub_iam, user_id=2002)
        res = ece_hod.post(
            f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
            {"decision": "reject", "comments": "Cross-department reject attempt."},
            format="json",
        )
        assert res.status_code == 403, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.SUBMITTED

    def test_TD_005_bw_ba_01_hod_rejection_blocked_if_not_submitted(self, stub_iam):
        """
        test_id: TD-005
        source_id: BW-BA-01
        Verify that HoD rejection cannot be performed on a request that is not in Submitted state.
        test_type: negative
        """
        archive = _make_archive(user_id=1001, department="CSE", status=ArchiveStatus.REJECTED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
            {"decision": "reject", "comments": "Attempting reject on already rejected."},
            format="json",
        )
        assert res.status_code == 400, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.REJECTED


# ===========================================================================
# BW-BA-02: Secure Archival - Approved, Non-Sensitive Classification (TD-006 .. TD-010)
# ===========================================================================

class TestBwBa02SecureArchivalApprovedNonSensitive:
    """Tests for basis workflow BW-BA-02: User submits, HoD approves, SysAdmin classifies non-sensitive."""

    def test_TD_006_bw_ba_02_complete_approved_non_sensitive(self, stub_iam):
        """
        test_id: TD-006
        source_id: BW-BA-02
        Verify complete basis workflow BW-BA-02 execution where user submits, HoD approves,
        and SysAdmin assigns a non-Sensitive authoritative classification.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "department_minutes.pdf",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "pdf",
                "file_size_bytes": 1024,
                "reason": "Department administrative minutes",
                "initial_classification": "routine",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        hod_res = hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "approve", "comments": "Approved for institutional record."},
            format="json",
        )
        assert hod_res.status_code == 200, hod_res.data
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.status == ArchiveStatus.HOD_APPROVED

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        cls_res = sys_client.post(
            f"/api/v1/badms/archives/{archive_id}/classify/",
            {"classification": "routine", "comments": "Confirmed routine administrative record."},
            format="json",
        )
        assert cls_res.status_code == 200, cls_res.data
        archive.refresh_from_db()
        assert archive.authoritative_classification == ArchiveClassification.ROUTINE
        assert archive.status == ArchiveStatus.POLICY_APPLIED

    def test_TD_007_bw_ba_02_transition_2_hod_approval_routes_to_sysadmin(self, stub_iam):
        """
        test_id: TD-007
        source_id: BW-BA-02
        Verify that respective HoD approval transitions request from Submitted to HoD Approved
        and routes it to SysAdmin (Transition 2).
        test_type: decision
        """
        archive = _make_archive(user_id=1001, department="CSE", status=ArchiveStatus.SUBMITTED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
            {"decision": "approve", "comments": "CSE HoD endorses request."},
            format="json",
        )
        assert res.status_code == 200, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.HOD_APPROVED
        assert BadmsNotification.objects.filter(
            recipient_role="sysadmin",
            notification_type="classification_required",
            related_object_id=str(archive.pk),
        ).exists()

    def test_TD_008_bw_ba_02_transition_3_sysadmin_classifies_non_sensitive(self, stub_iam):
        """
        test_id: TD-008
        source_id: BW-BA-02
        Verify that SysAdmin assigning a non-Sensitive classification (Routine, Archival, or
        Critical) transitions request to Classified Non-Sensitive / Policy Applied (Transition 3).
        test_type: decision
        """
        archive = _make_archive(
            user_id=1001, department="CSE", status=ArchiveStatus.HOD_APPROVED
        )
        before_security_notifs = BadmsNotification.objects.filter(
            recipient_role="it_security"
        ).count()

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/archives/{archive.pk}/classify/",
            {"classification": "archival", "comments": "Classification: Archival."},
            format="json",
        )
        assert res.status_code == 200, res.data
        archive.refresh_from_db()
        assert archive.authoritative_classification == ArchiveClassification.ARCHIVAL
        assert archive.status == ArchiveStatus.POLICY_APPLIED
        assert (
            BadmsNotification.objects.filter(recipient_role="it_security").count()
            == before_security_notifs
        )

    def test_TD_009_bw_ba_02_non_sysadmin_cannot_classify_archival_request(self, stub_iam):
        """
        test_id: TD-009
        source_id: BW-BA-02
        Verify that a non-SysAdmin actor cannot assign authoritative classification to an
        approved archival request.
        test_type: authorization
        """
        archive = _make_archive(
            user_id=1001, department="CSE", status=ArchiveStatus.HOD_APPROVED
        )
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/archives/{archive.pk}/classify/",
            {"classification": "routine"},
            format="json",
        )
        assert res.status_code == 403, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.HOD_APPROVED
        assert archive.authoritative_classification is None

    def test_TD_010_bw_ba_02_sysadmin_classification_blocked_prior_to_hod_approval(self, stub_iam):
        """
        test_id: TD-010
        source_id: BW-BA-02
        Verify that SysAdmin classification cannot be performed prior to HoD approval.
        test_type: negative
        """
        archive = _make_archive(
            user_id=1001, department="CSE", status=ArchiveStatus.SUBMITTED
        )
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/archives/{archive.pk}/classify/",
            {"classification": "routine"},
            format="json",
        )
        assert res.status_code == 400, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.SUBMITTED
        assert archive.authoritative_classification is None


# ===========================================================================
# BW-BA-03: Secure Archival - Approved, Sensitive Encryption (TD-011 .. TD-015)
# ===========================================================================

class TestBwBa03SecureArchivalApprovedSensitive:
    """Tests for basis workflow BW-BA-03: Sensitive archival with IT Security encryption."""

    def test_TD_011_bw_ba_03_complete_sensitive_encryption_workflow(self, stub_iam):
        """
        test_id: TD-011
        source_id: BW-BA-03
        Verify complete basis workflow BW-BA-03 execution through submission, HoD approval,
        SysAdmin Sensitive classification, and IT Security AES-256 encryption.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "patient_trial_data.csv",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "csv",
                "file_size_bytes": 4096,
                "reason": "Clinical trial research data",
                "initial_classification": "sensitive",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        hod_res = hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "approve", "comments": "CSE HoD approves trial data archive."},
            format="json",
        )
        assert hod_res.status_code == 200, hod_res.data

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        cls_res = sys_client.post(
            f"/api/v1/badms/archives/{archive_id}/classify/",
            {"classification": "sensitive", "comments": "Confirmed Sensitive PII content."},
            format="json",
        )
        assert cls_res.status_code == 200, cls_res.data
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.status == ArchiveStatus.ROUTED_TO_SECURITY

        sec_client = _it_security_client(stub_iam, user_id=4001)
        enc_res = sec_client.post(
            f"/api/v1/badms/archives/{archive_id}/configure-encryption/",
            {"algorithm": "AES-256-GCM", "key_id": "KEY-AES256-WF-01"},
            format="json",
        )
        assert enc_res.status_code == 200, enc_res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED
        assert archive.is_encrypted is True
        assert "AES" in archive.encryption_algorithm.upper()

    def test_TD_012_bw_ba_03_transition_3_sensitive_classification_routes_to_it_security(self, stub_iam):
        """
        test_id: TD-012
        source_id: BW-BA-03
        Verify that SysAdmin assigning authoritative classification Sensitive transitions request
        to Classified Sensitive / Routed to IT Security (Transition 3).
        test_type: routing
        """
        archive = _make_archive(
            user_id=1001, department="CSE", status=ArchiveStatus.HOD_APPROVED
        )
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/archives/{archive.pk}/classify/",
            {"classification": "sensitive", "comments": "Restricted research data."},
            format="json",
        )
        assert res.status_code == 200, res.data
        archive.refresh_from_db()
        assert archive.authoritative_classification == ArchiveClassification.SENSITIVE
        assert archive.status == ArchiveStatus.ROUTED_TO_SECURITY
        assert BadmsNotification.objects.filter(
            recipient_role="it_security",
            notification_type="security_encryption_required",
            related_object_id=str(archive.pk),
        ).exists()

    def test_TD_013_bw_ba_03_transition_4_encryption_configuration_creates_encrypted_archive(self, stub_iam):
        """
        test_id: TD-013
        source_id: BW-BA-03
        Verify that successful encryption configuration by IT Security Team transitions request
        to Sensitive Archive Encrypted (Transition 4).
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ROUTED_TO_SECURITY,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
        )
        sec_client = _it_security_client(stub_iam, user_id=4001)
        res = sec_client.post(
            f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
            {"algorithm": "AES-256-GCM", "key_id": "KEY-AES256-TD013"},
            format="json",
        )
        assert res.status_code == 200, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED
        assert archive.is_encrypted is True
        assert "AES" in archive.encryption_algorithm.upper()

    def test_TD_014_bw_ba_03_non_it_security_actor_cannot_configure_encryption(self, stub_iam):
        """
        test_id: TD-014
        source_id: BW-BA-03
        Verify that a non-IT Security actor cannot configure encryption on sensitive archival requests.
        test_type: authorization
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ROUTED_TO_SECURITY,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
        )
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
            {"algorithm": "AES-256-GCM", "key_id": "KEY-SYSADMIN-DENIED"},
            format="json",
        )
        assert res.status_code == 403, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.ROUTED_TO_SECURITY
        assert archive.is_encrypted is False

    def test_TD_015_bw_ba_03_encryption_configuration_blocked_for_non_sensitive_request(self, stub_iam):
        """
        test_id: TD-015
        source_id: BW-BA-03
        Verify that encryption configuration cannot be triggered for requests not classified as Sensitive.
        test_type: negative
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.ROUTINE,
            auth_classification=ArchiveClassification.ROUTINE,
        )
        sec_client = _it_security_client(stub_iam, user_id=4001)
        res = sec_client.post(
            f"/api/v1/badms/archives/{archive.pk}/configure-encryption/",
            {"algorithm": "AES-256-GCM", "key_id": "KEY-SHOULD-FAIL"},
            format="json",
        )
        assert res.status_code == 400, res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.POLICY_APPLIED
        assert archive.is_encrypted is False


# ===========================================================================
# CW-BA-01: Composite - Secure Archival Request Processing (TD-016 .. TD-021)
# ===========================================================================

class TestCwBa01SecureArchivalProcessing:
    """Tests for composite workflow CW-BA-01: Branching and end-to-end composite paths."""

    def test_TD_016_cw_ba_01_hod_decision_branching_reject_vs_approve(self, stub_iam):
        """
        test_id: TD-016
        source_id: CW-BA-01
        Verify composite workflow CW-BA-01 decision branching at HoD review between Reject and Approve paths.
        test_type: decision
        """
        arc1 = _make_archive(user_id=1001, department="CSE", file_name="doc1.pdf", status=ArchiveStatus.SUBMITTED)
        arc2 = _make_archive(user_id=1001, department="CSE", file_name="doc2.pdf", status=ArchiveStatus.SUBMITTED)

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res1 = hod_client.post(
            f"/api/v1/badms/archives/{arc1.pk}/hod-decision/",
            {"decision": "reject", "comments": "Insufficient metadata."},
            format="json",
        )
        assert res1.status_code == 200, res1.data
        arc1.refresh_from_db()
        assert arc1.status == ArchiveStatus.REJECTED

        res2 = hod_client.post(
            f"/api/v1/badms/archives/{arc2.pk}/hod-decision/",
            {"decision": "approve", "comments": "Approved."},
            format="json",
        )
        assert res2.status_code == 200, res2.data
        arc2.refresh_from_db()
        assert arc2.status == ArchiveStatus.HOD_APPROVED
        assert BadmsNotification.objects.filter(
            recipient_role="sysadmin",
            notification_type="classification_required",
            related_object_id=str(arc2.pk),
        ).exists()

    def test_TD_017_cw_ba_01_sysadmin_classification_branching_non_sensitive_vs_sensitive(self, stub_iam):
        """
        test_id: TD-017
        source_id: CW-BA-01
        Verify composite workflow CW-BA-01 decision branching at SysAdmin classification between
        Non-Sensitive and Sensitive paths.
        test_type: decision
        """
        arc1 = _make_archive(user_id=1001, department="CSE", status=ArchiveStatus.HOD_APPROVED)
        arc2 = _make_archive(user_id=1001, department="CSE", status=ArchiveStatus.HOD_APPROVED)

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res1 = sys_client.post(
            f"/api/v1/badms/archives/{arc1.pk}/classify/",
            {"classification": "routine", "comments": "Routine class."},
            format="json",
        )
        assert res1.status_code == 200, res1.data
        arc1.refresh_from_db()
        assert arc1.status == ArchiveStatus.POLICY_APPLIED

        res2 = sys_client.post(
            f"/api/v1/badms/archives/{arc2.pk}/classify/",
            {"classification": "sensitive", "comments": "Sensitive class."},
            format="json",
        )
        assert res2.status_code == 200, res2.data
        arc2.refresh_from_db()
        assert arc2.status == ArchiveStatus.ROUTED_TO_SECURITY
        assert BadmsNotification.objects.filter(
            recipient_role="it_security",
            notification_type="security_encryption_required",
            related_object_id=str(arc2.pk),
        ).exists()

    def test_TD_018_cw_ba_01_end_to_end_composite_sensitive_path(self, stub_iam):
        """
        test_id: TD-018
        source_id: CW-BA-01
        Verify CW-BA-01 end-to-end composite execution along the approved Sensitive path through all four participating roles.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "patient_health_cohort.csv",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "csv",
                "file_size_bytes": 2048,
                "reason": "Health cohort dataset",
                "initial_classification": "sensitive",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.status == ArchiveStatus.SUBMITTED

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        hod_res = hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "approve", "comments": "Endorsed by HoD."},
            format="json",
        )
        assert hod_res.status_code == 200, hod_res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.HOD_APPROVED

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        cls_res = sys_client.post(
            f"/api/v1/badms/archives/{archive_id}/classify/",
            {"classification": "sensitive", "comments": "Authoritative Sensitive classification."},
            format="json",
        )
        assert cls_res.status_code == 200, cls_res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.ROUTED_TO_SECURITY

        sec_client = _it_security_client(stub_iam, user_id=4001)
        enc_res = sec_client.post(
            f"/api/v1/badms/archives/{archive_id}/configure-encryption/",
            {"algorithm": "AES-256-GCM", "key_id": "KEY-AES256-CW01"},
            format="json",
        )
        assert enc_res.status_code == 200, enc_res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED
        assert archive.is_encrypted is True

    def test_TD_019_cw_ba_01_end_to_end_composite_non_sensitive_path(self, stub_iam):
        """
        test_id: TD-019
        source_id: CW-BA-01
        Verify CW-BA-01 end-to-end composite execution along the approved Non-Sensitive path through User, HoD, and SysAdmin.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "course_syllabus.pdf",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "pdf",
                "file_size_bytes": 1024,
                "reason": "Preservation of 2026 syllabus",
                "initial_classification": "routine",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        hod_res = hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "approve", "comments": "CSE HoD approval."},
            format="json",
        )
        assert hod_res.status_code == 200, hod_res.data

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        cls_res = sys_client.post(
            f"/api/v1/badms/archives/{archive_id}/classify/",
            {"classification": "routine", "comments": "Routine syllabus doc."},
            format="json",
        )
        assert cls_res.status_code == 200, cls_res.data
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.status == ArchiveStatus.POLICY_APPLIED

    def test_TD_020_cw_ba_01_end_to_end_composite_rejection_path(self, stub_iam):
        """
        test_id: TD-020
        source_id: CW-BA-01
        Verify CW-BA-01 end-to-end composite execution along the Rejection path through User and HoD.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "unauthorized_scan.pdf",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "pdf",
                "file_size_bytes": 1024,
                "reason": "Personal files",
                "initial_classification": "routine",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        dec_res = hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "reject", "comments": "Personal files not eligible for institutional archive."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        archive = ArchivalRequest.objects.get(pk=archive_id)
        assert archive.status == ArchiveStatus.REJECTED

        # Classification attempts must fail after rejection
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        cls_res = sys_client.post(
            f"/api/v1/badms/archives/{archive_id}/classify/",
            {"classification": "routine"},
            format="json",
        )
        assert cls_res.status_code == 400, cls_res.data
        archive.refresh_from_db()
        assert archive.status == ArchiveStatus.REJECTED

    def test_TD_021_cw_ba_01_notification_dispatch_at_milestones(self, stub_iam):
        """
        test_id: TD-021
        source_id: CW-BA-01
        Verify notification dispatch at each milestone transition in composite workflow CW-BA-01.
        test_type: routing
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/archives/",
            {
                "file_name": "milestone_test.pdf",
                "document_date": "2026-03-01",
                "owners": ["u1001"],
                "file_type": "pdf",
                "file_size_bytes": 1024,
                "reason": "Notification audit trail check",
                "initial_classification": "sensitive",
            },
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        archive_id = sub_res.data["id"]

        # Milestone 1: Submission
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="archive_submitted",
            related_object_id=str(archive_id),
        ).exists()
        assert BadmsNotification.objects.filter(
            recipient_role="HOD",
            notification_type="hod_review_required",
            related_object_id=str(archive_id),
        ).exists()

        # Milestone 2: HoD Approval
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        hod_client.post(
            f"/api/v1/badms/archives/{archive_id}/hod-decision/",
            {"decision": "approve", "comments": "HoD approved."},
            format="json",
        )
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="archive_hod_approved",
            related_object_id=str(archive_id),
        ).exists()
        assert BadmsNotification.objects.filter(
            recipient_role="sysadmin",
            notification_type="classification_required",
            related_object_id=str(archive_id),
        ).exists()

        # Milestone 3: SysAdmin Classification
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        sys_client.post(
            f"/api/v1/badms/archives/{archive_id}/classify/",
            {"classification": "sensitive", "comments": "Sensitive doc."},
            format="json",
        )
        assert BadmsNotification.objects.filter(
            recipient_role="it_security",
            notification_type="security_encryption_required",
            related_object_id=str(archive_id),
        ).exists()


# ===========================================================================
# BW-BA-04: Storage Extension - Rejected (TD-022 .. TD-026)
# ===========================================================================

class TestBwBa04StorageExtensionRejected:
    """Tests for basis workflow BW-BA-04: User submits storage extension and HoD rejects it."""

    def test_TD_022_bw_ba_04_complete_storage_extension_rejection(self, stub_iam):
        """
        test_id: TD-022
        source_id: BW-BA-04
        Verify complete basis workflow BW-BA-04 execution where user submits storage extension
        and respective HoD rejects it.
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/storage-extensions/",
            {"requested_bytes": 1073741824, "reason": "Need extra storage for AI model weights"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        ext_id = sub_res.data["id"]
        ext = StorageExtensionRequest.objects.get(pk=ext_id)
        assert ext.status == StorageExtensionStatus.SUBMITTED

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        dec_res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext_id}/decision/",
            {"decision": "reject", "comments": "Department budget limits storage expansion."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.REJECTED
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="storage_extension_rejected",
            related_object_id=str(ext_id),
        ).exists()

    def test_TD_023_bw_ba_04_transition_1_submission_routes_to_hod(self, stub_iam):
        """
        test_id: TD-023
        source_id: BW-BA-04
        Verify that valid storage-extension submission transitions request from Not Submitted
        to Submitted and routes to respective HoD (Transition 1).
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/storage-extensions/",
            {"requested_bytes": 536870912, "reason": "Research dataset expansion"},
            format="json",
        )
        assert res.status_code == 201, res.data
        assert res.data["status"] == StorageExtensionStatus.SUBMITTED
        ext_id = res.data["id"]
        assert BadmsNotification.objects.filter(
            recipient_role="HOD",
            notification_type="storage_extension_review_required",
            related_object_id=str(ext_id),
        ).exists()

    def test_TD_024_bw_ba_04_transition_2_hod_rejection_decision(self, stub_iam):
        """
        test_id: TD-024
        source_id: BW-BA-04
        Verify that respective HoD rejection transitions Submitted storage-extension request
        to Rejected (Transition 2).
        test_type: decision
        """
        ext = _make_storage_extension(user_id=1001, department="CSE", status=StorageExtensionStatus.SUBMITTED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "reject", "comments": "Quota expansion not approved."},
            format="json",
        )
        assert res.status_code == 200, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.REJECTED
        assert BadmsAuditLog.objects.filter(
            action="badms.storage.reject",
            target_type="storage_extension",
            target_id=str(ext.pk),
            outcome="rejected",
        ).exists()

    def test_TD_025_bw_ba_04_different_department_hod_cannot_reject(self, stub_iam):
        """
        test_id: TD-025
        source_id: BW-BA-04
        Verify department-scope enforcement where an HoD from a different department cannot
        reject storage extension request.
        test_type: authorization
        """
        ext = _make_storage_extension(user_id=1001, department="CSE", status=StorageExtensionStatus.SUBMITTED)
        ece_hod = _ece_hod_client(stub_iam, user_id=2002)
        res = ece_hod.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "reject", "comments": "Cross-department rejection attempt."},
            format="json",
        )
        assert res.status_code == 403, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.SUBMITTED

    def test_TD_026_bw_ba_04_rejection_blocked_if_not_submitted(self, stub_iam):
        """
        test_id: TD-026
        source_id: BW-BA-04
        Verify that storage-extension rejection cannot be performed on requests not in Submitted state.
        test_type: negative
        """
        ext = _make_storage_extension(user_id=1001, department="CSE", status=StorageExtensionStatus.REJECTED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "reject", "comments": "Double reject attempt."},
            format="json",
        )
        assert res.status_code == 400, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.REJECTED


# ===========================================================================
# BW-BA-05: Storage Extension - Approved (TD-027 .. TD-031)
# ===========================================================================

class TestBwBa05StorageExtensionApproved:
    """Tests for basis workflow BW-BA-05: User submits storage extension and HoD approves it."""

    def test_TD_027_bw_ba_05_complete_storage_extension_approval(self, stub_iam):
        """
        test_id: TD-027
        source_id: BW-BA-05
        Verify complete basis workflow BW-BA-05 execution where user submits storage extension
        and respective HoD approves it.
        test_type: positive
        """
        quota, _ = UserStorageQuota.objects.get_or_create(
            user_id=1001,
            defaults={"department": "CSE", "allocated_bytes": 1073741824, "used_bytes": 1073741824},
        )
        initial_allocated = quota.allocated_bytes

        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/storage-extensions/",
            {"requested_bytes": 1073741824, "reason": "Genomic dataset storage expansion"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        ext_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        dec_res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext_id}/decision/",
            {"decision": "approve", "comments": "Approved based on lab requirements."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        ext = StorageExtensionRequest.objects.get(pk=ext_id)
        assert ext.status == StorageExtensionStatus.HOD_APPROVED
        quota.refresh_from_db()
        assert quota.allocated_bytes == initial_allocated + 1073741824
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="storage_extension_approved",
            related_object_id=str(ext_id),
        ).exists()

    def test_TD_028_bw_ba_05_transition_2_hod_approval_decision(self, stub_iam):
        """
        test_id: TD-028
        source_id: BW-BA-05
        Verify that respective HoD approval transitions storage-extension request from Submitted
        to Approved (Transition 2).
        test_type: decision
        """
        ext = _make_storage_extension(user_id=1001, department="CSE", status=StorageExtensionStatus.SUBMITTED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "approve", "comments": "CSE HoD approves request."},
            format="json",
        )
        assert res.status_code == 200, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.HOD_APPROVED
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="storage_extension_approved",
            related_object_id=str(ext.pk),
        ).exists()

    def test_TD_029_bw_ba_05_hod_approves_within_infrastructure_capacity(self, stub_iam):
        """
        test_id: TD-029
        source_id: BW-BA-05
        Verify that HoD can approve storage extension when requested storage does not exceed
        available infrastructure.
        test_type: positive
        """
        ext = _make_storage_extension(
            user_id=1001,
            department="CSE",
            requested_bytes=536870912,  # 512 MB within infrastructure
            status=StorageExtensionStatus.SUBMITTED,
        )
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "approve", "comments": "Infrastructure check verified."},
            format="json",
        )
        assert res.status_code == 200, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.HOD_APPROVED

    def test_TD_030_bw_ba_05_non_hod_cannot_approve_storage_extension(self, stub_iam):
        """
        test_id: TD-030
        source_id: BW-BA-05
        Verify that a non-HoD actor cannot approve a storage-extension request.
        test_type: authorization
        """
        ext = _make_storage_extension(user_id=1001, department="CSE", status=StorageExtensionStatus.SUBMITTED)
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "approve", "comments": "Self-approval attempt."},
            format="json",
        )
        assert res.status_code == 403, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.SUBMITTED

    def test_TD_031_bw_ba_05_approval_blocked_if_not_submitted(self, stub_iam):
        """
        test_id: TD-031
        source_id: BW-BA-05
        Verify that approval cannot be executed on storage-extension requests not in Submitted state.
        test_type: negative
        """
        ext = _make_storage_extension(user_id=1001, department="CSE", status=StorageExtensionStatus.HOD_APPROVED)
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext.pk}/decision/",
            {"decision": "approve", "comments": "Repeat approval attempt."},
            format="json",
        )
        assert res.status_code == 400, res.data
        ext.refresh_from_db()
        assert ext.status == StorageExtensionStatus.HOD_APPROVED


# ===========================================================================
# CW-BA-02: Composite - Storage-Extension Request Processing (TD-032 .. TD-035)
# ===========================================================================

class TestCwBa02StorageExtensionProcessing:
    """Tests for composite workflow CW-BA-02: Storage extension branching and composite execution."""

    def test_TD_032_cw_ba_02_hod_decision_branching_approve_vs_reject(self, stub_iam):
        """
        test_id: TD-032
        source_id: CW-BA-02
        Verify composite workflow CW-BA-02 decision branching at HoD review between Approve and Reject paths.
        test_type: decision
        """
        ext1 = _make_storage_extension(user_id=1001, department="CSE", reason="Reason 1", status=StorageExtensionStatus.SUBMITTED)
        ext2 = _make_storage_extension(user_id=1001, department="CSE", reason="Reason 2", status=StorageExtensionStatus.SUBMITTED)

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res1 = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext1.pk}/decision/",
            {"decision": "approve", "comments": "Approved."},
            format="json",
        )
        assert res1.status_code == 200, res1.data
        ext1.refresh_from_db()
        assert ext1.status == StorageExtensionStatus.HOD_APPROVED

        res2 = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext2.pk}/decision/",
            {"decision": "reject", "comments": "Rejected."},
            format="json",
        )
        assert res2.status_code == 200, res2.data
        ext2.refresh_from_db()
        assert ext2.status == StorageExtensionStatus.REJECTED

        assert BadmsNotification.objects.filter(
            user_id=1001, notification_type="storage_extension_approved", related_object_id=str(ext1.pk)
        ).exists()
        assert BadmsNotification.objects.filter(
            user_id=1001, notification_type="storage_extension_rejected", related_object_id=str(ext2.pk)
        ).exists()

    def test_TD_033_cw_ba_02_end_to_end_composite_approved_path(self, stub_iam):
        """
        test_id: TD-033
        source_id: CW-BA-02
        Verify CW-BA-02 end-to-end composite execution along the Approved path (BW-BA-05 trajectory).
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/storage-extensions/",
            {"requested_bytes": 1073741824, "reason": "ML training dataset requirement"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        ext_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        dec_res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext_id}/decision/",
            {"decision": "approve", "comments": "Approved for ML thesis."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        ext = StorageExtensionRequest.objects.get(pk=ext_id)
        assert ext.status == StorageExtensionStatus.HOD_APPROVED

    def test_TD_034_cw_ba_02_end_to_end_composite_rejected_path(self, stub_iam):
        """
        test_id: TD-034
        source_id: CW-BA-02
        Verify CW-BA-02 end-to-end composite execution along the Rejected path (BW-BA-04 trajectory).
        test_type: positive
        """
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/storage-extensions/",
            {"requested_bytes": 2147483648, "reason": "Excessive quota request"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        ext_id = sub_res.data["id"]

        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        dec_res = hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext_id}/decision/",
            {"decision": "reject", "comments": "Exceeds student quota allocation ceiling."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        ext = StorageExtensionRequest.objects.get(pk=ext_id)
        assert ext.status == StorageExtensionStatus.REJECTED

    def test_TD_035_cw_ba_02_storage_extension_notifications_across_branches(self, stub_iam):
        """
        test_id: TD-035
        source_id: CW-BA-02
        Verify storage-extension submission and decision notifications across CW-BA-02.
        test_type: routing
        """
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/storage-extensions/",
            {"requested_bytes": 1073741824, "reason": "Notification test extension"},
            format="json",
        )
        assert res.status_code == 201, res.data
        ext_id = res.data["id"]

        # Submission notification
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="storage_extension_submitted",
            related_object_id=str(ext_id),
        ).exists()

        # Decision notification
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        hod_client.post(
            f"/api/v1/badms/storage-extensions/{ext_id}/decision/",
            {"decision": "approve", "comments": "Approved."},
            format="json",
        )
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="storage_extension_approved",
            related_object_id=str(ext_id),
        ).exists()


# ===========================================================================
# BW-BA-06: Restoration - Non-Sensitive Standard Path (TD-036 .. TD-040)
# ===========================================================================

class TestBwBa06RestorationNonSensitiveStandard:
    """Tests for basis workflow BW-BA-06: Standard non-sensitive restoration path."""

    def test_TD_036_bw_ba_06_complete_non_sensitive_restoration_workflow(self, stub_iam):
        """
        test_id: TD-036
        source_id: BW-BA-06
        Verify complete basis workflow BW-BA-06 execution where user requests restoration of
        non-Sensitive data and SysAdmin executes technical restoration without approval.
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.ROUTINE,
            auth_classification=ArchiveClassification.ROUTINE,
            is_encrypted=False,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Restore routine dataset for semester review"},
            format="json",
        )
        assert res.status_code == 201, res.data
        restoration_id = res.data["id"]
        restoration = RestorationRequest.objects.get(pk=restoration_id)

        assert restoration.is_sensitive is False
        assert restoration.status == RestorationStatus.COMPLETED
        assert restoration.approved_by_user_id is None
        assert restoration.restored_at is not None
        assert restoration.integrity_verified is True

    def test_TD_037_bw_ba_06_transition_1_non_sensitive_transitions_directly_to_standard_path(self, stub_iam):
        """
        test_id: TD-037
        source_id: BW-BA-06
        Verify that requesting restoration of archived data with Classification != Sensitive
        transitions directly to Restoration Requested / Standard Path (Transition 1).
        test_type: decision
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.ARCHIVAL,
            auth_classification=ArchiveClassification.ARCHIVAL,
            is_encrypted=False,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Archival dataset recovery"},
            format="json",
        )
        assert res.status_code == 201, res.data
        restoration = RestorationRequest.objects.get(pk=res.data["id"])
        assert restoration.is_sensitive is False
        # Directly on standard path / completed without entering pending_approval queue
        assert restoration.status != RestorationStatus.PENDING_APPROVAL
        assert not BadmsNotification.objects.filter(
            recipient_role="sysadmin",
            notification_type="restoration_approval_required",
            related_object_id=str(restoration.pk),
        ).exists()

    def test_TD_038_bw_ba_06_transition_2_standard_path_execution_transitions_to_restored(self, stub_iam):
        """
        test_id: TD-038
        source_id: BW-BA-06
        Verify that SysAdmin execution of BA-UC-018 on standard-path restoration transitions
        state to Restored (Transition 2).
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.CRITICAL,
            auth_classification=ArchiveClassification.CRITICAL,
            is_encrypted=False,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Standard restoration execution"},
            format="json",
        )
        assert res.status_code == 201, res.data
        restoration = RestorationRequest.objects.get(pk=res.data["id"])
        assert restoration.status == RestorationStatus.COMPLETED
        assert restoration.restored_at is not None
        assert BadmsAuditLog.objects.filter(
            action="badms.restoration.execute_standard",
            target_type="restoration_request",
            target_id=str(restoration.pk),
            outcome="success",
        ).exists()

    def test_TD_039_bw_ba_06_non_sysadmin_cannot_execute_technical_restoration(self, stub_iam):
        """
        test_id: TD-039
        source_id: BW-BA-06
        Verify that a non-SysAdmin actor cannot execute technical data restoration under BA-UC-018.
        test_type: authorization
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.ROUTINE,
            auth_classification=ArchiveClassification.ROUTINE,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        res_create = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Standard path archive"},
            format="json",
        )
        restoration_id = res_create.data["id"]

        # Regular user attempts to invoke the restoration decision/approval execution endpoint
        res = u_client.post(
            f"/api/v1/badms/restorations/{restoration_id}/decision/",
            {"decision": "approve", "comments": "User unauthorized execution attempt"},
            format="json",
        )
        assert res.status_code == 403, res.data

    def test_TD_040_bw_ba_06_restoration_execution_blocked_for_unrequested_dataset(self, stub_iam):
        """
        test_id: TD-040
        source_id: BW-BA-06
        Verify that technical restoration execution cannot occur if request is not in Restoration
        Requested / Standard Path state.
        test_type: negative
        """
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        # Attempt to trigger restoration execution on a non-existent / unrequested record
        res = sys_client.post(
            "/api/v1/badms/restorations/99999/decision/",
            {"decision": "approve", "comments": "Executing restoration on unrequested dataset"},
            format="json",
        )
        assert res.status_code in (400, 404), res.data


# ===========================================================================
# BW-BA-07: Restoration - Sensitive SysAdmin Approval (TD-041 .. TD-047)
# ===========================================================================

class TestBwBa07RestorationSensitiveSysAdmin:
    """Tests for basis workflow BW-BA-07: Sensitive restoration requiring SysAdmin approval."""

    def test_TD_041_bw_ba_07_complete_sensitive_restoration_approval_workflow(self, stub_iam):
        """
        test_id: TD-041
        source_id: BW-BA-07
        Verify complete basis workflow BW-BA-07 execution along approval and restoration path
        where user requests Sensitive restoration, SysAdmin approves, and SysAdmin executes technical restoration.
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Restoration required for clinical audit"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        restoration_id = sub_res.data["id"]
        restoration = RestorationRequest.objects.get(pk=restoration_id)
        assert restoration.is_sensitive is True
        assert restoration.status == RestorationStatus.PENDING_APPROVAL

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        app_res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration_id}/decision/",
            {"decision": "approve", "comments": "Audit documentation verified. Restoration approved."},
            format="json",
        )
        assert app_res.status_code == 200, app_res.data
        restoration.refresh_from_db()
        assert restoration.status == RestorationStatus.COMPLETED
        assert restoration.approved_by_user_id == 3001
        assert restoration.restored_at is not None
        assert restoration.integrity_verified is True

    def test_TD_042_bw_ba_07_transition_2_sysadmin_rejection_decision(self, stub_iam):
        """
        test_id: TD-042
        source_id: BW-BA-07
        Verify basis workflow BW-BA-07 rejection outcome where SysAdmin rejects Sensitive data
        restoration request (Transition 2).
        test_type: decision
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Restoration request"},
            format="json",
        )
        restoration_id = sub_res.data["id"]

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        dec_res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration_id}/decision/",
            {"decision": "reject", "comments": "Sensitive data release denied by policy."},
            format="json",
        )
        assert dec_res.status_code == 200, dec_res.data
        restoration = RestorationRequest.objects.get(pk=restoration_id)
        assert restoration.status == RestorationStatus.REJECTED
        assert BadmsNotification.objects.filter(
            user_id=1001,
            notification_type="restoration_rejected",
            related_object_id=str(restoration_id),
        ).exists()

    def test_TD_043_bw_ba_07_transition_1_sensitive_request_routes_for_approval(self, stub_iam):
        """
        test_id: TD-043
        source_id: BW-BA-07
        Verify that restoration request for data classified as Sensitive transitions to Sensitive
        Restoration Pending Approval and routes to SysAdmin (Transition 1).
        test_type: routing
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Sensitive trial restoration"},
            format="json",
        )
        assert res.status_code == 201, res.data
        restoration_id = res.data["id"]
        restoration = RestorationRequest.objects.get(pk=restoration_id)
        assert restoration.status == RestorationStatus.PENDING_APPROVAL
        assert BadmsNotification.objects.filter(
            recipient_role="sysadmin",
            notification_type="restoration_approval_required",
            related_object_id=str(restoration_id),
        ).exists()

    def test_TD_044_bw_ba_07_transition_3_sysadmin_approval_eligibility(self, stub_iam):
        """
        test_id: TD-044
        source_id: BW-BA-07
        Verify that SysAdmin approval transitions request from Sensitive Restoration Pending Approval
        to Approved for Restoration (Transition 3).
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        restoration = RestorationRequest.objects.create(
            archive_id=archive.pk,
            requester_user_id=1001,
            target_type="archive",
            target_name=archive.file_name,
            reason="Sensitive restoration eligibility test",
            is_sensitive=True,
            status=RestorationStatus.PENDING_APPROVAL,
        )
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration.pk}/decision/",
            {"decision": "approve", "comments": "Approved for technical restoration."},
            format="json",
        )
        assert res.status_code == 200, res.data
        restoration.refresh_from_db()
        assert restoration.status in (RestorationStatus.APPROVED, RestorationStatus.COMPLETED)
        assert restoration.approved_by_user_id == 3001

    def test_TD_045_bw_ba_07_transition_4_technical_restoration_execution_succeeds(self, stub_iam):
        """
        test_id: TD-045
        source_id: BW-BA-07
        Verify that technical execution by SysAdmin on an approved Sensitive restoration transitions
        state to Restored (Transition 4).
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        restoration = RestorationRequest.objects.create(
            archive_id=archive.pk,
            requester_user_id=1001,
            target_type="archive",
            target_name=archive.file_name,
            reason="Technical restoration execution test",
            is_sensitive=True,
            status=RestorationStatus.PENDING_APPROVAL,
        )
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration.pk}/decision/",
            {"decision": "approve", "comments": "Execution clearance."},
            format="json",
        )
        assert res.status_code == 200, res.data
        restoration.refresh_from_db()
        assert restoration.status == RestorationStatus.COMPLETED
        assert restoration.restored_at is not None
        assert restoration.integrity_verified is True
        assert BadmsAuditLog.objects.filter(
            action="badms.restoration.approve",
            target_type="restoration_request",
            target_id=str(restoration.pk),
            outcome="success",
        ).exists()

    def test_TD_046_bw_ba_07_restoration_execution_blocked_while_pending_approval(self, stub_iam):
        """
        test_id: TD-046
        source_id: BW-BA-07
        Verify enforcement of BR-BA-005 where technical restoration execution is blocked while request
        is in Sensitive Restoration Pending Approval state.
        test_type: negative
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Sensitive request"},
            format="json",
        )
        restoration_id = sub_res.data["id"]
        restoration = RestorationRequest.objects.get(pk=restoration_id)

        # While pending approval, data restoration must not have executed
        assert restoration.status == RestorationStatus.PENDING_APPROVAL
        assert restoration.restored_at is None
        assert restoration.integrity_verified is False

    def test_TD_047_bw_ba_07_only_sysadmin_can_approve_sensitive_restoration(self, stub_iam):
        """
        test_id: TD-047
        source_id: BW-BA-07
        Verify that only SysAdmin can approve Sensitive data restoration under BA-UC-017 and non-SysAdmin
        roles cannot approve.
        test_type: authorization
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        restoration = RestorationRequest.objects.create(
            archive_id=archive.pk,
            requester_user_id=1001,
            target_type="archive",
            target_name=archive.file_name,
            reason="Restoration approval RBAC check",
            is_sensitive=True,
            status=RestorationStatus.PENDING_APPROVAL,
        )
        hod_client = _cse_hod_client(stub_iam, user_id=2001)
        res = hod_client.post(
            f"/api/v1/badms/restorations/{restoration.pk}/decision/",
            {"decision": "approve", "comments": "HoD unauthorized restoration approval attempt"},
            format="json",
        )
        assert res.status_code == 403, res.data
        restoration.refresh_from_db()
        assert restoration.status == RestorationStatus.PENDING_APPROVAL


# ===========================================================================
# CW-BA-03: Composite - Data Restoration Processing (TD-048 .. TD-053)
# ===========================================================================

class TestCwBa03DataRestorationProcessing:
    """Tests for composite workflow CW-BA-03: Complete data restoration branching and composite paths."""

    def test_TD_048_cw_ba_03_routing_decision_by_classification(self, stub_iam):
        """
        test_id: TD-048
        source_id: CW-BA-03
        Verify composite workflow CW-BA-03 routing decision based on archive classification at the
        restoration request stage.
        test_type: decision
        """
        routine_arc = _make_archive(
            user_id=1001,
            department="CSE",
            file_name="routine.pdf",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.ROUTINE,
            auth_classification=ArchiveClassification.ROUTINE,
        )
        sensitive_arc = _make_archive(
            user_id=1001,
            department="CSE",
            file_name="sensitive.pdf",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)

        res_rtn = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": routine_arc.pk, "reason": "Restore routine"},
            format="json",
        )
        assert res_rtn.status_code == 201, res_rtn.data
        rtn_restoration = RestorationRequest.objects.get(pk=res_rtn.data["id"])
        assert rtn_restoration.status == RestorationStatus.COMPLETED

        res_sen = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": sensitive_arc.pk, "reason": "Restore sensitive"},
            format="json",
        )
        assert res_sen.status_code == 201, res_sen.data
        sen_restoration = RestorationRequest.objects.get(pk=res_sen.data["id"])
        assert sen_restoration.status == RestorationStatus.PENDING_APPROVAL

    def test_TD_049_cw_ba_03_sysadmin_decision_branching_approve_vs_reject(self, stub_iam):
        """
        test_id: TD-049
        source_id: CW-BA-03
        Verify CW-BA-03 decision branch at Sensitive Restoration Pending Approval state where SysAdmin
        can either Approve or Reject.
        test_type: decision
        """
        archive1 = _make_archive(
            user_id=1001, department="CSE", file_name="s1.pdf",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE, is_encrypted=True,
        )
        archive2 = _make_archive(
            user_id=1001, department="CSE", file_name="s2.pdf",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE, is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        r1_id = u_client.post("/api/v1/badms/restorations/", {"archive_id": archive1.pk, "reason": "r1"}, format="json").data["id"]
        r2_id = u_client.post("/api/v1/badms/restorations/", {"archive_id": archive2.pk, "reason": "r2"}, format="json").data["id"]

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        app_res = sys_client.post(
            f"/api/v1/badms/restorations/{r1_id}/decision/",
            {"decision": "approve", "comments": "Approved."},
            format="json",
        )
        assert app_res.status_code == 200, app_res.data
        r1 = RestorationRequest.objects.get(pk=r1_id)
        assert r1.status == RestorationStatus.COMPLETED

        rej_res = sys_client.post(
            f"/api/v1/badms/restorations/{r2_id}/decision/",
            {"decision": "reject", "comments": "Rejected."},
            format="json",
        )
        assert rej_res.status_code == 200, rej_res.data
        r2 = RestorationRequest.objects.get(pk=r2_id)
        assert r2.status == RestorationStatus.REJECTED

    def test_TD_050_cw_ba_03_end_to_end_composite_standard_path(self, stub_iam):
        """
        test_id: TD-050
        source_id: CW-BA-03
        Verify CW-BA-03 end-to-end composite execution along the standard non-Sensitive path (BW-BA-06 trajectory).
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            file_name="standard_archive.pdf",
            status=ArchiveStatus.POLICY_APPLIED,
            classification=ArchiveClassification.ROUTINE,
            auth_classification=ArchiveClassification.ROUTINE,
            is_encrypted=False,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Restore for classroom lecture"},
            format="json",
        )
        assert res.status_code == 201, res.data
        restoration = RestorationRequest.objects.get(pk=res.data["id"])
        assert restoration.status == RestorationStatus.COMPLETED
        assert restoration.is_sensitive is False
        assert restoration.restored_at is not None

    def test_TD_051_cw_ba_03_end_to_end_composite_sensitive_approved_path(self, stub_iam):
        """
        test_id: TD-051
        source_id: CW-BA-03
        Verify CW-BA-03 end-to-end composite execution along the approved Sensitive path through approval
        and execution (BW-BA-07 trajectory).
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            file_name="cohort_records.csv",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Sensitive cohort access for clinical trial verification"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        restoration_id = sub_res.data["id"]
        restoration = RestorationRequest.objects.get(pk=restoration_id)
        assert restoration.status == RestorationStatus.PENDING_APPROVAL

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        app_res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration_id}/decision/",
            {"decision": "approve", "comments": "Clinical trial verification approved."},
            format="json",
        )
        assert app_res.status_code == 200, app_res.data
        restoration.refresh_from_db()
        assert restoration.status == RestorationStatus.COMPLETED
        assert restoration.restored_at is not None
        assert restoration.integrity_verified is True

    def test_TD_052_cw_ba_03_end_to_end_composite_sensitive_rejected_path(self, stub_iam):
        """
        test_id: TD-052
        source_id: CW-BA-03
        Verify CW-BA-03 end-to-end composite execution along the rejected Sensitive path.
        test_type: positive
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            file_name="confidential_records.csv",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        u_client = _user_client(stub_iam, user_id=1001)
        sub_res = u_client.post(
            "/api/v1/badms/restorations/",
            {"archive_id": archive.pk, "reason": "Restoration attempt"},
            format="json",
        )
        assert sub_res.status_code == 201, sub_res.data
        restoration_id = sub_res.data["id"]

        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        rej_res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration_id}/decision/",
            {"decision": "reject", "comments": "Access denied due to privacy policies."},
            format="json",
        )
        assert rej_res.status_code == 200, rej_res.data
        restoration = RestorationRequest.objects.get(pk=restoration_id)
        assert restoration.status == RestorationStatus.REJECTED
        assert restoration.restored_at is None

    def test_TD_053_cw_ba_03_restoration_execution_blocked_after_rejection(self, stub_iam):
        """
        test_id: TD-053
        source_id: CW-BA-03
        Verify that technical restoration execution cannot occur on a Sensitive restoration request
        after rejection.
        test_type: negative
        """
        archive = _make_archive(
            user_id=1001,
            department="CSE",
            file_name="rejected_sensitive.csv",
            status=ArchiveStatus.ENCRYPTED_ARCHIVE_CREATED,
            classification=ArchiveClassification.SENSITIVE,
            auth_classification=ArchiveClassification.SENSITIVE,
            is_encrypted=True,
        )
        restoration = RestorationRequest.objects.create(
            archive_id=archive.pk,
            requester_user_id=1001,
            target_type="archive",
            target_name=archive.file_name,
            reason="Already rejected request",
            is_sensitive=True,
            status=RestorationStatus.REJECTED,
        )
        sys_client = _sysadmin_client(stub_iam, user_id=3001)
        res = sys_client.post(
            f"/api/v1/badms/restorations/{restoration.pk}/decision/",
            {"decision": "approve", "comments": "Attempting to execute restoration on rejected request"},
            format="json",
        )
        assert res.status_code == 400, res.data
        restoration.refresh_from_db()
        assert restoration.status == RestorationStatus.REJECTED
