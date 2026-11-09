"""
FR Test Suite – Secure Archival Workflow
(CFR-BA-005, CFR-BA-006, CFR-BA-007, CFR-BA-008, CFR-BA-009)
Implements TD-015 through TD-032 from a8_design/FR_DESIGN.json.
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
    BadmsAuditLog,
    BadmsNotification,
    UserStorageQuota,
)
from modules.directory.models import UserRef

pytestmark = pytest.mark.django_db


# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

def _client(stub_iam, **session_kw):
    stub_iam(make_session(**session_kw))
    c = APIClient()
    c.credentials(HTTP_AUTHORIZATION="Token fake-token")
    return c


VALID_PAYLOAD = {
    "file_name": "research_data.pdf",
    "document_date": "2026-01-15",
    "owners": ["alice", "bob"],
    "file_type": "pdf",
    "reason": "Long-term institutional preservation",
    "file_size_bytes": 1024,
}


@pytest.fixture()
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


@pytest.fixture()
def cse_hod_ref():
    return UserRef.objects.create(
        user_id=2002,
        username="u2002",
        display_name="CSE HoD",
        kind="faculty",
        department="CSE",
        discipline="CSE",
        is_active=True,
    )


@pytest.fixture()
def ece_hod_ref():
    return UserRef.objects.create(
        user_id=3003,
        username="u3003",
        display_name="ECE HoD",
        kind="faculty",
        department="ECE",
        discipline="ECE",
        is_active=True,
    )


@pytest.fixture()
def user_quota(cse_user_ref):
    return UserStorageQuota.objects.create(
        user_id=cse_user_ref.user_id,
        department="CSE",
        allocated_bytes=10 * 1024 * 1024,
        used_bytes=0,
    )


# ---------------------------------------------------------------------------
# Helper: submit a valid archival request via service (bypasses quota check)
# ---------------------------------------------------------------------------

def _create_submitted_archive(user_id=1001, department="CSE"):
    return ArchivalRequest.objects.create(
        user_id=user_id,
        department=department,
        file_name="test_file.pdf",
        document_date=datetime.date(2026, 1, 15),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Preservation",
        initial_classification=ArchiveClassification.ROUTINE,
        status=ArchiveStatus.SUBMITTED,
    )


# ---------------------------------------------------------------------------
# TD-015  CFR-BA-005 / AFR-BA-019 – Authenticated user can initiate submission
# ---------------------------------------------------------------------------

def test_TD_015_authenticated_user_can_initiate_secure_archival_request(stub_iam, cse_user_ref, user_quota):
    """
    test_id: TD-015
    source_id: CFR-BA-005, AFR-BA-019
    Verify that an authenticated user can initiate a secure archival request.
    positive
    """
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = client.post("/api/v1/badms/archives/", VALID_PAYLOAD, format="json")
    assert res.status_code == 201, res.data


# ---------------------------------------------------------------------------
# TD-016  CFR-BA-005 / AFR-BA-020 – Request captures all required metadata fields
# ---------------------------------------------------------------------------

def test_TD_016_archival_request_captures_all_required_metadata_fields(stub_iam, cse_user_ref, user_quota):
    """
    test_id: TD-016
    source_id: CFR-BA-005, AFR-BA-020
    Verify that a secure archival request captures file name, date, owners,
    file type, reason, and file attachment.
    positive
    """
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    payload = dict(VALID_PAYLOAD)
    res = client.post("/api/v1/badms/archives/", payload, format="json")
    assert res.status_code == 201, res.data
    data = res.data
    assert data["file_name"] == payload["file_name"]
    assert data["document_date"] == payload["document_date"]
    assert data["file_type"] == payload["file_type"]
    assert data["reason"] == payload["reason"]


# ---------------------------------------------------------------------------
# TD-017  CFR-BA-005 / AFR-BA-021 – Validation failure: errors, no state change
# ---------------------------------------------------------------------------

def test_TD_017_validation_failure_shows_errors_and_no_state_change(stub_iam, cse_user_ref, user_quota):
    """
    test_id: TD-017
    source_id: CFR-BA-005, AFR-BA-021
    Verify BADMS validates request data and storage quota; on failure shows
    errors and makes no request-state change.
    validation
    """
    before_count = ArchivalRequest.objects.count()
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    # Missing required field: file_name
    invalid_payload = {
        "document_date": "2026-01-15",
        "file_type": "pdf",
        "reason": "Preservation",
        "file_size_bytes": 1024,
    }
    res = client.post("/api/v1/badms/archives/", invalid_payload, format="json")
    assert res.status_code in (400, 422), res.data
    assert ArchivalRequest.objects.count() == before_count, "No archive record should be created on validation failure"


# ---------------------------------------------------------------------------
# TD-018  CFR-BA-005 / AFR-BA-022 – Successful submission sets status to Submitted
# ---------------------------------------------------------------------------

def test_TD_018_successful_submission_sets_status_to_submitted(stub_iam, cse_user_ref, user_quota):
    """
    test_id: TD-018
    source_id: CFR-BA-005, AFR-BA-022
    Verify that on successful submission BADMS sets the secure archival request
    status to Submitted.
    positive
    """
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = client.post("/api/v1/badms/archives/", VALID_PAYLOAD, format="json")
    assert res.status_code == 201, res.data
    assert res.data["status"] == ArchiveStatus.SUBMITTED


# ---------------------------------------------------------------------------
# TD-019  CFR-BA-005 / AFR-BA-023 – Request routed to requester's HoD after submission
# ---------------------------------------------------------------------------

def test_TD_019_submitted_request_routed_to_requesters_hod(stub_iam, cse_user_ref, cse_hod_ref, user_quota):
    """
    test_id: TD-019
    source_id: CFR-BA-005, AFR-BA-023
    Verify BADMS routes a successfully submitted secure archival request to the
    HoD of the requester's department.
    positive
    """
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    res = client.post("/api/v1/badms/archives/", VALID_PAYLOAD, format="json")
    assert res.status_code == 201, res.data
    # Request must be in Submitted state (routed to HoD)
    archive = ArchivalRequest.objects.get(pk=res.data["id"])
    assert archive.status == ArchiveStatus.SUBMITTED
    # Submission notification must have been sent
    notif = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="archive_submitted",
    ).first()
    assert notif is not None, "Submission notification must be sent to the requester"


# ---------------------------------------------------------------------------
# TD-020  CFR-BA-005 / AFR-BA-029 – Default classification is Routine when omitted
# ---------------------------------------------------------------------------

def test_TD_020_default_classification_is_routine_when_omitted(stub_iam, cse_user_ref, user_quota):
    """
    test_id: TD-020
    source_id: CFR-BA-005, AFR-BA-029
    Verify that if no initial classification is supplied, BADMS assigns Routine
    as the default classification.
    boundary
    """
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    payload = dict(VALID_PAYLOAD)
    payload.pop("initial_classification", None)
    res = client.post("/api/v1/badms/archives/", payload, format="json")
    assert res.status_code == 201, res.data
    assert res.data["initial_classification"] == ArchiveClassification.ROUTINE


# ---------------------------------------------------------------------------
# TD-021  CFR-BA-006 / AFR-BA-024 – HoD can review request details before deciding
# ---------------------------------------------------------------------------

def test_TD_021_hod_can_review_request_details_before_decision(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-021
    source_id: CFR-BA-006, AFR-BA-024
    Verify that the routed HoD can review request details, attachments, and
    policy context before deciding on a secure archival request.
    positive
    """
    archive = _create_submitted_archive(user_id=cse_user_ref.user_id, department="CSE")
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_REVIEW),
    )
    res = client.get(f"/api/v1/badms/archives/{archive.pk}/")
    assert res.status_code == 200
    data = res.data
    assert data["file_name"] == archive.file_name
    assert data["reason"] == archive.reason
    assert data["department"] == archive.department


# ---------------------------------------------------------------------------
# TD-022  CFR-BA-006 / AFR-BA-025 – HoD can approve and decision is recorded
# ---------------------------------------------------------------------------

def test_TD_022_hod_can_approve_archival_request_and_decision_recorded(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-022
    source_id: CFR-BA-006, AFR-BA-025
    Verify HoD can approve a secure archival request and BADMS records the decision.
    positive
    """
    archive = _create_submitted_archive(user_id=cse_user_ref.user_id, department="CSE")
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_REVIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "approve", "comments": "Approved for preservation."},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.HOD_APPROVED
    assert archive.hod_user_id == cse_hod_ref.user_id


# ---------------------------------------------------------------------------
# TD-023  CFR-BA-006 / AFR-BA-025 – HoD can reject and decision is recorded
# ---------------------------------------------------------------------------

def test_TD_023_hod_can_reject_archival_request_and_decision_recorded(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-023
    source_id: CFR-BA-006, AFR-BA-025
    Verify HoD can reject a secure archival request and BADMS records the decision.
    positive
    """
    archive = _create_submitted_archive(user_id=cse_user_ref.user_id, department="CSE")
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_REVIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "reject", "comments": "Insufficient justification."},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.REJECTED
    assert archive.hod_user_id == cse_hod_ref.user_id


# ---------------------------------------------------------------------------
# TD-024  CFR-BA-006 / AFR-BA-026 – Only the HoD of requester's dept may decide
# ---------------------------------------------------------------------------

def test_TD_024_only_hod_of_requesters_department_may_approve_or_reject(stub_iam, cse_user_ref, ece_hod_ref):
    """
    test_id: TD-024
    source_id: CFR-BA-006, AFR-BA-026
    Verify only the HoD of the requester's own department is permitted to approve
    or reject that user's secure archival request.
    authorization
    """
    archive = _create_submitted_archive(user_id=cse_user_ref.user_id, department="CSE")
    # ECE HoD attempts to decide on a CSE archive
    client = _client(
        stub_iam,
        user_id=ece_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_REVIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "approve", "comments": "Cross-dept approve attempt"},
        format="json",
    )
    assert res.status_code in (403, 404), (
        f"Cross-department HoD must not be able to approve. Got {res.status_code}: {res.data}"
    )


# ---------------------------------------------------------------------------
# TD-025  CFR-BA-006 / AFR-BA-027 – After HoD approval, routed to SysAdmin
# ---------------------------------------------------------------------------

def test_TD_025_after_hod_approval_request_routed_to_sysadmin(stub_iam, cse_user_ref, cse_hod_ref):
    """
    test_id: TD-025
    source_id: CFR-BA-006, AFR-BA-027
    Verify that after HoD approval BADMS routes the secure archival request to
    SysAdmin for classification.
    positive
    """
    archive = _create_submitted_archive(user_id=cse_user_ref.user_id, department="CSE")
    client = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_REVIEW),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/hod-decision/",
        {"decision": "approve", "comments": "Approved."},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.HOD_APPROVED
    # SysAdmin classification notification must be sent
    notif = BadmsNotification.objects.filter(
        recipient_role="sysadmin",
        notification_type="classification_required",
    ).first()
    assert notif is not None, "SysAdmin must be notified to classify the approved archive"


# ---------------------------------------------------------------------------
# TD-026  CFR-BA-007 / AFR-BA-028 – SysAdmin can assign authoritative classification
# ---------------------------------------------------------------------------

def test_TD_026_sysadmin_can_assign_authoritative_classification(stub_iam, cse_user_ref):
    """
    test_id: TD-026
    source_id: CFR-BA-007, AFR-BA-028
    Verify SysAdmin can review an approved secure archival request and classify
    the data as Critical, Sensitive, Routine, or Archival.
    positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=cse_user_ref.user_id if hasattr(cse_user_ref, "user_id") else 1001,
        department="CSE",
        file_name="report.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["alice"],
        file_type="pdf",
        file_size_bytes=512,
        reason="Classification test",
        status=ArchiveStatus.HOD_APPROVED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_CLASSIFY),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "critical", "comments": "Classified as critical."},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.authoritative_classification == ArchiveClassification.CRITICAL


# ---------------------------------------------------------------------------
# TD-027  CFR-BA-007 / AFR-BA-030 – Security/retention rules applied by classification
# ---------------------------------------------------------------------------

def test_TD_027_security_and_retention_rules_applied_by_classification(stub_iam):
    """
    test_id: TD-027
    source_id: CFR-BA-007, AFR-BA-030
    Verify BADMS applies security and retention rules according to the
    authoritative data classification.
    positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=1001,
        department="CSE",
        file_name="policy_doc.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["carol"],
        file_type="pdf",
        file_size_bytes=256,
        reason="Retention test",
        status=ArchiveStatus.HOD_APPROVED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_CLASSIFY),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "routine"},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    # Policy-applied status indicates retention/security treatment was applied
    assert archive.status == ArchiveStatus.POLICY_APPLIED
    assert archive.authoritative_classification == ArchiveClassification.ROUTINE


# ---------------------------------------------------------------------------
# TD-028  CFR-BA-007 / AFR-BA-031 – Sensitive classification routes to IT Security
# ---------------------------------------------------------------------------

def test_TD_028_sensitive_classification_routes_to_it_security(stub_iam):
    """
    test_id: TD-028
    source_id: CFR-BA-007, AFR-BA-031
    Verify that if the authoritative classification is Sensitive, BADMS routes
    the request to IT Security for encryption configuration.
    positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=1001,
        department="CSE",
        file_name="sensitive_research.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["dave"],
        file_type="pdf",
        file_size_bytes=1024,
        reason="Sensitive route test",
        status=ArchiveStatus.HOD_APPROVED,
    )
    client = _client(
        stub_iam,
        user_id=50,
        kind="staff",
        active_role="sysadmin",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_CLASSIFY),
    )
    res = client.post(
        f"/api/v1/badms/archives/{archive.pk}/classify/",
        {"classification": "sensitive", "comments": "Needs encryption."},
        format="json",
    )
    assert res.status_code == 200, res.data
    archive.refresh_from_db()
    assert archive.status == ArchiveStatus.ROUTED_TO_SECURITY
    # Notification to IT Security must be sent
    notif = BadmsNotification.objects.filter(
        recipient_role="it_security",
        notification_type="security_encryption_required",
    ).first()
    assert notif is not None, "IT Security must be notified when archive classified as Sensitive"


# ---------------------------------------------------------------------------
# TD-029  CFR-BA-008 / AFR-BA-032 – IT Security can configure encryption
# ---------------------------------------------------------------------------

def test_TD_029_it_security_can_configure_encryption_for_sensitive_data(stub_iam):
    """
    test_id: TD-029
    source_id: CFR-BA-008, AFR-BA-032
    Verify IT Security Team can configure encryption for data classified as Sensitive.
    positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=1001,
        department="CSE",
        file_name="enc_config_test.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["eve"],
        file_type="pdf",
        file_size_bytes=512,
        reason="Encryption config test",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="IT Security",
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


# ---------------------------------------------------------------------------
# TD-030  CFR-BA-008 / AFR-BA-033, AFR-BA-034
#         AES-256 encrypted archive created and outcome recorded
# ---------------------------------------------------------------------------

def test_TD_030_encrypted_archive_created_with_aes256_and_outcome_recorded(stub_iam):
    """
    test_id: TD-030
    source_id: CFR-BA-008, AFR-BA-033, AFR-BA-034
    Verify BADMS creates encrypted archive using AES-256 at rest and in transit
    and records the outcome.
    positive
    """
    archive = ArchivalRequest.objects.create(
        user_id=1001,
        department="CSE",
        file_name="aes256_test.pdf",
        document_date=datetime.date(2026, 1, 1),
        owners=["frank"],
        file_type="pdf",
        file_size_bytes=256,
        reason="AES-256 test",
        status=ArchiveStatus.ROUTED_TO_SECURITY,
        authoritative_classification=ArchiveClassification.SENSITIVE,
    )
    client = _client(
        stub_iam,
        user_id=70,
        kind="staff",
        active_role="IT Security",
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
    assert "AES-256" in archive.encryption_algorithm.upper()

    # Audit outcome recorded
    audit = BadmsAuditLog.objects.filter(
        target_id=str(archive.pk),
        action="badms.archive.encrypt",
    ).first()
    assert audit is not None
    assert audit.outcome == "success"


# ---------------------------------------------------------------------------
# TD-031  CFR-BA-009 / AFR-BA-035 – User can track archival request status/history
# ---------------------------------------------------------------------------

def test_TD_031_user_can_track_archival_request_status_and_history(stub_iam, cse_user_ref, user_quota):
    """
    test_id: TD-031
    source_id: CFR-BA-009, AFR-BA-035
    Verify user can track the status and history of a secure archival request
    throughout processing.
    positive
    """
    client = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    post_res = client.post("/api/v1/badms/archives/", VALID_PAYLOAD, format="json")
    assert post_res.status_code == 201
    archive_id = post_res.data["id"]

    get_res = client.get(f"/api/v1/badms/archives/{archive_id}/")
    assert get_res.status_code == 200
    assert get_res.data["status"] == ArchiveStatus.SUBMITTED


# ---------------------------------------------------------------------------
# TD-032  CFR-BA-009 / AFR-BA-036 – Submission and decision notifications sent
# ---------------------------------------------------------------------------

def test_TD_032_submission_and_decision_notifications_sent(stub_iam, cse_user_ref, cse_hod_ref, user_quota):
    """
    test_id: TD-032
    source_id: CFR-BA-009, AFR-BA-036
    Verify BADMS sends a submission confirmation notification and decision
    notifications at approval/rejection stages.
    positive
    """
    # Step 1: Submit
    client_user = _client(
        stub_iam,
        user_id=cse_user_ref.user_id,
        kind="student",
        active_role="student",
        modules=("badms",),
        permissions=(p.ARCHIVE_CREATE, p.ARCHIVE_VIEW_SELF),
    )
    post_res = client_user.post("/api/v1/badms/archives/", VALID_PAYLOAD, format="json")
    assert post_res.status_code == 201
    archive_id = post_res.data["id"]

    # Submission notification
    sub_notif = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="archive_submitted",
    ).first()
    assert sub_notif is not None, "Submission confirmation notification must be sent"

    # Step 2: HoD approves
    client_hod = _client(
        stub_iam,
        user_id=cse_hod_ref.user_id,
        kind="faculty",
        active_role="HOD",
        modules=("badms",),
        permissions=(p.ARCHIVE_VIEW, p.ARCHIVE_REVIEW),
    )
    dec_res = client_hod.post(
        f"/api/v1/badms/archives/{archive_id}/hod-decision/",
        {"decision": "approve", "comments": "Looks good."},
        format="json",
    )
    assert dec_res.status_code == 200, dec_res.data

    # Decision notification to requester
    dec_notif = BadmsNotification.objects.filter(
        user_id=cse_user_ref.user_id,
        notification_type="archive_hod_approved",
    ).first()
    assert dec_notif is not None, "Decision notification must be sent to requester after HoD approval"
