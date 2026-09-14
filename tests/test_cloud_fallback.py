import io
import json
import unittest
from unittest.mock import MagicMock, patch

from models import NameParts, ProviderInfo, VerificationStatus
from verifier import (
    run_alternative_verification,
    run_verification,
    verify_github_commits,
    verify_m365_cloud,
    verify_pgp_keyring,
)


class TestCloudFallbackVerifiers(unittest.TestCase):

    @patch("urllib.request.urlopen")
    def test_m365_cloud_user_exists(self, mock_urlopen):
        # Mock response with IfExistsResult: 0 (User Exists)
        fake_response = io.BytesIO(json.dumps({"IfExistsResult": 0, "ThrottleStatus": 0}).encode("utf-8"))
        mock_urlopen.return_value.__enter__.return_value = fake_response

        status, code, msg = verify_m365_cloud("satya@microsoft.com")
        self.assertEqual(status, VerificationStatus.VALID)
        self.assertEqual(code, 200)
        self.assertIn("Microsoft 365 Cloud Directory", msg)

    @patch("urllib.request.urlopen")
    def test_m365_cloud_user_not_found(self, mock_urlopen):
        # Mock response with IfExistsResult: 1 (User Does Not Exist)
        fake_response = io.BytesIO(json.dumps({"IfExistsResult": 1, "ThrottleStatus": 0}).encode("utf-8"))
        mock_urlopen.return_value.__enter__.return_value = fake_response

        status, code, msg = verify_m365_cloud("fakeuser@microsoft.com")
        self.assertEqual(status, VerificationStatus.INVALID)
        self.assertEqual(code, 404)
        self.assertIn("Recipient not found", msg)

    @patch("urllib.request.urlopen")
    def test_m365_cloud_throttled(self, mock_urlopen):
        # Mock response with ThrottleStatus: 1
        fake_response = io.BytesIO(json.dumps({"ThrottleStatus": 1}).encode("utf-8"))
        mock_urlopen.return_value.__enter__.return_value = fake_response

        status, code, msg = verify_m365_cloud("test@microsoft.com")
        self.assertEqual(status, VerificationStatus.UNVERIFIED_TEMP_ERROR)
        self.assertEqual(code, 429)

    @patch("urllib.request.urlopen")
    def test_pgp_keyring_found(self, mock_urlopen):
        # Mock PGP keyserver response with matching uid
        fake_body = (
            "info:1:1\n"
            "pub:12345:1:1024:123::\n"
            "uid:Linus Torvalds <torvalds@kernel.org>:123::\n"
        ).encode("utf-8")
        fake_response = io.BytesIO(fake_body)
        mock_urlopen.return_value.__enter__.return_value = fake_response

        status, code, msg = verify_pgp_keyring("torvalds@kernel.org")
        self.assertEqual(status, VerificationStatus.VALID)
        self.assertEqual(code, 200)
        self.assertIn("OpenPGP", msg)

    @patch("urllib.request.urlopen")
    def test_pgp_keyring_not_found(self, mock_urlopen):
        fake_body = "info:1:0\n".encode("utf-8")
        fake_response = io.BytesIO(fake_body)
        mock_urlopen.return_value.__enter__.return_value = fake_response

        status, code, msg = verify_pgp_keyring("unknown@kernel.org")
        self.assertIsNone(status)
        self.assertIsNone(code)

    @patch("urllib.request.urlopen")
    def test_github_commits_found(self, mock_urlopen):
        fake_response = io.BytesIO(json.dumps({"total_count": 15}).encode("utf-8"))
        mock_urlopen.return_value.__enter__.return_value = fake_response

        status, code, msg = verify_github_commits("dev@company.com")
        self.assertEqual(status, VerificationStatus.VALID)
        self.assertEqual(code, 200)
        self.assertIn("15 public commits", msg)

    @patch("verifier.verify_m365_cloud")
    def test_run_alternative_verification_m365(self, mock_m365):
        mock_m365.side_effect = [
            (VerificationStatus.VALID, 200, "Verified in M365"),
            (VerificationStatus.INVALID, 404, "Not found in M365")
        ]

        provider = ProviderInfo(name="Microsoft 365", details="outlook.com")
        candidates = [("john.doe@company.com", "first.last"), ("jdoe@company.com", "flast")]

        results = run_alternative_verification(
            candidates=candidates,
            domain="company.com",
            provider=provider,
            delay=0.0
        )

        self.assertEqual(len(results), 2)
        self.assertEqual(results[0].status, VerificationStatus.VALID)
        self.assertEqual(results[1].status, VerificationStatus.INVALID)

    @patch("verifier.check_port_25_connectivity", return_value=False)
    @patch("verifier.get_mx_records")
    @patch("verifier.fingerprint_mail_provider")
    @patch("verifier.run_alternative_verification")
    def test_run_verification_auto_fallback(self, mock_alt, mock_fingerprint, mock_mx, mock_p25):
        from models import CandidateResult, MXRecord

        mock_mx.return_value = [MXRecord(host="mail.company.com", priority=10)]
        mock_fingerprint.return_value = ProviderInfo(name="Microsoft 365", details="outlook.com")
        mock_alt.return_value = [
            CandidateResult(
                email="john.doe@company.com",
                pattern_name="first.last",
                status=VerificationStatus.VALID,
                smtp_code=200,
                smtp_message="Verified via M365 Cloud"
            )
        ]

        person = NameParts(first_name="John", last_name="Doe")
        result = run_verification(
            domain="company.com",
            person=person,
            candidates=[("john.doe@company.com", "first.last")],
            cloud_fallback=True
        )

        self.assertFalse(result.port_25_open)
        self.assertEqual(result.verification_method, "HTTPS Cloud & Identity Verifier")
        self.assertEqual(len(result.get_valid_emails()), 1)
        self.assertEqual(result.candidates[0].status, VerificationStatus.VALID)


if __name__ == "__main__":
    unittest.main()
