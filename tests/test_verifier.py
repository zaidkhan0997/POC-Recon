import unittest
from unittest.mock import patch, MagicMock
from models import MXRecord, VerificationStatus, NameParts
from verifier import (
    get_mx_records,
    fingerprint_mail_provider,
    check_catch_all,
    verify_single_candidate,
    run_verification,
)


class TestVerifier(unittest.TestCase):

    @patch("dns.resolver.Resolver.resolve")
    def test_get_mx_records_success(self, mock_resolve):
        # Create mock MX answer
        r1 = MagicMock()
        r1.exchange = "mail2.example.com."
        r1.preference = 20

        r2 = MagicMock()
        r2.exchange = "mail1.example.com."
        r2.preference = 10

        mock_resolve.return_value = [r1, r2]

        records = get_mx_records("example.com")
        self.assertEqual(len(records), 2)
        # Should be sorted by priority
        self.assertEqual(records[0].host, "mail1.example.com")
        self.assertEqual(records[0].priority, 10)
        self.assertEqual(records[1].host, "mail2.example.com")
        self.assertEqual(records[1].priority, 20)

    def test_fingerprint_provider_google(self):
        mx = [MXRecord(host="aspmx.l.google.com", priority=1)]
        info = fingerprint_mail_provider("example.com", mx)
        self.assertEqual(info.name, "Google Workspace")

    def test_fingerprint_provider_microsoft(self):
        mx = [MXRecord(host="example-com.mail.protection.outlook.com", priority=10)]
        info = fingerprint_mail_provider("example.com", mx)
        self.assertEqual(info.name, "Microsoft 365 / Exchange Online")

    @patch("verifier.SMTPClient")
    def test_check_catch_all_true(self, mock_smtp_cls):
        mock_client = MagicMock()
        mock_smtp_cls.return_value = mock_client
        mock_client.connect.return_value = (220, "smtp.example.com ESMTP")
        mock_client.helo.return_value = (250, "Hello")
        mock_client.mail_from.return_value = (250, "OK")
        mock_client.rcpt_to.return_value = (250, "Recipient OK")

        is_catch_all, code, _ = check_catch_all("mail.example.com", "example.com")
        self.assertTrue(is_catch_all)
        self.assertEqual(code, 250)

    @patch("verifier.SMTPClient")
    def test_check_catch_all_false(self, mock_smtp_cls):
        mock_client = MagicMock()
        mock_smtp_cls.return_value = mock_client
        mock_client.connect.return_value = (220, "smtp.example.com ESMTP")
        mock_client.helo.return_value = (250, "Hello")
        mock_client.mail_from.return_value = (250, "OK")
        mock_client.rcpt_to.return_value = (550, "No such user")

        is_catch_all, code, _ = check_catch_all("mail.example.com", "example.com")
        self.assertFalse(is_catch_all)
        self.assertEqual(code, 550)

    @patch("verifier.SMTPClient")
    def test_verify_single_candidate_valid(self, mock_smtp_cls):
        mock_client = MagicMock()
        mock_smtp_cls.return_value = mock_client
        mock_client.connect.return_value = (220, "smtp.example.com ESMTP")
        mock_client.helo.return_value = (250, "Hello")
        mock_client.mail_from.return_value = (250, "OK")
        mock_client.rcpt_to.return_value = (250, "Recipient OK")

        status, code, msg = verify_single_candidate("jane.doe@example.com", "mail.example.com", "example.com")
        self.assertEqual(status, VerificationStatus.VALID)
        self.assertEqual(code, 250)

    @patch("verifier.SMTPClient")
    def test_verify_single_candidate_invalid(self, mock_smtp_cls):
        mock_client = MagicMock()
        mock_smtp_cls.return_value = mock_client
        mock_client.connect.return_value = (220, "smtp.example.com ESMTP")
        mock_client.helo.return_value = (250, "Hello")
        mock_client.mail_from.return_value = (250, "OK")
        mock_client.rcpt_to.return_value = (550, "5.1.1 User unknown")

        status, code, msg = verify_single_candidate("fake@example.com", "mail.example.com", "example.com")
        self.assertEqual(status, VerificationStatus.INVALID)
        self.assertEqual(code, 550)

    @patch("verifier.get_mx_records")
    def test_dry_run_mode(self, mock_get_mx):
        mock_get_mx.return_value = [MXRecord(host="mail.example.com", priority=10)]
        person = NameParts(first_name="Jane", last_name="Doe", raw_name="Jane Doe")
        candidates = [("jane.doe@example.com", "first.last")]

        result = run_verification(
            domain="example.com",
            person=person,
            candidates=candidates,
            dry_run=True
        )

        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.candidates[0].status, VerificationStatus.SKIPPED)


if __name__ == "__main__":
    unittest.main()
