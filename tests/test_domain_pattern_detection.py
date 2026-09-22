import unittest
from unittest.mock import patch, MagicMock
from models import NameParts, ProviderInfo, VerificationStatus, ReconResult, CandidateResult
from generator import generate_email_patterns
from verifier import (
    compute_confidence,
    detect_domain_email_pattern,
    extract_pattern_from_localpart,
    run_verification,
)


class TestDomainPatternDetection(unittest.TestCase):

    def test_extract_pattern_from_localpart(self):
        # Role accounts should be ignored
        self.assertIsNone(extract_pattern_from_localpart("info"))
        self.assertIsNone(extract_pattern_from_localpart("support"))
        self.assertIsNone(extract_pattern_from_localpart("admin"))
        self.assertIsNone(extract_pattern_from_localpart("dmarc"))

        # Separator formats
        self.assertEqual(extract_pattern_from_localpart("john.doe"), "first.last")
        self.assertEqual(extract_pattern_from_localpart("j.doe"), "f.last")
        self.assertEqual(extract_pattern_from_localpart("john.d"), "first.l")
        self.assertEqual(extract_pattern_from_localpart("john_doe"), "first_last")
        self.assertEqual(extract_pattern_from_localpart("j_doe"), "f_last")

        # Single tokens
        self.assertEqual(extract_pattern_from_localpart("zaid"), "first")
        self.assertEqual(extract_pattern_from_localpart("sarah"), "first")
        self.assertEqual(extract_pattern_from_localpart("superlongcompoundname"), "firstlast")

    def test_preferred_pattern_confidence_elevation(self):
        # Without preferred pattern, first.last gets 85, first gets 60
        base_first_last = compute_confidence(VerificationStatus.UNVERIFIED_PORT_BLOCKED, "first.last")
        base_first = compute_confidence(VerificationStatus.UNVERIFIED_PORT_BLOCKED, "first")
        self.assertGreater(base_first_last, base_first)

        # With preferred_pattern="first", first gets 90 and first.last gets max 60
        pref_first = compute_confidence(
            VerificationStatus.UNVERIFIED_PORT_BLOCKED,
            "first",
            preferred_pattern="first"
        )
        pref_first_last = compute_confidence(
            VerificationStatus.UNVERIFIED_PORT_BLOCKED,
            "first.last",
            preferred_pattern="first"
        )
        self.assertEqual(pref_first, 90)
        self.assertEqual(pref_first_last, 60)
        self.assertGreater(pref_first, pref_first_last)

    def test_preferred_pattern_with_google_workspace(self):
        provider = ProviderInfo(name="Google Workspace", spf_record="v=spf1 include:_spf.google.com -all")
        # With preferred_pattern="first", Google bonus + strict SPF applies to "first"
        conf = compute_confidence(
            VerificationStatus.UNVERIFIED_PORT_BLOCKED,
            "first",
            provider=provider,
            preferred_pattern="first"
        )
        # 90 (base) + 5 (google) = 95
        self.assertEqual(conf, 95)

    def test_generator_respects_preferred_pattern(self):
        patterns = generate_email_patterns("Zaid", None, "Khan", "company.com", preferred_pattern="first")
        self.assertTrue(len(patterns) > 0)
        # First candidate in list must be the preferred "first" pattern
        self.assertEqual(patterns[0][0], "zaid@company.com")
        self.assertEqual(patterns[0][1], "first")

        # Test flast preference
        patterns_flast = generate_email_patterns("Zaid", None, "Khan", "company.com", preferred_pattern="flast")
        self.assertEqual(patterns_flast[0][0], "zkhan@company.com")
        self.assertEqual(patterns_flast[0][1], "flast")

    @patch("verifier.detect_domain_email_pattern")
    @patch("verifier.check_port_25_connectivity", return_value=False)
    @patch("verifier.get_mx_records")
    def test_run_verification_with_preferred_pattern(self, mock_mx, mock_p25, mock_detect):
        mock_mx.return_value = [MagicMock(host="aspmx.l.google.com", priority=1)]
        mock_detect.return_value = (None, None, [], None)

        person = NameParts(first_name="Zaid", last_name="Khan", raw_name="Zaid Khan")
        candidates = [
            ("zaid@company.com", "first"),
            ("zaid.khan@company.com", "first.last"),
            ("zkhan@company.com", "flast")
        ]

        result = run_verification(
            domain="company.com",
            person=person,
            candidates=candidates,
            cloud_fallback=False,
            preferred_pattern="first",
            auto_detect_pattern=False
        )

        best = result.get_primary_candidate()
        self.assertIsNotNone(best)
        self.assertEqual(best.email, "zaid@company.com")
        self.assertEqual(best.pattern_name, "first")
        self.assertEqual(best.confidence, 95)

    @patch("verifier.detect_domain_email_pattern")
    @patch("verifier.check_port_25_connectivity", return_value=False)
    @patch("verifier.get_mx_records")
    def test_run_verification_direct_osint_match(self, mock_mx, mock_p25, mock_detect):
        mock_mx.return_value = [MagicMock(host="mail.company.com", priority=10)]
        # Simulate domain OSINT finding exact email for the person
        mock_detect.return_value = (
            "first",
            "Found on website contact page",
            ["zaid@company.com", "info@company.com"],
            ("zaid@company.com", "first")
        )

        person = NameParts(first_name="Zaid", last_name="Khan", raw_name="Zaid Khan")
        candidates = [
            ("zaid@company.com", "first"),
            ("zaid.khan@company.com", "first.last"),
        ]

        result = run_verification(
            domain="company.com",
            person=person,
            candidates=candidates,
            cloud_fallback=False,
            auto_detect_pattern=True
        )

        best = result.get_primary_candidate()
        self.assertIsNotNone(best)
        self.assertEqual(best.email, "zaid@company.com")
        self.assertEqual(best.status, VerificationStatus.VALID)
        self.assertEqual(best.confidence, 100)
        self.assertIn("Confirmed via domain OSINT", best.smtp_message)


if __name__ == "__main__":
    unittest.main()
