import unittest
from unittest.mock import patch
from models import NameParts, MXRecord, VerificationStatus, CandidateResult, ReconResult
from verifier import run_verification


class TestSingleWorkingEmail(unittest.TestCase):

    def test_get_primary_candidate_picks_valid(self):
        person = NameParts(first_name="Dean", last_name="Black", raw_name="Dean Black")
        result = ReconResult(target_domain="verawholehealth.com", person=person)
        c1 = CandidateResult(email="dean.black@verawholehealth.com", pattern_name="first.last", status=VerificationStatus.UNVERIFIED_PORT_BLOCKED)
        c2 = CandidateResult(email="dblack@verawholehealth.com", pattern_name="flast", status=VerificationStatus.VALID)
        result.candidates = [c1, c2]

        best = result.get_primary_candidate()
        self.assertIsNotNone(best)
        self.assertEqual(best.email, "dblack@verawholehealth.com")

    @patch("verifier.check_port_25_connectivity", return_value=True)
    @patch("verifier.check_catch_all", return_value=(False, 250, "OK"))
    @patch("verifier.verify_single_candidate")
    @patch("verifier.get_mx_records")
    def test_early_exit_on_valid_email(self, mock_mx, mock_verify, mock_ca, mock_p25):
        mock_mx.return_value = [MXRecord(host="mail.example.com", priority=10)]
        mock_verify.side_effect = [
            (VerificationStatus.VALID, 250, "2.1.5 Recipient OK"),
            (VerificationStatus.INVALID, 550, "5.1.1 User unknown"),
        ]

        person = NameParts(first_name="Dean", last_name="Black", raw_name="Dean Black")
        candidates = [
            ("dean.black@example.com", "first.last"),
            ("dean@example.com", "first"),
            ("dblack@example.com", "flast")
        ]

        result = run_verification(
            domain="example.com",
            person=person,
            candidates=candidates,
            early_exit=True
        )

        # Should have stopped after candidate 1 because it was VALID
        self.assertEqual(len(result.candidates), 1)
        self.assertEqual(result.best_candidate.email, "dean.black@example.com")
        self.assertEqual(result.best_candidate.status, VerificationStatus.VALID)


if __name__ == "__main__":
    unittest.main()
