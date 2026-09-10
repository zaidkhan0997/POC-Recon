import unittest
import tempfile
import os
import json
import csv
from models import ReconResult, NameParts, MXRecord, CandidateResult, VerificationStatus, ProviderInfo
from utils import export_results_json, export_results_csv, export_results_txt, export_results_html


class TestUtils(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.person = NameParts(first_name="Jane", last_name="Doe", raw_name="Jane Doe")
        self.mx = [MXRecord(host="mail.example.com", priority=10)]
        self.provider = ProviderInfo(name="Google Workspace", spf_record="v=spf1 include:_spf.google.com ~all")
        self.candidates = [
            CandidateResult(
                email="jane.doe@example.com",
                pattern_name="first.last",
                status=VerificationStatus.VALID,
                smtp_code=250,
                smtp_message="OK"
            ),
            CandidateResult(
                email="jane@example.com",
                pattern_name="first",
                status=VerificationStatus.INVALID,
                smtp_code=550,
                smtp_message="User not found"
            )
        ]
        self.result = ReconResult(
            target_domain="example.com",
            person=self.person,
            mx_records=self.mx,
            provider=self.provider,
            is_catch_all=False,
            port_25_open=True,
            candidates=self.candidates
        )

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_results_json(self):
        json_path = os.path.join(self.temp_dir.name, "out.json")
        export_results_json(self.result, json_path)
        self.assertTrue(os.path.exists(json_path))

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["domain"], "example.com")
        self.assertEqual(data["person"]["first_name"], "Jane")
        self.assertEqual(len(data["candidates"]), 2)
        self.assertEqual(data["candidates"][0]["status"], "VALID")

    def test_export_results_csv(self):
        csv_path = os.path.join(self.temp_dir.name, "out.csv")
        export_results_csv(self.result, csv_path)
        self.assertTrue(os.path.exists(csv_path))

        with open(csv_path, "r", encoding="utf-8") as f:
            reader = list(csv.DictReader(f))

        self.assertEqual(len(reader), 2)
        self.assertEqual(reader[0]["email"], "jane.doe@example.com")
        self.assertEqual(reader[0]["status"], "VALID")
        self.assertEqual(reader[0]["smtp_code"], "250")

    def test_export_results_txt(self):
        txt_path = os.path.join(self.temp_dir.name, "out.txt")
        export_results_txt(self.result, txt_path, company_linkedin="https://linkedin.com/company/ex", person_linkedin="https://linkedin.com/in/jane")
        self.assertTrue(os.path.exists(txt_path))

        with open(txt_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("example.com", content)
        self.assertIn("Jane Doe", content)
        self.assertIn("jane.doe@example.com", content)
        self.assertIn("[VALID]", content)
        self.assertIn("https://linkedin.com/in/jane", content)

    def test_export_results_html(self):
        html_path = os.path.join(self.temp_dir.name, "out.html")
        export_results_html(self.result, html_path, company_linkedin="https://linkedin.com/company/ex", person_linkedin="https://linkedin.com/in/jane")
        self.assertTrue(os.path.exists(html_path))

        with open(html_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("Jane Doe", content)
        self.assertIn("example.com", content)
        self.assertIn("jane.doe@example.com", content)
        self.assertIn("Google Workspace", content)
        self.assertIn("copyText", content)


if __name__ == "__main__":
    unittest.main()

