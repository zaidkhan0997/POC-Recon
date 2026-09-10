import unittest
from generator import generate_email_patterns


class TestGenerator(unittest.TestCase):

    def test_standard_patterns(self):
        candidates = generate_email_patterns(
            first_name="Jane",
            middle_name=None,
            last_name="Doe",
            domain="example.com"
        )
        emails = [email for email, _ in candidates]

        expected_patterns = [
            "jane.doe@example.com",
            "jane@example.com",
            "jdoe@example.com",
            "janedoe@example.com",
            "jane_doe@example.com",
            "doe.jane@example.com",
            "j.doe@example.com",
            "doe@example.com",
            "djane@example.com",
            "jane.d@example.com",
            "j_doe@example.com",
        ]

        for exp in expected_patterns:
            self.assertIn(exp, emails, f"Expected {exp} to be in generated candidates.")

    def test_unicode_and_accents_normalization(self):
        candidates = generate_email_patterns(
            first_name="René",
            middle_name=None,
            last_name="Müller",
            domain="example.com"
        )
        emails = [email for email, _ in candidates]

        self.assertIn("rene.muller@example.com", emails)
        self.assertIn("rmuller@example.com", emails)

    def test_middle_name_patterns(self):
        candidates = generate_email_patterns(
            first_name="John",
            middle_name="C",
            last_name="Smith",
            domain="corp.com"
        )
        emails = [email for email, _ in candidates]

        self.assertIn("john.c.smith@corp.com", emails)
        self.assertIn("johncsmith@corp.com", emails)
        self.assertIn("jcsmith@corp.com", emails)

    def test_deduplication(self):
        candidates = generate_email_patterns(
            first_name="Bob",
            middle_name=None,
            last_name="Bob",
            domain="example.com"
        )
        emails = [email for email, _ in candidates]
        self.assertEqual(len(emails), len(set(emails)), "Generated candidate list contains duplicates.")


if __name__ == "__main__":
    unittest.main()
