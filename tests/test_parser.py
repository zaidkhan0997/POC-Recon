import unittest
from parser import normalize_domain, parse_person_name, extract_name_from_linkedin_slug


class TestParser(unittest.TestCase):

    def test_normalize_domain_valid(self):
        cases = [
            ("https://www.example.com/", "example.com"),
            ("http://example.com/about?ref=test", "example.com"),
            ("www.example.com#section", "example.com"),
            ("example.com/", "example.com"),
            ("sub.domain.corp.co.uk", "sub.domain.corp.co.uk"),
            ("https://EXAMPLE.COM/path", "example.com"),
            ("example.com:8080/test", "example.com"),
        ]
        for input_url, expected in cases:
            with self.subTest(input_url=input_url):
                self.assertEqual(normalize_domain(input_url), expected)

    def test_normalize_domain_invalid(self):
        invalid_cases = ["", "   ", "http://", "not_a_valid_domain", "example..com"]
        for bad_url in invalid_cases:
            with self.subTest(bad_url=bad_url):
                with self.assertRaises(ValueError):
                    normalize_domain(bad_url)

    def test_parse_person_name_simple(self):
        parts = parse_person_name("Jane Doe")
        self.assertEqual(parts.first_name, "Jane")
        self.assertIsNone(parts.middle_name)
        self.assertEqual(parts.last_name, "Doe")

    def test_parse_person_name_with_middle(self):
        parts = parse_person_name("John C. Smith")
        self.assertEqual(parts.first_name, "John")
        self.assertEqual(parts.middle_name, "C")
        self.assertEqual(parts.last_name, "Smith")

    def test_parse_person_name_with_honorifics(self):
        parts = parse_person_name("Dr. Jane Doe")
        self.assertEqual(parts.first_name, "Jane")
        self.assertEqual(parts.last_name, "Doe")

        parts2 = parse_person_name("Prof. John Smith")
        self.assertEqual(parts2.first_name, "John")
        self.assertEqual(parts2.last_name, "Smith")

    def test_parse_person_name_with_credentials(self):
        parts = parse_person_name("Jane Doe, MBA")
        self.assertEqual(parts.first_name, "Jane")
        self.assertEqual(parts.last_name, "Doe")

        parts2 = parse_person_name("Dr. John C. Smith, Ph.D., PMP")
        self.assertEqual(parts2.first_name, "John")
        self.assertEqual(parts2.middle_name, "C")
        self.assertEqual(parts2.last_name, "Smith")

    def test_parse_person_name_single(self):
        parts = parse_person_name("Cher")
        self.assertEqual(parts.first_name, "Cher")
        self.assertEqual(parts.last_name, "")

    def test_extract_name_from_linkedin_slug(self):
        parts = extract_name_from_linkedin_slug("https://www.linkedin.com/in/jane-doe-12345678/")
        self.assertIsNotNone(parts)
        self.assertEqual(parts.first_name, "Jane")
        self.assertEqual(parts.last_name, "Doe")

        parts2 = extract_name_from_linkedin_slug("john-c-smith-987654")
        self.assertIsNotNone(parts2)
        self.assertEqual(parts2.first_name, "John")
        self.assertEqual(parts2.middle_name, "C")
        self.assertEqual(parts2.last_name, "Smith")


if __name__ == "__main__":
    unittest.main()
