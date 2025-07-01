import unittest
from unittest.mock import patch, MagicMock
from src.bandit_analysis import Scanner

# From "code/" folder execute:
# python -m unittest tests/test_bandit_analysis.py

class TestScanner(unittest.TestCase):

    def setUp(self):
        self.scanner = Scanner()

    def test_display_results_no_issues(self):
        with patch('builtins.print') as mock_print:
            self.scanner.display_results([])
            mock_print.assert_called_with("No security issues found! Everything looks secured.")

    def test_display_results_with_issue(self):
        fake_issue = MagicMock()
        fake_issue.severity = 'medium'
        fake_issue.confidence = 'high'
        fake_issue.fname = 'example.py'
        fake_issue.lineno = 5
        fake_issue.text = 'This is a test issue'
        fake_issue.test_id = 'B101'

        with patch('builtins.print') as mock_print:
            self.scanner.display_results([fake_issue])
            mock_print.assert_any_call("Scan Results: ")
            mock_print.assert_any_call("Found 1 potential vulnerabilities.")

    def test_scan_file_invalid_path(self):
        with patch('builtins.print') as mock_print:
            self.scanner.scan_file("not_a_real_file.py")
            mock_print.assert_any_call("File not found!")

    def test_scan_directory_invalid_path(self):
        with patch('builtins.print') as mock_print:
            self.scanner.scan_directory("not_a_real_dir")
            mock_print.assert_any_call("Directory not found!")

    def test_check_injection_flaws_invalid_path(self):
        with patch('builtins.print') as mock_print:
            self.scanner.check_injection_flaws("bad_path")
            mock_print.assert_any_call("Target not found!")

    def test_check_weak_cryptography_invalid_path(self):
        with patch('builtins.print') as mock_print:
            self.scanner.check_weak_cryptography("bad_path")
            mock_print.assert_any_call("Target not found!")

    def test_run_all_checks_invalid_path(self):
        with patch('builtins.print') as mock_print:
            self.scanner.run_all_checks("bad_path")
            mock_print.assert_any_call("Target not found!")

if __name__ == '__main__':
    unittest.main()
