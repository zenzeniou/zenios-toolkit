import unittest
from unittest.mock import patch, Mock
from src.web_security import WebSecurityScanner


class TestWebSecurityScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = WebSecurityScanner()
        
    def test_is_valid_url_valid(self):
        valid_urls = [
            "http://example.com",
            "https://127.0.0.1:8000",
            "http://localhost",
            "http://[::1]"
        ]
        
        for url in valid_urls:
            self.assertTrue(self.scanner.is_valid_url(url))
            
    
    def test_is_valid_url_invalid(self):
        invalid_urls = [
            "htp://example.com",
            "example.com",
            "localhost:8000"
        ]
        
        for url in invalid_urls:
            self.assertFalse(self.scanner.is_valid_url(url))
            

    @patch("requests.get")
    def test_check_scrape_data(self,mock_get):
        html = """
        <html>
            <body>
                Contact us at admin@example.com or 192.168.1.1
            </body>
        </html>
        """
        
        mock_get.return_value = Mock(status_code=200,text=html)
        self.scanner.scrape_data("http://test.com") 
        
        
    @patch("requests.get")
    def test_vulnerable_directory_brute_force_detects_open_dir(self, mock_get):
        mock_get.return_value = Mock(status_code=200)
        self.scanner.VULNERABLE_DIRECTORIES = ["admin"]
        self.scanner.vulnerable_directory_brute_force("http://test.com")    
        
        
if __name__ == "__main__":
    unittest.main() 
                                            