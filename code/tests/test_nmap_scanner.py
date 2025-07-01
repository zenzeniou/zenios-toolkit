import unittest
from unittest.mock import patch,MagicMock
from src.nmap_scanner import NetworkScanner


class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        patcher = patch("src.nmap_scanner.nmap.PortScanner",return_value=MagicMock())
        self.addCleanup(patcher.stop)
        self.mock_scanner_class = patcher.start()
        
        self.scanner = NetworkScanner()
        
    def test_validate_target_valid_ipv4(self):
        self.assertTrue(self.scanner.validate_target("192.168.1.1"))
    
    def test_validate_target_valid_cidr(self):
        self.assertTrue(self.scanner.validate_target("10.0.0.0/24"))
        
    def test_validate_target_valid_domain(self):
        self.assertTrue(self.scanner.validate_target("example.com"))
        self.assertTrue(self.scanner.validate_target("sub.example.co.uk"))
        
    def test_validate_target_invalid(self):
        self.assertFalse(self.scanner.validate_target("999.999.999.999"))
        self.assertFalse(self.scanner.validate_target("http://example.com"))  
        
if __name__ == "__main__":
    unittest.main() 
    