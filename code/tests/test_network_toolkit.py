import unittest
from unittest.mock import patch,MagicMock
from src.network_toolkit import NetworkToolkit

class TestNetworkTool(unittest.TestCase):
    def setUp(self):
        self.toolkit = NetworkToolkit()
        
    @patch("builtins.input",side_effect=["1"])
    def test_main_menu_valid_choice(self,mock_input):
        choice = self.toolkit.main_menu()
        self.assertEqual(choice,1)
        
    @patch("builtins.input",side_effect=["a","6","2"])
    def test_main_invalid_then_valid_choice(self,mock_input):
        choice = self.toolkit.main_menu()
        self.assertEqual(choice,2)
        
        
    @patch("builtins.input",side_effect=["localhost","80"])
    @patch("socket.socket")
    
    def test_simple_port_scanner_valid(self,mock_socket,mock_input):
        instance = mock_socket.return_value
        instance.connect_ex.return_value = 0
        with patch("builtins.input",side_effect=["localhost","80"]):
            self.toolkit.simple_port_scanner()
        self.assertIn(80,self.toolkit.open_ports)      
        
    @patch("builtins.input", side_effect=["www.example.com", "", ""])
    @patch("http.client.HTTPConnection")
    def test_check_http_status(self, mock_http_conn, mock_input):
        mock_conn = mock_http_conn.return_value
        mock_conn.getresponse.return_value.status = 200
        mock_conn.getresponse.return_value.reason = "OK"
        mock_conn.getresponse.return_value.getheaders.return_value = [("Content-Type", "text/html")]
        self.toolkit.check_http_status()
        mock_conn.request.assert_called_with("HEAD", "/")
        mock_conn.close.assert_called_once()  
        
        
if __name__ == "__main__":
    unittest.main()     
                                           