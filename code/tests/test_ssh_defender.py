import unittest
from unittest.mock import patch, mock_open, MagicMock
from src.ssh_defender import SSHDefender
import time

class TestSSHDefender(unittest.TestCase):
    def setUp(self):
        self.defender = SSHDefender()
        
    @patch("builtins.open",new_callable=mock_open, read_data=
        "2025-05-07T12:00:00 Failed password for invalid user from 192.168.0.100\n"
        "2025-05-07T12:00:01 Failed password for invalid user from 192.168.0.100\n"
        "2025-05-07T12:00:02 Failed password for invalid user from 192.168.0.100\n"
        "2025-05-07T12:00:03 Failed password for invalid user from 192.168.0.100\n"
        "2025-05-07T12:00:04 Failed password for invalid user from 192.168.0.100\n")
    
    @patch("time.time", return_value=time.mktime(time.strptime("2025-05-07 12:00:05", "%Y-%m-%d %H:%M:%S")))

    def test_analyze_logs_counts_attempts(self,mock_time,mock_open_file):
        result = self.defender.analyze_logs()
        self.assertTrue(result)
        self.assertEqual(self.defender.attempts["192.168.0.100"],5)
        
        
    @patch("subprocess.run")
    def test_ban_ip_success(self,mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        result = self.defender.ban_ip("10.0.0.1")
        self.assertTrue(result)
        self.assertIn("10.0.0.1",self.defender.banned_ips)
                   
if __name__ == "__main__":
    unittest.main() 
            