import unittest
from src.password_generator import PasswordTool

class TestPasswordTool(unittest.TestCase):
    def setUp(self):
        self.tool = PasswordTool()
        
        
    def test_generate_password_no_word(self):
        password = self.tool.generate_passwd(16)
        self.assertEqual(len(password),16)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password)) 
        self.assertTrue(any(c.isdigit() for c in password))
        
    def test_generate_password_with_word(self):
        custom_word = "Secure"
        passwd_length = 20
        
        password = self.tool.generate_passwd(passwd_length,user_word=custom_word)
        self.assertEqual(len(password),passwd_length)     
        self.assertIn(custom_word.replace(" ",""),password)
        
    def test_generate_password_word_too_long(self):
        custom_word = "x" * 40  # Too long
        passwd_length = 16
        password = self.tool.generate_passwd(passwd_length, user_word=custom_word)
        self.assertEqual(password, "")        
        
    
    def test_base64_encode_decode(self):
        original = "LetsTestThis!"
        encoded = self.tool.encode_passwd(original)
        decoded = self.tool.decode_passwd(encoded)
        self.assertEqual(decoded,original)
        
        
if __name__ == "__main__":
    unittest.main()  
                            