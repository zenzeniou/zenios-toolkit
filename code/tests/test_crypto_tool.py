import unittest
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from src.crypto_tool import CryptoTool
import base64
import os

class testCryptoTool(unittest.TestCase):
    def setUp(self):
        self.tool = CryptoTool()
        self.message = b"Test Message"
        self.password = b"password"
        self.backend = default_backend()
        
    def test_sha256_hash(self):    
        digest = self.tool.sha256_hash(self.message)
        self.assertEqual(len(digest),64) #SHA256 = 256 bits = 64 Hex characters
        

    def test_sha3_256_hash(self):
        digest = self.tool.sha3_256_hash(self.message)
        self.assertEqual(len(digest),64)
        
    
    def test_aes_encrypt_decrypt(self):
        #Encrypt
        salt = os.urandom(16)
        iv = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        ) 
        
        key = kdf.derive(self.password)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.tool.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(self.message) + encryptor.finalize()         
        
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.tool.backend)
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()

        self.assertEqual(self.message, decrypted)
        
        
        
    def test_rsa_encryption_decryption(self):
        private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=self.tool.backend)
        public_key = private_key.public_key()   
        
        ciphertext = public_key.encrypt(
            self.message,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)
        )
        
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        self.assertEqual(plaintext, self.message)  
        
        
    def test_invalid_base64_input_aes_decrypt(self):
        with self.assertRaises(Exception):
            base64.b64decode("not_base64!!!")
            
            
    if __name__ == "__main__":
        unittest.main()  
                                  