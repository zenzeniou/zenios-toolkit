from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from colorama import Fore,Style
import os
import base64
import getpass


class CryptoTool:
    def __init__(self):
        self.backend = default_backend()
        self.supported_algos = {
            "1" : "AES-256 (Symmetric)",
            "2" : "RSA (Assymetric)",
            "3" : "SHA-256",
            "4" : "SAH-3-256",
        }
        
    def display_options(self):
        print(Fore.CYAN + "\nMain Options:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. Encryption/Decryption" + Style.RESET_ALL)
        print(Fore.CYAN + "2. Hashing" + Style.RESET_ALL)
        print(Fore.CYAN + "3. Exit" + Style.RESET_ALL)
        
    
    def render_user_choice(self,prompt,min_number,max_number):
        while True:
            try:
                choice = int(input(Fore.YELLOW + prompt + Style.RESET_ALL))
                if min_number <= choice <= max_number:
                    return choice
                else:
                    print(Fore.RED + f"Enter a number between {min_number} and {max_number}." + Style.RESET_ALL)
            except ValueError:
                print(Fore.RED + "Invalid input. Please enter a valid number." + Style.RESET_ALL)
                
    def run(self):
        while True:
            self.display_options()
            choice = self.render_user_choice("Enter your choice (1-3):",1,3)
            
            if choice == 1:
                self.handle_encryption()
            elif choice == 2:
                self.handle_hashing()
            elif choice == 3:
                print(Fore.GREEN + "Thank you for choosing my crypto toolkit! Goodbye." + Style.RESET_ALL)
                break
                
                
    def handle_encryption(self):
        print(Fore.CYAN + "Supported Algorithms:" + Style.RESET_ALL)
        print(Fore.CYAN + "1. AES-256 (Symmetric)" + Style.RESET_ALL)
        print(Fore.CYAN + "2. RSA (Assymetric)" + Style.RESET_ALL)
        
        algorithm_choice = self.render_user_choice("Enter your choice (1-2):",1,2)    
        operation = self.render_user_choice("1.Encrypt \n2.Decrypt\nChoose Operation (1-2)",1,2)
        
        if algorithm_choice == 1:
            if operation == 1:
                self.aes_encrypt()
            else:
                self.aes_decrypt()
        
        elif algorithm_choice == 2:
            if operation == 1:
                self.rsa_encrypt()
            else:
                self.rsa_decrypt()  
                
    
    def handle_hashing(self):
        print(Fore.CYAN + "\nSupported Algorithms:" + Style.RESET_ALL)
        print(Fore.CYAN + "1.SHA-256" + Style.RESET_ALL)
        print(Fore.CYAN + "2.SHA-3-25" + Style.RESET_ALL)
        
        algorithm_choice = self.render_user_choice("Select Algorithm (1-2): ", 1 , 2)
        while True:
            message = input(Fore.YELLOW + "Enter message to hash: " + Style.RESET_ALL)
            if message.strip():
                break
            print(Fore.RED + "Message cannot be empty. Please try again." + Style.RESET_ALL)
        
        try:
            message = message.encode('utf-8')
            if algorithm_choice == 1:
                digest_process = self.sha256_hash(message)
            elif algorithm_choice == 2:
                digest_process = self.sha3_256_hash(message)
            
            print(Fore.GREEN + "\n Hash Result:" + Style.RESET_ALL)
            print(Fore.GREEN + digest_process + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Error during hashing: {str(e)}" + Style.RESET_ALL)
                   
        
    def aes_encrypt(self):
        print(Fore.CYAN + "\nAES Encryption" + Style.RESET_ALL)
        while True:
            message = input(Fore.YELLOW + "Enter message to encrypt: " + Style.RESET_ALL)
            if message.strip():
                break
            print(Fore.RED + "Message cannot be empty. Please try again." + Style.RESET_ALL)
            
        while True:
            password = getpass.getpass(Fore.YELLOW + "Enter encryption password: " + Style.RESET_ALL)
            if password.strip():
                break
            print(Fore.RED + "Password cannot be empty. Please try again." + Style.RESET_ALL)
        
        try:
            message = message.encode('utf-8') # Ensure message is in bytes
            password = password.encode('utf-8') # Ensure password is in bytes
            
            salt = os.urandom(16) # Generate a random salt
            kdf = PBKDF2HMAC(algorithm=hashes.SHA3_256(),length=32,salt=salt,iterations=100000,backend=self.backend) # Get a key from the password
            key = kdf.derive(password) # Derive the key
            
            iv = os.urandom(16) # iv iv used to ensure that the same plaintext encrypts to different ciphertexts each time.
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=self.backend) #combine the key and iv
            encryptor = cipher.encryptor() # Create an encryptor object
            ciphertext = encryptor.update(message) + encryptor.finalize()
            
            encrypted_data = salt + iv + ciphertext # Combine salt, iv, and ciphertext
            encoded_data = base64.b64encode(encrypted_data).decode('utf-8') # Encode the result in base64
            
            print(Fore.GREEN + "\nEncrypted Result:" + Style.RESET_ALL)
            print(Fore.GREEN + encoded_data + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Encryption failed: {str(e)}" + Style.RESET_ALL)
        
        
    def aes_decrypt(self):
        print(Fore.CYAN + "\nAES Decryption" + Style.RESET_ALL)
        while True:
            encoded_data = input(Fore.YELLOW + "Enter Encrypted Data: " + Style.RESET_ALL)
            if encoded_data.strip():
                break
            print(Fore.RED + "Encrypted data cannot be empty. Please try again." + Style.RESET_ALL)
            
        while True:
            password = getpass.getpass(Fore.YELLOW + "Enter decryption password: " + Style.RESET_ALL)
            if password.strip():
                break
            print(Fore.RED + "Password cannot be empty. Please try again." + Style.RESET_ALL)
        
        try:
            password = password.encode('utf-8') # Ensure password is in bytes
            encrypted_data = base64.b64decode(encoded_data) # Decode the base64 encoded data
            if len(encrypted_data) < 32:
                raise ValueError("Invalid encrypted data format")
                
            salt = encrypted_data[:16] # Extract the salt, 16 bytes from the start
            iv = encrypted_data[16:32] # Extract the iv, 16 bytes after the salt
            ciphertext = encrypted_data[32:] # The rest is the ciphertext
            
            kdf = PBKDF2HMAC(algorithm=hashes.SHA3_256(),length=32,salt=salt,iterations=100000,backend=self.backend) # Derive the key from the password and salt
            key = kdf.derive(password)
            
            cipher = Cipher(algorithms.AES(key),modes.CFB(iv),backend=self.backend)
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            print(Fore.GREEN + "\nDecrypted Message:" + Style.RESET_ALL)
            print(Fore.GREEN + plaintext.decode('utf-8') + Style.RESET_ALL)
        except Exception as e:
            print(Fore.RED + f"Decryption failed: {str(e)}" + Style.RESET_ALL)
            
                        
    def rsa_encrypt(self):
        print(Fore.CYAN + "RSA Encryption" + Style.RESET_ALL)
        while True:
            message = input(Fore.YELLOW + "Enter message to encrypt: " + Style.RESET_ALL)
            if message.strip():
                break
            print(Fore.RED + "Message cannot be empty. Please try again." + Style.RESET_ALL)
        
        try:
            message = message.encode('utf-8') # Ensure message is in bytes
            
            if not hasattr(self, 'rsa_private_key'):
                self.rsa_private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048,
                    backend=self.backend
                ) # Generate a new RSA private key, 65537 is a common public exponent, 2048 is a common key size
                
            public_key = self.rsa_private_key.public_key()
            ciphertext = public_key.encrypt(
                message,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )  # Encrypt the message using the public key, OAEP is a padding scheme, mgf is a mask generation function
                      
            encoded_ciphertext = base64.b64encode(ciphertext).decode('utf-8') # Encode the ciphertext in base64
            print(Fore.GREEN + "\nEncrypted Result:" + Style.RESET_ALL)
            print(Fore.GREEN + encoded_ciphertext + Style.RESET_ALL)
            
            while True:
                save_key = input(Fore.YELLOW + "\nSave private key for decryption? (y/n): " + Style.RESET_ALL).lower()
                if save_key in ('y', 'n'):
                    break
                print(Fore.RED + "Please enter 'y' or 'n'." + Style.RESET_ALL)
                
            if save_key == "y":
                while True:
                    filename = input(Fore.YELLOW + "Enter the filename to save the private key: " + Style.RESET_ALL)
                    if filename.strip():
                        break
                    print(Fore.RED + "Filename cannot be empty. Please try again." + Style.RESET_ALL)
                
                try:
                    pem = self.rsa_private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    ) # Convert the private key to PEM format, pem is a base64 encoded format.
                    
                    with open(filename,'wb') as file:
                        file.write(pem)
                    print(Fore.GREEN + f"Private key was saved to {filename}" + Style.RESET_ALL)
                except Exception as e:
                    print(Fore.RED + f"Error saving private key: {str(e)}" + Style.RESET_ALL)
                    
        except Exception as e:
            print(Fore.RED + f"Encryption failed: {str(e)}" + Style.RESET_ALL)
            
    
    def rsa_decrypt(self):
        print(Fore.CYAN + "\nRSA Decryption" + Style.RESET_ALL)
        while True:
            encoded_ciphertext = input(Fore.YELLOW + "Enter encrypted data: " + Style.RESET_ALL)
            if encoded_ciphertext.strip():
                break
            print(Fore.RED + "Encrypted data cannot be empty. Please try again." + Style.RESET_ALL)
        
        if not hasattr(self,'rsa_private_key'):
            while True:
                key_file = input(Fore.YELLOW + "Enter path to RSA private key file: " + Style.RESET_ALL) #ask the user for the path to the private key file
                if key_file.strip():
                    break
                print(Fore.RED + "Filename cannot be empty. Please try again." + Style.RESET_ALL)
                
            try:
                with open(key_file,'rb') as file:
                    self.rsa_private_key = serialization.load_pem_private_key(
                        file.read(),
                        password=None,
                        backend=self.backend
                    ) #trying to load the private key from the file, if it is not found, it will raise an error.
                    
            except FileNotFoundError:
                print(Fore.RED + "Error: File not found." + Style.RESET_ALL)
                return
            except Exception as e:
                print(Fore.RED + f"Error loading private key: {str(e)}" + Style.RESET_ALL)
                return
            
        try:
            cipher_text = base64.b64decode(encoded_ciphertext)
            plaintext = self.rsa_private_key.decrypt(
                cipher_text,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ) #this part is decrypting the ciphertext using the private key
            
            print(Fore.GREEN + "\nDecrypted Message: " + Style.RESET_ALL)
            print(Fore.GREEN + plaintext.decode('utf-8') + Style.RESET_ALL)
            
        except Exception as e:
            print(Fore.RED + f"Decryption failed: {str(e)}" + Style.RESET_ALL)    
            
            
    def sha256_hash(self,message):
        try:
            digest = hashes.Hash(hashes.SHA256(), backend=self.backend) #set the hashing algorithm to SHA-256
            digest.update(message) #digest is a hash object that can be used to hash data
            return digest.finalize().hex() #hex because it is a hexadecimal representation of the hash
        except Exception as e:
            raise Exception(f"SHA-256 hashing failed: {str(e)}")
    
    def sha3_256_hash(self,message):
        try:
            digest = hashes.Hash(hashes.SHA3_256(), backend=self.backend) #set the hashing algorithm to SHA-3-256
            digest.update(message) #updating the hash object with the message
            return digest.finalize().hex() #finalize the hash and return it in hexadecimal format
        except Exception as e:
            raise Exception(f"SHA3-256 hashing failed: {str(e)}")                                                      
        

def main():
    try:
        toolkit = CryptoTool()
        toolkit.run()
    except KeyboardInterrupt:
        print(Fore.RED + "\nOperation cancelled by user. Exiting..." + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"An unexpected error occurred: {str(e)}" + Style.RESET_ALL)
    

if __name__ == "__main__":
    main()
