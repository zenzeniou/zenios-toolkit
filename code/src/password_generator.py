import secrets #more secure for password generations than <random>.
import string
import base64
import math
import time
import qrcode
from PIL import Image
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from colorama import Fore,Style

class PasswordTool:
    def __init__(self):
        self.password = None

    def choose_action(self):
        print(f"{Fore.LIGHTYELLOW_EX}\n##############################################################{Style.RESET_ALL}")
        print(f"{Fore.CYAN}\nWelcome to the Password Generator/Encoder/Decoder Tool!{Style.RESET_ALL}")
        print(f"\n{Fore.RED}[1] Generate a strong password{Style.RESET_ALL}")  
        print(f"{Fore.GREEN}[2] Encode/Decode Password using base64{Style.RESET_ALL}")
        print(f"[3] Exit!")  
        print(f"{Fore.LIGHTYELLOW_EX}\n##############################################################{Style.RESET_ALL}")
    
        return input("\nEnter 1 or 2: ").strip()
    
    def handle_password_generation(self):
        length = self.password_length()
        print(f"{Fore.LIGHTMAGENTA_EX}\n- The length of your password will be {length} characters!{Style.RESET_ALL}")
        
        user_word = self.include_user_string(length)
        if user_word != "":
            print(f"{Fore.GREEN}- Your word/phrase is: {user_word}{Style.RESET_ALL}")
            
        self.password = self.generate_passwd(length,user_word)
        print(f"\nYour password is: {Fore.LIGHTBLUE_EX}{self.password}{Style.RESET_ALL}") 
        
        qr_choice = input("\nWould you like to generate a QR code for this password? (y/n): ").strip().lower()
        
        if qr_choice == 'y':
            filename = input("Enter filename for QR code (default: password_qr.png): ").strip()
            if not filename:
                filename = "password_qr.png"
            self.generate_qr(self.password, filename)
         
    
    def handle_encoding_decoding(self):
        print("[1] to Encode a password")
        print("[2] to Decode a password")
        
        user_choice = input("Enter 1 or 2: ").strip()
        
        if user_choice == "1":
            password_to_encode = input("Enter the password you would like to encode: ").strip()
            print(f"Encoded Password: {self.encode_passwd(password_to_encode)}")
            
        elif user_choice == "2":
            password_to_decode = input("Enter the password you would like to decode: ").strip()     
            
            try:
                print(f"Decoded Password:  {self.decode_passwd(password_to_decode)}")
            except Exception as err:
                print(err)
                
        else:
            print("Invlaid password input!")            

#This function is responsible to get the passwd length from the user and make sure is between 12 and 32 characters
    def password_length(self):
        first_attempt = True
        LIMIT =  32 
        
        while True:
            if first_attempt:
                user_input = input(f"{Fore.LIGHTCYAN_EX}\n- How long would you like your password to be? \n- The minimum is 12 characters and the maximum is 32! \n- Length of password: {Style.RESET_ALL}").strip()
                first_attempt = False
            else:
                user_input = input(f"{Fore.LIGHTCYAN_EX}\n- Length of password: {Style.RESET_ALL}")
                        
            if user_input.isdigit():
                user_input = int(user_input)
                if 12 <= user_input <= LIMIT:
                    return user_input
                elif user_input < 12:
                    print(f"\n{Fore.RED}A strong password is longer than 12 characters!{Style.RESET_ALL}")
                elif user_input > LIMIT:
                    print(f"\n{Fore.RED}The limit for this program is 32 characters.{Style.RESET_ALL}")                
            else:
                print(f"\n{Fore.RED}Enter a valid number!{Style.RESET_ALL}")
                                  
#This function asks the user for a custom word/phrase to include in their password
    def include_user_string(self,max_length):
        
        LIMIT = math.floor(max_length / 2) #The limit for user's custom word
        
        print(f"\n{Fore.LIGHTMAGENTA_EX}- You can include a custom word or even a phrase inside your password (max {LIMIT} letters, spaces don't count!). The longer your password length, the longer your custom word/phrase can be!{Style.RESET_ALL}")
        print(f"\n{Fore.LIGHTMAGENTA_EX}- Enter nothing to not include a custom word or a phrase inside your password!{Style.RESET_ALL}")
        
        while True:
            user_input = input(f"\n- Custom word/phrase: ").strip()
            
            if user_input == "":
                return ""
            
            filtered_input = user_input.replace(" ","") #remove spaces
            
            if not filtered_input.isalpha(): #check if input is only strings
                print(f"\n{Fore.RED}Enter a valid word or phrase (letters and spaces only)!{Style.RESET_ALL}")
                continue
            
            if len(filtered_input) > LIMIT: #user exceeded the LIMIT
                exceeded_chars = len(filtered_input) - LIMIT
                print(f"\n{Fore.RED}Exceeded the Limit by ({exceeded_chars} characters)!{Style.RESET_ALL}")
                continue
            
            return user_input

#This function generates the password using secrets and string python built in libraries
    def generate_passwd(self,length, user_word=""):
        
        #Defining the character set for the passwd
        all_chars = string.ascii_letters + string.digits + string.punctuation
        
        #Generate random chars
        passwd_chars = []
        
        filtered_user_word = user_word.replace(" ","")
        word_length = len(filtered_user_word)
        
        remaining_length = length - word_length
        if remaining_length < 0:
            print(f"{Fore.RED}Error: Custom word/phrase is too long!{Style.RESET_ALL}")
            return ""
        
        random_part = ''.join(secrets.choice(all_chars) for _ in range(remaining_length))  
        position = secrets.choice(["start","middle","end"])                      
        
        if position == "start":
            final_password = filtered_user_word + random_part
        elif position == "end":
            final_password = random_part + filtered_user_word
        else:
            middle_index = len(random_part) // 2
            final_password = random_part[:middle_index] + filtered_user_word + random_part[middle_index:]  
            
        return final_password                      
        
        
#This function is responsible to check the password strength using Selenium
    def check_password_strength(self,password):
        
        options = Options()
        options.add_argument("--headless") #Run chrome in headless mode
        options.add_argument("--disable-gpu") #For windows compatibility
        options.add_argument("--log-level=3") #Suppress most logs
        options.add_argument("--disable-logging")
        
        driver = webdriver.Chrome(options=options)
        driver.get("https://bitwarden.com/password-strength/")
        
        try:
            
            time.sleep(2)  # Wait for the password input to be ready
            password_input = driver.find_element(By.CSS_SELECTOR, 'input[name="password"]') # Enter the user's password
            password_input.send_keys(password)
            
            time.sleep(3)  # Wait for the password to be processed
            result_elements = driver.find_elements(By.CSS_SELECTOR, ".font-bold.text-primaryBlue\\!")
            
            if len(result_elements) > 1:
                crack_time = result_elements[1].text
                passw_level = result_elements[0].text
                print("\nAccording to bitwarden.com ...")
                time.sleep(2)
                print(f"\n{Fore.LIGHTGREEN_EX}- It would take a computer {crack_time} to crack your password.{Style.RESET_ALL}")
                print(f"{Fore.LIGHTCYAN_EX}- That means, your password level is: {passw_level.upper()}{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.RED}Could not determine crack time.{Style.RESET_ALL}")            
        
        except Exception as e:
            print(f"An error occurred: {e}")
            
        finally:      
            driver.quit()  # Close the browser

    #This function is responsible to encode a given passwd to base64 format
    def encode_passwd(self,passwd):
        encoded_bytes = base64.b64encode(passwd.encode("utf-8"))
        encoded_string = encoded_bytes.decode("utf-8")
        return encoded_string

    #This function is responsible to decode a given passwd to base64 format
    def decode_passwd(self,passwd):
        decoded_bytes = base64.b64decode(passwd.encode("utf-8"))
        decoded_string = decoded_bytes.decode("utf-8")
        return decoded_string 

    def generate_qr(self,password,filename="password_qr.png"):
        qr = qrcode.QRCode(version=1,box_size=10,border=5)
        qr.add_data(password)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="blue",back_color="white").get_image()
        
        
        pil_img = Image.new("RGB",img.size,(255,255,255))
        pil_img.paste(img,(0,0))
        
        pil_img.show() #This will open the image with the default viewer
        pil_img.save(filename)
        
        print(f"\n{Fore.GREEN}QR code saved as {filename}{Style.RESET_ALL}")
        

def main():
    tool = PasswordTool()
    
    while True:
        user_choice = tool.choose_action()
        
        if user_choice == "1":
            tool.handle_password_generation()
            tool.check_password_strength(tool.password) # <-- Call the Selenium function here
        elif user_choice == "2":
            tool.handle_encoding_decoding()
        elif user_choice == "3":
            print("Stay secure. Goodbye!")
            break        
        else:
            print(f"{Fore.RED}Invalid Choice{Style.RESET_ALL}")                
        

if __name__ == "__main__":
    main()   
     