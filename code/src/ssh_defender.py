import os
import re
import time
import subprocess
import smtplib
from pathlib import Path
from shutil import copyfile
from datetime import datetime
from email.message import EmailMessage

#To make sure the user has the package needed = "dpkg -l | grep rsyslog"
#If installed the user will see something like this = "ii   rsyslog   ...   ..."

"""
sudo apt install rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog

"""

#Command on linux to see banned IPs = "sudo iptables -L INPUT -n -v --line-numbers"
#Command on linux to unban an IP = "sudo iptables -D INPUT 1" where 1 is the line number


#Enviroment Variables set up process for email functionality:
#export EMAIL_FROM="yourname@gmail.com"
#export EMAIL_USER="yourname@gmail.com"  # Your full Gmail address
#export EMAIL_PASSWORD="your-16-digit-app-password"  # The app password you generated
#export SMTP_SERVER="smtp.gmail.com"
#export SMTP_PORT=465

#Link to create a gmail app passwords = https://myaccount.google.com/apppasswords


#The program should always run with sudo priveleges.
#In order for the program to work with the email functionality: The user should use "sudo -E ssh_defender.py"


LOG_FILE = "/var/log/auth.log"
BACKUP_DIR = "/var/log/ssh_defender_backups"
NUMBER_OF_FAILED_ATTEMPTS = 5
BANTIME = 3600  # 1 hour in seconds
SAFE_IPS = ["127.0.0.1","192.168.1.1"] #These IPs are safe because they are local or trusted IPs

class SSHDefender:
    def __init__(self):
        self.attempts = {} #should be reseted
        self.banned_ips = {} #Dictionary to keep track of banned IPs and their ban time
        self.setup_directories() #Make sure the backup directory exists
        
    def setup_directories(self):
        Path(BACKUP_DIR).mkdir(parents=True, exist_ok=True) #Make sure the backup directory exists
        
    def analyze_logs(self):
        
        self.attempts = {} #Reset attempts at each run
        current_time = time.time() #get the current time
        
        try:
            with open(LOG_FILE,'r') as log_file:
                for line in log_file:
                    if "Failed password" in line: #search for failed password attempts
                        time_match = re.search(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})', line)  # ISO 8601 format
                        if time_match:
                            date_part,time_part = time_match.groups() #Extract date and time from the log line
                            log_time_str = f"{date_part} {time_part}" #Combine date + time
                            log_time = time.mktime(time.strptime(log_time_str, "%Y-%m-%d %H:%M:%S"))
                            
                            if current_time - log_time <= BANTIME:
                                ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line) #Extract the IP address from the log line   
                         
                                if ip_match:
                                    ip = ip_match.group(1)
                                    if ip not in SAFE_IPS:
                                        self.attempts[ip] = self.attempts.get(ip, 0) + 1 #Increment the count of failed attempts for the IP
        except FileNotFoundError:
            print(f"Error: Log file {LOG_FILE} not found.")
            return False
        
        return True     
    
    def block_suspicious_ips(self):
        new_banned_ips = []
        current_time = time.time()
        
        #Expired IPs (remove from iptables and internal list)
        expired_ips = [
            ip for ip, ban_time in self.banned_ips.items() #check if the IP is expired
            if current_time - ban_time >= BANTIME #ANd If the ban time has expired
        ]
        
        for ip in expired_ips:
            try:
                subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"],check=True) #this is the command to unban the IP
                print(f"Unbanned IP: {ip}")
            except subprocess.CalledProcessError as e:
                print(f"Failed to unban IP {ip}: {e}")                
            
        #Update banned_ips to only include bans
        self.banned_ips = {ip: ban_time for ip, ban_time in self.banned_ips.items()
                            if current_time - ban_time < BANTIME}
        
         
        #Ban new IPs            
        for ip, count in self.attempts.items():
            if count >= NUMBER_OF_FAILED_ATTEMPTS and ip not in self.banned_ips: #ban the IP if it has failed more than the set number of attempts
                self.ban_ip(ip)
                new_banned_ips.append(ip)
                
        return new_banned_ips                

    def ban_ip(self, ip):
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True) #this is the command to ban the IP
            self.banned_ips[ip] = time.time()
            print(f"Blocked IP: {ip}")
            return True
        except subprocess.CalledProcessError as e:
            print(f"Faied to block IP {ip}: {e}")
            return False
            
    def backup_logs(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S") #get the current timestamp
        backup_path = os.path.join(BACKUP_DIR, f"auth_log_backup_{timestamp}.log") #Create a backup of the log file
        
        try:
            copyfile(LOG_FILE, backup_path) #Copy the log file to the backup directory
            print(f"Created backup of log file: {backup_path}")
            return backup_path
        except Exception as e:
            print(f"Failed to create backup: {e}")
            return None

#This function will return the timestamps of the first and last failed attempts for each IP
    def get_attempt_timestamps(self,ips_to_check):
        
        timestamps = {}
        
        try:
            with open(LOG_FILE,'r') as log_file:
                for line in log_file:
                    if "Failed password" in line:
                        ip_match = re.search(r'from (\d+\.\d+\.\d+\.\d+)' , line) #regex to extract the IP address
                        if ip_match and ip_match.group(1) in ips_to_check:
                            ip = ip_match.group(1)
                            time_match = re.search(r'(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})',line) #regex to extract the date and time
                            
                            if time_match:
                                timestamp = f"{time_match.group(1)} {time_match.group(2)}"
                                if ip not in timestamps:
                                    timestamps[ip] = {"first" : timestamp}
                                timestamps[ip]['last'] = timestamp                                            
        except FileNotFoundError:
            print(f"Log file {LOG_FILE} not found!")
        
        return timestamps
    

#This function is responsible for sending the email notification
def send_email(email_address,intruder_data,blocked_ips):
    if not email_address:
        return False
    
    required_vars = ['EMAIL_FROM','EMAIL_USER','EMAIL_PASSWORD','SMTP_SERVER'] #required enviroment variables
    
    if not all(var in os.environ for var in required_vars):
        print("Email configuration incomplete. Please set all required enviroment variables.") #Some of the enviroment variables are missing
        return False
    
    try:
        msg = EmailMessage() #Create the email message
        msg['Subject'] = "SSH Intruder Alert" #subject of the email
        msg['From'] = os.getenv('EMAIL_FROM') #sender email address
        msg['TO'] = email_address #recipient email address
        
        #This wiil be the body of the email, containing the details of the intrusion
        body = f"""
        The SSH Defender program has detected suspicious SSH connection failures targeted to your machine.

        Intruder: {intruder_data['ip']}
        First failed connection: {intruder_data['first_attempt']}
        Last failed connection: {intruder_data['last_attempt']}
        Total failed attempts: {intruder_data['attempt_count']}

        Blocked Addresses: {', '.join(blocked_ips)}
        """ 
    
        msg.set_content(body.strip()) #Set the body of the email
        smtp_port = int(os.getenv('SMTP_PORT','465')) #SMTP port is the default port and 465 is the default port for SSL
        
        with smtplib.SMTP_SSL(os.getenv('SMTP_SERVER'),smtp_port) as server:
            server.login(os.getenv('EMAIL_USER'),os.getenv('EMAIL_PASSWORD')) #Login to the email server
            server.send_message(msg)
            
        print(f"Sent intrusion alert to {email_address}")
        return True
    
    except Exception as e:
        print(f"Failed to send email notification: {e}")
        return False
                  

def banner():
    print("\n" + "="*50)
    print("SSH INTRUSION RESPONSE TOOL".center(50))
    print("="*50)
    print(f"Monitoring: {LOG_FILE}")
    print(f"No. Of Failed Attempts: {NUMBER_OF_FAILED_ATTEMPTS} failed attempts")
    print(f"Backup directory: {BACKUP_DIR}")
    print("="*50 + "\n")    
    
    
def main():
    banner()
    
    email_address = input("Enter your email address for alerts (leave blank to skip): ").strip()
    
    defender = SSHDefender()
    
    try:
        
        while True:
            if defender.analyze_logs():
                banned_ips = defender.block_suspicious_ips()
                
                if banned_ips:
                    print(f"Banned IPs: {', '.join(banned_ips)}")
                    defender.backup_logs()
                    
                    timestamps = defender.get_attempt_timestamps(banned_ips)
                    
                    if email_address:
                        for ip in banned_ips:
                            if ip in timestamps:
                                intruder_data = {
                                    'ip' : ip,
                                    'first_attempt' : timestamps[ip]['first'],
                                    'last_attempt' : timestamps[ip]['last'],
                                    'attempt_count' : defender.attempts.get(ip,0)
                                }
                                
                                send_email(email_address,intruder_data,list(defender.banned_ips.keys()))
                else:
                    print("No suspicious IPs found")   
        
            time.sleep(60)                                                 
        
    except KeyboardInterrupt:
        print("\nExiting SSH Defender...")
        
  
        
if __name__ == "__main__":
    main() 
                                                                                    