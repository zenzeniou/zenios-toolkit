import nmap
import re
from datetime import datetime
import json


class NetworkScanner:
    def __init__(self):
        self.scanner = nmap.PortScanner()

    def validate_target(self, target):
        """
        Validates if the input is either:
        - A valid IPv4 address (e.g., 192.168.1.1)
        - A valid IPv4 CIDR range (e.g., 192.168.1.0/24)
        - A valid domain name (e.g., example.com, sub.example.com)
        """
        # Check if user input is an IPv4
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$')
        if ip_pattern.match(target):
            return all(0 <= int(num) <= 255 for num in target.replace('/', '.').split('.')[:4])
        
        # Check if user input is a domain name
        domain_pattern = re.compile(
            r'^(?!https?://)'  # Rejects http:// or https://
            r'([a-zA-Z0-9-]+\.)+'  # Subdomains 
            r'([a-zA-Z]{2,63})$'  # TLD 
        )
        return bool(domain_pattern.match(target))
    
    def save_results(self, host, scan_type, results):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") #get current date and time 
        json_filename = f"scan_results_{host}_{timestamp}.json" #format the filename with host and timestamp in json format
        
        with open(json_filename, 'w') as json_file:
            json.dump(results, json_file, indent=4) #write the results to json file, dump is used to convert the python object to json format
            
        print(f"\nResults saved to {json_filename}")
      
    def network_scanning(self):
        while True:
            target = input("Enter target IP or range (e.x., 192.168.1.1), CIDR range (e.x, 192.168.1.0/24), or domain (ex., example.com): ")
            if self.validate_target(target):
                break
            else:
                print("Invalid format! Try again.")
                
        print("\nSelect scan type:")
        print("1. Stealth SYN SCAN (default)") #SYN scan is the default scan type
        print("2. TCP Scan") #TCP scan is used to connect to the target and check if the port is open or closed
        print("3. UDP Scan") #UDP scan is used to check if the UDP port is open or closed
        print("4. TCP ACK Scan") #TCP ACK scan is used to check if the port is open or closed
        print("5. NULL Scan") #NULL scan is used to check if the port is open or closed
        print("6. FIN Scan") #FIN scan is used to check if the port is open or closed
        print("7. Xmas Scan") #Xmas scan is used to check if the port is open or closed
        
        choice = input("Enter your choice (1-7, default is 1): ") or "1"
        
        scan_types = {
            "1": ("-sS", "Stealth SYN Scan"),
            "2": ("-sT", "TCP Connect Scan"),
            "3": ("-sU", "UDP Scan"),
            "4": ("-sA", "TCP ACK Scan"),
            "5": ("-sN", "NULL Scan"),
            "6": ("-sF", "FIN Scan"),
            "7": ("-sX", "Xmas Scan")
        }            
        
        scan_option, scan_name = scan_types.get(choice, ("-sS", "Stealth SYN Scan")) #default is SYN scan
        
        print(f"\n Starting {scan_name} on {target}...")
        
        try:
            self.scanner.scan(hosts=target, arguments=scan_option) #scan the target with the selected scan type
            
            if not self.scanner.all_hosts():
                print("No hosts found. Check your target and try again.")
                return
            
            json_results = {
                "scan_type": scan_name,
                "target": target,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hosts": []
            } #saved scan results in json format, including scan type, target, and scan time,hosts
            
            for host in self.scanner.all_hosts():
                host_results = f"\nScan results for {host}\n"
                host_results += f"Host Status: {self.scanner[host].state()}\n"
                
                host_json = {
                    "host": host,
                    "status": self.scanner[host].state(),
                    "tcp_ports": [],
                    "udp_ports": []
                }
                
                if "tcp" in self.scanner[host]:
                    host_results += "\nTCP Ports:\n"
                    for port in self.scanner[host]['tcp']:
                        service = self.scanner[host]['tcp'][port]['name'] #get the service name
                        state = self.scanner[host]['tcp'][port]['state'] #get the state of the port
                        product = self.scanner[host]['tcp'][port].get('product', '') #get the product name
                        version = self.scanner[host]['tcp'][port].get('version', '') #get the version of the service
                        host_results += f"Port {port}: {state} - {service} {product} {version}\n".strip() + "\n"
                        
                        host_json["tcp_ports"].append({
                            "port": port,
                            "state": state,
                            "service": service,
                            "product": product,
                            "version": version
                        })
                        
                if "udp" in self.scanner[host]:
                    host_results += "\nUDP Ports:\n"                  
                    for port in self.scanner[host]['udp']:
                        service = self.scanner[host]['udp'][port]['name'] #get the service name
                        state = self.scanner[host]['udp'][port]['state'] #get the state of the port
                        product = self.scanner[host]['udp'][port].get('product', '') #get the product name
                        version = self.scanner[host]['udp'][port].get('version', '') #get the version of the service
                        host_results += f"Port {port}: {state} - {service} {product} {version}\n".strip() + "\n"
                        
                        host_json["udp_ports"].append({
                            "port": port,
                            "state": state,
                            "service": service,
                            "product": product,
                            "version": version
                        })

                print(host_results)
                json_results["hosts"].append(host_json)
                
            self.save_results(target, scan_name, json_results)
                
        except Exception as e:
            print(f"An error occurred: {e}")
    
    def vulnerability_detection(self):
        while True:
            target = input("Enter target IP or range (e.x., 192.168.1.1), CIDR range (e.x, 192.168.1.0/24), or domain (ex., example.com): ")
            if self.validate_target(target):
                break
            else:
                print("Invalid input. Please Try Again.")
                
        program_scripts = {
            '1': ('vuln', 'General vulnerability checks'), #this script will check general vulnerabilities
            '2': ('http-sql-injection', 'Check for SQL injection vulnerabilities'), #this script will check for SQL injection vulnerabilities  
            '3': ('ssl-heartbleed', 'Detect Heartbleed vulnerability'), #this script will check for Heartbleed vulnerability, for example, OpenSSL
            '4': ('smb-vuln-ms17-010', 'Detect EternalBlue vulnerability'), #this script will check for EternalBlue vulnerability, for example, SMBv1
            '5': ('dns-zone-transfer', 'Check for DNS zone transfer vulnerability') #this script will check for DNS zone transfer vulnerability
        }   
        
        print("\nScripts you can use in this program:")
        for number, (script, desc) in program_scripts.items():
            print(f"{number}. {script} - {desc}")
            
        while True:
            choice = input("\n Select a script (1-5): ")
            if choice in program_scripts:
                script, script_name = program_scripts[choice]
                break
            else:
                print("Invalid selection! Please choose 1-5: ")
                
        print(f"\nRunning {script_name} on {target}...")
        
        try:
            self.scanner.scan(hosts=target, arguments=f'-sV --script {script}')
            
            if not self.scanner.all_hosts():
                print("No hosts found. Check your target and try again.")
                return
            
            json_results = {
                "script": script,
                "script_name": script_name,
                "target": target,
                "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "hosts": []
            }
            
            for host in self.scanner.all_hosts():
                host_results = f"\n Vulnerability results for {host}\n"
                
                host_json = {
                    "host": host,
                    "vulnerabilities": []
                }
                
                if 'tcp' in self.scanner[host]:
                    for port in self.scanner[host]['tcp']:
                        port_information = self.scanner[host]['tcp'][port] #get the port information
                        if 'script' in port_information:
                            host_results += f"\nPort {port} ({port_information['name']}) findings:\n"
                            for script_name, output in port_information['script'].items():
                                host_results += f"\n [+] {script_name}:\n{output}\n"
                                
                            host_json["vulnerabilities"].append({
                                "port": port,
                                "service": port_information['name'],
                                "scripts": [{
                                    "name": name,
                                    "output": output
                                } for name, output in port_information['script'].items()]
                            })
                        else:
                            host_results += f"\nNo vulnerabilities found on port {port}!\n"

                print(host_results)
                json_results["hosts"].append(host_json)
            
            self.save_results(target, f"NSE Script: {script}", json_results)
            
        except Exception as e:
            print(f"An error occurred: {e}")                                                                                             
             

def main():
    tool = NetworkScanner()
    
    while True:
        print("\nMain Menu:")
        print("1. Network Scanning & Host Discovery")
        print("2. Vulnerability Detection with built in Scripts")
        print("3. Exit")
        
        choice = input("Enter your choice (1-3): ")
        
        if choice == "1":
            tool.network_scanning()
            
        elif choice == "2":
            tool.vulnerability_detection()
            
        elif choice == "3":
            break
        
        else:
            print("Invalid Choice. Please try again!")
            

if __name__ == "__main__":
    main()
    