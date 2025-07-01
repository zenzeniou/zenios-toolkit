import socket
from scapy.all import srp, sniff
from scapy.layers.l2 import ARP
from scapy.config import conf
from scapy.layers.l2 import Ether
from scapy.layers.http import HTTPRequest
from scapy.all import Raw
import subprocess
import platform
import threading
import http.client


class NetworkToolkit:
    def __init__(self):
        self.open_ports = []  # Shared List to store open ports
        self.lock = threading.Lock()  # Lock for thread-safe operations on open_ports

    def main_menu(self):
        print("Welcome to the Network Toolkit!")
        print("1. Network Scanner")
        print("2. HTTP Packet Sniffer")
        print("3. Ping a Host")
        print("4. Exit")

        while True:
            try:
                choice = int(input("Please select an option (1-4): "))
                if choice in [1, 2, 3, 4]:
                    return choice
                else:
                    print("Please enter a valid option (1-4).")
            except ValueError:
                print("Invalid input. Please enter a number.")
            
    def network_scanner(self):
        print("\n Network Scanner Option: ")
        print("1. Scan Local Network for Active Devices (ARP Scan).")
        print("2. Simple Port Scanner.")
        print("3. Check HTTP Server Status.")
        print("4. Back to Main Menu.")
        
        choice = input("Please select an option (1-4): ").strip()
        
        if choice == "1":
            self.arp_scan()
        elif choice == "2":
            self.simple_port_scanner()
        elif choice == "3":
            self.check_http_status()
        elif choice == "4":
            return
        else:
            print("Invalid choice. Please select a valid option (1-4).")                     
    
    def arp_scan(self):
        print("\nARP Scan - Discovering devices on the local network...")
        
        try:
            # Get the default gateway IP address to determine the local network range
            gateway_ip = conf.route.route("0.0.0.0")[2]  # Pick the default gateway IP address
            network = gateway_ip + "/24"  # Assuming a /24 subnet mask for simplicity
            
        except:
            print("Could not determine the local network. Will use default 192.168.1.0/24 for scanning.") 
            network = "192.168.1.0/24"  # Default network range for scanning
            
        print(f"Scanning network: {network}")
        
        arp = ARP(pdst=network)  # Create an ARP request packet to scan the network
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Create an Ethernet frame to broadcast the ARP request
        packet = ether / arp  # Combine the Ethernet frame and ARP request into a single packet
        
        try:
            result = srp(packet, timeout=3, verbose=0)[0]  # Send the packet and wait for a response

            devices = []  # List to store discovered devices
            for sent, received in result:  # Iterate over the responses
                devices.append({'ip': received.psrc, 'mac': received.hwsrc})  # Store the IP and MAC address of each device

            print("Active devices on the network:")
            print("IP Address".ljust(15) + "MAC Address")
            print("-" * 40)
            for device in devices:  # Print the discovered devices
                print(device['ip'].ljust(15) + device['mac'])
                
            print(f"\nFound {len(devices)} devices on the network.")

        except Exception as e:                    
            print(f"An error occurred while scanning the network: {e}")

    def simple_port_scanner(self):
        target = input("Enter the target IP address or hostname: ").strip()
        ports = input("Enter ports to scan (for example: 80,443 or 1-100): ").strip()
        
        try:
            if "-" in ports:
                start, end = map(int, ports.split("-"))
                ports = range(start, end + 1)  # Plus one to include the end port
            elif "," in ports:
                ports = list(map(int, ports.split(","))) #mapping to int
            else:
                ports = [int(ports)] # Single port scan
                
        except:
            print("Invalid port range. Will use default ports 1-100.")
            ports = range(1, 101)  # 101 to include the end port

        print(f"\nScanning {target} on ports {ports}...")
        print("Port".ljust(10) + "Status")
        print("-" * 40)
        
        self.open_ports = []  # List to store open ports 
        
        def scan_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create a TCP socket
                sock.settimeout(1)  # Set a timeout for the connection attempt
                result = sock.connect_ex((target, port))  # Try to connect to the target on the specified port
                sock.close()
                
                with self.lock:                
                    if result == 0:  # 0 means the port is open
                        status = "OPEN"
                        self.open_ports.append(port)
                    else:
                        status = "CLOSED"
                        
                    print(str(port).ljust(10) + status)  # Print the port status
                
            except:
                with self.lock:
                    print(f"Error connecting to port {port}.")
        
        # Create and start threads                    
        threads = []
        for port in ports:
            t = threading.Thread(target=scan_port, args=(port,)) # Create a thread for each port
            threads.append(t) 
            t.start() # Start the thread
        
        for t in threads:
            t.join() # Wait for all threads to finish                                
                    
        print(f"\nScan Completed. Found {len(self.open_ports)} open ports.")                                              
   
    def http_packet_sniffer(self):
        # Great website for testing: http://testphp.vulnweb.com/signup.php
        
        print("\n HTTP Packet Sniffer - Listening for HTTP packets...")
        print("Press Ctrl+C to stop sniffing.")
        
        def process_packet(packet):  # Callback function to process each captured packet
            if packet.haslayer(HTTPRequest):  # Check if the packet has an HTTP request layer
                url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()  # Extract the URL from the packet
                print(f"HTTP Request: {url}")
                
                if packet.haslayer(Raw):  # Check if the packet has a raw data layer
                    load = packet[Raw].load.decode(errors='ignore')
                    for keyword in ["password", "user", "login", "email", "username",
                                    "auth", "token", "sessionid", "credential", "account",
                                    "passphrase", "secret", "key", "loginid", "apikey"]:  # sensitive keywords
                        if keyword in load.lower():
                            print(f"Sensitive data found: {load}")
                            break
        try:
            sniff(filter="tcp port 80", prn=process_packet, store=False)  # Start sniffing for HTTP packets on port 80                
        except KeyboardInterrupt:
            print("\nSniffing stopped.")
        except Exception as e:
            print(f"An error occurred while sniffing: {e}")                                    
           
    def ping_host(self):
        host = input("Enter the host to ping: ").strip()
        count = input("Enter the number of pings (default is 4): ").strip()  # Number of pings to be sent
        ip_version = input("Use IPv6 (y/n, default is IPv4): ").strip().lower()  # IP version to be used
        
        try:
            if count:
                count = int(count)
            else:
                count = 4  # Default number of pings to send
            
            if ip_version == "y":
                print(f"\nPinging {host} {count} times using IPv6...")
            else:
                print(f"\nPinging {host} {count} times using IPv4...")        
                        
            if platform.system().lower() == "windows":
                base_command = ["ping", "-n", str(count)]  # Windows uses -n for count
                if ip_version == "y":
                    base_command.append("-6")  # IPv6 option for Windows
                else:
                    base_command.append("-4")                
            else:
                base_command = ["ping", "-c", str(count)]  # Unix uses -c for count
                if ip_version == "y":
                    base_command.append("-6")  # IPv6 option for Unix
                else:
                    base_command.append("-4")                
                    
            base_command.append(host)  # Add the host to the command                
            subprocess.run(base_command)  # Run the ping command using subprocess
            
        except ValueError:
            print("Invalid input. Please enter a valid number for count.")
        except subprocess.CalledProcessError:
            print(f"An error occurred while pinging {host}.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")                                                                                                               

    def check_http_status(self):
        print("\nHTTP Server Status Check")
        target = input("Enter the target host (e.g., www.example.com): ").strip()
        port = input("Enter the port (default is 80): ").strip()
        path = input("Enter the path to check (default is '/'): ").strip() or "/"
        
        try:
            port = int(port) if port else 80  # Default to port 80 if not specified
            
            print(f"\nChecking HTTP status of {target}:{port}...")
            
            # Handle HTTPS if port is 443
            if port == 443:
                conn = http.client.HTTPSConnection(target, port, timeout=5) # Create HTTPS connection
            else:
                conn = http.client.HTTPConnection(target, port, timeout=5) # Create HTTP connection
                
            conn.request("HEAD", path) #get the HTTP header
            response = conn.getresponse() #conn is responsible for the response
            
            print(f"HTTP Status: {response.status} {response.reason}") #returns the status code and reason
            print("Response Headers:")
            for header, value in response.getheaders():
                print(f"{header}: {value}") #returns the headers
                
            conn.close()
            
        except ValueError:
            print("Invalid port number. Please enter a valid integer.")
        except socket.gaierror:
            print("Error: Could not resolve hostname. Please check the target host.")
        except ConnectionRefusedError:
            print("Error: Connection refused. The server may be down or not accepting connections.")
        except TimeoutError:
            print("Error: Connection timed out. The server may be unreachable.")
        except Exception as e:
            print(f"An error occurred while checking HTTP status: {e}")


def main():
    toolkit = NetworkToolkit()
    
    while True:
        choice = toolkit.main_menu()  # Display the main menu and get the user's choice
        
        if choice == 1:
            toolkit.network_scanner()  # Call the network scanner options
        elif choice == 2:
            toolkit.http_packet_sniffer()  # Call the HTTP packet sniffer function
        elif choice == 3:
            toolkit.ping_host()  # Call the ping host function
        elif choice == 4:
            print("Exiting the Network Toolkit. Goodbye!")
            break  # Exit the program    
    
    
if __name__ == "__main__":
    main()
    