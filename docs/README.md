# Python Toolkit Project

![Python](https://img.shields.io/badge/python-3.13.3-blue)
![](https://img.shields.io/badge/Security-Toolkit-red)

A Python toolkit involving network programming, security tools, and automation capabilities.


---

## Table of Contents
- [Python Toolkit Project](#python-toolkit-project)
  - [Table of Contents](#table-of-contents)
  - [Project Overview](#project-overview)
  - [Features](#features)
  - [Setup](#setup)
  - [Usage](#usage)
  - [Main Menu](#main-menu)
  - [Bandit Analysis](#bandit-analysis)
    - [Available Arguments](#available-arguments)
  - [Cryptography Tool](#cryptography-tool)
  - [Network Toolkit](#network-toolkit)
  - [Nmap Scanner](#nmap-scanner)
    - [How to Launch](#how-to-launch)
    - [Network Scanning \& Host Discovery](#network-scanning--host-discovery)
    - [Vulnerability Detection (Nmap Scripting Engine)](#vulnerability-detection-nmap-scripting-engine)
  - [Password Generator](#password-generator)
  - [SSH Defender](#ssh-defender)
    - [Prerequisites](#prerequisites)
    - [Running the tool](#running-the-tool)
  - [Web Security Scanner](#web-security-scanner)
    - [How SQLi Detection Works:](#how-sqli-detection-works)
    - [How XSS Detection Works:](#how-xss-detection-works)
    - [Limitations](#limitations)
  - [Requirements](#requirements)
  - [Testing](#testing)
  - [Test Coverage](#test-coverage)
    - [Running Tests](#running-tests)
  - [Disclaimer](#disclaimer)


---

## Project Overview
This project is part of the **Scripting And Code Analysis** course. This comprehensive toolkit combines multiple security tools into a single, user-friendly interface. Designed for both security professionals and developers. It provides essential tools for code analysis, network scanning, cryptography and web security testing.



## Features
The toolkit includes seven main components:

- **Bandit Analysis**: Python code security analysis.
- **Cryptography Tool**: Encryption/Decryption and hashing utilities.
- **Network Toolkit**: Network Scanning and analysis tools.
- **Nmap Scanner**: Advanced network scanning with Nmap.
- **Password Generator**: Secure password creation and management.
- **SSH Defender**: SSH Intrusion detection and prevention.
- **Web Security Scanner**: Web Vulnerability Detection.


## Setup

Clone the repository:

```bash
git clone https://github.com/zenzeniou/zenios-toolkit.git

cd zenios-saca-toolkit-project/
```
<br>

Install Python Dependencies:

```bash
#Navigate to the directory to install the virtual enviroment, for example:
cd code/src/

#For Windows 
python -m venv .venv
.\.venv\Scripts\Activate

#For Linux
python3 -m venv .venv
source .venv/bin/activate

```

```bash
cd /code/tests/
pip install -r requirements.txt
```

---

For **Nmap Scanner** (Linux Only):
```bash
sudo apt install nmap
```

<br>

For **SSH Defender** (Linux Only):
```bash
sudo apt intall rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog
```


## Usage
Run the toolkit:
```bash
cd code/src/

#For Windows
python main.py

#For Linux
sudo python main.py
```


## Main Menu
The Main Menu allows users to launch any of the available tools by selecting an option from 1 to 7. Simply enter the corresponding number to start the desired tool. To exit the program, enter 0.

There are two exceptions:

- The **Bandit Analysis tool** is not launched through the Main Menu. Instead, it requires command-line arguments to run. For more information on how to use it, refer to the [Bandit Analysis](#bandit-analysis) section.
- The **SSH defender tool** can be run from the Main Menu; however, if you wish to enable email alerts by providing your email address, you must start the program manually using sudo with enviroment preservation:
```bash
sudo -E python ssh_defender.py
``` 


## Bandit Analysis

**Purpose**: Static code analysis for Python files to identify security vulnerabilities.

This tool integrates bandit, a security analysis tool for Python code, with a command-line interface built using Python's argparse module. Instead of launcing the tool from the main menu, users should navigate to the CLI script and run Bandit with specific arguments.

```bash
cd /code/src
python bandit_analysis.py [argument] [path_to_file_or_directory]
```

### Available Arguments

| Argument               | Description                                                |
|------------------------|------------------------------------------------------------|
| `-h`, `--help`         | Show this help message and exit                            |
| `-s`, `--scan-file`    | Scan a single Python file                                  |
| `-d`, `--scan-dir`     | Scan a directory containing Python files                   |
| `-i`, `--injection`    | Check for injection flaws in a file or directory           |
| `-c`, `--crypto`       | Check for weak cryptography usage in a file or directory   |
| `-a`, `--all`          | Run all security checks on a file or directory             |


Once the scan is complete, the tool presents the results in a structured format displaying:
- **Severity Level** (eg. LOW,MEDIUM,HIGH)
- **Confidence Level**(eg. LOW,MEDIUM,HIGH)
- **Location of the issue** (file path and line number)
- **Code snippet that triggered the alert**
- **Description of the issue**
- **Bandit Test ID** (eg. B324,B105,B608)

Users can then refer to the original Bandit Documentation's Test Plugin Listing at https://bandit.readthedocs.io/en/latest/plugins/index.html#complete-test-plugin-listing for detailed explanations of each test.

---

## Cryptography Tool

**Purpose**: Secure encryption/decryption and hashing operations.

To start the Cryptography Tool, open the main menu and select option 2.
This Tool supports both symmetric and assymetric encryption methods:

- **AES-256**: Encrypt messages using a password of your choice. Share the encrypted message and password with a friend who also has the tool, and they can decrypt it using the same password.
- **RSA**: For more advanced encryption, enter your message and the tool will encrypt it using a newly generated key pair. You will be prompted to save the private key, which can be named and stored in the /code/src/ directory. During decryption, if the key file is still in the directory, the tool will automatically use it. If the file has been removed or deleted, you will need to manually provide a new file path to decrypt the message.

Additionally the tool offers secure hashing options.
- **SHA-256 & SHA-3-256**: Choose a hash algorithm and input your message - The process is simple and user frindly. 


---


## Network Toolkit
**Purpose**: Network Scanning and Analysis tool.

You can launch this tool from the main menu by selecting option 3. It provides a set of powerfull network utilities. For Linux users, it is recommended and for some functionalities even necessary to run the tool with sudo privileges.

**Available Features:**

1. Network Scanner

The Network Scanner includes three scanning options:

- **ARP Scan**
Detects active devices on the local network using ARP request.
  
- **Port Scan**
Performs a simple TCP Port scan on a specified IP address or hostname.

- **HTTP Server Status**
Checks if an HTTP server is responsive. You can specify:
  - **Host**
  - **Port** (Default:80)
  - **Path** (Default:/)      

---

2. HTTP Packet Sniffer

Starts capturing HTTP traffic immediately. Displays potentially sensitive information transmitted over unsecured HTTP connections—ideal for debugging or analyzing traffic in test environments.

---

3. Ping a Host

Sends ICMP echo requests to a target host. You can configure:
- **Target hostname or IP address**
- **Number of pings** (default: `4`)
- **Protocol**: IPv4 (default) or IPv6 



---

## Nmap Scanner

**Usage**: This tool integrates Nmap to provide two powerful capabilities:

1. **Network Scanning & Host Discovery**
2. **Vulnerability Detection using Nmap Scripts**

---

### How to Launch

From the main menu, select **Option 4** to launch the Nmap module.

> **Linux users:** Ensure the `nmap` package is installed on your system.  
> Install via terminal:  
> ```bash
> sudo apt install nmap
> ```
> **Windows users:** Follow the official guide to install Nmap:  
> [https://nmap.org/book/inst-windows.html](https://nmap.org/book/inst-windows.html)

---

### Network Scanning & Host Discovery

You’ll be prompted to enter a **target** (IP address, CIDR range, or domain). Then, choose one of the following scan types:

- 🔹 SYN Scan
- 🔹 TCP Connect Scan
- 🔹 UDP Scan
- 🔹 TCP ACK Scan
- 🔹 NULL Scan
- 🔹 FIN Scan
- 🔹 XMAS Scan

> Want to understand the differences between scan types?  
> Check out the official Nmap scanning guide:  
> [https://nmap.org/book/man-port-scanning-techniques.html](https://nmap.org/book/man-port-scanning-techniques.html)

---

### Vulnerability Detection (Nmap Scripting Engine)

You’ll be prompted to enter a **target**, and then select from a list of built-in vulnerability scripts, such as:

- `vuln`
- `http-sql-injection`
- `ssl-heartbleed`
- `smb-vuln-ms17-010`
- `dns-zone-transfer`

> Browse the full list of available scripts and their documentation:  
> [https://nmap.org/nsedoc/scripts/](https://nmap.org/nsedoc/scripts/)

---


## Password Generator

**Usage**: Create and manage secure passwords.

You can launch this tool via the main menu by selecting option 5.

**Features**:

1. Strong Password Generator

When choosing option 1, the tool will prompt you to enter your desired pasword length (between 12-32 characters, which is considered a safe range).

**What makes this password generation unique**:
- You can optionally include a custom word or phrase in your password.
- Your phrase will be inserted at a rnadom position (start,middle,end) to ensure both security and memorability.
- If you skip this step, the password will be entirely random and still secure.
  
**After generating your password**:
- You will be asked to whether you would like to generate a QR code for safekeeping.
- If yes, a QR image will be save locally at `/code/src/password_qr.png` (or your custom filename).
- You can scan this QR code image to retrieve your password.

**Under the hood**:
- The program uses the Selenium module to automatically test your password's strength via  https://bitwarden.com/password-strength/
- Results are fetched silently in the background (GPU disabled) and include:
- Time to crack your password.
- Password rating (eg. VERY WEAK, WEAK, GOOD, STRONG). 

**Use of secrets instead of random:**
- For password generation, the secrets module is used instead of random, as it provides cryptographically secure random values. After research, I chose secrets because it's designed for generating tokens and passwords that are harder to predict, enhancing the overall security of the generated credentials.

2. Base64 Encode/Decode
Selecting option 2 lets you easily encode strings to base64 and decode base64 strings back to plain text.

**IMPORTANT: NO USER INPUT IS STORED OR TRACKED!!!**


---


## SSH Defender

**IMPORTANT: THIS TOOL IS DESIGNED TO RUN ON LINUX SYSTEMS ONLY!**

**Usage**: SSH intrusion detection and prevention.


### Prerequisites

Ensure that rsyslog is installed and running on your system, as it is required for SSH log monitoring.

- To check if it is installed, run:
```bash
dpkg -l | grep rsyslog
```

- If installed, you will see output similar to:
```bash
ii rsyslog ...
```

- If it is not installed, set it up with:
```bash
sudo apt install rsyslog
sudo systemctl enable rsyslog
sudo systemctl start rsyslog 
```

### Running the tool

Launch the program from the main menu and choose option 6. <br>
**Important: You must run the program with sudo privileges!**

**If the user chooses to provide their email address so they can receive alerts for potential ssh intruders. They should run the program with:**
```bash
sudo -E ssh_defender.py
```

At startup you will be prompted optionally to provide your email address for real-time intrussion alrets.
If you skip this step, the tool will still monitor SSH activity and respond to intrusions.

**When a potential SSH intruder is detected:**
- The tool blocks the intruder's IP via iptables.
- Displays a list of all currently banned IP addresses.
- Creates a log backup at: `/var/log/ssh_defender_backups/auth_log_backup_[timestamp].log`

**IP Unblocking Logic:**
- Ban Duration: IPs are blocked for 1 hour (Bantime = 3600 seconds)
- Auto Unblock: Every 60 seconds, the tool checks if any bans have expired.
- Restoration: Expired IPs are unblocked from both iptables and the internal list.
  

**Optional Email Notification Setup**:

If you would like to receive email alerts when an SSH intrusion is detected, you must configure the following enviroment variables before you run the tool:

```bash
export EMAIL_FROM = "yourname@gmail.com"
export EMAI_USER = "yourname@gmail.com"
export EMAIL_PASSWORD = "your 16 digit app password"
export SMTP_SERVER = "smtp.gmail.com"
export SMTP_PORT = 465
```

**IMPORTANT: DO NOT USE YOUR ACTUAL EMAIL PASSWORD. INSTEAD GENERATE AN APP PASSWORD**

- To generate an app password, visit:
- What is an app password? : https://support.google.com/mail/answer/185833?hl=en
- Generate your app password: https://myaccount.google.com/apppasswords

Set an app name (eg.MAIL), click "Create", and use the generated password (formatted like XXXX XXXX XXXX XXXX) as EMAIL_PASSWORD.

**IF THE USER NEEDS TO UNBAN AN IP ADDRESS MANUALLY:**
```bash
sudo iptables -L INPUT -n -v --line-numbers #See all blocked IP addresses
sudo iptables -D INPUT 1 #Where 1 is the line number of the IP you want to unblock
```

---

## Web Security Scanner

**Usage**: Web Application vulnerability scanning.

To start the vulnerability scanner, select option 7 from the main menu. <br>The user will be promted with three scanning functionalities:

1. SQL Injection (SQLi) and Cross-Site Scripting (XSS) Scanner:

**Good Target for testing:**
- http://testphp.vulnweb.com/artists.php?artist=1

### How SQLi Detection Works:
- Extracts base URL (eg. http://example.com/product.php?id=1)
- Injects common SQLi payloads like 1' OR '1'='1
- Sends GET requests with the payload.
- Checks for error indicators in the response (eg. "SQL syntax", "warning", "mysql").
- Flags potential vulnerabilities bases on response patterns.

### How XSS Detection Works:
- Inserts common XSS payloads into the URL parameter.
- Sends GET requests to the modified URLs.
- Searches the response for reflected payloads.
- If found, reports a possible XSS vulnerability.

### Limitations
- The tool assumes parameter names: "id=" for SQLi, "input=" for XSS.
- Only test GET requests (ignores POST-based attacks).
- 5 second request timeout to prevent long waits.
- It may produce false positives/negatives.


2. Data Scraper (Emails, API Keys, IPs, Credentials):

The option scrapes a given webpage for sensitive information such as:

- Email Addresses.
- API Keys.
- IP Addresses.
- Usernames and Passwords.

In the screencast demonstartion, an AI generated vulnerable HTML page was used to showcase detection capability. <br>The tool highlights any identifies data directly to the user.


3. Sensitive Directory Brute Force:

This tool performs directory enumeration to uncover hidden or sensitive paths like:
<br> User provides the target URL (eg. http://testphp.vulnweb.com/) and the scanner attempts to discover accessible sensitive directories.



## Requirements
Install via requirements.txt

```bash
bandit
cryptography
scapy
nmap
selenium
qrcode
requests
bs4
```

All other modules used for this project are python built in tools!


---

## Testing

The project includes comprehensive unit tests for each major component to ensure functionality and reliability. Tests are located in the `code/tests/` directory and can be run individually or collectively.

## Test Coverage

- **Bandit Analysis**
  - Tests file and directory scanning functionality
  - Verifies proper handling of invalid paths
  - Checks display formatting of scan results
  - Validates special case checks (injection flaws, weak cryptography)

- **Cryptography Tool**
  - Tests SHA-256 and SHA3-256 hashing algorithms
  - Validates AES-256 encryption/decryption cycle
  - Verifies RSA encryption/decryption functionality
  - Checks error handling for invalid Base64 input

- **Network Toolkit**
  - Tests main menu input validation
  - Verifies port scanning functionality
  - Checks HTTP status monitoring
  - Validates socket operations

- **Nmap Scanner**
  - Tests target validation (IP, CIDR, domain formats)
  - Verifies proper rejection of invalid targets
  - Mocks scanner operations for reliability

- **Password Generator**
  - Tests password generation with and without custom words
  - Verifies length requirements enforcement
  - Validates Base64 encoding/decoding
  - Checks handling of overly long custom words

- **SSH Defender**
  - Tests log analysis and attempt counting
  - Verifies IP banning functionality
  - Mocks system commands for safe testing
  - Simulates time-based events

- **Web Security Scanner**
  - Tests URL validation
  - Verifies data scraping functionality
  - Checks directory brute force detection
  - Mocks web requests for reliable testing

### Running Tests

All tests must be executed from the `/code/` directory.

**Run All Tests:**

```bash
pip install unittest
cd code/
python -m unittest discover -s tests -p "test_*.py"
```

**Run Specific test module:**
```bash
cd code/
python -m unittest tests/test_[module_name].py
```


## Disclaimer
This toolkit is for educational and authorized security testing purposes only. Always obtain proper authorization before scanning or testing systems that you don't own. The developer is not responsible for any misuse of these tools.
