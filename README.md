# Docker Security Lab

A containerized cybersecurity learning environment featuring a vulnerable web application and penetration testing tools. Perfect for learning ethical hacking, vulnerability assessment, and Docker security concepts.

## Learning Objectives

- Practice SQL injection and XSS attacks in a safe environment
- Learn Docker containerization for security testing
- Use industry-standard penetration testing tools
- Understand web application vulnerabilities
- Master container networking and isolation

## Architecture

```
┌─────────────────┐    ┌─────────────────┐
│  Security Tools │    │ Vulnerable App  │
│   (Kali Linux)  │◄──►│   (PHP/Apache)  │
│                 │    │                 │
│ • nmap          │    │ • SQL Injection │
│ • sqlmap        │    │ • XSS           │
│ • nikto         │    │ • Weak Auth     │
│ • dirb          │    │                 │
└─────────────────┘    └─────────────────┘
```

## Quick Start

### Prerequisites
- Docker Desktop installed and running
- Basic knowledge of command line

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/docker-security-lab.git
cd docker-security-lab

# Start the lab
docker compose up --build -d

# Verify containers are running
docker ps
```

### Access Points
- **Vulnerable Web App**: http://localhost:8080
- **Security Tools**: `docker exec -it security-tools bash`

## Usage Guide

### 1. Web Application Testing
Visit http://localhost:8080 and try these attacks:

**SQL Injection:**
- Username: `admin' OR '1'='1`
- Password: `anything`

**XSS Attack:**
- Username: `<script>alert('XSS')</script>`
- Password: `anything`

**Valid Credentials:**
- Username: `admin`
- Password: `password`

### 2. Penetration Testing Tools

Connect to the security tools container:
```bash
docker exec -it security-tools bash
```

**Network Scanning:**
```bash
nmap -A vulnerable-web
```

**Web Vulnerability Scanning:**
```bash
nikto -h http://vulnerable-web
```

**Directory Brute Force:**
```bash
dirb http://vulnerable-web
```

**Automated SQL Injection:**
```bash
sqlmap -u "http://vulnerable-web" --forms --batch
```

## Detailed Documentation

- [Vulnerability Guide](docs/vulnerabilities.md) - Detailed explanation of each vulnerability
- [Tool Usage](docs/tools.md) - Complete guide to all security tools
- [Attack Scenarios](docs/attacks.md) - Step-by-step attack walkthroughs
- [Docker Guide](docs/docker.md) - Understanding the containerization

## Security Considerations

**WARNING**: This lab contains intentionally vulnerable code. 

- Only run in isolated environments
- Never deploy to production
- Use for educational purposes only
- Keep containers isolated from production networks

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add new vulnerabilities or tools
4. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built for cybersecurity education
- Inspired by OWASP WebGoat and DVWA
- Uses Kali Linux security tools

---
**Disclaimer**: This tool is for educational purposes only. Users are responsible for complying with applicable laws and regulations.

## Security Automation

### n8n Workflow Automation
- **Access**: http://localhost:5678 (admin:password)
- **Features**: 
  - Automated security scans every 6 hours
  - Nmap network discovery and service detection
  - Nikto web vulnerability assessment
  - Combined reporting with timestamps
- **Workflow**: Import from `n8n-workflows/automated-security-scans.json`

### Scan API Endpoints
- **Nmap**: `http://localhost:8080/scan.php?action=nmap`
- **Nikto**: `http://localhost:8080/scan.php?action=nikto`
