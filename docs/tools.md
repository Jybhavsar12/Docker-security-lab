# Security Tools Guide

## Nmap - Network Scanner

### Basic Usage
```bash
# Basic port scan
nmap vulnerable-web

# Service version detection
nmap -sV vulnerable-web

# Aggressive scan
nmap -A vulnerable-web

# Vulnerability scripts
nmap --script http-vuln* vulnerable-web
```

## SQLMap - SQL Injection Tool

### Basic Usage
```bash
# Automatic form detection
sqlmap -u "http://vulnerable-web" --forms --batch

# Manual parameter testing
sqlmap -u "http://vulnerable-web" --data="username=test&password=test" -p username

# Database enumeration
sqlmap -u "http://vulnerable-web" --forms --batch --dbs

# Data extraction
sqlmap -u "http://vulnerable-web" --forms --batch --dump
```

## Nikto - Web Vulnerability Scanner

### Basic Usage
```bash
# Basic scan
nikto -h http://vulnerable-web

# Verbose output
nikto -h http://vulnerable-web -v

# Save results
nikto -h http://vulnerable-web -o nikto_results.txt

# All plugins
nikto -h http://vulnerable-web -Plugins @@ALL
```

## Dirb - Directory Brute Forcer

### Basic Usage
```bash
# Basic directory scan
dirb http://vulnerable-web

# Custom wordlist
dirb http://vulnerable-web /usr/share/dirb/wordlists/common.txt

# File extensions
dirb http://vulnerable-web -X .php,.txt,.bak

# Recursive scan
dirb http://vulnerable-web -r
```

## Curl - Manual Testing

### Basic Usage
```bash
# GET request
curl http://vulnerable-web

# POST request
curl -X POST http://vulnerable-web -d "username=admin&password=test"

# Verbose output
curl -v http://vulnerable-web

# Save response
curl http://vulnerable-web -o response.html
```