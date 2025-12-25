# Security Automation with n8n

## Overview
Automated security scanning workflow using n8n that runs nmap and nikto scans every 6 hours against the vulnerable web application.

## Workflow Components

### 1. Schedule Trigger
- **Frequency**: Every 6 hours
- **Purpose**: Automatically triggers security scans

### 2. Nmap Scan Node
- **Type**: HTTP Request (GET)
- **URL**: `http://vulnerable-web/scan.php?action=nmap`
- **Output**: Network and service discovery results

### 3. Nikto Scan Node  
- **Type**: HTTP Request (GET)
- **URL**: `http://vulnerable-web/scan.php?action=nikto`
- **Output**: Web vulnerability assessment results

### 4. Process Results Node
- **Type**: Function (JavaScript)
- **Purpose**: Combines scan results with timestamps and metadata

## Setup Instructions

1. Access n8n at `http://localhost:5678`
2. Login with `admin:password`
3. Import the workflow JSON or create manually
4. Activate the workflow
5. View results in execution history

## Sample Output
```json
{
  "timestamp": "2025-12-25T05:28:41.000Z",
  "scans": {
    "nmap": {
      "scan_type": "nmap",
      "target": "vulnerable-web", 
      "results": "Nmap scan report for vulnerable-web..."
    },
    "nikto": {
      "scan_type": "nikto",
      "target": "vulnerable-web",
      "results": "- Nikto v2.1.5 scan results..."
    }
  },
  "summary": {
    "nmap_completed": true,
    "nikto_completed": true,
    "total_scans": 2
  }
}
```