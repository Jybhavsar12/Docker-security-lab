# Docker Architecture Guide

## Container Overview

### Vulnerable Web Application
- **Base Image**: `php:8.1-apache`
- **Purpose**: Hosts the vulnerable PHP application
- **Port**: 80 (mapped to host 8080)
- **Network**: `security-lab`

### Security Tools Container
- **Base Image**: `kalilinux/kali-rolling`
- **Purpose**: Provides penetration testing tools
- **Tools**: nmap, sqlmap, nikto, dirb, curl, wget
- **Network**: `security-lab`

## Docker Compose Configuration

```yaml
services:
  vulnerable-app:
    build: ./vulnerable-app
    ports:
      - "8080:80"
    networks:
      - security-lab
    container_name: vulnerable-web

  security-tools:
    build: ./security-tools
    networks:
      - security-lab
    container_name: security-tools
    stdin_open: true
    tty: true

networks:
  security-lab:
    driver: bridge
```

## Useful Docker Commands

### Container Management
```bash
# Start the lab
docker compose up -d

# Stop the lab
docker compose down

# Rebuild containers
docker compose up --build -d

# View logs
docker compose logs vulnerable-app
docker compose logs security-tools
```

### Container Interaction
```bash
# Connect to security tools
docker exec -it security-tools bash

# Connect to vulnerable app
docker exec -it vulnerable-web bash

# Copy files from container
docker cp security-tools:/tools/results.txt ./results.txt
```

### Troubleshooting
```bash
# Check container status
docker ps

# View container details
docker inspect vulnerable-web

# Check network connectivity
docker network ls
docker network inspect docker-security-lab_security-lab
```

## Security Considerations

### Container Isolation
- Containers run in isolated network
- No direct access to host system
- Safe for running vulnerable applications

### Data Persistence
- Containers are ephemeral
- Data is lost when containers are removed
- Use volumes for persistent data if needed

### Network Security
- Custom bridge network isolates containers
- Only necessary ports are exposed
- No external network access by default