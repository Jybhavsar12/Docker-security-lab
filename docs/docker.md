# Docker Architecture Guide

## Container Overview

### Vulnerable Web Application
- **Base Image**: `php:8.1-apache`
- **Purpose**: Hosts the vulnerable PHP application with multiple security flaws
- **Port**: 80 (mapped to host 8080)
- **Network**: `security-lab`
- **Vulnerabilities**: SQL injection, XSS, command injection, file upload, directory traversal

### Security Tools Container
- **Base Image**: `ubuntu:22.04`
- **Purpose**: Provides penetration testing tools for security assessment
- **Tools**: nmap, sqlmap, nikto, dirb, hydra, curl, wget, python3
- **Network**: `security-lab`
- **Usage**: Interactive container for running security tests

### Vulnerable SSH Server
- **Base Image**: `ubuntu:20.04`
- **Purpose**: SSH server with intentional security weaknesses
- **Port**: 22 (mapped to host 2222)
- **Credentials**: admin/admin, test/test, guest/guest, root/toor
- **Network**: `security-lab`

### Vulnerable Database (Optional)
- **Base Image**: `mysql:8.0`
- **Purpose**: Database server for advanced SQL injection testing
- **Port**: 3306 (mapped to host 3306)
- **Credentials**: root/root, webapp/password123
- **Network**: `security-lab`

### Vulnerable FTP Server (Optional)
- **Base Image**: `fauria/vsftpd`
- **Purpose**: FTP server with weak authentication
- **Port**: 21 (mapped to host 21)
- **Credentials**: admin/password
- **Network**: `security-lab`

## Docker Compose Configuration

### Main Configuration
```yaml
services:
  vulnerable-app:
    build: ./vulnerable-app
    ports:
      - "8080:80"
    networks:
      - security-lab
    container_name: vulnerable-web

  vulnerable-ssh:
    build: ./vulnerable-ssh
    ports:
      - "2222:22"
    networks:
      - security-lab
    container_name: vulnerable-ssh

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

### ARM64 Compatibility
For Apple Silicon Macs, use the minimal configuration or ensure platform compatibility:
```yaml
vulnerable-db:
  image: mysql:8.0
  platform: linux/amd64  # Force x86_64 emulation if needed
```

## Useful Docker Commands

### Container Management
```bash
# Start the lab (build if needed)
docker compose up --build -d

# Start with minimal services (ARM64 compatible)
docker compose -f docker-compose-minimal.yml up --build -d

# Stop the lab
docker compose down

# Stop and remove all data
docker compose down -v

# Rebuild specific container
docker compose build vulnerable-app
docker compose up -d vulnerable-app

# View logs
docker compose logs vulnerable-app
docker compose logs security-tools
docker compose logs -f  # Follow logs in real-time
```

### Container Interaction
```bash
# Connect to security tools (primary testing environment)
docker exec -it security-tools bash

# Connect to vulnerable web app
docker exec -it vulnerable-web bash

# Connect to SSH server
docker exec -it vulnerable-ssh bash

# Run single command in container
docker exec security-tools nmap vulnerable-web
```

### File Operations
```bash
# Copy files from container to host
docker cp security-tools:/tools/results.txt ./results.txt
docker cp vulnerable-web:/var/log/apache2/access.log ./access.log

# Copy files from host to container
docker cp ./wordlist.txt security-tools:/tools/
docker cp ./payload.php vulnerable-web:/var/www/html/uploads/
```

### Troubleshooting
```bash
# Check container status
docker ps -a

# View detailed container information
docker inspect vulnerable-web
docker inspect security-tools

# Check resource usage
docker stats

# View container processes
docker exec vulnerable-web ps aux

# Check network connectivity
docker network ls
docker network inspect docker-security-lab_security-lab

# Test network connectivity between containers
docker exec security-tools ping vulnerable-web
docker exec security-tools nmap vulnerable-web
```

### Advanced Operations
```bash
# Access container filesystem
docker exec -it vulnerable-web ls -la /var/www/html/
docker exec -it security-tools find /tools -name "*.txt"

# Monitor network traffic
docker exec security-tools tcpdump -i eth0

# Check open ports in container
docker exec vulnerable-web netstat -tulpn
docker exec security-tools ss -tulpn

# View environment variables
docker exec vulnerable-web env
docker exec security-tools printenv
```

## Security Considerations

### Container Isolation
- Containers run in isolated custom network (`security-lab`)
- No direct access to host system files
- Network traffic contained within Docker bridge
- Safe for running vulnerable applications and attack tools

### Data Persistence
- Containers are ephemeral by default
- Data is lost when containers are removed
- Use volumes for persistent data if needed:
  ```yaml
  volumes:
    - ./results:/tools/results
    - ./uploads:/var/www/html/uploads
  ```

### Network Security
- Custom bridge network isolates lab from other containers
- Only necessary ports are exposed to host
- No external network access by default
- Internal DNS resolution between containers

### Host Protection
- Containers cannot access host filesystem without explicit volumes
- Limited resource usage prevents system impact
- Easy cleanup with `docker compose down`
- No permanent system modifications

### Best Practices
- Always run in isolated environment
- Never expose to public networks
- Regular cleanup of containers and images
- Monitor resource usage during intensive scans
- Keep Docker and images updated for security

## Performance Optimization

### Resource Limits
```yaml
services:
  security-tools:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          memory: 512M
```

### Build Optimization
```bash
# Use BuildKit for faster builds
DOCKER_BUILDKIT=1 docker compose build

# Build with no cache
docker compose build --no-cache

# Parallel builds
docker compose build --parallel
```

## Backup and Recovery

### Export Container State
```bash
# Create container snapshot
docker commit security-tools security-tools-snapshot

# Export container as tar
docker export security-tools > security-tools-backup.tar
```

### Volume Backup
```bash
# Backup persistent data
docker run --rm -v security-lab_data:/data -v $(pwd):/backup ubuntu tar czf /backup/lab-data.tar.gz /data
```
