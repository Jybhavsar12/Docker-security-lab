FROM kalilinux/kali-rolling

# Update and install security tools
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    sqlmap \
    nikto \
    dirb \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /tools

# Keep container running
CMD ["tail", "-f", "/dev/null"]