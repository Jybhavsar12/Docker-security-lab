FROM ubuntu:22.04

# Avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install security tools
RUN apt-get update && apt-get install -y \
    nmap \
    curl \
    wget \
    python3 \
    python3-pip \
    git \
    nikto \
    dirb \
    hydra \
    netcat \
    dnsutils \
    net-tools \
    iputils-ping \
    && rm -rf /var/lib/apt/lists/*

# Install sqlmap via pip (more reliable on ARM64)
RUN pip3 install sqlmap

# Set working directory
WORKDIR /tools

# Keep container running
CMD ["tail", "-f", "/dev/null"]
