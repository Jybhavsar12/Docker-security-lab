FROM ubuntu:20.04

# Install SSH server
RUN apt-get update && apt-get install -y \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create vulnerable SSH configuration
RUN mkdir /var/run/sshd

# Weak SSH configuration
RUN echo 'PermitRootLogin yes' >> /etc/ssh/sshd_config
RUN echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config
RUN echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config
RUN echo 'Protocol 2' >> /etc/ssh/sshd_config

# Create users with weak passwords
RUN useradd -m -s /bin/bash admin && echo 'admin:admin' | chpasswd
RUN useradd -m -s /bin/bash test && echo 'test:test' | chpasswd
RUN useradd -m -s /bin/bash guest && echo 'guest:guest' | chpasswd
RUN echo 'root:toor' | chpasswd

# Add sensitive files
RUN echo 'FLAG{ssh_weak_credentials}' > /home/admin/secret.txt
RUN echo 'Database: mysql://root:password123@vulnerable-db/webapp' > /home/admin/config.txt

EXPOSE 22
CMD ["/usr/sbin/sshd", "-D"]
