FROM php:8.1-apache

# Update package lists and install packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    default-mysql-client \
    iputils-ping \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite

# Copy application files
COPY . /var/www/html/

# Create uploads directory with insecure permissions
RUN mkdir -p /var/www/html/uploads && chmod 777 /var/www/html/uploads

# Set permissions
RUN chown -R www-data:www-data /var/www/html/
RUN chmod -R 755 /var/www/html/

# Add sensitive files for directory traversal testing
RUN echo 'FLAG{directory_traversal_success}' > /etc/sensitive_config.txt
RUN echo 'admin:$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi' > /etc/shadow_backup

EXPOSE 80
