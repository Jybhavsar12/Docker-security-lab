FROM php:8.1-apache

# Update package lists and install packages
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    default-mysql-client && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Enable Apache modules
RUN a2enmod rewrite

# Copy application files
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html/
RUN chmod -R 755 /var/www/html/

EXPOSE 80
