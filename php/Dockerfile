FROM php:8.2-fpm-alpine

# Install dependencies
RUN apk add --no-cache \
    curl \
    libzip-dev \
    zip \
    unzip

# Install PHP extensions
RUN docker-php-ext-install pdo pdo_mysql

# Create non-root user (matches user: 1000:1000 in docker-compose)
# Alpine already has 'www-data' (82), but we want 1000.
# We use shadow to get usermod/groupmod for cleaner handling
RUN apk add --no-cache shadow && \
    usermod -u 1000 www-data && \
    groupmod -g 1000 www-data

# Set working directory
WORKDIR /var/www/html

# Switch to non-root user
USER www-data
