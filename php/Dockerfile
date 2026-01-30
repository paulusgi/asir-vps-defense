FROM php:8.2-fpm-alpine

# Install dependencies
RUN apk add --no-cache \
    curl \
    curl-dev \
    libzip-dev \
    zip \
    unzip \
    libmaxminddb \
    libmaxminddb-dev \
    autoconf \
    make \
    g++

# Install PHP extensions
RUN docker-php-ext-install curl pdo pdo_mysql \
    && pecl install maxminddb \
    && docker-php-ext-enable maxminddb

# Create non-root user (matches user: 1000:1000 in docker-compose)
# Alpine already has 'www-data' (82), but we want 1000.
# We use shadow to get usermod/groupmod for cleaner handling
RUN apk add --no-cache shadow && \
    usermod -u 1000 www-data && \
    groupmod -g 1000 www-data

# Set working directory
WORKDIR /var/www/html

# Copy tuned PHP-FPM pool configuration
COPY pool.d/www.conf /usr/local/etc/php-fpm.d/zz-custom.conf

# Ensure configs are world-readable for the non-root runtime user
RUN chmod 644 /usr/local/etc/php-fpm.d/zz-custom.conf && \
    find /usr/local/etc/php/conf.d -type f -name '*.ini' -exec chmod 644 {} \;

# Switch to non-root user
USER www-data
