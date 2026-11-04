FROM php:8.3-fpm-alpine

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

# Non-root user matching `user: 10001:10001` in docker-compose. A dedicated UID, not 1000,
# which on cloud images belongs to the distribution's default login user.
# We use shadow to get usermod/groupmod for cleaner handling
RUN apk add --no-cache shadow && \
    usermod -u 10001 www-data && \
    groupmod -g 10001 www-data

# Set working directory
WORKDIR /var/www/html

# Copy tuned PHP-FPM pool configuration
COPY pool.d/www.conf /usr/local/etc/php-fpm.d/zz-custom.conf

# Ensure configs are world-readable for the non-root runtime user
RUN chmod 644 /usr/local/etc/php-fpm.d/zz-custom.conf && \
    find /usr/local/etc/php/conf.d -type f -name '*.ini' -exec chmod 644 {} \;

# Switch to non-root user
USER www-data
