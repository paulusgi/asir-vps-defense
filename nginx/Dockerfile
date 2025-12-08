FROM owasp/modsecurity-crs:nginx

# Disable default configuration generation to prevent conflicts
ENV NGINX_ENVSUBST_TEMPLATE_SUFFIX=.disabled

# Remove default configuration file if it exists
RUN rm -f /etc/nginx/conf.d/default.conf

# Copy our custom configuration
COPY conf.d/public.conf /etc/nginx/conf.d/public.conf

# Switch to root to fix permissions (The image runs as nginx user by default)
USER root
RUN chown root:root /etc/nginx/conf.d/public.conf && \
    chmod 644 /etc/nginx/conf.d/public.conf

# Create the directory where ModSecurity tries to copy files and give it permissions
# We use UID 101 (nginx) to be precise and avoid name resolution issues
RUN mkdir -p /etc/modsecurity.d && \
    chown -R 101:101 /etc/modsecurity.d && \
    chmod -R 755 /etc/modsecurity.d

# Disable the problematic script that tries to copy config files
# We will rely on default config or mount our own if needed
RUN mv /docker-entrypoint.d/90-copy-modsecurity-config.sh /docker-entrypoint.d/90-copy-modsecurity-config.sh.disabled

# Disable other scripts that try to modify non-existent files
RUN mv /docker-entrypoint.d/92-update-real_ip.sh /docker-entrypoint.d/92-update-real_ip.sh.disabled

# Switch back to the default user (usually nginx or 101)
USER 101
