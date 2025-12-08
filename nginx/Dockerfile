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
# This fixes: "90-copy-modsecurity-config.sh: error: cannot copy config files to /etc/modsecurity.d"
RUN mkdir -p /etc/modsecurity.d && \
    chown -R nginx:nginx /etc/modsecurity.d

# Switch back to the default user (usually nginx or 101)
USER nginx
