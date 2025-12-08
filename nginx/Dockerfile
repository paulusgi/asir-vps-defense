FROM owasp/modsecurity-crs:nginx

# Switch to root early so we can modify packaged files
USER root

# Remove default server template to avoid PROXY_SSL_CONFIG placeholder issues
RUN rm -f /etc/nginx/conf.d/default.conf /etc/nginx/templates/conf.d/default.conf.template

# Mantener la plantilla modsecurity.conf original para que envsubst genere la config estándar

# Copy our custom configuration
COPY conf.d/public.conf /etc/nginx/conf.d/public.conf

# Switch to root to fix permissions (The image runs as nginx user by default)

RUN chown root:root /etc/nginx/conf.d/public.conf && \
    chmod 644 /etc/nginx/conf.d/public.conf

# Create the directory where ModSecurity tries to copy files and give it permissions
# We use UID 101 (nginx) to be precise and avoid name resolution issues
RUN mkdir -p /etc/modsecurity.d && \
    chown -R 101:101 /etc/modsecurity.d && \
    chmod -R 755 /etc/modsecurity.d

# Keep entrypoint scripts intact so that the official envsubst-based
# modsecurity configuration is generated with all required variables.
# We only disable the ones that are known to touch paths we don't use.
RUN mv /docker-entrypoint.d/92-update-real_ip.sh /docker-entrypoint.d/92-update-real_ip.sh.disabled
RUN mv /docker-entrypoint.d/93-update-proxy-ssl-config.sh /docker-entrypoint.d/93-update-proxy-ssl-config.sh.disabled
RUN mv /docker-entrypoint.d/94-activate-plugins.sh /docker-entrypoint.d/94-activate-plugins.sh.disabled

# Let the original 90-copy-modsecurity-config.sh run (default behavior) so it
# renders /etc/modsecurity.d/modsecurity.conf from the template with env vars.
# Ensure CRS setup/rules are present as shipped by the base image.
RUN cp /opt/owasp-crs/crs-setup.conf /etc/modsecurity.d/crs-setup.conf || \
    cp /opt/owasp-crs/crs-setup.conf.example /etc/modsecurity.d/crs-setup.conf
RUN cp -r /opt/owasp-crs/rules /etc/modsecurity.d/rules

# Fix permissions for our manual setup
RUN chown -R 101:101 /etc/modsecurity.d && \
    chmod -R 755 /etc/modsecurity.d

# Switch back to the default user (usually nginx or 101)
USER 101
