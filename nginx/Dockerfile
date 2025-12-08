FROM owasp/modsecurity-crs:nginx

# Disable default configuration generation to prevent conflicts
ENV NGINX_ENVSUBST_TEMPLATE_SUFFIX=.disabled

# Remove default configuration file if it exists
RUN rm -f /etc/nginx/conf.d/default.conf

# Copy our custom configuration
COPY conf.d/public.conf /etc/nginx/conf.d/public.conf

# Switch to root to fix permissions (The image runs as nginx user by default)
USER root

# Load ModSecurity Module explicitly (Required because the base nginx.conf doesn't load it)
RUN sed -i '1i load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf

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

# 3. Create a main include file
RUN echo "include /etc/modsecurity.d/modsecurity.conf" > /etc/modsecurity.d/main.conf && \
    echo "include /etc/modsecurity.d/crs-setup.conf" >> /etc/modsecurity.d/main.conf && \
    echo "include /etc/modsecurity.d/rules/*.conf" >> /etc/modsecurity.d/main.conf

# Fix permissions for our manual setup
RUN chown -R 101:101 /etc/modsecurity.d && \
    chmod -R 755 /etc/modsecurity.d

# Switch back to the default user (usually nginx or 101)
USER 101
