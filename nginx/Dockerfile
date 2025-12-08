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

# Disable the problematic script that tries to copy config files
# We will rely on default config or mount our own if needed
RUN mv /docker-entrypoint.d/90-copy-modsecurity-config.sh /docker-entrypoint.d/90-copy-modsecurity-config.sh.disabled

# Disable other scripts that try to modify non-existent files
RUN mv /docker-entrypoint.d/92-update-real_ip.sh /docker-entrypoint.d/92-update-real_ip.sh.disabled
RUN mv /docker-entrypoint.d/93-update-proxy-ssl-config.sh /docker-entrypoint.d/93-update-proxy-ssl-config.sh.disabled
RUN mv /docker-entrypoint.d/94-activate-plugins.sh /docker-entrypoint.d/94-activate-plugins.sh.disabled

# MANUALLY SETUP MODSECURITY (Since we disabled the auto-scripts)
# 1. Copy the recommended configuration (from template) and replace variables
RUN cp /etc/nginx/templates/modsecurity.d/modsecurity.conf.template /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_RULE_ENGINE}/On/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_REQ_BODY_ACCESS}/On/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_REQ_BODY_LIMIT}/13107200/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_REQ_BODY_NOFILES_LIMIT}/131072/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_RESP_BODY_ACCESS}/On/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_RESP_BODY_LIMIT}/1048576/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_PCRE_MATCH_LIMIT}/100000/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_PCRE_MATCH_LIMIT_RECURSION}/100000/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_TAG}/modsecurity/g' /etc/modsecurity.d/modsecurity.conf && \
    sed -i 's/${MODSEC_REQ_BODY_LIMIT_ACTION}/Reject/g' /etc/modsecurity.d/modsecurity.conf

# 2. Copy CRS Setup and Rules
# Try both locations for crs-setup.conf to be safe
RUN if [ -f /opt/owasp-crs/crs-setup.conf ]; then \
        cp /opt/owasp-crs/crs-setup.conf /etc/modsecurity.d/crs-setup.conf; \
    else \
        cp /opt/owasp-crs/crs-setup.conf.example /etc/modsecurity.d/crs-setup.conf; \
    fi && \
    cp -r /opt/owasp-crs/rules /etc/modsecurity.d/rules

# 3. Create a main include file
RUN echo "include /etc/modsecurity.d/modsecurity.conf" > /etc/modsecurity.d/main.conf && \
    echo "include /etc/modsecurity.d/crs-setup.conf" >> /etc/modsecurity.d/main.conf && \
    echo "include /etc/modsecurity.d/rules/*.conf" >> /etc/modsecurity.d/main.conf

# Fix permissions for our manual setup
RUN chown -R 101:101 /etc/modsecurity.d && \
    chmod -R 755 /etc/modsecurity.d

# Switch back to the default user (usually nginx or 101)
USER 101
