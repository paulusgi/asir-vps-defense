FROM owasp/modsecurity-crs:nginx

# Disable default configuration generation to prevent conflicts
ENV NGINX_ENVSUBST_TEMPLATE_SUFFIX=.disabled

# Remove default configuration file if it exists
RUN rm -f /etc/nginx/conf.d/default.conf

# Copy our custom configuration
COPY conf.d/public.conf /etc/nginx/conf.d/public.conf

# Ensure permissions are correct (root owner, readable by all)
RUN chown root:root /etc/nginx/conf.d/public.conf && \
    chmod 644 /etc/nginx/conf.d/public.conf
