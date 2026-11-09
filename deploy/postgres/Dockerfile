# Disposable integration-store image; keep PostgreSQL's major version unchanged.
FROM postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15
# The official entrypoint uses gosu only to become postgres. Use Alpine's small
# C helper instead of shipping gosu's obsolete Go standard library.
RUN apk add --no-cache su-exec=0.3-r0 \
    && grep -F 'exec gosu postgres "$BASH_SOURCE" "$@"' /usr/local/bin/docker-entrypoint.sh \
    && sed -i 's/exec gosu postgres/exec su-exec postgres/' /usr/local/bin/docker-entrypoint.sh \
    && rm /usr/local/bin/gosu

# Compose provisions the disposable data tmpfs with this image's postgres UID/GID.
USER postgres
