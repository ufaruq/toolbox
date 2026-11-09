# Disposable PostgreSQL 18 fixture; Compose mounts the versioned data parent.
FROM postgres:18.6-alpine3.24@sha256:123b17998ccaf47e53b502e8c6a1e79afd8f579c6f3eec83c563da026f957395
# The official entrypoint uses gosu only to become postgres. Use Alpine's small
# C helper instead of shipping gosu's obsolete Go standard library.
RUN apk add --no-cache su-exec=0.3-r0 \
    && grep -F 'exec gosu postgres "$BASH_SOURCE" "$@"' /usr/local/bin/docker-entrypoint.sh \
    && sed -i 's/exec gosu postgres/exec su-exec postgres/' /usr/local/bin/docker-entrypoint.sh \
    && rm /usr/local/bin/gosu

# Compose provisions the disposable data tmpfs with this image's postgres UID/GID.
USER postgres
