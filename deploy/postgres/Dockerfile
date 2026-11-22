# Disposable PostgreSQL 18 fixture; Compose mounts the versioned data parent.
FROM postgres:18.6-alpine3.24@sha256:9ba53c7d41ea093baf5c1ba635ba5434c4f979880527d49bb7d9237d3193085b
# The official entrypoint uses gosu only to become postgres. Use Alpine's small
# C helper instead of shipping gosu's obsolete Go standard library.
RUN apk add --no-cache su-exec=0.3-r0 \
    && grep -F 'exec gosu postgres "$BASH_SOURCE" "$@"' /usr/local/bin/docker-entrypoint.sh \
    && sed -i 's/exec gosu postgres/exec su-exec postgres/' /usr/local/bin/docker-entrypoint.sh \
    && rm /usr/local/bin/gosu

# Compose provisions the disposable data tmpfs with this image's postgres UID/GID.
USER postgres
