# Disposable integration-store image; keep PostgreSQL's major version unchanged.
FROM postgres:17.11-alpine3.24@sha256:3540c0362c809df084ffac0ae69fe794515f9de92692f02178bcdce0ef0302ac
# The official entrypoint uses gosu only to become postgres. Use Alpine's small
# C helper instead of shipping gosu's obsolete Go standard library.
RUN apk add --no-cache su-exec=0.3-r0 \
    && grep -F 'exec gosu postgres "$BASH_SOURCE" "$@"' /usr/local/bin/docker-entrypoint.sh \
    && sed -i 's/exec gosu postgres/exec su-exec postgres/' /usr/local/bin/docker-entrypoint.sh \
    && rm /usr/local/bin/gosu

# Compose provisions the disposable data tmpfs with this image's postgres UID/GID.
USER postgres
