#!/bin/sh
set -eu
# The official image drops to postgres after initializing PGDATA. Copy only the
# server TLS key here; never copy application signing or encryption keys.
mkdir -p /var/lib/postgresql/tls
cp /run/toolbox/postgres.key /var/lib/postgresql/tls/server.key
cp /run/toolbox/postgres.crt /var/lib/postgresql/tls/server.crt
chown postgres:postgres /var/lib/postgresql/tls/server.key /var/lib/postgresql/tls/server.crt
chmod 600 /var/lib/postgresql/tls/server.key
exec /usr/local/bin/docker-entrypoint.sh "$@"
