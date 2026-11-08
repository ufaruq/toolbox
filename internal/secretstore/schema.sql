CREATE TABLE {{schema}}.current_secrets (
  path text PRIMARY KEY CHECK (length(path) BETWEEN 1 AND 512 AND path ~ '^[A-Za-z0-9_-]+(/[A-Za-z0-9_-]+)*$'),
  version bigint NOT NULL CHECK (version > 0),
  hidden boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE {{schema}}.secret_versions (
  path text NOT NULL REFERENCES {{schema}}.current_secrets(path),
  version bigint NOT NULL CHECK (version > 0),
  ciphertext bytea NOT NULL CHECK (octet_length(ciphertext) BETWEEN 1 AND 2097152),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (path,version)
);
CREATE INDEX secret_versions_age ON {{schema}}.secret_versions(created_at);
