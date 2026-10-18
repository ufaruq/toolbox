-- The runtime role must not own these objects or have schema CREATE privilege.
CREATE TABLE users (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','Issuer','Subject','Status'] AND (payload - ARRAY['ID','Issuer','Subject','Status']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  issuer text GENERATED ALWAYS AS (payload->>'Issuer') STORED NOT NULL,
  subject text GENERATED ALWAYS AS (payload->>'Subject') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  CHECK (length(id) > 0 AND length(issuer) > 0 AND length(subject) > 0 AND length(status) > 0),
  UNIQUE (issuer, subject)
);

CREATE TABLE agents (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','OwnerID','Name','Status'] AND (payload - ARRAY['ID','OwnerID','Name','Status']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  CHECK (length(id) > 0 AND length(status) > 0),
  FOREIGN KEY (owner_id) REFERENCES users (id),
  UNIQUE (id, owner_id)
);

CREATE TABLE credentials (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','AgentID','Hash','Status','ExpiresAt'] AND (payload - ARRAY['ID','AgentID','Hash','Status','ExpiresAt']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  agent_id text GENERATED ALWAYS AS (payload->>'AgentID') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  CHECK (length(id) > 0 AND length(status) > 0),
  CHECK (length(payload->>'Hash') > 0),
  CHECK ((payload->>'ExpiresAt')::timestamptz > '-infinity'::timestamptz),
  FOREIGN KEY (agent_id) REFERENCES agents (id)
);

CREATE TABLE sessions (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','UserID','CSRFHash','ExpiresAt'] AND (payload - ARRAY['ID','UserID','CSRFHash','ExpiresAt']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'UserID') STORED NOT NULL,
  CHECK (length(id) > 0),
  CHECK (length(payload->>'CSRFHash') > 0),
  CHECK ((payload->>'ExpiresAt')::timestamptz > '-infinity'::timestamptz),
  FOREIGN KEY (owner_id) REFERENCES users (id),
  UNIQUE (id, owner_id)
);

CREATE TABLE connections (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','OwnerID','Provider','Subject','ClientID','Status','Epoch','SecretVersion','Scopes'] AND (payload - ARRAY['ID','OwnerID','Provider','Subject','ClientID','Status','Epoch','SecretVersion','Scopes']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  provider text GENERATED ALWAYS AS (payload->>'Provider') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  epoch bigint GENERATED ALWAYS AS ((payload->>'Epoch')::bigint) STORED NOT NULL,
  secret_version bigint GENERATED ALWAYS AS ((payload->>'SecretVersion')::bigint) STORED NOT NULL,
  CHECK (length(id) > 0 AND length(provider) > 0 AND length(status) > 0),
  CHECK (epoch > 0 AND secret_version >= 0),
  FOREIGN KEY (owner_id) REFERENCES users (id),
  UNIQUE (id, owner_id)
);

CREATE TABLE resources (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ConnectionID','FileID','MIME','Name','VerifiedAt'] AND (payload - ARRAY['ConnectionID','FileID','MIME','Name','VerifiedAt']) = '{}'::jsonb),
  connection_id text GENERATED ALWAYS AS (payload->>'ConnectionID') STORED NOT NULL,
  file_id text GENERATED ALWAYS AS (payload->>'FileID') STORED NOT NULL,
  owner_id text NOT NULL,
  CHECK (length(connection_id) > 0 AND length(file_id) > 0),
  PRIMARY KEY (connection_id, file_id),
  UNIQUE (connection_id, file_id, owner_id),
  FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id)
);

CREATE TABLE grants (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','OwnerID','AgentID','ConnectionID','Tool','Action','FileID','Epoch','Version','NotBefore','ExpiresAt','RevokedAt'] AND (payload - ARRAY['ID','OwnerID','AgentID','ConnectionID','Tool','Action','FileID','Epoch','Version','NotBefore','ExpiresAt','RevokedAt']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  agent_id text GENERATED ALWAYS AS (payload->>'AgentID') STORED NOT NULL,
  connection_id text GENERATED ALWAYS AS (payload->>'ConnectionID') STORED NOT NULL,
  tool text GENERATED ALWAYS AS (payload->>'Tool') STORED NOT NULL,
  action text GENERATED ALWAYS AS (payload->>'Action') STORED NOT NULL,
  file_id text GENERATED ALWAYS AS (payload->>'FileID') STORED NOT NULL,
  epoch bigint GENERATED ALWAYS AS ((payload->>'Epoch')::bigint) STORED NOT NULL,
  version bigint GENERATED ALWAYS AS ((payload->>'Version')::bigint) STORED NOT NULL,
  CHECK (length(id) > 0 AND length(tool) > 0 AND length(action) > 0 AND length(file_id) > 0),
  CHECK (epoch > 0 AND version > 0),
  CHECK ((payload->>'ExpiresAt')::timestamptz > (payload->>'NotBefore')::timestamptz),
  FOREIGN KEY (agent_id, owner_id) REFERENCES agents (id, owner_id),
  FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id),
  FOREIGN KEY (connection_id, file_id, owner_id) REFERENCES resources (connection_id, file_id, owner_id),
  UNIQUE (id, agent_id, owner_id, tool, file_id)
);

CREATE TABLE delegation_requests (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','AgentID','FileID','Tool','Digest','Status','GrantID','Version','DurationSeconds','RequestedExpiry','ExpiresAt'] AND (payload - ARRAY['ID','AgentID','FileID','Tool','Digest','Status','GrantID','Version','DurationSeconds','RequestedExpiry','ExpiresAt']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  agent_id text GENERATED ALWAYS AS (payload->>'AgentID') STORED NOT NULL,
  owner_id text NOT NULL,
  file_id text GENERATED ALWAYS AS (payload->>'FileID') STORED NOT NULL,
  tool text GENERATED ALWAYS AS (payload->>'Tool') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  approved_grant_id text GENERATED ALWAYS AS (NULLIF(payload->>'GrantID', '')) STORED,
  version bigint GENERATED ALWAYS AS ((payload->>'Version')::bigint) STORED NOT NULL,
  duration_seconds bigint GENERATED ALWAYS AS ((payload->>'DurationSeconds')::bigint) STORED NOT NULL,
  CHECK (length(id) > 0 AND length(file_id) > 0 AND length(tool) > 0 AND length(status) > 0),
  CHECK (length(payload->>'Digest') > 0),
  CHECK (version > 0 AND duration_seconds > 0),
  CHECK ((status = 'approved') = (approved_grant_id IS NOT NULL)),
  UNIQUE (approved_grant_id),
  FOREIGN KEY (agent_id, owner_id) REFERENCES agents (id, owner_id),
  FOREIGN KEY (approved_grant_id, agent_id, owner_id, tool, file_id) REFERENCES grants (id, agent_id, owner_id, tool, file_id)
);

CREATE TABLE oauth_transactions (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','OwnerID','SessionID','StateHash','NonceHash','SecretRef','ConnectionID','ExpiresAt','Consumed'] AND (payload - ARRAY['ID','OwnerID','SessionID','StateHash','NonceHash','SecretRef','ConnectionID','ExpiresAt','Consumed']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  session_id text GENERATED ALWAYS AS (payload->>'SessionID') STORED NOT NULL,
  connection_id text GENERATED ALWAYS AS (NULLIF(payload->>'ConnectionID', '')) STORED,
  CHECK (length(id) > 0),
  CHECK (length(payload->>'StateHash') > 0 AND length(payload->>'NonceHash') > 0 AND length(payload->>'SecretRef') > 0),
  FOREIGN KEY (session_id, owner_id) REFERENCES sessions (id, owner_id),
  FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id)
);

CREATE TABLE cleanup_outbox (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','ConnectionID','OwnerID','Status','Epoch'] AND (payload - ARRAY['ID','ConnectionID','OwnerID','Status','Epoch']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  connection_id text GENERATED ALWAYS AS (payload->>'ConnectionID') STORED NOT NULL,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  epoch bigint GENERATED ALWAYS AS ((payload->>'Epoch')::bigint) STORED NOT NULL,
  CHECK (length(id) > 0 AND length(status) > 0),
  CHECK (epoch > 0),
  FOREIGN KEY (connection_id, owner_id) REFERENCES connections (id, owner_id)
);

CREATE TABLE audit_events (
  payload jsonb NOT NULL CHECK (jsonb_typeof(payload) = 'object' AND payload ?& ARRAY['ID','At','ActorType','ActorID','SubjectID','Action','GrantID','ConnectionID','ResourceID','Outcome','InvocationID','Bytes'] AND (payload - ARRAY['ID','At','ActorType','ActorID','SubjectID','Action','GrantID','ConnectionID','ResourceID','Outcome','InvocationID','Bytes']) = '{}'::jsonb),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  event_order bigserial UNIQUE,
  subject_id text GENERATED ALWAYS AS (NULLIF(payload->>'SubjectID', '')) STORED,
  bytes bigint GENERATED ALWAYS AS ((payload->>'Bytes')::bigint) STORED NOT NULL,
  CHECK (length(id) > 0),
  CHECK (bytes >= 0)
);

-- Audit references intentionally have no FKs: immutable events survive lifecycle
-- cleanup and can describe failed actions against nonexistent or deleted IDs.
CREATE FUNCTION toolbox_reject_audit_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'audit events are append-only' USING ERRCODE = '23514'; END;
$$;
CREATE TRIGGER audit_immutable BEFORE UPDATE OR DELETE ON audit_events
  FOR EACH ROW EXECUTE FUNCTION toolbox_reject_audit_mutation();
CREATE TRIGGER audit_no_truncate BEFORE TRUNCATE ON audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION toolbox_reject_audit_mutation();

CREATE FUNCTION toolbox_protect_grant() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'grants cannot be deleted' USING ERRCODE = '23514';
  END IF;
  IF (NEW.payload - 'RevokedAt') IS DISTINCT FROM (OLD.payload - 'RevokedAt')
     OR (OLD.payload->'RevokedAt' IS DISTINCT FROM 'null'::jsonb
         AND NEW.payload->'RevokedAt' IS DISTINCT FROM OLD.payload->'RevokedAt') THEN
    RAISE EXCEPTION 'grant is immutable except first revocation' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER grant_immutable BEFORE UPDATE OR DELETE ON grants
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_grant();

CREATE FUNCTION toolbox_protect_approval() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NULLIF(OLD.payload->>'GrantID', '') IS NOT NULL THEN
    IF TG_OP = 'DELETE' OR NEW.payload IS DISTINCT FROM OLD.payload OR NEW.owner_id IS DISTINCT FROM OLD.owner_id THEN
      RAISE EXCEPTION 'approved request is immutable' USING ERRCODE = '23514';
    END IF;
  END IF;
  IF TG_OP = 'DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER approval_immutable BEFORE UPDATE OR DELETE ON delegation_requests
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_approval();

CREATE FUNCTION toolbox_protect_owner() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.payload->>'OwnerID' IS DISTINCT FROM OLD.payload->>'OwnerID' THEN
    RAISE EXCEPTION 'owner is immutable' USING ERRCODE = '23514';
  END IF;
  IF TG_TABLE_NAME = 'connections' AND (NEW.payload->>'Epoch')::bigint < (OLD.payload->>'Epoch')::bigint THEN
    RAISE EXCEPTION 'connection epoch cannot decrease' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER agent_owner_immutable BEFORE UPDATE ON agents
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_owner();
CREATE TRIGGER connection_owner_immutable BEFORE UPDATE ON connections
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_owner();
