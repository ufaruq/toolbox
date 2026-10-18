-- Canonical owner identity is part of the caller binding, including for updates
-- to users made outside the adapter. This adds no restrictions to legacy rows.
ALTER TABLE users ADD CONSTRAINT users_id_identity_unique UNIQUE (id, issuer, subject);

CREATE TABLE caller_profiles (
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload) = 'object'
    AND payload ?& ARRAY['ID','OwnerID','AgentID','Issuer','UserID','ClientID','Label','Status','Tools','ApprovedAt','ExpiresAt']
    AND (payload - ARRAY['ID','OwnerID','AgentID','Issuer','UserID','ClientID','Label','Status','Tools','ApprovedAt','ExpiresAt']) = '{}'::jsonb
  ),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  agent_id text GENERATED ALWAYS AS (payload->>'AgentID') STORED NOT NULL,
  issuer text GENERATED ALWAYS AS (payload->>'Issuer') STORED NOT NULL,
  user_id text GENERATED ALWAYS AS (payload->>'UserID') STORED NOT NULL,
  client_id text GENERATED ALWAYS AS (payload->>'ClientID') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  CHECK (length(id) > 0 AND length(issuer) > 0 AND length(user_id) > 0 AND length(client_id) > 0),
  CHECK (status IN ('active','disabled')),
  CHECK (jsonb_typeof(payload->'ID') = 'string' AND jsonb_typeof(payload->'OwnerID') = 'string' AND jsonb_typeof(payload->'AgentID') = 'string'),
  CHECK (jsonb_typeof(payload->'Issuer') = 'string' AND jsonb_typeof(payload->'UserID') = 'string' AND jsonb_typeof(payload->'ClientID') = 'string'),
  CHECK (jsonb_typeof(payload->'Label') = 'string' AND jsonb_typeof(payload->'Status') = 'string'),
  CHECK (jsonb_typeof(payload->'Tools') IN ('array','null')),
  CHECK (NOT jsonb_path_exists(payload, '$.Tools[*] ? (@.type() != "string" && @.type() != "null")')),
  CHECK (jsonb_typeof(payload->'ApprovedAt') = 'string' AND jsonb_typeof(payload->'ExpiresAt') = 'string'),
  CHECK (isfinite((payload->>'ApprovedAt')::timestamptz) AND (payload->>'ApprovedAt')::timestamptz <> '0001-01-01T00:00:00Z'::timestamptz),
  CHECK (isfinite((payload->>'ExpiresAt')::timestamptz) AND (payload->>'ExpiresAt')::timestamptz <> '0001-01-01T00:00:00Z'::timestamptz AND (payload->>'ExpiresAt')::timestamptz > (payload->>'ApprovedAt')::timestamptz),
  FOREIGN KEY (owner_id, issuer, user_id) REFERENCES users (id, issuer, subject),
  FOREIGN KEY (agent_id, owner_id) REFERENCES agents (id, owner_id),
  UNIQUE (issuer, user_id, client_id),
  UNIQUE (agent_id)
);

CREATE TABLE owner_logins (
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload) = 'object'
    AND payload ?& ARRAY['ID','StateHash','NonceHash','BrowserHash','SecretRef','ExpiresAt','Consumed']
    AND (payload - ARRAY['ID','StateHash','NonceHash','BrowserHash','SecretRef','ExpiresAt','Consumed']) = '{}'::jsonb
  ),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  CHECK (jsonb_typeof(payload->'ID') = 'string' AND length(id) > 0),
  CHECK (jsonb_typeof(payload->'StateHash') = 'string' AND length(payload->>'StateHash') > 0),
  CHECK (jsonb_typeof(payload->'NonceHash') = 'string' AND length(payload->>'NonceHash') > 0),
  CHECK (jsonb_typeof(payload->'BrowserHash') = 'string' AND length(payload->>'BrowserHash') > 0),
  CHECK (jsonb_typeof(payload->'SecretRef') = 'string' AND length(payload->>'SecretRef') > 0),
  CHECK (jsonb_typeof(payload->'Consumed') = 'boolean'),
  CHECK (jsonb_typeof(payload->'ExpiresAt') = 'string'),
  CHECK (isfinite((payload->>'ExpiresAt')::timestamptz) AND (payload->>'ExpiresAt')::timestamptz <> '0001-01-01T00:00:00Z'::timestamptz)
);

CREATE FUNCTION toolbox_protect_caller_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.payload->'ID', NEW.payload->'OwnerID', NEW.payload->'AgentID', NEW.payload->'Issuer', NEW.payload->'UserID', NEW.payload->'ClientID')
    IS DISTINCT FROM
    (OLD.payload->'ID', OLD.payload->'OwnerID', OLD.payload->'AgentID', OLD.payload->'Issuer', OLD.payload->'UserID', OLD.payload->'ClientID') THEN
    RAISE EXCEPTION 'caller profile binding is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER caller_profile_binding_immutable BEFORE UPDATE ON caller_profiles
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_caller_profile();

CREATE FUNCTION toolbox_protect_owner_login() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.payload - ARRAY['Consumed','ExpiresAt']) IS DISTINCT FROM (OLD.payload - ARRAY['Consumed','ExpiresAt'])
     OR (NEW.payload->>'ExpiresAt')::timestamptz IS DISTINCT FROM (OLD.payload->>'ExpiresAt')::timestamptz
     OR (OLD.payload->'Consumed' = 'true'::jsonb AND NEW.payload->'Consumed' IS DISTINCT FROM 'true'::jsonb) THEN
    RAISE EXCEPTION 'owner login binding is immutable and consumption cannot revert' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER owner_login_consumption_monotonic BEFORE UPDATE ON owner_logins
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_owner_login();
