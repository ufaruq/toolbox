-- Owner authentication is independent of owner-bound Google connection OAuth.
CREATE TABLE owner_login_transactions (
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload) = 'object'
    AND payload ?& ARRAY['ID','StateHash','BrowserHash','NonceHash','SecretRef','Issuer','ClientID','RedirectURI','PreviousSessionID','IssuedSessionID','Status','ExpiresAt']
    AND (payload - ARRAY['ID','StateHash','BrowserHash','NonceHash','SecretRef','Issuer','ClientID','RedirectURI','PreviousSessionID','IssuedSessionID','Status','ExpiresAt']) = '{}'::jsonb
  ),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  state_hash text GENERATED ALWAYS AS (payload->>'StateHash') STORED NOT NULL UNIQUE,
  previous_session_id text GENERATED ALWAYS AS (NULLIF(payload->>'PreviousSessionID', '')) STORED,
  issued_session_id text GENERATED ALWAYS AS (NULLIF(payload->>'IssuedSessionID', '')) STORED,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  CHECK (
    jsonb_typeof(payload->'ID') = 'string' AND jsonb_typeof(payload->'StateHash') = 'string'
    AND jsonb_typeof(payload->'BrowserHash') = 'string' AND jsonb_typeof(payload->'NonceHash') = 'string'
    AND jsonb_typeof(payload->'SecretRef') = 'string' AND jsonb_typeof(payload->'Issuer') = 'string'
    AND jsonb_typeof(payload->'ClientID') = 'string' AND jsonb_typeof(payload->'RedirectURI') = 'string'
    AND jsonb_typeof(payload->'PreviousSessionID') = 'string' AND jsonb_typeof(payload->'IssuedSessionID') = 'string'
    AND jsonb_typeof(payload->'Status') = 'string' AND jsonb_typeof(payload->'ExpiresAt') = 'string'
  ),
  CHECK (length(id) > 0 AND length(state_hash) > 0),
  CHECK (length(payload->>'BrowserHash') > 0 AND length(payload->>'NonceHash') > 0 AND length(payload->>'SecretRef') > 0),
  CHECK (length(payload->>'Issuer') > 0 AND length(payload->>'ClientID') > 0 AND length(payload->>'RedirectURI') > 0),
  CHECK (status IN ('pending','exchanging','complete','failed','cancelled')),
  CHECK ((status = 'complete') = (issued_session_id IS NOT NULL)),
  CHECK ((payload->>'ExpiresAt')::timestamptz > '-infinity'::timestamptz),
  FOREIGN KEY (previous_session_id) REFERENCES sessions (id),
  FOREIGN KEY (issued_session_id) REFERENCES sessions (id)
);

CREATE FUNCTION toolbox_protect_user_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.payload->>'Issuer' IS DISTINCT FROM OLD.payload->>'Issuer'
     OR NEW.payload->>'Subject' IS DISTINCT FROM OLD.payload->>'Subject' THEN
    RAISE EXCEPTION 'user identity is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER user_identity_immutable BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_user_identity();

CREATE FUNCTION toolbox_protect_owner_login() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE previous_status text; next_status text;
BEGIN
  next_status := NEW.payload->>'Status';
  IF TG_OP = 'INSERT' THEN
    -- The adapter uses INSERT ... ON CONFLICT DO UPDATE. PostgreSQL runs its
    -- INSERT trigger before detecting the conflict; existing IDs are checked by
    -- this function's UPDATE branch against their actual previous state.
    IF NOT EXISTS (SELECT 1 FROM owner_login_transactions WHERE id = NEW.payload->>'ID')
       AND (next_status IS DISTINCT FROM 'pending' OR NULLIF(NEW.payload->>'IssuedSessionID', '') IS NOT NULL) THEN
      RAISE EXCEPTION 'owner login must start pending' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  previous_status := OLD.payload->>'Status';
  IF (NEW.payload - ARRAY['Status','IssuedSessionID']) IS DISTINCT FROM (OLD.payload - ARRAY['Status','IssuedSessionID']) THEN
    RAISE EXCEPTION 'owner login binding is immutable' USING ERRCODE = '23514';
  END IF;
  IF previous_status IS DISTINCT FROM next_status AND NOT (
      previous_status = 'pending' AND next_status IN ('exchanging','cancelled')
      OR previous_status = 'exchanging' AND next_status IN ('complete','failed','cancelled')) THEN
    RAISE EXCEPTION 'owner login transition rejected' USING ERRCODE = '23514';
  END IF;
  IF NEW.payload->>'IssuedSessionID' IS DISTINCT FROM OLD.payload->>'IssuedSessionID'
     AND NOT (COALESCE(OLD.payload->>'IssuedSessionID', '') = '' AND previous_status = 'exchanging' AND next_status = 'complete') THEN
    RAISE EXCEPTION 'owner login issued session is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER owner_login_immutable BEFORE INSERT OR UPDATE ON owner_login_transactions
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_owner_login();

-- Defer relationship retention to commit so a transaction may revoke its issued
-- session and remove terminal metadata atomically, despite adapter delete order.
CREATE FUNCTION toolbox_protect_owner_login_deletion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (OLD.payload->>'ExpiresAt')::timestamptz > clock_timestamp()
     AND OLD.payload->>'Status' IN ('pending','exchanging') THEN
    RAISE EXCEPTION 'active owner login cannot be deleted' USING ERRCODE = '23514';
  END IF;
  IF EXISTS (SELECT 1 FROM sessions WHERE id = NULLIF(OLD.payload->>'IssuedSessionID', '')
             AND (payload->>'ExpiresAt')::timestamptz > clock_timestamp()) THEN
    RAISE EXCEPTION 'live owner session relationship cannot be deleted' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END;
$$;
CREATE CONSTRAINT TRIGGER owner_login_retention AFTER DELETE ON owner_login_transactions
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION toolbox_protect_owner_login_deletion();
