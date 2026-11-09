-- Candidates carry verified identity and decision metadata, never permissions.
CREATE TABLE caller_candidates (
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload) = 'object'
    AND payload ?& ARRAY['ID','OwnerID','Issuer','UserID','ClientID','Status','FirstSeenAt','DecidedAt']
    AND (payload - ARRAY['ID','OwnerID','Issuer','UserID','ClientID','Status','FirstSeenAt','DecidedAt']) = '{}'::jsonb
    AND jsonb_typeof(payload->'ID') = 'string' AND jsonb_typeof(payload->'OwnerID') = 'string'
    AND jsonb_typeof(payload->'Issuer') = 'string' AND jsonb_typeof(payload->'UserID') = 'string'
    AND jsonb_typeof(payload->'ClientID') = 'string' AND jsonb_typeof(payload->'Status') = 'string'
    AND jsonb_typeof(payload->'FirstSeenAt') = 'string' AND jsonb_typeof(payload->'DecidedAt') = 'string'
  ),
  id text GENERATED ALWAYS AS (payload->>'ID') STORED NOT NULL PRIMARY KEY,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  issuer text GENERATED ALWAYS AS (payload->>'Issuer') STORED NOT NULL,
  user_id text GENERATED ALWAYS AS (payload->>'UserID') STORED NOT NULL,
  client_id text GENERATED ALWAYS AS (payload->>'ClientID') STORED NOT NULL,
  status text GENERATED ALWAYS AS (payload->>'Status') STORED NOT NULL,
  CHECK (length(id) > 0 AND length(owner_id) > 0 AND length(issuer) > 0 AND length(user_id) > 0 AND length(client_id) > 0),
  CHECK (status IN ('pending','rejected','approved')),
  CHECK (isfinite((payload->>'FirstSeenAt')::timestamptz) AND (payload->>'FirstSeenAt')::timestamptz <> '0001-01-01T00:00:00Z'::timestamptz),
  CHECK (isfinite((payload->>'DecidedAt')::timestamptz) AND
    ((status = 'pending' AND (payload->>'DecidedAt')::timestamptz = '0001-01-01T00:00:00Z'::timestamptz) OR
     (status <> 'pending' AND (payload->>'DecidedAt')::timestamptz <> '0001-01-01T00:00:00Z'::timestamptz AND (payload->>'DecidedAt')::timestamptz >= (payload->>'FirstSeenAt')::timestamptz))),
  FOREIGN KEY (owner_id, issuer, user_id) REFERENCES identity_bindings(owner_id, issuer, subject),
  UNIQUE (issuer, user_id, client_id)
);

CREATE FUNCTION toolbox_protect_caller_candidate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.payload->'ID', NEW.payload->'OwnerID', NEW.payload->'Issuer', NEW.payload->'UserID', NEW.payload->'ClientID', NEW.payload->'FirstSeenAt')
    IS DISTINCT FROM
    (OLD.payload->'ID', OLD.payload->'OwnerID', OLD.payload->'Issuer', OLD.payload->'UserID', OLD.payload->'ClientID', OLD.payload->'FirstSeenAt') THEN
    RAISE EXCEPTION 'caller candidate identity is immutable' USING ERRCODE = '23514';
  END IF;
  IF (OLD.status = 'approved' AND NEW.payload->>'Status' <> 'approved')
    OR (OLD.status = 'rejected' AND NEW.payload->>'Status' = 'approved')
    OR (OLD.status = NEW.payload->>'Status' AND OLD.payload->'DecidedAt' IS DISTINCT FROM NEW.payload->'DecidedAt') THEN
    RAISE EXCEPTION 'caller candidate decision is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER caller_candidate_immutable BEFORE UPDATE ON caller_candidates
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_caller_candidate();

-- Deferred checks permit atomic profile creation + candidate consumption in
-- either order while retaining the approved-profile invariant at commit.
CREATE FUNCTION toolbox_check_candidate_profile() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE i text; u text; c text;
BEGIN
  IF TG_OP = 'DELETE' THEN i := OLD.issuer; u := OLD.user_id; c := OLD.client_id;
  ELSE i := NEW.issuer; u := NEW.user_id; c := NEW.client_id; END IF;
  IF EXISTS (
    SELECT 1 FROM caller_candidates candidate
    WHERE candidate.issuer=i AND candidate.user_id=u AND candidate.client_id=c
      AND ((candidate.status = 'approved') IS DISTINCT FROM EXISTS (
        SELECT 1 FROM caller_profiles profile WHERE profile.issuer=i AND profile.user_id=u AND profile.client_id=c AND profile.owner_id=candidate.owner_id
      ))
  ) THEN
    RAISE EXCEPTION 'candidate approval requires its exact caller profile' USING ERRCODE = '23514';
  END IF;
  RETURN NULL;
END;
$$;
CREATE CONSTRAINT TRIGGER caller_candidate_profile AFTER INSERT OR UPDATE OR DELETE ON caller_candidates
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION toolbox_check_candidate_profile();
CREATE CONSTRAINT TRIGGER caller_profile_candidate AFTER INSERT OR UPDATE OR DELETE ON caller_profiles
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION toolbox_check_candidate_profile();

-- An approved candidate preserves its existing profile and agent binding.
-- Relabeling, disabling and expiry remain supported by ordinary profile updates.
CREATE FUNCTION toolbox_protect_approved_candidate_profile() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (SELECT 1 FROM caller_candidates WHERE issuer=OLD.issuer AND user_id=OLD.user_id AND client_id=OLD.client_id AND status='approved') THEN
    RAISE EXCEPTION 'approved candidate profile cannot be replaced' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END;
$$;
CREATE TRIGGER approved_candidate_profile_no_delete BEFORE DELETE ON caller_profiles
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_approved_candidate_profile();
