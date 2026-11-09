-- GitHub repository grants are separate from legacy Google document grants.
CREATE TABLE github_connections (
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND payload ?& ARRAY['ID','OwnerID','RepositoryOwner','RepositoryName','Status','InstallationID','RepositoryID','Epoch'] AND (payload-ARRAY['ID','OwnerID','RepositoryOwner','RepositoryName','Status','InstallationID','RepositoryID','Epoch'])='{}'::jsonb),
 id text GENERATED ALWAYS AS (payload->>'ID') STORED PRIMARY KEY,
 owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL REFERENCES users(id),
 repository_id bigint GENERATED ALWAYS AS ((payload->>'RepositoryID')::bigint) STORED NOT NULL CHECK(repository_id>0),
 CHECK(length(payload->>'ID')>0 AND length(payload->>'RepositoryOwner')>0 AND length(payload->>'RepositoryName')>0),
 CHECK((payload->>'InstallationID')::bigint>0 AND (payload->>'Epoch')::bigint>0),
 CHECK(payload->>'Status' IN ('active','disconnected')),
 UNIQUE(id,owner_id,repository_id)
);
CREATE TABLE github_grants (
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND payload ?& ARRAY['ID','OwnerID','AgentID','ConnectionID','RepositoryID','Epoch','Scope','NotBefore','ExpiresAt','RevokedAt'] AND (payload-ARRAY['ID','OwnerID','AgentID','ConnectionID','RepositoryID','Epoch','Scope','NotBefore','ExpiresAt','RevokedAt'])='{}'::jsonb),
 id text GENERATED ALWAYS AS (payload->>'ID') STORED PRIMARY KEY,
 owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
 agent_id text GENERATED ALWAYS AS (payload->>'AgentID') STORED NOT NULL,
 connection_id text GENERATED ALWAYS AS (payload->>'ConnectionID') STORED NOT NULL,
 repository_id bigint GENERATED ALWAYS AS ((payload->>'RepositoryID')::bigint) STORED NOT NULL,
 CHECK(length(payload->>'ID')>0 AND (payload->>'Epoch')::bigint>0),
 CHECK(jsonb_typeof(payload->'Scope')='object' AND jsonb_typeof(payload->'Scope'->'Actions')='array' AND jsonb_array_length(payload->'Scope'->'Actions')>0),
 CHECK(isfinite((payload->>'NotBefore')::timestamptz) AND isfinite((payload->>'ExpiresAt')::timestamptz) AND (payload->>'ExpiresAt')::timestamptz>(payload->>'NotBefore')::timestamptz),
 FOREIGN KEY(agent_id,owner_id) REFERENCES agents(id,owner_id),
 FOREIGN KEY(connection_id,owner_id,repository_id) REFERENCES github_connections(id,owner_id,repository_id),
 UNIQUE(id,owner_id,agent_id,connection_id,repository_id)
);
CREATE TABLE github_requests (
 payload jsonb NOT NULL CHECK(jsonb_typeof(payload)='object' AND payload ?& ARRAY['ID','OwnerID','AgentID','ConnectionID','Status','Digest','GrantID','RepositoryID','Epoch','Scope','ExpiresAt','ReviewExpiresAt'] AND (payload-ARRAY['ID','OwnerID','AgentID','ConnectionID','Status','Digest','GrantID','RepositoryID','Epoch','Scope','ExpiresAt','ReviewExpiresAt'])='{}'::jsonb),
 id text GENERATED ALWAYS AS (payload->>'ID') STORED PRIMARY KEY,
 owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
 agent_id text GENERATED ALWAYS AS (payload->>'AgentID') STORED NOT NULL,
 connection_id text GENERATED ALWAYS AS (payload->>'ConnectionID') STORED NOT NULL,
 repository_id bigint GENERATED ALWAYS AS ((payload->>'RepositoryID')::bigint) STORED NOT NULL,
 grant_id text GENERATED ALWAYS AS (NULLIF(payload->>'GrantID','')) STORED UNIQUE,
 CHECK(length(payload->>'ID')>0 AND length(payload->>'Digest')>0 AND (payload->>'Epoch')::bigint>0),
 CHECK(payload->>'Status' IN ('pending','approved','denied','expired')),
 CHECK((payload->>'Status'='approved')=(NULLIF(payload->>'GrantID','') IS NOT NULL)),
 CHECK(jsonb_typeof(payload->'Scope')='object'),
 CHECK(isfinite((payload->>'ExpiresAt')::timestamptz) AND isfinite((payload->>'ReviewExpiresAt')::timestamptz)),
 FOREIGN KEY(agent_id,owner_id) REFERENCES agents(id,owner_id),
 FOREIGN KEY(connection_id,owner_id,repository_id) REFERENCES github_connections(id,owner_id,repository_id),
 FOREIGN KEY(grant_id,owner_id,agent_id,connection_id,repository_id) REFERENCES github_grants(id,owner_id,agent_id,connection_id,repository_id)
);
CREATE FUNCTION toolbox_protect_github() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'github authorization deletion forbidden' USING ERRCODE='23514'; END IF;
 IF TG_TABLE_NAME='github_connections' THEN
  IF NEW.payload-ARRAY['Status','Epoch'] IS DISTINCT FROM OLD.payload-ARRAY['Status','Epoch'] OR (NEW.payload->>'Epoch')::bigint<(OLD.payload->>'Epoch')::bigint OR (OLD.payload->>'Status'='disconnected' AND NEW.payload->>'Status'<>'disconnected') OR (NEW.payload->>'Status'<>OLD.payload->>'Status' AND (NEW.payload->>'Epoch')::bigint<=(OLD.payload->>'Epoch')::bigint) THEN
   RAISE EXCEPTION 'github connection binding immutable' USING ERRCODE='23514'; END IF;
 ELSIF TG_TABLE_NAME='github_grants' THEN
  IF NEW.payload-'RevokedAt' IS DISTINCT FROM OLD.payload-'RevokedAt' OR (OLD.payload->'RevokedAt'<>'null'::jsonb AND NEW.payload->'RevokedAt' IS DISTINCT FROM OLD.payload->'RevokedAt') THEN
   RAISE EXCEPTION 'github grant immutable' USING ERRCODE='23514'; END IF;
 ELSE
  IF (OLD.payload->>'Status'<>'pending' AND NEW.payload IS DISTINCT FROM OLD.payload) OR NEW.payload-ARRAY['Status','GrantID'] IS DISTINCT FROM OLD.payload-ARRAY['Status','GrantID'] THEN
   RAISE EXCEPTION 'github request binding immutable' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER github_connection_immutable BEFORE UPDATE OR DELETE ON github_connections FOR EACH ROW EXECUTE FUNCTION toolbox_protect_github();
CREATE TRIGGER github_grant_immutable BEFORE UPDATE OR DELETE ON github_grants FOR EACH ROW EXECUTE FUNCTION toolbox_protect_github();
CREATE TRIGGER github_request_immutable BEFORE UPDATE OR DELETE ON github_requests FOR EACH ROW EXECUTE FUNCTION toolbox_protect_github();

-- Validate JSON types explicitly: SQL CHECK treats NULL as success. Reject null
-- security fields rather than allowing casts/comparisons to become unknown.
CREATE FUNCTION toolbox_validate_github_record() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE key text; value jsonb; scope jsonb; conn jsonb; granted jsonb;
BEGIN
 FOR key,value IN SELECT * FROM jsonb_each(NEW.payload) LOOP
  IF key IN ('InstallationID','RepositoryID','Epoch') THEN
   IF jsonb_typeof(value) <> 'number' OR value::text !~ '^[1-9][0-9]*$' THEN
    RAISE EXCEPTION 'github numeric field invalid' USING ERRCODE='23514'; END IF;
  ELSIF key='Scope' THEN
   IF jsonb_typeof(value)<>'object' THEN RAISE EXCEPTION 'github scope invalid' USING ERRCODE='23514'; END IF;
  ELSIF key='RevokedAt' THEN
   IF value<>'null'::jsonb AND (jsonb_typeof(value)<>'string' OR NOT isfinite((value#>>'{}')::timestamptz)) THEN
    RAISE EXCEPTION 'github revocation invalid' USING ERRCODE='23514'; END IF;
  ELSE
   IF jsonb_typeof(value)<>'string' OR (length(value#>>'{}')=0 AND key<>'GrantID') THEN
    RAISE EXCEPTION 'github string field invalid' USING ERRCODE='23514'; END IF;
  END IF;
 END LOOP;
 IF TG_TABLE_NAME<>'github_connections' THEN
  SELECT payload INTO conn FROM github_connections WHERE id=NEW.payload->>'ConnectionID';
  IF conn IS NULL OR (NEW.payload->>'Epoch')::bigint>(conn->>'Epoch')::bigint THEN
   RAISE EXCEPTION 'github epoch invalid' USING ERRCODE='23514'; END IF;
  scope:=NEW.payload->'Scope';
  IF NOT scope ?& ARRAY['Actions','Branches','BaseBranches','Paths','PullRequests','ExpectedHead','AllowUnconditionalWrites'] OR scope-ARRAY['Actions','Branches','BaseBranches','Paths','PullRequests','ExpectedHead','AllowUnconditionalWrites']<>'{}'::jsonb THEN
   RAISE EXCEPTION 'github scope fields invalid' USING ERRCODE='23514'; END IF;
  FOR key,value IN SELECT * FROM jsonb_each(scope) LOOP
   IF key='ExpectedHead' THEN
    IF jsonb_typeof(value)<>'string' OR (value#>>'{}') !~ '^([a-f0-9]{40})?$' THEN RAISE EXCEPTION 'github head invalid' USING ERRCODE='23514'; END IF;
   ELSIF key='AllowUnconditionalWrites' THEN
    IF jsonb_typeof(value)<>'boolean' THEN RAISE EXCEPTION 'github write acknowledgment invalid' USING ERRCODE='23514'; END IF;
   ELSIF value<>'null'::jsonb THEN
    IF jsonb_typeof(value)<>'array' OR jsonb_array_length(value)>128 THEN RAISE EXCEPTION 'github scope list invalid' USING ERRCODE='23514'; END IF;
    IF key='PullRequests' THEN
     IF EXISTS(SELECT 1 FROM jsonb_array_elements(value) e WHERE jsonb_typeof(e)<>'number' OR e::text !~ '^[1-9][0-9]*$') THEN RAISE EXCEPTION 'github PR list invalid' USING ERRCODE='23514'; END IF;
    ELSE
     IF EXISTS(SELECT 1 FROM jsonb_array_elements(value) e WHERE jsonb_typeof(e)<>'string' OR length(e#>>'{}')=0) THEN RAISE EXCEPTION 'github scope entry invalid' USING ERRCODE='23514'; END IF;
    END IF;
   END IF;
  END LOOP;
  IF scope->'Actions'='null'::jsonb OR jsonb_array_length(scope->'Actions') NOT BETWEEN 1 AND 10 THEN RAISE EXCEPTION 'github actions invalid' USING ERRCODE='23514'; END IF;
 END IF;
 IF TG_TABLE_NAME='github_requests' AND NEW.payload->>'Status'='approved' THEN
  SELECT payload INTO granted FROM github_grants WHERE id=NEW.payload->>'GrantID';
  IF granted IS NULL OR NEW.payload->'Scope' IS DISTINCT FROM granted->'Scope' OR NEW.payload->'Epoch' IS DISTINCT FROM granted->'Epoch' OR (NEW.payload->>'ExpiresAt')::timestamptz IS DISTINCT FROM (granted->>'ExpiresAt')::timestamptz THEN
   RAISE EXCEPTION 'github approval scope mismatch' USING ERRCODE='23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER github_connection_validate BEFORE INSERT OR UPDATE ON github_connections FOR EACH ROW EXECUTE FUNCTION toolbox_validate_github_record();
CREATE TRIGGER github_grant_validate BEFORE INSERT OR UPDATE ON github_grants FOR EACH ROW EXECUTE FUNCTION toolbox_validate_github_record();
CREATE TRIGGER github_request_validate BEFORE INSERT OR UPDATE ON github_requests FOR EACH ROW EXECUTE FUNCTION toolbox_validate_github_record();
