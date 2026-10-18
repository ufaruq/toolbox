CREATE FUNCTION {{schema}}.protect_current_version() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF EXISTS (SELECT 1 FROM {{schema}}.current_secrets c WHERE c.path=OLD.path AND c.version=OLD.version AND NOT (c.hidden AND c.path LIKE 'oauth-transactions/%')) THEN
  RAISE EXCEPTION 'current credential cannot be deleted' USING ERRCODE='23514';
 END IF;
 RETURN OLD;
END $$;
CREATE TRIGGER current_version_retained BEFORE DELETE ON {{schema}}.secret_versions FOR EACH ROW EXECUTE FUNCTION {{schema}}.protect_current_version();
CREATE FUNCTION {{schema}}.reject_version_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'credential history is immutable' USING ERRCODE='23514'; END $$;
CREATE TRIGGER versions_immutable BEFORE UPDATE OF path,version,ciphertext ON {{schema}}.secret_versions FOR EACH ROW EXECUTE FUNCTION {{schema}}.reject_version_update();
CREATE FUNCTION {{schema}}.retire_oauth(p text, v bigint) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF p NOT LIKE 'oauth-transactions/%' THEN RETURN false; END IF;
 UPDATE {{schema}}.current_secrets SET hidden=true WHERE path=p AND version=v;
 RETURN FOUND;
END $$;
REVOKE ALL ON FUNCTION {{schema}}.retire_oauth(text,bigint) FROM PUBLIC;

CREATE TABLE {{schema}}.retention_cursor (id boolean PRIMARY KEY DEFAULT true CHECK(id), path text NOT NULL);
INSERT INTO {{schema}}.retention_cursor(id,path) VALUES(true,'');
