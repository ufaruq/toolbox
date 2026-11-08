-- A shared identity namespace gives primary and verified alias identities the
-- same uniqueness and composite caller-ownership foreign-key boundary.
CREATE TABLE identity_bindings (
  issuer text NOT NULL CHECK (length(issuer) > 0),
  subject text NOT NULL CHECK (length(subject) > 0),
  owner_id text NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  PRIMARY KEY (issuer, subject),
  UNIQUE (owner_id, issuer, subject)
);
INSERT INTO identity_bindings(issuer, subject, owner_id) SELECT issuer, subject, id FROM users;

CREATE TABLE identity_aliases (
  payload jsonb NOT NULL CHECK (
    jsonb_typeof(payload) = 'object'
    AND payload ?& ARRAY['Issuer','Subject','OwnerID']
    AND (payload - ARRAY['Issuer','Subject','OwnerID']) = '{}'::jsonb
    AND jsonb_typeof(payload->'Issuer') = 'string'
    AND jsonb_typeof(payload->'Subject') = 'string'
    AND jsonb_typeof(payload->'OwnerID') = 'string'
  ),
  issuer text GENERATED ALWAYS AS (payload->>'Issuer') STORED NOT NULL,
  subject text GENERATED ALWAYS AS (payload->>'Subject') STORED NOT NULL,
  owner_id text GENERATED ALWAYS AS (payload->>'OwnerID') STORED NOT NULL,
  CHECK (length(issuer) > 0 AND length(subject) > 0 AND length(owner_id) > 0),
  PRIMARY KEY (issuer, subject),
  FOREIGN KEY (owner_id) REFERENCES users(id),
  FOREIGN KEY (owner_id, issuer, subject) REFERENCES identity_bindings(owner_id, issuer, subject)
);

CREATE FUNCTION toolbox_insert_primary_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO identity_bindings(issuer, subject, owner_id)
    VALUES(NEW.issuer, NEW.subject, NEW.id);
  RETURN NEW;
END;
$$;
CREATE TRIGGER user_primary_identity AFTER INSERT ON users
  FOR EACH ROW EXECUTE FUNCTION toolbox_insert_primary_identity();

CREATE FUNCTION toolbox_protect_primary_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF (NEW.payload->'Issuer', NEW.payload->'Subject') IS DISTINCT FROM
     (OLD.payload->'Issuer', OLD.payload->'Subject') THEN
    RAISE EXCEPTION 'primary identity is immutable' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER user_primary_identity_immutable BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_primary_identity();

CREATE FUNCTION toolbox_insert_alias_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  INSERT INTO identity_bindings(issuer, subject, owner_id)
    VALUES(NEW.payload->>'Issuer', NEW.payload->>'Subject', NEW.payload->>'OwnerID');
  RETURN NEW;
END;
$$;
CREATE TRIGGER alias_identity_binding BEFORE INSERT ON identity_aliases
  FOR EACH ROW EXECUTE FUNCTION toolbox_insert_alias_identity();

CREATE FUNCTION toolbox_reject_alias_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'identity aliases are append-only' USING ERRCODE = '23514'; END;
$$;
CREATE TRIGGER identity_alias_immutable BEFORE UPDATE OR DELETE ON identity_aliases
  FOR EACH ROW EXECUTE FUNCTION toolbox_reject_alias_mutation();
CREATE TRIGGER identity_alias_no_truncate BEFORE TRUNCATE ON identity_aliases
  FOR EACH STATEMENT EXECUTE FUNCTION toolbox_reject_alias_mutation();

CREATE FUNCTION toolbox_protect_identity_binding() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- A primary can disappear only with its owner. Alias FKs and their immutable
  -- trigger prohibit deleting or cascading an alias-backed owner.
  IF TG_OP = 'DELETE' AND NOT EXISTS (SELECT 1 FROM users WHERE id=OLD.owner_id) THEN
    RETURN OLD;
  END IF;
  RAISE EXCEPTION 'identity binding is immutable' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER identity_binding_immutable BEFORE UPDATE OR DELETE ON identity_bindings
  FOR EACH ROW EXECUTE FUNCTION toolbox_protect_identity_binding();
CREATE TRIGGER identity_binding_no_truncate BEFORE TRUNCATE ON identity_bindings
  FOR EACH STATEMENT EXECUTE FUNCTION toolbox_reject_alias_mutation();

-- A registry row cannot manufacture an identity without a canonical owner or
-- an alias record. Deferred validation permits the alias's BEFORE INSERT trigger.
CREATE FUNCTION toolbox_check_identity_binding_source() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM users WHERE id=NEW.owner_id AND issuer=NEW.issuer AND subject=NEW.subject)
     AND NOT EXISTS (SELECT 1 FROM identity_aliases WHERE owner_id=NEW.owner_id AND issuer=NEW.issuer AND subject=NEW.subject) THEN
    RAISE EXCEPTION 'identity binding requires a primary or verified alias' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END;
$$;
CREATE CONSTRAINT TRIGGER identity_binding_source AFTER INSERT ON identity_bindings
  DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION toolbox_check_identity_binding_source();

ALTER TABLE caller_profiles DROP CONSTRAINT caller_profiles_owner_id_issuer_user_id_fkey;
ALTER TABLE caller_profiles ADD CONSTRAINT caller_profiles_owner_identity_fkey
  FOREIGN KEY (owner_id, issuer, user_id) REFERENCES identity_bindings(owner_id, issuer, subject);
