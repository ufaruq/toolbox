-- Preserve a completed login's revocation path through later replacements.
-- Keep this additive: existing installations have already applied migration 002.
CREATE OR REPLACE FUNCTION toolbox_protect_owner_login_deletion() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF EXISTS (
    WITH RECURSIVE descendants(payload) AS (
      SELECT OLD.payload
      UNION
      SELECT child.payload
      FROM owner_login_transactions child
      JOIN descendants parent
        ON child.previous_session_id = NULLIF(parent.payload->>'IssuedSessionID', '')
    )
    SELECT 1 FROM descendants d
    LEFT JOIN sessions s ON s.id = NULLIF(d.payload->>'IssuedSessionID', '')
    WHERE (d.payload->>'Status' IN ('pending','exchanging')
           AND (d.payload->>'ExpiresAt')::timestamptz > clock_timestamp())
       OR (s.payload->>'ExpiresAt')::timestamptz > clock_timestamp()
  ) THEN
    RAISE EXCEPTION 'live owner login relationship cannot be deleted' USING ERRCODE = '23514';
  END IF;
  RETURN OLD;
END;
$$;
