ALTER TABLE credentials DROP CONSTRAINT credentials_payload_check;
UPDATE credentials SET payload = payload || '{"PepperID":"legacy"}'::jsonb;
ALTER TABLE credentials ADD CONSTRAINT credentials_payload_check CHECK (
  jsonb_typeof(payload) = 'object'
  AND payload ?& ARRAY['ID','AgentID','Hash','Status','ExpiresAt','PepperID']
  AND (payload - ARRAY['ID','AgentID','Hash','Status','ExpiresAt','PepperID']) = '{}'::jsonb
  AND jsonb_typeof(payload->'PepperID') = 'string'
  AND (payload->>'PepperID') ~ '^[A-Za-z0-9_-]{0,64}$'
);
ALTER TABLE sessions DROP CONSTRAINT sessions_payload_check;
UPDATE sessions SET payload = payload || '{"PepperID":"legacy"}'::jsonb;
ALTER TABLE sessions ADD CONSTRAINT sessions_payload_check CHECK (
  jsonb_typeof(payload) = 'object'
  AND payload ?& ARRAY['ID','UserID','CSRFHash','ExpiresAt','PepperID']
  AND (payload - ARRAY['ID','UserID','CSRFHash','ExpiresAt','PepperID']) = '{}'::jsonb
  AND jsonb_typeof(payload->'PepperID') = 'string'
  AND (payload->>'PepperID') ~ '^[A-Za-z0-9_-]{0,64}$'
);
