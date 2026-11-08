-- Preserve historic audit payloads and append-only triggers while allowing
-- verified caller attribution on new events. Never rewrite old audit records.
ALTER TABLE audit_events DROP CONSTRAINT audit_events_payload_check;
ALTER TABLE audit_events ADD CONSTRAINT audit_events_payload_check CHECK (
  jsonb_typeof(payload) = 'object'
  AND payload ?& ARRAY['ID','At','ActorType','ActorID','SubjectID','Action','GrantID','ConnectionID','ResourceID','Outcome','InvocationID','Bytes']
  AND (payload - ARRAY['ID','At','ActorType','ActorID','SubjectID','Action','GrantID','ConnectionID','ResourceID','Outcome','InvocationID','Bytes','AgentID','CallerProfileID','ClientID']) = '{}'::jsonb
  AND (NOT (payload ? 'AgentID') OR jsonb_typeof(payload->'AgentID') = 'string')
  AND (NOT (payload ? 'CallerProfileID') OR jsonb_typeof(payload->'CallerProfileID') = 'string')
  AND (NOT (payload ? 'ClientID') OR jsonb_typeof(payload->'ClientID') = 'string')
);
