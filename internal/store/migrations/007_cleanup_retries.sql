ALTER TABLE cleanup_outbox DROP CONSTRAINT cleanup_outbox_payload_check;
UPDATE cleanup_outbox SET payload = payload || jsonb_build_object(
 'CreatedAt',clock_timestamp(),'LastAttemptAt','0001-01-01T00:00:00Z',
 'NextAttemptAt','0001-01-01T00:00:00Z','Attempts',0,'LastError','');
ALTER TABLE cleanup_outbox ADD CONSTRAINT cleanup_outbox_payload_check CHECK (
 jsonb_typeof(payload)='object'
 AND payload ?& ARRAY['ID','ConnectionID','OwnerID','Status','Epoch','CreatedAt','LastAttemptAt','NextAttemptAt','Attempts','LastError']
 AND (payload - ARRAY['ID','ConnectionID','OwnerID','Status','Epoch','CreatedAt','LastAttemptAt','NextAttemptAt','Attempts','LastError'])='{}'::jsonb
 AND jsonb_typeof(payload->'Attempts')='number' AND (payload->>'Attempts')::integer BETWEEN 0 AND 1000000
 AND (payload->>'LastError') IN ('','provider_unavailable')
 AND (payload->>'CreatedAt')::timestamptz > '-infinity'::timestamptz
 AND (payload->>'LastAttemptAt')::timestamptz > '-infinity'::timestamptz
 AND (payload->>'NextAttemptAt')::timestamptz > '-infinity'::timestamptz
);
