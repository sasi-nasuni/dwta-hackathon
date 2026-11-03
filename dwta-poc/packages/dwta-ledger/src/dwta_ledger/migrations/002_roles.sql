-- 002: one role per writer service, each limited to its own tables (LED-03).
-- Role passwords are set by `dwta-ledger migrate` from the environment, never stored here.

GRANT USAGE ON SCHEMA public TO dwta_classifier, dwta_matcher, dwta_incident, dwta_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO dwta_classifier, dwta_matcher, dwta_incident, dwta_reader;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO dwta_classifier, dwta_matcher, dwta_incident;

GRANT INSERT, UPDATE ON files, artifacts TO dwta_classifier;
GRANT INSERT ON alerts TO dwta_classifier;
GRANT INSERT, UPDATE ON consumer_offsets TO dwta_classifier;

GRANT INSERT ON feed_entries, feed_matches, alerts TO dwta_matcher;
GRANT INSERT, UPDATE ON consumer_offsets TO dwta_matcher;

GRANT INSERT, UPDATE ON incidents TO dwta_incident;
GRANT INSERT, UPDATE, DELETE ON review_items, review_decisions TO dwta_incident;
GRANT INSERT ON alerts TO dwta_incident;
