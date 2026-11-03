-- 003: step ⑤ antivirus rescan verdict per review item (spec §5.10.4, AV-03).
ALTER TABLE review_items
  ADD COLUMN av_verdict     TEXT CHECK (av_verdict IN ('detected', 'clean', 'not_scanned', 'error')),
  ADD COLUMN av_signature   TEXT,
  ADD COLUMN av_engine      TEXT,
  ADD COLUMN av_definitions TEXT,
  ADD COLUMN av_scanned_at  TIMESTAMPTZ;
