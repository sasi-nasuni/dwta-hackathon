-- 004: who deleted a file and when (needed by the attack-outputs "replaced original" rule, spec §5.10.2).
ALTER TABLE files
  ADD COLUMN deleted_by     TEXT,
  ADD COLUMN deleted_sim_ts TIMESTAMPTZ;
