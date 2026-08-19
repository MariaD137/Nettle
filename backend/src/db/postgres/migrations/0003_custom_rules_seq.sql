-- SQLite's listCustomRules() broke same-millisecond created_at ties on the
-- implicit `rowid` column (insertion order). PostgreSQL has no equivalent
-- system column safe to sort by, so this adds a real monotonic sequence
-- column to restore the same deterministic tiebreak.

ALTER TABLE custom_rules ADD COLUMN seq BIGSERIAL;
