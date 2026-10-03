-- +goose Up
-- Verdict cache for SafeDep's community malware analysis service, shared by all
-- tenants like the other feed caches (public data, no tenant column, no RLS).
CREATE TABLE malysis_verdict (
  ecosystem   text NOT NULL,
  name        text NOT NULL,
  version     text NOT NULL,
  is_malware  boolean NOT NULL,
  verified    boolean NOT NULL,
  analysis_id text NOT NULL DEFAULT '',
  summary     text NOT NULL DEFAULT '',
  fetched_at  timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name, version)
);
GRANT SELECT, INSERT, UPDATE ON malysis_verdict TO depguard_app;

-- +goose Down
DROP TABLE malysis_verdict;
