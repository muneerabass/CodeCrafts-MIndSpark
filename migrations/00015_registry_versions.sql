-- +goose Up
-- Release metadata read straight from npm / PyPI (publish time, publisher,
-- provenance, install scripts): global cache for the fresh-release rules.
CREATE TABLE registry_versions (
  ecosystem       text NOT NULL,           -- OSV ecosystem name
  name_norm       text NOT NULL,
  version         text NOT NULL,
  published_at    timestamptz NOT NULL,
  publisher       text NOT NULL DEFAULT '',
  provenance      boolean NOT NULL DEFAULT false,
  install_scripts jsonb NOT NULL DEFAULT '{}',
  PRIMARY KEY (ecosystem, name_norm, version)
);
CREATE TABLE registry_fetched (
  ecosystem  text NOT NULL,
  name_norm  text NOT NULL,
  found      boolean NOT NULL DEFAULT true,
  newest     timestamptz,                    -- newest release; fresh packages are refetched sooner
  fetched_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (ecosystem, name_norm)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON registry_versions, registry_fetched TO depguard_app;

-- +goose Down
DROP TABLE registry_fetched;
DROP TABLE registry_versions;
