-- +goose Up
-- When the package itself first appeared (oldest version), for the "new package" rule.
ALTER TABLE package_latest ADD COLUMN first_published timestamptz;
-- Cached rows lack it; let them refresh.
DELETE FROM package_latest;
-- Go metadata was looked up without deps.dev's leading "v" and cached as not found
-- (no license, no repo); drop it so it is fetched again correctly.
DELETE FROM package_meta WHERE ecosystem = 'Go';

-- +goose Down
ALTER TABLE package_latest DROP COLUMN first_published;
