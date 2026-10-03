-- +goose Up
-- Reviews without findings were stored as JSON null; findings is always an array.
UPDATE pr_reviews SET findings = '[]' WHERE jsonb_typeof(findings) <> 'array';

-- +goose Down
SELECT 1;
