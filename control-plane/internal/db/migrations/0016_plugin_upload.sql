-- Plugin upload — make the plugins table hold an actually-installable module.
--
-- 0001_init created `plugins` with `wasm_blob_uri TEXT NOT NULL` ("s3://..."),
-- which assumed an object store. No object store was ever built: MinIO appeared
-- in an early compose file with no S3 consumer anywhere in the codebase and was
-- removed as dead scaffolding. So the column could never be populated, and the
-- plugins table has held zero rows since it was created while the control plane
-- returned a hardcoded empty list.
--
-- The WASM module now lives in Postgres as bytea. For plugin-sized artifacts
-- (tens of KB to a few MB, capped at 10 MB on upload) this is the right trade:
-- the bytes replicate with the database, every control-plane node can serve them
-- to any of the WAF nodes, and they survive container recreation — none of which
-- is true of a file on one node's disk, which is how plugins could previously be
-- loaded at all (a manifest path on the data plane's own filesystem, unreachable
-- in a 3-node fleet).
--
-- Identity becomes (tenant_id, name): a plugin name is what the data plane loads
-- and what an operator reasons about, so re-uploading a name is an UPGRADE, not a
-- second coexisting row. The original (tenant_id, name, version) unique is left
-- in place; the new stricter index simply subsumes it.

-- +goose Up
-- +goose StatementBegin
ALTER TABLE plugins
    ADD COLUMN IF NOT EXISTS wasm        BYTEA,
    ADD COLUMN IF NOT EXISTS description TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS author      TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS hooks       JSONB  NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS permissions JSONB  NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS size_bytes  BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS uploaded_by TEXT   NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS updated_at  TIMESTAMPTZ NOT NULL DEFAULT now();

-- wasm_blob_uri is now vestigial. It cannot be dropped without breaking a
-- rollback to the previous schema, so it is merely relaxed: new rows leave it
-- empty rather than being forced to invent an s3:// URI that resolves nowhere.
ALTER TABLE plugins ALTER COLUMN wasm_blob_uri SET DEFAULT '';
ALTER TABLE plugins ALTER COLUMN wasm_blob_uri DROP NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS plugins_tenant_name_key ON plugins (tenant_id, name);
CREATE INDEX IF NOT EXISTS plugins_enabled_idx ON plugins (enabled);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS plugins_enabled_idx;
DROP INDEX IF EXISTS plugins_tenant_name_key;
ALTER TABLE plugins ALTER COLUMN wasm_blob_uri SET NOT NULL;
ALTER TABLE plugins ALTER COLUMN wasm_blob_uri DROP DEFAULT;
ALTER TABLE plugins
    DROP COLUMN IF EXISTS updated_at,
    DROP COLUMN IF EXISTS uploaded_by,
    DROP COLUMN IF EXISTS size_bytes,
    DROP COLUMN IF EXISTS permissions,
    DROP COLUMN IF EXISTS hooks,
    DROP COLUMN IF EXISTS author,
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS wasm;
-- +goose StatementEnd
