# Organization metadata schema compatibility

This component's non-production database initializer adapts the pinned upstream
Ent schema so custom field names are unique by `(tenant_metadata, name)`.
`internal/models/metadata_schema.go` must remain aligned with the console and
the other service initializer. It preserves unrelated additive columns and
indexes; it does not enable destructive schema-drop options.

Deploy this compatible initializer before the console's custom metadata upgrade.
The console explicitly removes the obsolete global name invariant in inventory
migration `042_custom_metadata.sql`. Older initializers can recreate that global
constraint or fail after two organizations reuse a field name. Drain older
console instances before allowing new metadata edits and do not restart an
incompatible service initializer against the upgraded database.

`TestMetadataSchemaPreservesOrganizationNamesOnRestart` uses the actual service
initializer twice against an isolated PostgreSQL schema. It verifies duplicate
names across organizations, rejection within one organization and retention of
an unrelated custom column/index. Set `APPLE_MDM_TEST_DATABASE_URL` (or
`AGENT_ENROLLMENT_TEST_DATABASE_URL`) to a disposable PostgreSQL database to run
it. Automatic initialization retains the existing `ENV != prod` behavior.

See the console's [custom metadata deployment guide](https://github.com/the-luap/openuem-console/blob/feature/native-ios-management/docs/custom-metadata.md)
for field revisions, value tombstones, deletion receipts and upgrade constraints.
