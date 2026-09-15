package models

import (
	"errors"
	"slices"

	atlas "ariga.io/atlas/sql/schema"
	entschema "entgo.io/ent/dialect/sql/schema"
)

// Keep this adapter aligned in the console, worker and certificate manager.
// Additive startup migration must not recreate global metadata-name uniqueness
// after the console has moved that invariant into the organization scope.
func metadataFieldScope() entschema.MigrateOption {
	return entschema.WithDiffHook(func(next entschema.Differ) entschema.Differ {
		return entschema.DiffFunc(func(current, desired *atlas.Schema) ([]atlas.Change, error) {
			table, ok := desired.Table("org_metadata")
			if !ok {
				return next.Diff(current, desired)
			}
			name, hasName := table.Column("name")
			tenant, hasTenant := table.Column("tenant_metadata")
			if !hasName || !hasTenant {
				return nil, errors.New("metadata schema columns are missing")
			}
			removed := map[*atlas.Index]bool{}
			table.Indexes = slices.DeleteFunc(table.Indexes, func(index *atlas.Index) bool {
				remove := index.Unique && len(index.Parts) == 1 && index.Parts[0].C == name
				if remove {
					removed[index] = true
				}
				return remove
			})
			name.Indexes = slices.DeleteFunc(name.Indexes, func(index *atlas.Index) bool { return removed[index] })
			if _, exists := table.Index("uem_metadata_field_name_tenant"); !exists {
				table.AddIndexes(atlas.NewUniqueIndex("uem_metadata_field_name_tenant").AddColumns(tenant, name))
			}
			return next.Diff(current, desired)
		})
	})
}
