package models

import (
	"database/sql"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// Exercise the actual service initializer twice, including additive objects
// owned by the console and duplicate field names in separate organizations.
func TestMetadataSchemaPreservesOrganizationNamesOnRestart(t *testing.T) {
	dsn := os.Getenv("APPLE_MDM_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = os.Getenv("AGENT_ENROLLMENT_TEST_DATABASE_URL")
	}
	if dsn == "" {
		t.Skip("set APPLE_MDM_TEST_DATABASE_URL for PostgreSQL schema restart coverage")
	}
	t.Setenv("ENV", "test")
	admin, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "metadata_startup_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.ExecContext(t.Context(), "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec("DROP SCHEMA " + schema + " CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	db, err := sql.Open("pgx", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for attempt := range 2 {
		model, err := New(u.String())
		if err != nil {
			t.Fatal(err)
		}
		model.Close()
		if attempt == 0 {
			for _, statement := range []string{
				"INSERT INTO tenants(id,description) VALUES(101,'First'),(102,'Second')",
				"INSERT INTO org_metadata(name,description,tenant_metadata) VALUES('Shared name','First definition',101),('Shared name','Second definition',102)",
				"ALTER TABLE org_metadata ADD COLUMN uem_restart_sentinel text DEFAULT 'retained'",
				"CREATE INDEX uem_restart_sentinel ON org_metadata(uem_restart_sentinel)",
			} {
				if _, err = db.ExecContext(t.Context(), statement); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err = db.ExecContext(t.Context(), "INSERT INTO org_metadata(name,tenant_metadata) VALUES('Shared name',101)"); err == nil {
			t.Fatal("duplicate field name accepted within one organization")
		}
	}
	var count int
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM org_metadata WHERE name='Shared name' AND uem_restart_sentinel='retained'").Scan(&count); err != nil || count != 2 {
		t.Fatal("restart changed scoped fields", count, err)
	}
	if err = db.QueryRowContext(t.Context(), "SELECT count(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname='uem_restart_sentinel'").Scan(&count); err != nil || count != 1 {
		t.Fatal("restart removed additive index", count, err)
	}
}
