//go:build linux || darwin

package privatepki

import "slices"

// Optional exports follow the original journal suffix. Omitting their settings
// preserves the exact configuration and layout of existing PKI.
func (c Config) layout() ([]string, []string) {
	dirs, files := slices.Clone(directories), slices.Clone(artifacts)
	if len(c.DatabaseNames) != 0 {
		dirs = append(dirs, "database")
		files = append(files, "database/server.key", "database/server.pem")
	}
	if c.AdministratorAuthority {
		dirs = append(dirs, "administrator-authority")
		files = append(files, "administrator-authority/ca.key", "administrator-authority/ca.pem", "trust/administrator-ca.pem")
	}
	return dirs, files
}

func (c Config) roles() []string {
	roles := []string{"authority", "console", "broker", "gateway"}
	if len(c.DatabaseNames) != 0 {
		roles = append(roles, "database")
	}
	if c.AdministratorAuthority {
		roles = append(roles, "administrator-authority")
	}
	return roles
}

func identityPaths(role string) (string, string) {
	base := role + "/server"
	if role == "authority" || role == "administrator-authority" {
		base = role + "/ca"
	}
	if role == "gateway" {
		base = role + "/client"
	}
	return base + ".key", base + ".pem"
}

var trustSources = map[string]string{
	"gateway/backend-ca.pem":     "authority/ca.pem",
	"console/gateway-leaves.pem": "gateway/client.pem",
	"broker/gateway-leaves.pem":  "gateway/client.pem",
	"trust/backend-ca.pem":       "authority/ca.pem",
	"trust/administrator-ca.pem": "administrator-authority/ca.pem",
}
