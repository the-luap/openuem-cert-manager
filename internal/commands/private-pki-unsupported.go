//go:build !linux && !darwin

package commands

import "github.com/urfave/cli/v2"

// The reference initializer uses native Unix directory durability and leases.
// Other deployment hosts run it in the Linux initialization container.
func PlatformSetupCommands() []*cli.Command { return nil }
