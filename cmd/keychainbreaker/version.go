package main

import (
	"cmp"
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// Set by GoReleaser through -ldflags -X; builds without them fall back to the module's build info.
var (
	version   = ""
	commit    = ""
	buildDate = ""
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			v, c, d := buildVersion()
			_, err := fmt.Fprintf(cmd.OutOrStdout(), "keychainbreaker %s\n  commit: %s\n  built:  %s\n", v, c, d)
			return err
		},
	}
}

func buildVersion() (ver, rev, date string) {
	ver, rev, date = version, commit, buildDate
	if info, ok := debug.ReadBuildInfo(); ok {
		if ver == "" && info.Main.Version != "(devel)" {
			ver = info.Main.Version
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = cmp.Or(rev, s.Value[:min(len(s.Value), 8)])
			case "vcs.time":
				date = cmp.Or(date, s.Value)
			}
		}
	}
	return cmp.Or(ver, "dev"), cmp.Or(rev, "none"), cmp.Or(date, "unknown")
}
