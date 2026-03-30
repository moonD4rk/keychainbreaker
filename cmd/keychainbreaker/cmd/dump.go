package cmd

import (
	"github.com/spf13/cobra"
)

// NewDumpCmd creates the dump subcommand.
func NewDumpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dump",
		Short: "Export all keychain data to a JSON file",
		RunE:  runDump,
	}
}

func runDump(cmd *cobra.Command, _ []string) error {
	kc, err := openAndTryUnlock(cmd)
	if err != nil {
		return err
	}

	gps, err := kc.GenericPasswords()
	if err != nil {
		return err
	}

	ips, err := kc.InternetPasswords()
	if err != nil {
		return err
	}

	pks, err := kc.PrivateKeys()
	if err != nil {
		return err
	}

	certs, err := kc.Certificates()
	if err != nil {
		return err
	}

	outputPath, _ := cmd.Flags().GetString(flagOutput)
	if outputPath == "" {
		outputPath = "keychain_dump.json"
	}

	output := dumpOutput{
		GenericPasswords:  gps,
		InternetPasswords: ips,
		PrivateKeys:       pks,
		Certificates:      certs,
	}

	if err := writeJSONFile(outputPath, output); err != nil {
		return err
	}

	printDumpSummary(gps, ips, pks, certs, kc.Unlocked(), outputPath)
	return nil
}
