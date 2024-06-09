package main

import (
	"context"
	"os"

	"github.com/konimarti/go-patatt"
	"github.com/spf13/cobra"
)

var (
	Verbose bool
	Debug   bool
	Section string
)

func main() {
	ctx := context.Background()

	cmd := &cobra.Command{
		Use:               "patatt",
		Short:             "Cryptographically attest patches before sending out",
		CompletionOptions: cobra.CompletionOptions{HiddenDefaultCmd: true},
		PersistentPreRun:  func(_ *cobra.Command, _ []string) { setLogLevel() },
	}

	cmd.Version = "0.1.0"

	cmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "be a bit more verbose")
	cmd.PersistentFlags().BoolVarP(&Debug, "debug", "d", false, "show debugging output")
	cmd.MarkFlagsMutuallyExclusive("verbose", "debug")

	cmd.PersistentFlags().StringVarP(&Section, "section", "s", "", "use config section [patatt \"section\"] ")

	cmd.AddCommand(newValidateCmd())
	cmd.AddCommand(newSignCmd())

	// cmd.AddCommand(newGenkeyCmd())
	// cmd.AddCommand(newInstallHookCmd())

	if err := cmd.ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}

}

func setLogLevel() {
	switch {
	case Verbose:
		patatt.SetLogLevel(patatt.INFO)
	case Debug:
		patatt.SetLogLevel(patatt.DEBUG)
	default:
		patatt.SetLogLevel(patatt.CRITICAL)
	}
}

func handleErr(err error) {
	patatt.Criticalf("E: %s\n", err.Error())
	os.Exit(1)
}
