package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version  = "TempVersion" //use ldflags replace
	codename = "ArchNet-node"
	intro    = "A ArchNet backend based on multi core"
)

var versionCommand = cobra.Command{
	Use:   "version",
	Short: "Print version info",
	Run: func(_ *cobra.Command, _ []string) {
		showVersion()
	},
}

func init() {
	command.AddCommand(&versionCommand)
}

func showVersion() {
	fmt.Println("  ___           _       _   _      _   \n" +
		" / _ \\         | |     | \\ | |    | |  \n" +
		"/ /_\\ \\_ __ ___| |__   |  \\| | ___| |_ \n" +
		"|  _  | '__/ __| '_ \\  | . ` |/ _ \\ __|\n" +
		"| | | | | | (__| | | | | |\\  |  __/ |_ \n" +
		"\\_| |_/_|  \\___|_| |_| \\_| \\_/\\___|\\__|\n")
	fmt.Printf("%s %s (%s) \n", codename, version, intro)
}
