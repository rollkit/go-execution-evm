package commands

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "evm-middleware",
	Short: "EVM middleware for Rollkit",
}

func init() {
	rootCmd.AddCommand(runCmd)
}

func Execute() error {
	return rootCmd.Execute()
}
