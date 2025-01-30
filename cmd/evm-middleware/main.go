package main

import (
	"log"
	"os"

	cmd "github.com/rollkit/go-execution-evm/cmd/evm-middleware/commands"
)

func main() {
	if err := cmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
