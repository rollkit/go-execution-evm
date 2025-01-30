package main

import (
	"log"
	"os"

	cmd "github.com/rollkit/go-execution-evm/cmd/evm-middleware/commands"
)

const bufSize = 1024 * 1024

func main() {

	if err := cmd.Execute(); err != nil {
		log.Println(err)
		os.Exit(1)
	}

}
