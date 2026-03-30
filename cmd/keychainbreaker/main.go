package main

import (
	"os"

	"github.com/moond4rk/keychainbreaker/cmd/keychainbreaker/cmd"
)

func main() {
	if err := cmd.NewRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
