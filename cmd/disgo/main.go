package main

import (
	"fmt"
	"os"
	"github.com/steabert/disgo/pkg/cli"
)

func main() {
	cmd := cli.Build()
	if err := cmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
