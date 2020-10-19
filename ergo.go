package main

import (
	"log"

	"github.com/mdouchement/ergo/forwarder"
	"github.com/mdouchement/ergo/server"
	"github.com/spf13/cobra"
)

func main() {
	c := &cobra.Command{
		Use:   "ergo",
		Short: "Ergo proxy",
		Args:  cobra.ExactArgs(0),
	}
	c.AddCommand(server.Command())
	c.AddCommand(forwarder.Command())

	if err := c.Execute(); err != nil {
		log.Fatalf("%+v", err)
	}
}
