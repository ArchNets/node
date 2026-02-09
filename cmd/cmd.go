package cmd

import (
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var command = &cobra.Command{
	Use: "node",
}

var (
	config string
	watch  bool
)

func init() {
	command.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/archnets/config.yml", "config file path")
	command.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
}

func Run() {
	err := command.Execute()
	if err != nil {
		log.WithField("err", err).Error("Execute command failed")
	}
}
