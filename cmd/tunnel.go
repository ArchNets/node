package cmd

import (
	"fmt"
	"os"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var tunnelCommand = &cobra.Command{
	Use:   "tunnel",
	Short: "Manage tunnel nodes (WaterWall, Gost, NodePass)",
}

var tunnelInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install tunnel binaries (WaterWall, Gost, NodePass)",
	Run: func(cmd *cobra.Command, args []string) {
		c := loadConfig()
		tc := node.NewTunnelController(panel.NewClientV2(&c.ApiConfig), c.ApiConfig.ServerId)
		if err := tc.CheckAndInstallBinaries(); err != nil {
			log.Fatalf("Installation failed: %v", err)
		}
		log.Info("All tunnel components installed successfully")
	},
}

var tunnelUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Uninstall tunnel components and remove directories",
	Run: func(cmd *cobra.Command, args []string) {
		c := loadConfig()
		tc := node.NewTunnelController(panel.NewClientV2(&c.ApiConfig), c.ApiConfig.ServerId)
		if err := tc.Uninstall(); err != nil {
			log.Fatalf("Uninstallation failed: %v", err)
		}
		log.Info("All tunnel components uninstalled and directories removed")
	},
}

var tunnelStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start tunnel nodes",
	Run: func(cmd *cobra.Command, args []string) {
		c := loadConfig()
		tc := node.NewTunnelController(panel.NewClientV2(&c.ApiConfig), c.ApiConfig.ServerId)
		if err := tc.Start(); err != nil {
			log.Fatalf("Failed to start tunnel: %v", err)
		}
		log.Info("Tunnel nodes started. Press Ctrl+C to stop (if running in foreground)")
		// Wait for signal? Normally 'node server' is used for long-running.
		// For standalone start, we might want to keep it alive if it's not a service.
		select {}
	},
}

var tunnelStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop tunnel processes (kills running binaries)",
	Run: func(cmd *cobra.Command, args []string) {
		c := loadConfig()
		tc := node.NewTunnelController(panel.NewClientV2(&c.ApiConfig), c.ApiConfig.ServerId)
		// We stop by calling Uninstall logic but only stopping processes
		tc.Close()
		log.Info("Tunnel processes stopped")
	},
}

var tunnelRestartCmd = &cobra.Command{
	Use:   "restart",
	Short: "Restart tunnel nodes",
	Run: func(cmd *cobra.Command, args []string) {
		c := loadConfig()
		tc := node.NewTunnelController(panel.NewClientV2(&c.ApiConfig), c.ApiConfig.ServerId)
		tc.Close()
		if err := tc.Start(); err != nil {
			log.Fatalf("Failed to restart tunnel: %v", err)
		}
		log.Info("Tunnel nodes restarted")
		select {}
	},
}

func init() {
	tunnelCommand.AddCommand(tunnelInstallCmd)
	tunnelCommand.AddCommand(tunnelUninstallCmd)
	tunnelCommand.AddCommand(tunnelStartCmd)
	tunnelCommand.AddCommand(tunnelStopCmd)
	tunnelCommand.AddCommand(tunnelRestartCmd)

	command.AddCommand(tunnelCommand)
}

func loadConfig() *conf.Conf {
	c := conf.New()
	err := c.LoadFromPath(config) // 'config' is a global flag from server.go
	if err != nil {
		fmt.Printf("Error: failed to read config file: %v\n", err)
		os.Exit(1)
	}
	return c
}
