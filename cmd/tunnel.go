package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

const TunnelPidFile = "/var/run/archnets-tunnel.pid"

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

		// Write PID file
		if err := os.WriteFile(TunnelPidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644); err != nil {
			log.Warnf("Failed to write PID file: %v", err)
		}
		defer os.Remove(TunnelPidFile)

		log.Info("Tunnel nodes started. Press Ctrl+C to stop")

		// Handle signals
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Block until signal
		sig := <-sigChan
		log.WithField("signal", sig).Info("Received signal, shutting down...")

		// Graceful shutdown
		tc.Close()
	},
}

var tunnelStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop tunnel processes (kills running binaries)",
	Run: func(cmd *cobra.Command, args []string) {
		pidContent, err := os.ReadFile(TunnelPidFile)
		if err != nil {
			if os.IsNotExist(err) {
				log.Warn("PID file not found. Is the tunnel running?")
				return
			}
			log.Fatalf("Failed to read PID file: %v", err)
		}

		pid, err := strconv.Atoi(string(pidContent))
		if err != nil {
			log.Fatalf("Invalid PID in file: %v", err)
		}

		// Send SIGTERM using cross-platform helper
		log.Infof("Sending stop signal to tunnel process %d...", pid)
		if err := node.StopProcess(pid); err != nil {
			log.Warnf("Failed to stop process: %v", err)
		}

		// Optionally wait or check if it died?
		// node.sh will wait.
		log.Info("Signal sent")
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
