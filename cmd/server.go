package cmd

import (
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/core"
	"github.com/archnets/node/core/terminal"
	"github.com/archnets/node/limiter"
	"github.com/archnets/node/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// Global variables are now in cmd.go

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run node server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     true,
		ForceColors:      true,
	})
	if err != nil {
		log.WithField("err", err).Error("failed to read config file")
		return
	}
	switch c.LogConfig.Level {
	case "debug":
		log.SetLevel(log.DebugLevel)
	case "info":
		log.SetLevel(log.InfoLevel)
	case "warn", "warning":
		log.SetLevel(log.WarnLevel)
	case "error":
		log.SetLevel(log.ErrorLevel)
	}
	if c.LogConfig.Output != "" {
		f, err := os.OpenFile(c.LogConfig.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.WithField("err", err).Error("failed to open log file, using stdout instead")
		}
		log.SetOutput(f)
	}
	limiter.Init()
	p := panel.NewClientV2(&c.ApiConfig)
	serverconfig, err := panel.GetServerConfig(p)
	if err != nil {
		log.WithField("err", err).Error("failed to get server configuration")
		return
	}
	var reloadCh = make(chan struct{}, 1)
	xraycore := core.New(c, p)
	xraycore.ReloadCh = reloadCh
	err = xraycore.Start(serverconfig)
	if err != nil {
		log.WithField("err", err).Error("failed to start Xray core")
		return
	}
	defer xraycore.Close()
	nodes, err := node.New(xraycore, c, serverconfig)
	if err != nil {
		log.WithField("err", err).Error("failed to get node configuration")
		return
	}

	// Clean up legacy standalone tunnel process if lingering from older scripts
	cleanupLegacyTunnelProcess()

	// Start protocol nodes and unified tunnel controller concurrently once Xray core listeners are bound.
	tunnelCtrl := node.NewTunnelController(p, c.ApiConfig.ServerId, c)
	var startWG sync.WaitGroup
	var nodesStartErr error
	startWG.Add(2)
	go func() {
		defer startWG.Done()
		nodesStartErr = nodes.Start()
	}()
	go func() {
		defer startWG.Done()
		if tErr := tunnelCtrl.Start(); tErr != nil {
			log.WithField("err", tErr).Warn("Tunnel controller failed to start, will retry on next poll")
		}
	}()
	startWG.Wait()
	if nodesStartErr != nil {
		log.WithField("err", nodesStartErr).Error("failed to start nodes")
		_ = tunnelCtrl.Close()
		return
	}
	log.Infof("started %d nodes", serverconfig.Data.Total)

	// Initialize and start remote terminal controller for panel SSH sessions
	terminalCtrl := terminal.NewController(c.ApiConfig.ApiHost, c.ApiConfig.ServerId, c.ApiConfig.SecretKey)
	terminalCtrl.Start()
	if watch {
		if _, err := os.Stat(config); err == nil {
			// On file change, just signal reload; do not run reload concurrently here
			err = c.Watch(config, func() {
				select {
				case reloadCh <- struct{}{}:
				default: // drop if a reload is already queued
				}
			})
			if err != nil {
				log.WithField("err", err).Error("start watch failed")
				return
			}
		} else {
			log.Info("config file not present, skipping file watch (using environment variables)")
		}
	}
	// clear memory
	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-osSignals:
			var stopWG sync.WaitGroup
			if tunnelCtrl != nil {
				stopWG.Add(1)
				go func(tc *node.TunnelController) {
					defer stopWG.Done()
					_ = tc.Close()
				}(tunnelCtrl)
			}
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				nodes.Close()
			}()
			stopWG.Add(1)
			go func() {
				defer stopWG.Done()
				terminalCtrl.Close()
			}()
			stopWG.Wait()
			_ = xraycore.Close()
			return
		case <-reloadCh:
			log.Info("received reload signal, reloading configuration...")
			if err := reload(config, &nodes, &xraycore, &tunnelCtrl); err != nil {
				log.WithField("err", err).Error("reload failed")
			}
		}
	}
}

func reload(config string, nodes **node.Node, xcore **core.XrayCore, tunnelCtrl **node.TunnelController) error {
	// Preserve old reload channel so new core continues to receive signals
	var oldReloadCh chan struct{}

	if *xcore != nil {
		oldReloadCh = (*xcore).ReloadCh
	}

	var stopWG sync.WaitGroup
	if *tunnelCtrl != nil {
		stopWG.Add(1)
		go func(tc *node.TunnelController) {
			defer stopWG.Done()
			_ = tc.Close()
		}(*tunnelCtrl)
	}
	stopWG.Add(1)
	go func() {
		defer stopWG.Done()
		(*nodes).Close()
	}()
	stopWG.Wait()
	if err := (*xcore).Close(); err != nil {
		return err
	}

	newConf := conf.New()
	if err := newConf.LoadFromPath(config); err != nil {
		return err
	}
	p := panel.NewClientV2(&newConf.ApiConfig)
	serverconfig, err := panel.GetServerConfig(p)
	if err != nil {
		log.WithField("err", err).Error("failed to get server configuration")
		return err
	}

	newCore := core.New(newConf, p)
	// Reattach reload channel
	newCore.ReloadCh = oldReloadCh
	if err := newCore.Start(serverconfig); err != nil {
		return err
	}
	newNodes, err := node.New(newCore, newConf, serverconfig)
	if err != nil {
		return err
	}

	newTunnelCtrl := node.NewTunnelController(p, newConf.ApiConfig.ServerId, newConf)
	var startWG sync.WaitGroup
	var nodesStartErr error
	startWG.Add(2)
	go func() {
		defer startWG.Done()
		nodesStartErr = newNodes.Start()
	}()
	go func() {
		defer startWG.Done()
		if tErr := newTunnelCtrl.Start(); tErr != nil {
			log.WithField("err", tErr).Warn("Failed to restart tunnel controller on reload")
		}
	}()
	startWG.Wait()
	if nodesStartErr != nil {
		_ = newTunnelCtrl.Close()
		return nodesStartErr
	}

	*nodes = newNodes
	*xcore = newCore
	*tunnelCtrl = newTunnelCtrl

	log.Infof("%d nodes reloaded successfully", serverconfig.Data.Total)
	runtime.GC()
	return nil
}

func cleanupLegacyTunnelProcess() {
	pidPath := "/var/run/archnets-tunnel.pid"
	if pidBytes, err := os.ReadFile(pidPath); err == nil {
		cleanStr := strings.TrimSpace(string(pidBytes))
		if pid, err := strconv.Atoi(cleanStr); err == nil && pid > 1 && pid != os.Getpid() {
			if proc, err := os.FindProcess(pid); err == nil {
				_ = proc.Kill()
				log.WithField("pid", pid).Info("Terminated legacy standalone tunnel process from PID file")
			}
		}
		_ = os.Remove(pidPath)
	}
}
