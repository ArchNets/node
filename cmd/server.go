package cmd

import (
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/core"
	"github.com/archnets/node/limiter"
	"github.com/archnets/node/node"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	config string
	watch  bool
)

var serverCommand = cobra.Command{
	Use:   "server",
	Short: "Run node server",
	Run:   serverHandle,
	Args:  cobra.NoArgs,
}

func init() {
	serverCommand.PersistentFlags().
		StringVarP(&config, "config", "c",
			"/etc/archnets/config.yml", "config file path")
	serverCommand.PersistentFlags().
		BoolVarP(&watch, "watch", "w",
			true, "watch file path change")
	command.AddCommand(&serverCommand)
}

func serverHandle(_ *cobra.Command, _ []string) {
	showVersion()
	c := conf.New()
	err := c.LoadFromPath(config)
	log.SetFormatter(&log.TextFormatter{
		DisableTimestamp: true,
		DisableQuote:     true,
		PadLevelText:     false,
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
	err = nodes.Start()
	if err != nil {
		log.WithField("err", err).Error("failed to start nodes")
		return
	}
	log.Infof("started %d nodes", serverconfig.Data.Total)
	if watch {
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
	}
	// clear memory
	runtime.GC()

	osSignals := make(chan os.Signal, 1)
	signal.Notify(osSignals, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-osSignals:
			nodes.Close()
			_ = xraycore.Close()
			return
		case <-reloadCh:
			log.Info("received reload signal, reloading configuration...")
			if err := reload(config, &nodes, &xraycore); err != nil {
				log.WithField("err", err).Error("reload failed")
			}
		}
	}
}

func reload(config string, nodes **node.Node, xcore **core.XrayCore) error {
	// Preserve old reload channel so new core continues to receive signals
	var oldReloadCh chan struct{}

	if *xcore != nil {
		oldReloadCh = (*xcore).ReloadCh
	}

	(*nodes).Close()
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
	if err := newNodes.Start(); err != nil {
		return err
	}

	*nodes = newNodes
	*xcore = newCore
	log.Infof("%d nodes reloaded successfully", serverconfig.Data.Total)
	runtime.GC()
	return nil
}
