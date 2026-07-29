package core

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/archnets/node/api/panel"
	"github.com/archnets/node/common/task"
	"github.com/archnets/node/conf"
	"github.com/archnets/node/core/app/dispatcher"
	_ "github.com/archnets/node/core/distro/all"
	log "github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/proxyman"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/app/stats"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/routing"
	xraystats "github.com/xtls/xray-core/features/stats"
	coreConf "github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

type AddUsersParams struct {
	Tag   string
	Users []panel.UserInfo
	*panel.NodeInfo
}

type XrayCore struct {
	Config                      *conf.Conf
	Client                      *panel.ClientV2
	ReloadCh                    chan struct{}
	serverConfigMonitorPeriodic *task.Task
	access                      sync.Mutex
	Server                      *core.Instance
	users                       *UserMap
	ihm                         inbound.Manager
	ohm                         outbound.Manager
	dispatcher                  *dispatcher.DefaultDispatcher
	statsManager                xraystats.Manager
	outboundNames               []string
	wgMutex                     sync.Mutex
	wgOutbounds                 map[string]*WireguardOutbound
	wgFailures                  map[string]int
	wgEndpointIndex             map[string]int
	wgHandlerMissing            map[string]bool
	wgEscalationCount           map[string]int
	wgRecovering                map[string]bool
	wgWatchdogPeriodic          *task.Task
	wgWatchdogGroup             sync.WaitGroup
	watchdogCtx                 context.Context
	watchdogCancel              context.CancelFunc
}

type UserMap struct {
	uidMap  map[string]int
	mapLock sync.RWMutex
}

func New(config *conf.Conf, client *panel.ClientV2) *XrayCore {
	ctx, cancel := context.WithCancel(context.Background())
	core := &XrayCore{
		Config: config,
		Client: client,
		users: &UserMap{
			uidMap: make(map[string]int),
		},
		watchdogCtx:       ctx,
		watchdogCancel:    cancel,
		wgOutbounds:       make(map[string]*WireguardOutbound),
		wgFailures:        make(map[string]int),
		wgEndpointIndex:   make(map[string]int),
		wgHandlerMissing:  make(map[string]bool),
		wgEscalationCount: make(map[string]int),
		wgRecovering:      make(map[string]bool),
	}
	return core
}

func (v *XrayCore) Start(serverconfig *panel.ServerConfigResponse) error {
	v.access.Lock()
	defer v.access.Unlock()

	// Custom config
	dnsConfig, outBoundConfig, routeConfig, wgOutbounds, err := GetCustomConfig(serverconfig)
	if err != nil {
		log.WithField("err", err).Panic("failed to build custom config")
	}

	// What changed: Initialized/re-initialized WireGuard/WARP watchdog under dedicated wgMutex.
	// Why: Ensures WARP and WireGuard outbounds are covered after every reload without racing or blocking.
	v.initWatchdog(wgOutbounds)

	v.Server = getCore(v.Config, dnsConfig, outBoundConfig, routeConfig, serverconfig)
	if err := v.Server.Start(); err != nil {
		return err
	}
	v.ihm = v.Server.GetFeature(inbound.ManagerType()).(inbound.Manager)
	v.ohm = v.Server.GetFeature(outbound.ManagerType()).(outbound.Manager)
	v.dispatcher = v.Server.GetFeature(routing.DispatcherType()).(*dispatcher.DefaultDispatcher)
	if sm := v.Server.GetFeature(xraystats.ManagerType()); sm != nil {
		v.statsManager = sm.(xraystats.Manager)
	}
	// Store outbound names for stats collection
	if serverconfig.Data.Outbound != nil {
		v.outboundNames = make([]string, 0, len(*serverconfig.Data.Outbound))
		for _, ob := range *serverconfig.Data.Outbound {
			v.outboundNames = append(v.outboundNames, ob.Name)
		}
	}
	v.startTasks(serverconfig)
	return nil
}

func (v *XrayCore) initWatchdog(wgOutbounds map[string]*WireguardOutbound) {
	v.wgMutex.Lock()
	defer v.wgMutex.Unlock()

	v.wgOutbounds = wgOutbounds
	if v.wgFailures == nil {
		v.wgFailures = make(map[string]int)
	}
	if v.wgEndpointIndex == nil {
		v.wgEndpointIndex = make(map[string]int)
	}
	if v.wgHandlerMissing == nil {
		v.wgHandlerMissing = make(map[string]bool)
	}
	if v.wgEscalationCount == nil {
		v.wgEscalationCount = make(map[string]int)
	}
	if v.wgRecovering == nil {
		v.wgRecovering = make(map[string]bool)
	}

	if v.wgWatchdogPeriodic != nil {
		v.wgWatchdogPeriodic.Close()
		v.wgWatchdogPeriodic = nil
	}

	if len(v.wgOutbounds) > 0 {
		v.wgWatchdogPeriodic = &task.Task{
			Interval: 20 * time.Second,
			Execute:  v.WireguardWatchdog,
		}
		_ = v.wgWatchdogPeriodic.Start(false)
		log.Infof("Started WireGuard watchdog task for %d outbounds (20s interval)", len(v.wgOutbounds))
	}
}

func (v *XrayCore) Close() error {
	v.access.Lock()
	defer v.access.Unlock()
	if v.watchdogCancel != nil {
		v.watchdogCancel()
	}
	if v.serverConfigMonitorPeriodic != nil {
		v.serverConfigMonitorPeriodic.Close()
	}

	v.wgMutex.Lock()
	if v.wgWatchdogPeriodic != nil {
		v.wgWatchdogPeriodic.Close()
		v.wgWatchdogPeriodic = nil
	}
	v.wgMutex.Unlock()
	v.wgWatchdogGroup.Wait()
	v.Config = nil
	v.ihm = nil
	v.ohm = nil
	v.dispatcher = nil
	if v.Server != nil {
		err := v.Server.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func getCore(c *conf.Conf, dnsConfig *dns.Config, outBoundConfig []*core.OutboundHandlerConfig, routeConfig *router.Config, serverconfig *panel.ServerConfigResponse) *core.Instance {
	// Log Config
	coreLogConfig := &coreConf.LogConfig{
		LogLevel:  c.LogConfig.Level,
		AccessLog: c.LogConfig.Access,
		ErrorLog:  c.LogConfig.Output,
	}
	// Inbound config
	var inBoundConfig []*core.InboundHandlerConfig

	// Policy config
	statsPolicy := serverconfig.Data.StatsPolicy
	if statsPolicy == nil {
		statsPolicy = &panel.StatsPolicy{
			InboundUplink:   true,
			InboundDownlink: true,
		}
	}

	levelPolicyConfig := &coreConf.Policy{
		StatsUserUplink:   true,
		StatsUserDownlink: true,
		Handshake:         proto.Uint32(4),
		ConnectionIdle:    proto.Uint32(30),
		UplinkOnly:        proto.Uint32(2),
		DownlinkOnly:      proto.Uint32(4),
		BufferSize:        proto.Int32(64),
	}
	corePolicyConfig := &coreConf.PolicyConfig{}
	corePolicyConfig.Levels = map[uint32]*coreConf.Policy{0: levelPolicyConfig}
	corePolicyConfig.System = &coreConf.SystemPolicy{
		StatsInboundUplink:    statsPolicy.InboundUplink,
		StatsInboundDownlink:  statsPolicy.InboundDownlink,
		StatsOutboundUplink:   statsPolicy.OutboundUplink,
		StatsOutboundDownlink: statsPolicy.OutboundDownlink,
	}
	policyConfig, _ := corePolicyConfig.Build()
	// Build Xray conf
	config := &core.Config{
		App: []*serial.TypedMessage{
			serial.ToTypedMessage(coreLogConfig.Build()),
			serial.ToTypedMessage(&dispatcher.Config{}),
			serial.ToTypedMessage(&stats.Config{}),
			serial.ToTypedMessage(&proxyman.InboundConfig{}),
			serial.ToTypedMessage(&proxyman.OutboundConfig{}),
			serial.ToTypedMessage(policyConfig),
			serial.ToTypedMessage(dnsConfig),
			serial.ToTypedMessage(routeConfig),
		},
		Inbound:  inBoundConfig,
		Outbound: outBoundConfig,
	}

	// Observatory for leastPing strategy
	if obs := serverconfig.Data.Observatory; obs != nil && len(obs.SubjectSelector) > 0 {
		obsConfig := &coreConf.ObservatoryConfig{
			SubjectSelector:   obs.SubjectSelector,
			ProbeURL:          obs.ProbeURL,
			EnableConcurrency: obs.EnableConcurrency,
		}
		if obs.ProbeInterval != "" {
			if err := obsConfig.ProbeInterval.UnmarshalJSON([]byte(`"` + obs.ProbeInterval + `"`)); err != nil {
				log.WithField("err", err).Warn("invalid observatory probe_interval, using default")
			}
		}
		if obsMsg, err := obsConfig.Build(); err == nil {
			config.App = append(config.App, serial.ToTypedMessage(obsMsg))
		} else {
			log.WithField("err", err).Warn("failed to build observatory config")
		}
	}

	// BurstObservatory for leastLoad strategy
	if bobs := serverconfig.Data.BurstObservatory; bobs != nil && len(bobs.SubjectSelector) > 0 {
		pingCfg := bobs.PingConfig
		if pingCfg == nil {
			pingCfg = &panel.PingConfig{
				Destination: "http://www.google.com/gen_204",
				Interval:    "30s",
				Timeout:     "10s",
				Sampling:    3,
			}
		}
		// Build as JSON and unmarshal since healthCheckSettings is unexported
		bobsJSON := map[string]interface{}{
			"subjectSelector": bobs.SubjectSelector,
			"pingConfig": map[string]interface{}{
				"destination":  pingCfg.Destination,
				"connectivity": pingCfg.Connectivity,
				"interval":     pingCfg.Interval,
				"timeout":      pingCfg.Timeout,
				"sampling":     pingCfg.Sampling,
			},
		}
		bobsBytes, _ := json.Marshal(bobsJSON)
		var bobsConfig coreConf.BurstObservatoryConfig
		if err := json.Unmarshal(bobsBytes, &bobsConfig); err == nil {
			if bobsMsg, err := bobsConfig.Build(); err == nil {
				config.App = append(config.App, serial.ToTypedMessage(bobsMsg))
			} else {
				log.WithField("err", err).Warn("failed to build burst observatory config")
			}
		} else {
			log.WithField("err", err).Warn("failed to unmarshal burst observatory config")
		}
	}
	server, err := core.New(config)
	if err != nil {
		log.WithField("err", err).Panic("failed to create instance")
	}
	return server
}

func (c *XrayCore) startTasks(serverconfig *panel.ServerConfigResponse) {
	// fetch node info task
	pullinverval := serverconfig.Data.PullInterval
	if pullinverval <= 0 {
		pullinverval = 60
	}
	c.serverConfigMonitorPeriodic = &task.Task{
		Interval: time.Duration(pullinverval) * time.Second,
		Execute:  c.ServerConfigMonitor,
	}
	_ = c.serverConfigMonitorPeriodic.Start(false)
}

func (c *XrayCore) ServerConfigMonitor() (err error) {
	newServerConfig, err := panel.GetServerConfig(c.Client)
	if err != nil {
		log.WithField("err", err).Error("failed to get server configuration")
		return nil
	}
	if newServerConfig != nil {
		log.Error("server configuration changed, restarting nodes...")
		// Non-blocking signal to avoid goroutine stuck when channel is full or nil
		if c.ReloadCh != nil {
			select {
			case c.ReloadCh <- struct{}{}:
			default:
			}
		}
	}
	return nil
}
