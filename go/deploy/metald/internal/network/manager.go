package network

import (
	"log/slog"
	"sync"
	"time"

	"github.com/unkeyed/unkey/go/deploy/metald/internal/config"
)

// DefaultConfig returns default network configuration
func DefaultConfig() *Config {
	return &Config{ //nolint:exhaustruct // EnableIPv6 field uses zero value (false) which is appropriate for default config
		BridgeName:      "br-vms",
		BridgeIP:        "172.31.0.1/19",
		VMSubnet:        "172.31.0.0/19",
		DNSServers:      []string{"8.8.8.8", "8.8.4.4"},
		EnableRateLimit: true,
		RateLimitMbps:   1000, // 1000 Mbps default
	}
}

// NewManager creates a new network manager
func NewManager(logger *slog.Logger, netConfig *Config, mainConfig *config.NetworkConfig) (*Manager, error) {
	if netConfig == nil {
		netConfig = DefaultConfig()
	}

	logger = logger.With("component", "network-manager")
	logger.Info("creating network manager",
		slog.String("bridge_name", netConfig.BridgeName),
		slog.String("bridge_ip", netConfig.BridgeIP),
		slog.String("vm_subnet", netConfig.VMSubnet),
	)

	m := &Manager{ //nolint:exhaustruct // mu, bridgeCreated, and iptablesRules fields use appropriate zero values
		logger:     logger,
		config:     netConfig,
		idGen:      NewIDGenerator(),
		vmNetworks: make(map[string]*VMNetwork),
	}

	return m, nil
}

// Config holds network configuration
type Config struct {
	BridgeIP        string   // Default: "172.31.0.1/19"
	BridgeName      string   // Default: "br-vms"
	DNSServers      []string // Default: ["8.8.8.8", "8.8.4.4"]
	EnableIPv6      bool
	EnableRateLimit bool
	RateLimitMbps   int    // Per VM rate limit in Mbps
	VMSubnet        string // Default: "172.31.0.0/12"
}

type Manager struct {
	logger        *slog.Logger
	config        *Config
	portAllocator *PortAllocator
	idGen         *IDGenerator
	mu            sync.RWMutex
	vmNetworks    map[string]*VMNetwork

	bridgeMu       sync.RWMutex
	bridgeCreated  bool
	bridgeInitTime time.Time

	iptablesRules []string
}
