package main

import (
	"context"
	"encoding/json"
	"log"
	"net"
	"os"
	"time"
)

var DisableLogging bool
var CustomResolver *net.Resolver

type Config struct {
	ListenAddress  string            `json:"listen_address"`
	ListenPort     int               `json:"listen_port"`
	DisableLogging bool              `json:"disable_logging"`
	DnsServer      string            `json:"dns_server"`
	LBMode         string            `json:"lb_mode"`
	Interfaces     []InterfaceConfig `json:"interfaces"`
}

type InterfaceConfig struct {
	Name        string     `json:"name"`
	BindAddress string     `json:"bind_address"`
	Weight      int        `json:"weight"`
	Warp        WarpConfig `json:"warp"`
}

type WarpConfig struct {
	Enabled       bool   `json:"enabled"`
	Mode          string `json:"mode"`           // "system", "mixed", "gvisor", "auto"
	PrivateKey    string `json:"private_key"`
	PeerPublicKey string `json:"peer_public_key"`
	PeerEndpoint  string `json:"peer_endpoint"`
	LocalAddrV4   string `json:"local_address_v4"`
	LocalAddrV6   string `json:"local_address_v6"`
	InterfaceName string `json:"interface_name"` // optional, e.g. "wg-warp"
	MTU           int    `json:"mtu"`            // optional, default 1280
}

func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Apply default values
	if cfg.ListenAddress == "" {
		cfg.ListenAddress = "127.0.0.1"
	}
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 1080
	}
	if cfg.LBMode == "" {
		cfg.LBMode = "manual"
	}

	for i := range cfg.Interfaces {
		if cfg.Interfaces[i].Weight <= 0 {
			cfg.Interfaces[i].Weight = 1
		}
		if cfg.Interfaces[i].Warp.Enabled && cfg.Interfaces[i].Warp.MTU <= 0 {
			cfg.Interfaces[i].Warp.MTU = 1280
		}
	}

	DisableLogging = cfg.DisableLogging
	if cfg.DnsServer != "" {
		// Ensure port is set, default to 53
		serverAddr := cfg.DnsServer
		if _, _, err := net.SplitHostPort(serverAddr); err != nil {
			serverAddr = net.JoinHostPort(serverAddr, "53")
		}
		CustomResolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 2 * time.Second}
				return d.DialContext(ctx, "udp", serverAddr)
			},
		}
	}

	return &cfg, nil
}

func logPrintf(format string, v ...interface{}) {
	if !DisableLogging {
		log.Printf(format, v...)
	}
}


