package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		printHelp()
		os.Exit(1)
	}

	command := os.Args[1]
	switch command {
	case "list":
		listInterfaces()
	case "start":
		startServer(os.Args[2:])
	case "help":
		printHelp()
	default:
		fmt.Printf("Unknown command: %s\n", command)
		printHelp()
		os.Exit(1)
	}
}

func printHelp() {
	fmt.Println(`A SOCKS proxy that balances traffic between network interfaces, with optional Warp pairing.

Usage: dispatch <COMMAND>

Commands:
  list   Lists all available network interfaces
  start  Starts the SOCKS proxy server
  help   Print this message

Options:
  -h, --help     Print help

Run 'dispatch start -h' for more information on configuring the server.`)
}

func listInterfaces() {
	ifaces, err := net.Interfaces()
	if err != nil {
		log.Fatalf("Failed to list interfaces: %v", err)
	}

	fmt.Println("Available network interfaces:")
	for _, iface := range ifaces {
		// Filter out down or loopback interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		fmt.Printf("- Name: %s\n", iface.Name)
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			fmt.Printf("  Address: %s\n", ip.String())
		}
	}
}

func parseCLIAddress(arg string) (string, int, error) {
	parts := strings.Split(arg, "/")
	ipStr := parts[0]
	weight := 1
	if len(parts) > 1 {
		w, err := strconv.Atoi(parts[1])
		if err != nil {
			return "", 0, fmt.Errorf("invalid weight: %w", err)
		}
		weight = w
	}
	return ipStr, weight, nil
}

func startServer(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to config.json file")
	listenIP := fs.String("ip", "127.0.0.1", "Which IP to accept connections from")
	listenPort := fs.Int("port", 1080, "Which port to listen to for connections")
	fs.Parse(args)

	positionalArgs := fs.Args()

	var cfg *Config
	var err error

	if *configPath != "" {
		cfg, err = LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Failed to load config: %v", err)
		}
	} else if len(positionalArgs) > 0 {
		cfg = &Config{
			ListenAddress: *listenIP,
			ListenPort:    *listenPort,
		}
		for _, arg := range positionalArgs {
			ipStr, weight, err := parseCLIAddress(arg)
			if err != nil {
				log.Fatalf("Invalid address argument: %v", err)
			}
			cfg.Interfaces = append(cfg.Interfaces, InterfaceConfig{
				Name:        ipStr,
				BindAddress: ipStr,
				Weight:      weight,
			})
		}
	} else {
		// Fallback: check if local config.json exists in CWD
		path := "config.json"
		if _, err := os.Stat(path); err != nil {
			// If not found in CWD, check in the executable's directory
			if execPath, execErr := os.Executable(); execErr == nil {
				pathInExecDir := filepath.Join(filepath.Dir(execPath), "config.json")
				if _, statErr := os.Stat(pathInExecDir); statErr == nil {
					path = pathInExecDir
				}
			}
		}

		if _, err := os.Stat(path); err == nil {
			log.Printf("No arguments provided, loading config from %s...", path)
			cfg, err = LoadConfig(path)
			if err != nil {
				log.Fatalf("Failed to load config file: %v", err)
			}
		} else {
			log.Fatal("Error: No interfaces specified and config.json not found in current directory or executable directory.\nRun 'dispatch help' or 'dispatch start -h' for usage.")
		}
	}

	var routes []*InterfaceRoute

	for _, iface := range cfg.Interfaces {
		route := &InterfaceRoute{
			Name:   iface.Name,
			Weight: iface.Weight,
		}

		var bindIPv4, bindIPv6 net.IP
		if iface.BindAddress != "" {
			parsedIP := net.ParseIP(iface.BindAddress)
			if parsedIP != nil {
				if parsedIP.To4() != nil {
					bindIPv4 = parsedIP
				} else {
					bindIPv6 = parsedIP
				}
			} else {
				// Treat as interface name
				netIface, err := net.InterfaceByName(iface.BindAddress)
				if err != nil {
					log.Fatalf("Failed to find interface by name or IP %q: %v", iface.BindAddress, err)
				}
				addrs, err := netIface.Addrs()
				if err != nil {
					log.Fatalf("Failed to get addresses for interface %q: %v", iface.BindAddress, err)
				}
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
						continue
					}
					if ip.To4() != nil {
						if bindIPv4 == nil {
							bindIPv4 = ip
						}
					} else {
						if bindIPv6 == nil {
							bindIPv6 = ip
						}
					}
				}
				if bindIPv4 == nil && bindIPv6 == nil {
					log.Fatalf("No valid IP addresses found for interface %q", iface.BindAddress)
				}
			}
		}

		route.BindIPv4 = bindIPv4
		route.BindIPv6 = bindIPv6

		if iface.Warp.Enabled {
			route.Type = OutboundWarp
			tnet, warpDev, systemIP, actualMode, err := CreateWarpTunnel(
				iface.Warp.Mode,
				iface.Warp.PrivateKey,
				iface.Warp.PeerPublicKey,
				iface.Warp.PeerEndpoint,
				iface.Warp.LocalAddrV4,
				iface.Warp.LocalAddrV6,
				bindIPv4,
				bindIPv6,
				iface.Warp.InterfaceName,
				iface.Warp.MTU,
			)
			if err != nil {
				log.Fatalf("Failed to create Warp tunnel for interface %s: %v", iface.Name, err)
			}
			route.WarpNet = tnet
			route.WarpDev = warpDev
			route.WarpSystemIP = systemIP
			log.Printf("Route %s initialized in %s Warp mode", iface.Name, actualMode)
		} else {
			route.Type = OutboundDirect
		}

		routes = append(routes, route)
	}

	dispatcher := NewDispatcher(routes, cfg.LBMode)
	dispatcher.StartHealthChecks(context.Background(), 10*time.Second)

	server := NewSocksServer(net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.ListenPort)), dispatcher)

	// Handle graceful shutdown signals
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("Shutting down proxy server gracefully...")
		server.Close()
		dispatcher.Close()
		log.Println("Shutdown complete.")
		os.Exit(0)
	}()

	if err := server.ListenAndServe(); err != nil {
		if !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatalf("Server failed: %v", err)
		}
	}
}
