package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"runtime"
	"strconv"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func CreateWarpTunnel(
	mode string,
	privateKeyB64 string,
	peerPublicKeyB64 string,
	peerEndpoint string,
	localIPv4CIDR string,
	localIPv6CIDR string,
	physicalIPv4 net.IP,
	physicalIPv6 net.IP,
	interfaceName string,
	mtu int,
) (*netstack.Net, *device.Device, net.IP, string, error) {
	if mode == "" {
		mode = "auto"
	}
	if mtu <= 0 {
		mtu = 1280
	}

	// Resolve peer endpoint hostname if it's not a raw IP address
	host, port, err := net.SplitHostPort(peerEndpoint)
	if err == nil {
		if parsedIP := net.ParseIP(host); parsedIP == nil {
			ips, err := net.LookupIP(host)
			if err == nil && len(ips) > 0 {
				var resolvedIP net.IP
				for _, ipAddr := range ips {
					if ipAddr.To4() != nil {
						resolvedIP = ipAddr
						break
					}
				}
				if resolvedIP == nil {
					resolvedIP = ips[0]
				}
				peerEndpoint = net.JoinHostPort(resolvedIP.String(), port)
			}
		}
	}

	attemptedMode := mode
	if mode == "auto" {
		attemptedMode = "system"
	}

	if attemptedMode == "system" || attemptedMode == "mixed" {
		dev, systemIP, err := createSystemWarpTunnel(
			privateKeyB64,
			peerPublicKeyB64,
			peerEndpoint,
			localIPv4CIDR,
			localIPv6CIDR,
			physicalIPv4,
			physicalIPv6,
			interfaceName,
			mtu,
		)
		if err == nil {
			return nil, dev, systemIP, "system", nil
		}

		logPrintf("System-level Warp tunnel setup failed: %v", err)
		if mode == "system" {
			return nil, nil, nil, "", err
		}

		logPrintf("System mode failed. Trying fallback tunnel mode...")
		attemptedMode = "gvisor"
	}

	if attemptedMode == "gvisor" || mode == "mixed" {
		tnet, dev, err := createGvisorWarpTunnel(
			privateKeyB64,
			peerPublicKeyB64,
			peerEndpoint,
			localIPv4CIDR,
			localIPv6CIDR,
			physicalIPv4,
			physicalIPv6,
			mtu,
		)
		if err != nil {
			return nil, nil, nil, "", err
		}
		return tnet, dev, nil, "gvisor", nil
	}

	return nil, nil, nil, "", fmt.Errorf("unknown Warp mode: %s", mode)
}

func createSystemWarpTunnel(
	privateKeyB64 string,
	peerPublicKeyB64 string,
	peerEndpoint string,
	localIPv4CIDR string,
	localIPv6CIDR string,
	physicalIPv4 net.IP,
	physicalIPv6 net.IP,
	interfaceName string,
	mtu int,
) (*device.Device, net.IP, error) {
	if interfaceName == "" {
		interfaceName = "wg-warp"
	}

	tunDev, err := tun.CreateTUN(interfaceName, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create system TUN device %q: %w", interfaceName, err)
	}

	actualName, err := tunDev.Name()
	if err != nil {
		actualName = interfaceName
	}

	err = configureSystemTUN(actualName, localIPv4CIDR, localIPv6CIDR, mtu)
	if err != nil {
		tunDev.Close()
		return nil, nil, fmt.Errorf("failed to configure system TUN addresses: %w", err)
	}

	privHex, err := base64ToHex(privateKeyB64)
	if err != nil {
		tunDev.Close()
		return nil, nil, err
	}
	pubHex, err := base64ToHex(peerPublicKeyB64)
	if err != nil {
		tunDev.Close()
		return nil, nil, err
	}

	bind := NewIPBoundBind(physicalIPv4, physicalIPv6)
	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(tunDev, bind, logger)

	ipcConf := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint=%s\n",
		privHex, pubHex, peerEndpoint)

	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to configure wireguard IPC: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to bring up wireguard device: %w", err)
	}

	var systemIP net.IP
	if localIPv4CIDR != "" {
		systemIP = parseIPFromCIDR(localIPv4CIDR)
	} else if localIPv6CIDR != "" {
		systemIP = parseIPFromCIDR(localIPv6CIDR)
	}

	logPrintf("Established system-level Warp tunnel %s (IP=%v, MTU=%d) over physical IP: IPv4=%v, IPv6=%v", actualName, systemIP, mtu, physicalIPv4, physicalIPv6)
	return dev, systemIP, nil
}

func createGvisorWarpTunnel(
	privateKeyB64 string,
	peerPublicKeyB64 string,
	peerEndpoint string,
	localIPv4CIDR string,
	localIPv6CIDR string,
	physicalIPv4 net.IP,
	physicalIPv6 net.IP,
	mtu int,
) (*netstack.Net, *device.Device, error) {
	var localAddrs []netip.Addr
	if localIPv4CIDR != "" {
		prefix, err := netip.ParsePrefix(localIPv4CIDR)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local IPv4 CIDR: %w", err)
		}
		localAddrs = append(localAddrs, prefix.Addr())
	}
	if localIPv6CIDR != "" {
		prefix, err := netip.ParsePrefix(localIPv6CIDR)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid local IPv6 CIDR: %w", err)
		}
		localAddrs = append(localAddrs, prefix.Addr())
	}

	dnsServers := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	tunDevice, tnet, err := netstack.CreateNetTUN(localAddrs, dnsServers, mtu)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create net TUN: %w", err)
	}

	privHex, err := base64ToHex(privateKeyB64)
	if err != nil {
		return nil, nil, err
	}
	pubHex, err := base64ToHex(peerPublicKeyB64)
	if err != nil {
		return nil, nil, err
	}

	bind := NewIPBoundBind(physicalIPv4, physicalIPv6)
	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(tunDevice, bind, logger)

	ipcConf := fmt.Sprintf("private_key=%s\nreplace_peers=true\npublic_key=%s\nallowed_ip=0.0.0.0/0\nallowed_ip=::/0\nendpoint=%s\n",
		privHex, pubHex, peerEndpoint)

	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to configure wireguard IPC: %w", err)
	}

	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, nil, fmt.Errorf("failed to bring up wireguard device: %w", err)
	}

	logPrintf("Established userspace gVisor Warp tunnel (MTU=%d) over physical IP: IPv4=%v, IPv6=%v", mtu, physicalIPv4, physicalIPv6)
	return tnet, dev, nil
}

func configureSystemTUN(name, ipV4, ipV6 string, mtu int) error {
	mtuStr := strconv.Itoa(mtu)
	switch runtime.GOOS {
	case "linux":
		if ipV4 != "" {
			if err := exec.Command("ip", "addr", "add", ipV4, "dev", name).Run(); err != nil {
				return err
			}
		}
		if ipV6 != "" {
			if err := exec.Command("ip", "addr", "add", ipV6, "dev", name).Run(); err != nil {
				return err
			}
		}
		return exec.Command("ip", "link", "set", "mtu", mtuStr, "up", "dev", name).Run()
	case "darwin":
		if ipV4 != "" {
			ipOnly := parseIPFromCIDR(ipV4).String()
			if err := exec.Command("ifconfig", name, ipOnly, ipOnly, "netmask", "255.255.255.255", "mtu", mtuStr, "up").Run(); err != nil {
				return err
			}
		}
		if ipV6 != "" {
			ipOnly := parseIPFromCIDR(ipV6).String()
			if err := exec.Command("ifconfig", name, "inet6", "add", ipOnly, "prefixlen", "128").Run(); err != nil {
				return err
			}
		}
		return nil
	case "windows":
		if ipV4 != "" {
			ipOnly := parseIPFromCIDR(ipV4).String()
			if err := exec.Command("netsh", "interface", "ipv4", "set", "address", "name="+name, "source=static", "address="+ipOnly, "mask=255.255.255.255").Run(); err != nil {
				return err
			}
			exec.Command("netsh", "interface", "ipv4", "set", "subinterface", name, "mtu="+mtuStr, "store=active").Run()
		}
		if ipV6 != "" {
			ipOnly := parseIPFromCIDR(ipV6).String()
			if err := exec.Command("netsh", "interface", "ipv6", "add", "address", "interface="+name, "address="+ipOnly).Run(); err != nil {
				return err
			}
			exec.Command("netsh", "interface", "ipv6", "set", "subinterface", name, "mtu="+mtuStr, "store=active").Run()
		}
		return nil
	}
	return fmt.Errorf("unsupported OS for system TUN: %s", runtime.GOOS)
}

func parseIPFromCIDR(cidr string) net.IP {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.ParseIP(cidr)
	}
	return ip
}

func base64ToHex(b64 string) (string, error) {
	dec, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(dec), nil
}
