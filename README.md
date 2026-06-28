# dispatch-warp

A SOCKS proxy written in Go that balances traffic between multiple network interfaces, featuring optional userspace Cloudflare Warp (WireGuard) pairing.

*Works on Windows, macOS, and Linux.*

This is a Go-based rewrite and upgrade of [dispatch-proxy](https://github.com/alexkirsz/dispatch-proxy) (originally written in CoffeeScript/Rust).

## Key Features

- **Multi-WAN Load Balancing**: Distribute TCP/UDP traffic across multiple network adapters using a Weighted Round-Robin (WRR) algorithm. Supports specifying adapters via **local IP address** or **interface name** (e.g. `eth0`, `Ethernet`, `Wi-Fi`).
- **Active Health Checks & Auto-Failover**: Background health checker polls each interface's internet connectivity every 10 seconds. Inactive/unplugged interfaces are temporarily bypassed and automatically restored once they recover.
- **Userspace Cloudflare Warp (WireGuard)**: Route traffic through Cloudflare Warp in userspace using `wireguard-go` and `netstack`.
- **IP-Lock Routing**: Binds Warp UDP traffic directly to a physical adapter's local IP address, forcing the OS to route VPN traffic via that specific interface without administrative/root-level routing table changes.
- **Zero-Allocation Data Transfer**: Uses `sync.Pool` buffer reuse to ensure maximum throughput with minimal garbage collection overhead.
- **SOCKS4, SOCKS4a, and SOCKS5 Support**: Drop-in compatibility with legacy clients and download managers.
- **Config-Driven or CLI-Driven**: Run using a flexible `config.json` file or pass interface IPs/names directly via CLI arguments.

### Configuration Options

- **`listen_address` / `listen_port`**: The SOCKS/HTTP proxy host and port.
- **`dns_server`**: A custom UDP DNS server (e.g. `1.1.1.1:53` or `[2606:4700:4700::1111]:53`) to prevent DNS leaks and bypass the host OS resolver. Includes a built-in 5-minute memory cache to dramatically accelerate page load times. Supports both IPv4 and IPv6 over standard UDP. (Note: DoH/DoT are not supported natively).
- **`lb_mode`**: The load balancing algorithm:
  - `"manual"` (Default): Strictly respects the static `weight` values defined below (e.g. 70% traffic to Ethernet, 30% to Wi-Fi).
  - `"auto"`: Engages **Dynamic Latency-Aware Load Balancing (DLALB)**. It continuously benchmarks the exact ping of each interface and automatically scales weights inversely to latency. If Wi-Fi lags, its weight dynamically drops, keeping your download speed maxed out while preventing bufferbloat bottlenecks.
- **`interfaces`**: A list of adapters to route traffic through.
  - **`bind_address`**: The exact IP of the interface you want to use.
  - **`weight`**: The static ratio of traffic this interface should handle (used in `manual` mode).

#### Warp Options
- **`mode`**: Choose how WireGuard runs:
  - `"system"`: Native high-performance OS routing (requires Administrator/Root).
  - `"mixed"`: Hybrid mode combining OS tunneling with userspace networking.
  - `"gvisor"`: 100% pure userspace routing (no privileges required, extremely portable).
  - `"auto"` (Default): Tries `system` first, and gracefully falls back to `gvisor` if it lacks permissions.

> [!NOTE]
> **Windows System Mode (`wintun.dll`):** To run in native `system` mode on Windows (requiring Admin privileges), you must download the official `wintun.dll` from [wintun.net](https://www.wintun.net/) and place it in the same directory as the compiled `dispatch.exe` binary (or inside your system's `%PATH%`). If `wintun.dll` is missing, the proxy will print a warning and automatically fall back to userspace `gvisor` mode.

---

## Installation

### Option 1: Prebuilt Binaries (Recommended)

You can download the latest precompiled binaries for Windows, macOS, and Linux directly from the [GitHub Releases](https://github.com/SCUMBAG0LEE/dispatch-warp/releases/latest) page.

Since the filenames do not contain version numbers, you can always fetch the absolute latest version programmatically using GitHub's `latest` URL routing:
- **Windows**: `https://github.com/SCUMBAG0LEE/dispatch-warp/releases/latest/download/dispatch-warp-windows-amd64.exe`
- **Linux**: `https://github.com/SCUMBAG0LEE/dispatch-warp/releases/latest/download/dispatch-warp-linux-amd64`
- **macOS**: `https://github.com/SCUMBAG0LEE/dispatch-warp/releases/latest/download/dispatch-warp-darwin-amd64`

### Option 2: Build from Source

Ensure you have [Go 1.26.3 or later](https://go.dev/) installed.

```bash
git clone https://github.com/SCUMBAG0LEE/dispatch-warp.git
cd dispatch-warp
go mod tidy

# On Windows:
build.bat

# On Linux/macOS:
chmod +x build.sh
./build.sh
```

This will automatically compile the binary into the `build/` directory.

---

## Usage

```
A SOCKS proxy that balances traffic between network interfaces, with optional Warp pairing.

Usage: dispatch <COMMAND>

Commands:
  list   Lists all available network interfaces
  start  Starts the SOCKS proxy server
  help   Print this message

Options:
  -h, --help     Print help
```

### 1. List Available Interfaces

Find the local IP addresses of the adapters you want to bundle:
```bash
$ dispatch list

Available network interfaces:
- Name: Ethernet
  Address: 192.168.1.100/24
- Name: Wi-Fi
  Address: 192.168.1.101/24
```

### 2. Start the Server

#### Option A: Using `config.json` (Recommended for Warp)

Create a `config.json` in the working directory:
```json
{
  "listen_address": "127.0.0.1",
  "listen_port": 1080,
  "disable_logging": false,
  "dns_server": "1.1.1.1:53",
  "lb_mode": "manual",
  "interfaces": [
    {
      "name": "Ethernet",
      "bind_address": "192.168.1.100",
      "weight": 7,
      "warp": {
        "enabled": false
      }
    },
    {
      "name": "Wi-Fi Warp",
      "bind_address": "192.168.1.101",
      "weight": 3,
      "warp": {
        "enabled": true,
        "mode": "auto",
        "private_key": "YOUR_WARP_PRIVATE_KEY",
        "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
        "peer_endpoint": "engage.cloudflareclient.com:2408",
        "local_address_v4": "172.16.0.2/32",
        "local_address_v6": "2606:4700:110:8f83:6e63:b3e4:6b39:d475/128",
        "interface_name": "wg-warp",
        "mtu": 1280
      }
    }
  ]
```

#### Mapping to `wgcf` Profiles
If you use [wgcf](https://github.com/ViRb3/wgcf) to generate your Warp credentials, you can map the parameters from `wgcf-profile.conf` directly to your `config.json` configuration file:
- **`private_key`**: Matches the `PrivateKey` field inside `[Interface]`.
- **`peer_public_key`**: Matches the `PublicKey` field inside `[Peer]`.
- **`peer_endpoint`**: Matches the `Endpoint` field inside `[Peer]` (e.g. `engage.cloudflareclient.com:2408`).
- **`local_address_v4` & `local_address_v6`**: Match the separate IPv4 and IPv6 addresses listed in the `Address` field inside `[Interface]`.
- **`mtu`**: Matches the `MTU` field inside `[Interface]` (defaults to `1280`).



Run the server (it automatically looks for `config.json` if no arguments are provided):
```bash
$ dispatch start
```

Or specify a custom configuration file:
```bash
$ dispatch start --config my_custom_config.json
```

#### Option B: Using Command Line Arguments (Direct Routing Only)

Provide the interface IP addresses directly to dispatch to (matching the original project syntax):
```bash
$ dispatch start 192.168.1.100/7 192.168.1.101/3
```
This distributes incoming connections:
- 7 out of 10 times to `192.168.1.100` (Ethernet)
- 3 out of 10 times to `192.168.1.101` (Wi-Fi)

You can customize the listener address and port using `--ip` and `--port`:
```bash
$ dispatch start --ip 0.0.0.0 --port 8080 192.168.1.100/1 192.168.1.101/1
```

---

## License

This project is dual-licensed under the [MIT License](LICENSE-MIT) and the [Apache License 2.0](LICENSE-APACHE). You may choose either license for your purposes.
