package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, 64*1024) // 64KB buffer
	},
}

type dnsCacheEntry struct {
	ips       []net.IPAddr
	expiresAt time.Time
}

var (
	dnsCacheMu sync.RWMutex
	dnsCache   = make(map[string]dnsCacheEntry)
)

func cachedLookupIPAddr(ctx context.Context, resolver *net.Resolver, host string) ([]net.IPAddr, error) {
	dnsCacheMu.RLock()
	entry, found := dnsCache[host]
	dnsCacheMu.RUnlock()

	if found && time.Now().Before(entry.expiresAt) {
		return entry.ips, nil
	}

	ips, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ips) > 0 {
		dnsCacheMu.Lock()
		dnsCache[host] = dnsCacheEntry{
			ips:       ips,
			expiresAt: time.Now().Add(5 * time.Minute),
		}
		dnsCacheMu.Unlock()
	}
	return ips, err
}

func invalidateDNSCache(host string) {
	dnsCacheMu.Lock()
	delete(dnsCache, host)
	dnsCacheMu.Unlock()
}

type halfCloser interface {
	CloseWrite() error
}

type SocksServer struct {
	listenAddr string
	dispatcher *Dispatcher
	listener   net.Listener
}

func NewSocksServer(listenAddr string, dispatcher *Dispatcher) *SocksServer {
	return &SocksServer{
		listenAddr: listenAddr,
		dispatcher: dispatcher,
	}
}

func (s *SocksServer) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	defer listener.Close()
	logPrintf("Proxy server (SOCKS + HTTP) listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logPrintf("Accept error: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *SocksServer) handleConnection(client net.Conn) {
	defer client.Close()

	// Read version/first byte to determine protocol
	var ver [1]byte
	if _, err := io.ReadFull(client, ver[:]); err != nil {
		return
	}

	if ver[0] == 0x05 {
		s.handleSocks5(client)
	} else if ver[0] == 0x04 {
		s.handleSocks4(client)
	} else {
		// Treat as HTTP/HTTPS proxy
		s.handleHttp(client, ver[0])
	}
}

func (s *SocksServer) handleSocks5(client net.Conn) {
	// Read NMETHODS
	var nmethods [1]byte
	if _, err := io.ReadFull(client, nmethods[:]); err != nil {
		return
	}

	// Read methods
	methods := make([]byte, nmethods[0])
	if _, err := io.ReadFull(client, methods); err != nil {
		return
	}

	supportsNoAuth := false
	for _, m := range methods {
		if m == 0x00 {
			supportsNoAuth = true
			break
		}
	}

	if !supportsNoAuth {
		client.Write([]byte{0x05, 0xff})
		return
	}

	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return
	}

	if header[1] != 0x01 { // CONNECT
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var destAddr string
	var destIP net.IP

	switch header[3] { // ATYP
	case 0x01: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(client, ip[:]); err != nil {
			return
		}
		destIP = net.IP(ip[:])
		destAddr = destIP.String()
	case 0x03: // Domain name
		var lenByte [1]byte
		if _, err := io.ReadFull(client, lenByte[:]); err != nil {
			return
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(client, domain); err != nil {
			return
		}
		destAddr = string(domain)
	case 0x04: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(client, ip[:]); err != nil {
			return
		}
		destIP = net.IP(ip[:])
		destAddr = "[" + destIP.String() + "]"
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(client, portBytes[:]); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes[:]))

	targetHostPort := net.JoinHostPort(destAddr, strconv.Itoa(port))

	var targetIP net.IP
	if destIP != nil {
		targetIP = destIP
	} else {
		var ips []net.IPAddr
		var err error
		resolver := CustomResolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err = cachedLookupIPAddr(context.Background(), resolver, destAddr)
		if err != nil || len(ips) == 0 {
			client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				targetIP = ip.IP
				break
			}
		}
		if targetIP == nil {
			targetIP = ips[0].IP
		}
	}

	isIPv6 := targetIP.To4() == nil
	route, err := s.dispatcher.SelectRoute(isIPv6)
	if err != nil {
		logPrintf("Route selection failed: %v", err)
		client.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	network := "tcp4"
	if isIPv6 {
		network = "tcp6"
	}

	remote, err := route.DialContext(dialCtx, network, net.JoinHostPort(targetIP.String(), strconv.Itoa(port)))
	if err != nil {
		logPrintf("Dial target %s from %s failed on interface %s: %v", targetHostPort, client.RemoteAddr(), route.Name, err)
		if destIP == nil {
			invalidateDNSCache(destAddr)
		}
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		remote.Close()
		return
	}

	logPrintf("Forwarded SOCKS5 request from %s to %s via %s", client.RemoteAddr(), targetHostPort, route.Name)
	s.pipe(client, remote)
}

func (s *SocksServer) handleSocks4(client net.Conn) {
	var header [7]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		return
	}

	cmd := header[0]
	if cmd != 0x01 {
		client.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
		return
	}

	port := int(binary.BigEndian.Uint16(header[1:3]))
	ipBytes := header[3:7]
	destIP := net.IP(ipBytes)

	var oneByte [1]byte
	for {
		if _, err := io.ReadFull(client, oneByte[:]); err != nil {
			return
		}
		if oneByte[0] == 0x00 {
			break
		}
	}

	var destAddr string
	isSocks4a := ipBytes[0] == 0 && ipBytes[1] == 0 && ipBytes[2] == 0 && ipBytes[3] != 0
	if isSocks4a {
		var domainBytes []byte
		for {
			if _, err := io.ReadFull(client, oneByte[:]); err != nil {
				return
			}
			if oneByte[0] == 0x00 {
				break
			}
			domainBytes = append(domainBytes, oneByte[0])
		}
		destAddr = string(domainBytes)
	} else {
		destAddr = destIP.String()
	}

	var targetIP net.IP
	if !isSocks4a {
		targetIP = destIP
	} else {
		var ips []net.IPAddr
		var err error
		resolver := CustomResolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err = cachedLookupIPAddr(context.Background(), resolver, destAddr)
		if err != nil || len(ips) == 0 {
			client.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
			return
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				targetIP = ip.IP
				break
			}
		}
		if targetIP == nil {
			targetIP = ips[0].IP
		}
	}

	isIPv6 := targetIP.To4() == nil
	route, err := s.dispatcher.SelectRoute(isIPv6)
	if err != nil {
		client.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	network := "tcp4"
	if isIPv6 {
		network = "tcp6"
	}

	remote, err := route.DialContext(dialCtx, network, net.JoinHostPort(targetIP.String(), strconv.Itoa(port)))
	if err != nil {
		logPrintf("SOCKS4 Dial target %s from %s failed on interface %s: %v", net.JoinHostPort(destAddr, strconv.Itoa(port)), client.RemoteAddr(), route.Name, err)
		if isSocks4a {
			invalidateDNSCache(destAddr)
		}
		client.Write([]byte{0x00, 0x5b, 0, 0, 0, 0, 0, 0})
		return
	}

	if _, err := client.Write([]byte{0x00, 0x5a, 0, 0, 0, 0, 0, 0}); err != nil {
		remote.Close()
		return
	}

	logPrintf("Forwarded SOCKS4 request from %s to %s via %s", client.RemoteAddr(), net.JoinHostPort(destAddr, strconv.Itoa(port)), route.Name)
	s.pipe(client, remote)
}

func (s *SocksServer) handleHttp(client net.Conn, firstByte byte) {
	reader := bufio.NewReader(io.MultiReader(bytes.NewReader([]byte{firstByte}), client))

	reqLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}

	parts := strings.Split(strings.TrimSpace(reqLine), " ")
	if len(parts) < 2 {
		return
	}
	method := parts[0]
	rawURL := parts[1]

	var hostHeader string
	var reqHeaders strings.Builder
	reqHeaders.WriteString(reqLine)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		reqHeaders.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			hostHeader = strings.TrimSpace(line[5:])
		}
	}

	var targetHost string
	var targetPort string

	if method == "CONNECT" {
		host, port, err := net.SplitHostPort(rawURL)
		if err == nil {
			targetHost = host
			targetPort = port
		} else {
			targetHost = rawURL
			targetPort = "443"
		}
	} else {
		if strings.HasPrefix(rawURL, "http://") {
			urlWithoutScheme := rawURL[7:]
			slashIdx := strings.Index(urlWithoutScheme, "/")
			var hostPort string
			if slashIdx == -1 {
				hostPort = urlWithoutScheme
			} else {
				hostPort = urlWithoutScheme[:slashIdx]
			}
			host, port, err := net.SplitHostPort(hostPort)
			if err == nil {
				targetHost = host
				targetPort = port
			} else {
				targetHost = hostPort
				targetPort = "80"
			}
		} else if strings.HasPrefix(rawURL, "https://") {
			urlWithoutScheme := rawURL[8:]
			slashIdx := strings.Index(urlWithoutScheme, "/")
			var hostPort string
			if slashIdx == -1 {
				hostPort = urlWithoutScheme
			} else {
				hostPort = urlWithoutScheme[:slashIdx]
			}
			host, port, err := net.SplitHostPort(hostPort)
			if err == nil {
				targetHost = host
				targetPort = port
			} else {
				targetHost = hostPort
				targetPort = "443"
			}
		} else if hostHeader != "" {
			host, port, err := net.SplitHostPort(hostHeader)
			if err == nil {
				targetHost = host
				targetPort = port
			} else {
				targetHost = hostHeader
				targetPort = "80"
			}
		} else {
			return
		}
	}

	var targetIP net.IP
	parsedIP := net.ParseIP(targetHost)
	if parsedIP != nil {
		targetIP = parsedIP
	} else {
		var ips []net.IPAddr
		var err error
		resolver := CustomResolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		ips, err = cachedLookupIPAddr(context.Background(), resolver, targetHost)
		if err != nil || len(ips) == 0 {
			return
		}
		for _, ip := range ips {
			if ip.IP.To4() != nil {
				targetIP = ip.IP
				break
			}
		}
		if targetIP == nil {
			targetIP = ips[0].IP
		}
	}

	isIPv6 := targetIP.To4() == nil
	route, err := s.dispatcher.SelectRoute(isIPv6)
	if err != nil {
		logPrintf("HTTP route selection failed: %v", err)
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	network := "tcp4"
	if isIPv6 {
		network = "tcp6"
	}

	portInt, _ := strconv.Atoi(targetPort)
	remote, err := route.DialContext(dialCtx, network, net.JoinHostPort(targetIP.String(), strconv.Itoa(portInt)))
	if err != nil {
		logPrintf("HTTP Dial target %s:%s from %s failed on interface %s: %v", targetHost, targetPort, client.RemoteAddr(), route.Name, err)
		if parsedIP == nil {
			invalidateDNSCache(targetHost)
		}
		if method == "CONNECT" {
			client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		}
		return
	}

	if method == "CONNECT" {
		_, err = client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
		if err != nil {
			remote.Close()
			return
		}
	} else {
		_, err = remote.Write([]byte(reqHeaders.String()))
		if err != nil {
			remote.Close()
			return
		}
	}

	if reader.Buffered() > 0 {
		bufferedData := make([]byte, reader.Buffered())
		reader.Read(bufferedData)
		_, err = remote.Write(bufferedData)
		if err != nil {
			remote.Close()
			return
		}
	}

	logPrintf("HTTP Forwarded %s request from %s to %s:%s via %s", method, client.RemoteAddr(), targetHost, targetPort, route.Name)
	s.pipe(client, remote)
}

func (s *SocksServer) pipe(src, dst net.Conn) {
	defer src.Close()
	defer dst.Close()

	// Enable TCP Keep-Alive
	if tcp, ok := src.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(3 * time.Minute)
	}
	if tcp, ok := dst.(*net.TCPConn); ok {
		tcp.SetKeepAlive(true)
		tcp.SetKeepAlivePeriod(3 * time.Minute)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		io.CopyBuffer(dst, src, buf)
		if hc, ok := dst.(halfCloser); ok {
			hc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		buf := bufferPool.Get().([]byte)
		defer bufferPool.Put(buf)
		io.CopyBuffer(src, dst, buf)
		if hc, ok := src.(halfCloser); ok {
			hc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (s *SocksServer) Close() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

