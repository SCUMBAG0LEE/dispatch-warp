package main

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

type IPBoundEndpoint struct {
	dst netip.AddrPort
	src netip.AddrPort
}

func (e *IPBoundEndpoint) ClearSrc() {
	e.src = netip.AddrPort{}
}

func (e *IPBoundEndpoint) SrcToString() string {
	return e.src.String()
}

func (e *IPBoundEndpoint) DstToString() string {
	return e.dst.String()
}

func (e *IPBoundEndpoint) DstToBytes() []byte {
	ip := e.dst.Addr().AsSlice()
	port := e.dst.Port()
	b := make([]byte, len(ip)+2)
	copy(b, ip)
	binary.BigEndian.PutUint16(b[len(ip):], port)
	return b
}

func (e *IPBoundEndpoint) DstIP() netip.Addr {
	return e.dst.Addr()
}

func (e *IPBoundEndpoint) SrcIP() netip.Addr {
	return e.src.Addr()
}

type IPBoundBind struct {
	mu        sync.Mutex
	localIPv4 net.IP
	localIPv6 net.IP
	ipv4Conn  *net.UDPConn
	ipv6Conn  *net.UDPConn
}

func NewIPBoundBind(localIPv4, localIPv6 net.IP) *IPBoundBind {
	return &IPBoundBind{
		localIPv4: localIPv4,
		localIPv6: localIPv6,
	}
}

func (b *IPBoundBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.ipv4Conn != nil || b.ipv6Conn != nil {
		return nil, 0, errors.New("already open")
	}

	var actualPortVal int

	if len(b.localIPv4) > 0 {
		addr := &net.UDPAddr{IP: b.localIPv4, Port: int(port)}
		b.ipv4Conn, err = net.ListenUDP("udp4", addr)
		if err != nil {
			return nil, 0, err
		}
		loc := b.ipv4Conn.LocalAddr().(*net.UDPAddr)
		actualPortVal = loc.Port
	}

	if len(b.localIPv6) > 0 {
		p := int(port)
		if p == 0 && actualPortVal > 0 {
			p = actualPortVal
		}
		addr := &net.UDPAddr{IP: b.localIPv6, Port: p}
		b.ipv6Conn, err = net.ListenUDP("udp6", addr)
		if err != nil {
			if b.ipv4Conn != nil {
				b.ipv4Conn.Close()
				b.ipv4Conn = nil
			}
			return nil, 0, err
		}
		if actualPortVal == 0 {
			loc := b.ipv6Conn.LocalAddr().(*net.UDPAddr)
			actualPortVal = loc.Port
		}
	}

	if b.ipv4Conn == nil && b.ipv6Conn == nil {
		return nil, 0, errors.New("no local addresses configured for bind")
	}

	fns = make([]conn.ReceiveFunc, 0, 2)
	if b.ipv4Conn != nil {
		fns = append(fns, b.makeReceiveFunc(b.ipv4Conn))
	}
	if b.ipv6Conn != nil {
		fns = append(fns, b.makeReceiveFunc(b.ipv6Conn))
	}

	return fns, uint16(actualPortVal), nil
}

func (b *IPBoundBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	var errs []error
	if b.ipv4Conn != nil {
		if err := b.ipv4Conn.Close(); err != nil {
			errs = append(errs, err)
		}
		b.ipv4Conn = nil
	}
	if b.ipv6Conn != nil {
		if err := b.ipv6Conn.Close(); err != nil {
			errs = append(errs, err)
		}
		b.ipv6Conn = nil
	}

	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

func (b *IPBoundBind) SetMark(mark uint32) error {
	return nil
}

func (b *IPBoundBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addrPort, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &IPBoundEndpoint{dst: addrPort}, nil
}

func (b *IPBoundBind) BatchSize() int {
	return 1
}

func (b *IPBoundBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	ipv4 := b.ipv4Conn
	ipv6 := b.ipv6Conn
	b.mu.Unlock()

	e, ok := ep.(*IPBoundEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}

	dstUDPAddr := net.UDPAddrFromAddrPort(e.dst)

	if e.dst.Addr().Is4() {
		if ipv4 == nil {
			return net.ErrClosed
		}
		for _, buf := range bufs {
			if _, err := ipv4.WriteTo(buf, dstUDPAddr); err != nil {
				return err
			}
		}
	} else {
		if ipv6 == nil {
			return net.ErrClosed
		}
		for _, buf := range bufs {
			if _, err := ipv6.WriteTo(buf, dstUDPAddr); err != nil {
				return err
			}
		}
	}
	return nil
}

func (b *IPBoundBind) makeReceiveFunc(udpConn *net.UDPConn) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		buf := packets[0]
		n, raddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			return 0, err
		}
		sizes[0] = n

		loc := udpConn.LocalAddr().(*net.UDPAddr)
		dstIP, _ := netip.ParseAddr(loc.IP.String())

		raddrPort, err := netip.ParseAddrPort(raddr.String())
		if err != nil {
			return 0, err
		}

		eps[0] = &IPBoundEndpoint{
			dst: raddrPort,
			src: netip.AddrPortFrom(dstIP, uint16(loc.Port)),
		}
		return 1, nil
	}
}
