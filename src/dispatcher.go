package main

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type OutboundType int

const (
	OutboundDirect OutboundType = iota
	OutboundWarp
)

type InterfaceRoute struct {
	mu           sync.RWMutex
	Name         string
	Type         OutboundType
	BindIPv4     net.IP
	BindIPv6     net.IP
	Weight       int
	WarpNet      *netstack.Net
	WarpSystemIP  net.IP
	WarpDev       *device.Device
	Active        bool
	Latency       time.Duration
	CurrentWeight int
}

func (r *InterfaceRoute) SetLatency(lat time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Latency = lat
	
	latMs := lat.Milliseconds()
	if latMs <= 0 {
		latMs = 1
	}
	// Calculate inverse-proportional weight (e.g. 10ms = 100 weight, 100ms = 10 weight)
	weight := int(1000 / latMs)
	if weight < 1 {
		weight = 1
	}
	r.CurrentWeight = weight
}

func (r *InterfaceRoute) GetLatency() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Latency
}

func (r *InterfaceRoute) IsActive() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.Active
}

func (r *InterfaceRoute) SetActive(active bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Active = active
}

type Dispatcher struct {
	mu         sync.Mutex
	routesIPv4 []*InterfaceRoute
	routesIPv6 []*InterfaceRoute
	idxIPv4    int
	countIPv4  int
	idxIPv6    int
	countIPv6  int
	lbMode     string
}

func NewDispatcher(routes []*InterfaceRoute, lbMode string) *Dispatcher {
	var r4, r6 []*InterfaceRoute
	for _, r := range routes {
		r.Active = true // Default to active
		if r.Type == OutboundWarp {
			r4 = append(r4, r)
			r6 = append(r6, r)
		} else {
			if len(r.BindIPv4) > 0 {
				r4 = append(r4, r)
			}
			if len(r.BindIPv6) > 0 {
				r6 = append(r6, r)
			}
		}
	}
	return &Dispatcher{
		routesIPv4: r4,
		routesIPv6: r6,
		lbMode:     lbMode,
	}
}

func (d *Dispatcher) SelectRoute(isIPv6 bool) (*InterfaceRoute, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	routes := d.routesIPv4
	idx := &d.idxIPv4
	count := &d.countIPv4
	if isIPv6 {
		routes = d.routesIPv6
		idx = &d.idxIPv6
		count = &d.countIPv6
	}

	if len(routes) == 0 {
		return nil, fmt.Errorf("no interfaces available")
	}

	startIdx := *idx
	for {
		route := routes[*idx]

		// Determine effective weight based on lb_mode
		rWeight := route.Weight
		if d.lbMode == "auto" {
			route.mu.RLock()
			if route.CurrentWeight > 0 {
				rWeight = route.CurrentWeight
			}
			route.mu.RUnlock()
		}

		// Advance WRR state
		*count++
		if *count >= rWeight {
			*count = 0
			*idx = (*idx + 1) % len(routes)
		}

		if route.IsActive() {
			return route, nil
		}

		// Loop detection: if we check all routes and none are active, fallback to this route anyway
		if *idx == startIdx {
			return route, nil
		}
	}
}

func (r *InterfaceRoute) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if r.Type == OutboundWarp {
		if r.WarpNet != nil {
			return r.WarpNet.DialContext(ctx, network, address)
		}
		dialer := &net.Dialer{}
		if len(r.WarpSystemIP) > 0 {
			dialer.LocalAddr = &net.TCPAddr{IP: r.WarpSystemIP, Port: 0}
		}
		return dialer.DialContext(ctx, network, address)
	}

	dialer := &net.Dialer{}
	if network == "tcp4" || network == "tcp" {
		if len(r.BindIPv4) > 0 {
			dialer.LocalAddr = &net.TCPAddr{IP: r.BindIPv4, Port: 0}
		}
	} else if network == "tcp6" {
		if len(r.BindIPv6) > 0 {
			dialer.LocalAddr = &net.TCPAddr{IP: r.BindIPv6, Port: 0}
		}
	}
	return dialer.DialContext(ctx, network, address)
}

func (d *Dispatcher) StartHealthChecks(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		d.checkAllRoutes()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				d.checkAllRoutes()
			}
		}
	}()
}

func (d *Dispatcher) checkAllRoutes() {
	uniqueRoutes := make(map[*InterfaceRoute]bool)
	d.mu.Lock()
	for _, r := range d.routesIPv4 {
		uniqueRoutes[r] = true
	}
	for _, r := range d.routesIPv6 {
		uniqueRoutes[r] = true
	}
	d.mu.Unlock()

	for r := range uniqueRoutes {
		go d.checkRoute(r)
	}
}

func (d *Dispatcher) checkRoute(r *InterfaceRoute) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var lastErr error
	if len(r.BindIPv4) > 0 || r.Type == OutboundWarp {
		start := time.Now()
		conn, err := r.DialContext(ctx, "tcp4", "1.1.1.1:53")
		if err == nil {
			latency := time.Since(start)
			conn.Close()
			if !r.IsActive() {
				logPrintf("Interface %s is back online (IPv4 check succeeded)", r.Name)
			}
			r.SetActive(true)
			r.SetLatency(latency)
			return
		}
		lastErr = err
	}

	if len(r.BindIPv6) > 0 {
		start := time.Now()
		conn, err := r.DialContext(ctx, "tcp6", "[2606:4700:4700::1111]:53")
		if err == nil {
			latency := time.Since(start)
			conn.Close()
			if !r.IsActive() {
				logPrintf("Interface %s is back online (IPv6 check succeeded)", r.Name)
			}
			r.SetActive(true)
			r.SetLatency(latency)
			return
		}
		lastErr = err
	}

	if r.IsActive() {
		logPrintf("Health check failed for interface %s: %v. Marking as offline.", r.Name, lastErr)
	}
	r.SetActive(false)
}

func (d *Dispatcher) Close() {
	d.mu.Lock()
	defer d.mu.Unlock()

	uniqueRoutes := make(map[*InterfaceRoute]bool)
	for _, r := range d.routesIPv4 {
		uniqueRoutes[r] = true
	}
	for _, r := range d.routesIPv6 {
		uniqueRoutes[r] = true
	}

	for r := range uniqueRoutes {
		if r.Type == OutboundWarp && r.WarpDev != nil {
			logPrintf("Closing and tearing down Warp tunnel device: %s", r.Name)
			r.WarpDev.Close()
		}
	}
}
