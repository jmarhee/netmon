package bonjour

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
)

const (
	// DefaultBrowseService is the DNS-SD meta-service used to discover
	// advertised Bonjour service types on the local network.
	DefaultBrowseService = "_services._dns-sd._udp"

	// DefaultDomain is the default mDNS domain.
	DefaultDomain = "local."
)

// ServiceEntry is the normalized Bonjour service information emitted by the
// monitor.
type ServiceEntry struct {
	Name        string
	Type        string
	Domain      string
	HostName    string
	Port        int
	Text        []string
	IPv4        []net.IP
	IPv6        []net.IP
	FirstSeenAt time.Time
	LastSeenAt  time.Time
}

// AddressStrings returns a stable, human-friendly list of IP addresses.
func (e ServiceEntry) AddressStrings() []string {
	values := make([]string, 0, len(e.IPv4)+len(e.IPv6))
	for _, ip := range e.IPv4 {
		values = append(values, ip.String())
	}
	for _, ip := range e.IPv6 {
		values = append(values, ip.String())
	}
	sort.Strings(values)
	return values
}

// package-level mDNS hostname cache (IP string -> hostname). This allows other
// packages to quickly look up hostnames discovered via mDNS without requiring
// an active monitor instance reference.
var (
	mdnsMu    sync.RWMutex
	mdnsHosts = make(map[string]string)
)

// LookupHostname returns a hostname discovered via mDNS/Bonjour for the
// provided IP if available.
func LookupHostname(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	mdnsMu.RLock()
	h, ok := mdnsHosts[ip.String()]
	mdnsMu.RUnlock()
	return h, ok
}

// cacheHostname associates a hostname with provided IP addresses in the
// global mDNS cache.
func cacheHostname(host string, ips []net.IP) {
	if host == "" || len(ips) == 0 {
		return
	}
	mdnsMu.Lock()
	defer mdnsMu.Unlock()
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		mdnsHosts[ip.String()] = host
	}
}

// BonjourMonitor continuously browses Bonjour services and emits distinct or
// changed entries on the updates channel passed to Start or StartContext.
type BonjourMonitor struct {
	service  string
	domain   string
	resolver *zeroconf.Resolver

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
	updates chan<- ServiceEntry
	seen    map[string]ServiceEntry
}

// NewBonjourMonitor creates a monitor for the default DNS-SD meta-service,
// which lets callers discover the available Bonjour service types on the local
// network.
func NewBonjourMonitor() (*BonjourMonitor, error) {
	return NewServiceMonitor(DefaultBrowseService, DefaultDomain)
}

// NewServiceMonitor creates a monitor for a specific Bonjour service and domain.
func NewServiceMonitor(service, domain string) (*BonjourMonitor, error) {
	if strings.TrimSpace(service) == "" {
		service = DefaultBrowseService
	}
	if strings.TrimSpace(domain) == "" {
		domain = DefaultDomain
	}

	resolver, err := zeroconf.NewResolver(nil)
	if err != nil {
		return nil, fmt.Errorf("create bonjour resolver: %w", err)
	}

	return &BonjourMonitor{
		service:  service,
		domain:   domain,
		resolver: resolver,
		seen:     make(map[string]ServiceEntry),
	}, nil
}

// Start begins browsing using a background context.
func (m *BonjourMonitor) Start(updates chan<- ServiceEntry) error {
	return m.StartContext(context.Background(), updates)
}

// StartContext begins browsing using the provided context.
func (m *BonjourMonitor) StartContext(parent context.Context, updates chan<- ServiceEntry) error {
	if updates == nil {
		return errors.New("updates channel is required")
	}
	if parent == nil {
		parent = context.Background()
	}

	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return errors.New("bonjour monitor already running")
	}

	ctx, cancel := context.WithCancel(parent)
	entries := make(chan *zeroconf.ServiceEntry, 32)
	done := make(chan struct{})

	m.running = true
	m.cancel = cancel
	m.done = done
	m.updates = updates
	m.seen = make(map[string]ServiceEntry)
	m.mu.Unlock()

	go m.consume(ctx, entries, done)

	if err := m.resolver.Browse(ctx, m.service, m.domain, entries); err != nil {
		cancel()
		<-done

		m.mu.Lock()
		m.running = false
		m.cancel = nil
		m.done = nil
		m.updates = nil
		m.mu.Unlock()

		return fmt.Errorf("browse bonjour service %q in domain %q: %w", m.service, m.domain, err)
	}

	return nil
}

// Stop stops the active browse operation and waits for the consumer loop to exit.
func (m *BonjourMonitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}

	cancel := m.cancel
	done := m.done

	m.running = false
	m.cancel = nil
	m.done = nil
	m.updates = nil
	m.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if done != nil {
		<-done
	}
}

// Running reports whether the monitor is currently active.
func (m *BonjourMonitor) Running() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.running
}

// Service returns the configured browse service.
func (m *BonjourMonitor) Service() string {
	return m.service
}

// Domain returns the configured browse domain.
func (m *BonjourMonitor) Domain() string {
	return m.domain
}

func (m *BonjourMonitor) consume(ctx context.Context, entries <-chan *zeroconf.ServiceEntry, done chan<- struct{}) {
	defer close(done)

	for {
		select {
		case <-ctx.Done():
			return
		case entry, ok := <-entries:
			if !ok {
				return
			}
			if entry == nil {
				continue
			}

			normalized, emit := m.normalizeAndTrack(entry)
			if !emit {
				continue
			}

			m.mu.Lock()
			updates := m.updates
			m.mu.Unlock()

			if updates == nil {
				continue
			}

			select {
			case updates <- normalized:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (m *BonjourMonitor) normalizeAndTrack(entry *zeroconf.ServiceEntry) (ServiceEntry, bool) {
	now := time.Now()

	name := strings.TrimSuffix(entry.Instance, ".")
	serviceType := strings.TrimSuffix(entry.Service, ".")

	// When browsing the DNS-SD meta-service, the discovered "instance" is
	// actually the advertised service type, so expose it directly.
	if m.service == DefaultBrowseService && name != "" {
		serviceType = name
	}

	normalized := ServiceEntry{
		Name:        name,
		Type:        serviceType,
		Domain:      strings.TrimSuffix(entry.Domain, "."),
		HostName:    strings.TrimSuffix(entry.HostName, "."),
		Port:        entry.Port,
		Text:        cloneStrings(entry.Text),
		IPv4:        cloneIPs(entry.AddrIPv4),
		IPv6:        cloneIPs(entry.AddrIPv6),
		FirstSeenAt: now,
		LastSeenAt:  now,
	}

	key := serviceKey(normalized)
	fp := serviceFingerprint(normalized)

	m.mu.Lock()
	defer m.mu.Unlock()

	if prev, ok := m.seen[key]; ok {
		if serviceFingerprint(prev) == fp {
			return ServiceEntry{}, false
		}
		normalized.FirstSeenAt = prev.FirstSeenAt
	}

	// Track the normalized entry
	m.seen[key] = normalized

	// Determine a sensible hostname to store: prefer HostName, fall back to Name.
	host := strings.TrimSpace(normalized.HostName)
	if host == "" {
		host = strings.TrimSpace(normalized.Name)
	}

	if host != "" {
		// collect addresses (prefer IPv4 but include IPv6)
		addrs := append([]net.IP{}, normalized.IPv4...)
		addrs = append(addrs, normalized.IPv6...)
		// populate the package-level mDNS cache asynchronously
		go cacheHostname(host, addrs)
	}

	return normalized, true
}

func serviceKey(entry ServiceEntry) string {
	return strings.Join([]string{
		entry.Name,
		entry.Type,
		entry.Domain,
		entry.HostName,
		fmt.Sprintf("%d", entry.Port),
	}, "|")
}

func serviceFingerprint(entry ServiceEntry) string {
	parts := []string{
		entry.Name,
		entry.Type,
		entry.Domain,
		entry.HostName,
		fmt.Sprintf("%d", entry.Port),
	}

	text := cloneStrings(entry.Text)
	sort.Strings(text)
	parts = append(parts, text...)

	ipv4 := ipStrings(entry.IPv4)
	ipv6 := ipStrings(entry.IPv6)
	parts = append(parts, ipv4...)
	parts = append(parts, ipv6...)

	return strings.Join(parts, "|")
}

func cloneStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

func cloneIPs(values []net.IP) []net.IP {
	if len(values) == 0 {
		return nil
	}
	out := make([]net.IP, 0, len(values))
	for _, ip := range values {
		if ip == nil {
			continue
		}
		copied := make(net.IP, len(ip))
		copy(copied, ip)
		out = append(out, copied)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func ipStrings(values []net.IP) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, ip := range values {
		if ip == nil {
			continue
		}
		out = append(out, ip.String())
	}
	sort.Strings(out)
	return out
}
