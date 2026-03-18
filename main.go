package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	airportmon "inet-tool-cli/internal/airport"
	bonjourmon "inet-tool-cli/internal/bonjour"
	"inet-tool-cli/internal/scanner"
	wolpkg "inet-tool-cli/internal/wol"
)

type config struct {
	subnet     string
	outputPath string
	wakeMAC    string
	iface      string
	timeout    time.Duration
	interval   time.Duration
	scan       bool
	once       bool
	bonjour    bool
	airport    bool
	format     string // "text" or "json"
}

type lockedWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (lw *lockedWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	return lw.w.Write(p)
}

func writeJSON(out io.Writer, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = out.Write(append(data, '\n'))
	return err
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	cfg, err := parseFlags(args)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(os.Stderr, "netmon: %v\n", err)
		return 2
	}

	out, cleanup, err := newOutputWriter(cfg.outputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "netmon: open output file: %v\n", err)
		return 1
	}
	defer cleanup()

	logger := log.New(os.Stderr, "netmon: ", log.LstdFlags)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.airport && (strings.TrimSpace(cfg.iface) == "" || strings.EqualFold(strings.TrimSpace(cfg.iface), "auto")) {
		iface, err := airportmon.DefaultInterfaceName()
		if err != nil {
			logger.Printf("failed to determine capture interface: %v", err)
			return 1
		}
		cfg.iface = iface
	}

	if strings.TrimSpace(cfg.wakeMAC) != "" {
		mac, err := wolpkg.ParseMACAddress(cfg.wakeMAC)
		if err != nil {
			logger.Printf("invalid MAC address %q: %v", cfg.wakeMAC, err)
			return 1
		}

		if err := wolpkg.WakeOnLAN(mac); err != nil {
			logger.Printf("wake-on-LAN failed for %s: %v", mac, err)
			return 1
		}

		fmt.Fprintf(out, "Sent wake-on-LAN packet to %s\n", mac)
	}

	errCh := make(chan error, 4)

	if cfg.bonjour {
		if err := startBonjourMonitor(ctx, out, cfg.format); err != nil {
			logger.Printf("failed to start Bonjour monitor: %v", err)
			return 1
		}
	}

	if cfg.airport {
		if err := startAirportMonitor(ctx, cfg.iface, out, errCh, cfg.format); err != nil {
			logger.Printf("failed to start Airport monitor: %v", err)
			return 1
		}
	}

	if cfg.scan {
		sc := scanner.NewNetworkScanner(cfg.subnet)
		sc.Timeout = cfg.timeout

		if cfg.once {
			if err := scanAndPrint(sc, out, cfg.format); err != nil {
				logger.Printf("scan error: %v", err)
				return 1
			}

			if !cfg.bonjour && !cfg.airport {
				return 0
			}

			return waitForShutdown(ctx, errCh, logger)
		}

		if err := scanAndPrint(sc, out, cfg.format); err != nil {
			logger.Printf("scan error: %v", err)
		}

		ticker := time.NewTicker(cfg.interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return 0
			case err := <-errCh:
				if err != nil {
					logger.Print(err)
					return 1
				}
			case <-ticker.C:
				if err := scanAndPrint(sc, out, cfg.format); err != nil {
					logger.Printf("scan error: %v", err)
				}
			}
		}
	}

	if cfg.bonjour || cfg.airport {
		return waitForShutdown(ctx, errCh, logger)
	}

	return 0
}

func parseFlags(args []string) (config, error) {
	var cfg config

	fs := flag.NewFlagSet("netmon", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	fs.StringVar(&cfg.subnet, "subnet", "192.168.1.0/24", "Network subnet to scan")
	fs.StringVar(&cfg.outputPath, "output", "", "Write output to a file in addition to stdout")
	fs.StringVar(&cfg.wakeMAC, "wake", "", "MAC address to wake (for example: 00:11:22:33:44:55)")
	fs.StringVar(&cfg.iface, "iface", "en0", "Network interface to use (or 'auto' for automatic selection)")
	fs.StringVar(&cfg.format, "format", "text", "Output format: text|json")
	fs.DurationVar(&cfg.timeout, "timeout", 2*time.Second, "Timeout for host and service probes")
	fs.DurationVar(&cfg.interval, "interval", 5*time.Second, "Delay between scan cycles")
	fs.BoolVar(&cfg.scan, "scan", true, "Enable network scanning")
	fs.BoolVar(&cfg.once, "once", false, "Run one scan and exit unless a monitor is active")
	fs.BoolVar(&cfg.bonjour, "bonjour", false, "Monitor Bonjour/mDNS services")
	fs.BoolVar(&cfg.airport, "airport", false, "Monitor Apple Airport base stations")

	fs.Usage = func() {
		w := fs.Output()
		fmt.Fprintf(w, "Usage: %s [flags]\n\n", fs.Name())
		fmt.Fprintln(w, "netmon combines subnet scanning, Bonjour monitoring, Wake-on-LAN,")
		fmt.Fprintln(w, "and Apple Airport monitoring in a single CLI.")
		fmt.Fprintln(w, "\nFlags:")
		fs.PrintDefaults()
		fmt.Fprintln(w, "\nExamples:")
		fmt.Fprintf(w, "  %s -once\n", fs.Name())
		fmt.Fprintf(w, "  %s -subnet 192.168.1.0/24 -output scan.txt\n", fs.Name())
		fmt.Fprintf(w, "  %s -scan=false -bonjour\n", fs.Name())
		fmt.Fprintf(w, "  %s -scan=false -wake 00:11:22:33:44:55\n", fs.Name())
		fmt.Fprintf(w, "  %s -airport -iface auto\n", fs.Name())
		fmt.Fprintf(w, "  %s -format json\n", fs.Name())
	}

	if err := fs.Parse(args); err != nil {
		return cfg, err
	}

	if cfg.scan && strings.TrimSpace(cfg.subnet) == "" {
		return cfg, errors.New("subnet must not be empty when scanning is enabled")
	}
	if cfg.timeout <= 0 {
		return cfg, errors.New("timeout must be greater than zero")
	}
	if cfg.interval <= 0 {
		return cfg, errors.New("interval must be greater than zero")
	}

	// normalize format
	cfg.format = strings.ToLower(strings.TrimSpace(cfg.format))
	if cfg.format != "text" && cfg.format != "json" {
		return cfg, errors.New("invalid format: must be 'text' or 'json'")
	}

	return cfg, nil
}

func newOutputWriter(path string) (io.Writer, func(), error) {
	// If no path given, write to stdout only.
	if strings.TrimSpace(path) == "" {
		return &lockedWriter{w: os.Stdout}, func() {}, nil
	}

	// Clean the provided path first.
	clean := filepath.Clean(path)

	// If the path is relative, resolve it against the current working
	// directory and ensure it does not escape the working directory.
	if !filepath.IsAbs(clean) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, nil, fmt.Errorf("determine working dir: %w", err)
		}
		abs := filepath.Join(wd, clean)
		abs, err = filepath.Abs(abs)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve output path: %w", err)
		}
		// Ensure the resolved path is inside the working dir. Disallow paths
		// that escape via ../ sequences.
		rel, err := filepath.Rel(wd, abs)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid output path: %w", err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return nil, nil, fmt.Errorf("output path %q escapes working directory", path)
		}
		clean = abs
	} else {
		// For absolute paths, resolve to an absolute, cleaned path.
		abs, err := filepath.Abs(clean)
		if err != nil {
			return nil, nil, fmt.Errorf("resolve output path: %w", err)
		}
		clean = abs
	}

	// Ensure the parent directory exists and is writable.
	dir := filepath.Dir(clean)
	if dir == "" {
		dir = "."
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, nil, fmt.Errorf("ensure output directory: %w", err)
	}

	// Open the file with explicit flags to ensure we control creation and truncation.
	f, err := os.OpenFile(clean, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, nil, fmt.Errorf("open output file: %w", err)
	}

	writer := &lockedWriter{w: io.MultiWriter(os.Stdout, f)}
	cleanup := func() {
		_ = f.Close()
	}

	return writer, cleanup, nil
}

func scanAndPrint(sc *scanner.NetworkScanner, out io.Writer, format string) error {
	if format == "text" {
		fmt.Fprintf(out, "\n[%s] Scanning subnet %s\n", time.Now().Format(time.RFC3339), sc.Subnet)
	} else {
		// JSON mode: include metadata timestamp and subnet in the output envelope
		fmt.Fprintf(out, "")
	}

	devices, err := sc.Scan()
	if err != nil {
		return err
	}

	if len(devices) == 0 {
		if format == "text" {
			fmt.Fprintln(out, "No devices discovered.")
			return nil
		}
		// JSON: emit empty array
		return writeJSON(out, []interface{}{})
	}

	if format == "json" {
		// build serializable representation
		type svc struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Service  string `json:"service"`
			Version  string `json:"version,omitempty"`
		}
		type dev struct {
			IP       string `json:"ip"`
			MAC      string `json:"mac,omitempty"`
			Hostname string `json:"hostname,omitempty"`
			Vendor   string `json:"vendor,omitempty"`
			Services []svc  `json:"services,omitempty"`
		}

		outDevices := make([]dev, 0, len(devices))
		for _, d := range devices {
			item := dev{
				IP:       d.IP.String(),
				Hostname: d.Hostname,
				Vendor:   d.Vendor,
			}
			if len(d.MAC) > 0 {
				item.MAC = d.MAC.String()
			}
			if len(d.Services) > 0 {
				item.Services = make([]svc, 0, len(d.Services))
				for _, s := range d.Services {
					item.Services = append(item.Services, svc{
						Port:     s.Port,
						Protocol: s.Protocol,
						Service:  s.Service,
						Version:  s.Version,
					})
				}
			}
			outDevices = append(outDevices, item)
		}

		return writeJSON(out, outDevices)
	}

	for _, device := range devices {
		printDevice(out, device, format)
	}

	return nil
}

func startBonjourMonitor(ctx context.Context, out io.Writer, format string) error {
	monitor, err := bonjourmon.NewBonjourMonitor()
	if err != nil {
		return err
	}

	updates := make(chan bonjourmon.ServiceEntry, 32)
	if err := monitor.StartContext(ctx, updates); err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		monitor.Stop()
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case entry, ok := <-updates:
				if !ok {
					return
				}
				printBonjourEntry(out, entry, format)
			}
		}
	}()

	return nil
}

func startAirportMonitor(ctx context.Context, iface string, out io.Writer, errCh chan<- error, format string) error {
	monitor, err := airportmon.NewAirportMonitor(iface)
	if err != nil {
		return err
	}

	events := make(chan airportmon.AirportBaseStation, 32)
	monitor.Updates = events

	go func() {
		<-ctx.Done()
		_ = monitor.Close()
	}()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-events:
				if !ok {
					return
				}
				printAirportEvent(out, event, format)
			}
		}
	}()

	go func() {
		defer func() {
			_ = monitor.Close()
		}()

		if err := monitor.StartContext(ctx); err != nil && !errors.Is(err, context.Canceled) {
			select {
			case errCh <- fmt.Errorf("airport monitor: %w", err):
			default:
			}
		}
	}()

	return nil
}

func waitForShutdown(ctx context.Context, errCh <-chan error, logger *log.Logger) int {
	for {
		select {
		case <-ctx.Done():
			return 0
		case err := <-errCh:
			if err == nil {
				continue
			}
			logger.Print(err)
			return 1
		}
	}
}

func printDevice(out io.Writer, device scanner.DeviceInfo, format string) {
	if format == "json" {
		type svc struct {
			Port     int    `json:"port"`
			Protocol string `json:"protocol"`
			Service  string `json:"service"`
			Version  string `json:"version,omitempty"`
		}
		type dev struct {
			IP       string `json:"ip"`
			MAC      string `json:"mac,omitempty"`
			Hostname string `json:"hostname,omitempty"`
			Vendor   string `json:"vendor,omitempty"`
			Services []svc  `json:"services,omitempty"`
		}

		d := dev{
			IP:       device.IP.String(),
			Hostname: device.Hostname,
			Vendor:   device.Vendor,
		}
		if len(device.MAC) > 0 {
			d.MAC = device.MAC.String()
		}
		if len(device.Services) > 0 {
			d.Services = make([]svc, 0, len(device.Services))
			for _, s := range device.Services {
				d.Services = append(d.Services, svc{
					Port:     s.Port,
					Protocol: s.Protocol,
					Service:  s.Service,
					Version:  s.Version,
				})
			}
		}
		_ = writeJSON(out, d)
		return
	}

	mac := "<unknown>"
	if len(device.MAC) > 0 {
		mac = device.MAC.String()
	}

	if device.Hostname != "" {
		fmt.Fprintf(out, "Device: %s (%s) - %s\n", device.IP, mac, device.Hostname)
	} else {
		fmt.Fprintf(out, "Device: %s (%s)\n", device.IP, mac)
	}
	if device.Vendor != "" {
		fmt.Fprintf(out, "  Vendor: %s\n", device.Vendor)
	}

	if len(device.Services) == 0 {
		return
	}

	for _, svc := range device.Services {
		service := svc.Service
		if service == "" {
			service = "unknown"
		}

		protocol := svc.Protocol
		if protocol == "" {
			protocol = "tcp"
		}

		if svc.Version != "" {
			fmt.Fprintf(out, "  Service: %s/%d (%s, %s)\n", service, svc.Port, protocol, svc.Version)
			continue
		}

		fmt.Fprintf(out, "  Service: %s/%d (%s)\n", service, svc.Port, protocol)
	}
}

func printBonjourEntry(out io.Writer, entry bonjourmon.ServiceEntry, format string) {
	if format == "json" {
		j := struct {
			Name      string   `json:"name"`
			Type      string   `json:"type"`
			Domain    string   `json:"domain,omitempty"`
			HostName  string   `json:"host,omitempty"`
			Port      int      `json:"port,omitempty"`
			Addresses []string `json:"addresses,omitempty"`
			Text      []string `json:"txt,omitempty"`
			FirstSeen string   `json:"first_seen,omitempty"`
			LastSeen  string   `json:"last_seen,omitempty"`
		}{
			Name:      entry.Name,
			Type:      entry.Type,
			Domain:    entry.Domain,
			HostName:  entry.HostName,
			Port:      entry.Port,
			Addresses: entry.AddressStrings(),
			Text:      entry.Text,
		}
		if !entry.FirstSeenAt.IsZero() {
			j.FirstSeen = entry.FirstSeenAt.Format(time.RFC3339)
		}
		if !entry.LastSeenAt.IsZero() {
			j.LastSeen = entry.LastSeenAt.Format(time.RFC3339)
		}
		_ = writeJSON(out, j)
		return
	}

	name := entry.Name
	if name == "" {
		name = entry.HostName
	}
	if name == "" {
		name = "<unknown>"
	}

	serviceType := entry.Type
	if serviceType == "" {
		serviceType = "<unknown>"
	}

	fmt.Fprintf(out, "Bonjour Service: %s (%s)\n", name, serviceType)

	if entry.Domain != "" {
		fmt.Fprintf(out, "  Domain: %s\n", entry.Domain)
	}
	if entry.HostName != "" {
		fmt.Fprintf(out, "  Host: %s\n", entry.HostName)
	}
	if entry.Port > 0 {
		fmt.Fprintf(out, "  Port: %d\n", entry.Port)
	}

	addresses := entry.AddressStrings()
	if len(addresses) > 0 {
		fmt.Fprintf(out, "  Addresses: %s\n", strings.Join(addresses, ", "))
	}
	if len(entry.Text) > 0 {
		fmt.Fprintf(out, "  TXT: %s\n", strings.Join(entry.Text, ", "))
	}
	if !entry.FirstSeenAt.IsZero() {
		fmt.Fprintf(out, "  First Seen: %s\n", entry.FirstSeenAt.Format(time.RFC3339))
	}
	if !entry.LastSeenAt.IsZero() {
		fmt.Fprintf(out, "  Last Seen: %s\n", entry.LastSeenAt.Format(time.RFC3339))
	}
}

func printAirportEvent(out io.Writer, event airportmon.AirportBaseStation, format string) {
	if format == "json" {
		j := struct {
			BSSID       string `json:"bssid,omitempty"`
			SSID        string `json:"ssid,omitempty"`
			Channel     int    `json:"channel,omitempty"`
			SignalDBM   int    `json:"rssi_dbm,omitempty"`
			Vendor      string `json:"vendor,omitempty"`
			BeaconCount int    `json:"beacon_count,omitempty"`
			LastSeen    string `json:"last_seen,omitempty"`
		}{
			SSID:        event.SSID,
			Channel:     event.Channel,
			SignalDBM:   event.SignalDBM,
			Vendor:      event.Vendor,
			BeaconCount: event.BeaconCount,
		}
		if len(event.BSSID) > 0 {
			j.BSSID = event.BSSID.String()
		}
		if !event.LastSeen.IsZero() {
			j.LastSeen = event.LastSeen.Format(time.RFC3339)
		}
		_ = writeJSON(out, j)
		return
	}

	fmt.Fprintln(out, "Airport Base Station:")

	if len(event.BSSID) > 0 {
		fmt.Fprintf(out, "  BSSID: %s\n", event.BSSID.String())
	}
	if event.SSID != "" {
		fmt.Fprintf(out, "  SSID: %s\n", event.SSID)
	}
	if event.Channel > 0 {
		fmt.Fprintf(out, "  Channel: %d\n", event.Channel)
	}
	if event.SignalDBM != 0 {
		fmt.Fprintf(out, "  RSSI: %d dBm\n", event.SignalDBM)
	}
	if event.Vendor != "" {
		fmt.Fprintf(out, "  Vendor: %s\n", event.Vendor)
	}
	if event.BeaconCount > 0 {
		fmt.Fprintf(out, "  Beacon Count: %d\n", event.BeaconCount)
	}
	if !event.LastSeen.IsZero() {
		fmt.Fprintf(out, "  Last Seen: %s\n", event.LastSeen.Format(time.RFC3339))
	}
}
