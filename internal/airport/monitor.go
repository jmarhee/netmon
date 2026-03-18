package airport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	defaultSnapshotLen = int32(1600)
	defaultReadTimeout = time.Second
)

// AirportBaseStation describes a discovered Apple wireless base station or AP.
type AirportBaseStation struct {
	BSSID       net.HardwareAddr `json:"bssid"`
	SSID        string           `json:"ssid"`
	Channel     int              `json:"channel"`
	SignalDBM   int              `json:"signal_dbm"`
	Vendor      string           `json:"vendor"`
	LastSeen    time.Time        `json:"last_seen"`
	BeaconCount int              `json:"beacon_count"`
}

// AirportMonitor captures 802.11 management frames and keeps track of
// Apple-manufactured access points seen on the selected interface.
type AirportMonitor struct {
	Interface string
	Handle    *pcap.Handle
	Updates   chan AirportBaseStation

	mu       sync.RWMutex
	stations map[string]*AirportBaseStation
}

// NewAirportMonitor opens a live capture handle for the given interface.
func NewAirportMonitor(iface string) (*AirportMonitor, error) {
	if strings.TrimSpace(iface) == "" {
		return nil, errors.New("interface name is required")
	}

	handle, err := pcap.OpenLive(iface, defaultSnapshotLen, true, defaultReadTimeout)
	if err != nil {
		return nil, fmt.Errorf("open capture on %q: %w", iface, err)
	}

	return &AirportMonitor{
		Interface: iface,
		Handle:    handle,
		stations:  make(map[string]*AirportBaseStation),
	}, nil
}

// DefaultInterfaceName returns a practical default capture interface.
// On macOS this prefers en0 when available.
func DefaultInterfaceName() (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("list capture devices: %w", err)
	}

	var fallback string
	for _, dev := range devs {
		if dev.Name == "en0" {
			return dev.Name, nil
		}
		if fallback == "" && !strings.HasPrefix(dev.Name, "lo") {
			fallback = dev.Name
		}
	}

	if fallback != "" {
		return fallback, nil
	}

	if len(devs) == 0 {
		return "", errors.New("no capture interfaces found")
	}

	return devs[0].Name, nil
}

// Start begins packet capture until the handle is closed.
func (am *AirportMonitor) Start() error {
	return am.StartContext(context.Background())
}

// StartContext begins packet capture and stops when the context is canceled.
func (am *AirportMonitor) StartContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	am.mu.RLock()
	handle := am.Handle
	am.mu.RUnlock()

	if handle == nil {
		return errors.New("airport monitor is not initialized")
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		data, _, err := handle.ReadPacketData()
		if err != nil {
			switch err {
			case pcap.NextErrorTimeoutExpired:
				continue
			case pcap.NextErrorNoMorePackets:
				return nil
			default:
				if strings.Contains(strings.ToLower(err.Error()), "not active") {
					return nil
				}
				return fmt.Errorf("read packet: %w", err)
			}
		}

		packet := gopacket.NewPacket(data, handle.LinkType(), gopacket.Lazy)
		station, ok := am.processPacket(packet)
		if !ok {
			continue
		}

		if am.Updates != nil {
			select {
			case am.Updates <- station:
			default:
			}
		}
	}
}

// Close stops the capture handle.
func (am *AirportMonitor) Close() error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if am.Handle == nil {
		return nil
	}

	am.Handle.Close()
	am.Handle = nil
	return nil
}

// Snapshot returns a stable copy of the stations seen so far.
func (am *AirportMonitor) Snapshot() []AirportBaseStation {
	am.mu.RLock()
	defer am.mu.RUnlock()

	out := make([]AirportBaseStation, 0, len(am.stations))
	for _, station := range am.stations {
		out = append(out, copyStation(*station))
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].BSSID.String() < out[j].BSSID.String()
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})

	return out
}

// IsAppleOUI reports whether the given MAC address belongs to a known Apple OUI.
func IsAppleOUI(mac net.HardwareAddr) bool {
	if len(mac) < 3 {
		return false
	}
	prefix := strings.ToUpper(mac.String())
	if len(prefix) >= 8 {
		prefix = prefix[:8]
	}
	_, ok := appleOUIs[prefix]
	return ok
}

func (am *AirportMonitor) processPacket(packet gopacket.Packet) (AirportBaseStation, bool) {
	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer == nil {
		return AirportBaseStation{}, false
	}

	dot11, ok := dot11Layer.(*layers.Dot11)
	if !ok {
		return AirportBaseStation{}, false
	}

	bssid := pickBSSID(dot11)
	if len(bssid) == 0 || !IsAppleOUI(bssid) {
		return AirportBaseStation{}, false
	}

	ssid, channel := extractBeaconDetails(packet)
	signal := extractSignalDBM(packet)
	now := time.Now()

	return am.upsertStation(bssid, ssid, channel, signal, now), true
}

func (am *AirportMonitor) upsertStation(
	bssid net.HardwareAddr,
	ssid string,
	channel int,
	signal int,
	lastSeen time.Time,
) AirportBaseStation {
	key := strings.ToUpper(bssid.String())

	am.mu.Lock()
	defer am.mu.Unlock()

	station, exists := am.stations[key]
	if !exists {
		station = &AirportBaseStation{
			BSSID:     append(net.HardwareAddr(nil), bssid...),
			Vendor:    "Apple",
			Channel:   channel,
			SignalDBM: signal,
			SSID:      ssid,
			LastSeen:  lastSeen,
		}
		am.stations[key] = station
	}

	if ssid != "" {
		station.SSID = ssid
	}
	if channel > 0 {
		station.Channel = channel
	}
	if signal != 0 {
		station.SignalDBM = signal
	}
	station.LastSeen = lastSeen
	station.BeaconCount++

	return copyStation(*station)
}

func extractBeaconDetails(packet gopacket.Packet) (string, int) {
	var ssid string
	var channel int

	for _, layer := range packet.Layers() {
		ie, ok := layer.(*layers.Dot11InformationElement)
		if !ok {
			continue
		}

		switch uint8(ie.ID) {
		case 0:
			if len(ie.Info) > 0 {
				ssid = sanitizeSSID(ie.Info)
			} else {
				ssid = ""
			}
		case 3:
			if len(ie.Info) > 0 {
				channel = int(ie.Info[0])
			}
		}
	}

	return ssid, channel
}

func extractSignalDBM(packet gopacket.Packet) int {
	layer := packet.Layer(layers.LayerTypeRadioTap)
	if layer == nil {
		return 0
	}

	rt, ok := layer.(*layers.RadioTap)
	if !ok {
		return 0
	}

	return int(int8(rt.DBMAntennaSignal))
}

func pickBSSID(dot11 *layers.Dot11) net.HardwareAddr {
	candidates := []net.HardwareAddr{
		dot11.Address3,
		dot11.Address2,
		dot11.Address1,
	}

	for _, addr := range candidates {
		if len(addr) == 0 || isBroadcast(addr) {
			continue
		}
		return append(net.HardwareAddr(nil), addr...)
	}

	return nil
}

func isBroadcast(addr net.HardwareAddr) bool {
	if len(addr) != 6 {
		return false
	}
	for _, b := range addr {
		if b != 0xff {
			return false
		}
	}
	return true
}

func sanitizeSSID(b []byte) string {
	s := strings.TrimSpace(string(b))
	s = strings.Trim(s, "\x00")
	return s
}

func copyStation(in AirportBaseStation) AirportBaseStation {
	out := in
	if in.BSSID != nil {
		out.BSSID = append(net.HardwareAddr(nil), in.BSSID...)
	}
	return out
}

var appleOUIs = map[string]struct{}{
	"00:03:93": {},
	"00:0A:27": {},
	"00:0A:95": {},
	"00:0D:93": {},
	"00:11:24": {},
	"00:14:51": {},
	"00:16:CB": {},
	"00:17:F2": {},
	"00:19:E3": {},
	"00:1B:63": {},
	"00:1D:4F": {},
	"00:1E:52": {},
	"00:1F:5B": {},
	"00:21:E9": {},
	"00:22:41": {},
	"00:23:12": {},
	"00:23:32": {},
	"00:23:6C": {},
	"00:24:36": {},
	"00:25:00": {},
	"00:25:4B": {},
	"00:26:08": {},
	"00:26:4A": {},
	"00:26:B0": {},
	"00:26:BB": {},
	"04:0C:CE": {},
	"04:15:52": {},
	"04:1E:64": {},
	"04:26:65": {},
	"04:48:9A": {},
	"04:54:53": {},
	"04:69:F8": {},
	"04:DB:56": {},
	"04:E5:36": {},
	"04:F1:3E": {},
	"08:66:98": {},
	"08:70:45": {},
	"08:74:02": {},
	"08:F4:AB": {},
	"0C:15:39": {},
	"0C:30:21": {},
	"0C:3E:9F": {},
	"10:40:F3": {},
	"10:93:E9": {},
	"14:10:9F": {},
	"14:20:5E": {},
	"14:5A:05": {},
	"18:20:32": {},
	"1C:1A:C0": {},
	"1C:AB:A7": {},
	"20:78:F0": {},
	"24:A0:74": {},
	"28:37:37": {},
	"28:CF:DA": {},
	"2C:1F:23": {},
	"30:10:E4": {},
	"3C:07:54": {},
	"3C:15:C2": {},
	"40:30:04": {},
	"40:4D:7F": {},
	"48:60:BC": {},
	"4C:8D:79": {},
	"50:EA:D6": {},
	"54:26:96": {},
	"58:55:CA": {},
	"5C:59:48": {},
	"60:03:08": {},
	"60:33:4B": {},
	"60:69:44": {},
	"60:C5:47": {},
	"64:20:0C": {},
	"68:5B:35": {},
	"68:96:7B": {},
	"6C:40:08": {},
	"70:3E:AC": {},
	"78:31:C1": {},
	"78:4F:43": {},
	"7C:6D:62": {},
	"7C:C3:A1": {},
	"80:00:6E": {},
	"80:BE:05": {},
	"84:38:35": {},
	"84:78:8B": {},
	"88:1F:A1": {},
	"8C:2D:AA": {},
	"8C:58:77": {},
	"90:84:0D": {},
	"90:B2:1F": {},
	"94:94:26": {},
	"98:01:A7": {},
	"98:03:D8": {},
	"98:5A:EB": {},
	"98:F0:AB": {},
	"9C:04:EB": {},
	"9C:20:7B": {},
	"9C:29:3F": {},
	"A4:5E:60": {},
	"A4:B1:97": {},
	"A8:20:66": {},
	"A8:5B:78": {},
	"AC:29:3A": {},
	"AC:61:EA": {},
	"B0:34:95": {},
	"B8:09:8A": {},
	"B8:17:C2": {},
	"B8:53:AC": {},
	"BC:3B:AF": {},
	"BC:52:B7": {},
	"C4:2C:03": {},
	"C8:2A:14": {},
	"CC:08:8D": {},
	"CC:25:EF": {},
	"D0:03:4B": {},
	"D4:9A:20": {},
	"D8:30:62": {},
	"D8:96:95": {},
	"DC:2B:2A": {},
	"DC:37:14": {},
	"E0:AC:CB": {},
	"E0:B9:BA": {},
	"E4:8B:7F": {},
	"E8:06:88": {},
	"E8:B2:AC": {},
	"F0:18:98": {},
	"F0:99:B6": {},
	"F4:0F:24": {},
	"F4:37:B7": {},
	"F4:F1:5A": {},
	"F8:1E:DF": {},
	"F8:27:93": {},
	"F8:4F:57": {},
	"F8:FF:C2": {},
	"FC:25:3F": {},
}
