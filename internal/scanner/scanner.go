package scanner

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"inet-tool-cli/internal/bonjour"
)

// NetworkScanner performs best-effort local subnet discovery.
// It combines TCP probing, reverse DNS lookups, and ARP table inspection
// to build a device inventory without requiring elevated privileges.
type NetworkScanner struct {
	Subnet     string
	Timeout    time.Duration
	OutputFile *os.File
}

// DeviceInfo describes a discovered host on the network.
type DeviceInfo struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Hostname string
	Vendor   string
	Services []ServiceInfo
}

// ServiceInfo describes an open service discovered on a host.
type ServiceInfo struct {
	Port     int
	Protocol string
	Service  string
	Version  string
}

type knownService struct {
	name     string
	protocol string
}

var commonServices = map[int]knownService{
	22:   {name: "ssh", protocol: "tcp"},
	53:   {name: "dns", protocol: "tcp"},
	80:   {name: "http", protocol: "tcp"},
	139:  {name: "netbios-ssn", protocol: "tcp"},
	443:  {name: "https", protocol: "tcp"},
	445:  {name: "smb", protocol: "tcp"},
	548:  {name: "afp", protocol: "tcp"},
	631:  {name: "ipp", protocol: "tcp"},
	3306: {name: "mysql", protocol: "tcp"},
	3389: {name: "rdp", protocol: "tcp"},
	5900: {name: "vnc", protocol: "tcp"},
	8080: {name: "http-alt", protocol: "tcp"},
}

var commonPortOrder = []int{22, 53, 80, 139, 443, 445, 548, 631, 3306, 3389, 5900, 8080}

var vendorPrefixes = map[string]string{
	"00:03:93": "Apple",
	"00:05:02": "Apple",
	"00:0A:27": "Apple",
	"00:0D:93": "Apple",
	"00:11:24": "Apple",
	"00:14:51": "Apple",
	"00:16:CB": "Apple",
	"00:17:F2": "Apple",
	"00:19:E3": "Apple",
	"00:1B:63": "Apple",
	"00:1E:C2": "Apple",
	"00:21:E9": "Apple",
	"00:23:12": "Apple",
	"00:25:00": "Apple",
	"00:26:08": "Apple",
	"00:26:4A": "Apple",
	"00:26:B0": "Apple",
	"00:3E:E1": "Apple",
	"04:0C:CE": "Apple",
	"04:15:52": "Apple",
	"04:1E:64": "Apple",
	"04:26:65": "Apple",
	"04:4B:ED": "Apple",
	"08:00:07": "Apple",
	"08:66:98": "Apple",
	"0C:30:21": "Apple",
	"10:40:F3": "Apple",
	"14:10:9F": "Apple",
	"18:AF:61": "Apple",
	"1C:1A:C0": "Apple",
	"1C:AB:A7": "Apple",
	"20:3C:AE": "Apple",
	"24:A0:74": "Apple",
	"28:37:37": "Apple",
	"28:CF:E9": "Apple",
	"2C:1F:23": "Apple",
	"30:10:E4": "Apple",
	"34:12:98": "Apple",
	"3C:07:54": "Apple",
	"40:30:04": "Apple",
	"40:A6:D9": "Apple",
	"44:00:10": "Apple",
	"48:43:7C": "Apple",
	"4C:57:CA": "Apple",
	"50:EA:D6": "Apple",
	"54:26:96": "Apple",
	"58:55:CA": "Apple",
	"5C:95:AE": "Apple",
	"60:03:08": "Apple",
	"60:F8:1D": "Apple",
	"64:20:0C": "Apple",
	"68:AB:1E": "Apple",
	"6C:40:08": "Apple",
	"70:11:24": "Apple",
	"70:73:CB": "Apple",
	"74:E1:B6": "Apple",
	"78:31:C1": "Apple",
	"7C:C3:A1": "Apple",
	"80:BE:05": "Apple",
	"84:38:35": "Apple",
	"88:53:2E": "Apple",
	"88:63:DF": "Apple",
	"8C:2D:AA": "Apple",
	"90:72:40": "Apple",
	"90:B2:1F": "Apple",
	"94:94:26": "Apple",
	"98:01:A7": "Apple",
	"98:5A:EB": "Apple",
	"9C:20:7B": "Apple",
	"A4:5E:60": "Apple",
	"A8:20:66": "Apple",
	"AC:29:3A": "Apple",
	"B0:65:BD": "Apple",
	"B4:F0:AB": "Apple",
	"B8:09:8A": "Apple",
	"BC:52:B7": "Apple",
	"C8:2A:14": "Apple",
	"D0:03:4B": "Apple",
	"D4:61:9D": "Apple",
	"D8:30:62": "Apple",
	"D8:96:95": "Apple",
	"DC:2B:61": "Apple",
	"E0:33:8E": "Apple",
	"E0:F8:47": "Apple",
	"E4:8B:7F": "Apple",
	"E8:B2:AC": "Apple",
	"EC:35:86": "Apple",
	"F0:18:98": "Apple",
	"F0:99:B6": "Apple",
	"F4:0F:24": "Apple",
	"F4:F1:5A": "Apple",
	"F8:1E:DF": "Apple",
	"F8:27:93": "Apple",
	"F8:95:C7": "Apple",
	"F8:FF:C2": "Apple",

	"B8:27:EB": "Raspberry Pi",
	"DC:A6:32": "Raspberry Pi",
	"E4:5F:01": "Raspberry Pi",
	"00:1C:42": "Parallels",
	"00:50:56": "VMware",
	"00:0C:29": "VMware",
	"00:05:69": "VMware",
	"08:00:27": "VirtualBox",
}

// NewNetworkScanner returns a scanner configured with sensible defaults.
func NewNetworkScanner(subnet string) *NetworkScanner {
	return &NetworkScanner{
		Subnet:  subnet,
		Timeout: 2 * time.Second,
	}
}

// Scan performs a subnet scan and returns all discovered devices.
//
// The implementation is intentionally best-effort and avoids requiring raw
// socket privileges. For active detection it probes common TCP ports, then
// inspects the ARP cache to recover MAC addresses when possible.
func (ns *NetworkScanner) Scan() ([]DeviceInfo, error) {
	if ns.Subnet == "" {
		return nil, fmt.Errorf("scanner subnet is required")
	}

	timeout := ns.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	_, ipNet, err := net.ParseCIDR(ns.Subnet)
	if err != nil {
		return nil, fmt.Errorf("parse subnet %q: %w", ns.Subnet, err)
	}

	hosts, err := enumerateHosts(ipNet)
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return nil, nil
	}

	workerCount := 64
	if len(hosts) < workerCount {
		workerCount = len(hosts)
	}
	if workerCount < 1 {
		workerCount = 1
	}

	jobs := make(chan net.IP)
	results := make(chan DeviceInfo, len(hosts))

	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				device, ok := ns.scanHost(ip, timeout)
				if ok {
					results <- device
				}
			}
		}()
	}

	go func() {
		for _, ip := range hosts {
			jobs <- ip
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()

	devices := make([]DeviceInfo, 0, len(hosts))
	for device := range results {
		devices = append(devices, device)
	}

	sort.Slice(devices, func(i, j int) bool {
		return compareIPs(devices[i].IP, devices[j].IP) < 0
	})
	for i := range devices {
		sort.Slice(devices[i].Services, func(a, b int) bool {
			return devices[i].Services[a].Port < devices[i].Services[b].Port
		})
	}

	if ns.OutputFile != nil {
		if err := writeResultsJSON(ns.OutputFile, devices); err != nil {
			return devices, fmt.Errorf("write scan results: %w", err)
		}
	}

	return devices, nil
}

func (ns *NetworkScanner) scanHost(ip net.IP, timeout time.Duration) (DeviceInfo, bool) {
	services, reachable := ns.scanServices(ip, timeout)

	// Give the OS a short moment to populate its ARP/neighbor cache
	// after the connection attempts above.
	time.Sleep(50 * time.Millisecond)

	mac := lookupARP(ip)
	if len(mac) > 0 {
		reachable = true
	}
	if !reachable {
		return DeviceInfo{}, false
	}

	// Prefer reverse DNS; fall back to NetBIOS (nbtstat/NBNS) lookup when
	// reverse DNS does not return a name. NetBIOS lookup is a low-impact UDP
	// probe to port 137 and often yields useful hostnames for Windows-ish
	// or NetBIOS-speaking devices.
	hostname := reverseLookup(ip)
	if hostname == "" {
		// Try mDNS/Bonjour cache first (fast, uses existing Bonjour monitor if active).
		if h, ok := bonjour.LookupHostname(ip); ok && h != "" {
			hostname = h
		} else {
			// Fall back to NetBIOS NBSTAT probe if no mDNS hostname is available.
			if nb := netbiosLookup(ip); nb != "" {
				hostname = nb
			}
		}
	}
	vendor := vendorFromMAC(mac)

	return DeviceInfo{
		IP:       copyIP(ip),
		MAC:      mac,
		Hostname: hostname,
		Vendor:   vendor,
		Services: services,
	}, true
}

func (ns *NetworkScanner) scanServices(ip net.IP, timeout time.Duration) ([]ServiceInfo, bool) {
	portTimeout := perPortTimeout(timeout)
	services := make([]ServiceInfo, 0, len(commonPortOrder))
	reachable := false

	for _, port := range commonPortOrder {
		open, refused, service := probeTCP(ip, port, portTimeout)
		if refused {
			reachable = true
		}
		if open {
			reachable = true
			services = append(services, service)
		}
	}

	return services, reachable
}

func probeTCP(ip net.IP, port int, timeout time.Duration) (open bool, refused bool, service ServiceInfo) {
	meta, ok := commonServices[port]
	if !ok {
		meta = knownService{
			name:     "unknown",
			protocol: "tcp",
		}
	}

	service = ServiceInfo{
		Port:     port,
		Protocol: meta.protocol,
		Service:  meta.name,
	}

	address := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return false, isConnectionRefused(err), service
	}
	defer conn.Close()

	service.Version = sniffBanner(conn, port, ip)
	return true, false, service
}

func sniffBanner(conn net.Conn, port int, ip net.IP) string {
	_ = conn.SetDeadline(time.Now().Add(600 * time.Millisecond))

	switch port {
	case 22:
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		if n > 0 {
			return strings.TrimSpace(string(buf[:n]))
		}
	case 80, 631, 8080:
		_, _ = fmt.Fprintf(
			conn,
			"HEAD / HTTP/1.0\r\nHost: %s\r\nUser-Agent: netmon\r\nConnection: close\r\n\r\n",
			ip.String(),
		)

		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		if n > 0 {
			resp := string(buf[:n])
			for _, raw := range strings.Split(resp, "\n") {
				line := strings.TrimSpace(raw)
				lower := strings.ToLower(line)
				if strings.HasPrefix(lower, "server:") {
					return strings.TrimSpace(line[len("server:"):])
				}
			}
			if firstLine := strings.TrimSpace(strings.Split(resp, "\n")[0]); firstLine != "" {
				return firstLine
			}
		}
	case 3306:
		buf := make([]byte, 256)
		n, _ := conn.Read(buf)
		// MySQL greeting packet layout:
		// 3 bytes payload length + 1 byte sequence + 1 byte protocol + NUL-terminated version string.
		if n > 6 {
			versionField := buf[5:n]
			if idx := bytes.IndexByte(versionField, 0x00); idx > 0 {
				return string(versionField[:idx])
			}
		}
	}

	return ""
}

func enumerateHosts(ipNet *net.IPNet) ([]net.IP, error) {
	base := ipNet.IP.To4()
	if base == nil {
		return nil, fmt.Errorf("only IPv4 subnets are currently supported: %s", ipNet.String())
	}

	mask := net.IP(ipNet.Mask).To4()
	if mask == nil {
		return nil, fmt.Errorf("invalid IPv4 subnet mask for %s", ipNet.String())
	}

	network := base.Mask(ipNet.Mask)
	broadcast := make(net.IP, len(network))
	for i := range network {
		broadcast[i] = network[i] | ^mask[i]
	}

	ones, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("unexpected non-IPv4 mask size for %s", ipNet.String())
	}

	// /32 is a single host.
	if ones == 32 {
		return []net.IP{copyIP(network)}, nil
	}

	hosts := make([]net.IP, 0)
	current := copyIP(network)
	incrementIPv4(current)

	for ipNet.Contains(current) && compareIPs(current, broadcast) < 0 {
		hosts = append(hosts, copyIP(current))
		incrementIPv4(current)
	}

	// /31 has two usable addresses in many modern networks.
	if ones == 31 {
		return []net.IP{copyIP(network), copyIP(broadcast)}, nil
	}

	return hosts, nil
}

func incrementIPv4(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			return
		}
	}
}

func reverseLookup(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}

// netbiosEncodeName encodes a NetBIOS name according to RFC 1002 name encoding.
// The input name should be up to 15 bytes; it will be upper-cased and padded.
// The returned slice is the 32-byte encoded representation (without length
// prefix).
func netbiosEncodeName(name string) []byte {
	// Prepare a 16-byte NetBIOS name (padded with spaces)
	const nameLen = 16
	out := make([]byte, 0, 32)
	n := strings.ToUpper(name)
	if len(n) > 15 {
		n = n[:15]
	}
	// pad to 15 bytes then add the NetBIOS suffix 0x00 (workstation service)
	buf := make([]byte, nameLen)
	copy(buf, n)
	for i := len(n); i < 15; i++ {
		buf[i] = ' '
	}
	// suffix byte 0x00
	buf[15] = 0x00

	// For each byte, emit two ASCII uppercase letters 'A' + highNibble and 'A' + lowNibble
	for _, b := range buf {
		hi := (b >> 4) & 0x0F
		lo := b & 0x0F
		out = append(out, 'A'+hi)
		out = append(out, 'A'+lo)
	}
	return out
}

// netbiosLookup attempts a NetBIOS Node Status (NBSTAT) query to UDP/137 and
// parses the NBSTAT (type 0x0021) response according to RFC1002 to extract the
// NetBIOS workstation name when available. This implementation first performs
// a proper DNS-style parsing of the reply and looks for NBSTAT RRs; if found,
// it decodes the name table entries (15-byte names + 1 type + 1 flags) and
// returns the best candidate. If parsing fails, it falls back to a conservative
// heuristic scan.
func netbiosLookup(ip net.IP) string {
	if ip == nil {
		return ""
	}

	raddr := &net.UDPAddr{IP: ip, Port: 137}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Build NBNS node status query (question type NBSTAT = 0x0021).
	// Header: Transaction ID (2), Flags(2), QDCOUNT(2)=1, ANCOUNT(2)=0, NSCOUNT(2)=0, ARCOUNT(2)=0
	txid := uint16(time.Now().UnixNano() & 0xffff)
	header := []byte{
		byte(txid >> 8), byte(txid & 0xff),
		0x00, 0x00, // flags
		0x00, 0x01, // qdcount
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
	}

	// Question name: encoded NetBIOS name (32 bytes) prefixed by length byte (0x20)
	encoded := netbiosEncodeName("*") // wildcard name commonly used for NBSTAT
	// The encoded name is always 32 bytes per NetBIOS name encoding; use the
	// fixed 0x20 length byte rather than casting dynamic lengths to avoid
	// integer conversion issues flagged by static analyzers.
	q := make([]byte, 0, 1+len(encoded)+1+4)
	q = append(q, 0x20)
	q = append(q, encoded...)
	q = append(q, 0x00)       // end of name
	q = append(q, 0x00, 0x21) // type NBSTAT (0x0021)
	q = append(q, 0x00, 0x01) // class IN

	packet := append(header, q...)

	// Send packet and wait for response
	_ = conn.SetWriteDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := conn.Write(packet); err != nil {
		return ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	resp := make([]byte, 1500)
	n, err := conn.Read(resp)
	if err != nil || n == 0 {
		return ""
	}
	resp = resp[:n]

	// Basic bounds check for DNS header
	if len(resp) < 12 {
		return ""
	}

	// ANCOUNT is at bytes 6..7
	ancount := int(binary.BigEndian.Uint16(resp[6:8]))
	if ancount == 0 {
		// nothing to parse
		// fall through to heuristic below
	} else {
		// Skip question section to reach answer section.
		off := 12
		// walk the question name until zero terminator
		for off < len(resp) && resp[off] != 0 {
			// if pointer appears here (unlikely in question) handle conservatively
			if (resp[off] & 0xC0) == 0xC0 {
				// pointer: skip two bytes and break
				if off+1 < len(resp) {
					off += 2
				} else {
					return ""
				}
				break
			}
			off++
		}
		off++ // skip null terminator
		// skip qtype (2) and qclass (2)
		off += 4

		// Iterate answers
		for i := 0; i < ancount && off+10 <= len(resp); i++ {
			// Skip the answer name (could be pointer)
			if resp[off]&0xC0 == 0xC0 {
				// name is a pointer (2 bytes)
				off += 2
			} else {
				// labels until null
				for off < len(resp) && resp[off] != 0 {
					off++
				}
				off++ // skip null
			}
			if off+10 > len(resp) {
				break
			}
			typ := binary.BigEndian.Uint16(resp[off : off+2])
			//class := binary.BigEndian.Uint16(resp[off+2 : off+4])
			//ttl := binary.BigEndian.Uint32(resp[off+4 : off+8])
			rdlen := int(binary.BigEndian.Uint16(resp[off+8 : off+10]))
			off += 10

			if off+rdlen > len(resp) {
				break
			}

			if typ == 0x0021 && rdlen > 0 {
				// NBSTAT RDATA parsing. Structure:
				// 1 byte: number of names (N)
				// N * 18 bytes: 15-byte name, 1-byte name type, 1-byte flags
				rdata := resp[off : off+rdlen]
				if len(rdata) >= 1 {
					nnames := int(rdata[0])
					pos := 1
					// ensure we have enough bytes
					fallback := ""
					for j := 0; j < nnames; j++ {
						if pos+18 > len(rdata) {
							break
						}
						nameBytes := rdata[pos : pos+15]
						nameType := rdata[pos+15]
						// flags := rdata[pos+16] // flags can be inspected if needed
						pos += 18

						name := strings.TrimRight(string(nameBytes), " \x00")
						name = strings.TrimSpace(name)
						if name == "" {
							continue
						}

						if isLikelyHostname(name) {
							// Prefer certain name types (workstation 0x00, file-server 0x20)
							if nameType == 0x00 || nameType == 0x20 {
								return name
							}
							// keep the first plausible non-preferred name as a fallback
							if fallback == "" {
								fallback = name
							}
							// continue searching for a preferred type
						}
					}
					if fallback != "" {
						return fallback
					}
				}
			}
			off += rdlen
		}
	}

	// Fallback heuristic: scan the response for ASCII substrings like before.
	isNameChar := func(b byte) bool {
		// allow printable characters commonly found in hostnames/NetBIOS names
		if b >= 'A' && b <= 'Z' {
			return true
		}
		if b >= 'a' && b <= 'z' {
			return true
		}
		if b >= '0' && b <= '9' {
			return true
		}
		switch b {
		case '-', '_':
			return true
		}
		return false
	}

	for i := 0; i < len(resp); i++ {
		// collect a run of printable bytes
		if !isNameChar(resp[i]) {
			continue
		}
		j := i
		for j < len(resp) && isNameChar(resp[j]) && j-i <= 15 {
			j++
		}
		length := j - i
		if length >= 1 && length <= 15 {
			candidate := string(resp[i:j])
			// ignore purely numeric results
			allDigits := true
			for k := 0; k < len(candidate); k++ {
				if candidate[k] < '0' || candidate[k] > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				i = j
				continue
			}
			// Trim spaces and return
			candidate = strings.TrimSpace(candidate)
			if candidate != "" {
				return candidate
			}
		}
		i = j
	}

	return ""
}

// isLikelyHostname applies a few simple checks to decide whether a NetBIOS
// name is plausibly a workstation/host name we should present.
func isLikelyHostname(name string) bool {
	if name == "" {
		return false
	}
	// disallow names that are all digits
	allDigits := true
	for _, r := range name {
		if r < '0' || r > '9' {
			allDigits = false
			break
		}
	}
	if allDigits {
		return false
	}
	// disallow excessively short or long names
	if len(name) < 1 || len(name) > 15 {
		return false
	}
	// ensure characters are reasonable (letters, digits, -, _)
	for _, r := range name {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func lookupARP(ip net.IP) net.HardwareAddr {
	if runtime.GOOS == "linux" {
		if mac, ok := lookupARPWithIPNeigh(ip); ok {
			return mac
		}
		if mac, ok := lookupARPWithARP(ip); ok {
			return mac
		}
		return nil
	}

	if mac, ok := lookupARPWithARP(ip); ok {
		return mac
	}
	if mac, ok := lookupARPWithIPNeigh(ip); ok {
		return mac
	}
	return nil
}

func lookupARPWithARP(ip net.IP) (net.HardwareAddr, bool) {
	// Validate IP before invoking external command to avoid passing unexpected
	// or malformed input to the subprocess.
	if ip == nil {
		return nil, false
	}
	ipStr := ip.String()
	if net.ParseIP(ipStr) == nil {
		return nil, false
	}

	if _, err := exec.LookPath("arp"); err != nil {
		return nil, false
	}

	// Use exec.Command with validated ipStr as a single argument (no shell)
	// to avoid injection issues.
	// #nosec G204 -- ipStr is validated above (parsed as an IP), so this use
	// of exec.Command does not accept attacker-controlled shell input.
	cmd := exec.Command("arp", "-n", ipStr)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, false
	}

	text := strings.ToLower(string(out))
	if strings.Contains(text, "no entry") || strings.Contains(text, "incomplete") {
		return nil, false
	}

	mac := extractMACFromText(string(out))
	return mac, len(mac) > 0
}

func lookupARPWithIPNeigh(ip net.IP) (net.HardwareAddr, bool) {
	// Validate IP before invoking external command to avoid passing unexpected
	// or malformed input to the subprocess.
	if ip == nil {
		return nil, false
	}
	ipStr := ip.String()
	if net.ParseIP(ipStr) == nil {
		return nil, false
	}

	if _, err := exec.LookPath("ip"); err != nil {
		return nil, false
	}

	// Use exec.Command with validated ipStr as a single argument (no shell)
	// to avoid injection issues.
	// #nosec G204 -- ipStr is validated above (parsed as an IP), so this use
	// of exec.Command does not accept attacker-controlled shell input.
	cmd := exec.Command("ip", "neigh", "show", ipStr)
	out, err := cmd.CombinedOutput()
	if err != nil && len(out) == 0 {
		return nil, false
	}

	text := strings.ToLower(string(out))
	if strings.Contains(text, "failed") || strings.Contains(text, "incomplete") {
		return nil, false
	}

	mac := extractMACFromText(string(out))
	return mac, len(mac) > 0
}

func extractMACFromText(text string) net.HardwareAddr {
	for _, token := range strings.Fields(text) {
		clean := strings.Trim(token, "[](){}<>,;")
		clean = strings.TrimSuffix(clean, ".")
		clean = strings.ReplaceAll(clean, "-", ":")
		mac, err := net.ParseMAC(clean)
		if err == nil {
			return mac
		}
	}
	return nil
}

func vendorFromMAC(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}

	parts := strings.Split(strings.ToUpper(mac.String()), ":")
	if len(parts) < 3 {
		return ""
	}

	prefix := strings.Join(parts[:3], ":")
	return vendorPrefixes[prefix]
}

func perPortTimeout(total time.Duration) time.Duration {
	if total <= 0 {
		return 250 * time.Millisecond
	}

	timeout := total / 6
	if timeout < 200*time.Millisecond {
		timeout = 200 * time.Millisecond
	}
	if timeout > 750*time.Millisecond {
		timeout = 750 * time.Millisecond
	}
	return timeout
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "connection refused") || strings.Contains(msg, "actively refused")
}

func compareIPs(a, b net.IP) int {
	a4 := a.To4()
	b4 := b.To4()
	if a4 == nil || b4 == nil {
		return strings.Compare(a.String(), b.String())
	}
	return bytes.Compare(a4, b4)
}

func copyIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	dst := make(net.IP, len(ip))
	copy(dst, ip)
	return dst
}

func writeResultsJSON(file *os.File, devices []DeviceInfo) error {
	type serializableService struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
		Version  string `json:"version,omitempty"`
	}

	type serializableDevice struct {
		IP       string                `json:"ip"`
		MAC      string                `json:"mac,omitempty"`
		Hostname string                `json:"hostname,omitempty"`
		Vendor   string                `json:"vendor,omitempty"`
		Services []serializableService `json:"services,omitempty"`
	}

	out := make([]serializableDevice, 0, len(devices))
	for _, device := range devices {
		item := serializableDevice{
			IP:       device.IP.String(),
			Hostname: device.Hostname,
			Vendor:   device.Vendor,
		}
		if len(device.MAC) > 0 {
			item.MAC = device.MAC.String()
		}
		if len(device.Services) > 0 {
			item.Services = make([]serializableService, 0, len(device.Services))
			for _, service := range device.Services {
				item.Services = append(item.Services, serializableService{
					Port:     service.Port,
					Protocol: service.Protocol,
					Service:  service.Service,
					Version:  service.Version,
				})
			}
		}
		out = append(out, item)
	}

	payload, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}

	if _, err := file.Write(payload); err != nil {
		return err
	}
	_, err = file.WriteString("\n")
	return err
}
