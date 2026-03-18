package scanner

import (
	"net"
	"strings"
	"testing"
	"time"

	airport "inet-tool-cli/internal/airport"
	bonjour "inet-tool-cli/internal/bonjour"
)

func TestEnumerateHosts_IPV4Ranges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		cidr     string
		expected int
	}{
		{"192.0.2.0/30", 2}, // /30 -> two usable hosts
		{"192.0.2.1/32", 1}, // /32 -> single host
		{"192.0.2.0/31", 2}, // /31 -> two addresses per implementation
	}

	for _, tt := range tests {
		_, ipNet, err := net.ParseCIDR(tt.cidr)
		if err != nil {
			t.Fatalf("parse cidr %q: %v", tt.cidr, err)
		}
		hosts, err := enumerateHosts(ipNet)
		if err != nil {
			t.Fatalf("enumerateHosts(%q) unexpected error: %v", tt.cidr, err)
		}
		if len(hosts) != tt.expected {
			t.Fatalf("enumerateHosts(%q) expected %d hosts, got %d", tt.cidr, tt.expected, len(hosts))
		}
	}
}

func TestPerPortTimeout_Boundaries(t *testing.T) {
	t.Parallel()

	// total <= 0 uses default lower bound behavior
	d := perPortTimeout(0)
	if d < 200*time.Millisecond {
		t.Fatalf("perPortTimeout(0) returned %v, expected >= 200ms", d)
	}

	// very small total
	d = perPortTimeout(100 * time.Millisecond)
	if d < 200*time.Millisecond {
		t.Fatalf("perPortTimeout(100ms) returned %v, expected >= 200ms", d)
	}

	// very large total should be clamped
	d = perPortTimeout(10 * time.Second)
	if d > 750*time.Millisecond {
		t.Fatalf("perPortTimeout(10s) returned %v, expected <= 750ms", d)
	}

	// reasonable split
	total := 600 * time.Millisecond
	d = perPortTimeout(total)
	if d < 200*time.Millisecond || d > 750*time.Millisecond {
		t.Fatalf("perPortTimeout(%v) returned %v out of expected bounds", total, d)
	}
}

func TestCompareIPs_V4AndV6(t *testing.T) {
	t.Parallel()

	a := net.ParseIP("192.0.2.1")
	b := net.ParseIP("192.0.2.2")
	if compareIPs(a, b) >= 0 {
		t.Fatalf("expected a < b for %v, %v", a, b)
	}

	// IPv6 lexical comparison fallback
	ia := net.ParseIP("2001:db8::1")
	ib := net.ParseIP("2001:db8::2")
	if compareIPs(ia, ib) >= 0 {
		t.Fatalf("expected ia < ib for %v, %v", ia, ib)
	}
}

func TestVendorFromMAC_KnownPrefix(t *testing.T) {
	t.Parallel()

	mac, _ := net.ParseMAC("00:03:93:aa:bb:cc")
	v := vendorFromMAC(mac)
	if v == "" {
		t.Fatalf("expected vendor for %s to be non-empty", mac)
	}
	if !strings.Contains(strings.ToLower(v), "apple") {
		t.Fatalf("expected vendor to mention apple, got %q", v)
	}
}

func TestExtractMACFromText_VariousFormats(t *testing.T) {
	t.Parallel()

	cases := []struct {
		text     string
		expected string
	}{
		{"ether 00:11:22:33:44:55", "00:11:22:33:44:55"},
		{"HWaddr 00-11-22-33-44-55", "00:11:22:33:44:55"},
		{"prefix [00:11:22:33:44:55] tail", "00:11:22:33:44:55"},
		{"random 00:11:22:33:44:55.", "00:11:22:33:44:55"},
	}

	for _, c := range cases {
		mac := extractMACFromText(c.text)
		if mac == nil {
			t.Fatalf("expected to extract mac from %q", c.text)
		}
		if mac.String() != c.expected {
			t.Fatalf("extracted mac %q does not match expected %q for input %q", mac.String(), c.expected, c.text)
		}
	}
}

func TestBonjourMonitor_NewAndDefaults(t *testing.T) {
	t.Parallel()

	mon, err := bonjour.NewBonjourMonitor()
	if err != nil {
		t.Fatalf("NewBonjourMonitor returned error: %v", err)
	}
	if mon == nil {
		t.Fatalf("NewBonjourMonitor returned nil monitor")
	}

	// Verify default service value is as expected
	if mon.Service() != bonjour.DefaultBrowseService {
		t.Fatalf("expected default browse service %q, got %q", bonjour.DefaultBrowseService, mon.Service())
	}
}

func TestAirport_IsAppleOUI(t *testing.T) {
	t.Parallel()

	mac1, _ := net.ParseMAC("00:03:93:aa:bb:cc") // known Apple OUI in list
	if !airport.IsAppleOUI(mac1) {
		t.Fatalf("expected %s to be recognized as Apple OUI", mac1)
	}

	mac2, _ := net.ParseMAC("de:ad:be:ef:00:01")
	if airport.IsAppleOUI(mac2) {
		t.Fatalf("expected %s to NOT be recognized as Apple OUI", mac2)
	}
}
