package wol

import (
	"bytes"
	"net"
	"testing"
	"time"
)

func TestParseMACAddress_Valid(t *testing.T) {
	t.Parallel()

	raw := "00:11:22:33:44:55"
	mac, err := ParseMACAddress(raw)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(mac) != macLength {
		t.Fatalf("expected mac length %d, got %d", macLength, len(mac))
	}
	expected := "00:11:22:33:44:55"
	if mac.String() != expected {
		t.Fatalf("expected %s, got %s", expected, mac.String())
	}
}

func TestParseMACAddress_InvalidEmpty(t *testing.T) {
	t.Parallel()

	if _, err := ParseMACAddress(""); err == nil {
		t.Fatalf("expected error for empty MAC, got nil")
	}
}

func TestBuildMagicPacket_Valid(t *testing.T) {
	t.Parallel()

	mac, _ := ParseMACAddress("01:23:45:67:89:ab")
	packet, err := BuildMagicPacket(mac)
	if err != nil {
		t.Fatalf("unexpected error building magic packet: %v", err)
	}

	expectedLen := syncBytes + repetitions*macLength
	if len(packet) != expectedLen {
		t.Fatalf("expected packet length %d, got %d", expectedLen, len(packet))
	}

	// First syncBytes bytes must be 0xFF
	for i := 0; i < syncBytes; i++ {
		if packet[i] != 0xFF {
			t.Fatalf("expected sync byte 0xFF at pos %d, got %#x", i, packet[i])
		}
	}

	// The remainder should be repetitions of the MAC
	for r := 0; r < repetitions; r++ {
		start := syncBytes + r*macLength
		if !bytes.Equal(packet[start:start+macLength], mac) {
			t.Fatalf("magic packet repetition %d did not match mac: got %v want %v", r, packet[start:start+macLength], mac)
		}
	}
}

func TestBuildMagicPacket_InvalidLen(t *testing.T) {
	t.Parallel()

	// 5-byte MAC is invalid
	bad := net.HardwareAddr{1, 2, 3, 4, 5}
	if _, err := BuildMagicPacket(bad); err == nil {
		t.Fatalf("expected error for invalid mac length, got nil")
	}
}

func TestSendMagicPacket_LocalUDP(t *testing.T) {
	// This test binds a local UDP listener and sends a magic packet to it.
	// It verifies that SendMagicPacket successfully sends the packet and the
	// listener receives data matching the magic packet layout.
	t.Parallel()

	ln, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer ln.Close()

	port := ln.LocalAddr().(*net.UDPAddr).Port

	recvCh := make(chan []byte, 1)
	errCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 2048)
		_ = ln.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, _, err := ln.ReadFromUDP(buf)
		if err != nil {
			errCh <- err
			return
		}
		recv := make([]byte, n)
		copy(recv, buf[:n])
		recvCh <- recv
	}()

	mac, _ := ParseMACAddress("de:ad:be:ef:00:01")

	// Send to localhost and chosen port
	if err := SendMagicPacket(mac, "127.0.0.1", port); err != nil {
		t.Fatalf("SendMagicPacket returned error: %v", err)
	}

	select {
	case err := <-errCh:
		t.Fatalf("listener error: %v", err)
	case recv := <-recvCh:
		// Validate received packet matches expected magic packet
		expected, err := BuildMagicPacket(mac)
		if err != nil {
			t.Fatalf("failed to build expected packet: %v", err)
		}
		if !bytes.Equal(recv, expected) {
			t.Fatalf("received packet did not match expected magic packet; len got=%d want=%d", len(recv), len(expected))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for packet")
	}
}
