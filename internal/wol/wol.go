package wol

import (
	"errors"
	"fmt"
	"math"
	"net"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	// DefaultBroadcast is the conventional limited broadcast address used for
	// Wake-on-LAN packets.
	DefaultBroadcast = "255.255.255.255"

	// DefaultPort is the conventional UDP port for Wake-on-LAN.
	DefaultPort = 9

	macLength    = 6
	syncBytes    = 6
	repetitions  = 16
	writeTimeout = 3 * time.Second
)

// ParseMACAddress parses and validates a hardware address for Wake-on-LAN use.
func ParseMACAddress(raw string) (net.HardwareAddr, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("MAC address is required")
	}

	mac, err := net.ParseMAC(raw)
	if err != nil {
		return nil, fmt.Errorf("parse MAC address: %w", err)
	}

	if len(mac) != macLength {
		return nil, fmt.Errorf("expected %d-byte MAC address, got %d bytes", macLength, len(mac))
	}

	return mac, nil
}

// BuildMagicPacket builds a Wake-on-LAN magic packet for the provided MAC
// address. The packet format is:
//
//	6 bytes of 0xFF
//	16 repetitions of the target MAC address
func BuildMagicPacket(mac net.HardwareAddr) ([]byte, error) {
	if len(mac) != macLength {
		return nil, fmt.Errorf("invalid MAC address length: got %d bytes, want %d", len(mac), macLength)
	}

	packet := make([]byte, syncBytes+(repetitions*macLength))

	for i := 0; i < syncBytes; i++ {
		packet[i] = 0xFF
	}

	offset := syncBytes
	for i := 0; i < repetitions; i++ {
		copy(packet[offset:offset+macLength], mac)
		offset += macLength
	}

	return packet, nil
}

// WakeOnLAN sends a Wake-on-LAN magic packet using the default broadcast
// address and default UDP port.
func WakeOnLAN(mac net.HardwareAddr) error {
	return SendMagicPacket(mac, DefaultBroadcast, DefaultPort)
}

// SendMagicPacket sends a Wake-on-LAN magic packet to the given broadcast
// address and UDP port.
func SendMagicPacket(mac net.HardwareAddr, broadcastAddr string, port int) error {
	if strings.TrimSpace(broadcastAddr) == "" {
		broadcastAddr = DefaultBroadcast
	}

	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid UDP port %d", port)
	}

	packet, err := BuildMagicPacket(mac)
	if err != nil {
		return err
	}

	udpAddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(broadcastAddr, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		return fmt.Errorf("dial UDP: %w", err)
	}
	defer conn.Close()

	if err := enableBroadcast(conn); err != nil {
		return fmt.Errorf("enable broadcast on socket: %w", err)
	}

	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}

	n, err := conn.Write(packet)
	if err != nil {
		return fmt.Errorf("send magic packet: %w", err)
	}
	if n != len(packet) {
		return fmt.Errorf("short write: wrote %d of %d bytes", n, len(packet))
	}

	return nil
}

// enableBroadcast enables SO_BROADCAST on the underlying socket so packets can
// be sent to broadcast destinations like 255.255.255.255.
func enableBroadcast(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var sockErr error
	controlErr := rawConn.Control(func(fd uintptr) {
		// Convert uintptr to int safely: check bounds to avoid overflow
		if fd > uintptr(math.MaxInt) {
			sockErr = fmt.Errorf("file descriptor value %d overflows int", fd)
			return
		}
		// safe to cast now
		sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
	})
	if controlErr != nil {
		return controlErr
	}

	return sockErr
}
