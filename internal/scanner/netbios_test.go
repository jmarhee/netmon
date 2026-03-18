package scanner

import (
	"bytes"
	"testing"
)

// decodeNetbiosEncoded reverses the netbiosEncodeName transformation for tests:
// it takes the 32-byte encoded form and returns the 16 raw bytes.
func decodeNetbiosEncoded(encoded []byte) ([]byte, error) {
	if len(encoded) != 32 {
		return nil, ErrInvalidNetbiosEncodedLength
	}
	out := make([]byte, 16)
	for i := 0; i < 16; i++ {
		hi := encoded[i*2]
		lo := encoded[i*2+1]
		// Clamp hi/lo to the expected 'A'..'P' range so decoding is
		// deterministic and staticcheck does not flag an empty branch.
		if hi < 'A' {
			hi = 'A'
		} else if hi > 'P' {
			hi = 'P'
		}
		if lo < 'A' {
			lo = 'A'
		} else if lo > 'P' {
			lo = 'P'
		}
		out[i] = ((hi - 'A') << 4) | (lo - 'A')
	}
	return out, nil
}

// ErrInvalidNetbiosEncodedLength is a local test sentinel error used only in tests.
var ErrInvalidNetbiosEncodedLength = &testError{"invalid encoded length"}

type testError struct{ s string }

func (e *testError) Error() string { return e.s }

func TestNetBIOSEncodeName_Simple(t *testing.T) {
	t.Parallel()

	encoded := netbiosEncodeName("MYHOST")
	if len(encoded) != 32 {
		t.Fatalf("expected encoded length 32, got %d", len(encoded))
	}

	raw, err := decodeNetbiosEncoded(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// Expect the first 6 bytes to be 'M','Y','H','O','S','T', padded to 15 with spaces,
	// and the 16th byte (suffix) to be 0x00.
	expected := make([]byte, 16)
	copy(expected, []byte("MYHOST"))
	for i := 6; i < 15; i++ {
		expected[i] = ' '
	}
	expected[15] = 0x00

	if !bytes.Equal(raw, expected) {
		t.Fatalf("decoded bytes do not match expected\n got: %v\nwant: %v", raw, expected)
	}
}

func TestNetBIOSEncodeName_Truncation(t *testing.T) {
	t.Parallel()

	// Make a name longer than 15 chars; it should be truncated to 15.
	long := "ABCDEFGHIJKLMNOPQRST"
	encoded := netbiosEncodeName(long)
	if len(encoded) != 32 {
		t.Fatalf("expected encoded length 32, got %d", len(encoded))
	}

	raw, err := decodeNetbiosEncoded(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// raw should contain the first 15 uppercased characters of 'long', then 0x00
	expected := make([]byte, 16)
	copy(expected, []byte(long[:15]))
	expected[15] = 0x00

	if !bytes.Equal(raw, expected) {
		t.Fatalf("decoded truncated bytes do not match expected\n got: %v\nwant: %v", raw, expected)
	}
}

func TestNetBIOSEncodeName_Wildcard(t *testing.T) {
	t.Parallel()

	// The code uses "*" as a wildcard in NBSTAT queries; ensure encoding/decoding
	// round-trips (with uppercase/padding behavior).
	encoded := netbiosEncodeName("*")
	if len(encoded) != 32 {
		t.Fatalf("expected encoded length 32, got %d", len(encoded))
	}

	raw, err := decodeNetbiosEncoded(encoded)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}

	// The first byte should be '*' uppercased (still '*'), rest padded with spaces,
	// final suffix is 0x00.
	expected := make([]byte, 16)
	expected[0] = '*'
	for i := 1; i < 15; i++ {
		expected[i] = ' '
	}
	expected[15] = 0x00

	if !bytes.Equal(raw, expected) {
		t.Fatalf("decoded wildcard bytes do not match expected\n got: %v\nwant: %v", raw, expected)
	}
}
