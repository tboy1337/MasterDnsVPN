// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import "testing"

func TestEncodeLowerBase32UsesOnlyLowerAlphaNumeric(t *testing.T) {
	encoded := EncodeLowerBase32([]byte("MasterDnsVPN-123"))
	if encoded == "" {
		t.Fatal("encoded string must not be empty")
	}

	for i := 0; i < len(encoded); i++ {
		ch := encoded[i]
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		if ch >= '2' && ch <= '7' {
			continue
		}
		t.Fatalf("unexpected character at index %d: %q", i, ch)
	}
}

func TestDecodeLowerBase32RoundTrip(t *testing.T) {
	original := []byte{0x00, 0x01, 0x02, 0x10, 0x20, 0x30, 0x40, 0xFE, 0xFF}
	encoded := EncodeLowerBase32(original)

	decoded, err := DecodeLowerBase32([]byte(encoded))
	if err != nil {
		t.Fatalf("DecodeLowerBase32 returned error: %v", err)
	}
	if len(decoded) != len(original) {
		t.Fatalf("unexpected decoded length: got=%d want=%d", len(decoded), len(original))
	}
	for i := range original {
		if decoded[i] != original[i] {
			t.Fatalf("unexpected decoded byte at %d: got=%d want=%d", i, decoded[i], original[i])
		}
	}
}

func TestDecodeLowerBase32RejectsInvalidCharacters(t *testing.T) {
	invalidSamples := [][]byte{
		[]byte("ABCDEF"),
		[]byte("abc1"),
		[]byte("abc-123"),
		[]byte("abc="),
	}

	for _, sample := range invalidSamples {
		if _, err := DecodeLowerBase32(sample); err == nil {
			t.Fatalf("DecodeLowerBase32 should reject %q", sample)
		}
	}
}
