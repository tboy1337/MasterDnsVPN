// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package basecodec

import (
	"encoding/base32"
	"errors"
)

var (
	ErrInvalidLowerBase32 = errors.New("invalid lower base32 data")

	lowerBase32Encoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)
)

func EncodeLowerBase32(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	dst := make([]byte, lowerBase32Encoding.EncodedLen(len(data)))
	lowerBase32Encoding.Encode(dst, data)
	return string(dst)
}

func DecodeLowerBase32(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return []byte{}, nil
	}

	dst := make([]byte, lowerBase32Encoding.DecodedLen(len(data)))
	n, err := lowerBase32Encoding.Decode(dst, data)
	if err != nil {
		return nil, ErrInvalidLowerBase32
	}

	return dst[:n], nil
}
