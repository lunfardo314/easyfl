package easyfl

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// Uint64FromBytes takes any 8 or less bytes, padds with 0 prefix up to 8 bytes size and makes uin64 big-endian
func Uint64FromBytes(data []byte) (uint64, error) {
	if len(data) > 8 {
		return 0, fmt.Errorf("Uint64FromBytes: can't be more than 8 bytes")
	}
	var paddedData [8]byte
	copy(paddedData[8-len(data):], data)

	return binary.BigEndian.Uint64(paddedData[:]), nil
}

func MustUint64FromBytes(data []byte) uint64 {
	ret, err := Uint64FromBytes(data)
	AssertNoError(err)
	return ret
}

// TrimLeadingZeroBytes returns sub-slice without leading zeroes
func TrimLeadingZeroBytes(data []byte) []byte {
	for i := 0; i < len(data); i++ {
		if data[i] != 0 {
			return data[i:]
		}
	}
	return nil
}

func Uint64To8Bytes(v uint64) (ret [8]byte) {
	binary.BigEndian.PutUint64(ret[:], v)
	return
}

func TrimmedLeadingZeroUint64(v uint64) []byte {
	ret := Uint64To8Bytes(v)
	return TrimLeadingZeroBytes(ret[:])
}

func TrimmedLeadingZeroUint64Hex(v uint64) string {
	return hex.EncodeToString(TrimmedLeadingZeroUint64(v))
}
