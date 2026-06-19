package hkdf

import (
	"crypto/hkdf"
	"hash"
)

// GetBuffer, if non-nil, is used instead of make([]byte, size) for temporary
// scratch buffers within this package. Set via the parent tls package's
// SetBufferPool.
var GetBuffer func(int) []byte

// PutBuffer, if non-nil, returns a scratch buffer obtained via GetBuffer.
var PutBuffer func([]byte)

func Extract[H hash.Hash](h func() H, secret, salt []byte) []byte {
	res, err := hkdf.Extract(h, secret, salt)
	if err != nil {
		panic(err)
	}

	return res
}

func Expand[H hash.Hash](h func() H, pseudorandomKey []byte, info string, keyLength int) []byte {
	res, err := hkdf.Expand(h, pseudorandomKey, info, keyLength)
	if err != nil {
		panic(err)
	}

	return res
}
