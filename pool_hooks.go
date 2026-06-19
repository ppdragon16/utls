package tls

import (
	"github.com/refraction-networking/utls/internal/hkdf"
	"github.com/refraction-networking/utls/internal/tls13"
)

// SetBufferPool injects external buffer get/put functions into all uTLS
// internal packages that perform short-lived allocations. When non-nil,
// these functions replace make([]byte, size) at hot allocation sites,
// enabling buffer reuse via an external pool (e.g., sync.Pool or a
// tiered size-class allocator).
//
// Call once before creating any uTLS connections:
//
//	utls.SetBufferPool(pool.GetBuffer, pool.PutBuffer)
//
// Passing nil for both get and put restores the default make([]byte, n)
// behavior.
func SetBufferPool(get func(int) []byte, put func([]byte)) {
	tls13.GetBuffer = get
	tls13.PutBuffer = put
	hkdf.GetBuffer = get
	hkdf.PutBuffer = put
}

// getBuf returns a buffer of the given size from the injected pool,
// or falls back to make() if no pool is configured.
func getBuf(size int) []byte {
	if GetBuffer != nil {
		return GetBuffer(size)
	}
	return make([]byte, size)
}

// putBuf returns a buffer to the injected pool, if one is configured.
func putBuf(buf []byte) {
	if PutBuffer != nil {
		PutBuffer(buf)
	}
}

// GetBuffer is the hook for external buffer allocation.
// Set via SetBufferPool.
var GetBuffer func(int) []byte

// PutBuffer is the hook for external buffer deallocation.
// Set via SetBufferPool.
var PutBuffer func([]byte)
