package tls

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"io"
	"sync"

	"github.com/refraction-networking/utls/internal/hkdf"
	"github.com/refraction-networking/utls/internal/tls13"
)

// BytesBuffer is the interface used by Conn.hand and Conn.rawInput.
// *bytes.Buffer and *pool.PooledBuffer both satisfy it.
type BytesBuffer interface {
	Len() int
	Bytes() []byte
	Next(n int) []byte
	Read(p []byte) (n int, err error)
	Write(p []byte) (int, error)
	ReadFrom(r io.Reader) (int64, error)
	Grow(n int)
}

// NewBytesBufferFunc, if set, provides pooled BytesBuffer instances.
// Set by dae's init() to inject *pool.PooledBuffer.
var NewBytesBufferFunc func() BytesBuffer

// NewBytesBuffer returns a BytesBuffer: pooled if NewBytesBufferFunc is set,
// otherwise *bytes.Buffer.
func NewBytesBuffer() BytesBuffer {
	if NewBytesBufferFunc != nil {
		return NewBytesBufferFunc()
	}
	return new(bytes.Buffer)
}

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
	GetBuffer = get
	PutBuffer = put
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

// --- Hash object pooling ---

// SHA-256 and SHA-384 pools (the only hashes used in TLS 1.3).
var (
	sha256HashPool = sync.Pool{New: func() any { return sha256.New() }}
	sha384HashPool = sync.Pool{New: func() any { return sha512.New384() }}
)

// PooledHashNew returns a hash from the pool for the given crypto.Hash,
// or falls back to h.New() for unsupported types.
func PooledHashNew(h crypto.Hash) hash.Hash {
	switch h {
	case crypto.SHA256:
		return sha256HashPool.Get().(hash.Hash)
	case crypto.SHA384:
		return sha384HashPool.Get().(hash.Hash)
	default:
		return h.New()
	}
}

// PooledHashPut resets h and returns it to the appropriate pool based on
// its Size() (32 = SHA-256, 48 = SHA-384). Unknown sizes are no-ops.
func PooledHashPut(h hash.Hash) {
	if h == nil {
		return
	}
	switch h.Size() {
	case 32:
		h.Reset()
		sha256HashPool.Put(h)
	case 48:
		h.Reset()
		sha384HashPool.Put(h)
	}
}
