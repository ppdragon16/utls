// Package hkdf implements HKDF (RFC 5869) with buffer and hash pool support.
//
// Unlike crypto/hkdf, this implementation avoids internal heap allocations
// by using externally injected buffer get/put functions and pooled hash
// objects. The TLS 1.3 key schedule calls Extract/Expand ~16 times per
// handshake; each call previously allocated 3+ hashes via stdlib.
package hkdf

import (
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	fips140 "hash"
	"sync"
)

// GetBuffer, if non-nil, is used instead of make([]byte, size) for temporary
// scratch buffers. Set via the parent tls package's SetBufferPool.
var GetBuffer func(int) []byte

// PutBuffer, if non-nil, returns a scratch buffer obtained via GetBuffer.
var PutBuffer func([]byte)

// Hash pool: SHA-256 and SHA-384 are the only hashes used in TLS 1.3.
var (
	sha256Pool = sync.Pool{New: func() any { return sha256.New() }}
	sha384Pool = sync.Pool{New: func() any { return sha512.New384() }}
)

type hashKind uint8

const (
	hashSHA256 hashKind = iota // Size = 32, BlockSize = 64
	hashSHA384                 // Size = 48, BlockSize = 128
)

func (k hashKind) size() int {
	switch k {
	case hashSHA256:
		return 32
	case hashSHA384:
		return 48
	default:
		panic("hkdf: unknown hash kind")
	}
}

func (k hashKind) blockSize() int {
	switch k {
	case hashSHA256:
		return 64
	case hashSHA384:
		return 128
	default:
		panic("hkdf: unknown hash kind")
	}
}

// hashKindForHash maps crypto.Hash to the internal hashKind used by the pool.
func hashKindForHash(h crypto.Hash) hashKind {
	switch h {
	case crypto.SHA256:
		return hashSHA256
	case crypto.SHA384:
		return hashSHA384
	default:
		panic("hkdf: unsupported hash")
	}
}

// getHashFromPool returns a reset hash from the pool.
func getHashFromPool(k hashKind) fips140.Hash {
	switch k {
	case hashSHA256:
		h := sha256Pool.Get().(fips140.Hash)
		h.Reset()
		return h
	case hashSHA384:
		h := sha384Pool.Get().(fips140.Hash)
		h.Reset()
		return h
	default:
		panic("hkdf: unknown hash kind")
	}
}

// putHashToPool resets and returns a hash to the pool.
func putHashToPool(h fips140.Hash, k hashKind) {
	if h == nil {
		return
	}
	switch k {
	case hashSHA256:
		h.Reset()
		sha256Pool.Put(h)
	case hashSHA384:
		h.Reset()
		sha384Pool.Put(h)
	default:
		panic("hkdf: unknown hash kind")
	}
}

// Extract implements HKDF-Extract(salt, IKM) -> PRK (RFC 5869, Section 2.2).
func Extract(h crypto.Hash, secret, salt []byte) []byte {
	kind := hashKindForHash(h)
	if salt == nil {
		// Use zeros of hash length as the default salt.
		salt = make([]byte, kind.size())
	}
	return hmacSum(kind, salt, secret, nil)
}

// Expand implements HKDF-Expand(PRK, info, L) -> OKM (RFC 5869, Section 2.3).
// For TLS 1.3, L is always <= hash length so n is always 1.
func Expand(h crypto.Hash, prk []byte, info string, keyLength int) []byte {
	kind := hashKindForHash(h)
	hashLen := kind.size()

	n := (keyLength + hashLen - 1) / hashLen
	if n > 255 {
		panic("hkdf: requested key length too large")
	}

	out := GetBufOrMake(keyLength)

	// For TLS 1.3, n is always 1 (keyLength <= hashLen).
	// info is small — stack-allocated by the compiler in most cases.
	// prevBuf is reused across iterations: the old prev is fully copied
	// into scratch before hmacSum overwrites prevBuf, so no aliasing issue.
	var prevBuf []byte
	var prev []byte
	for i := 1; i <= n; i++ {
		// T(i) = HMAC-Hash(PRK, T(i-1) || info || byte(i))
		scratch := GetBufOrMake(len(prev) + len(info) + 1)
		scratch = scratch[:0]
		scratch = append(scratch, prev...)
		scratch = append(scratch, info...)
		scratch = append(scratch, byte(i))
		if prevBuf == nil {
			prevBuf = GetBufOrMake(hashLen)[:0]
		}
		prev = hmacSum(kind, prk, scratch, prevBuf)
		PutBufIfSet(scratch)
		copy(out[(i-1)*hashLen:], prev)
	}
	PutBufIfSet(prevBuf)

	return out[:keyLength]
}

// hmacSum computes HMAC-Hash(key, data) and writes the MAC to out.
// If out has sufficient capacity, the result is appended in-place without
// allocation; otherwise a new allocation occurs. The inner hash scratch is
// always obtained from the buffer pool.
func hmacSum(k hashKind, key, data, out []byte) []byte {
	blockSize := k.blockSize()
	hashLen := k.size()

	// For TLS 1.3, all HMAC keys are hash outputs (<= 48 bytes) which
	// never exceed SHA-256's block size (64) or SHA-384's (128), so we
	// skip RFC 2104's key-hashing step.

	// Build padded ipad/opad.
	ipad := GetBufOrMake(blockSize)
	opad := GetBufOrMake(blockSize)
	defer PutBufIfSet(ipad)
	defer PutBufIfSet(opad)

	for i := 0; i < len(key); i++ {
		ipad[i] = key[i] ^ 0x36
		opad[i] = key[i] ^ 0x5c
	}
	for i := len(key); i < blockSize; i++ {
		ipad[i] = 0x36
		opad[i] = 0x5c
	}

	// Inner hash: H(ipad || data). Sum writes into a pooled scratch buffer
	// to avoid allocation; the buffer is returned after outer.Write consumes it.
	inner := getHashFromPool(k)
	inner.Write(ipad)
	inner.Write(data)
	innerBuf := GetBufOrMake(hashLen)[:0]
	innerSum := inner.Sum(innerBuf)
	putHashToPool(inner, k)

	// Outer hash: H(opad || innerSum).
	outer := getHashFromPool(k)
	outer.Write(opad)
	outer.Write(innerSum)
	PutBufIfSet(innerBuf) // innerSum no longer needed
	result := outer.Sum(out)
	putHashToPool(outer, k)

	return result
}

func GetBufOrMake(size int) []byte {
	if GetBuffer != nil {
		return GetBuffer(size)
	}
	return make([]byte, size)
}

func PutBufIfSet(buf []byte) {
	if PutBuffer != nil && buf != nil {
		PutBuffer(buf)
	}
}
