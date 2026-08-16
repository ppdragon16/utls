// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/x509"
	"runtime"
	"sync"
	"sync/atomic"
)

type cacheEntry struct {
	refs atomic.Int64
	cert *x509.Certificate
}

// certCache implements an intern table for reference counted x509.Certificates,
// implemented in a similar fashion to BoringSSL's CRYPTO_BUFFER_POOL. This
// allows for a single x509.Certificate to be kept in memory and referenced from
// multiple Conns. Returned references should not be mutated by callers. Certificates
// are still safe to use after they are removed from the cache.
//
// The main difference between this implementation and CRYPTO_BUFFER_POOL is that
// CRYPTO_BUFFER_POOL is a more  generic structure which supports blobs of data,
// rather than specific structures. Since we only care about x509.Certificates,
// certCache is implemented as a specific cache, rather than a generic one.
//
// See https://boringssl.googlesource.com/boringssl/+/master/include/openssl/pool.h
// and https://boringssl.googlesource.com/boringssl/+/master/crypto/pool/pool.c
// for the BoringSSL reference.
type certCache struct {
	sync.Map
}

var globalCertCache = new(certCache)

// certHandles batches the cache references held by a single Conn or
// SessionState. A single finalizer releases every reference at once when the
// owner becomes unreachable, instead of the upstream per-certificate finalizer.
//
// Upstream wraps each certificate in an 8-byte activeCert handle with its own
// runtime.SetFinalizer, which allocates one object and one finalizer per
// certificate per handshake. At high connection churn these handles dominate
// the live object count (a dae heap profile showed 65% of all live objects were
// 8-byte cert handles) and each finalizer pins its object for an extra GC
// cycle. Batching keeps identical reference-counting semantics with a single
// allocation and finalizer per owner.
type certHandles struct {
	cache    *certCache
	entries  []*cacheEntry
	released bool
}

// newCertHandles returns an empty batch whose finalizer is armed immediately,
// so that references added to it are released even if the owner returns early
// on an error path.
func (cc *certCache) newCertHandles() *certHandles {
	h := &certHandles{cache: cc}
	runtime.SetFinalizer(h, (*certHandles).release)
	return h
}

// add takes a reference on e and records it for release.
func (h *certHandles) add(e *cacheEntry) {
	e.refs.Add(1)
	h.entries = append(h.entries, e)
}

// release decrements every reference and evicts entries whose refcount reaches
// zero. It is idempotent so it can safely run both as an explicit cleanup and
// as the finalizer target.
func (h *certHandles) release() {
	if h == nil || h.released {
		return
	}
	h.released = true
	for _, e := range h.entries {
		if e.refs.Add(-1) == 0 {
			h.cache.evict(e)
		}
	}
	h.entries = nil
}

// evict removes a cacheEntry from the cache.
func (cc *certCache) evict(e *cacheEntry) {
	cc.Delete(string(e.cert.Raw))
}

// newCert returns a x509.Certificate parsed from der, interned in the cache. If
// there is already a copy of the certificate in the cache, the cached copy is
// returned. The returned cacheEntry does NOT take a reference by itself; the
// caller must call certHandles.add on it to take (and later release) the
// reference. The parsed certificate is accessed via entry.cert and must not be
// mutated.
func (cc *certCache) newCert(der []byte) (*cacheEntry, error) {
	if entry, ok := cc.Load(string(der)); ok {
		return entry.(*cacheEntry), nil
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}

	entry := &cacheEntry{cert: cert}
	if e, loaded := cc.LoadOrStore(string(der), entry); loaded {
		return e.(*cacheEntry), nil
	}
	return entry, nil
}
