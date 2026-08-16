// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"encoding/pem"
	"fmt"
	"runtime"
	"testing"
	"time"
)

func TestCertCache(t *testing.T) {
	cc := certCache{}
	p, _ := pem.Decode([]byte(rsaCertPEM))
	if p == nil {
		t.Fatal("Failed to decode certificate")
	}

	certA, err := cc.newCert(p.Bytes)
	if err != nil {
		t.Fatalf("newCert failed: %s", err)
	}
	certB, err := cc.newCert(p.Bytes)
	if err != nil {
		t.Fatalf("newCert failed: %s", err)
	}
	if certA.cert != certB.cert {
		t.Fatal("newCert returned a unique reference for a duplicate certificate")
	}

	// newCert only interns the certificate; it does not take a reference.
	// References are taken via certHandles.add.
	if entry, ok := cc.Load(string(p.Bytes)); !ok {
		t.Fatal("cache does not contain expected entry")
	} else if refs := entry.(*cacheEntry).refs.Load(); refs != 0 {
		t.Fatalf("unexpected number of references before add: got %d, want 0", refs)
	}

	handlesA := cc.newCertHandles()
	handlesA.add(certA)
	handlesB := cc.newCertHandles()
	handlesB.add(certB)

	timeoutRefCheck := func(t *testing.T, key string, count int64) {
		t.Helper()
		c := time.After(4 * time.Second)
		for {
			select {
			case <-c:
				t.Fatal("timed out waiting for expected ref count")
			default:
				e, ok := cc.Load(key)
				if !ok && count != 0 {
					t.Fatal("cache does not contain expected key")
				} else if count == 0 && !ok {
					return
				}

				if e.(*cacheEntry).refs.Load() == count {
					return
				}
			}
		}
	}

	// Releasing handle A drops the refcount to 1, but the entry stays cached.
	handlesA.release()
	timeoutRefCheck(t, string(p.Bytes), 1)

	// Releasing handle B drops the refcount to 0 and evicts the entry.
	handlesB.release()
	timeoutRefCheck(t, string(p.Bytes), 0)
}

func TestCertCacheFinalizerReleases(t *testing.T) {
	cc := certCache{}
	p, _ := pem.Decode([]byte(rsaCertPEM))
	if p == nil {
		t.Fatal("Failed to decode certificate")
	}

	cert, err := cc.newCert(p.Bytes)
	if err != nil {
		t.Fatalf("newCert failed: %s", err)
	}

	handles := cc.newCertHandles()
	handles.add(cert)

	// Drop the only reference; the batch finalizer must decrement the refcount
	// and evict the entry once it runs.
	runtime.KeepAlive(handles)
	handles = nil
	runtime.GC()

	c := time.After(4 * time.Second)
	for {
		select {
		case <-c:
			t.Fatal("timed out waiting for the finalizer to evict the entry")
		default:
			if _, ok := cc.Load(string(p.Bytes)); !ok {
				return
			}
			runtime.GC()
		}
	}
}

func BenchmarkCertCache(b *testing.B) {
	p, _ := pem.Decode([]byte(rsaCertPEM))
	if p == nil {
		b.Fatal("Failed to decode certificate")
	}

	cc := certCache{}
	b.ReportAllocs()
	b.ResetTimer()
	// newCert itself must not allocate after the first call (intern + no handle),
	// and taking/releasing references must not allocate either.
	for extra := 0; extra < 4; extra++ {
		b.Run(fmt.Sprint(extra), func(b *testing.B) {
			handles := make([]*certHandles, extra+1)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for j := 0; j < extra+1; j++ {
					cert, err := cc.newCert(p.Bytes)
					if err != nil {
						b.Fatal(err)
					}
					handles[j] = cc.newCertHandles()
					handles[j].add(cert)
				}
				for j := 0; j < extra+1; j++ {
					handles[j].release()
				}
				runtime.GC()
			}
		})
	}
}
