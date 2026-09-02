package tls

import (
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// testPooled mirrors pool.PooledBuffer's ownership-relevant behavior so the
// tests exercise the same code paths as production (dae injects
// pool.PooledBuffer via NewBytesBufferFunc; the tests can't import
// outbound/pool — it would be an import cycle).
//
//   - ReadFromN slices the backing array with the cap-hold pattern that made
//     an out-of-band Reset panic ("slice bounds [:16384] with capacity 0").
//   - Reset models returning the array to the pool (sets recycled, nils buf).
type testPooled struct {
	mu       sync.Mutex
	buf      []byte
	recycled bool
}

func (b *testPooled) Len() int { return len(b.buf) }
func (b *testPooled) Bytes() []byte {
	return b.buf
}
func (b *testPooled) Next(n int) []byte {
	if n > len(b.buf) {
		n = len(b.buf)
	}
	d := b.buf[:n]
	b.buf = b.buf[n:]
	return d
}
func (b *testPooled) Read(p []byte) (int, error) {
	if len(b.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.buf)
	b.buf = b.buf[n:]
	return n, nil
}
func (b *testPooled) Write(p []byte) (int, error) {
	b.buf = append(b.buf, p...)
	return len(p), nil
}
func (b *testPooled) ReadFrom(r io.Reader) (int64, error) {
	var total int64
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		total += int64(n)
		b.buf = append(b.buf, buf[:n]...)
		if err != nil {
			if err == io.EOF {
				return total, nil
			}
			return total, err
		}
	}
}
func (b *testPooled) Grow(n int) {
	b.buf = append(b.buf, make([]byte, n)...)
}
func (b *testPooled) Reset() {
	b.recycled = true
	b.buf = nil
}
func (b *testPooled) Detach() []byte {
	d := b.buf
	b.buf = nil
	return d
}
func (b *testPooled) ReadFromN(r io.Reader, n int) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	needs := n - len(b.buf)
	if needs <= 0 {
		return nil
	}
	m := len(b.buf)
	if cap(b.buf)-m < needs+512 {
		nb := make([]byte, m+needs+512)
		copy(nb, b.buf)
		b.buf = nb
	}
	b.buf = b.buf[:m+needs]
	c := cap(b.buf)
	held := b.buf // reader keeps this slice across the blocking r.Read
	_, err := io.ReadFull(r, held[m:c])
	return err
}

// Guards the production panic:
//
//	panic: runtime error: slice bounds out of range [:16384] with capacity 0
//	  pool.(*PooledBuffer).ReadFromN (pooledbuf.go:131)
//	  utls.(*Conn).readFromUntil -> readRecordOrCCS -> (*UConn).Read
//	  (observed via smux.recvLoop -> vless.ReadRespHeader in dae)
//
// Upstream semantics interlock Close with Write only, so a Close may run
// concurrently with a Read blocked in ReadFromN. Close therefore recycles
// rawInput/hand only when it can take the read mutex (c.in.TryLock); if a
// Read is in flight the buffers are left to the GC instead of being
// returned to the pool under a live reader.

// No read in flight: Close must recycle — this is the pool hit-rate
// recovery (the 16K bucket sat at 77% while Close skipped recycling).
func TestCloseRecyclesRawInputWhenIdle(t *testing.T) {
	c1, _ := net.Pipe()
	c := &Conn{conn: c1, config: &Config{}, isClient: true}
	pb := &testPooled{}
	c.rawInput = pb
	c.hand = &testPooled{}
	pb.Write(make([]byte, 100))

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !pb.recycled {
		t.Fatal("Close with no read in flight did not recycle rawInput — pool hit-rate regression")
	}
}

// Read in flight: Close must NOT recycle (TryLock fails) and the pending
// reader must return cleanly — no use-after-put panic, no race.
//
// slowCloseConn makes Close() not wake the reader, so the reader stays
// parked inside ReadFromN holding c.in — the exact production geometry
// (smux recvLoop parked in vless.Read while the relay tears the conn down).
type slowCloseConn struct {
	net.Conn
	closeReq chan struct{}
}

func (c *slowCloseConn) Close() error {
	select {
	case <-c.closeReq:
	default:
		close(c.closeReq)
	}
	return nil
}

func TestCloseWhileReadInFlightSkipsRecycle(t *testing.T) {
	for i := 0; i < 50; i++ {
		c1, c2 := net.Pipe()
		sc := &slowCloseConn{Conn: c1, closeReq: make(chan struct{})}
		c := &Conn{conn: sc, config: &Config{}, isClient: true}
		pb := &testPooled{}
		c.rawInput = pb
		c.hand = &testPooled{}
		c.rawInputN, _ = c.rawInput.(interface {
			ReadFromN(r io.Reader, n int) error
		})

		done := make(chan struct{})
		go func() {
			defer close(done)
			// Mirror production: readRecordOrCCS holds c.in for the whole
			// read path (Conn.Read can't be used here — it forces a
			// handshake first). Park holding the lock, then block in
			// ReadFromN on the pipe.
			c.in.Lock()
			defer c.in.Unlock()
			_ = c.readFromUntil(c1, 16384)
		}()

		// Wait until the reader is parked holding c.in, then Close: the
		// deferred TryLock must fail and skip the recycle.
		time.Sleep(2 * time.Millisecond)
		if err := c.Close(); err != nil {
			t.Fatalf("iteration %d: Close: %v", i, err)
		}
		if pb.recycled {
			t.Fatalf("iteration %d: Close recycled rawInput while a Read was in flight", i)
		}

		c2.Close() // now wake the reader
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: Read did not return", i)
		}
	}
}

// TestCloseRecyclesAfterReaderReleases pins the common production case
// (relay error teardown while a Read is parked): the reader wakes when the
// underlying conn drops and releases c.in within Close's bounded retry
// window, so Close recycles anyway instead of leaving the buffers to the GC.
func TestCloseRecyclesAfterReaderReleases(t *testing.T) {
	c1, _ := net.Pipe()
	c := &Conn{conn: c1, config: &Config{}, isClient: true}
	pb := &testPooled{}
	c.rawInput = pb
	c.hand = &testPooled{}
	c.rawInputN, _ = c.rawInput.(interface {
		ReadFromN(r io.Reader, n int) error
	})

	readerStarted := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		c.in.Lock() // mirror readRecordOrCCS: hold the read mutex while parked
		close(readerStarted)
		_ = c.readFromUntil(c1, 16384) // blocks in ReadFromN on the pipe
		c.in.Unlock()
	}()
	<-readerStarted

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }() // enters the bounded retry loop
	time.Sleep(2 * time.Millisecond)      // let Close attempt (and miss) first

	c1.Close() // wake the reader -> it releases c.in
	<-done
	if err := <-closeDone; err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !pb.recycled {
		t.Fatal("Close did not recycle after the reader released within the retry window")
	}
}
