package tls

import (
	"io"
	"net"
	"testing"
	"time"
)

// TestCloseDoesNotRecycleRawInput guards the production panic:
//
//	panic: runtime error: slice bounds out of range [:16384] with capacity 0
//	  pool.(*PooledBuffer).ReadFromN (pooledbuf.go:131)
//	  utls.(*Conn).readFromUntil -> readRecordOrCCS -> (*UConn).Read
//	  (observed via smux.recvLoop -> vless.ReadRespHeader in dae)
//
// Upstream semantics interlock Close with Write only, so a Close may run
// concurrently with a Read blocked in ReadFromN. Close therefore must not
// call rawInput.Reset(): PooledBuffer.Reset returns the backing array to
// the pool and nils the slice while the reader still holds the old cap —
// a use-after-put that panics or, worse, lets another connection reuse
// the array (cross-connection data corruption).
func TestCloseDoesNotRecycleRawInput(t *testing.T) {
	c1, _ := net.Pipe()
	c := &Conn{conn: c1, config: &Config{}, isClient: true}
	c.rawInput = NewBytesBuffer()
	c.rawInput.Write(make([]byte, 100))

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if c.rawInput.Len() == 0 && cap(c.rawInput.Bytes()) == 0 {
		t.Fatal("Close recycled rawInput via Reset — races with concurrent Read (production panic source)")
	}
}

// TestCloseWhileReadInFlight is the -race companion: a real Close racing a
// Read that is actively cycling inside ReadFromN. Pre-fix, Close's deferred
// rawInput.Reset() wrote b.buf=nil and PutBuffer'ed the array while
// ReadFromN read cap(b.buf) and sliced — a data race the race detector
// flags deterministically.
func TestCloseWhileReadInFlight(t *testing.T) {
	for i := 0; i < 50; i++ {
		c1, c2 := net.Pipe()
		c := &Conn{conn: c1, config: &Config{}, isClient: true}
		c.rawInput = NewBytesBuffer()
		c.rawInputN, _ = c.rawInput.(interface {
			ReadFromN(r io.Reader, n int) error
		})

		done := make(chan struct{})
		go func() {
			defer close(done)
			_ = c.readFromUntil(c1, 16384) // blocks in ReadFromN on the pipe
		}()

		// Feed the reader so ReadFromN passes its first slice op and keeps
		// looping — the exact window where the production panic fired.
		go func() {
			c2.Write(make([]byte, 4096))
			c2.Write(make([]byte, 4096))
		}()

		time.Sleep(time.Millisecond)
		go func() {
			_ = c.Close()
			c2.Close()
		}()

		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: Read did not return", i)
		}
	}
}
