package routing

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/archnets/node/core/relay/telemetry"
)

func TestStartUDPListenerLoop_NoPanicOnEarlyWriteFailure(t *testing.T) {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	entryUDP, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer entryUDP.Close()

	// Pre-closed pipe guarantees immediate write failures on Stream/StreamTwin
	claimFn := func(timeout time.Duration) (net.Conn, error) {
		c1, c2 := net.Pipe()
		_ = c2.Close()
		return c1, nil
	}

	ctx := t.Context()
	stats := telemetry.NewStats()
	StartUDPListenerLoop(ctx, entryUDP, 6444, claimFn, stats, true)

	// Hammer packets concurrently from multiple clients so write path fails before/during pumpStream startup
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cli, dErr := net.Dial("udp", entryUDP.LocalAddr().String())
			if dErr != nil {
				return
			}
			defer cli.Close()
			for j := 0; j < 20; j++ {
				_, _ = cli.Write([]byte("OPENVPN_HELLO_PACKET"))
				time.Sleep(time.Millisecond)
			}
		}()
	}
	wg.Wait()
}
