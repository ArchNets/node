//go:build linux

package telemetry

import (
	"io"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	splicePipeCapacity = 256 * 1024 // 256 KiB pipe capacity for zero-copy kernel transfers
	maxSplicePipePool  = 256        // Bounded pool caps open pipe FDs (512 max) and kernel slab usage (~64 MiB max)
)

type splicePipe struct {
	pr        int
	pw        int
	closeOnce sync.Once
}

func (p *splicePipe) close() {
	if p == nil {
		return
	}
	p.closeOnce.Do(func() {
		if p.pr >= 0 {
			_ = unix.Close(p.pr)
			p.pr = -1
		}
		if p.pw >= 0 {
			_ = unix.Close(p.pw)
			p.pw = -1
		}
	})
}

// Bounded channel pool: unlike sync.Pool, GC never silently evicts items without closing their OS pipe FDs.
var splicePipePool = make(chan *splicePipe, maxSplicePipePool)

func getSplicePipe() *splicePipe {
	select {
	case p := <-splicePipePool:
		if p != nil {
			return p
		}
	default:
	}
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return nil
	}
	_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETPIPE_SZ, splicePipeCapacity)
	return &splicePipe{pr: fds[0], pw: fds[1]}
}

func putSplicePipe(p *splicePipe, broken bool) {
	if p == nil {
		return
	}
	if broken {
		p.close()
		return
	}
	// Drain any lingering bytes in pipe and verify EAGAIN before returning to pool
	var discard [4096]byte
	for {
		n, err := unix.Read(p.pr, discard[:])
		if n > 0 {
			continue
		}
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
			break
		}
		p.close()
		return
	}
	select {
	case splicePipePool <- p:
	default:
		p.close()
	}
}

// spliceRelay moves bytes directly between two TCP sockets using Linux kernel splice(2).
// Bytes are transferred inside kernel memory without crossing into user-space.
func spliceRelay(dst, src *net.TCPConn, onChunk func(n int)) (handled bool, err error) {
	srcRaw, err := src.SyscallConn()
	if err != nil {
		return false, nil
	}
	dstRaw, err := dst.SyscallConn()
	if err != nil {
		return false, nil
	}

	pipe := getSplicePipe()
	if pipe == nil {
		return false, nil
	}
	broken := false
	defer func() {
		putSplicePipe(pipe, broken)
	}()
	pr, pw := pipe.pr, pipe.pw

	for {
		inPipe, err := spliceDrain(srcRaw, pw)
		if err != nil {
			broken = true
			if !handled {
				return false, nil
			}
			return true, err
		}
		if inPipe == 0 {
			return true, nil
		}
		handled = true

		for inPipe > 0 {
			n, err := splicePump(dstRaw, pr, inPipe)
			if n > 0 {
				inPipe -= n
				if onChunk != nil {
					onChunk(int(n))
				}
			}
			if err != nil {
				broken = true
				return true, err
			}
			if n == 0 {
				broken = true
				return true, io.ErrUnexpectedEOF
			}
		}
	}
}

func spliceDrain(raw syscall.RawConn, pw int) (int64, error) {
	var moved int64
	var spliceErr error

	rawErr := raw.Read(func(fd uintptr) bool {
		for {
			n, err := unix.Splice(int(fd), nil, pw, nil, splicePipeCapacity, unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN {
				return false
			}
			moved, spliceErr = int64(n), err
			return true
		}
	})
	if rawErr != nil {
		return 0, rawErr
	}
	return moved, spliceErr
}

func splicePump(raw syscall.RawConn, pr int, max int64) (int64, error) {
	var moved int64
	var spliceErr error

	rawErr := raw.Write(func(fd uintptr) bool {
		for {
			n, err := unix.Splice(pr, nil, int(fd), nil, int(max), unix.SPLICE_F_MOVE|unix.SPLICE_F_NONBLOCK)
			if err == unix.EINTR {
				continue
			}
			if err == unix.EAGAIN {
				return false
			}
			moved, spliceErr = int64(n), err
			return true
		}
	})
	if rawErr != nil {
		return 0, rawErr
	}
	return moved, spliceErr
}
