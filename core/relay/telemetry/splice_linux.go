//go:build linux

package telemetry

import (
	"io"
	"net"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const splicePipeCapacity = 1 << 20 // 1 MiB pipe capacity for zero-copy kernel transfers

type splicePipe struct {
	pr int
	pw int
}

var splicePipePool = sync.Pool{
	New: func() any {
		var fds [2]int
		if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
			return nil
		}
		_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETPIPE_SZ, splicePipeCapacity)
		return &splicePipe{pr: fds[0], pw: fds[1]}
	},
}

func getSplicePipe() *splicePipe {
	if p, ok := splicePipePool.Get().(*splicePipe); ok && p != nil {
		return p
	}
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return nil
	}
	_, _ = unix.FcntlInt(uintptr(fds[0]), unix.F_SETPIPE_SZ, splicePipeCapacity)
	return &splicePipe{pr: fds[0], pw: fds[1]}
}

func putSplicePipe(p *splicePipe) {
	if p == nil {
		return
	}
	// Drain any lingering bytes in pipe before returning to pool
	var discard [4096]byte
	for {
		n, err := unix.Read(p.pr, discard[:])
		if n <= 0 || err != nil {
			break
		}
	}
	splicePipePool.Put(p)
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
	defer putSplicePipe(pipe)
	pr, pw := pipe.pr, pipe.pw

	for {
		inPipe, err := spliceDrain(srcRaw, pw)
		if err != nil {
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
				return true, err
			}
			if n == 0 {
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
