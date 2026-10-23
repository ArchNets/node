//go:build linux

package telemetry

import (
	"io"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

const splicePipeCapacity = 1 << 20 // 1 MiB pipe capacity for zero-copy kernel transfers

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

	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		return false, nil
	}
	pr, pw := fds[0], fds[1]
	defer unix.Close(pr)
	defer unix.Close(pw)

	_, _ = unix.FcntlInt(uintptr(pr), unix.F_SETPIPE_SZ, splicePipeCapacity)

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
