package agent

import (
	"errors"
	"os"
	"syscall"
)

// Windows socket errnos the retry decision has to recognize by number.
//
// net.Error.Timeout() does not cover them: the platform reports WSAETIMEDOUT
// (10060) for a dial whose SYN was dropped, and Errno.Timeout() on Windows accepts
// only EAGAIN/EWOULDBLOCK/ETIMEDOUT (ETIMEDOUT is 536871033 there), so a genuinely
// timed-out dial answers Timeout()==false and looks permanent. Measured
// 2026-11-23 against the TSecBench 2026-11-22 journals: 11 of 20 failed runs ended
// on `dial tcp …: connectex: A connection attempt failed because the connected
// party did not properly respond…` and 4 more on `wsasend: An existing connection
// was forcibly closed by the remote host`, none of which matched a retry pattern,
// so those runs died on the first attempt. Literal numbers keep this file building
// on Linux and macOS, where they are never produced.
const (
	wsaeTimedout = syscall.Errno(10060) // WSAETIMEDOUT: connect got no answer
	wsaeRefused  = syscall.Errno(10061) // WSAECONNREFUSED: listener gone (gateway restarting)
	wsaeReset    = syscall.Errno(10054) // WSAECONNRESET: peer closed mid-stream
)

// isConnErrnoRetryable answers for the socket numbers above. A refusal is
// included on purpose: at this layer the peer is the model gateway next door,
// which restarts in seconds, so "nobody listening" is usually the tail of a
// restart — unlike a target host that is really gone.
//
// Callers must run it after the net.Error timeout branch and before the message
// fallback: on Windows these numbers are the reliable signal, and a wrapper that
// kept only the text is covered by the message patterns instead.
func isConnErrnoRetryable(err error) bool {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		switch errno {
		case wsaeTimedout, wsaeRefused, wsaeReset:
			return true
		}
		return false
	}
	// Some paths wrap the errno in os.SyscallError without keeping the chain.
	var pathErr *os.SyscallError
	if errors.As(err, &pathErr) && pathErr.Err != nil {
		return isConnErrnoRetryable(pathErr.Err)
	}
	return false
}
