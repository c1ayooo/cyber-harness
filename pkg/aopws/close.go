package aopws

import (
	"time"

	"github.com/gorilla/websocket"
)

// CloseReason names why this side ends the stream. The reason travels on the
// close frame, so the far side can tell an intentional shutdown from a socket
// that stopped working without reading the transport error. It is a fixed set,
// not free-form text: a peer that has to parse prose to decide whether the link
// is unstable is back to guessing.
type CloseReason uint8

const (
	// CloseGoingAway: this side shuts the stream down on purpose.
	CloseGoingAway CloseReason = iota
	// CloseReadFailed: this side stopped receiving from the peer.
	CloseReadFailed
	// CloseWriteFailed: this side could not deliver to the peer.
	CloseWriteFailed
)

// closeFrameTimeout bounds the last write a dying connection gets. A socket that
// already failed takes no frame, so this only decides how long Close may wait.
const closeFrameTimeout = time.Second

func (r CloseReason) frame() []byte {
	switch r {
	case CloseReadFailed:
		return websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "read failed")
	case CloseWriteFailed:
		return websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "write failed")
	default:
		return websocket.FormatCloseMessage(websocket.CloseGoingAway, "host closing")
	}
}

// markFailure records the first local transport failure this stream saw.
func (s *Stream) markFailure(reason CloseReason) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if !s.failed {
		s.failure, s.failed = reason, true
	}
}

// markPeerClose records that the peer started the close handshake.
func (s *Stream) markPeerClose() {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	s.peerClose = true
}

// closePlan says what to put on our close frame, and whether to send one at
// all. A peer-initiated close gets none: sending a second frame would describe
// an ending the peer already caused.
//
// stateMu guards the close plan: the first local failure, not the later Close
// call, is the real reason the stream ends; a peer that opened the close
// handshake itself gets no frame from us (the protocol echo already went out on
// the read path).
func (s *Stream) closePlan() (CloseReason, bool) {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.peerClose {
		return 0, false
	}
	if s.failed {
		return s.failure, true
	}
	return CloseGoingAway, true
}
