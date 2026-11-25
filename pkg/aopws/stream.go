// Package aopws adapts Gorilla WebSocket connections to AOP envelope streams.
package aopws

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	aop "github.com/c1ayooo/cyber/aop"
	"github.com/gorilla/websocket"
	"google.golang.org/protobuf/encoding/protojson"
	protobuf "google.golang.org/protobuf/proto"
)

type Encoding uint8

const (
	Binary Encoding = iota
	ProtoJSON
)

type Options struct {
	Encoding     Encoding
	WriteTimeout time.Duration
	PingInterval time.Duration
	PongTimeout  time.Duration
}

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

// Stream owns WebSocket framing, liveness and serialized writes for one AOP
// connection. The caller retains responsibility for dialing or upgrading it.
type Stream struct {
	conn         *websocket.Conn
	encoding     Encoding
	writeTimeout time.Duration
	pingInterval time.Duration

	writeMu   sync.Mutex
	closeOnce sync.Once
	done      chan struct{}

	// stateMu guards the close plan: the first local failure, not the later
	// Close call, is the real reason the stream ends; a peer that opened the
	// close handshake itself gets no frame from us (the protocol echo already
	// went out on the read path).
	stateMu   sync.Mutex
	failure   CloseReason
	failed    bool
	peerClose bool
}

func New(ctx context.Context, conn *websocket.Conn, options Options) (*Stream, error) {
	if conn == nil {
		return nil, fmt.Errorf("AOP WebSocket connection is required")
	}
	if options.Encoding != Binary && options.Encoding != ProtoJSON {
		return nil, fmt.Errorf("unsupported AOP WebSocket encoding %d", options.Encoding)
	}
	if options.WriteTimeout < 0 || options.PingInterval < 0 || options.PongTimeout < 0 {
		return nil, fmt.Errorf("AOP WebSocket timeouts cannot be negative")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stream := &Stream{
		conn:         conn,
		encoding:     options.Encoding,
		writeTimeout: options.WriteTimeout,
		pingInterval: options.PingInterval,
		done:         make(chan struct{}),
	}
	if options.PongTimeout > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(options.PongTimeout)); err != nil {
			_ = conn.Close()
			return nil, err
		}
		conn.SetPongHandler(func(string) error {
			return conn.SetReadDeadline(time.Now().Add(options.PongTimeout))
		})
	}
	go stream.monitor(ctx)
	return stream, nil
}

func (s *Stream) Recv() (*aop.Envelope, error) {
	_, data, err := s.conn.ReadMessage()
	if err != nil {
		var peerClose *websocket.CloseError
		if errors.As(err, &peerClose) {
			s.markPeerClose()
		} else {
			s.markFailure(CloseReadFailed)
		}
		return nil, err
	}
	envelope := new(aop.Envelope)
	switch s.encoding {
	case Binary:
		err = protobuf.Unmarshal(data, envelope)
	case ProtoJSON:
		err = protojson.Unmarshal(data, envelope)
	}
	if err != nil {
		return nil, fmt.Errorf("decode AOP envelope: %w", err)
	}
	return envelope, nil
}

func (s *Stream) Send(envelope *aop.Envelope) error {
	if envelope == nil {
		return fmt.Errorf("AOP envelope is required")
	}
	frame := websocket.BinaryMessage
	var data []byte
	var err error
	switch s.encoding {
	case Binary:
		data, err = protobuf.Marshal(envelope)
	case ProtoJSON:
		frame = websocket.TextMessage
		data, err = protojson.Marshal(envelope)
	}
	if err != nil {
		return fmt.Errorf("encode AOP envelope: %w", err)
	}

	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return fmt.Errorf("AOP WebSocket is closed")
	default:
	}
	if s.writeTimeout > 0 {
		if err := s.conn.SetWriteDeadline(time.Now().Add(s.writeTimeout)); err != nil {
			s.markFailure(CloseWriteFailed)
			return err
		}
	}
	err = s.conn.WriteMessage(frame, data)
	if err != nil {
		s.markFailure(CloseWriteFailed)
	}
	return err
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

func (s *Stream) Close() error {
	if s == nil {
		return nil
	}
	var err error
	s.closeOnce.Do(func() {
		close(s.done)
		// Tell the peer why this side is going away before dropping the socket:
		// a bare FIN carries no reason, and the far side cannot then tell a
		// shutdown from a broken link. Best effort by design — a socket that
		// already failed takes no frame.
		if reason, send := s.closePlan(); send {
			_ = s.conn.WriteControl(websocket.CloseMessage, reason.frame(), time.Now().Add(closeFrameTimeout))
		}
		err = s.conn.Close()
	})
	return err
}

func (s *Stream) monitor(ctx context.Context) {
	if s.pingInterval <= 0 {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-s.done:
		}
		return
	}
	ticker := time.NewTicker(s.pingInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = s.Close()
			return
		case <-s.done:
			return
		case <-ticker.C:
			if err := s.ping(); err != nil {
				_ = s.Close()
				return
			}
		}
	}
}

func (s *Stream) ping() error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	select {
	case <-s.done:
		return fmt.Errorf("AOP WebSocket is closed")
	default:
	}
	deadline := time.Time{}
	if s.writeTimeout > 0 {
		deadline = time.Now().Add(s.writeTimeout)
	}
	err := s.conn.WriteControl(websocket.PingMessage, nil, deadline)
	if err != nil {
		s.markFailure(CloseWriteFailed)
	}
	return err
}

var _ aop.EnvelopeStream = (*Stream)(nil)
