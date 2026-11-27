package aopws

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	aop "github.com/chainreactors/cyber/aop"
	"github.com/gorilla/websocket"
)

var testUpgrader = websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

// closeFrameCodeText decodes a close frame payload: a 2-byte code, then UTF-8
// text.
func closeFrameCodeText(frame []byte) (int, string) {
	if len(frame) < 2 {
		return 0, ""
	}
	return int(binary.BigEndian.Uint16(frame[:2])), string(frame[2:])
}

func dialTestWebSocket(t *testing.T, serverURL string) *websocket.Conn {
	t.Helper()
	conn, response, err := websocket.DefaultDialer.Dial(strings.Replace(serverURL, "http", "ws", 1), nil)
	if response != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func TestStreamRoundTripsBothEncodings(t *testing.T) {
	for _, test := range []struct {
		name     string
		encoding Encoding
		frame    int
	}{
		{name: "binary", encoding: Binary, frame: websocket.BinaryMessage},
		{name: "protojson", encoding: ProtoJSON, frame: websocket.TextMessage},
	} {
		t.Run(test.name, func(t *testing.T) {
			frames := make(chan int, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, err := testUpgrader.Upgrade(w, r, nil)
				if err != nil {
					return
				}
				defer conn.Close()
				frame, data, err := conn.ReadMessage()
				if err != nil {
					return
				}
				frames <- frame
				_ = conn.WriteMessage(frame, data)
			}))
			defer server.Close()

			conn := dialTestWebSocket(t, server.URL)
			stream, err := New(t.Context(), conn, Options{Encoding: test.encoding, WriteTimeout: time.Second})
			if err != nil {
				t.Fatal(err)
			}
			defer stream.Close()
			if err := stream.Send(&aop.Envelope{Id: "round-trip"}); err != nil {
				t.Fatal(err)
			}
			received, err := stream.Recv()
			if err != nil {
				t.Fatal(err)
			}
			if received.GetId() != "round-trip" {
				t.Fatalf("received id = %q", received.GetId())
			}
			if frame := <-frames; frame != test.frame {
				t.Fatalf("frame = %d, want %d", frame, test.frame)
			}
		})
	}
}

func TestStreamSerializesConcurrentWrites(t *testing.T) {
	const writes = 32
	serverResult := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			serverResult <- err
			return
		}
		defer conn.Close()
		for range writes {
			if _, _, err := conn.ReadMessage(); err != nil {
				serverResult <- err
				return
			}
		}
		serverResult <- nil
	}))
	defer server.Close()

	conn := dialTestWebSocket(t, server.URL)
	stream, err := New(context.Background(), conn, Options{WriteTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()

	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := range writes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- stream.Send(&aop.Envelope{Id: fmt.Sprintf("write-%d", i)})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-serverResult; err != nil {
		t.Fatal(err)
	}
}

func TestStreamReportsConsistentDecodeErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.WriteMessage(websocket.BinaryMessage, []byte{0xff})
	}))
	defer server.Close()

	conn := dialTestWebSocket(t, server.URL)
	stream, err := New(t.Context(), conn, Options{Encoding: Binary})
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Recv(); err == nil || !strings.Contains(err.Error(), "decode AOP envelope") {
		t.Fatalf("Recv() error = %v", err)
	}
}

// A shutdown must reach the far side as a close frame with one of the fixed
// reasons. A bare FIN says only "the socket ended", which is exactly the
// ambiguity that makes a mid-turn disconnect impossible to attribute.
func TestStreamCloseTellsThePeerWhy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := testUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		stream, err := New(r.Context(), conn, Options{Encoding: Binary, WriteTimeout: time.Second})
		if err != nil {
			return
		}
		_ = stream.Close()
	}))
	defer server.Close()

	conn := dialTestWebSocket(t, server.URL)
	defer conn.Close()
	_, _, err := conn.ReadMessage()
	var closeErr *websocket.CloseError
	if !errors.As(err, &closeErr) {
		t.Fatalf("err = %v, want the peer's close frame", err)
	}
	if closeErr.Code != websocket.CloseGoingAway {
		t.Fatalf("close code = %d, want %d", closeErr.Code, websocket.CloseGoingAway)
	}
	if closeErr.Text != "host closing" {
		t.Fatalf("close text = %q", closeErr.Text)
	}
}

// The first local failure decides the reason: by the time Close runs, the socket
// error that caused it is already gone.
func TestStreamCloseReasonFollowsTheFirstFailure(t *testing.T) {
	broken := &Stream{}
	broken.markFailure(CloseReadFailed)
	broken.markFailure(CloseWriteFailed)
	reason, send := broken.closePlan()
	if !send || reason != CloseReadFailed {
		t.Fatalf("plan = %v/%v, want the first failure", reason, send)
	}
	if code, text := closeFrameCodeText(reason.frame()); code != websocket.CloseInternalServerErr || text != "read failed" {
		t.Fatalf("frame = %d/%q", code, text)
	}

	// A peer that opened the close handshake gets no second frame from us.
	peer := &Stream{}
	peer.markPeerClose()
	peer.markFailure(CloseReadFailed)
	if _, send := peer.closePlan(); send {
		t.Fatal("a peer-initiated close must not be answered with our own frame")
	}
}
