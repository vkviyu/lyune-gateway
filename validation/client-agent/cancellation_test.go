package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vkviyu/lyune-gateway/validation/client-agent/internal/wire"
)

// A real deadline-capable read half with independently controlled send failures.
// This makes the Close race deterministic without relying on UDP scheduling.
type cancellationStream struct {
	net.Conn
	sendCtx    context.Context
	cancelSend context.CancelCauseFunc
	writeErr   error
	closeErr   error
	closeCause error
	readErr    error
	failWrite  int
	writes     int
	deadline   time.Time
	readCancel bool
	closed     chan struct{}
	closeOnce  sync.Once
}

func (s *cancellationStream) Context() context.Context { return s.sendCtx }
func (s *cancellationStream) StreamID() quic.StreamID  { return 0 }
func (s *cancellationStream) SetDeadline(d time.Time) error {
	s.deadline = d
	return s.Conn.SetReadDeadline(d)
}
func (s *cancellationStream) CancelRead(quic.StreamErrorCode) {
	s.readCancel = true
	_ = s.Conn.Close()
}
func (s *cancellationStream) CancelWrite(quic.StreamErrorCode) {}
func (s *cancellationStream) Write(p []byte) (int, error) {
	s.writes++
	if s.writes == s.failWrite {
		s.cancelSend(s.writeErr)
		return 0, s.writeErr
	}
	return len(p), nil
}
func (s *cancellationStream) Close() error {
	s.cancelSend(s.closeCause)
	s.closeOnce.Do(func() { close(s.closed) })
	return s.closeErr
}
func (s *cancellationStream) Read(p []byte) (int, error) {
	if s.readErr != nil {
		<-s.closed
		return 0, s.readErr
	}
	return s.Conn.Read(p)
}

func newCancellationStream(t *testing.T) (*cancellationStream, net.Conn) {
	t.Helper()
	client, peer := net.Pipe()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() {
		cancel(nil)
		_ = client.Close()
		_ = peer.Close()
	})
	return &cancellationStream{Conn: client, sendCtx: ctx, cancelSend: cancel, closed: make(chan struct{})}, peer
}

func testOpen(t *testing.T, dest wire.DestKind, route uint8, body string) *wire.Frame {
	t.Helper()
	frame, err := wire.NewOpen(dest, 1, route, wire.ResponseRequired, wire.FlagEOF, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func runCancellationClient(t *testing.T, name string, ctx context.Context, stream requestStream) (string, error) {
	t.Helper()
	request := testOpen(t, wire.DestService, 2, "request")
	switch name {
	case "generic":
		result := exchangeOnStream(ctx, stream, exchangeRequest{
			Chunks: []string{"head", "tail"}, ResponseMode: "required",
		}, time.Now())
		var body strings.Builder
		for _, frame := range result.ResponseFrames {
			body.WriteString(frame.Body)
		}
		if result.Error != "" {
			return body.String(), errors.New(result.Error)
		}
		return body.String(), nil
	case "im":
		frame, err := imExchangeOnStream(ctx, stream, request)
		if err != nil {
			return "", err
		}
		return string(frame.Body), nil
	case "none":
		return "", sendNoResponseOnStream(ctx, stream, request)
	default:
		t.Fatal("unknown client")
		return "", nil
	}
}

func TestRemoteUploadCancellationPreservesResponse(t *testing.T) {
	for _, client := range []string{"generic", "im", "none"} {
		for _, phase := range []string{"header", "body", "close", "typed-close"} {
			for _, outcome := range []string{"response", "reset", "connection", "deadline", "gateway-error"} {
				t.Run(client+"/"+phase+"/"+outcome, func(t *testing.T) {
					stream, peer := newCancellationStream(t)
					stop := &quic.StreamError{StreamID: 0, ErrorCode: 0x123, Remote: true}
					switch phase {
					case "header", "body":
						stream.failWrite = 1
						if phase == "body" {
							stream.failWrite = 2
						}
						stream.writeErr = fmt.Errorf("wrapped: %w", stop)
					case "close":
						stream.closeErr = errors.New("close called for canceled stream 0")
						stream.closeCause = stop
					case "typed-close":
						stream.closeErr = stop
					}
					var wantErr string
					switch outcome {
					case "reset":
						stream.readErr = &quic.StreamError{StreamID: 0, ErrorCode: 0x456, Remote: true}
						wantErr = stream.readErr.Error()
					case "connection":
						stream.readErr = &quic.ApplicationError{ErrorCode: 0x789, ErrorMessage: "peer connection failed", Remote: true}
						wantErr = "peer connection failed"
					case "deadline":
						wantErr = "deadline"
					default:
						go func() {
							<-stream.closed
							defer peer.Close()
							if client == "none" && outcome == "response" {
								return
							}
							dest, route, body := wire.DestService, uint8(2), "response after STOP"
							if outcome == "gateway-error" {
								dest, route, body = wire.DestGateway, 0xf0, "route rejected"
							}
							frame, _ := wire.NewOpen(dest, 1, route, wire.ResponseRequired, wire.FlagEOF, []byte(body))
							_ = wire.WriteFrame(peer, frame)
						}()
						if outcome == "gateway-error" && client != "im" {
							wantErr = "route rejected"
						}
					}
					timeout := time.Second
					if outcome == "deadline" {
						timeout = 20 * time.Millisecond
					}
					ctx, cancel := context.WithTimeout(context.Background(), timeout)
					defer cancel()
					body, err := runCancellationClient(t, client, ctx, stream)
					if outcome == "deadline" {
						// Either the context timer or the transport read deadline
						// can win; both must remain active after STOP.
						if err == nil || (!strings.Contains(err.Error(), "deadline") && !strings.Contains(err.Error(), "timeout")) {
							t.Fatalf("expected response timeout, got %v", err)
						}
						deadline, _ := ctx.Deadline()
						if time.Now().Before(deadline) {
							t.Fatal("response ended before its deadline")
						}
					} else if wantErr != "" {
						if err == nil || !strings.Contains(err.Error(), wantErr) {
							t.Fatalf("want %q, got body=%q err=%v", wantErr, body, err)
						}
					} else if err != nil {
						t.Fatal(err)
					} else if client != "none" {
						want := "response after STOP"
						if outcome == "gateway-error" {
							want = "route rejected"
						}
						if body != want {
							t.Fatalf("response lost: %q", body)
						}
					}
					deadline, _ := ctx.Deadline()
					if !stream.deadline.Equal(deadline) {
						t.Fatal("response deadline changed")
					}
					if outcome != "deadline" && stream.readCancel {
						t.Fatal("STOP canceled the response read")
					}
					if stream.failWrite > 0 && stream.writes != stream.failWrite {
						t.Fatalf("upload continued: %d writes", stream.writes)
					}
				})
			}
		}
	}
}

func TestLocalAndConnectionUploadErrorsAreNotSuppressed(t *testing.T) {
	for _, client := range []string{"generic", "im", "none"} {
		for _, phase := range []string{"write", "close"} {
			for _, failure := range []error{
				&quic.StreamError{ErrorCode: 77, Remote: false},
				&quic.ApplicationError{ErrorCode: 88, ErrorMessage: "connection gone", Remote: true},
				io.ErrClosedPipe,
			} {
				t.Run(fmt.Sprintf("%s/%s/%T", client, phase, failure), func(t *testing.T) {
					stream, _ := newCancellationStream(t)
					if phase == "write" {
						stream.failWrite, stream.writeErr = 1, failure
					} else {
						stream.closeErr, stream.closeCause = failure, failure
					}
					ctx, cancel := context.WithTimeout(context.Background(), time.Second)
					defer cancel()
					_, err := runCancellationClient(t, client, ctx, stream)
					if err == nil || !strings.Contains(err.Error(), failure.Error()) {
						t.Fatalf("upload failure lost: %v", err)
					}
				})
			}
		}
	}
}

func TestStopInterruptsUploadDelay(t *testing.T) {
	stream, peer := newCancellationStream(t)
	var response bytes.Buffer
	_ = wire.WriteFrame(&response, testOpen(t, wire.DestService, 2, "early response"))
	go func() {
		stream.cancelSend(&quic.StreamError{Remote: true, ErrorCode: 9})
		<-stream.closed
		_, _ = peer.Write(response.Bytes())
		_ = peer.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result := exchangeOnStream(ctx, stream, exchangeRequest{
		Chunks: []string{"head", "never send"}, DelayMS: 5000, ResponseMode: "required",
	}, time.Now())
	if result.Error != "" || len(result.RequestFrames) != 1 || len(result.ResponseFrames) != 1 {
		t.Fatalf("STOP did not interrupt delay and preserve response: %+v", result)
	}
}

func TestGenericStopPreservesResponseModeValidation(t *testing.T) {
	for _, tc := range []struct {
		mode    string
		body    string
		wantErr string
	}{
		{mode: "none"},
		{mode: "required", wantErr: "empty response stream"},
		{mode: "none", body: "unexpected", wantErr: "application frames"},
	} {
		t.Run(tc.mode+"/"+tc.wantErr, func(t *testing.T) {
			stream, peer := newCancellationStream(t)
			stream.failWrite = 1
			stream.writeErr = &quic.StreamError{ErrorCode: 123, Remote: true}
			go func() {
				<-stream.closed
				defer peer.Close()
				if tc.body != "" {
					frame, _ := wire.NewOpen(wire.DestService, 1, 2, wire.ResponseRequired, wire.FlagEOF, []byte(tc.body))
					_ = wire.WriteFrame(peer, frame)
				}
			}()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			result := exchangeOnStream(ctx, stream, exchangeRequest{
				Chunks: []string{"request"}, ResponseMode: tc.mode,
			}, time.Now())
			if (tc.wantErr == "" && result.Error != "") || !strings.Contains(result.Error, tc.wantErr) {
				t.Fatalf("response mode validation changed: %+v", result)
			}
			if stream.readCancel {
				t.Fatal("STOP canceled the response read")
			}
		})
	}
}
