//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vkviyu/lyune-gateway/validation/client-agent/internal/wire"
	"golang.org/x/net/websocket"
)

// Run with -tags=integration -run TestBackendHalfCloseLoopback -count=1.
// LYUNE_GATEWAY_BIN must name a locally built gateway executable.
// All listeners use ephemeral loopback ports; TLS keys and config are temporary.
func TestBackendHalfCloseLoopback(t *testing.T) {
	for _, transport := range []string{"RawQUIC", "WSS"} {
		for _, scenario := range []string{"EarlyFIN", "STOP_SENDING"} {
			t.Run(transport+"/"+scenario, func(t *testing.T) {
				backend, rawAddr, wssAddr := startHalfCloseGateway(t)
				ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
				defer cancel()
				deadline, _ := ctx.Deadline()
				var client halfCloseClient
				if transport == "RawQUIC" {
					client = rawHalfCloseClient(t, ctx, rawAddr)
				} else {
					client = wssHalfCloseClient(t, ctx, wssAddr)
				}

				open, err := wire.NewOpen(wire.DestService, 1, 0, wire.ResponseRequired, 0, []byte(scenario))
				halfCloseCheck(t, err)
				client.send(halfCloseBytes(t, open), false)
				stream, err := backend.AcceptStream(ctx)
				halfCloseCheck(t, err)
				halfCloseCheck(t, stream.SetDeadline(deadline))
				got, err := wire.ReadFrame(stream)
				halfCloseCheck(t, err)
				if got.Header != open.Header || !bytes.Equal(got.Body, open.Body) {
					t.Fatalf("backend got unexpected OPEN: %+v", got)
				}

				stop := scenario == "STOP_SENDING"
				if stop {
					stream.CancelRead(0x102) // Only gateway -> backend.
				}
				reply, err := wire.NewOpen(wire.DestService, 1, 0, wire.ResponseRequired, wire.FlagEOF, []byte("receipt:"+scenario))
				halfCloseCheck(t, err)
				want := halfCloseBytes(t, reply)
				_, err = stream.Write(want)
				halfCloseCheck(t, err)
				halfCloseCheck(t, stream.Close())
				if got := client.response(stop); !bytes.Equal(got, want) {
					t.Fatalf("final response through FIN = %q, want %q", got, want)
				}
				t.Log("exact business response and response FIN received with upload still open")
				if !stop {
					// Causally after the client observed response transport FIN.
					tail, err := wire.NewData(wire.FlagEOF, []byte("upload after response FIN"))
					halfCloseCheck(t, err)
					wantTail := halfCloseBytes(t, tail)
					client.send(wantTail, true)
					gotTail, err := io.ReadAll(stream)
					if err != nil || !bytes.Equal(gotTail, wantTail) {
						t.Fatalf("backend upload through FIN = %q, %v; want %q and clean FIN", gotTail, err, wantTail)
					}
					t.Log("backend received exact post-response upload and clean request FIN")
				}
			})
		}
	}
}

// Exercise the agent's actual exchange implementation as well as the causally
// ordered transport probes above. This catches clients that cancel their reader
// when a remote STOP_SENDING makes a write or Close fail.
func TestBackendHalfCloseValidationAgent(t *testing.T) {
	for _, stop := range []bool{false, true} {
		name := "EarlyFIN"
		if stop {
			name = "STOP_SENDING"
		}
		t.Run(name, func(t *testing.T) {
			backend, rawAddr, _ := startHalfCloseGateway(t)
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()
			conn := connectHalfCloseAgent(t, ctx, rawAddr)
			done := make(chan exchangeResult, 1)
			go func() {
				done <- runExchange(ctx, conn, exchangeRequest{
					Kind: "service", Group: 1, Chunks: []string{"agent-head", "agent-tail"},
					DelayMS: 500, TimeoutMS: 6000, ResponseMode: "required",
				})
			}()
			stream, err := backend.AcceptStream(ctx)
			halfCloseCheck(t, err)
			deadline, _ := ctx.Deadline()
			halfCloseCheck(t, stream.SetDeadline(deadline))
			head, err := wire.ReadFrame(stream)
			halfCloseCheck(t, err)
			if head.Header.Type != wire.FrameOpen || head.Header.Flags.IsEOF() || string(head.Body) != "agent-head" {
				t.Fatalf("unexpected agent OPEN: %+v", head)
			}
			if stop {
				stream.CancelRead(0x102)
			}
			reply, err := wire.NewOpen(wire.DestService, 1, 0, wire.ResponseRequired, wire.FlagEOF, []byte("agent-receipt"))
			halfCloseCheck(t, err)
			halfCloseCheck(t, wire.WriteFrame(stream, reply))
			halfCloseCheck(t, stream.Close())
			select {
			case result := <-done:
				if result.Error != "" || len(result.ResponseFrames) != 1 {
					t.Fatalf("agent failed to retain business response: %+v", result)
				}
				frame := result.ResponseFrames[0]
				if frame.Type != "OPEN" || frame.DestKind != 1 || frame.Group != 1 || frame.RouteKey != 0 || !frame.EOF || frame.Body != "agent-receipt" {
					t.Fatalf("agent response changed: %+v", frame)
				}
				if stop {
					if len(result.RequestFrames) != 1 {
						t.Fatalf("agent did not stop upload: %+v", result)
					}
				} else {
					if len(result.RequestFrames) != 2 || frame.ObservedMS >= result.RequestFrames[1].ObservedMS {
						t.Fatalf("agent did not upload after observing business response: %+v", result)
					}
					tail, err := wire.NewData(wire.FlagEOF, []byte("agent-tail"))
					halfCloseCheck(t, err)
					got, err := io.ReadAll(stream)
					halfCloseCheck(t, err)
					if !bytes.Equal(got, halfCloseBytes(t, tail)) {
						t.Fatalf("agent tail not delivered to backend: %q", got)
					}
				}
			case <-ctx.Done():
				t.Fatal("validation agent did not complete")
			}
			// Prove the physical connection survives cancellation/half close.
			ping := runExchange(ctx, conn, exchangeRequest{
				Kind: "control", RouteKey: 2, Chunks: []string{"after-half-close"},
				TimeoutMS: 1000, ResponseMode: "required",
			})
			if ping.Error != "" || len(ping.ResponseFrames) != 1 || ping.ResponseFrames[0].RouteKey != 3 || ping.ResponseFrames[0].Body != "after-half-close" {
				t.Fatalf("same-connection ping failed: %+v", ping)
			}
			t.Log("real agent exchange retained business response; same-connection ping passed")
		})
	}
}

func halfCloseCheck(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func halfCloseBytes(t *testing.T, frame *wire.Frame) []byte {
	t.Helper()
	var buf bytes.Buffer
	halfCloseCheck(t, wire.WriteFrame(&buf, frame))
	return buf.Bytes()
}

type halfCloseClient struct {
	send     func([]byte, bool)
	response func(expectStop bool) []byte
}

func connectHalfCloseAgent(t *testing.T, ctx context.Context, addr string) *quic.Conn {
	t.Helper()
	// Reuse the real validation agent connect path. Explicit stream operations
	// let the next upload depend on receipt of FIN instead of a timed delay.
	a := &Agent{}
	req := httptest.NewRequestWithContext(ctx, "POST", "/api/connect", strings.NewReader(fmt.Sprintf(
		`{"address":%q,"server_name":"localhost","insecure_skip_verify":true}`, addr)))
	w := httptest.NewRecorder()
	a.handleConnect(w, req)
	if w.Code != 200 {
		t.Fatalf("agent connect: %s", w.Body.String())
	}
	conn, err := a.connection()
	halfCloseCheck(t, err)
	t.Cleanup(func() { _ = conn.CloseWithError(0, "test done") })
	return conn
}

func rawHalfCloseClient(t *testing.T, ctx context.Context, addr string) halfCloseClient {
	t.Helper()
	conn := connectHalfCloseAgent(t, ctx, addr)
	s, err := conn.OpenStreamSync(ctx)
	halfCloseCheck(t, err)
	deadline, _ := ctx.Deadline()
	halfCloseCheck(t, s.SetDeadline(deadline))
	return halfCloseClient{
		send: func(b []byte, fin bool) {
			_, err := s.Write(b)
			halfCloseCheck(t, err)
			if fin {
				halfCloseCheck(t, s.Close())
			}
		},
		response: func(stop bool) []byte {
			b, err := io.ReadAll(s)
			halfCloseCheck(t, err)
			if stop {
				select {
				case <-s.Context().Done():
					var stopped *quic.StreamError
					if !errors.As(context.Cause(s.Context()), &stopped) || !stopped.Remote {
						t.Fatalf("expected remote STOP_SENDING, got %v", context.Cause(s.Context()))
					}
				case <-ctx.Done():
					t.Errorf("missing STOP_SENDING on upload; received response %q", b)
				}
			}
			return b
		},
	}
}

func wssHalfCloseClient(t *testing.T, ctx context.Context, addr string) halfCloseClient {
	t.Helper()
	_, port, err := net.SplitHostPort(addr)
	halfCloseCheck(t, err)
	cfg, err := websocket.NewConfig("wss://localhost:"+port+"/lyune/v2", "http://127.0.0.1")
	halfCloseCheck(t, err)
	cfg.Protocol = []string{"lyune.v2"}
	cfg.TlsConfig = &tls.Config{ServerName: "localhost", InsecureSkipVerify: true} // ephemeral loopback cert
	// Dial numeric loopback directly, while HTTP Host agrees with TLS SNI.
	dialer := tls.Dialer{Config: cfg.TlsConfig}
	socket, err := dialer.DialContext(ctx, "tcp", addr)
	halfCloseCheck(t, err)
	t.Cleanup(func() { _ = socket.Close() })
	deadline, _ := ctx.Deadline()
	halfCloseCheck(t, socket.SetDeadline(deadline))
	ws, err := websocket.NewClient(cfg, socket)
	halfCloseCheck(t, err)
	t.Cleanup(func() { _ = ws.Close() })
	halfCloseCheck(t, ws.SetDeadline(deadline))
	// One physical connection per case, hence client logical stream ID 0.
	return halfCloseClient{
		send: func(payload []byte, fin bool) {
			record := make([]byte, 20+len(payload))
			record[0], record[1] = 1, 1
			if fin {
				record[2] = 1
			}
			binary.BigEndian.PutUint32(record[16:20], uint32(len(payload)))
			copy(record[20:], payload)
			halfCloseCheck(t, websocket.Message.Send(ws, record))
		},
		response: func(expectStop bool) []byte {
			var body []byte
			var fin, stopped bool
			for !fin || (expectStop && !stopped) {
				var record []byte
				if err := websocket.Message.Receive(ws, &record); err != nil {
					t.Fatalf("read WSS stream 0 (FIN=%t STOP=%t response=%q): %v", fin, stopped, body, err)
				}
				if len(record) < 20 || record[0] != 1 || record[3] != 0 || record[2]&^byte(1) != 0 ||
					binary.BigEndian.Uint64(record[4:12]) != 0 || int(binary.BigEndian.Uint32(record[16:20])) != len(record)-20 {
					t.Fatalf("unexpected WSS envelope: %x", record)
				}
				switch record[1] {
				case 1:
					if fin {
						t.Fatal("STREAM after response FIN")
					}
					body = append(body, record[20:]...)
					fin = record[2]&1 != 0
				case 3: // STOP upload; acknowledge RESET but keep reading response.
					if !expectStop || stopped || len(record) != 20 || record[2] != 0 {
						t.Fatalf("unexpected STOP: %x", record)
					}
					stopped = true
					record[1] = 2
					halfCloseCheck(t, websocket.Message.Send(ws, record))
				default:
					t.Fatalf("unexpected WSS record type %d on response", record[1])
				}
			}
			return body
		},
	}
}

func startHalfCloseGateway(t *testing.T) (backend *quic.Conn, rawAddr, wssAddr string) {
	t.Helper()
	dir := t.TempDir()
	bin := os.Getenv("LYUNE_GATEWAY_BIN")
	if bin == "" {
		t.Fatal("set LYUNE_GATEWAY_BIN to an absolute path to a locally built gateway")
	}
	if !filepath.IsAbs(bin) {
		t.Fatal("LYUNE_GATEWAY_BIN must be absolute")
	}
	cert, key := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if out, err := exec.Command("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", key, "-out", cert).CombinedOutput(); err != nil {
		t.Fatalf("generate temporary TLS identity: %v: %s", err, out)
	}
	pair, err := tls.LoadX509KeyPair(cert, key)
	halfCloseCheck(t, err)
	listener, err := quic.ListenAddr("127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{pair}, NextProtos: []string{wire.ALPN}}, nil)
	halfCloseCheck(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	halfCloseCheck(t, err)
	defer udp.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	halfCloseCheck(t, err)
	defer tcp.Close()
	rawAddr, wssAddr = udp.LocalAddr().String(), tcp.Addr().String()
	config := fmt.Sprintf(`{
		"runtime":{"threads":1},
		"server":{"listen_host":"127.0.0.1","listen_port":%d,"certificate_file":%q,"private_key_file":%q,
			"quic":{"max_connections":16,"idle_timeout_ms":60000,"alpn":"lyune/2","congestion_control":"bbr"},
			"wss":{"enabled":true,"listen_host":"127.0.0.1","listen_port":%d,"allowed_origins":["http://127.0.0.1"]}},
		"backend":{"direct":{"routes":[{"group":1,"route_key":0,"endpoints":[{"host":"127.0.0.1","port":%d}]}],
			"verify_certificate":false,"root_certificate_file":null,"max_receive_queue":32,"idle_timeout_ms":60000,"alpn":"lyune/2","congestion_control":"bbr"}},
		"worker":{"backend_poll_interval_ms":2},
		"cluster":{"enabled":false,"node_id":1,"advertise_host":"127.0.0.1","advertise_port":7946,"handoff_queue_capacity":16}
	}`, udp.LocalAddr().(*net.UDPAddr).Port, cert, key, tcp.Addr().(*net.TCPAddr).Port, listener.Addr().(*net.UDPAddr).Port)
	configPath := filepath.Join(dir, "gateway.json")
	halfCloseCheck(t, os.WriteFile(configPath, []byte(config), 0600))
	log, err := os.Create(filepath.Join(dir, "gateway.log"))
	halfCloseCheck(t, err)
	defer log.Close()
	cmd := exec.Command(bin, "server", "--config", configPath)
	cmd.Dir, cmd.Stdout, cmd.Stderr = dir, log, log
	halfCloseCheck(t, udp.Close())
	halfCloseCheck(t, tcp.Close())
	halfCloseCheck(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			b, _ := os.ReadFile(log.Name())
			t.Logf("gateway log:\n%s", b)
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
	defer cancel()
	backend, err = listener.Accept(ctx)
	halfCloseCheck(t, err)
	t.Cleanup(func() { _ = backend.CloseWithError(0, "test done") })
	return backend, rawAddr, wssAddr
}
