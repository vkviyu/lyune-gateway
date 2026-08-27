package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vkviyu/lyune-gateway/validation/client-agent/internal/wire"
)

type Agent struct {
	mu          sync.RWMutex
	conn        *quic.Conn
	target      string
	serverName  string
	connectedAt time.Time
	imMu        sync.RWMutex
	imSessions  map[string]*imSession
}

type connectRequest struct {
	Address            string `json:"address"`
	ServerName         string `json:"server_name"`
	InsecureSkipVerify bool   `json:"insecure_skip_verify"`
}

type statusResponse struct {
	Connected          bool   `json:"connected"`
	Target             string `json:"target,omitempty"`
	ServerName         string `json:"server_name,omitempty"`
	ALPN               string `json:"alpn,omitempty"`
	LocalAddress       string `json:"local_address,omitempty"`
	RemoteAddress      string `json:"remote_address,omitempty"`
	ConnectedAt        string `json:"connected_at,omitempty"`
	ConnectionClosedBy string `json:"connection_closed_by,omitempty"`
}

type exchangeRequest struct {
	Kind        string   `json:"kind"`
	Group       uint8    `json:"group"`
	RouteKey    uint8    `json:"route_key"`
	Chunks      []string `json:"chunks"`
	DelayMS     int      `json:"delay_ms"`
	ReadDelayMS int      `json:"read_delay_ms"`
	TimeoutMS   int      `json:"timeout_ms"`
	Parallel    int      `json:"parallel"`
}

type observedFrame struct {
	Type       string `json:"type"`
	Flags      uint8  `json:"flags"`
	EOF        bool   `json:"eof"`
	DestKind   uint8  `json:"dest_kind,omitempty"`
	Group      uint8  `json:"group,omitempty"`
	RouteKey   uint8  `json:"route_key,omitempty"`
	Body       string `json:"body"`
	ObservedMS int64  `json:"observed_ms"`
}

type exchangeResult struct {
	StreamID       uint64          `json:"stream_id"`
	RequestFrames  []observedFrame `json:"request_frames"`
	ResponseFrames []observedFrame `json:"response_frames"`
	RequestFinMS   int64           `json:"request_fin_ms"`
	DurationMS     int64           `json:"duration_ms"`
	Error          string          `json:"error,omitempty"`
}

type exchangeResponse struct {
	Results  []exchangeResult `json:"results"`
	Passed   int              `json:"passed"`
	Failed   int              `json:"failed"`
	Parallel int              `json:"parallel"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8787", "HTTP listen address for the validation UI")
	flag.Parse()

	agent := &Agent{}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", agent.handleStatus)
	mux.HandleFunc("/api/connect", agent.handleConnect)
	mux.HandleFunc("/api/disconnect", agent.handleDisconnect)
	mux.HandleFunc("/api/exchange", agent.handleExchange)
	mux.HandleFunc("/api/im/auth", agent.handleIMAuth)
	mux.HandleFunc("/api/im/status", agent.handleIMStatus)
	mux.HandleFunc("/api/im/command", agent.handleIMCommand)
	mux.HandleFunc("/api/im/events", agent.handleIMEvents)
	mux.HandleFunc("/api/im/logout", agent.handleIMLogout)
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "alpn": wire.ALPN})
	})

	server := &http.Server{
		Addr:              *listen,
		Handler:           localCORS(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("Lyune validation client-agent listening on http://%s", *listen)
	log.Fatal(server.ListenAndServe())
}

func (a *Agent) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	writeJSON(w, http.StatusOK, a.statusLocked())
}

func (a *Agent) handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request connectRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if request.Address == "" {
		request.Address = "127.0.0.1:8443"
	}
	if request.ServerName == "" {
		request.ServerName = "localhost"
	}

	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, request.Address, &tls.Config{
		ServerName:         request.ServerName,
		NextProtos:         []string{wire.ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: request.InsecureSkipVerify, // Explicitly local-only; the UI labels this mode.
	}, &quic.Config{
		EnableDatagrams: true,
		KeepAlivePeriod: 10 * time.Second,
	})
	if err != nil {
		writeError(w, http.StatusBadGateway, fmt.Errorf("QUIC dial %s: %w", request.Address, err))
		return
	}

	a.mu.Lock()
	if a.conn != nil {
		_ = a.conn.CloseWithError(0, "replaced by validation UI")
	}
	a.conn = conn
	a.target = request.Address
	a.serverName = request.ServerName
	a.connectedAt = time.Now()
	status := a.statusLocked()
	a.mu.Unlock()

	log.Printf("connected target=%s local=%s alpn=%s", request.Address, conn.LocalAddr(), status.ALPN)
	writeJSON(w, http.StatusOK, status)
}

func (a *Agent) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	a.mu.Lock()
	if a.conn != nil {
		_ = a.conn.CloseWithError(0, "validation UI disconnect")
	}
	a.conn = nil
	a.target = ""
	a.serverName = ""
	a.connectedAt = time.Time{}
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, statusResponse{Connected: false})
}

func (a *Agent) handleExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request exchangeRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if len(request.Chunks) == 0 {
		request.Chunks = []string{"hello through lyune"}
	}
	if request.TimeoutMS <= 0 {
		request.TimeoutMS = 10_000
	}
	if request.DelayMS < 0 || request.ReadDelayMS < 0 || request.ReadDelayMS > 60_000 || request.TimeoutMS > 180_000 {
		writeError(w, http.StatusBadRequest, errors.New("delays must be non-negative, read_delay_ms at most 60000, and timeout_ms at most 180000"))
		return
	}
	if request.Parallel <= 0 {
		request.Parallel = 1
	}
	if request.Parallel > 128 {
		writeError(w, http.StatusBadRequest, errors.New("parallel must be at most 128"))
		return
	}

	conn, err := a.connection()
	if err != nil {
		writeError(w, http.StatusConflict, err)
		return
	}

	results := make([]exchangeResult, request.Parallel)
	var wait sync.WaitGroup
	for index := range results {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results[index] = runExchange(r.Context(), conn, request)
		}()
	}
	wait.Wait()

	response := exchangeResponse{Results: results, Parallel: request.Parallel}
	for _, result := range results {
		if result.Error == "" {
			response.Passed++
		} else {
			response.Failed++
		}
	}
	status := http.StatusOK
	if response.Failed > 0 {
		status = http.StatusBadGateway
	}
	writeJSON(w, status, response)
}

func runExchange(parent context.Context, conn *quic.Conn, request exchangeRequest) exchangeResult {
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, time.Duration(request.TimeoutMS)*time.Millisecond)
	defer cancel()

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return exchangeResult{Error: fmt.Sprintf("open stream: %v", err)}
	}
	deadline := started.Add(time.Duration(request.TimeoutMS) * time.Millisecond)
	_ = stream.SetDeadline(deadline)
	result := exchangeResult{StreamID: uint64(stream.StreamID())}

	type readResult struct {
		frames []observedFrame
		err    error
	}
	readDone := make(chan readResult, 1)
	go func() {
		if request.ReadDelayMS > 0 {
			select {
			case <-ctx.Done():
				readDone <- readResult{err: ctx.Err()}
				return
			case <-time.After(time.Duration(request.ReadDelayMS) * time.Millisecond):
			}
		}
		var frames []observedFrame
		for {
			frame, readErr := wire.ReadFrame(stream)
			if readErr != nil {
				if readErr == io.EOF {
					readErr = nil
				}
				readDone <- readResult{frames: frames, err: readErr}
				return
			}
			frames = append(frames, observe(frame, time.Since(started)))
		}
	}()

	dest := wire.DestService
	group := request.Group
	routeKey := request.RouteKey
	if request.Kind == "control" {
		dest = wire.DestGateway
		group = 0
	} else if request.Kind != "" && request.Kind != "service" {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return exchangeResult{StreamID: result.StreamID, Error: "kind must be service or control"}
	}

	for index, chunk := range request.Chunks {
		flags := wire.Flags(0)
		if index == len(request.Chunks)-1 {
			flags |= wire.FlagEOF
		}
		var frame *wire.Frame
		if index == 0 {
			frame, err = wire.NewOpen(dest, group, routeKey, flags, []byte(chunk))
		} else {
			frame, err = wire.NewData(flags, []byte(chunk))
		}
		if err != nil {
			stream.CancelRead(1)
			stream.CancelWrite(1)
			return exchangeResult{StreamID: result.StreamID, Error: fmt.Sprintf("build frame: %v", err)}
		}
		if err := wire.WriteFrame(stream, frame); err != nil {
			stream.CancelRead(1)
			stream.CancelWrite(1)
			return exchangeResult{StreamID: result.StreamID, Error: fmt.Sprintf("write frame: %v", err)}
		}
		result.RequestFrames = append(result.RequestFrames, observe(frame, time.Since(started)))
		if request.DelayMS > 0 && index != len(request.Chunks)-1 {
			select {
			case <-ctx.Done():
				stream.CancelRead(1)
				stream.CancelWrite(1)
				return exchangeResult{StreamID: result.StreamID, Error: ctx.Err().Error()}
			case <-time.After(time.Duration(request.DelayMS) * time.Millisecond):
			}
		}
	}
	result.RequestFinMS = time.Since(started).Milliseconds()
	if err := stream.Close(); err != nil {
		return exchangeResult{StreamID: result.StreamID, Error: fmt.Sprintf("close request side: %v", err)}
	}

	select {
	case read := <-readDone:
		result.ResponseFrames = read.frames
		if read.err != nil {
			result.Error = fmt.Sprintf("read response: %v", read.err)
		} else if len(read.frames) == 0 {
			result.Error = "gateway returned an empty response stream"
		} else {
			for _, frame := range read.frames {
				if frame.Type == "OPEN" && frame.DestKind == uint8(wire.DestGateway) && frame.RouteKey == 0xF0 {
					result.Error = fmt.Sprintf("gateway error: %s", frame.Body)
					break
				}
			}
		}
	case <-ctx.Done():
		stream.CancelRead(1)
		select {
		case read := <-readDone:
			result.ResponseFrames = read.frames
		case <-time.After(100 * time.Millisecond):
		}
		result.Error = fmt.Sprintf("wait response: %v", ctx.Err())
	}
	result.DurationMS = time.Since(started).Milliseconds()
	return result
}

func observe(frame *wire.Frame, elapsed time.Duration) observedFrame {
	typeName := "DATA"
	if frame.Header.Type == wire.FrameOpen {
		typeName = "OPEN"
	}
	return observedFrame{
		Type:       typeName,
		Flags:      uint8(frame.Header.Flags),
		EOF:        frame.Header.Flags.IsEOF(),
		DestKind:   uint8(frame.Header.DestKind),
		Group:      frame.Header.Group,
		RouteKey:   frame.Header.RouteKey,
		Body:       string(frame.Body),
		ObservedMS: elapsed.Milliseconds(),
	}
}

func (a *Agent) connection() (*quic.Conn, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.conn == nil {
		return nil, errors.New("not connected; call /api/connect first")
	}
	select {
	case <-a.conn.Context().Done():
		return nil, fmt.Errorf("QUIC connection is closed: %w", context.Cause(a.conn.Context()))
	default:
		return a.conn, nil
	}
}

func (a *Agent) statusLocked() statusResponse {
	if a.conn == nil {
		return statusResponse{Connected: false}
	}
	select {
	case <-a.conn.Context().Done():
		return statusResponse{
			Connected:          false,
			Target:             a.target,
			ServerName:         a.serverName,
			ConnectionClosedBy: fmt.Sprint(context.Cause(a.conn.Context())),
		}
	default:
		state := a.conn.ConnectionState()
		return statusResponse{
			Connected:     true,
			Target:        a.target,
			ServerName:    a.serverName,
			ALPN:          state.TLS.NegotiatedProtocol,
			LocalAddress:  a.conn.LocalAddr().String(),
			RemoteAddress: a.conn.RemoteAddr().String(),
			ConnectedAt:   a.connectedAt.Format(time.RFC3339Nano),
		}
	}
}

func decodeJSON(r *http.Request, target any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func methodNotAllowed(w http.ResponseWriter) {
	writeError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
}

func localCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "http://127.0.0.1:5173" || origin == "http://localhost:5173" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
