package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/vkviyu/lyune-gateway/validation/client-agent/internal/wire"
)

const (
	imGroup = 1
	imRoute = 2
)

type imUser struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
}

type imSession struct {
	id          string
	conn        *quic.Conn
	target      string
	serverName  string
	connectedAt time.Time

	mu              sync.RWMutex
	token           string
	destID          uint64
	ttl             uint32
	user            *imUser
	events          []imEvent
	nextSeq         uint64
	notify          chan struct{}
	closedErr       string
	writeOnNextPush bool
}

type imEvent struct {
	Seq        uint64          `json:"seq"`
	ReceivedAt string          `json:"received_at"`
	Targets    []uint64        `json:"targets"`
	Payload    json.RawMessage `json:"payload"`
}

type imSessionStatus struct {
	SessionID          string  `json:"session_id"`
	Connected          bool    `json:"connected"`
	Authenticated      bool    `json:"authenticated"`
	Target             string  `json:"target,omitempty"`
	ALPN               string  `json:"alpn,omitempty"`
	LocalAddress       string  `json:"local_address,omitempty"`
	RemoteAddress      string  `json:"remote_address,omitempty"`
	ConnectedAt        string  `json:"connected_at,omitempty"`
	DestID             uint64  `json:"dest_id,omitempty"`
	AdmissionTTL       uint32  `json:"admission_ttl_seconds,omitempty"`
	User               *imUser `json:"user,omitempty"`
	ConnectionClosedBy string  `json:"connection_closed_by,omitempty"`
}

type imAuthRequest struct {
	SessionID  string `json:"session_id,omitempty"`
	Address    string `json:"address,omitempty"`
	ServerName string `json:"server_name,omitempty"`
	Insecure   bool   `json:"insecure_skip_verify"`
	Action     string `json:"action"`
	Username   string `json:"username"`
	Password   string `json:"password"`
}

type imCommandRequest struct {
	SessionID  string `json:"session_id"`
	Type       string `json:"type"`
	Name       string `json:"name,omitempty"`
	InviteCode string `json:"invite_code,omitempty"`
	GroupID    uint64 `json:"group_id,omitempty"`
	Text       string `json:"text,omitempty"`
}

type imAuthPayload struct {
	OK        bool    `json:"ok"`
	Type      string  `json:"type"`
	Token     string  `json:"token"`
	ExpiresAt string  `json:"expires_at"`
	User      *imUser `json:"user"`
}

func (a *Agent) handleIMAuth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request imAuthRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	session, created, err := a.imSessionForAuth(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if err := session.authenticate(r.Context(), request.Action, request.Username, request.Password); err != nil {
		if created {
			a.removeIMSession(session.id)
			session.close("authentication rejected")
		}
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	writeJSON(w, http.StatusOK, session.status())
}

func (a *Agent) handleIMStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, err := a.imSession(r.URL.Query().Get("session_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeJSON(w, http.StatusOK, session.status())
}

func (a *Agent) handleIMCommand(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request imCommandRequest
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	session, err := a.imSession(request.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	payload, err := session.command(r.Context(), request)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

// handleIMExchange runs transport-level validation streams on an already
// authenticated IM connection. It is deliberately separate from application
// commands and is only exposed by the loopback validation agent.
func (a *Agent) handleIMExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		SessionID string `json:"session_id"`
		exchangeRequest
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := prepareExchangeRequest(&request.exchangeRequest); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	session, err := a.imSession(request.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	writeExchangeResponse(w, runExchanges(r.Context(), session.conn, request.exchangeRequest))
}

func (a *Agent) handleIMEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w)
		return
	}
	session, err := a.imSession(r.URL.Query().Get("session_id"))
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	after, _ := strconv.ParseUint(r.URL.Query().Get("after"), 10, 64)
	timeoutMS, _ := strconv.Atoi(r.URL.Query().Get("timeout_ms"))
	if timeoutMS <= 0 || timeoutMS > 30_000 {
		timeoutMS = 25_000
	}
	events := session.waitEvents(r.Context(), after, time.Duration(timeoutMS)*time.Millisecond)
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (a *Agent) handleIMLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	session, err := a.imSession(request.SessionID)
	if err == nil {
		a.removeIMSession(request.SessionID)
		session.close("user logged out")
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// / Validation-only negative path: arm one IM session to send application bytes back on the
// / next Gateway-initiated stream. lyune/2 reserves that reverse half for an empty FIN, so the
// / Gateway must close this connection as a protocol violation without affecting other users.
func (a *Agent) handleIMViolateServerStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w)
		return
	}
	var request struct {
		SessionID string `json:"session_id"`
	}
	if err := decodeJSON(r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	session, err := a.imSession(request.SessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, err)
		return
	}
	session.mu.Lock()
	session.writeOnNextPush = true
	session.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "armed": true})
}

func (a *Agent) imSessionForAuth(ctx context.Context, request imAuthRequest) (*imSession, bool, error) {
	if request.SessionID != "" {
		session, err := a.imSession(request.SessionID)
		return session, false, err
	}
	address := request.Address
	if address == "" {
		address = "127.0.0.1:8443"
	}
	serverName := request.ServerName
	if serverName == "" {
		serverName = "localhost"
	}
	dialCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(dialCtx, address, &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{wire.ALPN},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: request.Insecure, // Local validation only; exposed explicitly in the UI.
	}, &quic.Config{EnableDatagrams: true, KeepAlivePeriod: 10 * time.Second})
	if err != nil {
		return nil, false, fmt.Errorf("QUIC dial %s: %w", address, err)
	}
	id, err := randomID(18)
	if err != nil {
		_ = conn.CloseWithError(1, "session id generation failed")
		return nil, false, err
	}
	session := &imSession{
		id: id, conn: conn, target: address, serverName: serverName,
		connectedAt: time.Now(), notify: make(chan struct{}),
	}
	a.imMu.Lock()
	if a.imSessions == nil {
		a.imSessions = make(map[string]*imSession)
	}
	a.imSessions[id] = session
	a.imMu.Unlock()
	go session.acceptPushes()
	log.Printf("IM session connected id=%s target=%s local=%s", id, address, conn.LocalAddr())
	return session, true, nil
}

func (a *Agent) imSession(id string) (*imSession, error) {
	if id == "" {
		return nil, errors.New("session_id is required")
	}
	a.imMu.RLock()
	session := a.imSessions[id]
	a.imMu.RUnlock()
	if session == nil {
		return nil, errors.New("IM session not found")
	}
	return session, nil
}

func (a *Agent) removeIMSession(id string) {
	a.imMu.Lock()
	delete(a.imSessions, id)
	a.imMu.Unlock()
}

func (s *imSession) authenticate(ctx context.Context, action, username, password string) error {
	body, err := json.Marshal(map[string]string{"action": action, "username": username, "password": password})
	if err != nil {
		return err
	}
	request, err := wire.NewOpen(wire.DestGateway, 0, 0x10, wire.ResponseRequired, wire.FlagEOF, body)
	if err != nil {
		return err
	}
	response, err := s.exchange(ctx, request)
	if err != nil {
		return err
	}
	if response.Header.Type != wire.FrameOpen || response.Header.DestKind != wire.DestGateway {
		return errors.New("gateway returned an invalid authentication response")
	}
	if response.Header.RouteKey == 0x12 {
		return fmt.Errorf("authentication rejected: %s", response.Body)
	}
	if response.Header.RouteKey != 0x11 {
		return fmt.Errorf("unexpected authentication control type 0x%02x", response.Header.RouteKey)
	}
	destID, ttl, opaque, err := wire.ParseAuthGrant(response.Body)
	if err != nil {
		return fmt.Errorf("parse auth grant: %w", err)
	}
	var payload imAuthPayload
	if err := json.Unmarshal(opaque, &payload); err != nil || !payload.OK || payload.Token == "" || payload.User == nil {
		return errors.New("authentication service returned an invalid application session")
	}
	s.mu.Lock()
	s.token, s.destID, s.ttl, s.user = payload.Token, destID, ttl, payload.User
	s.mu.Unlock()
	return nil
}

func (s *imSession) command(ctx context.Context, request imCommandRequest) (json.RawMessage, error) {
	s.mu.RLock()
	token := s.token
	s.mu.RUnlock()
	if token == "" {
		return nil, errors.New("session is not authenticated")
	}
	body, err := json.Marshal(map[string]any{
		"type": request.Type, "token": token, "name": request.Name,
		"invite_code": request.InviteCode, "group_id": request.GroupID, "text": request.Text,
	})
	if err != nil {
		return nil, err
	}
	responseMode := wire.ResponseRequired
	if request.Type == "typing" {
		responseMode = wire.ResponseNone
	}
	frame, err := wire.NewOpen(wire.DestService, imGroup, imRoute, responseMode, wire.FlagEOF, body)
	if err != nil {
		return nil, err
	}
	if responseMode == wire.ResponseNone {
		if err := s.sendNoResponse(ctx, frame); err != nil {
			return nil, err
		}
		return json.RawMessage(`{"ok":true,"type":"accepted"}`), nil
	}
	response, err := s.exchange(ctx, frame)
	if err != nil {
		return nil, err
	}
	if response.Header.Type == wire.FrameOpen && response.Header.DestKind == wire.DestGateway && response.Header.RouteKey == 0xF0 {
		return nil, fmt.Errorf("gateway rejected IM exchange: %s", response.Body)
	}
	if response.Header.Type != wire.FrameOpen || response.Header.DestKind != wire.DestService {
		return nil, errors.New("gateway returned an invalid IM response")
	}
	if !json.Valid(response.Body) {
		return nil, errors.New("IM backend returned invalid JSON")
	}
	return json.RawMessage(response.Body), nil
}

func (s *imSession) sendNoResponse(parent context.Context, request *wire.Frame) error {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open no-response stream: %w", err)
	}
	_ = stream.SetDeadline(time.Now().Add(4 * time.Second))
	if err := wire.WriteFrame(stream, request); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return fmt.Errorf("write no-response request: %w", err)
	}
	if err := stream.Close(); err != nil {
		return fmt.Errorf("finish no-response request: %w", err)
	}
	response, err := wire.ReadFrame(stream)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("finish no-response exchange: %w", err)
	}
	if response.Header.DestKind == wire.DestGateway && response.Header.RouteKey == 0xF0 {
		return fmt.Errorf("gateway rejected no-response exchange: %s", response.Body)
	}
	return errors.New("no-response exchange unexpectedly returned an application frame")
}

func (s *imSession) exchange(parent context.Context, request *wire.Frame) (*wire.Frame, error) {
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open QUIC stream: %w", err)
	}
	deadline := time.Now().Add(12 * time.Second)
	_ = stream.SetDeadline(deadline)
	if err := wire.WriteFrame(stream, request); err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, fmt.Errorf("write request: %w", err)
	}
	if err := stream.Close(); err != nil {
		return nil, fmt.Errorf("finish request: %w", err)
	}
	response, err := wire.ReadFrame(stream)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if !response.Header.Flags.IsEOF() {
		stream.CancelRead(1)
		return nil, errors.New("one-shot response did not carry EOF")
	}
	return response, nil
}

func (s *imSession) acceptPushes() {
	for {
		stream, err := s.conn.AcceptStream(s.conn.Context())
		if err != nil {
			s.mu.Lock()
			if s.closedErr == "" {
				s.closedErr = fmt.Sprint(context.Cause(s.conn.Context()))
			}
			s.signalLocked()
			s.mu.Unlock()
			return
		}
		go s.readPush(stream)
	}
}

func (s *imSession) readPush(stream *quic.Stream) {
	defer stream.Close()
	frame, err := wire.ReadFrame(stream)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Printf("IM session %s read push: %v", s.id, err)
		}
		return
	}
	if frame.Header.Type != wire.FrameOpen || frame.Header.DestKind != wire.DestPeer || !frame.Header.Flags.IsEOF() {
		log.Printf("IM session %s rejected non one-shot .peer push", s.id)
		return
	}
	s.mu.Lock()
	violateDirection := s.writeOnNextPush
	s.writeOnNextPush = false
	s.mu.Unlock()
	if violateDirection {
		invalid, buildErr := wire.NewOpen(wire.DestService, imGroup, imRoute, wire.ResponseRequired, wire.FlagEOF, []byte("client bytes on a Gateway-initiated stream"))
		if buildErr == nil {
			_ = wire.WriteFrame(stream, invalid)
		}
		return
	}
	targets, payload, err := wire.ParseTargetList(frame.Body)
	if err != nil || !json.Valid(payload) {
		log.Printf("IM session %s rejected malformed push: %v", s.id, err)
		return
	}
	s.mu.Lock()
	s.nextSeq++
	event := imEvent{
		Seq: s.nextSeq, ReceivedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Targets: targets, Payload: append(json.RawMessage(nil), payload...),
	}
	s.events = append(s.events, event)
	if len(s.events) > 512 {
		s.events = append([]imEvent(nil), s.events[len(s.events)-512:]...)
	}
	s.signalLocked()
	s.mu.Unlock()
}

func (s *imSession) waitEvents(ctx context.Context, after uint64, timeout time.Duration) []imEvent {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		s.mu.RLock()
		events := s.eventsAfterLocked(after)
		notify := s.notify
		s.mu.RUnlock()
		if len(events) > 0 {
			return events
		}
		select {
		case <-ctx.Done():
			return []imEvent{}
		case <-deadline.C:
			return []imEvent{}
		case <-notify:
		}
	}
}

func (s *imSession) eventsAfterLocked(after uint64) []imEvent {
	index := 0
	for index < len(s.events) && s.events[index].Seq <= after {
		index++
	}
	return append([]imEvent(nil), s.events[index:]...)
}

func (s *imSession) signalLocked() {
	close(s.notify)
	s.notify = make(chan struct{})
}

func (s *imSession) status() imSessionStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	status := imSessionStatus{
		SessionID: s.id, Target: s.target, ConnectedAt: s.connectedAt.Format(time.RFC3339Nano),
		DestID: s.destID, AdmissionTTL: s.ttl, User: s.user,
		Authenticated: s.token != "", ConnectionClosedBy: s.closedErr,
	}
	select {
	case <-s.conn.Context().Done():
		return status
	default:
		state := s.conn.ConnectionState()
		status.Connected = true
		status.ALPN = state.TLS.NegotiatedProtocol
		status.LocalAddress = s.conn.LocalAddr().String()
		status.RemoteAddress = s.conn.RemoteAddr().String()
		return status
	}
}

func (s *imSession) close(reason string) {
	_ = s.conn.CloseWithError(0, reason)
	s.mu.Lock()
	s.closedErr = reason
	s.signalLocked()
	s.mu.Unlock()
}

func randomID(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
