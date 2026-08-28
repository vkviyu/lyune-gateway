// im-mixed-load drives the real validation client-agent HTTP API. The agent then
// uses independent native QUIC connections to exercise Gateway and Reactor, so
// this command does not replace any part of the transport under test.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

type config struct {
	agentURL   string
	gateway    string
	serverName string
	prefix     string
	password   string
	users      int
	messages   int
	typings    int
	queries    int
}

type runner struct {
	config config
	client *http.Client
}

type user struct {
	ID       uint64 `json:"id"`
	Username string `json:"username"`
}

type sessionStatus struct {
	SessionID     string `json:"session_id"`
	Connected     bool   `json:"connected"`
	Authenticated bool   `json:"authenticated"`
	ALPN          string `json:"alpn"`
	User          *user  `json:"user"`
}

type group struct {
	ID         uint64 `json:"id"`
	Name       string `json:"name"`
	InviteCode string `json:"invite_code"`
}

type message struct {
	ID     uint64 `json:"id"`
	Text   string `json:"text"`
	Sender user   `json:"sender"`
}

type presence struct {
	User           user `json:"user"`
	Online         bool `json:"online"`
	OnlineSessions int  `json:"online_sessions"`
}

type commandResponse struct {
	OK       bool       `json:"ok"`
	Type     string     `json:"type"`
	Error    string     `json:"error"`
	Group    *group     `json:"group"`
	Message  *message   `json:"message"`
	Messages []message  `json:"messages"`
	Presence []presence `json:"presence"`
}

type event struct {
	Seq     uint64          `json:"seq"`
	Targets []uint64        `json:"targets"`
	Payload json.RawMessage `json:"payload"`
}

type eventsResponse struct {
	Events []event `json:"events"`
}

type eventPayload struct {
	OK      bool     `json:"ok"`
	Type    string   `json:"type"`
	GroupID uint64   `json:"group_id"`
	User    *user    `json:"user"`
	Message *message `json:"message"`
}

type exchangeResult struct {
	Error       string `json:"error"`
	Termination string `json:"termination"`
}

type exchangeResponse struct {
	Results  []exchangeResult `json:"results"`
	Passed   int              `json:"passed"`
	Failed   int              `json:"failed"`
	Parallel int              `json:"parallel"`
}

type diagnosticSummary struct {
	Name     string `json:"name"`
	Parallel int    `json:"parallel"`
	Passed   int    `json:"passed"`
}

type clientSummary struct {
	Username      string `json:"username"`
	MessagePushes int    `json:"message_pushes"`
	TypingPushes  int    `json:"typing_pushes"`
}

type summary struct {
	Passed           bool                `json:"passed"`
	Scenario         string              `json:"scenario"`
	ALPN             string              `json:"alpn"`
	Users            int                 `json:"users"`
	RequiredMessages int                 `json:"required_messages"`
	NoResponseTyping int                 `json:"no_response_typing"`
	RequiredQueries  int                 `json:"required_queries"`
	DurableMessages  int                 `json:"durable_messages"`
	DurationMS       int64               `json:"duration_ms"`
	Diagnostics      []diagnosticSummary `json:"diagnostics"`
	Clients          []clientSummary     `json:"clients"`
}

func main() {
	var cfg config
	flag.StringVar(&cfg.agentURL, "agent", "http://127.0.0.1:8787", "validation client-agent base URL")
	flag.StringVar(&cfg.gateway, "gateway", "127.0.0.1:8443", "Gateway QUIC address")
	flag.StringVar(&cfg.serverName, "server-name", "localhost", "Gateway TLS server name")
	flag.StringVar(&cfg.prefix, "prefix", fmt.Sprintf("m15-%d", time.Now().Unix()), "unique database scenario prefix")
	flag.StringVar(&cfg.password, "password", "M15-valid-password-2026", "password for disposable validation users")
	flag.IntVar(&cfg.users, "users", 8, "number of distinct real users and QUIC sessions")
	flag.IntVar(&cfg.messages, "messages", 32, "required persistent messages")
	flag.IntVar(&cfg.typings, "typings", 64, "no-response typing commands")
	flag.IntVar(&cfg.queries, "queries", 32, "required history/presence queries")
	flag.Parse()

	if cfg.users < 2 || cfg.users > 32 || cfg.messages < 1 || cfg.messages > 100 || cfg.typings < 1 || cfg.queries < 1 {
		fatal(errors.New("users must be 2-32, messages 1-100, and typings/queries positive"))
	}
	if strings.TrimSpace(cfg.prefix) == "" {
		fatal(errors.New("prefix must not be empty"))
	}

	r := &runner{
		config: cfg,
		client: &http.Client{Timeout: 20 * time.Second},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	result, err := r.run(ctx)
	if err != nil {
		fatal(err)
	}
	encoded, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(encoded))
}

func (r *runner) run(ctx context.Context) (*summary, error) {
	started := time.Now()
	sessions := make([]sessionStatus, r.config.users)
	for index := range sessions {
		username := r.username(index)
		status, err := r.authenticate(ctx, "register", username)
		if err != nil {
			return nil, fmt.Errorf("register %s: %w", username, err)
		}
		if !status.Connected || !status.Authenticated || status.ALPN != "lyune/2" || status.User == nil {
			return nil, fmt.Errorf("register %s returned invalid session: %+v", username, status)
		}
		sessions[index] = status
	}
	defer r.logoutAll(sessions)

	created, err := r.command(ctx, sessions[0].SessionID, map[string]any{
		"type": "create_group", "name": r.config.prefix + " mixed load",
	})
	if err != nil || !created.OK || created.Group == nil {
		return nil, fmt.Errorf("create group: response=%+v error=%w", created, err)
	}
	for _, session := range sessions[1:] {
		joined, joinErr := r.command(ctx, session.SessionID, map[string]any{
			"type": "join_group", "invite_code": created.Group.InviteCode,
		})
		if joinErr != nil || !joined.OK {
			return nil, fmt.Errorf("join group as %s: response=%+v error=%w", session.User.Username, joined, joinErr)
		}
	}

	type concurrentResult struct {
		category   string
		diagnostic *diagnosticSummary
		err        error
	}
	totalJobs := r.config.messages + r.config.typings + r.config.queries + 4
	results := make(chan concurrentResult, totalJobs)
	var wait sync.WaitGroup
	launch := func(category string, operation func() (*diagnosticSummary, error)) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			diagnostic, operationErr := operation()
			results <- concurrentResult{category: category, diagnostic: diagnostic, err: operationErr}
		}()
	}

	for index := 0; index < r.config.messages; index++ {
		index := index
		launch("message", func() (*diagnosticSummary, error) {
			response, commandErr := r.command(ctx, sessions[index%len(sessions)].SessionID, map[string]any{
				"type": "send_message", "group_id": created.Group.ID,
				"text": r.messageText(index),
			})
			if commandErr != nil || !response.OK || response.Type != "message_sent" {
				return nil, fmt.Errorf("message %d: response=%+v error=%w", index, response, commandErr)
			}
			return nil, nil
		})
	}
	for index := 0; index < r.config.typings; index++ {
		index := index
		launch("typing", func() (*diagnosticSummary, error) {
			response, commandErr := r.command(ctx, sessions[index%len(sessions)].SessionID, map[string]any{
				"type": "typing", "group_id": created.Group.ID,
			})
			if commandErr != nil || !response.OK || response.Type != "accepted" {
				return nil, fmt.Errorf("typing %d: response=%+v error=%w", index, response, commandErr)
			}
			return nil, nil
		})
	}
	for index := 0; index < r.config.queries; index++ {
		index := index
		launch("query", func() (*diagnosticSummary, error) {
			commandType := "history"
			if index%2 != 0 {
				commandType = "presence"
			}
			response, commandErr := r.command(ctx, sessions[index%len(sessions)].SessionID, map[string]any{
				"type": commandType, "group_id": created.Group.ID,
			})
			if commandErr != nil || !response.OK || response.Type != commandType {
				return nil, fmt.Errorf("%s query %d: response=%+v error=%w", commandType, index, response, commandErr)
			}
			return nil, nil
		})
	}

	diagnostics := []struct {
		name string
		body map[string]any
	}{
		{"required-echo", map[string]any{"kind": "service", "group": 1, "route_key": 0, "chunks": []string{"mixed required"}, "response_mode": "required", "parallel": 16}},
		{"no-response-echo", map[string]any{"kind": "service", "group": 1, "route_key": 0, "chunks": []string{"mixed no response"}, "response_mode": "none", "parallel": 16}},
		{"reset-input", map[string]any{"kind": "service", "group": 1, "route_key": 0, "chunks": []string{"reset", "unwritten tail"}, "response_mode": "required", "reset_input_after": 1, "parallel": 8}},
		{"stop-response", map[string]any{"kind": "service", "group": 1, "route_key": 0, "chunks": []string{"stop response"}, "response_mode": "required", "stop_response": true, "parallel": 8}},
	}
	for _, diagnostic := range diagnostics {
		diagnostic := diagnostic
		launch("diagnostic", func() (*diagnosticSummary, error) {
			response, exchangeErr := r.exchange(ctx, sessions[0].SessionID, diagnostic.body)
			if exchangeErr != nil {
				return nil, fmt.Errorf("%s: %w", diagnostic.name, exchangeErr)
			}
			if response.Failed != 0 || response.Passed != response.Parallel {
				return nil, fmt.Errorf("%s incomplete: %+v", diagnostic.name, response)
			}
			return &diagnosticSummary{Name: diagnostic.name, Parallel: response.Parallel, Passed: response.Passed}, nil
		})
	}

	wait.Wait()
	close(results)
	var diagnosticResults []diagnosticSummary
	var operationErrors []error
	for result := range results {
		if result.err != nil {
			operationErrors = append(operationErrors, fmt.Errorf("%s: %w", result.category, result.err))
		}
		if result.diagnostic != nil {
			diagnosticResults = append(diagnosticResults, *result.diagnostic)
		}
	}
	if len(operationErrors) != 0 {
		return nil, errors.Join(operationErrors...)
	}

	// A cancellation on one stream must not poison the shared diagnostic connection.
	ping, err := r.exchange(ctx, sessions[0].SessionID, map[string]any{
		"kind": "service", "group": 1, "route_key": 0, "chunks": []string{"post-cancellation ping"},
		"response_mode": "required", "parallel": 1,
	})
	if err != nil || ping.Failed != 0 || ping.Passed != 1 {
		return nil, fmt.Errorf("post-cancellation ping: response=%+v error=%w", ping, err)
	}
	diagnosticResults = append(diagnosticResults, diagnosticSummary{Name: "post-cancellation-ping", Parallel: 1, Passed: 1})
	sort.Slice(diagnosticResults, func(left, right int) bool { return diagnosticResults[left].Name < diagnosticResults[right].Name })

	expectedTargets := make([]uint64, 0, len(sessions))
	for _, session := range sessions {
		expectedTargets = append(expectedTargets, session.User.ID)
	}
	slices.Sort(expectedTargets)
	clientResults := make([]clientSummary, 0, len(sessions))
	for _, session := range sessions {
		messages, typings, eventErr := r.waitForEvents(ctx, session, expectedTargets)
		if eventErr != nil {
			return nil, eventErr
		}
		clientResults = append(clientResults, clientSummary{
			Username: session.User.Username, MessagePushes: messages, TypingPushes: typings,
		})
	}

	history, err := r.command(ctx, sessions[0].SessionID, map[string]any{
		"type": "history", "group_id": created.Group.ID,
	})
	if err != nil || !history.OK || history.Type != "history" {
		return nil, fmt.Errorf("final history: response=%+v error=%w", history, err)
	}
	seenMessages := make(map[string]bool, len(history.Messages))
	for _, stored := range history.Messages {
		seenMessages[stored.Text] = true
	}
	for index := 0; index < r.config.messages; index++ {
		if !seenMessages[r.messageText(index)] {
			return nil, fmt.Errorf("durable history is missing %q", r.messageText(index))
		}
	}

	presenceResult, err := r.command(ctx, sessions[0].SessionID, map[string]any{
		"type": "presence", "group_id": created.Group.ID,
	})
	if err != nil || !presenceResult.OK || len(presenceResult.Presence) != len(sessions) {
		return nil, fmt.Errorf("final presence: response=%+v error=%w", presenceResult, err)
	}
	for _, item := range presenceResult.Presence {
		if !item.Online || item.OnlineSessions != 1 {
			return nil, fmt.Errorf("unexpected presence for %s: online=%t sessions=%d", item.User.Username, item.Online, item.OnlineSessions)
		}
	}

	return &summary{
		Passed: true, Scenario: r.config.prefix, ALPN: "lyune/2", Users: len(sessions),
		RequiredMessages: r.config.messages, NoResponseTyping: r.config.typings,
		RequiredQueries: r.config.queries, DurableMessages: r.config.messages,
		DurationMS: time.Since(started).Milliseconds(), Diagnostics: diagnosticResults, Clients: clientResults,
	}, nil
}

func (r *runner) authenticate(ctx context.Context, action, username string) (sessionStatus, error) {
	var status sessionStatus
	err := r.post(ctx, "/api/im/auth", map[string]any{
		"address": r.config.gateway, "server_name": r.config.serverName,
		"insecure_skip_verify": true, "action": action,
		"username": username, "password": r.config.password,
	}, &status)
	return status, err
}

func (r *runner) command(ctx context.Context, sessionID string, fields map[string]any) (commandResponse, error) {
	fields["session_id"] = sessionID
	var response commandResponse
	err := r.post(ctx, "/api/im/command", fields, &response)
	return response, err
}

func (r *runner) exchange(ctx context.Context, sessionID string, fields map[string]any) (exchangeResponse, error) {
	fields["session_id"] = sessionID
	var response exchangeResponse
	err := r.post(ctx, "/api/im/exchange", fields, &response)
	return response, err
}

func (r *runner) waitForEvents(ctx context.Context, session sessionStatus, expectedTargets []uint64) (int, int, error) {
	deadline := time.Now().Add(8 * time.Second)
	for {
		var response eventsResponse
		path := fmt.Sprintf("/api/im/events?session_id=%s&after=0&timeout_ms=250", session.SessionID)
		if err := r.get(ctx, path, &response); err != nil {
			return 0, 0, fmt.Errorf("events for %s: %w", session.User.Username, err)
		}
		messageCount, typingCount := 0, 0
		for _, received := range response.Events {
			targets := append([]uint64(nil), received.Targets...)
			slices.Sort(targets)
			if !slices.Equal(targets, expectedTargets) {
				return 0, 0, fmt.Errorf("event %d for %s has wrong targets %v, want %v", received.Seq, session.User.Username, targets, expectedTargets)
			}
			var payload eventPayload
			if err := json.Unmarshal(received.Payload, &payload); err != nil || !payload.OK {
				return 0, 0, fmt.Errorf("event %d for %s has invalid payload: %s", received.Seq, session.User.Username, received.Payload)
			}
			switch payload.Type {
			case "message":
				if payload.Message == nil || !strings.HasPrefix(payload.Message.Text, r.config.prefix+"-message-") {
					return 0, 0, fmt.Errorf("event %d for %s has a foreign message", received.Seq, session.User.Username)
				}
				messageCount++
			case "typing":
				if payload.GroupID == 0 || payload.User == nil {
					return 0, 0, fmt.Errorf("event %d for %s has invalid typing data", received.Seq, session.User.Username)
				}
				typingCount++
			default:
				return 0, 0, fmt.Errorf("event %d for %s has unexpected type %q", received.Seq, session.User.Username, payload.Type)
			}
		}
		if messageCount == r.config.messages && typingCount == r.config.typings {
			return messageCount, typingCount, nil
		}
		if messageCount > r.config.messages || typingCount > r.config.typings {
			return 0, 0, fmt.Errorf("duplicate pushes for %s: messages=%d typings=%d", session.User.Username, messageCount, typingCount)
		}
		if time.Now().After(deadline) {
			return 0, 0, fmt.Errorf("push timeout for %s: messages=%d/%d typings=%d/%d", session.User.Username, messageCount, r.config.messages, typingCount, r.config.typings)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (r *runner) messageText(index int) string {
	return fmt.Sprintf("%s-message-%03d", r.config.prefix, index+1)
}

func (r *runner) username(index int) string {
	digest := sha256.Sum256([]byte(r.config.prefix))
	return fmt.Sprintf("m15_%x_%02d", digest[:5], index+1)
}

func (r *runner) logoutAll(sessions []sessionStatus) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, session := range sessions {
		var response map[string]any
		_ = r.post(ctx, "/api/im/logout", map[string]any{"session_id": session.SessionID}, &response)
	}
}

func (r *runner) post(ctx context.Context, path string, requestBody, responseBody any) error {
	encoded, err := json.Marshal(requestBody)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(r.config.agentURL, "/")+path, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	return r.do(request, responseBody)
}

func (r *runner) get(ctx context.Context, path string, responseBody any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(r.config.agentURL, "/")+path, nil)
	if err != nil {
		return err
	}
	return r.do(request, responseBody)
}

func (r *runner) do(request *http.Request, responseBody any) error {
	response, err := r.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("%s %s: HTTP %d: %s", request.Method, request.URL.Path, response.StatusCode, strings.TrimSpace(string(body)))
	}
	if err := json.Unmarshal(body, responseBody); err != nil {
		return fmt.Errorf("decode %s: %w (body %q)", request.URL.Path, err, body)
	}
	return nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "im-mixed-load:", err)
	os.Exit(1)
}
