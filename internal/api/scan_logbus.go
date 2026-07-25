package api

// scan_logbus.go — in-memory log broadcaster for in-process scans.
//
// When a scan runs in-process (via runScanInProcess), there is no child
// process whose stdout we can tail. This file provides a lightweight
// pub-sub log bus so the SSE /api/scans/:id/logs/stream endpoint can
// deliver live log lines to connected dashboard clients.
//
// Architecture
// ────────────
//   1. ScanLogf(scanID, …)       — explicit call from scan_runner.go
//   2. logBusHook (logrus hook)  — automatically intercepts every logrus
//      entry emitted inside a scan goroutine and feeds it into the bus.
//      The hook uses utils.GetCurrentScanID() to find the correct scanID
//      without any manual plumbing in each scanner module.
//
// Wire-up: call RegisterLogBusHook() once at startup (done in server init).

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/h0tak88r/AutoAR/internal/utils"
	"github.com/sirupsen/logrus"
)

const (
	logBusChanSize    = 512  // lines buffered per subscriber
	logBusMaxSubs     = 8    // max SSE clients per scan
	logBusMaxLogLines = 8192 // cap stored log lines per scan
)

// ── Log bus ──────────────────────────────────────────────────────────────────

type logBus struct {
	mu   sync.RWMutex
	subs map[string][]chan string // scanID → subscriber channels
	logs map[string][]string     // scanID → stored log lines (for late joiners)
}

var globalLogBus = &logBus{
	subs: make(map[string][]chan string),
	logs: make(map[string][]string),
}

// Logf appends a formatted log line to the in-process log bus for scanID.
// This is a fire-and-forget call — it never blocks.
func (b *logBus) Logf(scanID, format string, args ...interface{}) {
	if scanID == "" {
		return
	}
	line := fmt.Sprintf(format, args...)
	if line == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	// Store for late joiners (capped).
	stored := b.logs[scanID]
	if len(stored) < logBusMaxLogLines {
		b.logs[scanID] = append(stored, line)
	}

	// Fan out to all current subscribers.
	for _, ch := range b.subs[scanID] {
		select {
		case ch <- line:
		default: // subscriber is slow — drop rather than block
		}
	}
}

// Subscribe returns a channel that receives log lines for scanID.
// The caller must call Unsubscribe when done.
// It also returns all previously stored lines so late joiners catch up.
func (b *logBus) Subscribe(scanID string) (history []string, ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	// Copy stored lines for replay.
	stored := b.logs[scanID]
	history = make([]string, len(stored))
	copy(history, stored)

	if len(b.subs[scanID]) >= logBusMaxSubs {
		// At the subscriber cap: hand back an already-closed channel so the SSE
		// loop receives ok=false and tears down cleanly.
		ch = make(chan string)
		close(ch)
		return history, ch
	}
	ch = make(chan string, logBusChanSize)
	b.subs[scanID] = append(b.subs[scanID], ch)
	return history, ch
}

// Unsubscribe removes the channel from the subscriber list for scanID.
func (b *logBus) Unsubscribe(scanID string, ch chan string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	subs := b.subs[scanID]
	for i, s := range subs {
		if s == ch {
			b.subs[scanID] = append(subs[:i], subs[i+1:]...)
			break
		}
	}
}

// Close drains and removes all state for a finished scan (prevents leaks).
func (b *logBus) Close(scanID string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ch := range b.subs[scanID] {
		close(ch)
	}
	delete(b.subs, scanID)
	delete(b.logs, scanID)
}

// ScanLogf is the public convenience function for logging a scan event to the bus.
func ScanLogf(scanID, format string, args ...interface{}) {
	globalLogBus.Logf(scanID, format, args...)
}

// ── logrus hook → log bus ────────────────────────────────────────────────────

// logBusHook is a logrus hook that forwards every log entry emitted from
// inside a scan goroutine to globalLogBus.  It uses utils.GetCurrentScanID()
// to identify which scan the current goroutine belongs to — the same mechanism
// used by phase_logs.go and workflow.go.
type logBusHook struct{}

var (
	_logBusHookOnce sync.Once
	// Level threshold: forward Info and above to the live log panel.
	// Debug lines would be too noisy for the UI.
	_logBusMinLevel = logrus.InfoLevel
)

// Levels returns the logrus levels this hook handles.
func (h *logBusHook) Levels() []logrus.Level {
	levels := make([]logrus.Level, 0, 5)
	for _, l := range logrus.AllLevels {
		if l <= _logBusMinLevel {
			levels = append(levels, l)
		}
	}
	return levels
}

// Fire is called by logrus for every matching log entry.
func (h *logBusHook) Fire(entry *logrus.Entry) error {
	scanID := utils.GetCurrentScanID()
	if scanID == "" {
		return nil // not inside a scan goroutine — ignore
	}

	line := formatBusLine(entry)
	globalLogBus.Logf(scanID, "%s", line)
	return nil
}

// formatBusLine produces a compact, human-readable log line for the UI.
// Format: "HH:MM:SS [LEVEL] message  key=val …"
func formatBusLine(entry *logrus.Entry) string {
	var buf bytes.Buffer

	// Timestamp
	buf.WriteString(entry.Time.Format("15:04:05"))
	buf.WriteByte(' ')

	// Level tag
	switch entry.Level {
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		buf.WriteString("[ERR]  ")
	case logrus.WarnLevel:
		buf.WriteString("[WARN] ")
	case logrus.InfoLevel:
		buf.WriteString("[INFO] ")
	default:
		buf.WriteString("[DBG]  ")
	}

	// Message
	buf.WriteString(strings.TrimSpace(entry.Message))

	// Extra fields (skip internal logrus/time fields)
	skip := map[string]bool{"time": true, "level": true, "msg": true}
	for k, v := range entry.Data {
		if skip[k] {
			continue
		}
		buf.WriteByte(' ')
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(fmt.Sprintf("%v", v))
	}

	return buf.String()
}

// RegisterLogBusHook installs the logBusHook on the global logrus logger.
// Safe to call multiple times — installs the hook only once.
func RegisterLogBusHook() {
	_logBusHookOnce.Do(func() {
		l := utils.GetLogger()
		if l == nil {
			return
		}
		l.AddHook(&logBusHook{})
	})
}

// ── keepalive ticker for SSE connections ─────────────────────────────────────

// StartLogBusKeepalive sends a periodic comment-style ping on all active scan
// buses so nginx / load-balancer idle timeouts do not drop SSE connections.
// Call once at server startup; it runs until the process exits.
func StartLogBusKeepalive() {
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		for range t.C {
			globalLogBus.mu.RLock()
			ids := make([]string, 0, len(globalLogBus.subs))
			for id := range globalLogBus.subs {
				ids = append(ids, id)
			}
			globalLogBus.mu.RUnlock()
			for _, id := range ids {
				globalLogBus.Logf(id, ": keepalive")
			}
		}
	}()
}
