package tsid

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// LogSink delivers one log line to the host. It must not block for long.
type LogSink func(level, msg string, fields map[string]any)

type logLine struct {
	level, msg string
	fields     map[string]any
}

// logger queues lines and writes them from one goroutine, so plugin calls
// never re-enter the host synchronously.
type logger struct {
	mu   sync.RWMutex
	sink LogSink
	ch   chan logLine
	once sync.Once
}

var logs = &logger{ch: make(chan logLine, 256)}

// SetLogSink installs (or with nil, removes) the host log sink. After
// SetLogSink(nil) returns, no host call is in flight and none starts.
func SetLogSink(s LogSink) {
	logs.once.Do(func() { go logs.drain() })
	logs.mu.Lock()
	logs.sink = s
	logs.mu.Unlock()
}

func (l *logger) drain() {
	for line := range l.ch {
		l.mu.RLock()
		sink := l.sink
		msg := formatLine(line.msg, line.fields)
		if sink != nil {
			// The host log formatter shows only some field keys, so the
			// fields go into the message text.
			sink(line.level, msg, nil)
		}
		l.mu.RUnlock()
		if sink == nil {
			fmt.Fprintf(os.Stderr, "[tailscale-identity] %s: %s\n", line.level, msg)
		}
	}
}

// Logf queues a log line. Lines are dropped when the queue is full.
func Logf(level, msg string, fields map[string]any) {
	logs.once.Do(func() { go logs.drain() })
	select {
	case logs.ch <- logLine{level, msg, fields}:
	default:
	}
}

func formatLine(msg string, fields map[string]any) string {
	if len(fields) == 0 {
		return msg
	}
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(msg)
	for _, k := range keys {
		v := fmt.Sprint(fields[k])
		if strings.ContainsAny(v, " \t\"") || v == "" {
			v = fmt.Sprintf("%q", v)
		}
		fmt.Fprintf(&b, " %s=%s", k, v)
	}
	return b.String()
}
