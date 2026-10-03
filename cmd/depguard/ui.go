package main

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Terminal output goes to stderr so the wrapped tool's stdout stays clean.
var out io.Writer = os.Stderr

var colorOn = func() bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	if os.Getenv("FORCE_COLOR") != "" {
		return true
	}
	fi, err := os.Stderr.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}()

func paint(code, s string) string {
	if !colorOn {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func bold(s string) string   { return paint("1", s) }
func dim(s string) string    { return paint("2", s) }
func red(s string) string    { return paint("31", s) }
func green(s string) string  { return paint("32", s) }
func yellow(s string) string { return paint("33", s) }
func cyan(s string) string   { return paint("36", s) }

func brand() string { return paint("1;35", "◆ depguard") }

func sevLabel(s string) string {
	switch s {
	case "critical":
		return paint("1;37;41", " CRITICAL ")
	case "high":
		return paint("1;31", "HIGH    ")
	case "medium":
		return paint("33", "MEDIUM  ")
	case "low":
		return paint("36", "LOW     ")
	default:
		return dim(fmt.Sprintf("%-8s", strings.ToUpper(s)))
	}
}

// spinner shows progress on a terminal; it is silent when output is piped.
type spinner struct {
	mu   sync.Mutex
	msg  string
	stop chan struct{}
	done sync.WaitGroup
}

func startSpinner(msg string) *spinner {
	s := &spinner{msg: msg, stop: make(chan struct{})}
	if !colorOn {
		fmt.Fprintf(out, "%s %s\n", brand(), msg)
		return s
	}
	s.done.Add(1)
	go func() {
		defer s.done.Done()
		frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
		start := time.Now()
		for i := 0; ; i++ {
			s.mu.Lock()
			fmt.Fprintf(out, "\r\x1b[2K%s %s %s %s", brand(), cyan(frames[i%len(frames)]), s.msg, dim(fmt.Sprintf("%.0fs", time.Since(start).Seconds())))
			s.mu.Unlock()
			select {
			case <-s.stop:
				fmt.Fprint(out, "\r\x1b[2K")
				return
			case <-time.After(90 * time.Millisecond):
			}
		}
	}()
	return s
}

func (s *spinner) update(msg string) {
	s.mu.Lock()
	s.msg = msg
	s.mu.Unlock()
	if !colorOn {
		fmt.Fprintf(out, "%s %s\n", brand(), msg)
	}
}

func (s *spinner) end() {
	select {
	case <-s.stop:
	default:
		close(s.stop)
	}
	s.done.Wait()
}

// box draws a rounded box around lines (width from the longest visible line).
func box(color func(string) string, lines ...string) {
	w := 0
	for _, l := range lines {
		w = max(w, visibleLen(l))
	}
	fmt.Fprintln(out, color("╭"+strings.Repeat("─", w+2)+"╮"))
	for _, l := range lines {
		fmt.Fprintln(out, color("│")+" "+l+strings.Repeat(" ", w-visibleLen(l))+" "+color("│"))
	}
	fmt.Fprintln(out, color("╰"+strings.Repeat("─", w+2)+"╯"))
}

// visibleLen ignores ANSI escapes.
func visibleLen(s string) int {
	n, esc := 0, false
	for _, r := range s {
		switch {
		case r == '\x1b':
			esc = true
		case esc:
			if r == 'm' {
				esc = false
			}
		default:
			n++
		}
	}
	return n
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
