package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"time"
)

type agentConfig struct {
	c            *client
	pmgLogDir    string
	stateFile    string
	endpointType string
	gryph        bool
}

// agentState persists shipping progress between runs.
type agentState struct {
	PMGOffsets map[string]int64 `json:"pmg_offsets"` // log file name -> bytes shipped
	GryphSince string           `json:"gryph_since"` // RFC3339 start of next gryph export
}

func defaultPMGLogDir() string {
	if d := os.Getenv("PMG_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "logs")
	}
	dir, _ := os.UserConfigDir() // pmg: <UserConfigDir>/safedep/pmg/logs
	return filepath.Join(dir, "safedep", "pmg", "logs")
}

func defaultStateFile() string {
	dir, _ := os.UserConfigDir()
	return filepath.Join(dir, "depguard", "agent-state.json")
}

func runAgent(args []string) error {
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	apiURL, apiKey := addClientFlags(fs)
	interval := fs.Duration("interval", 5*time.Minute, "sync interval")
	once := fs.Bool("once", false, "sync once and exit")
	cfg := agentConfig{}
	fs.StringVar(&cfg.pmgLogDir, "pmg-log-dir", envOr("DEPGUARD_PMG_LOG_DIR", defaultPMGLogDir()), "pmg event log directory (env DEPGUARD_PMG_LOG_DIR)")
	fs.StringVar(&cfg.stateFile, "state-file", envOr("DEPGUARD_AGENT_STATE", defaultStateFile()), "agent state file (env DEPGUARD_AGENT_STATE)")
	fs.StringVar(&cfg.endpointType, "endpoint-type", "developer", "developer|ci|agent_sandbox")
	fs.BoolVar(&cfg.gryph, "gryph", true, "ship gryph agent events when gryph is on PATH")
	fs.Parse(args)
	var err error
	if cfg.c, err = newClient(*apiURL, *apiKey); err != nil {
		return err
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	for {
		if err := cfg.sync(); err != nil {
			fmt.Fprintln(os.Stderr, "depguard agent:", err)
			if *once {
				return err
			}
		}
		if *once {
			return nil
		}
		select {
		case <-stop:
			return nil
		case <-time.After(*interval):
		}
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// machineIdentifier is a stable, non-reversible id for this machine.
func machineIdentifier() string {
	seed := ""
	for _, f := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if b, err := os.ReadFile(f); err == nil && len(bytes.TrimSpace(b)) > 0 {
			seed = string(bytes.TrimSpace(b))
			break
		}
	}
	if seed == "" {
		seed, _ = os.Hostname()
	}
	sum := sha256.Sum256([]byte("depguard:" + seed))
	return hex.EncodeToString(sum[:16])
}

func (a *agentConfig) sync() error {
	host, _ := os.Hostname()
	var ci struct {
		EndpointID string `json:"endpoint_id"`
	}
	if _, err := a.c.do("POST", "/v1/endpoints/checkin", "", map[string]string{
		"identifier": machineIdentifier(), "endpoint_type": a.endpointType, "hostname": host,
		"os": runtime.GOOS + "/" + runtime.GOARCH, "agent_version": version,
	}, &ci); err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	items := discover(home)
	if _, err := a.c.do("POST", "/v1/endpoints/"+ci.EndpointID+"/inventory", "", map[string]any{"items": items}, nil); err != nil {
		return err
	}
	st := a.loadState()
	errPMG := a.shipPMG(ci.EndpointID, st)
	var errGryph error
	if a.gryph {
		errGryph = a.shipGryph(ci.EndpointID, st)
	}
	if err := a.saveState(st); err != nil {
		return err
	}
	if errPMG != nil {
		return errPMG
	}
	return errGryph
}

func (a *agentConfig) loadState() *agentState {
	st := &agentState{PMGOffsets: map[string]int64{}}
	if b, err := os.ReadFile(a.stateFile); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.PMGOffsets == nil {
		st.PMGOffsets = map[string]int64{}
	}
	return st
}

func (a *agentConfig) saveState(st *agentState) error {
	if err := os.MkdirAll(filepath.Dir(a.stateFile), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	tmp := a.stateFile + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.stateFile)
}

const pmgChunk = 1 << 20 // keeps a batch well under the server's 10k-line cap

// shipPMG sends complete new lines of each *-pmg.log file, then advances the offset.
func (a *agentConfig) shipPMG(endpointID string, st *agentState) error {
	files, _ := filepath.Glob(filepath.Join(a.pmgLogDir, "*-pmg.log"))
	sort.Strings(files)
	present := map[string]bool{}
	for _, f := range files {
		name := filepath.Base(f)
		present[name] = true
		for {
			chunk, next, err := readNewLines(f, st.PMGOffsets[name], pmgChunk)
			if err != nil {
				return err
			}
			if len(bytes.TrimSpace(chunk)) > 0 {
				if _, err := a.c.do("POST", "/v1/endpoints/"+endpointID+"/pmg-events", "application/x-ndjson", bytes.NewReader(chunk), nil); err != nil {
					return err
				}
			}
			if next == st.PMGOffsets[name] {
				break
			}
			st.PMGOffsets[name] = next
		}
	}
	for name := range st.PMGOffsets { // pmg deletes old logs
		if !present[name] {
			delete(st.PMGOffsets, name)
		}
	}
	return nil
}

// readNewLines returns up to max bytes of complete lines starting at off, and the
// offset after them. A file that shrank (rotated/truncated) restarts at 0.
func readNewLines(path string, off int64, max int) ([]byte, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, off, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err == nil && fi.Size() < off {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, err
	}
	buf := make([]byte, max)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, off, err
	}
	buf = buf[:n]
	end := bytes.LastIndexByte(buf, '\n')
	if end < 0 {
		return nil, off, nil // no complete line yet
	}
	return buf[:end+1], off + int64(end+1), nil
}

// shipGryph exports gryph events since the last run (JSONL) and ships them;
// the server dedupes by event id, so overlapping windows are harmless.
func (a *agentConfig) shipGryph(endpointID string, st *agentState) error {
	bin, err := exec.LookPath("gryph")
	if err != nil {
		return nil
	}
	since := st.GryphSince
	if since == "" {
		since = "24h"
	}
	start := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	out, err := exec.Command(bin, "export", "--since", since).Output()
	if err != nil {
		return fmt.Errorf("gryph export: %w", err)
	}
	lines := bytes.Split(out, []byte("\n"))
	for i := 0; i < len(lines); {
		var batch [][]byte
		size := 0
		for ; i < len(lines) && len(batch) < 5000 && size < pmgChunk; i++ {
			if l := bytes.TrimSpace(lines[i]); len(l) > 0 {
				batch, size = append(batch, l), size+len(l)
			}
		}
		if len(batch) == 0 {
			continue
		}
		body := bytes.Join(batch, []byte("\n"))
		if _, err := a.c.do("POST", "/v1/endpoints/"+endpointID+"/agent-events", "application/x-ndjson", bytes.NewReader(body), nil); err != nil {
			return err
		}
	}
	st.GryphSince = start
	return nil
}

// tildePath shows home-relative paths as ~/... so usernames are not shipped.
func tildePath(home, p string) string {
	if rel, err := filepath.Rel(home, p); err == nil && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel)
	}
	return p
}
