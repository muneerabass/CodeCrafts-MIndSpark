package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server reply of POST /v1/packages/check.
type checkFinding struct {
	Rule     string `json:"rule"`
	Category string `json:"category"`
	Severity string `json:"severity"`
	Blocking bool   `json:"blocking"`
	Summary  string `json:"summary"`
	FixedIn  string `json:"fixed_in"`
	URL      string `json:"url"`
}

type checkVerdict struct {
	Ecosystem string         `json:"ecosystem"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Direct    *bool          `json:"direct"`
	Via       []string       `json:"via"`
	Decision  string         `json:"decision"`
	Findings  []checkFinding `json:"findings"`
}

type checkResult struct {
	Decision  string         `json:"decision"`
	BlockMode bool           `json:"block_mode"`
	Checked   int            `json:"checked"`
	Packages  []checkVerdict `json:"packages"`
}

// guardOpts are depguard's own flags for a wrapped command
// (`depguard --force --reason "..." npm install x`, or DEPGUARD_FORCE/DEPGUARD_REASON).
type guardOpts struct {
	force   bool
	reason  string
	dryRun  bool
	jsonOut bool
	apiURL  string
	apiKey  string
}

// parseGuardFlags consumes leading depguard flags before the tool name.
func parseGuardFlags(args []string) (guardOpts, []string, error) {
	o := guardOpts{force: os.Getenv("DEPGUARD_FORCE") != "", reason: os.Getenv("DEPGUARD_REASON")}
	for len(args) > 0 && strings.HasPrefix(args[0], "--") {
		flag, val, hasVal := strings.Cut(args[0], "=")
		next := func() (string, error) {
			if hasVal {
				return val, nil
			}
			if len(args) < 2 {
				return "", fmt.Errorf("%s needs a value", flag)
			}
			args = args[1:]
			return args[0], nil
		}
		var err error
		switch flag {
		case "--force":
			o.force = true
		case "--dry-run":
			o.dryRun = true
		case "--json":
			o.jsonOut = true
		case "--reason":
			o.reason, err = next()
		case "--api-url":
			o.apiURL, err = next()
		case "--api-key":
			o.apiKey, err = next()
		default:
			return o, nil, fmt.Errorf("unknown flag %s", flag)
		}
		if err != nil {
			return o, nil, err
		}
		args = args[1:]
	}
	return o, args, nil
}

// maxShimDepth stops shim → depguard → shim loops (each shim increments DEPGUARD_SHIM_DEPTH).
const maxShimDepth = 10 // real nesting (yarn → npm run → npx) stays well below; a loop hits it at once

// runGuard checks an install command and then runs the real tool. It returns the exit code.
func runGuard(o guardOpts, tool string, args []string) int {
	if d, _ := strconv.Atoi(os.Getenv("DEPGUARD_SHIM_DEPTH")); d >= maxShimDepth {
		fmt.Fprintf(out, "%s %s\n", brand(), red(fmt.Sprintf("✖ %s: depguard shims called each other %d times (another wrapper on PATH runs depguard again); run depguard doctor", tool, d)))
		return 1
	}
	bin, err := realTool(tool)
	if err != nil {
		fmt.Fprintf(out, "%s %s\n", brand(), red(err.Error()))
		return 127
	}
	inv := classify(tool, args)
	// Not an install, or already inside a checked install (lifecycle scripts, nested calls).
	if !inv.install || os.Getenv("DEPGUARD_ACTIVE") != "" || os.Getenv("DEPGUARD_DISABLE") != "" {
		return o.run(bin, args, false)
	}
	cwd, _ := os.Getwd()
	pc, err := findProject(cwd)
	if err != nil {
		fmt.Fprintf(out, "%s %s\n", brand(), yellow(err.Error()))
	}
	failClosed := pc != nil && pc.FailClosed
	c, err := resolveClient(o.apiURL, o.apiKey, pc)
	if err != nil {
		if failClosed {
			fmt.Fprintf(out, "%s %s %s\n", brand(), red("✖"), err)
			return 1
		}
		fmt.Fprintf(out, "%s %s %s\n", brand(), yellow("!"), dim(err.Error()+" — running "+tool+" unchecked"))
		return o.run(bin, args, false)
	}
	c.http = &http.Client{Timeout: 30 * time.Second}
	checked := !inv.exec // DEPGUARD_ACTIVE only for installs; what npx/uvx run afterwards is checked again

	start := time.Now()
	sp := startSpinner(fmt.Sprintf("resolving what %s would install…", bold(inv.name())))
	res, rerr := resolve(inv, cwd, bin)
	needsBuild := errors.Is(rerr, errNeedsBuild)
	if rerr != nil && !needsBuild && notFound(rerr) {
		sp.end()
		fmt.Fprintf(out, "%s %s %s could not resolve this install:\n%s\n", brand(), red("✖"), tool, dim(indent(lastLines(rerr.Error(), 4))))
		// Registries remove malicious versions: say so when depguard knows the exact version.
		req := checkRequest{Packages: pinnedPackages(inv)}
		var result checkResult
		if len(req.Packages) > 0 {
			if _, err := c.do("POST", "/v1/packages/check", "", req, &result); err == nil && len(result.Packages) > 0 {
				printReport(result, &resolution{note: "the registry no longer serves this version; here is what depguard knows about it"}, inv, time.Since(start))
			}
		}
		return 1
	}
	if rerr != nil {
		note := "could not resolve the full dependency tree: " + firstLine(rerr.Error())
		if needsBuild {
			note = "cannot resolve without building packages; checked the exact versions named on the command line"
		}
		if failClosed {
			sp.end()
			fmt.Fprintf(out, "%s %s %s — install stopped (fail_closed in %s)\n%s\n", brand(), red("✖"), firstLine(note), projectFile, dim(indent(lastLines(rerr.Error(), 4))))
			return 1
		}
		// Fall back to the packages named on the command line with exact versions.
		res = &resolution{partial: true, note: note}
		res.req.Packages = pinnedPackages(inv)
	}
	if len(inv.specs) == 0 {
		res.req.Before = nil // a plain install installs everything: check the whole tree
	}
	if pc != nil {
		res.req.RepoRules = pc.Rules
	}
	key := ""
	if res.key != "" {
		key = cacheKey(c.base, c.key, res.req.RepoRules, res.key)
	}
	if key != "" && cacheHit(c, key) {
		sp.end()
		fmt.Fprintf(out, "%s %s %s\n", brand(), green("✔"), dim("dependencies unchanged since the last clean check"))
		return o.run(bin, args, checked)
	}
	if len(res.req.Packages) == 0 && len(res.req.After) == 0 {
		sp.end()
		fmt.Fprintf(out, "%s %s %s\n", brand(), yellow("!"), dim(firstNonEmpty(res.note, "nothing to check")+" — running "+tool))
		return o.run(bin, args, checked)
	}
	sp.update("checking packages against your team's policy…")
	var result checkResult
	_, err = c.do("POST", "/v1/packages/check", "", res.req, &result)
	sp.end()
	if err != nil {
		if failClosed {
			fmt.Fprintf(out, "%s %s check failed: %v\n", brand(), red("✖"), err)
			return 1
		}
		fmt.Fprintf(out, "%s %s %s\n", brand(), yellow("!"), dim("check unavailable ("+firstLine(err.Error())+") — running "+tool+" unchecked"))
		return o.run(bin, args, false)
	}
	if o.jsonOut {
		b, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(b))
	} else {
		printReport(result, res, inv, time.Since(start))
	}

	decision := result.Decision
	if decision == "block" && o.force {
		decision = "override"
	}
	if decision == "allow" && key != "" {
		cacheStore(c, key)
	}
	logEvent(c, inv, result, decision, o.reason)
	switch {
	case decision == "block":
		fmt.Fprintf(out, "  %s\n\n", dim("Install stopped. To install anyway: depguard --force --reason \"why\" "+tool+" "+strings.Join(args, " ")))
		return 1
	case decision == "override":
		fmt.Fprintf(out, "  %s %s\n\n", yellow("⚠ override:"), "installing despite blocking findings"+map[bool]string{true: " (" + o.reason + ")", false: ""}[o.reason != ""])
	}
	if o.dryRun {
		return map[string]int{"block": 1}[result.Decision]
	}
	return o.run(bin, args, checked)
}

// pinnedPackages are the exact versions named on the command line.
func pinnedPackages(inv invocation) []checkPkg {
	var pkgs []checkPkg
	t := true
	for _, s := range inv.specs {
		if n, v, ok := pinned(inv.tool, s); ok {
			pkgs = append(pkgs, checkPkg{Ecosystem: toolEcosystem[inv.tool], Name: n, Version: v, Direct: &t})
		}
	}
	return pkgs
}

func (inv invocation) name() string { return strings.TrimSpace(inv.tool + " " + inv.sub) }

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return truncate(l, 140)
}

// printReport renders the verdict.
func printReport(r checkResult, res *resolution, inv invocation, took time.Duration) {
	fmt.Fprintln(out)
	head := fmt.Sprintf("%s  checked %s for %s", brand(), bold(plural(r.Checked, "package", "packages")), bold(inv.name()))
	fmt.Fprintf(out, "%s %s\n", head, dim(fmt.Sprintf("(%.1fs)", took.Seconds())))
	if res.note != "" {
		fmt.Fprintf(out, "  %s %s\n", yellow("note:"), dim(res.note))
	}
	if r.Checked == 0 {
		fmt.Fprintf(out, "  %s %s\n\n", green("✔"), "nothing new to install: these packages are already in your lockfile "+dim("(depguard check reviews the whole project)"))
		return
	}
	if len(r.Packages) == 0 {
		fmt.Fprintln(out)
		box(green, green("✔ No known vulnerabilities, malware or policy issues"), dim("Installing…"))
		fmt.Fprintln(out)
		return
	}
	fmt.Fprintln(out)
	// Low-signal notices (unmaintained, extra license notes) are summarised so real problems stand out.
	var shown []checkVerdict
	quiet := map[string][]string{}
	for _, p := range r.Packages {
		if p.Decision != "block" && allQuiet(p.Findings) {
			for _, f := range p.Findings {
				if q := quiet[quietRule(f)]; len(q) == 0 || q[len(q)-1] != p.Name {
					quiet[quietRule(f)] = append(q, p.Name)
				}
			}
			continue
		}
		shown = append(shown, p)
	}
	const show = 12
	for i, p := range shown {
		if i == show {
			fmt.Fprintf(out, "  %s\n", dim(fmt.Sprintf("… and %d more packages with findings (use --json for all)", len(shown)-show)))
			break
		}
		icon := yellow("▲")
		if p.Decision == "block" {
			icon = red("✖")
		}
		kind := ""
		if p.Direct != nil {
			kind = map[bool]string{true: cyan("direct"), false: dim("transitive")}[*p.Direct]
		}
		if p.Direct != nil && !*p.Direct && len(p.Via) > 1 {
			kind += dim(" via " + strings.Join(p.Via[:len(p.Via)-1], " → "))
		}
		fmt.Fprintf(out, "  %s %s %s  %s\n", icon, bold(p.Name), dim(p.Version), kind)
		for j, f := range p.Findings {
			if j == 4 {
				fmt.Fprintf(out, "      %s\n", dim(fmt.Sprintf("+%d more findings", len(p.Findings)-4)))
				break
			}
			fmt.Fprintf(out, "      %s %s\n", sevLabel(f.Severity), truncate(f.Summary, 110))
			if f.FixedIn != "" {
				fix := f.FixedIn
				if p.Ecosystem == "Go" && !strings.HasPrefix(fix, "v") {
					fix = "v" + fix
				}
				fmt.Fprintf(out, "        %s %s\n", green("↑ fix:"), "upgrade to "+bold(fix))
			}
			if f.URL != "" {
				fmt.Fprintf(out, "        %s\n", dim(f.URL))
			}
		}
	}
	for _, rule := range []string{"unmaintained", "no-source-repo", "license-weak-copyleft", "license-multiple", "license-note"} {
		if names := quiet[rule]; len(names) > 0 {
			list := strings.Join(names[:min(4, len(names))], ", ")
			if len(names) > 4 {
				list += fmt.Sprintf(" +%d", len(names)-4)
			}
			label := quietLabel[rule]
			if len(names) == 1 { // "1 package looks", not "1 package look"
				verb, rest, _ := strings.Cut(label, " ")
				label = map[string]string{"look": "looks", "have": "has", "use": "uses", "list": "lists"}[verb] + " " + rest
			}
			fmt.Fprintf(out, "  %s %s %s\n", dim("•"), plural(len(names), "package", "packages")+" "+label, dim("("+list+")"))
		}
	}
	fmt.Fprintln(out)
	blocked, warned := 0, 0
	for _, p := range r.Packages {
		if p.Decision == "block" {
			blocked++
		} else {
			warned++
		}
	}
	switch r.Decision {
	case "block":
		box(red, red(bold("✖ BLOCKED"))+"  "+plural(blocked, "package breaks", "packages break")+" your team's policy",
			dim(plural(warned, "other warning", "other warnings")+" · block mode is "+map[bool]string{true: "on", false: "off (malware always blocks)"}[r.BlockMode]))
	default:
		box(yellow, yellow(bold("▲ WARNING"))+"  "+plural(len(r.Packages), "package has", "packages have")+" findings",
			dim("Not blocking ("+map[bool]string{true: "warnings only", false: "team block mode is off"}[r.BlockMode]+") · installing…"))
	}
	fmt.Fprintln(out)
}

// logEvent records the decision on the dashboard (Endpoints → Package events).
// Best effort: it never holds up the install for more than 5 seconds.
func logEvent(c *client, inv invocation, r checkResult, decision, reason string) {
	lc := *c
	lc.http = &http.Client{Timeout: 5 * time.Second}
	done := make(chan struct{})
	go func() {
		defer close(done)
		sendEvents(&lc, inv, r, decision, reason)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

func sendEvents(c *client, inv invocation, r checkResult, decision, reason string) {
	st := loadGuardState()
	if st.EndpointID == "" {
		host, _ := os.Hostname()
		var ci struct {
			EndpointID string `json:"endpoint_id"`
		}
		if _, err := c.do("POST", "/v1/endpoints/checkin", "", map[string]string{
			"identifier": machineIdentifier(), "endpoint_type": "developer", "hostname": host,
			"os": runtime.GOOS + "/" + runtime.GOARCH, "agent_version": version,
		}, &ci); err != nil {
			return
		}
		st.EndpointID = ci.EndpointID
		saveGuardState(st)
	}
	cwd, _ := os.Getwd()
	now := time.Now().UTC()
	var lines []string
	add := func(ev map[string]any) {
		b, _ := json.Marshal(ev)
		lines = append(lines, string(b))
	}
	add(map[string]any{"timestamp": now, "event_type": "guard." + decision,
		"message":   fmt.Sprintf("%s: %s (%s with findings of %d checked)", inv.name(), decision, plural(len(r.Packages), "package", "packages"), r.Checked),
		"ecosystem": toolEcosystem[inv.tool], "details": map[string]any{"command": inv.tool + " " + strings.Join(inv.args, " "), "dir": filepath.Base(cwd), "reason": reason, "checked": r.Checked}})
	for i, p := range r.Packages {
		if i == 50 {
			break
		}
		var rules []string
		msg := p.Decision
		for _, f := range p.Findings {
			rules = append(rules, f.Rule)
		}
		if len(p.Findings) > 0 {
			msg = p.Findings[0].Summary
		}
		add(map[string]any{"timestamp": now, "event_type": "guard.package." + p.Decision, "package_name": p.Name, "version": p.Version,
			"ecosystem": p.Ecosystem, "message": msg, "details": map[string]any{"rules": rules}})
	}
	_, _ = c.do("POST", "/v1/endpoints/"+st.EndpointID+"/pmg-events", "application/x-ndjson", strings.NewReader(strings.Join(lines, "\n")+"\n"), nil)
}

// ---------------------------------------------------------------- real tool

// realTool finds the package manager on PATH, skipping depguard's own shims
// (the shim dir however it is reached, and any copy of a shim script).
func realTool(tool string) (string, error) {
	shims, _ := os.Stat(shimDir())
	selfPath, _ := os.Executable()
	self, _ := os.Stat(selfPath)
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if d == "" {
			continue
		}
		if fi, err := os.Stat(d); err != nil || (shims != nil && os.SameFile(fi, shims)) {
			continue
		}
		for _, name := range toolNames(tool) {
			p := filepath.Join(d, name)
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() || (runtime.GOOS != "windows" && fi.Mode()&0o111 == 0) {
				continue
			}
			if (self != nil && os.SameFile(fi, self)) || isShim(p) {
				continue
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found on PATH", tool)
}

// isShim: depguard's shim scripts carry this marker near the top.
func isShim(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b := make([]byte, 200)
	n, _ := io.ReadFull(f, b)
	return bytes.Contains(b[:n], []byte("depguard install guard"))
}

func toolNames(tool string) []string {
	if runtime.GOOS == "windows" {
		return []string{tool + ".exe", tool + ".cmd", tool + ".bat"}
	}
	return []string{tool}
}

// ---------------------------------------------------------------- state & cache

type guardState struct {
	EndpointID string                `json:"endpoint_id"`
	Cache      map[string]cacheEntry `json:"cache"` // cacheKey -> last clean check
}

type cacheEntry struct {
	At            time.Time `json:"at"`
	PolicyVersion string    `json:"policy_version"`
}

func guardStatePath() string { return filepath.Join(configDir(), "guard-state.json") }

func loadGuardState() *guardState {
	st := &guardState{}
	if b, err := os.ReadFile(guardStatePath()); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.Cache == nil {
		st.Cache = map[string]cacheEntry{}
	}
	return st
}

func saveGuardState(st *guardState) {
	for k, e := range st.Cache {
		if time.Since(e.At) > cacheTTL {
			delete(st.Cache, k)
		}
	}
	if os.MkdirAll(configDir(), 0o700) == nil {
		b, _ := json.Marshal(st)
		_ = writeFileAtomic(guardStatePath(), b, 0o600)
	}
}

// A clean result is reused for 12 hours, and only while the team policy is unchanged.
const cacheTTL = 12 * time.Hour

// cacheKey identifies a clean check: the same API, API key, repo rules and resolution.
func cacheKey(base, apiKey string, rules []rule, resKey string) string {
	k := sha256.Sum256([]byte(apiKey))
	r, _ := json.Marshal(rules)
	rh := sha256.Sum256(r)
	h := sha256.Sum256([]byte(strings.TrimRight(base, "/") + "\x00" + hex.EncodeToString(k[:8]) + "\x00" + hex.EncodeToString(rh[:]) + "\x00" + resKey))
	return hex.EncodeToString(h[:16])
}

// valid: fresh, and checked under the policy the team has now.
func (e cacheEntry) valid(policyVersion string) bool {
	return time.Since(e.At) < cacheTTL && policyVersion != "" && e.PolicyVersion == policyVersion
}

func cacheHit(c *client, key string) bool {
	e, ok := loadGuardState().Cache[key]
	return ok && time.Since(e.At) < cacheTTL && e.valid(policyVersion(c)) // /v1/me only for a live entry
}

func cacheStore(c *client, key string) {
	if pv := policyVersion(c); pv != "" {
		st := loadGuardState()
		st.Cache[key] = cacheEntry{time.Now(), pv}
		saveGuardState(st)
	}
}

// policyVersion is GET /v1/me policy_version, fetched at most once per run ("" when unknown).
var policyVersion = func() func(*client) string {
	var once sync.Once
	var v string
	return func(c *client) string {
		once.Do(func() {
			lc := *c
			lc.http = &http.Client{Timeout: 5 * time.Second}
			var me struct {
				PolicyVersion string `json:"policy_version"`
			}
			if _, err := lc.do("GET", "/v1/me", "", nil, &me); err == nil {
				v = me.PolicyVersion
			}
		})
		return v
	}
}()

func hashKey(kind string, b []byte) string {
	cwd, _ := os.Getwd()
	h := sha256.New()
	h.Write([]byte(kind + "\x00" + cwd + "\x00"))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))[:32]
}

var quietLabel = map[string]string{
	"unmaintained": "look unmaintained", "no-source-repo": "have no public source repository",
	"license-weak-copyleft": "use weak-copyleft licenses (fine when unmodified)", "license-multiple": "list several licenses",
	"license-note": "have license text to review (non-standard or unclear, not blocking)",
}

// quietRule groups a non-blocking, low-signal finding for the summary line ("" = show it).
func quietRule(f checkFinding) string {
	switch {
	case f.Blocking:
		return ""
	case quietLabel[f.Rule] != "":
		return f.Rule
	case f.Category == "license" && f.Severity != "high" && f.Severity != "critical":
		return "license-note"
	}
	return ""
}

func allQuiet(fs []checkFinding) bool {
	for _, f := range fs {
		if quietRule(f) == "" {
			return false
		}
	}
	return len(fs) > 0
}

// notFound: the package manager says the requested package or version does not exist.
func notFound(err error) bool {
	m := strings.ToLower(err.Error())
	for _, s := range []string{"e404", "etarget", "no matching version", "404 not found", "no matching distribution",
		"could not find a version", "unknown revision", "no matching package", "could not find `", "not found in registry",
		"because there are no versions of", "invalid version", "is not in the npm registry"} {
		if strings.Contains(m, s) {
			return true
		}
	}
	return false
}

func indent(s string) string { return "  " + strings.ReplaceAll(s, "\n", "\n  ") }

// run executes the real tool unless this is a dry run (check only, never run anything).
// checked marks an install depguard checked: nested calls (lifecycle scripts) skip the check.
func (o guardOpts) run(bin string, args []string, checked bool) int {
	if o.dryRun {
		fmt.Fprintf(out, "  %s\n", dim("dry run: nothing was run"))
		return 0
	}
	env := os.Environ()
	if checked {
		env = append(env, "DEPGUARD_ACTIVE=1")
	}
	return execTool(bin, args, env)
}
