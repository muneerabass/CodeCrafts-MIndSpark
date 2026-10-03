package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
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

// runGuard checks an install command and then runs the real tool. It returns the exit code.
func runGuard(o guardOpts, tool string, args []string) int {
	bin, err := realTool(tool)
	if err != nil {
		fmt.Fprintf(out, "%s %s\n", brand(), red(err.Error()))
		return 127
	}
	inv := classify(tool, args)
	// Not an install, or already inside a checked install (lifecycle scripts, nested calls).
	if !inv.install || os.Getenv("DEPGUARD_ACTIVE") != "" || os.Getenv("DEPGUARD_DISABLE") != "" {
		return o.run(bin, args)
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
		return o.run(bin, args)
	}

	start := time.Now()
	sp := startSpinner(fmt.Sprintf("resolving what %s would install…", bold(tool+" "+inv.sub)))
	res, rerr := resolve(inv, cwd, bin)
	if rerr != nil && notFound(rerr) {
		sp.end()
		fmt.Fprintf(out, "%s %s %s could not resolve this install:\n%s\n", brand(), red("✖"), tool, dim(indent(lastLines(rerr.Error(), 4))))
		// Registries remove malicious versions: say so when depguard knows the exact version.
		var req checkRequest
		t := true
		for _, sp := range inv.specs {
			if n, v, ok := pinned(inv.tool, sp); ok {
				req.Packages = append(req.Packages, checkPkg{Ecosystem: toolEcosystem[inv.tool], Name: n, Version: v, Direct: &t})
			}
		}
		var result checkResult
		if len(req.Packages) > 0 {
			if _, err := c.do("POST", "/v1/packages/check", "", req, &result); err == nil && len(result.Packages) > 0 {
				printReport(result, &resolution{note: "the registry no longer serves this version; here is what depguard knows about it"}, inv, time.Since(start))
			}
		}
		return 1
	}
	if rerr != nil {
		// Fall back to the packages named on the command line with exact versions.
		res = &resolution{partial: true, note: "could not resolve the full dependency tree: " + firstLine(rerr.Error())}
		for _, s := range inv.specs {
			if n, v, ok := pinned(inv.tool, s); ok {
				direct := true
				res.req.Packages = append(res.req.Packages, checkPkg{Ecosystem: toolEcosystem[inv.tool], Name: n, Version: v, Direct: &direct})
			}
		}
	}
	if len(inv.specs) == 0 {
		res.req.Before = nil // a plain install installs everything: check the whole tree
	}
	if res.key != "" && cacheHit(res.key) {
		sp.end()
		fmt.Fprintf(out, "%s %s %s\n", brand(), green("✔"), dim("dependencies unchanged since the last clean check"))
		return o.run(bin, args)
	}
	if len(res.req.Packages) == 0 && len(res.req.After) == 0 {
		sp.end()
		fmt.Fprintf(out, "%s %s %s\n", brand(), yellow("!"), dim(firstNonEmpty(res.note, "nothing to check")+" — running "+tool))
		return o.run(bin, args)
	}
	if pc != nil {
		res.req.RepoRules = pc.Rules
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
		return o.run(bin, args)
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
	logEvent(c, inv, result, decision, o.reason)
	switch {
	case decision == "block":
		fmt.Fprintf(out, "  %s\n\n", dim("Install stopped. To install anyway: depguard --force --reason \"why\" "+tool+" "+strings.Join(args, " ")))
		return 1
	case decision == "override":
		fmt.Fprintf(out, "  %s %s\n\n", yellow("⚠ override:"), "installing despite blocking findings"+map[bool]string{true: " (" + o.reason + ")", false: ""}[o.reason != ""])
	case decision == "allow" && res.key != "":
		cacheStore(res.key)
	}
	if o.dryRun {
		return map[string]int{"block": 1}[result.Decision]
	}
	return execTool(bin, args)
}

func firstLine(s string) string {
	l, _, _ := strings.Cut(s, "\n")
	return truncate(l, 140)
}

// printReport renders the verdict.
func printReport(r checkResult, res *resolution, inv invocation, took time.Duration) {
	fmt.Fprintln(out)
	head := fmt.Sprintf("%s  checked %s for %s", brand(), bold(plural(r.Checked, "package", "packages")), bold(inv.tool+" "+inv.sub))
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

// logEvent records the decision on the dashboard (Endpoints → Package events). Best effort.
func logEvent(c *client, inv invocation, r checkResult, decision, reason string) {
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
		"message":   fmt.Sprintf("%s %s: %s (%s with findings of %d checked)", inv.tool, inv.sub, decision, plural(len(r.Packages), "package", "packages"), r.Checked),
		"ecosystem": toolEcosystem[inv.tool], "details": map[string]any{"command": inv.tool + " " + strings.Join(inv.args, " "), "dir": filepath.Base(cwd), "reason": reason, "checked": r.Checked}})
	for i, p := range r.Packages {
		if i == 50 {
			break
		}
		var rules []string
		for _, f := range p.Findings {
			rules = append(rules, f.Rule)
		}
		add(map[string]any{"timestamp": now, "event_type": "guard.package." + p.Decision, "package_name": p.Name, "version": p.Version,
			"ecosystem": p.Ecosystem, "message": p.Findings[0].Summary, "details": map[string]any{"rules": rules}})
	}
	_, _ = c.do("POST", "/v1/endpoints/"+st.EndpointID+"/pmg-events", "application/x-ndjson", strings.NewReader(strings.Join(lines, "\n")+"\n"), nil)
}

// ---------------------------------------------------------------- real tool

// realTool finds the package manager on PATH, skipping depguard's own shims.
func realTool(tool string) (string, error) {
	shims, _ := filepath.Abs(shimDir())
	self, _ := os.Executable()
	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if abs, _ := filepath.Abs(d); abs == shims {
			continue
		}
		for _, name := range toolNames(tool) {
			p := filepath.Join(d, name)
			fi, err := os.Stat(p)
			if err != nil || fi.IsDir() || (runtime.GOOS != "windows" && fi.Mode()&0o111 == 0) {
				continue
			}
			if same, _ := filepath.EvalSymlinks(p); same == self {
				continue
			}
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found on PATH", tool)
}

func toolNames(tool string) []string {
	if runtime.GOOS == "windows" {
		return []string{tool + ".exe", tool + ".cmd", tool + ".bat"}
	}
	return []string{tool}
}

// execTool runs the real tool with the terminal attached and returns its exit code.
func execTool(bin string, args []string) int {
	cmd := exec.Command(bin, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(), "DEPGUARD_ACTIVE=1")
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintf(out, "%s %v\n", brand(), err)
		return 127
	}
	return 0
}

// ---------------------------------------------------------------- state & cache

type guardState struct {
	EndpointID string               `json:"endpoint_id"`
	Checked    map[string]time.Time `json:"checked"` // resolution hash -> last clean check
}

func guardStatePath() string { return filepath.Join(configDir(), "guard-state.json") }

func loadGuardState() *guardState {
	st := &guardState{}
	if b, err := os.ReadFile(guardStatePath()); err == nil {
		_ = json.Unmarshal(b, st)
	}
	if st.Checked == nil {
		st.Checked = map[string]time.Time{}
	}
	return st
}

func saveGuardState(st *guardState) {
	for k, t := range st.Checked {
		if time.Since(t) > cacheTTL {
			delete(st.Checked, k)
		}
	}
	if os.MkdirAll(configDir(), 0o700) == nil {
		b, _ := json.Marshal(st)
		_ = writeFileAtomic(guardStatePath(), b, 0o600)
	}
}

// A clean result is reused for a day: new advisories are picked up daily.
const cacheTTL = 24 * time.Hour

func cacheHit(key string) bool {
	t, ok := loadGuardState().Checked[key]
	return ok && time.Since(t) < cacheTTL
}

func cacheStore(key string) {
	st := loadGuardState()
	st.Checked[key] = time.Now()
	saveGuardState(st)
}

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

// run executes the real tool unless this is a dry run (check only, never install).
func (o guardOpts) run(bin string, args []string) int {
	if o.dryRun {
		fmt.Fprintf(out, "  %s\n", dim("dry run: nothing was installed"))
		return 0
	}
	return execTool(bin, args)
}
