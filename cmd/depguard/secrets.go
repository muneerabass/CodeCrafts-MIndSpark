package main

import (
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/depguard/depguard/internal/vaultcrypto"
	"golang.org/x/term"
)

// The project vault is end-to-end encrypted: the CLI downloads ciphertext and
// decrypts it here with the member's private key, which is sealed with their
// vault passphrase (see internal/vaultcrypto).

type vaultMember struct {
	UserID         string                     `json:"user_id"`
	PublicKey      string                     `json:"public_key"`
	WrappedPrivate vaultcrypto.WrappedPrivate `json:"wrapped_private"`
}

type vaultItem struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Kind       string   `json:"kind"`
	Keys       []string `json:"keys"`
	IV         string   `json:"iv"`
	Ciphertext string   `json:"ciphertext"`
}

type vaultResp struct {
	ProjectID string                  `json:"project_id"`
	Project   string                  `json:"project"`
	MyKey     *vaultcrypto.WrappedKey `json:"my_key"`
	Items     []vaultItem             `json:"items"`
	Member    vaultMember             `json:"member"`
}

// session is the unlocked private key, kept in a user-only file in the runtime
// dir (tmpfs on Linux) until it expires or `depguard secrets lock` removes it.
type session struct {
	UserID  string    `json:"user_id"`
	API     string    `json:"api"`
	Key     string    `json:"key"` // base64 PKCS#8
	Expires time.Time `json:"expires"`
}

func sessionPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "depguard-"+strconv.Itoa(os.Getuid()))
	}
	return filepath.Join(dir, "depguard", "vault-session.json")
}

func loadSession(api string) (*ecdh.PrivateKey, string, error) {
	b, err := os.ReadFile(sessionPath())
	if err != nil {
		return nil, "", errors.New("the vault is locked: run `depguard secrets unlock` in a terminal")
	}
	var s session
	if json.Unmarshal(b, &s) != nil || time.Now().After(s.Expires) || s.API != api {
		os.Remove(sessionPath())
		return nil, "", errors.New("the vault session expired: run `depguard secrets unlock` again")
	}
	der, err := base64.StdEncoding.DecodeString(s.Key)
	if err != nil {
		return nil, "", err
	}
	k, err := vaultcrypto.ParsePKCS8(der)
	return k, s.UserID, err
}

func saveSession(k *ecdh.PrivateKey, userID, api string, ttl time.Duration) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	p := sessionPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.Marshal(session{UserID: userID, API: api, Key: base64.StdEncoding.EncodeToString(der), Expires: time.Now().Add(ttl)})
	return writeFileAtomic(p, b, 0o600)
}

func readPassphrase() (string, error) {
	if p := os.Getenv("DEPGUARD_VAULT_PASSPHRASE"); p != "" {
		return p, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("no terminal to ask for the vault passphrase: run `depguard secrets unlock` first, or set DEPGUARD_VAULT_PASSPHRASE")
	}
	fmt.Fprint(os.Stderr, "Vault passphrase: ")
	b, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}

// vaultProject is the project name: --project, .depguard.yml, the git remote, then the folder name.
func vaultProject(flagProject string) string {
	if flagProject != "" {
		return flagProject
	}
	wd, _ := os.Getwd()
	if pc, _ := findProject(wd); pc != nil && pc.Project != "" {
		return pc.Project
	}
	if p := gitProject(wd); p != "" {
		return p
	}
	return filepath.Base(wd)
}

// unlockedVault fetches a project's vault and decrypts its items.
type secretSet struct {
	project string
	env     []vaultcrypto.EnvVar // from env items, later items override earlier ones
	files   map[string][]byte    // file items by name
}

func openVault(c *client, project string, allowPrompt bool) (*secretSet, error) {
	var v vaultResp
	if _, err := c.do("GET", "/v1/vault?project="+urlQuery(project), "", nil, &v); err != nil {
		return nil, err
	}
	priv, uid, err := loadSession(c.base)
	if err != nil || uid != v.Member.UserID {
		if !allowPrompt {
			if err == nil {
				err = errors.New("the unlocked vault belongs to another account: run `depguard secrets unlock` again")
			}
			return nil, err
		}
		pass, perr := readPassphrase()
		if perr != nil {
			return nil, perr
		}
		if priv, err = vaultcrypto.UnwrapPrivate(v.Member.WrappedPrivate, pass); err != nil {
			return nil, err
		}
		uid = v.Member.UserID
	}
	if v.MyKey == nil {
		return nil, errors.New("you have no access to this vault yet: ask a teammate to approve you in depguard")
	}
	vk, err := vaultcrypto.UnwrapKey(priv, *v.MyKey, v.ProjectID, uid)
	if err != nil {
		return nil, err
	}
	sort.Slice(v.Items, func(i, j int) bool { return v.Items[i].Name < v.Items[j].Name })
	s := &secretSet{project: v.Project, files: map[string][]byte{}}
	for _, it := range v.Items {
		pt, err := vaultcrypto.DecryptItem(vk, it.IV, it.Ciphertext, v.ProjectID, it.Name)
		if err != nil {
			return nil, err
		}
		if it.Kind == "env" {
			s.env = append(s.env, vaultcrypto.ParseEnv(string(pt))...)
		} else {
			s.files[it.Name] = pt
		}
	}
	return s, nil
}

// prepare writes file items to a private temp dir and returns the environment
// for a child process plus a cleanup function.
func (s *secretSet) prepare() ([]string, func(), error) {
	env := os.Environ()
	for _, v := range s.env {
		env = append(env, v.Key+"="+v.Value)
	}
	cleanup := func() {}
	if len(s.files) > 0 {
		dir, err := os.MkdirTemp("", "depguard-secrets-")
		if err != nil {
			return nil, nil, err
		}
		cleanup = func() { os.RemoveAll(dir) }
		for name, b := range s.files {
			p := filepath.Join(dir, filepath.Base(name))
			if err := os.WriteFile(p, b, 0o600); err != nil {
				cleanup()
				return nil, nil, err
			}
		}
		env = append(env, "DEPGUARD_SECRETS_DIR="+dir)
	}
	return env, cleanup, nil
}

// mask replaces every secret value (6+ characters) in s, longest first.
func (s *secretSet) mask(out string) string {
	vals := s.env
	sort.Slice(vals, func(i, j int) bool { return len(vals[i].Value) > len(vals[j].Value) })
	for _, v := range vals {
		if len(v.Value) >= 6 {
			out = strings.ReplaceAll(out, v.Value, "«"+v.Key+"»")
		}
	}
	return out
}

func runSecrets(args []string) (int, error) {
	if len(args) == 0 {
		return 2, errors.New("usage: depguard secrets unlock|lock|list|run [--project owner/repo] [-- command]")
	}
	fs := flag.NewFlagSet("secrets "+args[0], flag.ExitOnError)
	project := fs.String("project", "", "project name (default: .depguard.yml, git remote, folder)")
	ttl := fs.Duration("ttl", 8*time.Hour, "unlock: how long the vault stays unlocked")
	apiURL, apiKey := addClientFlags(fs)
	_ = fs.Parse(args[1:])
	c, err := resolveClient(*apiURL, *apiKey, nil)
	if err != nil {
		return 2, err
	}
	switch args[0] {
	case "unlock":
		var me struct {
			Member *vaultMember `json:"member"`
		}
		if _, err := c.do("GET", "/v1/vault/me", "", nil, &me); err != nil {
			return 2, err
		}
		if me.Member == nil {
			return 2, errors.New("set up your vault passphrase first: open a project's Secrets tab in depguard")
		}
		pass, err := readPassphrase()
		if err != nil {
			return 2, err
		}
		k, err := vaultcrypto.UnwrapPrivate(me.Member.WrappedPrivate, pass)
		if err != nil {
			return 2, err
		}
		if err := saveSession(k, me.Member.UserID, c.base, *ttl); err != nil {
			return 2, err
		}
		fmt.Fprintf(out, "%s vault unlocked for %s (lock with: depguard secrets lock)\n", brand(), ttl.Round(time.Minute))
		return 0, nil
	case "lock":
		os.Remove(sessionPath())
		fmt.Fprintf(out, "%s vault locked\n", brand())
		return 0, nil
	case "list":
		var v vaultResp
		if _, err := c.do("GET", "/v1/vault?project="+urlQuery(vaultProject(*project)), "", nil, &v); err != nil {
			return 2, err
		}
		fmt.Fprintf(out, "%s %s\n", brand(), v.Project)
		for _, it := range v.Items {
			fmt.Fprintf(out, "  %-28s %-5s %s\n", it.Name, it.Kind, strings.Join(it.Keys, " "))
		}
		return 0, nil
	case "run":
		cmdArgs := fs.Args()
		if len(cmdArgs) == 0 {
			return 2, errors.New("usage: depguard secrets run [--project p] -- command [args]")
		}
		s, err := openVault(c, vaultProject(*project), true)
		if err != nil {
			return 2, err
		}
		env, cleanup, err := s.prepare()
		if err != nil {
			return 2, err
		}
		defer cleanup()
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, os.Stdin, os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode(), nil
			}
			return 127, err
		}
		return 0, nil
	}
	return 2, fmt.Errorf("unknown command %q: use unlock, lock, list or run", args[0])
}

func urlQuery(s string) string { return url.QueryEscape(s) }
