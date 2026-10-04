package vaultcrypto

import (
	"regexp"
	"strings"
)

// EnvVar is one KEY=VALUE of a .env file.
type EnvVar struct{ Key, Value string }

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)

// ParseEnv reads a .env file: comments, `export KEY=…`, single quotes
// (literal), double quotes (\n, \", \\ escapes; may span lines) and unquoted
// values with ` #` comments. Must match parseEnv in web/lib/vault-crypto.ts.
func ParseEnv(src string) []EnvVar {
	var out []EnvVar
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		k = strings.TrimSpace(k)
		if !ok || !envKey.MatchString(k) {
			continue
		}
		v = strings.TrimSpace(v)
		switch {
		case strings.HasPrefix(v, `"`):
			body := v[1:]
			for !closedDouble(body) && i+1 < len(lines) {
				i++
				body += "\n" + lines[i]
			}
			v = unescapeDouble(body)
		case strings.HasPrefix(v, "'"):
			if j := strings.Index(v[1:], "'"); j >= 0 {
				v = v[1 : j+1]
			} else {
				v = v[1:]
			}
		default:
			if j := strings.Index(v, " #"); j >= 0 {
				v = strings.TrimSpace(v[:j])
			}
		}
		out = append(out, EnvVar{k, v})
	}
	return out
}

// closedDouble reports whether s contains an unescaped closing double quote.
func closedDouble(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
		} else if s[i] == '"' {
			return true
		}
	}
	return false
}

func unescapeDouble(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			break
		}
		if c == '\\' && i+1 < len(s) {
			i++
			switch s[i] {
			case 'n':
				b.WriteByte('\n')
			case 't':
				b.WriteByte('\t')
			default:
				b.WriteByte(s[i])
			}
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// SecretValues returns the values worth fingerprinting and masking (12+ chars).
func SecretValues(vars []EnvVar) []EnvVar {
	var out []EnvVar
	for _, v := range vars {
		if len(v.Value) >= 12 {
			out = append(out, v)
		}
	}
	return out
}
