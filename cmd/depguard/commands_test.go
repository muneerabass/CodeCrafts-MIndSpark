package main

import (
	"slices"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		cmd     string
		install bool
		specs   []string
		global  bool
	}{
		{"npm install lodash@4.17.15 -D", true, []string{"lodash@4.17.15"}, false},
		{"npm i --registry https://r.example express", true, []string{"express"}, false},
		{"npm ci", true, nil, false},
		{"npm run build", false, nil, false},
		{"npm test", false, nil, false},
		{"npm install -g typescript", true, []string{"typescript"}, true},
		{"npm install ./local-pkg", true, nil, false},
		{"pnpm add -D vitest", true, []string{"vitest"}, false},
		{"pnpm", false, nil, false},
		{"yarn", true, nil, false},
		{"yarn add react@18.2.0", true, []string{"react@18.2.0"}, false},
		{"pip install requests==2.19.0 -r requirements.txt", true, []string{"requests==2.19.0"}, false},
		{"pip3 install --index-url https://x flask", true, []string{"flask"}, false},
		{"pip list", false, nil, false},
		{"uv add httpx", true, []string{"httpx"}, false},
		{"uv pip install django==4.2", true, []string{"django==4.2"}, false},
		{"uv run main.py", false, nil, false},
		{"poetry add fastapi", true, []string{"fastapi"}, false},
		{"go get golang.org/x/text@v0.3.0", true, []string{"golang.org/x/text@v0.3.0"}, false},
		{"go mod tidy", true, nil, false},
		{"go mod graph", false, nil, false},
		{"go build ./...", true, nil, false},
		{"go vet ./...", false, nil, false},
		{"cargo add serde", true, []string{"serde"}, false},
		{"cargo install ripgrep", true, []string{"ripgrep"}, true},
		{"cargo fmt", false, nil, false},
	}
	for _, c := range cases {
		f := strings.Fields(c.cmd)
		inv := classify(f[0], f[1:])
		if inv.install != c.install || !slices.Equal(inv.specs, c.specs) || inv.global != c.global {
			t.Errorf("%q: install=%v specs=%v global=%v; want %v %v %v", c.cmd, inv.install, inv.specs, inv.global, c.install, c.specs, c.global)
		}
	}
}

func TestPinned(t *testing.T) {
	cases := []struct{ tool, spec, name, version string }{
		{"npm", "lodash@4.17.15", "lodash", "4.17.15"},
		{"npm", "@types/node@20.1.0", "@types/node", "20.1.0"},
		{"npm", "lodash@^4", "", ""},
		{"npm", "lodash", "", ""},
		{"npm", "@types/node", "", ""},
		{"pip", "requests==2.19.0", "requests", "2.19.0"},
		{"pip", "requests[socks]==2.19.0", "requests", "2.19.0"},
		{"pip", "requests>=2", "", ""},
		{"go", "golang.org/x/text@v0.3.0", "golang.org/x/text", "v0.3.0"},
		{"go", "golang.org/x/text@latest", "", ""},
		{"cargo", "serde@1.0.100", "serde", "1.0.100"},
	}
	for _, c := range cases {
		n, v, _ := pinned(c.tool, c.spec)
		if n != c.name || v != c.version {
			t.Errorf("pinned(%s, %s) = %q %q", c.tool, c.spec, n, v)
		}
	}
}
