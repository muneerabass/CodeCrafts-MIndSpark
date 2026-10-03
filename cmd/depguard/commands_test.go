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
		{"go build ./...", false, nil, false},
		{"go vet ./...", false, nil, false},
		{"cargo add serde", true, []string{"serde"}, false},
		{"cargo install ripgrep", true, []string{"ripgrep"}, true},
		{"cargo fmt", false, nil, false},

		// subcommand after unknown or value flags; flag values are never specs
		{"pip --proxy http://p install x", true, []string{"x"}, false},
		{"pip install --only-binary :all: --timeout 30 x", true, []string{"x"}, false},
		{"pip install -v requests", true, []string{"requests"}, false},
		{"npm --loglevel silent install x", true, []string{"x"}, false},
		{"npm i --cache /tmp/c --userconfig ./rc express", true, []string{"express"}, false},
		{"pnpm --filter web add x", true, []string{"x"}, false},
		{"yarn add --network-timeout 100000 react", true, []string{"react"}, false},
		{"uv pip install --index https://x flask", true, []string{"flask"}, false},
		{"cargo +nightly add x", true, []string{"x"}, false},
		{"cargo add --color always -j 4 serde", true, []string{"serde"}, false},
		{"poetry install --with dev", true, nil, false},
		{"poetry add -E socks --source internal requests", true, []string{"requests"}, false},
		{"npm run install", false, nil, false},
		{"poetry run pip install x", false, nil, false},

		// help and version never install
		{"yarn --version", false, nil, false},
		{"yarn -v", false, nil, false},
		{"yarn --frozen-lockfile", true, nil, false},
		{"npm install --help", false, nil, false},
		{"pip install --version", false, nil, false},
		{"cargo add -h", false, nil, false},

		// go and cargo: only commands that fetch dependencies
		{"go test ./...", false, nil, false},
		{"go run ./cmd/x", false, nil, false},
		{"go generate ./...", false, nil, false},
		{"go install ./cmd/x", false, nil, false},
		{"go install golang.org/x/tools/gopls@v0.15.0", true, []string{"golang.org/x/tools/gopls@v0.15.0"}, false},
		{"go mod download", true, nil, false},
		{"cargo build --release", false, nil, false},
		{"cargo test -- add", false, nil, false},
		{"cargo clippy", false, nil, false},
		{"cargo update", true, nil, false},
		{"cargo fetch", true, nil, false},
		{"cargo generate-lockfile", true, nil, false},
		{"cargo install ripgrep --version 13.0.0", true, []string{"ripgrep@13.0.0"}, true},
		{"cargo install --vers=13.0.0 ripgrep", true, []string{"ripgrep@13.0.0"}, true},

		// upgrades and frozen syncs
		{"uv lock -U", true, nil, false},
		{"uv sync --frozen", true, nil, false},
		{"poetry update requests", true, []string{"requests"}, false},

		// fetch-and-run
		{"npx cowsay@1.5.0", true, []string{"cowsay@1.5.0"}, false},
		{"npx -y cowsay hello", true, []string{"cowsay"}, false},
		{"npx --package=typescript tsc -p tsconfig.json", true, []string{"typescript"}, false},
		{"npx --version", false, nil, false},
		{"npm exec -- eslint --fix .", true, []string{"eslint"}, false},
		{"npm exec eslint --help", true, []string{"eslint"}, false},
		{"pnpm dlx create-vite@5.0.0", true, []string{"create-vite@5.0.0"}, false},
		{"yarn dlx cowsay", true, []string{"cowsay"}, false},
		{"uvx ruff", true, []string{"ruff"}, false},
		{"uvx ruff@0.5.0 check --help", true, []string{"ruff==0.5.0"}, false},
		{"uvx --from httpie==3.2.2 http", true, []string{"httpie==3.2.2"}, false},
		{"uv tool run black", true, []string{"black"}, false},
	}
	for _, c := range cases {
		f := strings.Fields(c.cmd)
		inv := classify(f[0], f[1:])
		if inv.install != c.install || !slices.Equal(inv.specs, c.specs) || inv.global != c.global {
			t.Errorf("%q: install=%v specs=%v global=%v; want %v %v %v", c.cmd, inv.install, inv.specs, inv.global, c.install, c.specs, c.global)
		}
		runs := f[0] == "npx" || f[0] == "uvx" || slices.Contains(f, "exec") || slices.Contains(f, "dlx") || slices.Contains(f, "tool")
		if inv.exec != (runs && c.install) {
			t.Errorf("%q: exec=%v", c.cmd, inv.exec)
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
		{"npm", "pkg@1", "", ""},
		{"npm", "pkg@18", "", ""},
		{"npm", "pkg@beta", "", ""},
		{"npm", "pkg@1.2", "", ""},
		{"npm", "pkg@1.2.3-beta.1", "pkg", "1.2.3-beta.1"},
		{"npm", "pkg@v1.2.3", "pkg", "v1.2.3"},
		{"npx", "cowsay@1.5.0", "cowsay", "1.5.0"},
		{"cargo", "serde@1", "", ""},
		{"go", "golang.org/x/text@v0", "", ""},
		{"go", "example.com/m@v0.0.0-20230101120000-abcdef123456", "example.com/m", "v0.0.0-20230101120000-abcdef123456"},
		{"go", "example.com/m@v2.0.0+incompatible", "example.com/m", "v2.0.0+incompatible"},
		{"pip", "django==4.2", "django", "4.2"},
		{"pip", "django==4.*", "", ""},
		{"uvx", "ruff==0.5.0", "ruff", "0.5.0"},
	}
	for _, c := range cases {
		n, v, _ := pinned(c.tool, c.spec)
		if n != c.name || v != c.version {
			t.Errorf("pinned(%s, %s) = %q %q", c.tool, c.spec, n, v)
		}
	}
}
