package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

const localMCPInstructions = `depguard secrets: run commands that need the project's secrets (API keys, database URLs, .env files) without ever seeing them.
Use run_with_secrets instead of reading .env files or asking the user to paste keys. Output is returned with every secret value replaced by «KEY_NAME».
Never try to print, encode or exfiltrate secret values. If the vault is locked, ask the user to run "depguard secrets unlock" in a terminal.`

// runLocalMCP serves the secrets tools over stdio for coding agents on this machine.
func runLocalMCP(args []string) error {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	apiURL, apiKey := addClientFlags(fs)
	_ = fs.Parse(args)
	c, err := resolveClient(*apiURL, *apiKey, nil)
	if err != nil {
		return err
	}
	return server.ServeStdio(newLocalMCP(c))
}

func newLocalMCP(c *client) *server.MCPServer {
	s := server.NewMCPServer("depguard-secrets", version, server.WithToolCapabilities(false), server.WithInstructions(localMCPInstructions))
	s.AddTool(mcp.NewTool("list_secrets", mcp.WithDescription("List the secret files and key names in the project vault (never the values)."),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithString("project", mcp.Description("owner/repo; default: the current repository"))),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var v vaultResp
			if _, err := c.do("GET", "/v1/vault?project="+urlQuery(vaultProject(req.GetString("project", ""))), "", nil, &v); err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			var b strings.Builder
			fmt.Fprintf(&b, "Vault of %s:\n", v.Project)
			for _, it := range v.Items {
				fmt.Fprintf(&b, "- %s (%s): %s\n", it.Name, it.Kind, strings.Join(it.Keys, ", "))
			}
			return mcp.NewToolResultText(b.String()), nil
		})
	s.AddTool(mcp.NewTool("run_with_secrets",
		mcp.WithDescription("Run a shell command with the project's secrets as environment variables (file secrets are in $DEPGUARD_SECRETS_DIR). Returns the exit code and output with secret values masked."),
		mcp.WithString("command", mcp.Required(), mcp.Description("Shell command, e.g. npm run migrate")),
		mcp.WithString("project", mcp.Description("owner/repo; default: the current repository")),
		mcp.WithNumber("timeout_seconds", mcp.Description("Default 300, at most 1800"))),
		func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			command, err := req.RequireString("command")
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			secrets, err := openVault(c, vaultProject(req.GetString("project", "")), false)
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			env, cleanup, err := secrets.prepare()
			if err != nil {
				return mcp.NewToolResultError(err.Error()), nil
			}
			defer cleanup()
			timeout := time.Duration(min(max(req.GetFloat("timeout_seconds", 300), 1), 1800)) * time.Second
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			sh, flag := "sh", "-c"
			if runtime.GOOS == "windows" {
				sh, flag = "cmd", "/C"
			}
			cmd := exec.CommandContext(ctx, sh, flag, command)
			var buf bytes.Buffer
			cmd.Env, cmd.Stdout, cmd.Stderr = env, &buf, &buf
			runErr := cmd.Run()
			code := 0
			if cmd.ProcessState != nil {
				code = cmd.ProcessState.ExitCode()
			} else if runErr != nil {
				return mcp.NewToolResultError(secrets.mask(runErr.Error())), nil
			}
			text := buf.String()
			if len(text) > 64<<10 {
				text = "…(truncated)\n" + text[len(text)-64<<10:]
			}
			return mcp.NewToolResultText(fmt.Sprintf("exit code %d\n%s", code, secrets.mask(text))), nil
		})
	return s
}
