//go:build !windows

package main

import (
	"fmt"
	"syscall"
)

// execTool replaces depguard with the real tool: exact exit code, signals and terminal.
func execTool(bin string, args, env []string) int {
	err := syscall.Exec(bin, append([]string{bin}, args...), env)
	fmt.Fprintf(out, "%s %v\n", brand(), err)
	return 127
}
