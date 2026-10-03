package engine

import (
	"embed"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"

	"github.com/safedep/code/plugin/callgraph"
	"github.com/safedep/xbom/pkg/codeanalysis"
	"github.com/safedep/xbom/pkg/signatures"
)

// signaturesFS holds AI/SaaS signatures copied from safedep/xbom v0.0.3
// (Apache-2.0, signatures/; cryptography signatures omitted). xbom embeds
// them in its main package, which is not importable, so we embed our copy.
//
//go:embed signatures
var signaturesFS embed.FS

func init() { signatures.SetEmbeddedSignatureFS(signaturesFS) }

// aiUsage runs xbom's code analysis over files and returns matches like
// "Anthropic API - AI client in app.py:8". Failures only log.
func aiUsage(files []file, log *slog.Logger) (out []string) {
	if len(files) == 0 {
		return nil
	}
	defer func() {
		if r := recover(); r != nil { // tree-sitter/cgo code; never take the scan down
			log.Error("xbom panic", "panic", r)
			out = nil
		}
	}()
	dir, err := os.MkdirTemp("", "depguard-xbom-*")
	if err != nil {
		log.Warn("xbom temp dir", "err", err)
		return nil
	}
	defer os.RemoveAll(dir)
	writeFiles(dir, files)
	sigs, err := signatures.LoadAllSignatures()
	if err != nil {
		log.Warn("xbom signatures", "err", err)
		return nil
	}
	wf := codeanalysis.NewCodeAnalysisWorkflow(codeanalysis.CodeAnalysisWorkflowConfig{SourcePath: dir, SignaturesToMatch: sigs}, nil)
	findings, err := wf.Execute()
	if err != nil {
		log.Warn("xbom analysis", "err", err)
		return nil
	}
	for _, matches := range findings.SignatureWiseMatchResults {
		for _, m := range matches {
			sig := m.MatchedSignature
			rel, err := filepath.Rel(dir, m.FilePath)
			if err != nil {
				rel = filepath.Base(m.FilePath)
			}
			loc := filepath.ToSlash(rel)
			if line := firstLine(m.MatchedConditions); line > 0 {
				loc = fmt.Sprintf("%s:%d", loc, line)
			}
			out = append(out, fmt.Sprintf("%s - %s in %s", sig.GetProduct(), sig.GetService(), loc))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

func firstLine(conds []callgraph.MatchedCondition) int {
	for _, c := range conds {
		for _, e := range c.Evidences {
			if e.CallerIdentifier != nil {
				return int(e.CallerIdentifier.StartPoint().Row) + 1
			}
		}
	}
	return 0
}
