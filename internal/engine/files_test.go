package engine

import (
	"os"
	"testing"
)

func TestWriteFilesRejectsTraversal(t *testing.T) {
	dir := t.TempDir()
	lfs, notes := writeFiles(dir, []file{{Path: "../evil.txt", Data: []byte("x")}, {Path: "/etc/x", Data: []byte("x")},
		{Path: "a/../../b", Data: []byte("x")}, {Path: "ok/go.mod", Data: []byte("module x")}})
	if len(lfs) != 1 || lfs[0].RepoPath != "ok/go.mod" || len(notes) != 3 {
		t.Fatalf("lfs %v notes %v", lfs, notes)
	}
	if _, err := os.Stat(dir + "/../evil.txt"); err == nil {
		t.Fatal("file escaped temp dir")
	}
}
