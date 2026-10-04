package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// imageName splits an image reference into a project name and version:
// "ghcr.io/acme/api:1.4@sha256:ab12…" → ("ghcr.io/acme/api", "1.4").
func imageName(ref string) (string, string) {
	name, digest, _ := strings.Cut(ref, "@")
	tag := ""
	if i := strings.LastIndex(name, ":"); i > strings.LastIndex(name, "/") {
		name, tag = name[:i], name[i+1:]
	}
	name = strings.TrimPrefix(strings.TrimPrefix(name, "docker.io/"), "library/")
	switch {
	case tag != "":
	case digest != "":
		tag = strings.TrimPrefix(digest, "sha256:")
		if len(tag) > 12 {
			tag = tag[:12]
		}
	default:
		tag = "latest"
	}
	return name, tag
}

// imageSBOM writes a CycloneDX SBOM of a container image into dir using syft
// (https://github.com/anchore/syft), which reads images from a registry, the
// local Docker daemon or an archive without running them.
func imageSBOM(ref, dir string) (string, error) {
	syft, err := exec.LookPath("syft")
	if err != nil {
		return "", errors.New("container scanning needs syft: install it (https://github.com/anchore/syft#installation, e.g. `brew install syft`) " +
			"or create an SBOM with any tool and run: depguard scan --sbom image.cdx.json")
	}
	out := filepath.Join(dir, "image.cdx.json")
	cmd := exec.Command(syft, "scan", ref, "-o", "cyclonedx-json@1.6="+out, "-q")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	start := time.Now()
	fmt.Fprintf(os.Stderr, "depguard: reading %s with syft…\n", ref)
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("syft %s: %w: %s", ref, err, strings.TrimSpace(stderr.String()))
	}
	fmt.Fprintf(os.Stderr, "depguard: SBOM created in %s\n", time.Since(start).Round(time.Second))
	return "image.cdx.json", nil
}

// isSBOM reports whether a file name is an SBOM the server can read.
func isSBOM(name string) bool {
	return strings.HasSuffix(name, ".cdx.json") || strings.HasSuffix(name, ".spdx.json") || name == "bom.json"
}
