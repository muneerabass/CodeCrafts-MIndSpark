package main

import "testing"

func TestImageName(t *testing.T) {
	for ref, want := range map[string][2]string{
		"node:18-alpine":                               {"node", "18-alpine"},
		"docker.io/library/nginx":                      {"nginx", "latest"},
		"ghcr.io/acme/api:1.4@sha256:abcdef0123456789": {"ghcr.io/acme/api", "1.4"},
		"localhost:5000/team/app":                      {"localhost:5000/team/app", "latest"},
		"registry.io/x/y@sha256:0123456789abcdef9":     {"registry.io/x/y", "0123456789ab"},
	} {
		if n, v := imageName(ref); n != want[0] || v != want[1] {
			t.Errorf("%s: %s %s", ref, n, v)
		}
	}
	if !isSBOM("image.cdx.json") || !isSBOM("app.spdx.json") || isSBOM("package-lock.json") {
		t.Error("isSBOM")
	}
}
