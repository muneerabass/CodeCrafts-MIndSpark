package scan

import (
	"testing"

	"github.com/safedep/vet/pkg/models"
)

func TestImported(t *testing.T) {
	imports := ImportedPackages(map[string][]byte{
		"src/app.ts": []byte(`import express from 'express';
import type { X } from "@scope/pkg/sub/path";
import './local';
import fs from 'node:fs';
export * from "re-exported";
const lazy = await import('lazy-mod');
const _ = require("lodash/fp");
import "side-effect";`),
		"app/main.py": []byte(`import os, yaml as y
import google.protobuf.message
from bs4 import BeautifulSoup
from . import sibling
from PIL import Image
  import dotenv`),
		"main.go": []byte(`package main
import (
	"fmt"
	gin "github.com/gin-gonic/gin/binding"
	_ "github.com/lib/pq"
)
import "golang.org/x/sync/errgroup"`),
		"App.java": []byte(`package x;
import com.fasterxml.jackson.databind.ObjectMapper;
import static org.junit.Assert.*;
import org.apache.commons.lang3.*;`),
	})
	cases := []struct {
		eco, name       string
		imported, known bool
	}{
		{models.EcosystemNpm, "express", true, true},
		{models.EcosystemNpm, "@scope/pkg", true, true},
		{models.EcosystemNpm, "re-exported", true, true},
		{models.EcosystemNpm, "lazy-mod", true, true},
		{models.EcosystemNpm, "lodash", true, true},
		{models.EcosystemNpm, "side-effect", true, true},
		{models.EcosystemNpm, "local", false, true},
		{models.EcosystemNpm, "react", false, true},
		{models.EcosystemPyPI, "PyYAML", true, true},
		{models.EcosystemPyPI, "beautifulsoup4", true, true},
		{models.EcosystemPyPI, "Pillow", true, true},
		{models.EcosystemPyPI, "protobuf", true, true},
		{models.EcosystemPyPI, "python-dotenv", true, true},
		{models.EcosystemPyPI, "requests", false, true},
		{models.EcosystemGo, "github.com/gin-gonic/gin", true, true},
		{models.EcosystemGo, "github.com/lib/pq", true, true},
		{models.EcosystemGo, "golang.org/x/sync", true, true},
		{models.EcosystemGo, "github.com/gin-gonic/gin-extra", false, true},
		{models.EcosystemMaven, "com.fasterxml.jackson.core:jackson-databind", false, true},
		{models.EcosystemMaven, "com.fasterxml.jackson.databind:x", true, true},
		{models.EcosystemMaven, "org.junit:junit", true, true},
		{models.EcosystemMaven, "org.apache.commons:commons-lang3", true, true},
		{models.EcosystemCargo, "serde", false, false},
	}
	for _, c := range cases {
		imp, known := Imported(imports, c.eco, c.name)
		if imp != c.imported || known != c.known {
			t.Errorf("%s %s: imported=%v known=%v", c.eco, c.name, imp, known)
		}
	}
	if _, known := Imported(ImportedPackages(map[string][]byte{"a.py": []byte("import x")}), models.EcosystemNpm, "x"); known {
		t.Fatal("no JS source: npm imports must be unknown")
	}
}
