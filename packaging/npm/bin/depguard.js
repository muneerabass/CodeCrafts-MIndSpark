#!/usr/bin/env node
// Launcher for the depguard CLI: runs the prebuilt binary for this platform.
'use strict';
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const targets = {
  'linux-x64': 'linux-amd64',
  'linux-arm64': 'linux-arm64',
  'darwin-x64': 'darwin-amd64',
  'darwin-arm64': 'darwin-arm64',
  'win32-x64': 'windows-amd64',
  'win32-arm64': 'windows-arm64',
};
const key = `${process.platform}-${process.arch}`;
const target = targets[key];
if (!target) {
  console.error(`depguard: no prebuilt binary for ${key}; install with: go install github.com/depguard/depguard/cmd/depguard@latest`);
  process.exit(1);
}
const bin = path.join(__dirname, '..', 'vendor', target, process.platform === 'win32' ? 'depguard.exe' : 'depguard');
try {
  fs.chmodSync(bin, 0o755); // npm may drop the executable bit
} catch {}
const r = spawnSync(bin, process.argv.slice(2), { stdio: 'inherit' });
if (r.error) {
  console.error(`depguard: ${r.error.message}`);
  process.exit(1);
}
process.exit(r.status === null ? 1 : r.status);
