// Package skills embeds the agent skills shipped with depguard (served by the
// API at /agent/SKILL.md and installed by `depguard setup agents`).
package skills

import _ "embed"

// Depguard is skills/depguard/SKILL.md.
//
//go:embed depguard/SKILL.md
var Depguard string

// InstallScript is skills/install.sh; __API_URL__ is replaced with the API's public URL.
//
//go:embed install.sh
var InstallScript string
