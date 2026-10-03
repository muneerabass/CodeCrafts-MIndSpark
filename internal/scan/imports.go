package scan

import (
	"path"
	"regexp"
	"strings"

	"github.com/safedep/vet/pkg/models"
)

// Import keys are "<lang>:<name>"; "lang:<lang>" marks that source of that
// language was seen, so "not imported" can be told apart from "unknown".
var (
	jsImport = regexp.MustCompile(`(?:\bfrom\s*|\bimport\s*|\bimport\s*\(\s*|\brequire\s*\(\s*)['"]([^'"\n]+)['"]`)
	pyImport = regexp.MustCompile(`(?m)^[ \t]*import[ \t]+([\w., \t]+)`)
	pyFrom   = regexp.MustCompile(`(?m)^[ \t]*from[ \t]+([\w.]+)[ \t]+import\b`)
	goBlock  = regexp.MustCompile(`(?s)\bimport\s*\((.*?)\)`)
	goSingle = regexp.MustCompile(`(?m)^\s*import\s+(?:[\w.]+\s+)?"([^"]+)"`)
	quoted   = regexp.MustCompile(`"([^"]+)"`)
	javaImp  = regexp.MustCompile(`(?m)^\s*import\s+(?:static\s+)?([\w.]+?)(?:\.\*)?\s*;`)
)

var langByExt = map[string]string{
	".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js",
	".py": "py", ".go": "go", ".java": "java",
}

// ImportedPackages returns the packages/modules imported by source files
// (path → content), keyed "<lang>:<name>". Use Imported to ask about a dep.
func ImportedPackages(files map[string][]byte) map[string]bool {
	out := map[string]bool{}
	for p, data := range files {
		lang := langByExt[path.Ext(p)]
		if lang == "" {
			continue
		}
		out["lang:"+lang] = true
		src := string(data)
		switch lang {
		case "js":
			for _, m := range jsImport.FindAllStringSubmatch(src, -1) {
				if n := jsPackage(m[1]); n != "" {
					out["js:"+n] = true
				}
			}
		case "py":
			var mods []string
			for _, m := range pyImport.FindAllStringSubmatch(src, -1) {
				for _, part := range strings.Split(m[1], ",") {
					if f := strings.Fields(part); len(f) > 0 {
						mods = append(mods, f[0])
					}
				}
			}
			for _, m := range pyFrom.FindAllStringSubmatch(src, -1) {
				mods = append(mods, m[1])
			}
			for _, mod := range mods {
				// Every dotted prefix: "google.protobuf.message" → google, google.protobuf, …
				for i, seg := 0, strings.Split(mod, "."); i < len(seg) && seg[0] != ""; i++ {
					out["py:"+strings.ToLower(strings.Join(seg[:i+1], "."))] = true
				}
			}
		case "go":
			for _, b := range goBlock.FindAllStringSubmatch(src, -1) {
				for _, q := range quoted.FindAllStringSubmatch(b[1], -1) {
					out["go:"+q[1]] = true
				}
			}
			for _, m := range goSingle.FindAllStringSubmatch(src, -1) {
				out["go:"+m[1]] = true
			}
		case "java":
			for _, m := range javaImp.FindAllStringSubmatch(src, -1) {
				out["java:"+m[1]] = true
			}
		}
	}
	return out
}

// jsPackage maps an import specifier to its npm package ("" for relative
// paths, URLs and node: builtins): "@a/b/c" → "@a/b", "lodash/fp" → "lodash".
func jsPackage(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") || strings.Contains(spec, ":") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) < 2 {
			return ""
		}
		return parts[0] + "/" + parts[1]
	}
	return parts[0]
}

// pyModules maps PyPI distributions to the module they install when the
// names differ (normalized dist name → module).
var pyModules = map[string][]string{
	"pyyaml": {"yaml"}, "beautifulsoup4": {"bs4"}, "scikit-learn": {"sklearn"}, "pillow": {"pil"},
	"python-dateutil": {"dateutil"}, "opencv-python": {"cv2"}, "opencv-python-headless": {"cv2"},
	"opencv-contrib-python": {"cv2"}, "protobuf": {"google.protobuf"}, "google-api-python-client": {"googleapiclient"},
	"google-cloud-storage": {"google.cloud.storage"}, "google-cloud-bigquery": {"google.cloud.bigquery"},
	"google-auth": {"google.auth"}, "grpcio": {"grpc"}, "pymongo": {"pymongo", "bson", "gridfs"},
	"psycopg2-binary": {"psycopg2"}, "psycopg2": {"psycopg2"}, "psycopg": {"psycopg"}, "mysqlclient": {"mysqldb"},
	"pymysql": {"pymysql"}, "python-dotenv": {"dotenv"}, "python-jose": {"jose"}, "pyjwt": {"jwt"},
	"python-multipart": {"multipart"}, "attrs": {"attr", "attrs"}, "msgpack-python": {"msgpack"},
	"pycryptodome": {"crypto"}, "pycryptodomex": {"cryptodome"}, "pyopenssl": {"openssl"}, "dnspython": {"dns"},
	"python-magic": {"magic"}, "pyserial": {"serial"}, "pyzmq": {"zmq"}, "pygithub": {"github"},
	"python-slugify": {"slugify"}, "faiss-cpu": {"faiss"}, "faiss-gpu": {"faiss"}, "tensorflow-gpu": {"tensorflow"},
	"typing-extensions": {"typing_extensions"}, "setuptools": {"setuptools", "pkg_resources"},
	"scikit-image": {"skimage"}, "pyinstaller": {"pyinstaller"}, "discord.py": {"discord"}, "discord-py": {"discord"},
	"ruamel.yaml": {"ruamel.yaml"}, "ruamel-yaml": {"ruamel.yaml"}, "websocket-client": {"websocket"},
	"python-socketio": {"socketio"}, "python-engineio": {"engineio"}, "pytest-asyncio": {"pytest_asyncio"},
	"sentence-transformers": {"sentence_transformers"}, "huggingface-hub": {"huggingface_hub"},
	"llama-index": {"llama_index"}, "langchain-community": {"langchain_community"}, "jinja2": {"jinja2"},
	"markupsafe": {"markupsafe"}, "pywin32": {"win32api", "win32con", "pywintypes"}, "ldap3": {"ldap3"},
	"python-ldap": {"ldap"}, "pyasn1": {"pyasn1"}, "email-validator": {"email_validator"},
}

// Imported reports whether depName is imported by source in imports (from
// ImportedPackages). known is false when the ecosystem is unsupported or no
// source of its language was seen.
func Imported(imports map[string]bool, ecosystem, depName string) (imported, known bool) {
	switch ecosystem {
	case models.EcosystemNpm:
		return imports["js:"+depName], imports["lang:js"]
	case models.EcosystemPyPI:
		n := normName(ecosystem, depName)
		mods := pyModules[n]
		if mods == nil {
			mods = []string{strings.ReplaceAll(n, "-", "_"), strings.ReplaceAll(strings.TrimPrefix(n, "python-"), "-", "_")}
		}
		for _, m := range mods {
			if imports["py:"+m] {
				return true, true
			}
		}
		return false, imports["lang:py"]
	case models.EcosystemGo:
		for k := range imports {
			if imp, ok := strings.CutPrefix(k, "go:"); ok && (imp == depName || strings.HasPrefix(imp, depName+"/")) {
				return true, true
			}
		}
		return false, imports["lang:go"]
	case models.EcosystemMaven:
		group, _, _ := strings.Cut(depName, ":")
		for k := range imports {
			if imp, ok := strings.CutPrefix(k, "java:"); ok && group != "" && (imp == group || strings.HasPrefix(imp, group+".")) {
				return true, true
			}
		}
		return false, imports["lang:java"]
	}
	return false, false
}
