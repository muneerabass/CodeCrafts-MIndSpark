"""Builds platform wheels for the depguard CLI (depguard-cli on PyPI or a --find-links index).

Usage: python3 pypi_build.py <version> <dist/cli dir> <out dir>
Each wheel holds one prebuilt binary and a tiny launcher (console script `depguard`).
"""
import base64, hashlib, os, sys, zipfile

PLATFORMS = {  # binary suffix -> wheel platform tag
    "linux-amd64": "manylinux2014_x86_64.musllinux_1_1_x86_64",
    "linux-arm64": "manylinux2014_aarch64.musllinux_1_1_aarch64",
    "darwin-amd64": "macosx_10_12_x86_64",
    "darwin-arm64": "macosx_11_0_arm64",
    "windows-amd64": "win_amd64",
    "windows-arm64": "win_arm64",
}

LAUNCHER = '''"""depguard CLI launcher: runs the bundled binary."""
import os, subprocess, sys

def main():
    exe = "depguard.exe" if os.name == "nt" else "depguard"
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bin", exe)
    if os.name != "nt":
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        os.execv(path, [path] + sys.argv[1:])
    sys.exit(subprocess.call([path] + sys.argv[1:]))
'''


def record_line(name, data):
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"{name},sha256={digest},{len(data)}"


def build(version, cli_dir, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    dist_info = f"depguard_cli-{version}.dist-info"
    for suffix, tag in PLATFORMS.items():
        exe = "depguard.exe" if suffix.startswith("windows") else "depguard"
        src = os.path.join(cli_dir, f"depguard-{suffix}" + (".exe" if exe.endswith(".exe") else ""))
        if not os.path.exists(src):
            continue
        binary = open(src, "rb").read()
        files = {
            "depguard_cli/__init__.py": LAUNCHER.encode(),
            "depguard_cli/__main__.py": b"from depguard_cli import main\nmain()\n",
            f"depguard_cli/bin/{exe}": binary,
            f"{dist_info}/METADATA": (
                "Metadata-Version: 2.1\nName: depguard-cli\nVersion: " + version + "\n"
                "Summary: depguard CLI: check package installs against your team's supply chain policy\n"
                "Requires-Python: >=3.8\n").encode(),
            f"{dist_info}/WHEEL": f"Wheel-Version: 1.0\nGenerator: depguard\nRoot-Is-Purelib: false\nTag: py3-none-{tag}\n".encode(),
            f"{dist_info}/entry_points.txt": b"[console_scripts]\ndepguard = depguard_cli:main\n",
        }
        wheel = os.path.join(out_dir, f"depguard_cli-{version}-py3-none-{tag}.whl")
        records = []
        with zipfile.ZipFile(wheel, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in files.items():
                info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
                info.external_attr = (0o755 if name.endswith(("/depguard", ".exe")) else 0o644) << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, data)
                records.append(record_line(name, data))
            records.append(f"{dist_info}/RECORD,,")
            z.writestr(f"{dist_info}/RECORD", "\n".join(records) + "\n")
        print("wheel", os.path.basename(wheel))
    # A simple index page so `pip install --find-links <url>` works over HTTP.
    links = "".join(f'<a href="{f}">{f}</a><br>\n' for f in sorted(os.listdir(out_dir)) if f.endswith(".whl"))
    open(os.path.join(out_dir, "index.html"), "w").write(f"<!doctype html><title>depguard-cli</title>\n{links}")


if __name__ == "__main__":
    build(*sys.argv[1:4])
