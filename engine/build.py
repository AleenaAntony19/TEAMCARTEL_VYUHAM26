"""Build the standalone engine: python engine/build.py  ->  dist/shield-engine/ (one folder, no Python needed).

CI runs this on each OS. Set SHIELD_TESSERACT_DIR to a folder holding tesseract(.exe) + tessdata to bundle OCR.
"""
import os
import shutil
import sys
from pathlib import Path

import PyInstaller.__main__

ROOT = Path(__file__).resolve().parent.parent
sep = os.pathsep
args = [
    str(ROOT / "engine" / "shield_engine.py"),
    "--name", "shield-engine",
    "--onedir", "--noconfirm", "--clean",
    "--distpath", str(ROOT / "dist"),
    "--workpath", str(ROOT / "build" / "pyinstaller"),
    "--specpath", str(ROOT / "build"),
    "--paths", str(ROOT),
    # plugins / entry points loaded dynamically; shield's own (even lazy) imports are followed automatically
    "--collect-submodules", "detect_secrets",
    "--collect-all", "bandit",
    "--copy-metadata", "bandit",
    "--copy-metadata", "stevedore",
    "--exclude-module", "mcp.cli",
    "--collect-submodules", "pydantic",
    "--exclude-module", "shield.api",  # HTTP server is not part of the editor engine
    "--exclude-module", "fastapi",
    "--exclude-module", "uvicorn",
    "--exclude-module", "torch",
    "--exclude-module", "streamlit",
    "--exclude-module", "spacy",
    "--exclude-module", "presidio_analyzer",
    "--exclude-module", "playwright",
    "--exclude-module", "tkinter",
    "--exclude-module", "matplotlib",
]
models = ROOT / "models"
if any(models.glob("*.onnx")):
    args += ["--add-data", f"{models}{sep}models"]  # YuNet/SFace: shield.models.BASE resolves to the bundle root
tess = os.getenv("SHIELD_TESSERACT_DIR")
if tess:
    args += ["--add-data", f"{tess}{sep}tesseract"]
PyInstaller.__main__.run(args)
out = ROOT / "dist" / "shield-engine"


def _fix_macos_openssl(bundle: Path) -> None:
    """opencv's wheel ships an older libcrypto; PyInstaller de-duplicates by file name and points Python's _ssl
    at it (ImportError: Symbol not found _X509_STORE_get1_objects). Use the OpenSSL _ssl was linked against."""
    import _ssl
    import subprocess

    linked = subprocess.run(["otool", "-L", _ssl.__file__], capture_output=True, text=True, check=True).stdout
    for line in linked.splitlines():
        lib = Path(line.strip().split(" (")[0])
        if lib.name in {"libssl.3.dylib", "libcrypto.3.dylib"} and lib.exists():
            dst = bundle / "_internal" / lib.name
            if dst.is_symlink() or dst.exists():
                dst.unlink()
            shutil.copy2(lib.resolve(), dst)
            dst.chmod(0o755)
            subprocess.run(["codesign", "--force", "-s", "-", str(dst)], check=True, capture_output=True)


if sys.platform == "darwin":
    _fix_macos_openssl(out)
print(f"built {out} ({sum(f.stat().st_size for f in out.rglob('*') if f.is_file()) / 1e6:.0f} MB)")
shutil.rmtree(ROOT / "build", ignore_errors=True)
sys.exit(0)
