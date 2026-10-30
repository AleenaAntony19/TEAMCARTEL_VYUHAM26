"""Single entry point for the bundled engine (PyInstaller). Lets the VS Code / Antigravity extension run
without a Python install:
  shield-engine scan|fix|bank ...   -> shield.codescan CLI
  shield-engine mcp                 -> MCP stdio server
  shield-engine llm test|explain    -> LLM helper
  shield-engine bandit ...          -> bundled bandit (used by the SAST engine when frozen)
"""
import os
import sys
from pathlib import Path


def _use_bundled_tesseract() -> None:
    """Prefer a tesseract shipped next to the engine (Windows build); else whatever is on PATH."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    exe = base / "tesseract" / ("tesseract.exe" if os.name == "nt" else "tesseract")
    if exe.exists():
        import pytesseract

        pytesseract.pytesseract.tesseract_cmd = str(exe)
        os.environ.setdefault("TESSDATA_PREFIX", str(exe.parent / "tessdata"))


def main() -> int:
    _use_bundled_tesseract()
    args = sys.argv[1:]
    mode = args[0] if args else ""
    if mode == "mcp":
        from shield.mcp.tools import main as mcp_main

        mcp_main()
        return 0
    if mode == "llm":
        from shield.llm import main as llm_main

        return llm_main(args[1:])
    if mode == "bandit":
        from bandit.cli.main import main as bandit_main

        sys.argv = ["bandit", *args[1:]]
        return bandit_main()
    if mode == "--version":
        print("shield-engine 0.4.0")
        return 0
    from shield.codescan.__main__ import main as scan_main

    return scan_main(args)


if __name__ == "__main__":
    raise SystemExit(main())
