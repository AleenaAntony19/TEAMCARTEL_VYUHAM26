# Shield·Code (VS Code)

Scans the open workspace with the local Shield·Scout engine and shows findings in **Problems** (inline diagnostics) and the **Shield·Code → Findings** view.

## Install (no Python needed)
Get the `.vsix` built for your OS (see the main README) and run **Extensions: Install from VSIX…**. The build bundles the scanner engine, so nobody needs Python. OCR needs Tesseract: the Windows build includes it; on macOS/Linux install it (`brew install tesseract` / `apt install tesseract-ocr`), or OCR is reported as unavailable while everything else works.

**Developers** (no bundled engine): set `shieldCode.pythonPath` to a Python 3.11 with `requirements.txt`, and `shieldCode.enginePath` to the `shield_scout` folder. On Windows, leaving `pythonPath` empty uses the `py -3` launcher.

## Use
- **Shield: Scan Workspace** (also the shield icon in the view title, or the status bar). Shows progress and can be cancelled; files are found dynamically (git-tracked + untracked-not-ignored, or a directory walk), honouring `shieldCode.exclude`, size limits and always-skipped folders (`node_modules`, `.git`, venvs, `dist`…).
- Analyzers run in parallel up to `shieldCode.concurrency`, bounded by `shieldCode.timeoutSeconds`. Engines that time out or fail, OCR availability and per-file errors appear under **Scan problems** and in **Shield: Show Log**.
- After a first scan, saving a file re-scans just that file (secrets/PII/media/document engines).
- **Quick fixes** (lightbulb on a diagnostic): each opens a **diff preview**, then a modal listing every file change and note; nothing changes until you press **Apply**. Text edits are applied by the engine on disk and can be undone with git. Binary changes (image redaction) keep the original in `.shield/backup/` (git-ignored). Secret fixes always say *rotate the key*: moving a committed secret does not un-leak it.
- **Image findings** show the OCR bounding box (`x y w h`). A PDQ fingerprint/near-duplicate finding is for matching only; it does not sanitize anything.
- **AI Provider** panel: choose None / Groq / Anthropic Claude, paste a key (stored in VS Code Secret Storage, never in settings), **Test**. "Explain with AI" sends only rule, engine, severity and masked evidence.
- **Shield: Export SARIF Report** for CI / code-scanning upload.

## Development
`npm run typecheck`, `npm test` (pure helpers, `node --test`), `npm run build`, `npm run package`. The extension was not exercised inside a live VS Code instance by the automated checks; see the main README for what is tested.
