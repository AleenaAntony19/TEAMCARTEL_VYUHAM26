# 🤖 SHIELD·SCOUT Agent Catalog & Persona Taxonomy

> **Swarm Architecture Reference**  


---

## 1. Agent Swarm Taxonomy Overview

SHIELD·SCOUT organizes autonomous agents into **6 Specialized Guilds**:
1. **Document Inspection Guild:** Format-specific low-level parsers (PDF, DOCX, XLSX, Images).
2. **Multi-Ideology Deliberation Guild:** Competing analytical personas that debate ambiguous findings and filter noise.
3. **Domain Specialist Guild:** Context-aware recognition of high-risk Indian and global PII.
4. **Adversarial Red-Team Guild:** Internal attackers that verify sanitization integrity.
5. **Critical-Site Scout Guild:** Polite crawlers traversing high-risk dump repositories.
6. **Likeness & Forensic Guild:** On-device biometric matching and Section 63 BSA dossier generation.

---

## 2. Guild 1: Document Inspection Guild

### 1.1 `PdfStreamInspector`
* **Role:** Deep container dissection for PDF files.
* **Ideology:** Structural zero-trust. Assumes visual pages are merely rendering instructions over hidden binary streams.
* **ECC Skills & Capabilities:** PyMuPDF low-level xref table walking, FlateDecode decompression, font subset cache scanning, annotation extraction, embedded file extraction.
* **Input:** Raw `.pdf` file path.
* **Output:** Document layers (`visible`, `annotations`, `embedded`, `metadata`), xref mapping of embedded images.
* **Failure Mode:** On damaged xref tables, attempts incremental repair or escalates to rasterization fallback.

### 1.2 `DocxXmlInspector`
* **Role:** OOXML WordprocessingML structure analyzer.
* **Ideology:** Syntactic deconstruction. Knows that text split across runs (`w:r`) or inside deletion markers (`w:del`) bypasses naive string filters.
* **ECC Skills & Capabilities:** ZIP member traversal, lxml XPath querying, XML namespace handling, paragraph run concatenation.
* **Input:** Raw `.docx` package.
* **Output:** Unified paragraph text with character offset maps back to XML run nodes, comments list, author metadata.
* **Failure Mode:** Reconstructs corrupted XML via lenient lxml parser or reports unrecoverable container error.

### 1.3 `SheetCacheInspector`
* **Role:** Spreadsheet formula and cache analyzer.
* **Ideology:** Calculation cache hunter. Targets evaluated `<v>` caches that survive cell formula clearing.
* **ECC Skills & Capabilities:** openpyxl workbook manipulation, XML worksheet traversal, defined name range extraction, `veryHidden` sheet state unmasking.
* **Input:** Raw `.xlsx` file path.
* **Output:** Cell values, evaluated formula strings, hidden sheet data, cell comment nodes, pivot table cache definitions.

### 1.4 `OcrVisualInspector`
* **Role:** Optical character recognition & visual layout analyzer.
* **Ideology:** Spatial visual grounding. Treats documents as 2D spatial coordinate fields rather than plain text streams.
* **ECC Skills & Capabilities:** Tesseract OCR (PSM 6 line parsing), bounding box clustering, DPI normalization, contrast enhancement.
* **Input:** Rendered PDF pages, standalone `.jpg` / `.png` images.
* **Output:** Word-level token coordinates `(text, (x, y, w, h))` and line-level text clusters.

---

## 3. Guild 2: Multi-Ideology Deliberation Guild

When candidate PII has ambiguous confidence (between 0.40 and 0.75) or when estimating leak severity, these competing personas debate to reach consensus:

### 2.1 `PrivacyHawk` (The Zero-Trust Defender)
* **Persona:** Hyper-vigilant data protection officer.
* **Core Mindset:** *"Any exposed identifier is a catastrophic leak until mathematically disproven."*
* **Responsibilities:**
  - Flags partial identifiers (last 4 digits of account, surname + partial address).
  - Maximizes detection recall; errs on the side of caution.
  - Pushes for maximum redaction bounding boxes (+4px padding).

### 2.2 `PragmaticDev` (The Noise-Filter Specialist)
* **Persona:** Experienced software engineer & developer productivity advocate.
* **Core Mindset:** *"Do not break the business document or flood CI/CD with false positives."*
* **Responsibilities:**
  - Evaluates whether an email is documentation placeholder (`user@example.com`).
  - Checks if a 12-digit number is an invoice ID or serial code rather than an Aadhaar.
  - Protects document layout and readability from unnecessary over-redaction.

### 2.3 `StatutoryAuditor` (The Legal Compliance Officer)
* **Persona:** Indian DPDP Act 2023 & BSA Section 63 regulatory specialist.
* **Core Mindset:** *"Liability is defined strictly by statutory definitions and penal exposure."*
* **Responsibilities:**
  - Enforces mandatory compliance for Indian Critical PII (Aadhaar under UIDAI regulations, PAN under Income Tax Act).
  - Calculates linkage exposure (e.g., PAN alone = Medium 75; PAN + Name + DOB = Critical 95).
  - Ensures transformation audit trails satisfy Section 63 BSA evidentiary requirements.

### 2.4 `SwarmAdjudicator` (The Consensus Chief)
* **Persona:** Impartial judicial arbitrator.
* **Core Mindset:** *"Balanced, deterministic synthesis based on evidence, checksums, and context."*
* **Responsibilities:**
  - Moderates inter-agent debate rounds (capped at 2 rounds).
  - Weighs checksum evidence (e.g., Verhoeff valid $\rightarrow$ overrules PragmaticDev; Verhoeff invalid $\rightarrow$ overrules PrivacyHawk).
  - Emits the definitive entity coordinates map to the redaction engine.

---

## 4. Guild 3: Domain Specialist Guild

### 3.1 `IndiaKycSpecialist`
* **Focus:** Indian sovereign and commercial identity credentials.
* **Capabilities:**
  - `IN_AADHAAR`: 12-digit regex with mathematical Verhoeff dihedral $D_5$ group checksum verification.
  - `IN_PAN`: 10-character alphanumeric syntax (`[A-Z]{5}[0-9]{4}[A-Z]`).
  - `IN_UPI`: Virtual Payment Address matching against all authorized Indian PSP handles (`@okaxis`, `@oksbi`, `@paytm`, etc.).
  - `IN_IFSC`: RBI bank branch routing codes (`[A-Z]{4}0[A-Z0-9]{6}`).
  - `IN_BANK_ACCOUNT`: 9–18 digit sequences requiring financial keyword context (`a/c`, `account`, `bank`).

### 3.2 `FinSecSpecialist`
* **Focus:** Commercial financial and payment credentials.
* **Capabilities:**
  - Credit and debit card numbers with Luhn MOD-10 checksum validation.
  - Salary, compensation, tax withholding, and payroll ledger structures.

### 3.3 `HealthSpecialist`
* **Focus:** Protected Health Information (PHI).
* **Capabilities:**
  - Diagnosis codes, prescription details, hospital admission numbers, patient biometric identifiers.

---

## 5. Guild 4: Adversarial Red-Team Guild

### 5.1 `TextExtractionAttacker`
* **Role:** Simulates external adversaries running automated OCR or text scraping on exported files.
* **Attack Method:** Uses independent CLI binaries (`pdftotext -layout`, clean Tesseract OCR) to extract text and matches against original unredacted values and regex variants.

### 5.2 `BinaryGrepAttacker`
* **Role:** Simulates deep forensic analysts inspecting file streams with hex viewers.
* **Attack Method:** Decompresses all container streams (deflated PDF objects, zipped XML members) into contiguous memory and performs byte-level string search.

### 5.3 `MetadataAuditor`
* **Role:** Inspects document headers for residual leak channels.
* **Attack Method:** Parses PDF `/Info` dictionaries, XMP metadata trees, Word `docProps/core.xml` creator tags, image EXIF/GPS tags, and embedded attachment tables.

---

## 6. Guild 5: Critical-Site Scout Guild

### 6.1 `DefaultCrawler`
* **Target Sites:** Standard static paste repositories and image boards.
* **Strategy:** Extracts `<img>` tags (`src`, `data-src`, `srcset`) and shallow internal hyperlinks.

### 6.2 `GalleryCrawler`
* **Target Sites:** Dynamic image galleries with infinite scroll.
* **Strategy:** Launches headless Chromium via Playwright, scrolls virtual DOM incrementally (up to 15 scrolls), waits for network idle, and extracts lazy-loaded image URLs.

### 6.3 `ForumThreadCrawler`
* **Target Sites:** Multi-page thread dump sites.
* **Strategy:** Follows pagination links (`rel=next`, `Next »`, `page=N+1`), extracts media references, caps depth to 10 pages per thread.

### 6.4 `ScraperMirrorCrawler`
* **Target Sites:** Directory mirrors and cards.
* **Strategy:** Extracts media cards strictly without recording user names or personal bio descriptions to preserve privacy.

---

## 7. Guild 6: Likeness & Forensic Guild

### 7.1 `PdqMatcher`
* **Engine:** Meta 256-bit Dihedral Perceptual Hash (PDQ v2).
* **Operation:** Hashes candidates across dihedral rotations (90°, 180°, 270°, flip) and multi-region crops (full, 80%, 60%, face crop). Matches via Hamming bitwise distance ($\le 31$ Strong, $32–45$ Marginal).

### 7.2 `FaceMatcher`
* **Engine:** OpenCV `FaceDetectorYN` (YuNet) + `FaceRecognizerSF` (SFace).
* **Operation:** Detects faces ($\ge 40\text{px}$), extracts 128-d float embeddings, quantizes to 128-byte int8 arrays, and calculates cosine similarity against enrolled victim vector ($\ge 0.363$ match threshold).

### 7.3 `QueryFirewall`
* **Safety Role:** Intercepts every outgoing search query. Wipes raw PII variants; permits only high-level organizational, location, or date context to prevent leak broadcast via query logs.

### 7.4 `EvidenceAgent`
* **Legal Role:** Captures full-page DOM-blurred screenshots, HAR network traces (omitting image bodies), RDAP abuse emails, CDN signatures, and Section 63 BSA certificate bundles.

