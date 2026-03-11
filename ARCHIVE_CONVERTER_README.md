# Archive Converter - Production-Grade Directory to ZIP Archiver

A robust, production-grade Python utility that safely converts directories into ZIP archives with comprehensive fault tolerance, integrity validation, and deep content analysis.

## Overview

Archive Converter is designed to handle complex archiving scenarios where reliability is critical:
- **Corrupted filesystems** and permission issues
- **Massive directories** with thousands of files
- **Unpredictable I/O conditions** (locked files, concurrent modifications)
- **Deep content analysis** (entropy detection, duplicate detection, suspicious file identification)

The tool implements an **8-phase pipeline** with atomic operations, comprehensive logging, and detailed reports.

## Key Features

✅ **Phase-Based Pipeline Architecture**
- Phase 1: Filesystem Discovery (with cycle detection)
- Phase 2: Integrity Validation Scan
- Phase 3: Scan Report Generation
- Phase 4: User Decision Gate
- Phase 5: Safe Compression Engine
- Phase 6: Archive Integrity Validation
- Phase 7: Atomic Finalization
- Phase 8: Final Execution Report

✅ **Advanced File Validation**
- Permission verification
- Read access testing
- Symlink validation (broken link detection)
- Concurrent modification detection
- Locked file detection
- Metadata consistency checks
- File status classification (VALID, UNREADABLE, PERMISSION_DENIED, BROKEN_SYMLINK, etc.)

✅ **Deep Content Analysis**
- Shannon entropy calculation for compression potential estimation
- File classification by extension and MIME type
- Largest files identification
- Duplicate file detection via SHA-256 hashing
- Suspicious file flagging (executable patterns, keyword detection)
- High-entropy file discovery (encrypted/pre-compressed content)

✅ **Robust Error Handling**
- Recursive retry logic with exponential backoff
- Safe file addition with metadata validation
- Archive integrity verification via CRC checks
- Atomic finalization (rename-based atomicity)
- Comprehensive logging to file and console

✅ **Flexible Policy Controls**
- Include/exclude patterns (glob-style matching)
- Suspicious file thresholds with gating
- Configurable parallel hashing for large files
- Optional JSON analysis reports

✅ **Progress Tracking**
- Real-time ETA countdown estimation
- Progress bars for discovery and compression
- Detailed process timing

## Installation

### Requirements
- Python 3.8+
- Dependencies: `tqdm` (for progress bars)

### Setup

```bash
# Clone or download the repository
cd archive-converter

# (Optional) Create a virtual environment
python -m venv venv
source venv/Scripts/activate  # Windows
# or
source venv/bin/activate      # Linux/macOS

# Install dependencies
pip install tqdm
```

## Usage

### Basic Command-Line Usage

```bash
python archive_converter.py /path/to/source/directory /path/to/destination/folder
```

**Interactive Mode** (if no arguments provided):
```bash
python archive_converter.py
# Then enter source directory and destination folder paths when prompted
```

### Example

```bash
# Archive a project folder
python archive_converter.py "C:\Users\John\Projects\my_app" "D:\Backups\"

# This creates: D:\Backups\my_app.zip
#         and: D:\Backups\my_app.analysis.json
```

## Configuration via Environment Variables

Control archiver behavior without modifying code:

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `ARCHIVER_INCLUDE_PATTERNS` | CSV | (none) | Glob patterns to include (e.g., `*.py;*.txt`) |
| `ARCHIVER_EXCLUDE_PATTERNS` | CSV | `**/__pycache__/**;**/.git/**;**/.venv/**;**/*.tmp` | Glob patterns to exclude |
| `ARCHIVER_FAIL_ON_SUSPICIOUS` | bool | `0` | Fail if suspicious files exceed limit |
| `ARCHIVER_SUSPICIOUS_LIMIT` | int | `0` | Max suspicious files allowed (0 = no limit) |
| `ARCHIVER_WRITE_JSON_REPORT` | bool | `1` | Generate JSON analysis report |
| `ARCHIVER_HASH_WORKERS` | int | Auto (2-8) | Parallel workers for SHA-256 hashing |
| `ARCHIVER_HASH_MAX_MB` | int | `1024` | Max file size (MB) for hashing |

### Configuration Examples

```bash
# Windows - Only archive Python files
set ARCHIVER_INCLUDE_PATTERNS=*.py
python archive_converter.py C:\source C:\dest

# Exclude node_modules and build artifacts
set ARCHIVER_EXCLUDE_PATTERNS=**/node_modules/**;**/build/**;**/.venv/**
python archive_converter.py C:\source C:\dest

# Fail if more than 5 suspicious files detected
set ARCHIVER_FAIL_ON_SUSPICIOUS=1
set ARCHIVER_SUSPICIOUS_LIMIT=5
python archive_converter.py C:\source C:\dest
```

## Output Files

### Main Archive
- **`<foldername>.zip`** — Compressed archive file containing all valid files

### Analysis Report
- **`<foldername>.analysis.json`** — Machine-readable analysis data:
  - File counts (discovered, scanned, valid, etc.)
  - Extension and MIME type distributions
  - Largest files
  - High-entropy files (potential encryption/compression)
  - Duplicate file groups
  - Suspicious files
  - Archive statistics

### Logs
- **`archive_converter.log`** — Detailed execution log with timestamps

## Core Classes

### DirectoryArchiver
Main orchestration class managing the 8-phase pipeline.

**Key Methods:**
- `discover_filesystem()` — Phase 1: Traverse directory tree safely
- `perform_integrity_scan()` — Phase 2: Validate all discovered files
- `generate_scan_report()` — Phase 3: Create human-readable summary
- `user_decision_gate()` — Phase 4: Prompt user to continue/abort
- `safe_compression_engine()` — Phase 5-7: Compress with validation
- `generate_final_report()` — Phase 8: Summary statistics
- `run()` — Execute complete pipeline

### Data Classes

**FileInfo**
Represents a single discovered file with metadata and status.

```python
@dataclass
class FileInfo:
    path: Path
    size: Optional[int]
    mtime: Optional[float]
    is_symlink: bool
    is_dir: bool
    status: FileStatus  # VALID, UNREADABLE, PERMISSION_DENIED, etc.
    error_message: Optional[str]
    hash_value: Optional[str]  # SHA-256 digest
```

**ScanReport**
Aggregated statistics from Phase 2 scan.

```python
@dataclass
class ScanReport:
    total_discovered: int
    total_scanned: int
    valid_files: int
    unreadable_files: int
    permission_errors: int
    broken_symlinks: int
    read_failures: int
    # ... more counters
    issues: List[str]  # Detailed issues found
```

**DeepAnalysisReport**
Rich analytics generated from file content sampling.

```python
@dataclass
class DeepAnalysisReport:
    total_bytes_scanned: int
    extension_counts: Dict[str, int]
    mime_type_counts: Dict[str, int]
    largest_files: List[Tuple[str, int]]
    high_entropy_files: List[Tuple[str, float]]
    duplicate_file_groups: List[List[str]]
    suspicious_files: List[str]
    avg_entropy: float
    estimated_compression_potential_percent: float
```

**ArchiverPolicy**
Runtime configuration controls.

```python
@dataclass
class ArchiverPolicy:
    include_patterns: List[str]
    exclude_patterns: List[str]
    fail_on_suspicious: bool
    suspicious_limit: int
    write_json_report: bool
    hash_parallel_workers: int
    hash_max_file_size_mb: int
```

## File Status Types

| Status | Meaning | Archived? |
|--------|---------|-----------|
| `VALID` | File passed all validations | ✅ Yes |
| `UNREADABLE` | Cannot access file | ❌ No |
| `PERMISSION_DENIED` | Access permission blocked | ❌ No |
| `BROKEN_SYMLINK` | Symlink target doesn't exist | ❌ No |
| `METADATA_MISMATCH` | Stat/metadata inconsistency | ❌ No |
| `CONCURRENT_MODIFICATION` | File changed during scan | ❌ No |
| `READ_FAILURE` | I/O error when reading | ❌ No |
| `LOCKED_FILE` | File locked by another process | ❌ No |
| `SKIPPED_BY_POLICY` | Excluded by include/exclude rules | ❌ No |

## Advanced Features

### Entropy Analysis
The tool calculates Shannon entropy for file samples to:
- Estimate compression potential (low entropy = highly compressible)
- Detect encrypted or pre-compressed files (high entropy ≥ 7.5 bits/byte)
- Profile archive contents

**Entropy Interpretation:**
- `0.0-3.0` — Highly repetitive content (very compressible)
- `3.0-7.0` — Normal text/document content
- `7.0-8.0` — Near-random data (likely encrypted/compressed)

### Duplicate Detection
Files are hashed (SHA-256) to identify duplicates:
- Reduces archiving needs
- Identifies redundant files
- Configurable parallel processing

### Suspicious File Detection
Flags potentially risky files based on:
- **Executable patterns:** `.exe`, `.dll`, `.jar`, `.scr`, `.msi`, `.ps1`, `.bat`, `.cmd`
- **Keyword patterns:** "password", "credential", "secret", "token", "key", "wallet", "backup", "private"

Can fail pipeline if suspicious file count exceeds limit.

## Example Output

### Scan Report
```
SCAN REPORT
===========

Total files discovered: 1,245
Total files scanned: 1,245
Valid files: 1,200
Permission errors: 25
Broken symlinks: 3
Read failures: 17
...
Average entropy: 5.234 bits/byte
Estimated compression potential: 65.43%
Suspicious files flagged: 2
```

### Final Report
```
FINAL EXECUTION REPORT
======================

Archive path: /dest/my_app.zip
Total files processed: 1,200
Files archived: 1,195
Files skipped: 5
Total data archived: 2,547,891,234 bytes
Compression duration: 45.67 seconds
Integrity verification: PASSED

Compression ratio: 42.15%
Average compression speed: 55.82 MB/s
```

## Error Handling Strategy

1. **Discovery Phase:** Cyclic reference detection, permission graceful handling
2. **Validation Phase:** Multi-point checks (existence, permissions, read access, metadata, locks)
3. **Compression Phase:** Retry logic (up to 3 attempts) with exponential backoff
4. **Finalization:** CRC-based archive validation before atomic rename

## Performance Considerations

- **Large Directories:** Uses generator-based traversal to minimize memory
- **Parallel Hashing:** Configurable worker threads for efficient hash computation
- **Progress Tracking:** Real-time ETA countdown with minimal overhead
- **Atomic Operations:** Temp file + rename prevents partial/corrupted archives

## Logging

Logs are written to `archive_converter.log` and console:

```
2025-03-11 14:32:15,234 - INFO - Starting directory archiving process
2025-03-11 14:32:15,245 - INFO - Phase 1: Starting filesystem discovery
2025-03-11 14:32:18,123 - INFO - Phase 2: Starting integrity validation scan
...
```

## Troubleshooting

### Archive already exists
The tool will prompt before overwriting. You can type 'y' to confirm overwrite.

### Permission denied errors
Ensure your script has read access to the source directory. On Windows, run as Administrator if needed.

### Out of memory with large directories
The tool uses generators to minimize memory impact, but JSON report generation stores all data. Disable with `ARCHIVER_WRITE_JSON_REPORT=0`.

### Slow compression
Increase parallel workers: `ARCHIVER_HASH_WORKERS=16` (if system has available CPU cores).

## License

This tool is provided as-is for production use.

## Contributing

Contributions welcome! Key areas:
- Additional file validation strategies
- Improved entropy-based compression potential modeling
- Alternative archive formats (7z, tar.gz, rar)
- Incremental archiving support
- Cloud storage integration

---

**Created:** March 2025  
**Python Version:** 3.8+  
**Status:** Production-ready
