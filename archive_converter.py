#!/usr/bin/env python3
"""
Production-Grade Directory to ZIP Archive Converter

This program safely converts a directory into a ZIP archive with maximum reliability,
handling corrupted filesystems, massive directories, and unpredictable I/O conditions.

Architecture:
- Phase 1: Filesystem Discovery
- Phase 2: Integrity Validation Scan
- Phase 3: Scan Report Generation
- Phase 4: User Decision Gate
- Phase 5: Safe Compression Engine
- Phase 6: Archive Integrity Validation
- Phase 7: Atomic Finalization
- Phase 8: Final Execution Report
"""

import os
import sys
import stat
import time
import logging
import zipfile
import json
import fnmatch
from pathlib import Path
from typing import Generator, Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import hashlib
import mimetypes
import math
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from tqdm import tqdm


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('archive_converter.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class FileStatus(Enum):
    """File classification status."""
    VALID = "valid"
    UNREADABLE = "unreadable"
    PERMISSION_DENIED = "permission_denied"
    BROKEN_SYMLINK = "broken_symlink"
    METADATA_MISMATCH = "metadata_mismatch"
    CONCURRENT_MODIFICATION = "concurrent_modification"
    READ_FAILURE = "read_failure"
    LOCKED_FILE = "locked_file"
    SKIPPED_BY_POLICY = "skipped_by_policy"


@dataclass
class FileInfo:
    """Information about a discovered file."""
    path: Path
    size: Optional[int] = None
    mtime: Optional[float] = None
    is_symlink: bool = False
    is_dir: bool = False
    status: FileStatus = FileStatus.VALID
    error_message: Optional[str] = None
    hash_value: Optional[str] = None


@dataclass
class ScanReport:
    """Comprehensive scan report."""
    total_discovered: int = 0
    total_scanned: int = 0
    valid_files: int = 0
    unreadable_files: int = 0
    permission_errors: int = 0
    broken_symlinks: int = 0
    read_failures: int = 0
    zero_byte_files: int = 0
    modified_during_scan: int = 0
    locked_files: int = 0
    policy_skipped: int = 0
    issues: List[str] = field(default_factory=list)


@dataclass
class ArchiveStats:
    """Final archive statistics."""
    archive_path: Path
    total_processed: int = 0
    files_archived: int = 0
    files_skipped: int = 0
    total_data_archived: int = 0
    compression_duration: float = 0.0
    integrity_verified: bool = False


@dataclass
class DeepAnalysisReport:
    """Deep content and structure analytics for scanned files."""
    total_bytes_scanned: int = 0
    extension_counts: Dict[str, int] = field(default_factory=dict)
    mime_type_counts: Dict[str, int] = field(default_factory=dict)
    largest_files: List[Tuple[str, int]] = field(default_factory=list)
    high_entropy_files: List[Tuple[str, float]] = field(default_factory=list)
    duplicate_file_groups: List[List[str]] = field(default_factory=list)
    suspicious_files: List[str] = field(default_factory=list)
    avg_entropy: float = 0.0
    estimated_compression_potential_percent: float = 0.0


@dataclass
class ArchiverPolicy:
    """Runtime policy controls for filtering and risk gates."""
    include_patterns: List[str] = field(default_factory=list)
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "**/__pycache__/**",
        "**/.git/**",
        "**/.venv/**",
        "**/*.tmp",
    ])
    fail_on_suspicious: bool = False
    suspicious_limit: int = 0
    write_json_report: bool = True
    hash_parallel_workers: int = max(2, min(8, (os.cpu_count() or 4)))
    hash_max_file_size_mb: int = 1024


class DirectoryArchiver:
    """Production-grade directory to ZIP archiver."""

    def __init__(
        self,
        source_dir: Path,
        archive_path: Path,
        max_retries: int = 3,
        policy: Optional[ArchiverPolicy] = None,
    ):
        self.source_dir = source_dir.resolve()
        self.archive_path = archive_path.resolve()
        self.max_retries = max_retries
        self.policy = policy or ArchiverPolicy()
        self.scan_report = ScanReport()
        self.archive_stats = ArchiveStats(archive_path)
        self.process_start_time: Optional[float] = None
        self.estimated_total_units: int = 0
        self.completed_units: int = 0
        self._last_countdown_log: float = 0.0
        self.deep_report = DeepAnalysisReport()
        self._extension_counter: Counter[str] = Counter()
        self._mime_counter: Counter[str] = Counter()
        self._size_index: List[Tuple[str, int]] = []
        self._entropy_values: List[float] = []
        self._high_entropy_candidates: List[Tuple[str, float]] = []
        self._suspicious_patterns = {
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.scr', '.msi'
        }
        self._suspicious_names = {
            'password', 'credential', 'secret', 'token', 'key', 'wallet', 'backup', 'private'
        }

    @staticmethod
    def _format_seconds(seconds: float) -> str:
        """Format duration as HH:MM:SS."""
        seconds = max(0, int(seconds))
        hours, remainder = divmod(seconds, 3600)
        minutes, secs = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{secs:02d}"

    def _start_process_countdown(self, estimated_total_units: int):
        """Initialize countdown estimator for full pipeline progress."""
        self.process_start_time = time.time()
        self.estimated_total_units = max(estimated_total_units, 1)
        self.completed_units = 0
        self._last_countdown_log = 0.0
        logger.info("Estimated total process time: calculating...")

    def _tick_process_progress(self, units: int = 1, force_log: bool = False):
        """Advance process progress and periodically log remaining time estimate."""
        if self.process_start_time is None:
            return

        self.completed_units = min(self.completed_units + units, self.estimated_total_units)
        now = time.time()

        # Keep logs readable for large trees and still provide frequent ETA updates.
        if not force_log and (now - self._last_countdown_log) < 2.0:
            return

        elapsed = now - self.process_start_time
        remaining_units = max(self.estimated_total_units - self.completed_units, 0)

        if self.completed_units > 0 and remaining_units > 0:
            avg_unit_time = elapsed / self.completed_units
            eta_seconds = avg_unit_time * remaining_units
            logger.info(
                "Process countdown: ~%s remaining (%s/%s units complete)",
                self._format_seconds(eta_seconds),
                self.completed_units,
                self.estimated_total_units,
            )
        elif remaining_units == 0:
            logger.info("Process countdown: 00:00:00 remaining (complete)")

        self._last_countdown_log = now

    def discover_filesystem(self) -> Generator[FileInfo, None, None]:
        """
        Phase 1: Filesystem Discovery

        Safely traverse the directory tree using generator-based iteration.
        Prevents infinite loops from symlinks and cyclic references.
        """
        logger.info("Phase 1: Starting filesystem discovery")
        visited: Set[Path] = set()

        def _walk_tree(current_path: Path) -> Generator[FileInfo, None, None]:
            try:
                # Check for cycles
                resolved = current_path.resolve()
                if resolved in visited:
                    logger.warning(f"Cyclic reference detected: {current_path}")
                    return
                visited.add(resolved)

                # Get directory contents
                try:
                    entries = list(current_path.iterdir())
                except (PermissionError, OSError) as e:
                    logger.warning(f"Cannot list directory {current_path}: {e}")
                    yield FileInfo(
                        path=current_path,
                        is_dir=True,
                        status=FileStatus.PERMISSION_DENIED,
                        error_message=str(e)
                    )
                    return

                for entry in entries:
                    try:
                        stat_info = entry.lstat()
                        is_symlink = stat.S_ISLNK(stat_info.st_mode)
                        is_dir = stat.S_ISDIR(stat_info.st_mode) and not is_symlink

                        file_info = FileInfo(
                            path=entry,
                            size=stat_info.st_size if not is_symlink else None,
                            mtime=stat_info.st_mtime,
                            is_symlink=is_symlink,
                            is_dir=is_dir
                        )

                        yield file_info

                        # Recurse into directories
                        if is_dir:
                            yield from _walk_tree(entry)

                    except (OSError, IOError) as e:
                        logger.warning(f"Error accessing {entry}: {e}")
                        yield FileInfo(
                            path=entry,
                            status=FileStatus.UNREADABLE,
                            error_message=str(e)
                        )

            except Exception as e:
                logger.error(f"Unexpected error in directory traversal: {e}")
                yield FileInfo(
                    path=current_path,
                    status=FileStatus.UNREADABLE,
                    error_message=str(e)
                )

        yield from _walk_tree(self.source_dir)

    def validate_file_integrity(self, file_info: FileInfo) -> FileInfo:
        """
        Phase 2: Integrity Validation Scan

        Perform comprehensive validation on a single file.
        """
        try:
            # 1. Existence verification
            if not file_info.path.exists():
                file_info.status = FileStatus.UNREADABLE
                file_info.error_message = "File does not exist"
                return file_info

            # 2-3. File type and symlink validation
            if file_info.is_symlink:
                try:
                    file_info.path.resolve()
                except (OSError, RuntimeError):
                    file_info.status = FileStatus.BROKEN_SYMLINK
                    file_info.error_message = "Broken symlink"
                    return file_info

            # Skip directories for further validation
            if file_info.is_dir:
                return file_info

            # 4. Read permission verification
            if not os.access(file_info.path, os.R_OK):
                file_info.status = FileStatus.PERMISSION_DENIED
                file_info.error_message = "Read permission denied"
                return file_info

            # 5. Metadata inspection
            try:
                stat_info = file_info.path.stat()
                current_size = stat_info.st_size
                current_mtime = stat_info.st_mtime

                # Check for concurrent modification
                if file_info.mtime and abs(current_mtime - file_info.mtime) > 1.0:
                    file_info.status = FileStatus.CONCURRENT_MODIFICATION
                    file_info.error_message = "File modified during scan"
                    return file_info

                file_info.size = current_size
                file_info.mtime = current_mtime

            except (OSError, IOError) as e:
                file_info.status = FileStatus.METADATA_MISMATCH
                file_info.error_message = f"Metadata error: {e}"
                return file_info

            # 6. File size validation
            if file_info.size is None or file_info.size < 0:
                file_info.status = FileStatus.METADATA_MISMATCH
                file_info.error_message = "Invalid file size"
                return file_info

            # 7-10. Safe file operations
            try:
                with open(file_info.path, 'rb') as f:
                    # Test read access
                    test_data = f.read(1024)
                    if len(test_data) == 0 and file_info.size > 0:
                        file_info.status = FileStatus.READ_FAILURE
                        file_info.error_message = "Failed to read file data"
                        return file_info

            except (OSError, IOError, PermissionError) as e:
                if "being used by another process" in str(e).lower():
                    file_info.status = FileStatus.LOCKED_FILE
                    file_info.error_message = "File is locked"
                else:
                    file_info.status = FileStatus.READ_FAILURE
                    file_info.error_message = f"Read error: {e}"
                return file_info

            # All validations passed
            file_info.status = FileStatus.VALID
            self._analyze_file_deep(file_info)
            return file_info

        except Exception as e:
            logger.error(f"Unexpected error validating {file_info.path}: {e}")
            file_info.status = FileStatus.UNREADABLE
            file_info.error_message = f"Validation error: {e}"
            return file_info

    @staticmethod
    def _calculate_entropy(sample: bytes) -> float:
        """Calculate Shannon entropy for a byte sample."""
        if not sample:
            return 0.0

        freq = Counter(sample)
        length = len(sample)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def _analyze_file_deep(self, file_info: FileInfo):
        """Build rich analytics from file metadata and sampled content."""
        if file_info.is_dir or file_info.status != FileStatus.VALID:
            return

        path_str = str(file_info.path)
        size = file_info.size or 0
        self.deep_report.total_bytes_scanned += size
        self._size_index.append((path_str, size))

        suffix = file_info.path.suffix.lower() or '<no_ext>'
        self._extension_counter[suffix] += 1

        mime, _ = mimetypes.guess_type(file_info.path.name)
        self._mime_counter[mime or 'application/octet-stream'] += 1

        # Read at most 128KB for entropy/compressibility profiling.
        try:
            with open(file_info.path, 'rb') as f:
                sample = f.read(128 * 1024)
        except (OSError, IOError):
            return

        entropy = self._calculate_entropy(sample)
        self._entropy_values.append(entropy)
        if entropy >= 7.5:
            self._high_entropy_candidates.append((path_str, entropy))

        # Heuristic suspicious signal from extension and filename keywords.
        lower_name = file_info.path.name.lower()
        if suffix in self._suspicious_patterns or any(k in lower_name for k in self._suspicious_names):
            self.deep_report.suspicious_files.append(path_str)

    def finalize_deep_analysis(self):
        """Finalize derived deep analysis metrics after scanning."""
        self.deep_report.extension_counts = dict(self._extension_counter.most_common())
        self.deep_report.mime_type_counts = dict(self._mime_counter.most_common())

        self.deep_report.largest_files = sorted(
            self._size_index,
            key=lambda item: item[1],
            reverse=True,
        )[:10]

        self.deep_report.high_entropy_files = sorted(
            self._high_entropy_candidates,
            key=lambda item: item[1],
            reverse=True,
        )[:10]

        if self._entropy_values:
            self.deep_report.avg_entropy = sum(self._entropy_values) / len(self._entropy_values)

        hash_to_paths: Dict[str, List[str]] = {}
        for file_info in getattr(self, "_validated_files", []):
            if file_info.status == FileStatus.VALID and file_info.hash_value:
                hash_to_paths.setdefault(file_info.hash_value, []).append(str(file_info.path))

        duplicates: List[List[str]] = []
        for paths in hash_to_paths.values():
            if len(paths) > 1:
                duplicates.append(paths)
        self.deep_report.duplicate_file_groups = duplicates[:20]

        # Entropy-driven estimate: lower entropy usually means more compressible.
        # 8.0 bits/byte means essentially random (near non-compressible).
        normalized_entropy = min(max(self.deep_report.avg_entropy / 8.0, 0.0), 1.0)
        self.deep_report.estimated_compression_potential_percent = max(
            0.0,
            (1.0 - normalized_entropy) * 100,
        )

    @staticmethod
    def _compute_file_sha256(path: Path) -> Optional[str]:
        """Compute SHA-256 for a file path."""
        try:
            hasher = hashlib.sha256()
            with open(path, 'rb') as f:
                while chunk := f.read(1024 * 1024):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except (OSError, IOError, PermissionError):
            return None

    def _parallel_hash_files(self, validated_files: List[FileInfo]):
        """Compute file hashes in parallel for deep duplicate analysis."""
        logger.info("Phase 2b: Parallel hash analysis")
        max_size_bytes = self.policy.hash_max_file_size_mb * 1024 * 1024
        hash_targets = [
            f for f in validated_files
            if f.status == FileStatus.VALID and not f.is_dir and (f.size or 0) <= max_size_bytes
        ]

        if not hash_targets:
            return

        with ThreadPoolExecutor(max_workers=self.policy.hash_parallel_workers) as executor:
            future_map = {executor.submit(self._compute_file_sha256, f.path): f for f in hash_targets}
            for future in tqdm(as_completed(future_map), total=len(future_map), desc="Hashing files", unit="file"):
                file_info = future_map[future]
                digest = future.result()
                if digest:
                    file_info.hash_value = digest

    def _matches_policy(self, file_info: FileInfo) -> bool:
        """Evaluate include/exclude policy patterns against a file path."""
        if file_info.is_dir:
            return True

        rel_path = file_info.path.relative_to(self.source_dir).as_posix()

        if self.policy.include_patterns:
            if not any(fnmatch.fnmatch(rel_path, pattern) for pattern in self.policy.include_patterns):
                return False

        if any(fnmatch.fnmatch(rel_path, pattern) for pattern in self.policy.exclude_patterns):
            return False

        return True

    def perform_integrity_scan(self) -> List[FileInfo]:
        """
        Phase 2: Perform integrity validation scan on all discovered files.
        """
        logger.info("Phase 2: Starting integrity validation scan")

        discovered_files = list(self.discover_filesystem())
        self.scan_report.total_discovered = len(discovered_files)

        # Initial estimate: scan work + likely compression work + fixed orchestration steps.
        self._start_process_countdown((len(discovered_files) * 2) + 4)

        validated_files = []
        with tqdm(total=len(discovered_files), desc="Scanning files", unit="file") as pbar:
            for file_info in discovered_files:
                if not self._matches_policy(file_info):
                    file_info.status = FileStatus.SKIPPED_BY_POLICY
                    file_info.error_message = "Skipped by policy rules"
                    validated_files.append(file_info)
                    self._update_scan_report(file_info)
                    self._tick_process_progress()
                    pbar.update(1)
                    continue

                validated = self.validate_file_integrity(file_info)
                validated_files.append(validated)
                self._update_scan_report(validated)
                self._tick_process_progress()
                pbar.update(1)

        self.scan_report.total_scanned = len(validated_files)
        self._parallel_hash_files(validated_files)
        self._validated_files = validated_files
        self.finalize_deep_analysis()
        self._tick_process_progress(force_log=True)
        return validated_files

    def _update_scan_report(self, file_info: FileInfo):
        """Update scan report counters based on file status."""
        if file_info.status == FileStatus.VALID:
            self.scan_report.valid_files += 1
        elif file_info.status == FileStatus.UNREADABLE:
            self.scan_report.unreadable_files += 1
        elif file_info.status == FileStatus.PERMISSION_DENIED:
            self.scan_report.permission_errors += 1
        elif file_info.status == FileStatus.BROKEN_SYMLINK:
            self.scan_report.broken_symlinks += 1
        elif file_info.status == FileStatus.READ_FAILURE:
            self.scan_report.read_failures += 1
        elif file_info.status == FileStatus.CONCURRENT_MODIFICATION:
            self.scan_report.modified_during_scan += 1
        elif file_info.status == FileStatus.LOCKED_FILE:
            self.scan_report.locked_files += 1
        elif file_info.status == FileStatus.SKIPPED_BY_POLICY:
            self.scan_report.policy_skipped += 1

        if file_info.size == 0 and not file_info.is_dir:
            self.scan_report.zero_byte_files += 1

        if file_info.error_message:
            self.scan_report.issues.append(f"{file_info.path}: {file_info.error_message}")

    def generate_scan_report(self) -> str:
        """
        Phase 3: Generate structured diagnostic report.
        """
        logger.info("Phase 3: Generating scan report")

        extension_preview = list(self.deep_report.extension_counts.items())[:10]
        mime_preview = list(self.deep_report.mime_type_counts.items())[:10]
        duplicates_count = sum(len(group) for group in self.deep_report.duplicate_file_groups)

        report = f"""
SCAN REPORT
===========

Total files discovered: {self.scan_report.total_discovered}
Total files scanned: {self.scan_report.total_scanned}
Valid files: {self.scan_report.valid_files}
Unreadable files: {self.scan_report.unreadable_files}
Permission errors: {self.scan_report.permission_errors}
Broken symlinks: {self.scan_report.broken_symlinks}
Read failures: {self.scan_report.read_failures}
Zero-byte files: {self.scan_report.zero_byte_files}
Files modified during scan: {self.scan_report.modified_during_scan}
Locked files: {self.scan_report.locked_files}
Files skipped by policy: {self.scan_report.policy_skipped}
Total bytes scanned: {self.deep_report.total_bytes_scanned:,}
Unique extensions: {len(self.deep_report.extension_counts)}
Unique MIME types: {len(self.deep_report.mime_type_counts)}
Average entropy: {self.deep_report.avg_entropy:.3f} bits/byte
Estimated compression potential (entropy model): {self.deep_report.estimated_compression_potential_percent:.2f}%
Potential duplicate groups: {len(self.deep_report.duplicate_file_groups)}
Files inside duplicate groups: {duplicates_count}
Suspicious files flagged: {len(self.deep_report.suspicious_files)}

TOP EXTENSIONS:
{self._format_count_pairs(extension_preview)}

TOP MIME TYPES:
{self._format_count_pairs(mime_preview)}

ISSUES DETECTED:
"""

        if self.scan_report.issues:
            for issue in self.scan_report.issues[:50]:  # Limit to first 50 issues
                report += f"- {issue}\n"
            if len(self.scan_report.issues) > 50:
                report += f"... and {len(self.scan_report.issues) - 50} more issues\n"
        else:
            report += "No issues detected.\n"

        report += "\nTOP LARGE FILES:\n"
        for path, size in self.deep_report.largest_files:
            report += f"- {path} ({size:,} bytes)\n"

        if self.deep_report.high_entropy_files:
            report += "\nHIGH-ENTROPY FILES (possible pre-compressed/encrypted):\n"
            for path, entropy in self.deep_report.high_entropy_files:
                report += f"- {path} (entropy={entropy:.3f})\n"

        if self.deep_report.duplicate_file_groups:
            report += "\nPOTENTIAL DUPLICATES (by SHA-256):\n"
            for idx, group in enumerate(self.deep_report.duplicate_file_groups[:10], start=1):
                report += f"Group {idx}:\n"
                for p in group:
                    report += f"  - {p}\n"

        if self.deep_report.suspicious_files:
            report += "\nSUSPICIOUS FILE INDICATORS:\n"
            for p in self.deep_report.suspicious_files[:20]:
                report += f"- {p}\n"
            if len(self.deep_report.suspicious_files) > 20:
                report += f"... and {len(self.deep_report.suspicious_files) - 20} more\n"

        return report

    @staticmethod
    def _format_count_pairs(pairs: List[Tuple[str, int]]) -> str:
        """Render key/value counters for reports."""
        if not pairs:
            return "- none"
        return "\n".join(f"- {k}: {v}" for k, v in pairs)

    def get_corrupt_files(self, validated_files: List[FileInfo]) -> List[FileInfo]:
        """
        Return files that were confirmed as problematic during integrity scan.
        Only non-directory entries are considered for deletion.
        """
        corrupt_statuses = {
            FileStatus.UNREADABLE,
            FileStatus.PERMISSION_DENIED,
            FileStatus.BROKEN_SYMLINK,
            FileStatus.METADATA_MISMATCH,
            FileStatus.CONCURRENT_MODIFICATION,
            FileStatus.READ_FAILURE,
            FileStatus.LOCKED_FILE,
        }

        return [
            file_info
            for file_info in validated_files
            if not file_info.is_dir and file_info.status in corrupt_statuses
        ]

    def delete_corrupt_files(self, corrupt_files: List[FileInfo], require_confirmation: bool = True) -> Tuple[int, int]:
        """
        Delete files that were explicitly marked as corrupt.

        Returns a tuple: (deleted_count, failed_count)
        """
        if not corrupt_files:
            logger.info("No corrupt files detected for deletion")
            return 0, 0

        if require_confirmation:
            print(f"Detected {len(corrupt_files)} corrupt file(s).")
            response = input("Delete confirmed corrupt files now? (y/n): ").strip().lower()
            if response not in ['y', 'yes']:
                logger.info("User skipped corrupt file deletion")
                return 0, 0

        deleted_count = 0
        failed_count = 0

        for file_info in corrupt_files:
            path = file_info.path
            try:
                # For broken symlinks, exists() can be False while the symlink still exists.
                if not path.exists() and not path.is_symlink():
                    logger.warning(f"Skipping missing corrupt file: {path}")
                    failed_count += 1
                    continue

                if path.is_dir():
                    logger.warning(f"Skipping directory marked as corrupt: {path}")
                    failed_count += 1
                    continue

                path.unlink()
                deleted_count += 1
                logger.info(f"Deleted corrupt file: {path}")

            except FileNotFoundError:
                logger.warning(f"Corrupt file already missing: {path}")
                failed_count += 1
            except PermissionError as e:
                logger.error(f"Permission denied deleting corrupt file {path}: {e}")
                failed_count += 1
            except OSError as e:
                logger.error(f"Failed to delete corrupt file {path}: {e}")
                failed_count += 1

        logger.info(
            "Corrupt file deletion complete: deleted=%s failed=%s",
            deleted_count,
            failed_count,
        )
        return deleted_count, failed_count

    def user_decision_gate(self, report: str) -> bool:
        """
        Phase 4: User decision gate.

        Returns True to continue, False to abort.
        """
        logger.info("Phase 4: User decision gate")

        if self.policy.fail_on_suspicious and len(self.deep_report.suspicious_files) > self.policy.suspicious_limit:
            logger.error(
                "Policy gate blocked compression: suspicious files=%s limit=%s",
                len(self.deep_report.suspicious_files),
                self.policy.suspicious_limit,
            )
            print(
                "Policy gate blocked compression: "
                f"suspicious files ({len(self.deep_report.suspicious_files)}) exceed limit "
                f"({self.policy.suspicious_limit})."
            )
            return False

        has_issues = (
            self.scan_report.unreadable_files > 0 or
            self.scan_report.permission_errors > 0 or
            self.scan_report.broken_symlinks > 0 or
            self.scan_report.read_failures > 0 or
            self.scan_report.modified_during_scan > 0 or
            self.scan_report.locked_files > 0 or
            self.scan_report.policy_skipped > 0
        )

        if not has_issues:
            logger.info("No issues detected, proceeding with compression")
            return True

        print(report)
        while True:
            response = input("Issues detected. Continue with compression (skipping problematic files)? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                logger.info("User chose to continue")
                return True
            elif response in ['n', 'no']:
                logger.info("User chose to abort")
                return False
            else:
                print("Please enter 'y' or 'n'")

    def safe_compression_engine(self, validated_files: List[FileInfo]) -> Optional[Path]:
        """
        Phase 5: Safe compression engine with atomic operations.
        """
        logger.info("Phase 5: Starting safe compression")

        # Create temporary archive file
        temp_archive = self.archive_path.with_suffix('.tmp')
        start_time = time.time()

        try:
            with zipfile.ZipFile(temp_archive, 'w', zipfile.ZIP_DEFLATED, allowZip64=True) as zf:
                valid_files = [f for f in validated_files if f.status == FileStatus.VALID and not f.is_dir]

                # Refine total estimate once compressible file count is known.
                self.estimated_total_units = max(
                    self.completed_units,
                    self.scan_report.total_discovered + len(valid_files) + 4,
                )

                with tqdm(total=len(valid_files), desc="Compressing files", unit="file") as pbar:
                    for file_info in valid_files:
                        if self._add_file_safely(zf, file_info):
                            self.archive_stats.files_archived += 1
                            self.archive_stats.total_data_archived += file_info.size or 0
                        else:
                            self.archive_stats.files_skipped += 1
                        self._tick_process_progress()
                        pbar.update(1)

            self.archive_stats.compression_duration = time.time() - start_time
            self.archive_stats.total_processed = len(valid_files)

            # Phase 6: Archive integrity validation
            logger.info("Phase 6: Validating archive integrity")
            if self._validate_archive(temp_archive):
                self.archive_stats.integrity_verified = True

                # Phase 7: Atomic finalization
                logger.info("Phase 7: Atomic finalization")
                temp_archive.rename(self.archive_path)
                return self.archive_path
            else:
                logger.error("Archive validation failed")
                temp_archive.unlink()
                return None

        except Exception as e:
            logger.error(f"Compression failed: {e}")
            if temp_archive.exists():
                temp_archive.unlink()
            return None

    def _add_file_safely(self, zf: zipfile.ZipFile, file_info: FileInfo) -> bool:
        """
        Safely add a file to the archive with retries and validation.
        """
        relative_path = file_info.path.relative_to(self.source_dir)

        for attempt in range(self.max_retries + 1):
            try:
                # Recheck existence and permissions
                if not file_info.path.exists() or not os.access(file_info.path, os.R_OK):
                    logger.warning(f"File no longer accessible: {file_info.path}")
                    return False

                # Recheck metadata
                current_stat = file_info.path.stat()
                if (file_info.mtime and abs(current_stat.st_mtime - file_info.mtime) > 1.0) or \
                   (file_info.size and current_stat.st_size != file_info.size):
                    logger.warning(f"File metadata changed: {file_info.path}")
                    return False

                # Add to archive
                zf.write(file_info.path, relative_path)
                return True

            except Exception as e:
                logger.warning(f"Failed to add {file_info.path} (attempt {attempt + 1}/{self.max_retries + 1}): {e}")
                if attempt < self.max_retries:
                    time.sleep(0.1 * (2 ** attempt))  # Exponential backoff
                else:
                    logger.error(f"Failed to add {file_info.path} after {self.max_retries + 1} attempts")
                    return False

        return False

    def _validate_archive(self, archive_path: Path) -> bool:
        """
        Validate archive integrity using ZipFile.testzip().
        """
        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                bad_file = zf.testzip()
                if bad_file:
                    logger.error(f"Archive corruption detected at: {bad_file}")
                    return False

                # Additional validation
                expected_count = self.archive_stats.files_archived
                actual_count = len(zf.filelist)
                if actual_count != expected_count:
                    logger.error(f"File count mismatch: expected {expected_count}, got {actual_count}")
                    return False

                # Verify CRCs
                for info in zf.filelist:
                    with zf.open(info) as f:
                        f.read()  # This will raise if CRC fails

                logger.info("Archive integrity validation passed")
                return True

        except Exception as e:
            logger.error(f"Archive validation failed: {e}")
            return False

    def generate_final_report(self) -> str:
        """
        Phase 8: Generate final execution report.
        """
        logger.info("Phase 8: Generating final report")

        report = f"""
FINAL EXECUTION REPORT
======================

Archive path: {self.archive_stats.archive_path}
Total files processed: {self.archive_stats.total_processed}
Files archived: {self.archive_stats.files_archived}
Files skipped: {self.archive_stats.files_skipped}
Total data archived: {self.archive_stats.total_data_archived:,} bytes
Compression duration: {self.archive_stats.compression_duration:.2f} seconds
Integrity verification: {'PASSED' if self.archive_stats.integrity_verified else 'FAILED'}

Compression ratio: {self._calculate_compression_ratio():.2f}%
Average compression speed: {self._calculate_compression_speed():.2f} MB/s
Deep estimated compression potential: {self.deep_report.estimated_compression_potential_percent:.2f}%
Duplicate groups identified: {len(self.deep_report.duplicate_file_groups)}
Suspicious files flagged: {len(self.deep_report.suspicious_files)}
Policy skipped files: {self.scan_report.policy_skipped}
"""

        return report

    def _calculate_compression_ratio(self) -> float:
        """Calculate compression ratio."""
        if self.archive_stats.total_data_archived == 0:
            return 0.0

        try:
            archive_size = self.archive_path.stat().st_size
            return (1 - archive_size / self.archive_stats.total_data_archived) * 100
        except:
            return 0.0

    def _calculate_compression_speed(self) -> float:
        """Calculate compression speed in MB/s."""
        if self.archive_stats.compression_duration == 0:
            return 0.0

        data_mb = self.archive_stats.total_data_archived / (1024 * 1024)
        return data_mb / self.archive_stats.compression_duration

    def export_json_report(self):
        """Export a machine-readable analysis report beside the archive."""
        if not self.policy.write_json_report:
            return

        output_path = self.archive_path.with_suffix('.analysis.json')
        payload = {
            "source_dir": str(self.source_dir),
            "archive_path": str(self.archive_path),
            "scan": {
                "total_discovered": self.scan_report.total_discovered,
                "total_scanned": self.scan_report.total_scanned,
                "valid_files": self.scan_report.valid_files,
                "unreadable_files": self.scan_report.unreadable_files,
                "permission_errors": self.scan_report.permission_errors,
                "broken_symlinks": self.scan_report.broken_symlinks,
                "read_failures": self.scan_report.read_failures,
                "zero_byte_files": self.scan_report.zero_byte_files,
                "modified_during_scan": self.scan_report.modified_during_scan,
                "locked_files": self.scan_report.locked_files,
                "policy_skipped": self.scan_report.policy_skipped,
            },
            "deep_analysis": {
                "total_bytes_scanned": self.deep_report.total_bytes_scanned,
                "extension_counts": self.deep_report.extension_counts,
                "mime_type_counts": self.deep_report.mime_type_counts,
                "largest_files": self.deep_report.largest_files,
                "high_entropy_files": self.deep_report.high_entropy_files,
                "duplicate_file_groups": self.deep_report.duplicate_file_groups,
                "suspicious_files": self.deep_report.suspicious_files,
                "avg_entropy": self.deep_report.avg_entropy,
                "estimated_compression_potential_percent": self.deep_report.estimated_compression_potential_percent,
            },
            "archive_stats": {
                "total_processed": self.archive_stats.total_processed,
                "files_archived": self.archive_stats.files_archived,
                "files_skipped": self.archive_stats.files_skipped,
                "total_data_archived": self.archive_stats.total_data_archived,
                "compression_duration": self.archive_stats.compression_duration,
                "integrity_verified": self.archive_stats.integrity_verified,
            },
        }

        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2)
            logger.info("JSON analysis report written: %s", output_path)
        except OSError as e:
            logger.error("Failed to write JSON report: %s", e)

    def run(self) -> bool:
        """
        Execute the complete archiving pipeline.
        """
        logger.info("Starting directory archiving process")

        try:
            # Phase 1-2: Discovery and scan
            validated_files = self.perform_integrity_scan()

            # Phase 3: Report generation
            report = self.generate_scan_report()
            self.export_json_report()
            self._tick_process_progress()

            # Phase 4: User decision
            if not self.user_decision_gate(report):
                logger.info("Archiving aborted by user")
                return False
            self._tick_process_progress()

            # Optional cleanup: delete only files already confirmed as corrupt.
            corrupt_files = self.get_corrupt_files(validated_files)
            self.delete_corrupt_files(corrupt_files, require_confirmation=True)
            self._tick_process_progress()

            # Phase 5-7: Compression and validation
            result = self.safe_compression_engine(validated_files)

            if result:
                # Phase 8: Final report
                final_report = self.generate_final_report()
                print(final_report)
                self._tick_process_progress(force_log=True)
                logger.info("Archiving completed successfully")
                return True
            else:
                logger.error("Archiving failed")
                return False

        except Exception as e:
            logger.error(f"Archiving process failed: {e}")
            return False


def main():
    """Main entry point."""
    if len(sys.argv) == 3:
        source_dir = Path(sys.argv[1].strip(' "'))
        dest_folder = Path(sys.argv[2].strip(' "'))
    else:
        print("Production-Grade Directory to ZIP Archive Converter")
        print("-----------------------------------------------")
        source_input = input("Enter source directory path: ").strip().strip(' "')
        if not source_input:
            print("Error: Source directory is required.")
            sys.exit(1)
        source_dir = Path(source_input)
        
        dest_input = input("Enter destination folder path: ").strip().strip(' "')
        if not dest_input:
            print("Error: Destination folder is required.")
            sys.exit(1)
        dest_folder = Path(dest_input)

    if not source_dir.exists():
        print(f"Error: Source directory does not exist: {source_dir}")
        sys.exit(1)

    if not source_dir.is_dir():
        print(f"Error: Source path is not a directory: {source_dir}")
        sys.exit(1)

    if not dest_folder.exists():
        print(f"Error: Destination folder does not exist: {dest_folder}")
        sys.exit(1)

    if not dest_folder.is_dir():
        print(f"Error: Destination path is not a directory: {dest_folder}")
        sys.exit(1)

    # Create archive path as source_folder_name.zip in destination folder
    archive_name = source_dir.name + ".zip"
    archive_path = dest_folder / archive_name

    if archive_path.exists():
        print(f"Warning: Archive file already exists: {archive_path}")
        response = input("Overwrite? (y/n): ").strip().lower()
        if response not in ['y', 'yes']:
            print("Aborted.")
            sys.exit(0)

    include_patterns = [p.strip() for p in os.getenv("ARCHIVER_INCLUDE_PATTERNS", "").split(';') if p.strip()]
    exclude_patterns = [p.strip() for p in os.getenv("ARCHIVER_EXCLUDE_PATTERNS", "").split(';') if p.strip()]
    fail_on_suspicious = os.getenv("ARCHIVER_FAIL_ON_SUSPICIOUS", "0").strip() in {"1", "true", "yes"}
    suspicious_limit = int(os.getenv("ARCHIVER_SUSPICIOUS_LIMIT", "0").strip())
    write_json_report = os.getenv("ARCHIVER_WRITE_JSON_REPORT", "1").strip() in {"1", "true", "yes"}
    hash_workers = int(os.getenv("ARCHIVER_HASH_WORKERS", str(max(2, min(8, (os.cpu_count() or 4))))).strip())
    hash_max_mb = int(os.getenv("ARCHIVER_HASH_MAX_MB", "1024").strip())

    policy = ArchiverPolicy(
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns or ArchiverPolicy().exclude_patterns,
        fail_on_suspicious=fail_on_suspicious,
        suspicious_limit=suspicious_limit,
        write_json_report=write_json_report,
        hash_parallel_workers=max(1, hash_workers),
        hash_max_file_size_mb=max(1, hash_max_mb),
    )

    archiver = DirectoryArchiver(source_dir, archive_path, policy=policy)
    success = archiver.run()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()