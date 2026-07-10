from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath


_SYMBOL_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.$:#<>~-]*$")


def iter_safe_repo_files(repo_root: Path):
    root = repo_root.expanduser().resolve()
    for lexical in root.rglob("*"):
        try:
            relative = lexical.relative_to(root).as_posix()
        except ValueError:
            continue
        resolved = safe_repo_file(root, relative)
        if resolved is not None:
            yield resolved


def safe_repo_file(repo_root: Path, relative_path: str | Path, *, require_exists: bool = True) -> Path | None:
    """Resolve a repository file without following repository-controlled symlinks."""
    root = repo_root.expanduser().resolve()
    raw = str(relative_path)
    if not _safe_relative_text(raw):
        return None
    relative = PurePosixPath(raw.replace("\\", "/"))
    candidate = root.joinpath(*relative.parts)
    if _has_symlink_component(root, candidate):
        return None
    try:
        resolved = candidate.resolve(strict=require_exists)
        resolved.relative_to(root)
    except (OSError, RuntimeError, ValueError):
        return None
    if require_exists and not resolved.is_file():
        return None
    return resolved


def safe_repo_relative(repo_root: Path, path: Path) -> str | None:
    root = repo_root.expanduser().resolve()
    try:
        lexical = path if path.is_absolute() else root / path
        relative = lexical.relative_to(root)
    except ValueError:
        return None
    resolved = safe_repo_file(root, relative.as_posix())
    if resolved is None:
        return None
    return relative.as_posix()


def normalize_repo_target(repo_root: Path, target: str, *, require_exists: bool = True) -> str:
    text = str(target or "").strip().strip("`").strip()
    if not text or text.lower() in {"none", "n/a", "na", "(none)"}:
        return ""
    if "\x00" in text or "\n" in text or "\r" in text:
        raise ValueError("target must be a single repository-relative path")
    text = text.replace("` / `", "::")
    text = re.sub(r"`\s*/\s*`", "::", text)
    text = re.sub(r"\s*::\s*", "::", text)
    path_text, separator, symbol = text.partition("::")
    path_text = path_text.strip()
    if not separator:
        legacy = re.fullmatch(r"(.+\.[A-Za-z0-9_+-]+):([A-Za-z_][A-Za-z0-9_.$#<>~-]*)", path_text)
        if legacy:
            path_text, symbol = legacy.groups()
            separator = "::"
    if separator and (not symbol.strip() or not _SYMBOL_RE.fullmatch(symbol.strip())):
        raise ValueError("target symbol has an invalid format")
    resolved = safe_repo_file(repo_root, path_text, require_exists=require_exists)
    if resolved is None:
        raise ValueError("target is not a regular repository-internal file")
    relative = resolved.relative_to(repo_root.expanduser().resolve()).as_posix()
    return f"{relative}::{symbol.strip()}" if separator else relative


def safe_output_relative(value: str) -> PurePosixPath:
    raw = str(value or "")
    if not _safe_relative_text(raw):
        raise ValueError(f"unsafe output path: {raw!r}")
    relative = PurePosixPath(raw.replace("\\", "/"))
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise ValueError(f"unsafe output path: {raw!r}")
    return relative


def _safe_relative_text(raw: str) -> bool:
    if not raw or "\x00" in raw or "\n" in raw or "\r" in raw:
        return False
    if raw.startswith(("/", "\\", "//", "\\\\")):
        return False
    posix = PurePosixPath(raw.replace("\\", "/"))
    windows = PureWindowsPath(raw)
    if posix.is_absolute() or windows.is_absolute() or windows.drive:
        return False
    return all(part not in {"", ".", ".."} for part in posix.parts)


def _has_symlink_component(root: Path, candidate: Path) -> bool:
    try:
        relative = candidate.relative_to(root)
    except ValueError:
        return True
    current = root
    for part in relative.parts:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            return True
    return False
