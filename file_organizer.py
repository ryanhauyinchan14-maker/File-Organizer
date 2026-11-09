"""
Easy File Organizer (Cross-Platform Security-Hardened Edition)
==============================================================
A modern, compact, beginner-friendly desktop utility for Windows, macOS, and Linux
that sorts loose files into neat category subfolders in 3 simple steps, backed by
enterprise-grade defensive programming and OS-aware security controls.

Cross-Platform & Security Controls Implemented:
1. Dynamic OS Detection & Path Resolution:
   - Uses `platform.system()` to adapt to Windows, macOS ("Darwin"), and Linux.
   - Resolves Downloads, Desktop, and Documents across Windows (including OneDrive
     redirection), macOS (`~/Downloads`, etc.), and Linux (`XDG_CONFIG_HOME` /
     `~/.config/user-dirs.dirs` with `~/Downloads` fallback).
2. OS-Specific Blacklisted System Directories:
   - Windows: Blocks root drives (`C:\\`, `D:\\`), `C:\\Windows`, `System32`, `SysWOW64`,
     `WinSxS`, `Program Files`, `Program Files (x86)`, `C:\\Users`, and root `AppData`.
   - macOS: Blocks `/`, `/System`, `/Library`, `/Applications`, `/private`, `/usr`,
     `/bin`, `/sbin`, `/Users`, and user `~/Library`.
   - Linux: Blocks `/`, `/boot`, `/etc`, `/sys`, `/proc`, `/dev`, `/usr`, `/bin`,
     `/sbin`, `/var`, `/root`, and `/home`.
   - All OSes: Blocks organizing the root user home directory itself (`Path.home()`).
3. Platform-Specific System & Hidden File Filtering:
   - Cross-platform: Dotfiles (`.`), Office lock files (`~$*`), incomplete downloads.
   - Windows: `desktop.ini`, `thumbs.db`, hidden/system file attributes.
   - macOS: `.DS_Store`, AppleDouble (`._*`), `.localized`, `.Trashes`, `.Spotlight-V100`,
     `Icon\\r`, and BSD `UF_HIDDEN` flag.
   - Linux: Editor swap/backup files (`*.swp`, `*.swo`, `*~`, `#*#`), `.directory`.
4. Cross-Platform Privilege & Non-Destructive File Permission Handling:
   - Detects Administrator (`ctypes.windll.shell32.IsUserAnAdmin()`) on Windows and
     `root` (`os.geteuid() == 0`) on macOS/Linux.
   - Checks POSIX write permissions (`os.access(..., os.W_OK)`) before moving.
   - Enforces path containment, symlink/junction defense, TOCTOU inode/size checks,
     and a strict zero-deletion guarantee.

Uses only the Python standard library: ctypes, os, pathlib, platform, shutil, stat, tkinter, typing.
"""

import ctypes
import os
from pathlib import Path
import platform
import shutil
import stat
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Set, Tuple


# ==============================================================================
# 1. OPERATING SYSTEM DETECTION & NATIVE TYPOGRAPHY
# ==============================================================================

# Detect host operating system: "Windows", "Darwin" (macOS), or "Linux"
CURRENT_OS: str = platform.system()

# Select clean native UI font per platform
if CURRENT_OS == "Windows":
    UI_FONT: str = "Segoe UI"
elif CURRENT_OS == "Darwin":
    UI_FONT = "Helvetica Neue"
else:
    UI_FONT = "DejaVu Sans"


# ==============================================================================
# 2. FILE CATEGORIES, ICONS & LABELS (CROSS-PLATFORM)
# ==============================================================================

CATEGORIES: Dict[str, Set[str]] = {
    "Photos & Images": {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".ico", ".heic", ".tiff"
    },
    "Documents": {
        ".pdf", ".docx", ".doc", ".txt", ".xlsx", ".xls", ".pptx", ".ppt",
        ".csv", ".rtf", ".odt", ".ods", ".odp", ".md", ".pages", ".numbers", ".key"
    },
    "Videos": {
        ".mp4", ".mkv", ".mov", ".avi", ".wmv", ".webm", ".m4v", ".flv"
    },
    "Music & Audio": {
        ".mp3", ".wav", ".aac", ".flac", ".m4a", ".ogg", ".wma", ".opus", ".aiff"
    },
    "Zip Files": {
        ".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".iso"
    },
    "Installers": {
        ".exe", ".msi", ".dmg", ".pkg", ".deb", ".rpm", ".appimage"
    },
    "Code & Scripts": {
        ".py", ".js", ".ts", ".html", ".css", ".json", ".bat", ".ps1",
        ".sh", ".zsh", ".bash", ".yaml", ".yml", ".xml", ".sql"
    },
}

DEFAULT_CATEGORY: str = "Other Files"

CATEGORY_META: List[Tuple[str, str, Tuple[str, str]]] = [
    ("Photos & Images", "📷", ("photo", "photos")),
    ("Documents", "📄", ("document", "documents")),
    ("Zip Files", "📦", ("zip file", "zip files")),
    ("Installers", "⚙️", ("installer", "installers")),
    ("Videos", "🎬", ("video", "videos")),
    ("Music & Audio", "🎵", ("audio file", "audio files")),
    ("Code & Scripts", "💻", ("code file", "code files")),
    ("Other Files", "📁", ("other file", "other files")),
]

CATEGORY_ICONS: Dict[str, str] = {name: icon for name, icon, _ in CATEGORY_META}
CATEGORY_NOUNS: Dict[str, Tuple[str, str]] = {name: nouns for name, _, nouns in CATEGORY_META}
CATEGORY_ORDER: List[str] = [name for name, _, _ in CATEGORY_META]

EXTENSION_TO_CATEGORY: Dict[str, str] = {
    ext.lower(): category
    for category, extensions in CATEGORIES.items()
    for ext in extensions
}


# ==============================================================================
# 3. SECURITY & METADATA FILTER CONSTANTS
# ==============================================================================

PROTECTED_FOLDER_MESSAGE: str = (
    "Protected System Folder: Organizing this directory is blocked to protect your operating system."
)

# Cross-platform + OS-specific hidden/system filenames (lowercase)
WINDOWS_IGNORED_FILENAMES: Set[str] = {
    "desktop.ini",
    "thumbs.db",
    "ehthumbs.db",
    "ehthumbs_vista.db",
    "ntuser.dat",
    "ntuser.ini",
    "bootmgr",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
}

MACOS_IGNORED_FILENAMES: Set[str] = {
    ".ds_store",
    ".localized",
    ".trashes",
    ".spotlight-v100",
    ".fseventsd",
    ".temporaryitems",
    ".volumeicon.icns",
    "icon\r",
}

LINUX_IGNORED_FILENAMES: Set[str] = {
    ".directory",
    ".trash",
}

ALL_IGNORED_FILENAMES: Set[str] = (
    WINDOWS_IGNORED_FILENAMES | MACOS_IGNORED_FILENAMES | LINUX_IGNORED_FILENAMES
)

# Incomplete download artifacts & OS shortcut/swap extensions
IGNORED_TEMP_EXTENSIONS: Set[str] = {
    ".tmp",
    ".temp",
    ".crdownload",
    ".part",
    ".partial",
    ".download",
    ".swp",
    ".swo",
    ".swn",
    ".lnk",
    ".url",
    ".webloc",
    ".desktop",
}

# Windows File Attribute bitmasks & macOS BSD flags
FILE_ATTRIBUTE_HIDDEN: int = 0x0002
FILE_ATTRIBUTE_SYSTEM: int = 0x0004
FILE_ATTRIBUTE_REPARSE_POINT: int = 0x0400
UF_HIDDEN: int = 0x8000  # macOS / BSD hidden file flag in st_flags

# Windows Reserved Device Names (guarded on all platforms for cross-platform safety)
WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "CONIN$", "CONOUT$", "CLOCK$",
    *(f"COM{i}" for i in range(0, 10)),
    *(f"LPT{i}" for i in range(0, 10)),
}

# Unicode Bidirectional / Spoofing characters used to disguise extensions (e.g., RLO \u202E)
UNICODE_SPOOFING_CHARS: Set[str] = {
    "\u202e", "\u202d", "\u202a", "\u202b", "\u202c",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200e", "\u200f", "\u200b", "\u200c", "\u200d", "\ufeff",
}

FORBIDDEN_FILENAME_CHARS: Set[str] = set('<>:"/\\|?*')


# ==============================================================================
# 4. CROSS-PLATFORM FOLDER RESOLUTION (WINDOWS / MACOS / LINUX XDG)
# ==============================================================================

def _parse_linux_xdg_user_dirs(home: Path) -> Dict[str, Path]:
    """
    Parse Linux XDG user directories from `$XDG_CONFIG_HOME/user-dirs.dirs`
    (defaulting to `~/.config/user-dirs.dirs`).
    Supports keys: XDG_DOWNLOAD_DIR, XDG_DESKTOP_DIR, XDG_DOCUMENTS_DIR.
    """
    xdg_config_home = os.environ.get("XDG_CONFIG_HOME", "").strip()
    config_dir = Path(xdg_config_home) if xdg_config_home else (home / ".config")
    user_dirs_file = config_dir / "user-dirs.dirs"

    key_map = {
        "XDG_DOWNLOAD_DIR": "Downloads",
        "XDG_DESKTOP_DIR": "Desktop",
        "XDG_DOCUMENTS_DIR": "Documents",
    }
    resolved_dirs: Dict[str, Path] = {}

    if not user_dirs_file.is_file():
        return resolved_dirs

    try:
        content = user_dirs_file.read_text(encoding="utf-8", errors="ignore")
        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            if key not in key_map:
                continue

            # Strip surrounding quotes and expand $HOME / ${HOME}
            cleaned_val = val.strip().strip('"').strip("'")
            cleaned_val = cleaned_val.replace("${HOME}", str(home)).replace(
                "$HOME", str(home)
            )
            candidate = Path(cleaned_val)
            if not candidate.is_absolute():
                candidate = home / candidate
            resolved_dirs[key_map[key]] = candidate
    except OSError:
        pass

    return resolved_dirs


def resolve_user_folder(folder_name: str, current_os: str = CURRENT_OS) -> Path:
    """
    Specification 1 (Cross-Platform Quick Folders):
    Reliably resolve 'Downloads', 'Desktop', and 'Documents' across:
    - Windows: Standard home folder with OneDrive redirection fallback.
    - macOS ("Darwin"): `Path.home() / folder_name`.
    - Linux ("Linux"): `XDG_CONFIG_HOME/user-dirs.dirs` (`XDG_DOWNLOAD_DIR`, etc.)
      with fallback to `Path.home() / folder_name`.
    """
    home = Path.home()
    direct_path = home / folder_name

    if current_os == "Windows":
        if direct_path.exists():
            return direct_path
        # Check environment OneDrive variables and ~/OneDrive fallback
        for env_key in ("OneDriveConsumer", "OneDrive", "OneDriveCommercial"):
            env_val = os.environ.get(env_key, "").strip()
            if env_val:
                od_candidate = Path(env_val) / folder_name
                if od_candidate.exists():
                    return od_candidate
        onedrive_path = home / "OneDrive" / folder_name
        if onedrive_path.exists():
            return onedrive_path
        return direct_path

    if current_os == "Linux":
        xdg_dirs = _parse_linux_xdg_user_dirs(home)
        if folder_name in xdg_dirs:
            xdg_candidate = xdg_dirs[folder_name]
            if xdg_candidate.exists():
                return xdg_candidate
        return direct_path

    # macOS ("Darwin") and other POSIX platforms
    return direct_path


# ==============================================================================
# 5. ENTERPRISE CROSS-PLATFORM SECURITY CONTROLS
# ==============================================================================

def is_running_with_elevated_privileges(current_os: str = CURRENT_OS) -> bool:
    """
    Specification 4 (Root / Administrator Detection):
    - On Windows: Check via `ctypes.windll.shell32.IsUserAnAdmin()`.
    - On macOS / Linux: Check via `os.geteuid() == 0`.
    """
    try:
        if current_os == "Windows":
            if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "shell32"):
                return bool(ctypes.windll.shell32.IsUserAnAdmin())
        else:
            if hasattr(os, "geteuid"):
                return os.geteuid() == 0
    except (OSError, AttributeError, ValueError):
        pass
    return False


def is_symlink_or_junction(path: Path) -> bool:
    """
    Control 3 (Symlink, NTFS Junction Point & Reparse Point Defense):
    Return True if `path` is a symbolic link, NTFS junction point, mount point,
    or carries the Windows FILE_ATTRIBUTE_REPARSE_POINT bit.
    Never follows the link target (uses os.lstat).
    """
    try:
        if path.is_symlink():
            return True
        if hasattr(path, "is_junction") and path.is_junction():
            return True
        lstat_info = os.lstat(path)
        attrs = getattr(lstat_info, "st_file_attributes", 0)
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT:
            return True
        if stat.S_ISLNK(lstat_info.st_mode):
            return True
    except (OSError, ValueError):
        return True
    return False


def _normalize_path_str(path_str: str, current_os: str) -> str:
    """Normalize a path string for comparison on the given OS."""
    cleaned = path_str.strip()
    if current_os == "Windows":
        cleaned = cleaned.replace("/", "\\")
        if len(cleaned) > 3:
            cleaned = cleaned.rstrip("\\")
        return cleaned.lower()
    else:
        cleaned = cleaned.replace("\\", "/")
        if len(cleaned) > 1:
            cleaned = cleaned.rstrip("/")
        return cleaned


def _is_subpath_or_equal(target_norm: str, protected_norm: str, sep: str) -> bool:
    """Return True if `target_norm` equals `protected_norm` or is inside it."""
    if target_norm == protected_norm:
        return True
    return target_norm.startswith(protected_norm.rstrip(sep) + sep)


def is_protected_system_path(
    target_path: Path, current_os: str = CURRENT_OS
) -> Tuple[bool, str]:
    """
    Specification 2 (OS-Specific Blacklisted System Directories):
    Dynamically enforce system folder blacklists for Windows, macOS, and Linux,
    and prevent organizing the root user home directory on all platforms.
    """
    raw_str = str(target_path).strip()
    if not raw_str:
        return True, "Empty directory path."

    # If the path exists on the current host, reject symlinks/junctions immediately
    try:
        if target_path.exists() and is_symlink_or_junction(target_path):
            return True, "Symbolic links and junction directories are blocked."
        resolved = target_path.resolve() if target_path.exists() else target_path
    except (OSError, ValueError, RuntimeError):
        return True, "Could not safely resolve directory path."

    norm_target = _normalize_path_str(str(resolved), current_os)

    # 1. Block root directories on all platforms ('/' on POSIX, 'C:\', 'D:\' on Windows)
    if norm_target in ("/", "\\") or (
        len(norm_target) in (2, 3)
        and norm_target[1:2] == ":"
        and norm_target[2:] in ("", "\\", "/")
    ):
        return True, "Root filesystem directories cannot be organized."

    if resolved.parent == resolved:
        return True, "Root filesystem directories cannot be organized."

    # 2. Prevent organizing the root user home directory itself on all platforms
    #    (e.g., C:\Users\username, /Users/username, /home/username)
    try:
        home = Path.home()
        norm_home = _normalize_path_str(str(home), current_os)
        norm_home_parent = _normalize_path_str(str(home.parent), current_os)
        if norm_target in (norm_home, norm_home_parent):
            return True, "Organizing the root user directory is blocked."
    except (OSError, ValueError):
        home = None

    # 3. OS-Specific Blacklists
    if current_os == "Windows":
        drive_anchor = resolved.anchor or "C:\\"
        if not drive_anchor.endswith("\\"):
            drive_anchor = "C:\\"

        win_trees = [
            os.environ.get("SystemRoot", os.path.join(drive_anchor, "Windows")),
            os.environ.get("WINDIR", os.path.join(drive_anchor, "Windows")),
            os.path.join(drive_anchor, "Windows"),
            os.path.join(drive_anchor, "Windows", "System32"),
            os.path.join(drive_anchor, "Windows", "SysWOW64"),
            os.path.join(drive_anchor, "Windows", "WinSxS"),
            os.environ.get("ProgramFiles", os.path.join(drive_anchor, "Program Files")),
            os.environ.get(
                "ProgramFiles(x86)", os.path.join(drive_anchor, "Program Files (x86)")
            ),
            os.environ.get("ProgramW6432", os.path.join(drive_anchor, "Program Files")),
            os.environ.get("ProgramData", os.path.join(drive_anchor, "ProgramData")),
            os.path.join(drive_anchor, "Program Files"),
            os.path.join(drive_anchor, "Program Files (x86)"),
            os.path.join(drive_anchor, "ProgramData"),
            os.path.join(drive_anchor, "Recovery"),
            os.path.join(drive_anchor, "$Recycle.Bin"),
            os.path.join(drive_anchor, "System Volume Information"),
        ]
        if home is not None:
            win_trees.extend(
                [
                    str(
                        home
                        / "AppData"
                        / "Roaming"
                        / "Microsoft"
                        / "Windows"
                        / "Start Menu"
                    ),
                    str(
                        Path(drive_anchor)
                        / "ProgramData"
                        / "Microsoft"
                        / "Windows"
                        / "Start Menu"
                    ),
                ]
            )

        for tree in win_trees:
            if tree and _is_subpath_or_equal(
                norm_target, _normalize_path_str(tree, "Windows"), "\\"
            ):
                return True, "Protected Windows system or program directory."

        win_exact = {
            _normalize_path_str(os.path.join(drive_anchor, "Users"), "Windows"),
        }
        for env_key in ("APPDATA", "LOCALAPPDATA", "TEMP", "TMP"):
            env_val = os.environ.get(env_key, "")
            if env_val:
                win_exact.add(_normalize_path_str(env_val, "Windows"))

        if home is not None:
            for p in (
                home / "AppData",
                home / "AppData" / "Local",
                home / "AppData" / "Roaming",
                home / "AppData" / "LocalLow",
            ):
                win_exact.add(_normalize_path_str(str(p), "Windows"))

        if norm_target in win_exact:
            return True, "Protected Windows user or AppData root directory."

        win_components = {
            "windows",
            "system32",
            "syswow64",
            "winsxs",
            "program files",
            "program files (x86)",
            "programdata",
            "start menu",
            "startup",
            "$recycle.bin",
            "system volume information",
        }
        for part in norm_target.split("\\"):
            if part in win_components:
                return True, f"Protected Windows component '{part}'."

    elif current_os == "Darwin":
        # macOS Blacklist: /, /System, /Library, /Applications, /private, /usr, /bin, /sbin, ~/Library
        mac_trees = [
            "/System",
            "/Library",
            "/Applications",
            "/private",
            "/usr",
            "/bin",
            "/sbin",
            "/dev",
            "/etc",
            "/var",
            "/Volumes",
            "/cores",
        ]
        if home is not None:
            mac_trees.append(str(home / "Library").replace("\\", "/"))

        for tree in mac_trees:
            norm_tree = _normalize_path_str(tree, "Darwin")
            if _is_subpath_or_equal(norm_target, norm_tree, "/"):
                return True, f"Protected macOS directory '{tree}'."

        # Also block /Users root and any `/Users/<user>/Library` or `/Users/<user>`
        parts = [p for p in norm_target.split("/") if p]
        if parts == ["Users"] or (len(parts) == 2 and parts[0] == "Users"):
            return True, "Protected macOS /Users root directory."
        if len(parts) >= 3 and parts[0] == "Users" and parts[2] == "Library":
            return True, "Protected macOS ~/Library directory."

    else:
        # Linux / POSIX Blacklist: /, /boot, /etc, /sys, /proc, /dev, /usr, /bin, /sbin, /var, /root
        linux_trees = [
            "/boot",
            "/etc",
            "/sys",
            "/proc",
            "/dev",
            "/usr",
            "/bin",
            "/sbin",
            "/var",
            "/root",
            "/lib",
            "/lib64",
            "/run",
            "/opt",
            "/srv",
            "/snap",
        ]
        if home is not None:
            for hidden_crit in (".ssh", ".gnupg", ".config", ".local"):
                linux_trees.append(str(home / hidden_crit).replace("\\", "/"))

        for tree in linux_trees:
            norm_tree = _normalize_path_str(tree, "Linux")
            if _is_subpath_or_equal(norm_target, norm_tree, "/"):
                return True, f"Protected Linux system directory '{tree}'."

        parts = [p for p in norm_target.split("/") if p]
        if parts == ["home"] or (len(parts) == 2 and parts[0] == "home"):
            return True, "Protected Linux /home user root directory."

    return False, ""


def is_reserved_windows_name(filename: str) -> bool:
    """
    Control 2 (Windows Reserved Device Name Defense):
    Check if a filename matches a reserved MS-DOS/Windows device name such as
    CON, PRN, AUX, NUL, COM1-COM9, LPT1-LPT9 (with or without extensions).
    """
    trimmed = filename.strip(" .")
    if not trimmed:
        return True

    first_token = trimmed.split(".")[0].upper()
    stem_token = Path(trimmed).stem.upper()
    return first_token in WINDOWS_RESERVED_NAMES or stem_token in WINDOWS_RESERVED_NAMES


def inspect_and_sanitize_filename(raw_name: str) -> Tuple[bool, str, str]:
    """
    Control 2 (Path Traversal, ADS, Reserved Names & Unicode Spoofing Defense):
    - Blocks Alternate Data Streams (':' in filename) and path traversal ('..', '/', '\\').
    - Strips Unicode Bidirectional Override characters (such as RLO \\u202E) and
      ASCII control characters so disguised executables are neutralized.
    - Blocks Windows Reserved Device Names (CON, PRN, AUX, NUL, COM1..9, LPT1..9).
    """
    if not raw_name:
        return False, "", "Empty filename"

    if ":" in raw_name:
        return False, "", "Blocked Alternate Data Stream (ADS) or colon in filename"

    if (
        "/" in raw_name
        or "\\" in raw_name
        or ".." in raw_name
        or raw_name in (".", "..")
    ):
        return False, "", "Blocked path traversal sequence in filename"

    cleaned_chars: List[str] = []
    for ch in raw_name:
        code = ord(ch)
        if ch in UNICODE_SPOOFING_CHARS:
            continue
        if code < 32 or (127 <= code <= 159):
            continue
        if ch in FORBIDDEN_FILENAME_CHARS:
            continue
        cleaned_chars.append(ch)

    sanitized = "".join(cleaned_chars).strip(" .")
    if not sanitized or sanitized in (".", ".."):
        return False, "", "Filename unsafe after stripping control characters"

    if is_reserved_windows_name(raw_name) or is_reserved_windows_name(sanitized):
        return False, "", f"Blocked reserved device name '{raw_name}'"

    return True, sanitized, ""


def verify_path_containment(base_dir: Path, category_dir: Path, dest_path: Path) -> bool:
    """
    Control 2 & 3 (Strict Path Containment Verification):
    Strictly verify using Path.resolve() and os.path.commonpath() that:
    1. Neither `base_dir`, `category_dir`, nor `dest_path` is a symlink/junction.
    2. `category_dir` resolves as a direct child of `base_dir`.
    3. `dest_path` resolves as a direct child of `category_dir` and inside `base_dir`.
    """
    try:
        if is_symlink_or_junction(base_dir):
            return False
        if category_dir.exists() and is_symlink_or_junction(category_dir):
            return False
        if dest_path.exists() and is_symlink_or_junction(dest_path):
            return False

        resolved_base = base_dir.resolve()
        resolved_category = category_dir.resolve()
        resolved_dest = dest_path.resolve()

        norm_base = os.path.normcase(os.path.normpath(str(resolved_base)))
        norm_cat = os.path.normcase(os.path.normpath(str(resolved_category)))
        norm_dest = os.path.normcase(os.path.normpath(str(resolved_dest)))

        if os.path.commonpath([norm_base, norm_cat]) != norm_base:
            return False
        if os.path.commonpath([norm_base, norm_dest]) != norm_base:
            return False

        if resolved_category.parent != resolved_base:
            return False
        if resolved_dest.parent != resolved_category:
            return False

        return True
    except (OSError, ValueError, RuntimeError):
        return False


def _disallow_copy_fallback(_src: str, _dst: str) -> None:
    """
    Control 4 (Non-Destructive Atomic Move Helper):
    Prevents `shutil.move` from falling back to non-atomic copy+delete when a
    file is locked, guaranteeing zero partial copies and zero file deletions.
    """
    raise PermissionError("Atomic rename blocked because the file is currently in use.")


def atomic_verified_move(
    source_path: Path,
    dest_path: Path,
    base_dir: Path,
    category_dir: Path,
    current_os: str = CURRENT_OS,
) -> Tuple[bool, str]:
    """
    Specification 4 & Control 4 (Cross-Platform Permission Check, TOCTOU & Integrity):
    1. Verifies strict path containment and non-symlink status.
    2. On POSIX (macOS/Linux), checks write permissions via `os.access(..., os.W_OK)`.
    3. Captures pre-move `st_size` and `st_ino` via `os.lstat()`.
    4. Executes an atomic, non-overwriting move (`shutil.move` with copy fallback disabled).
    5. Verifies post-move destination existence, regular file mode, size, and inode.
    """
    if not verify_path_containment(base_dir, category_dir, dest_path):
        return (
            False,
            f"Blocked '{source_path.name}': Destination failed path containment check.",
        )

    if is_symlink_or_junction(source_path):
        return (
            False,
            f"Skipped '{source_path.name}' because symbolic links are not moved.",
        )

    try:
        # Specification 4: On POSIX (macOS/Linux), verify write permissions before moving
        if current_os != "Windows":
            if not os.access(source_path, os.W_OK) or not os.access(
                source_path.parent, os.W_OK
            ):
                return (
                    False,
                    f"Skipped {source_path.name} because you do not have write permission for it.",
                )

        pre_stat = os.lstat(source_path)
        if not stat.S_ISREG(pre_stat.st_mode):
            return (
                False,
                f"Skipped '{source_path.name}' because it is not a regular file.",
            )

        expected_size = pre_stat.st_size
        expected_ino = pre_stat.st_ino

        category_dir.mkdir(exist_ok=True)
        if is_symlink_or_junction(category_dir):
            return (
                False,
                f"Blocked '{source_path.name}': Category folder is a symlink or junction.",
            )

        # TOCTOU check immediately before moving
        confirm_stat = os.lstat(source_path)
        confirm_attrs = getattr(confirm_stat, "st_file_attributes", 0)
        if (
            not stat.S_ISREG(confirm_stat.st_mode)
            or (confirm_attrs & FILE_ATTRIBUTE_REPARSE_POINT)
            or confirm_stat.st_size != expected_size
            or (expected_ino != 0 and confirm_stat.st_ino != expected_ino)
        ):
            return (
                False,
                f"Skipped '{source_path.name}' because the file changed during scanning.",
            )

        if dest_path.exists():
            return (
                False,
                f"Skipped '{source_path.name}' to avoid overwriting an existing file.",
            )

        shutil.move(
            str(source_path),
            str(dest_path),
            copy_function=_disallow_copy_fallback,
        )

        # Post-move integrity verification
        post_stat = os.lstat(dest_path)
        if (
            not stat.S_ISREG(post_stat.st_mode)
            or post_stat.st_size != expected_size
            or (
                expected_ino != 0
                and post_stat.st_ino != 0
                and post_stat.st_ino != expected_ino
            )
        ):
            return (
                False,
                f"Warning: '{dest_path.name}' integrity verification mismatch after move.",
            )

        return True, ""

    except PermissionError:
        return (
            False,
            f"Skipped {source_path.name} because it is currently open or permission was denied.",
        )
    except FileExistsError:
        return (
            False,
            f"Skipped {source_path.name} because a file with that name already exists.",
        )
    except (OSError, ValueError):
        return (
            False,
            f"Skipped {source_path.name} because the operating system is currently using or protecting it.",
        )


# ==============================================================================
# 6. PLATFORM-SPECIFIC SYSTEM & HIDDEN FILE FILTERING
# ==============================================================================

def should_ignore_filename_by_rules(
    filename: str, current_os: str = CURRENT_OS
) -> bool:
    """
    Specification 3 (Platform-Specific System & Hidden File Filtering by name):
    - Cross-platform: Dotfiles (`.` prefix), Office lock files (`~$*`), incomplete
      downloads (`.crdownload`, `.part`, `.tmp`), and editor swap files (`*.swp`).
    - Windows: `desktop.ini`, `thumbs.db`, etc.
    - macOS: `.DS_Store`, AppleDouble (`._*`), `.localized`, `.Trashes`, `.Spotlight-V100`, `Icon\\r`.
    - Linux: Editor backup/swap files (`*.swp`, `*.swo`, `*~`, `#*#`), `.directory`.
    """
    if not filename:
        return True

    lower_name = filename.lower()

    # Cross-platform: Any file starting with '.' (includes .DS_Store, ._* AppleDouble, .localized, etc.)
    if filename.startswith("."):
        return True

    # Cross-platform: Office temporary lock files (~$Budget.xlsx)
    if filename.startswith("~$"):
        return True

    # Linux / Unix editor backup and auto-save files (*~ and #*#)
    if filename.endswith("~") or (
        filename.startswith("#") and filename.endswith("#")
    ):
        return True

    # Known OS system metadata filenames across Windows, macOS, and Linux
    if lower_name in ALL_IGNORED_FILENAMES:
        return True

    # Incomplete download artifacts & swap extensions
    ext = Path(filename).suffix.lower()
    if ext in IGNORED_TEMP_EXTENSIONS:
        return True

    return False


def should_ignore_file(
    file_path: Path, script_path: Path, current_os: str = CURRENT_OS
) -> bool:
    """
    Check both filename rules and OS-level hidden/system file attributes
    (Windows FILE_ATTRIBUTE_HIDDEN / SYSTEM and macOS UF_HIDDEN).
    """
    try:
        try:
            if file_path.resolve() == script_path:
                return True
        except (OSError, ValueError):
            pass

        if should_ignore_filename_by_rules(file_path.name, current_os=current_os):
            return True

        if file_path.exists():
            lstat_info = os.lstat(file_path)
            # Windows hidden / system attributes
            win_attrs = getattr(lstat_info, "st_file_attributes", 0)
            if win_attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                return True

            # macOS BSD UF_HIDDEN flag
            bsd_flags = getattr(lstat_info, "st_flags", 0)
            if bsd_flags & UF_HIDDEN:
                return True
    except (OSError, ValueError):
        return True

    return False


def get_category_for_filename(sanitized_filename: str) -> str:
    """Return the friendly subfolder name for a sanitized filename."""
    ext = Path(sanitized_filename).suffix.lower()
    return EXTENSION_TO_CATEGORY.get(ext, DEFAULT_CATEGORY)


def _split_stem_and_suffix(filename: str) -> Tuple[str, str]:
    """
    Split a filename into (stem, suffix), preserving compound archive extensions
    such as '.tar.gz', '.tar.bz2', and '.tar.xz'.
    """
    lower = filename.lower()
    for compound in (".tar.gz", ".tar.bz2", ".tar.xz"):
        if lower.endswith(compound) and len(filename) > len(compound):
            cut = len(filename) - len(compound)
            return filename[:cut], filename[cut:]
    p = Path(filename)
    return p.stem, p.suffix


def get_safe_destination_path(
    target_dir: Path, sanitized_filename: str, reserved_paths: Set[str]
) -> Path:
    """
    Guarantee no file is ever overwritten.
    If 'photo.png' already exists in the destination folder, returns 'photo (1).png',
    'photo (2).png', etc.
    """
    candidate = target_dir / sanitized_filename
    norm_cand = os.path.normcase(str(candidate))
    if not candidate.exists() and norm_cand not in reserved_paths:
        return candidate

    stem, suffix = _split_stem_and_suffix(sanitized_filename)
    counter = 1

    while True:
        new_name = f"{stem} ({counter}){suffix}"
        candidate = target_dir / new_name
        norm_cand = os.path.normcase(str(candidate))
        if not candidate.exists() and norm_cand not in reserved_paths:
            return candidate
        counter += 1


def format_natural_list(items: List[str]) -> str:
    """Format a list of strings into natural English (e.g., 'A, B, and C')."""
    if not items:
        return ""
    if len(items) == 1:
        return items[0]
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return f"{', '.join(items[:-1])}, and {items[-1]}"


def build_friendly_preview_sentence(category_counts: Dict[str, int]) -> str:
    """
    Build a friendly plain-English sentence from category counts, e.g.:
    'Found 12 photos, 4 documents, and 2 zip files ready to sort.'
    """
    parts: List[str] = []
    for category in CATEGORY_ORDER:
        count = category_counts.get(category, 0)
        if count > 0:
            singular, plural = CATEGORY_NOUNS.get(category, ("file", "files"))
            noun = singular if count == 1 else plural
            parts.append(f"{count} {noun}")

    if not parts:
        return "No loose files found! This folder is already neat and tidy."

    return f"Found {format_natural_list(parts)} ready to sort."


# ==============================================================================
# 7. CUSTOM ROUNDED BUTTON WIDGET (PURE TKINTER CANVAS)
# ==============================================================================

class RoundedButton(tk.Canvas):
    """
    A modern, rounded-corner button built on tk.Canvas that renders consistently
    across Windows, macOS, and Linux.
    """

    def __init__(
        self,
        parent: tk.Widget,
        text: str,
        command=None,
        width: int = 140,
        height: int = 38,
        corner_radius: int = 10,
        bg_color: str = "#2563EB",
        hover_color: str = "#1D4ED8",
        fg_color: str = "#FFFFFF",
        font: tuple = (UI_FONT, 10, "bold"),
        canvas_bg: str = "#FFFFFF",
    ) -> None:
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=canvas_bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2",
        )
        self.text = text
        self.command = command
        self.btn_width = width
        self.btn_height = height
        self.radius = min(corner_radius, height // 2, width // 2)
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.fg_color = fg_color
        self.font = font
        self._current_bg = bg_color

        self._draw()

        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<ButtonRelease-1>", self._on_click)

    def _draw(self) -> None:
        """Render the smooth rounded rectangle and centered label."""
        self.delete("all")
        w = self.btn_width
        h = self.btn_height
        r = self.radius
        c = self._current_bg

        self.create_oval(0, 0, 2 * r, 2 * r, fill=c, outline=c)
        self.create_oval(w - 2 * r, 0, w, 2 * r, fill=c, outline=c)
        self.create_oval(0, h - 2 * r, 2 * r, h, fill=c, outline=c)
        self.create_oval(w - 2 * r, h - 2 * r, w, h, fill=c, outline=c)
        self.create_rectangle(r, 0, w - r, h, fill=c, outline=c)
        self.create_rectangle(0, r, w, h - r, fill=c, outline=c)

        self.create_text(
            w // 2,
            h // 2,
            text=self.text,
            fill=self.fg_color,
            font=self.font,
        )

    def set_colors(self, bg_color: str, hover_color: str, fg_color: str) -> None:
        """Update button palette (e.g., when highlighting the active folder button)."""
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.fg_color = fg_color
        self._current_bg = bg_color
        self._draw()

    def _on_enter(self, _event) -> None:
        self._current_bg = self.hover_color
        self._draw()

    def _on_leave(self, _event) -> None:
        self._current_bg = self.bg_color
        self._draw()

    def _on_click(self, event) -> None:
        if 0 <= event.x <= self.btn_width and 0 <= event.y <= self.btn_height:
            if callable(self.command):
                self.command()


# ==============================================================================
# 8. MODERN, COMPACT 3-STEP APPLICATION (WINDOWS / MACOS / LINUX)
# ==============================================================================

class FriendlyFileOrganizerApp:
    """Compact, centered, modern 3-step file organizer window."""

    BG_WINDOW = "#F4F6F8"
    BG_CARD = "#FFFFFF"
    BORDER_CARD = "#E2E8F0"
    TEXT_PRIMARY = "#0F172A"
    TEXT_SECONDARY = "#475569"

    PILL_ACTIVE_BG = "#2563EB"
    PILL_ACTIVE_HOVER = "#1D4ED8"
    PILL_ACTIVE_FG = "#FFFFFF"

    PILL_INACTIVE_BG = "#EFF6FF"
    PILL_INACTIVE_HOVER = "#DBEAFE"
    PILL_INACTIVE_FG = "#1E40AF"

    PILL_BROWSE_BG = "#F1F5F9"
    PILL_BROWSE_HOVER = "#E2E8F0"
    PILL_BROWSE_FG = "#334155"

    PREVIEW_BTN_BG = "#3B82F6"
    PREVIEW_BTN_HOVER = "#2563EB"

    ORGANIZE_BTN_BG = "#10B981"
    ORGANIZE_BTN_HOVER = "#059669"

    WINDOW_WIDTH = 700
    WINDOW_HEIGHT_COLLAPSED = 630
    WINDOW_HEIGHT_EXPANDED = 780

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Easy File Organizer")
        self.root.configure(bg=self.BG_WINDOW)
        self.root.resizable(False, False)

        # Center the compact window on the user's screen
        self._center_window(self.WINDOW_WIDTH, self.WINDOW_HEIGHT_COLLAPSED)

        # Remember this script's path so it never moves itself
        try:
            self.script_path = Path(__file__).resolve()
        except (NameError, OSError):
            self.script_path = Path.cwd() / "file_organizer.py"

        # State
        self.current_folder: Path = resolve_user_folder("Downloads")
        self.active_shortcut: str = "Downloads"
        self.shortcut_buttons: Dict[str, RoundedButton] = {}
        self.details_expanded: bool = False
        self.running_elevated: bool = is_running_with_elevated_privileges()

        self._build_ui()
        self._update_folder_display()

    def _center_window(self, width: int, height: int) -> None:
        """Position the window comfortably in the center of the monitor."""
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = max((screen_w - width) // 2, 20)
        y = max((screen_h - height) // 2 - 20, 20)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _set_window_height(self, height: int) -> None:
        """Adjust window height smoothly when opening/closing the advanced details drawer."""
        self.root.update_idletasks()
        x = self.root.winfo_x()
        y = self.root.winfo_y()
        self.root.geometry(f"{self.WINDOW_WIDTH}x{height}+{x}+{y}")

    def _create_card(self, parent: tk.Widget, pady: tuple = (0, 10)) -> tk.Frame:
        """Create a crisp white panel card with a subtle border."""
        card = tk.Frame(
            parent,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=18,
            pady=14,
        )
        card.pack(fill=tk.X, pady=pady)
        return card

    def _build_ui(self) -> None:
        """Build the compact 3-step visual interface."""
        self.main_column = tk.Frame(
            self.root, bg=self.BG_WINDOW, width=652, padx=24, pady=14
        )
        self.main_column.pack(anchor=tk.N, fill=tk.BOTH, expand=True)

        # --- App Header ---
        header = tk.Frame(self.main_column, bg=self.BG_WINDOW)
        header.pack(fill=tk.X, pady=(0, 8))

        tk.Label(
            header,
            text="Easy File Organizer",
            font=(UI_FONT, 16, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_WINDOW,
            anchor="w",
        ).pack(fill=tk.X)

        os_label = "macOS" if CURRENT_OS == "Darwin" else CURRENT_OS
        tk.Label(
            header,
            text=f"Tidy up your loose files in 3 easy steps ({os_label}). Protected by built-in safety guards.",
            font=(UI_FONT, 9),
            fg=self.TEXT_SECONDARY,
            bg=self.BG_WINDOW,
            anchor="w",
        ).pack(fill=tk.X, pady=(1, 0))

        # Specification 4: Principle-of-Least-Privilege banner if running as Admin / root
        if self.running_elevated:
            priv_name = "Administrator" if CURRENT_OS == "Windows" else "root"
            admin_banner = tk.Frame(
                self.main_column,
                bg="#FEF3C7",
                highlightbackground="#F59E0B",
                highlightthickness=1,
                padx=12,
                pady=6,
            )
            admin_banner.pack(fill=tk.X, pady=(0, 8))
            tk.Label(
                admin_banner,
                text=f"🛡️ Security Notice: Running with elevated {priv_name} privileges. Please run as a standard user.",
                font=(UI_FONT, 8, "bold"),
                fg="#92400E",
                bg="#FEF3C7",
                anchor="w",
            ).pack(fill=tk.X)

        # ======================================================================
        # STEP 1: WHERE ARE YOUR MESSY FILES?
        # ======================================================================
        step1_card = self._create_card(self.main_column)

        tk.Label(
            step1_card,
            text="Step 1: Where are your messy files?",
            font=(UI_FONT, 11, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 10))

        btn_row = tk.Frame(step1_card, bg=self.BG_CARD)
        btn_row.pack(fill=tk.X, pady=(0, 10))

        shortcut_meta = [
            ("Downloads", "📥 Downloads", 132),
            ("Desktop", "🖥️ Desktop", 122),
            ("Documents", "📄 Documents", 136),
        ]
        for folder_key, label_text, width in shortcut_meta:
            btn = RoundedButton(
                btn_row,
                text=label_text,
                width=width,
                height=36,
                corner_radius=10,
                bg_color=self.PILL_INACTIVE_BG,
                hover_color=self.PILL_INACTIVE_HOVER,
                fg_color=self.PILL_INACTIVE_FG,
                font=(UI_FONT, 10, "bold"),
                canvas_bg=self.BG_CARD,
                command=lambda name=folder_key: self._select_shortcut_folder(name),
            )
            btn.pack(side=tk.LEFT, padx=(0, 8))
            self.shortcut_buttons[folder_key] = btn

        self.browse_btn = RoundedButton(
            btn_row,
            text="📂 Browse Other Folder...",
            width=190,
            height=36,
            corner_radius=10,
            bg_color=self.PILL_BROWSE_BG,
            hover_color=self.PILL_BROWSE_HOVER,
            fg_color=self.PILL_BROWSE_FG,
            font=(UI_FONT, 9, "bold"),
            canvas_bg=self.BG_CARD,
            command=self._browse_custom_folder,
        )
        self.browse_btn.pack(side=tk.LEFT)

        self.current_folder_label = tk.Label(
            step1_card,
            text="Currently organizing: Downloads",
            font=(UI_FONT, 11, "bold"),
            fg=self.PILL_ACTIVE_BG,
            bg=self.BG_CARD,
            anchor="w",
        )
        self.current_folder_label.pack(fill=tk.X)

        # ======================================================================
        # STEP 2: SAFE PREVIEW & VISUAL CATEGORY SUMMARY CARDS
        # ======================================================================
        step2_card = self._create_card(self.main_column)

        step2_top = tk.Frame(step2_card, bg=self.BG_CARD)
        step2_top.pack(fill=tk.X, pady=(0, 6))

        tk.Label(
            step2_top,
            text="Step 2: Safe Preview",
            font=(UI_FONT, 11, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD,
            anchor="w",
        ).pack(side=tk.LEFT)

        self.preview_btn = RoundedButton(
            step2_top,
            text="🔍 Preview What Will Happen",
            width=210,
            height=34,
            corner_radius=9,
            bg_color=self.PREVIEW_BTN_BG,
            hover_color=self.PREVIEW_BTN_HOVER,
            fg_color="#FFFFFF",
            font=(UI_FONT, 9, "bold"),
            canvas_bg=self.BG_CARD,
            command=self._run_safe_preview,
        )
        self.preview_btn.pack(side=tk.RIGHT)

        self.preview_summary_label = tk.Label(
            step2_card,
            text="Checking folder...",
            font=(UI_FONT, 10),
            fg=self.TEXT_SECONDARY,
            bg=self.BG_CARD,
            wraplength=600,
            justify=tk.LEFT,
            anchor="w",
        )
        self.preview_summary_label.pack(fill=tk.X, pady=(0, 8))

        self.badges_container = tk.Frame(step2_card, bg=self.BG_CARD)
        self.badges_container.pack(fill=tk.X)

        # ======================================================================
        # STEP 3: ORGANIZE (CENTERED BUTTON & CELEBRATION BANNER)
        # ======================================================================
        step3_card = self._create_card(self.main_column, pady=(0, 6))

        tk.Label(
            step3_card,
            text="Step 3: Organize",
            font=(UI_FONT, 11, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD,
            anchor="w",
        ).pack(fill=tk.X, pady=(0, 8))

        organize_btn_holder = tk.Frame(step3_card, bg=self.BG_CARD)
        organize_btn_holder.pack(fill=tk.X, pady=(0, 4))

        self.organize_btn = RoundedButton(
            organize_btn_holder,
            text="✨ Organize My Files",
            width=270,
            height=45,
            corner_radius=12,
            bg_color=self.ORGANIZE_BTN_BG,
            hover_color=self.ORGANIZE_BTN_HOVER,
            fg_color="#FFFFFF",
            font=(UI_FONT, 12, "bold"),
            canvas_bg=self.BG_CARD,
            command=self._run_organize_files,
        )
        self.organize_btn.pack(anchor=tk.CENTER)

        self.banner_frame = tk.Frame(step3_card, bg=self.BG_CARD)
        self.banner_frame.pack(fill=tk.X, pady=(6, 0))

        self.status_banner = tk.Label(
            self.banner_frame,
            text="",
            font=(UI_FONT, 11, "bold"),
            bg=self.BG_CARD,
            fg=self.TEXT_SECONDARY,
            padx=12,
            pady=8,
            wraplength=580,
            justify=tk.CENTER,
        )

        self.warning_label = tk.Label(
            self.banner_frame,
            text="",
            font=(UI_FONT, 9, "bold"),
            bg=self.BG_CARD,
            fg="#B45309",
            wraplength=580,
            justify=tk.CENTER,
        )

        # ======================================================================
        # COLLAPSIBLE ADVANCED FILE DETAILS TOGGLE (CLOSED BY DEFAULT)
        # ======================================================================
        advanced_bar = tk.Frame(self.main_column, bg=self.BG_WINDOW)
        advanced_bar.pack(fill=tk.X, pady=(2, 4))

        self.toggle_details_btn = tk.Label(
            advanced_bar,
            text="▸ Show individual file details (advanced)",
            font=(UI_FONT, 9),
            fg="#64748B",
            bg=self.BG_WINDOW,
            cursor="hand2",
            anchor="w",
        )
        self.toggle_details_btn.pack(side=tk.LEFT)
        self.toggle_details_btn.bind("<Button-1>", self._toggle_advanced_details)

        self.details_drawer = tk.Frame(
            self.main_column,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=10,
            pady=8,
        )

        self.status_box = tk.Text(
            self.details_drawer,
            height=6,
            wrap=tk.WORD,
            font=(UI_FONT, 9),
            bg="#F8FAFC",
            fg=self.TEXT_PRIMARY,
            relief=tk.FLAT,
            padx=8,
            pady=6,
            state=tk.DISABLED,
        )
        scrollbar = ttk.Scrollbar(
            self.details_drawer, orient=tk.VERTICAL, command=self.status_box.yview
        )
        self.status_box.configure(yscrollcommand=scrollbar.set)

        self.status_box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    # ==========================================================================
    # VISUAL CATEGORY BADGE RENDERING & ADVANCED TOGGLE
    # ==========================================================================

    def _render_category_badges(self, category_counts: Dict[str, int]) -> None:
        """Render 2-column visual category summary badges showing what was found."""
        for child in self.badges_container.winfo_children():
            child.destroy()

        non_empty = [
            (cat, CATEGORY_ICONS[cat], category_counts.get(cat, 0))
            for cat in CATEGORY_ORDER
            if category_counts.get(cat, 0) > 0
        ]

        if not non_empty:
            empty_badge = tk.Frame(
                self.badges_container,
                bg="#F8FAFC",
                highlightbackground="#E2E8F0",
                highlightthickness=1,
                padx=14,
                pady=10,
            )
            empty_badge.pack(fill=tk.X, pady=2)
            tk.Label(
                empty_badge,
                text="✨ No loose files waiting to be sorted in this folder!",
                font=(UI_FONT, 10, "bold"),
                fg="#059669",
                bg="#F8FAFC",
            ).pack(anchor="w")
            return

        self.badges_container.columnconfigure(0, weight=1, uniform="badge_col")
        self.badges_container.columnconfigure(1, weight=1, uniform="badge_col")

        for idx, (category, icon, count) in enumerate(non_empty):
            row = idx // 2
            col = idx % 2
            file_word = "file" if count == 1 else "files"

            badge = tk.Frame(
                self.badges_container,
                bg="#F8FAFC",
                highlightbackground="#CBD5E1",
                highlightthickness=1,
                padx=12,
                pady=6,
            )
            badge.grid(
                row=row,
                column=col,
                sticky="ew",
                padx=(0, 6) if col == 0 else (6, 0),
                pady=3,
            )

            tk.Label(
                badge,
                text=f"• {icon} {category}:",
                font=(UI_FONT, 10),
                fg=self.TEXT_PRIMARY,
                bg="#F8FAFC",
                anchor="w",
            ).pack(side=tk.LEFT)

            tk.Label(
                badge,
                text=f"{count} {file_word}",
                font=(UI_FONT, 10, "bold"),
                fg=self.PILL_ACTIVE_BG,
                bg="#F8FAFC",
                anchor="e",
            ).pack(side=tk.RIGHT)

    def _show_banner(
        self, text: str, is_success: bool = True, warnings: Optional[List[str]] = None
    ) -> None:
        """Display or hide the friendly celebration banner in Step 3."""
        if not text:
            self.status_banner.pack_forget()
        else:
            if is_success:
                self.status_banner.configure(
                    text=text,
                    bg="#ECFDF5",
                    fg="#065F46",
                    highlightbackground="#A7F3D0",
                    highlightthickness=1,
                )
            else:
                self.status_banner.configure(
                    text=text,
                    bg="#EFF6FF",
                    fg="#1E40AF",
                    highlightbackground="#BFDBFE",
                    highlightthickness=1,
                )
            self.status_banner.pack(fill=tk.X, pady=(4, 2))

        if warnings:
            shown = warnings[:3]
            if len(warnings) > 3:
                shown.append(
                    f"...and {len(warnings) - 3} more skipped items (see advanced details)."
                )
            self.warning_label.configure(text="\n".join(f"⚠️ {w}" for w in shown))
            self.warning_label.pack(fill=tk.X, pady=(2, 0))
        else:
            self.warning_label.pack_forget()

    def _toggle_advanced_details(self, _event=None) -> None:
        """Open or close the collapsible individual file details box."""
        self.details_expanded = not self.details_expanded
        if self.details_expanded:
            self.toggle_details_btn.configure(
                text="▾ Hide individual file details (advanced)"
            )
            self.details_drawer.pack(fill=tk.BOTH, expand=True, pady=(2, 0))
            self._set_window_height(self.WINDOW_HEIGHT_EXPANDED)
        else:
            self.toggle_details_btn.configure(
                text="▸ Show individual file details (advanced)"
            )
            self.details_drawer.pack_forget()
            self._set_window_height(self.WINDOW_HEIGHT_COLLAPSED)

    def _set_advanced_details(self, lines: List[str]) -> None:
        """Populate the hidden-by-default advanced file list."""
        self.status_box.configure(state=tk.NORMAL)
        self.status_box.delete("1.0", tk.END)
        if not lines:
            self.status_box.insert(tk.END, "No individual file actions to show.")
        else:
            self.status_box.insert(tk.END, "\n".join(lines))
        self.status_box.see("1.0")
        self.status_box.configure(state=tk.DISABLED)

    # ==========================================================================
    # STEP 1: FOLDER SELECTION HANDLERS (WITH OS BLACKLIST ENFORCEMENT)
    # ==========================================================================

    def _try_set_target_folder(self, candidate: Path, shortcut_name: str = "") -> bool:
        """Validate `candidate` against the OS system path blacklist before setting."""
        is_blocked, _reason = is_protected_system_path(candidate)
        if is_blocked:
            messagebox.showerror(
                "Protected System Folder",
                PROTECTED_FOLDER_MESSAGE,
                parent=self.root,
            )
            return False

        self.active_shortcut = shortcut_name
        self.current_folder = candidate
        self._update_folder_display()
        return True

    def _select_shortcut_folder(self, folder_name: str) -> None:
        """Handle clicking [Downloads], [Desktop], or [Documents]."""
        candidate = resolve_user_folder(folder_name)
        self._try_set_target_folder(candidate, shortcut_name=folder_name)

    def _browse_custom_folder(self) -> None:
        """Handle clicking [Browse Other Folder...] with immediate security validation."""
        initial = (
            str(self.current_folder)
            if self.current_folder.exists()
            else str(Path.home())
        )
        chosen = filedialog.askdirectory(
            parent=self.root,
            initialdir=initial,
            title="Choose a Folder to Organize",
        )
        if chosen:
            self._try_set_target_folder(Path(chosen), shortcut_name="")

    def _update_folder_display(self) -> None:
        """Update Step 1 button highlights, folder label, and refresh Step 2 badges."""
        for name, btn in self.shortcut_buttons.items():
            if name == self.active_shortcut:
                btn.set_colors(
                    self.PILL_ACTIVE_BG,
                    self.PILL_ACTIVE_HOVER,
                    self.PILL_ACTIVE_FG,
                )
            else:
                btn.set_colors(
                    self.PILL_INACTIVE_BG,
                    self.PILL_INACTIVE_HOVER,
                    self.PILL_INACTIVE_FG,
                )

        friendly_name = self.current_folder.name or str(self.current_folder)
        self.current_folder_label.configure(
            text=f"Currently organizing: {friendly_name}"
        )

        self._show_banner("")
        self._run_safe_preview(show_error_modal=False)

    # ==========================================================================
    # STEP 2 (SAFE PREVIEW) & STEP 3 (ORGANIZE MY FILES)
    # ==========================================================================

    def _scan_eligible_files(
        self,
    ) -> Tuple[List[Tuple[Path, str]], List[str], str]:
        """
        Scan only loose top-level files in the selected folder while enforcing:
        - OS-specific Critical System Path Blacklisting
        - Cross-platform Hidden & System Metadata Filtering
        - Filename Sanitization, ADS blocking & Reserved Device Name filtering
        - Symlink, NTFS Junction & Reparse Point exclusion
        - Per-entry exception isolation
        """
        is_blocked, _reason = is_protected_system_path(self.current_folder)
        if is_blocked:
            return [], [], PROTECTED_FOLDER_MESSAGE

        if not self.current_folder.exists() or not self.current_folder.is_dir():
            return (
                [],
                [],
                "We couldn't find that folder on your computer. Please choose another folder in Step 1.",
            )

        try:
            entries = sorted(
                self.current_folder.iterdir(), key=lambda p: p.name.lower()
            )
        except PermissionError:
            return (
                [],
                [],
                "Access to this folder was denied by your operating system. Please choose one of your personal folders.",
            )
        except (OSError, ValueError):
            return (
                [],
                [],
                "Something went wrong while opening this folder. Please try choosing another folder.",
            )

        eligible_items: List[Tuple[Path, str]] = []
        security_notes: List[str] = []

        for item in entries:
            try:
                if is_symlink_or_junction(item):
                    security_notes.append(
                        f"Skipped '{item.name}' (symbolic link or junction point ignored for safety)."
                    )
                    continue

                lstat_info = os.lstat(item)
                if stat.S_ISDIR(lstat_info.st_mode) or not stat.S_ISREG(
                    lstat_info.st_mode
                ):
                    continue

                if should_ignore_file(item, self.script_path):
                    continue

                is_safe, sanitized_name, block_reason = inspect_and_sanitize_filename(
                    item.name
                )
                if not is_safe:
                    security_notes.append(
                        f"Blocked '{item.name}' ({block_reason})."
                    )
                    continue

                eligible_items.append((item, sanitized_name))

            except (PermissionError, OSError, ValueError):
                continue

        return eligible_items, security_notes, ""

    def _run_safe_preview(self, show_error_modal: bool = True) -> None:
        """Step 2: Populate the visual category summary badges without moving anything."""
        eligible_items, security_notes, error_msg = self._scan_eligible_files()

        if error_msg:
            if show_error_modal:
                if error_msg == PROTECTED_FOLDER_MESSAGE:
                    messagebox.showerror(
                        "Protected System Folder", error_msg, parent=self.root
                    )
                else:
                    messagebox.showwarning(
                        "Cannot Open Folder", error_msg, parent=self.root
                    )
            else:
                self.preview_summary_label.configure(
                    text=error_msg,
                    fg=self.TEXT_SECONDARY,
                    font=(UI_FONT, 10),
                )
                self._render_category_badges({})
                self._set_advanced_details([])
            return

        category_counts: Dict[str, int] = {}
        preview_details: List[str] = []
        reserved_destinations: Set[str] = set()

        for file_path, sanitized_name in eligible_items:
            category = get_category_for_filename(sanitized_name)
            dest_dir = self.current_folder / category
            safe_dest = get_safe_destination_path(
                dest_dir, sanitized_name, reserved_destinations
            )

            if not verify_path_containment(self.current_folder, dest_dir, safe_dest):
                security_notes.append(
                    f"Blocked '{file_path.name}' (failed path containment check)."
                )
                continue

            reserved_destinations.add(os.path.normcase(str(safe_dest)))
            category_counts[category] = category_counts.get(category, 0) + 1

            if safe_dest.name != file_path.name:
                preview_details.append(
                    f"• Will move '{file_path.name}' into {category} (as '{safe_dest.name}')"
                )
            else:
                preview_details.append(
                    f"• Will move '{file_path.name}' into {category}"
                )

        summary_sentence = build_friendly_preview_sentence(category_counts)
        self.preview_summary_label.configure(
            text=summary_sentence,
            fg=self.TEXT_PRIMARY if category_counts else self.TEXT_SECONDARY,
            font=(UI_FONT, 10, "bold" if category_counts else "normal"),
        )

        self._render_category_badges(category_counts)
        self._set_advanced_details(preview_details + security_notes)

    def _run_organize_files(self) -> None:
        """Step 3: Move loose files into neat category subfolders with full security verification."""
        eligible_items, security_notes, error_msg = self._scan_eligible_files()

        if error_msg:
            if error_msg == PROTECTED_FOLDER_MESSAGE:
                messagebox.showerror(
                    "Protected System Folder", error_msg, parent=self.root
                )
            else:
                messagebox.showwarning(
                    "Cannot Open Folder", error_msg, parent=self.root
                )
            return

        if not eligible_items:
            self._show_banner(
                "🎉 All clean! This folder is already neat and tidy.",
                is_success=True,
                warnings=security_notes,
            )
            return

        moved_count = 0
        moved_counts_by_cat: Dict[str, int] = {}
        reserved_destinations: Set[str] = set()
        moved_details: List[str] = []
        skipped_warnings: List[str] = list(security_notes)

        for file_path, sanitized_name in eligible_items:
            try:
                category = get_category_for_filename(sanitized_name)
                category_dir = self.current_folder / category
                safe_dest = get_safe_destination_path(
                    category_dir, sanitized_name, reserved_destinations
                )

                success, warn_msg = atomic_verified_move(
                    source_path=file_path,
                    dest_path=safe_dest,
                    base_dir=self.current_folder,
                    category_dir=category_dir,
                )

                if success:
                    reserved_destinations.add(os.path.normcase(str(safe_dest)))
                    moved_count += 1
                    moved_counts_by_cat[category] = (
                        moved_counts_by_cat.get(category, 0) + 1
                    )
                    if safe_dest.name != file_path.name:
                        moved_details.append(
                            f"✓ Moved '{file_path.name}' into {category} (saved as '{safe_dest.name}')"
                        )
                    else:
                        moved_details.append(
                            f"✓ Moved '{file_path.name}' into {category}"
                        )
                else:
                    if warn_msg:
                        skipped_warnings.append(warn_msg)

            except (PermissionError, OSError, ValueError) as exc:
                skipped_warnings.append(
                    f"Skipped {file_path.name} ({exc.__class__.__name__})."
                )

        file_word = "file" if moved_count == 1 else "files"
        if moved_count > 0:
            banner_text = (
                f"🎉 All clean! {moved_count} {file_word} organized successfully."
            )
            self.preview_summary_label.configure(
                text=f"Sorted {moved_count} {file_word} into these folders:",
                fg=self.TEXT_PRIMARY,
                font=(UI_FONT, 10, "bold"),
            )
            self._render_category_badges(moved_counts_by_cat)
            self._show_banner(
                banner_text, is_success=True, warnings=skipped_warnings
            )
        else:
            self._show_banner(
                "No files were moved because they are currently open or protected.",
                is_success=False,
                warnings=skipped_warnings,
            )

        self._set_advanced_details(moved_details + skipped_warnings)


def main() -> None:
    """Start the Easy File Organizer desktop app."""
    root = tk.Tk()
    FriendlyFileOrganizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
