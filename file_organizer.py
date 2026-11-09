"""
Easy File Organizer (Cross-Platform Security-Hardened Edition)
==============================================================
A modern, responsive, beginner-friendly desktop utility for Windows, macOS, and Linux
that sorts loose files into neat category subfolders in 3 simple steps, backed by
dynamic folder queue prioritization and enterprise-grade security controls.

Features & Security Controls Implemented:
1. Dynamic "Messy Folders" Queue & Auto-Prioritization:
   - Automatically scans candidate folders (Downloads, Desktop, Documents, plus any
     custom folders added by the user) and counts loose, unsorted files in each.
   - Dynamically ranks folders so the messiest directories rise to the front of the
     queue with live count badges (e.g., `[📥 Downloads (15)]`, `[🖥️ Desktop (4)]`),
     while already-clean folders (`0` loose files) are demoted to the end of the line.
   - Automatically focuses the messiest folder on launch and auto-advances to the
     next messy folder in the queue as soon as the current folder is organized!
2. Responsive Resizable Layout:
   - Freely resizable (`860x730` default, `720x620` minimum) using responsive Tkinter
     grid weights so step cards scale smoothly and the bottom details log expands
     vertically to utilize extra screen space.
3. Custom Embedded App & Taskbar Icon:
   - Generates a crisp, self-contained PNG folder/organizer icon in memory using
     only standard library (`zlib`, `struct`, `base64`) and sets the Windows
     `AppUserModelID` so both title bar and taskbar show the custom icon.
4. "Undo Last Organize" & "Auto-Sort" Background Watcher:
   - Full transaction reversal (`[↩ Undo Last Organize]`) with conflict protection.
   - Live background watcher thread with download-stability delay (`1.5s`).
5. Cross-Platform & Enterprise Security Hardening:
   - OS-specific blacklists (Windows, macOS, Linux), `os.path.commonpath` containment,
     symlink/junction defense, Unicode RLO (`\\u202E`) stripping, ADS (`:`) blocking,
     Reserved Device Name filtering, and a strict zero-deletion/zero-overwrite guarantee.

Uses only the Python standard library:
base64, ctypes, os, pathlib, platform, shutil, stat, struct, threading, time, tkinter, typing, zlib.
"""

import base64
import ctypes
import os
from pathlib import Path
import platform
import shutil
import stat
import struct
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Dict, List, Optional, Set, Tuple
import zlib


# ==============================================================================
# 1. OPERATING SYSTEM DETECTION, APP ID & EMBEDDED ICON GENERATOR
# ==============================================================================

CURRENT_OS: str = platform.system()

if CURRENT_OS == "Windows":
    UI_FONT: str = "Segoe UI"
elif CURRENT_OS == "Darwin":
    UI_FONT = "Helvetica Neue"
else:
    UI_FONT = "DejaVu Sans"

APP_USER_MODEL_ID: str = "EasyFileOrganizer.Desktop.Utility.3"


def set_windows_app_user_model_id() -> None:
    """
    Register an explicit Windows AppUserModelID so the Windows 10/11 taskbar
    displays our custom organizer icon instead of the default Python logo.
    """
    if CURRENT_OS == "Windows":
        try:
            if hasattr(ctypes, "windll") and hasattr(ctypes.windll, "shell32"):
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    APP_USER_MODEL_ID
                )
        except (OSError, AttributeError, ValueError):
            pass


def build_embedded_icon_png_base64(size: int = 64) -> str:
    """
    Generate a crisp, modern folder-organizer PNG icon in memory using only
    `struct`, `zlib`, and `base64` (100% standalone, no external image files).
    """
    rows: List[bytes] = []
    scale = size / 64.0

    for y in range(size):
        row = bytearray([0])  # PNG filter type 0 (None)
        fy = y / scale
        for x in range(size):
            fx = x / scale
            r, g, b, a = 0, 0, 0, 0

            in_tab = (8 <= fx <= 28) and (10 <= fy <= 20)
            in_back = (6 <= fx <= 58) and (16 <= fy <= 54)
            in_doc = (16 <= fx <= 48) and (13 <= fy <= 32)
            in_flap = (6 <= fx <= 58) and (25 <= fy <= 54)

            if in_tab or in_back:
                r, g, b, a = 29, 78, 216, 255

            if in_doc:
                if (22 <= fx <= 42) and (int(fy) in (18, 22)):
                    r, g, b, a = 147, 197, 253, 255
                else:
                    r, g, b, a = 255, 255, 255, 255

            if in_flap:
                shade = int((fy - 25) * 0.9)
                r = max(37 - shade // 2, 25)
                g = max(115 - shade, 85)
                b = min(246, 235)
                a = 255

            dx = fx - 46.0
            dy = fy - 42.0
            dist_sq = dx * dx + dy * dy
            if dist_sq <= 121.0:
                r, g, b, a = 16, 185, 129, 255
                if (
                    abs((fx - 41) - (fy - 41)) <= 1.8 and 41 <= fx <= 45 and 41 <= fy <= 45
                ) or (
                    abs((fx - 45) + (fy - 45)) <= 1.8 and 45 <= fx <= 52 and 38 <= fy <= 45
                ):
                    r, g, b, a = 255, 255, 255, 255

            row.extend((r, g, b, a))
        rows.append(bytes(row))

    raw_data = b"".join(rows)

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)
    idat = zlib.compress(raw_data, level=9)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + make_chunk(b"IHDR", ihdr)
        + make_chunk(b"IDAT", idat)
        + make_chunk(b"IEND", b"")
    )
    return base64.b64encode(png_bytes).decode("ascii")


def apply_app_icon(root: tk.Tk) -> List[tk.PhotoImage]:
    """Attach the embedded 64x64 and 32x32 custom icons to the Tk window."""
    icons: List[tk.PhotoImage] = []
    try:
        icon_64 = tk.PhotoImage(data=build_embedded_icon_png_base64(64))
        icon_32 = tk.PhotoImage(data=build_embedded_icon_png_base64(32))
        root.iconphoto(True, icon_64, icon_32)
        icons.extend([icon_64, icon_32])
    except tk.TclError:
        pass
    return icons


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

# Friendly icons for standard user folders in the dynamic queue
FOLDER_ICONS: Dict[str, str] = {
    "downloads": "📥",
    "desktop": "🖥️",
    "documents": "📄",
}


# ==============================================================================
# 3. SECURITY & METADATA FILTER CONSTANTS
# ==============================================================================

PROTECTED_FOLDER_MESSAGE: str = (
    "Protected System Folder: Organizing this directory is blocked to protect your operating system."
)

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

IGNORED_TEMP_EXTENSIONS: Set[str] = {
    ".tmp",
    ".temp",
    ".crdownload",
    ".part",
    ".partial",
    ".download",
    ".opdownload",
    ".swp",
    ".swo",
    ".swn",
    ".lnk",
    ".url",
    ".webloc",
    ".desktop",
}

FILE_ATTRIBUTE_HIDDEN: int = 0x0002
FILE_ATTRIBUTE_SYSTEM: int = 0x0004
FILE_ATTRIBUTE_REPARSE_POINT: int = 0x0400
UF_HIDDEN: int = 0x8000

WINDOWS_RESERVED_NAMES: Set[str] = {
    "CON", "PRN", "AUX", "NUL",
    "CONIN$", "CONOUT$", "CLOCK$",
    *(f"COM{i}" for i in range(0, 10)),
    *(f"LPT{i}" for i in range(0, 10)),
}

UNICODE_SPOOFING_CHARS: Set[str] = {
    "\u202e", "\u202d", "\u202a", "\u202b", "\u202c",
    "\u2066", "\u2067", "\u2068", "\u2069",
    "\u200e", "\u200f", "\u200b", "\u200c", "\u200d", "\ufeff",
}

FORBIDDEN_FILENAME_CHARS: Set[str] = set('<>:"/\\|?*')

WATCHER_POLL_INTERVAL_SEC: float = 0.6
WATCHER_STABILITY_WINDOW_SEC: float = 1.5


# ==============================================================================
# 4. CROSS-PLATFORM FOLDER RESOLUTION (WINDOWS / MACOS / LINUX XDG)
# ==============================================================================

def _parse_linux_xdg_user_dirs(home: Path) -> Dict[str, Path]:
    """
    Parse Linux XDG user directories from `$XDG_CONFIG_HOME/user-dirs.dirs`
    (defaulting to `~/.config/user-dirs.dirs`).
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
    Reliably resolve 'Downloads', 'Desktop', and 'Documents' across Windows
    (including OneDrive redirection), macOS, and Linux (XDG user-dirs).
    """
    home = Path.home()
    direct_path = home / folder_name

    if current_os == "Windows":
        if direct_path.exists():
            return direct_path
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

    return direct_path


# ==============================================================================
# 5. ENTERPRISE CROSS-PLATFORM SECURITY CONTROLS
# ==============================================================================

def is_running_with_elevated_privileges(current_os: str = CURRENT_OS) -> bool:
    """
    Detect Administrator on Windows (`ctypes.windll.shell32.IsUserAnAdmin()`)
    and `root` on macOS/Linux (`os.geteuid() == 0`).
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
    Return True if `path` is a symbolic link, NTFS junction point, mount point,
    or carries the Windows FILE_ATTRIBUTE_REPARSE_POINT bit. Never follows links.
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
    Dynamically enforce system folder blacklists for Windows, macOS, and Linux,
    and prevent organizing the root user home directory on all platforms.
    """
    raw_str = str(target_path).strip()
    if not raw_str:
        return True, "Empty directory path."

    try:
        if target_path.exists() and is_symlink_or_junction(target_path):
            return True, "Symbolic links and junction directories are blocked."
        resolved = target_path.resolve() if target_path.exists() else target_path
    except (OSError, ValueError, RuntimeError):
        return True, "Could not safely resolve directory path."

    norm_target = _normalize_path_str(str(resolved), current_os)

    if norm_target in ("/", "\\") or (
        len(norm_target) in (2, 3)
        and norm_target[1:2] == ":"
        and norm_target[2:] in ("", "\\", "/")
    ):
        return True, "Root filesystem directories cannot be organized."

    if resolved.parent == resolved:
        return True, "Root filesystem directories cannot be organized."

    try:
        home = Path.home()
        norm_home = _normalize_path_str(str(home), current_os)
        norm_home_parent = _normalize_path_str(str(home.parent), current_os)
        if norm_target in (norm_home, norm_home_parent):
            return True, "Organizing the root user directory is blocked."
    except (OSError, ValueError):
        home = None

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

        parts = [p for p in norm_target.split("/") if p]
        if parts == ["Users"] or (len(parts) == 2 and parts[0] == "Users"):
            return True, "Protected macOS /Users root directory."
        if len(parts) >= 3 and parts[0] == "Users" and parts[2] == "Library":
            return True, "Protected macOS ~/Library directory."

    else:
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
    """Check if a filename matches a reserved Windows device name (CON, PRN, AUX, NUL, etc.)."""
    trimmed = filename.strip(" .")
    if not trimmed:
        return True

    first_token = trimmed.split(".")[0].upper()
    stem_token = Path(trimmed).stem.upper()
    return first_token in WINDOWS_RESERVED_NAMES or stem_token in WINDOWS_RESERVED_NAMES


def inspect_and_sanitize_filename(raw_name: str) -> Tuple[bool, str, str]:
    """
    Inspect and sanitize a filename against ADS (':'), path traversal ('..', '/', '\\'),
    Unicode Bidirectional Override spoofing ('\\u202E'), and Windows Reserved Device Names.
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
    Prevent `shutil.move` from falling back to non-atomic copy+delete when a
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
    Execute an atomic, non-overwriting file move from `source_path` into
    `category_dir / dest_path.name` with TOCTOU and post-move size/inode verification.
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


def atomic_verified_restore(
    moved_path: Path,
    restore_dest: Path,
    base_dir: Path,
    current_os: str = CURRENT_OS,
) -> Tuple[bool, str]:
    """
    Safely move a sorted file from its category subfolder (`moved_path`) back to
    the root target folder (`restore_dest`) for the "Undo Last Organize" feature.
    """
    try:
        if not moved_path.exists() or is_symlink_or_junction(moved_path):
            return (
                False,
                f"Could not restore '{moved_path.name}' (file was already moved or modified).",
            )

        category_dir = moved_path.parent
        if not verify_path_containment(base_dir, category_dir, moved_path):
            return (
                False,
                f"Blocked restore of '{moved_path.name}': Outside target folder.",
            )

        if restore_dest.resolve().parent != base_dir.resolve():
            return (
                False,
                f"Blocked restore of '{moved_path.name}': Invalid restore destination.",
            )

        if current_os != "Windows":
            if not os.access(moved_path, os.W_OK) or not os.access(base_dir, os.W_OK):
                return (
                    False,
                    f"Skipped restoring '{moved_path.name}' (write permission denied).",
                )

        pre_stat = os.lstat(moved_path)
        if not stat.S_ISREG(pre_stat.st_mode):
            return (
                False,
                f"Skipped restoring '{moved_path.name}' (not a regular file).",
            )

        expected_size = pre_stat.st_size
        expected_ino = pre_stat.st_ino

        if restore_dest.exists():
            return (
                False,
                f"Skipped restoring '{moved_path.name}' to avoid overwriting.",
            )

        shutil.move(
            str(moved_path),
            str(restore_dest),
            copy_function=_disallow_copy_fallback,
        )

        post_stat = os.lstat(restore_dest)
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
                f"Warning: '{restore_dest.name}' verification mismatch after undo.",
            )

        return True, ""

    except PermissionError:
        return (
            False,
            f"Could not restore '{moved_path.name}' because it is open in another app.",
        )
    except (OSError, ValueError):
        return (
            False,
            f"Could not restore '{moved_path.name}' because it is in use.",
        )


# ==============================================================================
# 6. PLATFORM-SPECIFIC SYSTEM & HIDDEN FILE FILTERING
# ==============================================================================

def should_ignore_filename_by_rules(
    filename: str, current_os: str = CURRENT_OS
) -> bool:
    """
    Filter out OS metadata and temporary/in-progress download files across
    Windows, macOS, and Linux.
    """
    if not filename:
        return True

    lower_name = filename.lower()

    if filename.startswith("."):
        return True

    if filename.startswith("~$"):
        return True

    if filename.endswith("~") or (
        filename.startswith("#") and filename.endswith("#")
    ):
        return True

    if lower_name in ALL_IGNORED_FILENAMES:
        return True

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
            win_attrs = getattr(lstat_info, "st_file_attributes", 0)
            if win_attrs & (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM):
                return True

            bsd_flags = getattr(lstat_info, "st_flags", 0)
            if bsd_flags & UF_HIDDEN:
                return True
    except (OSError, ValueError):
        return True

    return False


def count_eligible_loose_files(directory: Path, script_path: Path) -> int:
    """
    Quickly count how many loose, unsorted eligible files exist at the top level
    of `directory` for the dynamic folder queue ranking system.
    """
    is_blocked, _ = is_protected_system_path(directory)
    if is_blocked or not directory.exists() or not directory.is_dir():
        return 0

    count = 0
    try:
        for item in directory.iterdir():
            try:
                if is_symlink_or_junction(item):
                    continue
                lstat_info = os.lstat(item)
                if stat.S_ISDIR(lstat_info.st_mode) or not stat.S_ISREG(
                    lstat_info.st_mode
                ):
                    continue
                if should_ignore_file(item, script_path):
                    continue
                is_safe, _, _ = inspect_and_sanitize_filename(item.name)
                if is_safe:
                    count += 1
            except (PermissionError, OSError, ValueError):
                continue
    except (PermissionError, OSError, ValueError):
        return 0

    return count


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
# 7. CUSTOM ROUNDED BUTTON WIDGET (WITH DYNAMIC TEXT & COLOR UPDATES)
# ==============================================================================

class RoundedButton(tk.Canvas):
    """
    A modern, rounded-corner button built on tk.Canvas that renders consistently
    across Windows, macOS, and Linux, supporting enabled/disabled states and
    dynamic label updates.
    """

    DISABLED_BG = "#E2E8F0"
    DISABLED_FG = "#94A3B8"

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
        enabled: bool = True,
    ) -> None:
        super().__init__(
            parent,
            width=width,
            height=height,
            bg=canvas_bg,
            highlightthickness=0,
            bd=0,
            cursor="hand2" if enabled else "arrow",
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
        self.enabled = enabled
        self._current_bg = bg_color if enabled else self.DISABLED_BG

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
        c = self._current_bg if self.enabled else self.DISABLED_BG
        fg = self.fg_color if self.enabled else self.DISABLED_FG

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
            fill=fg,
            font=self.font,
        )

    def set_text(self, text: str, width: Optional[int] = None) -> None:
        """Update button label and optionally resize button width."""
        self.text = text
        if width is not None and width != self.btn_width:
            self.btn_width = width
            self.configure(width=width)
        self._draw()

    def set_enabled(self, enabled: bool) -> None:
        """Enable or disable the button visually and functionally."""
        self.enabled = enabled
        self._current_bg = self.bg_color if enabled else self.DISABLED_BG
        self.configure(cursor="hand2" if enabled else "arrow")
        self._draw()

    def set_colors(self, bg_color: str, hover_color: str, fg_color: str) -> None:
        """Update button palette (e.g., when highlighting the active folder button)."""
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.fg_color = fg_color
        self._current_bg = bg_color if self.enabled else self.DISABLED_BG
        self._draw()

    def _on_enter(self, _event) -> None:
        if self.enabled:
            self._current_bg = self.hover_color
            self._draw()

    def _on_leave(self, _event) -> None:
        if self.enabled:
            self._current_bg = self.bg_color
            self._draw()

    def _on_click(self, event) -> None:
        if not self.enabled:
            return
        if 0 <= event.x <= self.btn_width and 0 <= event.y <= self.btn_height:
            if callable(self.command):
                self.command()


# ==============================================================================
# 8. RESPONSIVE 3-STEP APPLICATION WITH DYNAMIC MESSY FOLDER QUEUE
# ==============================================================================

class FriendlyFileOrganizerApp:
    """
    Responsive, modern 3-step file organizer featuring dynamic folder queue
    prioritization, auto-progression, undo support, and a live auto-sort watcher.
    """

    BG_WINDOW = "#F4F6F8"
    BG_CARD = "#FFFFFF"
    BORDER_CARD = "#E2E8F0"
    TEXT_PRIMARY = "#0F172A"
    TEXT_SECONDARY = "#475569"

    # Active selected folder pill
    PILL_ACTIVE_BG = "#2563EB"
    PILL_ACTIVE_HOVER = "#1D4ED8"
    PILL_ACTIVE_FG = "#FFFFFF"

    # Unselected folder pill with messy files waiting (> 0)
    PILL_MESSY_BG = "#EFF6FF"
    PILL_MESSY_HOVER = "#DBEAFE"
    PILL_MESSY_FG = "#1E40AF"

    # Demoted clean folder pill (0 loose files)
    PILL_CLEAN_BG = "#F1F5F9"
    PILL_CLEAN_HOVER = "#E2E8F0"
    PILL_CLEAN_FG = "#64748B"

    # Browse / Add Folder button
    PILL_BROWSE_BG = "#F8FAFC"
    PILL_BROWSE_HOVER = "#E2E8F0"
    PILL_BROWSE_FG = "#334155"

    PREVIEW_BTN_BG = "#3B82F6"
    PREVIEW_BTN_HOVER = "#2563EB"

    ORGANIZE_BTN_BG = "#10B981"
    ORGANIZE_BTN_HOVER = "#059669"

    UNDO_BTN_BG = "#475569"
    UNDO_BTN_HOVER = "#334155"

    # Default & minimum window dimensions (freely resizable)
    WINDOW_DEFAULT_WIDTH = 860
    WINDOW_DEFAULT_HEIGHT = 730
    WINDOW_MIN_WIDTH = 720
    WINDOW_MIN_HEIGHT = 620

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Easy File Organizer")
        self.root.configure(bg=self.BG_WINDOW)

        # Requirement 2: Make the window freely resizable with comfortable minsize
        self.root.resizable(True, True)
        self.root.minsize(self.WINDOW_MIN_WIDTH, self.WINDOW_MIN_HEIGHT)

        # Attach embedded custom organizer icon
        self._icon_refs = apply_app_icon(self.root)

        # Center the window on launch
        self._center_window(self.WINDOW_DEFAULT_WIDTH, self.WINDOW_DEFAULT_HEIGHT)

        # Remember this script's path so it never moves itself
        try:
            self.script_path = Path(__file__).resolve()
        except (NameError, OSError):
            self.script_path = Path.cwd() / "file_organizer.py"

        # Requirement 1: Dynamic Candidate Folder Queue
        self.candidate_folders: List[Path] = []
        for default_name in ("Downloads", "Desktop", "Documents"):
            resolved_dir = resolve_user_folder(default_name)
            self._add_candidate_folder_internal(resolved_dir)

        self.folder_loose_counts: Dict[str, int] = {}
        self.ranked_folders: List[Path] = list(self.candidate_folders)
        self.queue_buttons: Dict[str, RoundedButton] = {}

        # Scan & rank folders on startup, and auto-focus the messiest folder first
        self._recalculate_folder_rankings()
        self.current_folder: Path = (
            self.ranked_folders[0]
            if self.ranked_folders
            else resolve_user_folder("Downloads")
        )

        self.details_expanded: bool = False
        self.running_elevated: bool = is_running_with_elevated_privileges()

        # Undo Transaction Log [(moved_dest_path, original_source_path), ...]
        self.last_transaction: List[Tuple[Path, Path]] = []

        # Live Auto-Sort Background Watcher State
        self.auto_sort_var = tk.BooleanVar(value=False)
        self._auto_sort_enabled: bool = False
        self._op_lock = threading.Lock()
        self._watcher_stop_event = threading.Event()
        self._watcher_thread: Optional[threading.Thread] = None
        self._watched_file_states: Dict[Path, Tuple[int, int, float]] = {}
        self._pending_auto_sorted: List[Tuple[Path, Path, str]] = []

        self._build_ui()
        self._refresh_folder_queue_ui()
        self._update_folder_display()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self) -> None:
        """Stop background watcher cleanly before closing the window."""
        self._watcher_stop_event.set()
        self.root.destroy()

    def _center_window(self, width: int, height: int) -> None:
        """Position the window comfortably in the center of the monitor."""
        self.root.update_idletasks()
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        x = max((screen_w - width) // 2, 20)
        y = max((screen_h - height) // 2 - 20, 20)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    # ==========================================================================
    # DYNAMIC "MESSY FOLDERS" QUEUE & AUTO-PRIORITIZATION ENGINE
    # ==========================================================================

    def _folder_key(self, folder: Path) -> str:
        """Return a normalized key string for deduplicating and indexing a folder."""
        return _normalize_path_str(str(folder), CURRENT_OS)

    def _add_candidate_folder_internal(self, folder: Path) -> bool:
        """Add `folder` to `self.candidate_folders` if not already present."""
        key = self._folder_key(folder)
        for existing in self.candidate_folders:
            if self._folder_key(existing) == key:
                return False
        self.candidate_folders.append(folder)
        return True

    def _recalculate_folder_rankings(self) -> None:
        """
        Scan all candidate folders, count loose unsorted files in each, and sort
        `self.ranked_folders` so messy folders (> 0 files) rise to the front in
        descending order of messiness while clean folders (0 files) are demoted
        to the end of the line.
        """
        counts: Dict[str, int] = {}
        for folder in self.candidate_folders:
            key = self._folder_key(folder)
            counts[key] = count_eligible_loose_files(folder, self.script_path)

        self.folder_loose_counts = counts

        # Sort by:
        # 1. Whether folder has loose files (messy first, clean demoted to end)
        # 2. Descending loose file count (messiest first)
        # 3. Original insertion index (stable tie-breaker)
        indexed = list(enumerate(self.candidate_folders))
        indexed.sort(
            key=lambda pair: (
                0 if counts.get(self._folder_key(pair[1]), 0) > 0 else 1,
                -counts.get(self._folder_key(pair[1]), 0),
                pair[0],
            )
        )
        self.ranked_folders = [pair[1] for pair in indexed]

    def _get_folder_button_label(self, folder: Path, count: int) -> str:
        """Format the dynamic folder pill text with icon and count badge."""
        name = folder.name or str(folder)
        icon = FOLDER_ICONS.get(name.lower(), "📁")
        if count > 0:
            return f"{icon} {name} ({count})"
        return f"✓ {name} (0)"

    def _refresh_folder_queue_ui(self) -> None:
        """
        Rebuild the Step 1 dynamic folder queue buttons in ranked order
        (messiest folders first, clean folders demoted to the end, followed by
        [📂 Browse / Add Folder...]).
        """
        for child in self.queue_container.winfo_children():
            child.destroy()
        self.queue_buttons.clear()

        active_key = self._folder_key(self.current_folder)

        for folder in self.ranked_folders:
            key = self._folder_key(folder)
            count = self.folder_loose_counts.get(key, 0)
            label_text = self._get_folder_button_label(folder, count)
            btn_width = max(138, min(240, len(label_text) * 8 + 28))

            is_active = key == active_key
            if is_active:
                bg, hover, fg = (
                    self.PILL_ACTIVE_BG,
                    self.PILL_ACTIVE_HOVER,
                    self.PILL_ACTIVE_FG,
                )
            elif count > 0:
                bg, hover, fg = (
                    self.PILL_MESSY_BG,
                    self.PILL_MESSY_HOVER,
                    self.PILL_MESSY_FG,
                )
            else:
                bg, hover, fg = (
                    self.PILL_CLEAN_BG,
                    self.PILL_CLEAN_HOVER,
                    self.PILL_CLEAN_FG,
                )

            btn = RoundedButton(
                self.queue_container,
                text=label_text,
                width=btn_width,
                height=36,
                corner_radius=10,
                bg_color=bg,
                hover_color=hover,
                fg_color=fg,
                font=(UI_FONT, 9, "bold"),
                canvas_bg=self.BG_CARD,
                command=lambda target=folder: self._select_queued_folder(target),
            )
            btn.pack(side=tk.LEFT, padx=(0, 8), pady=3)
            self.queue_buttons[key] = btn

        self.browse_btn = RoundedButton(
            self.queue_container,
            text="📂 Browse / Add Folder...",
            width=185,
            height=36,
            corner_radius=10,
            bg_color=self.PILL_BROWSE_BG,
            hover_color=self.PILL_BROWSE_HOVER,
            fg_color=self.PILL_BROWSE_FG,
            font=(UI_FONT, 9, "bold"),
            canvas_bg=self.BG_CARD,
            command=self._browse_custom_folder,
        )
        self.browse_btn.pack(side=tk.LEFT, padx=(0, 4), pady=3)

    # ==========================================================================
    # RESPONSIVE UI CONSTRUCTION (GRID WEIGHTS & DYNAMIC WRAPLENGTH)
    # ==========================================================================

    def _create_card(
        self, parent: tk.Widget, row: int, pady: tuple = (0, 10), sticky: str = "ew"
    ) -> tk.Frame:
        """Create a crisp white panel card placed in the responsive grid."""
        card = tk.Frame(
            parent,
            bg=self.BG_CARD,
            highlightbackground=self.BORDER_CARD,
            highlightthickness=1,
            padx=20,
            pady=14,
        )
        card.grid(row=row, column=0, sticky=sticky, pady=pady)
        card.columnconfigure(0, weight=1)
        return card

    def _build_ui(self) -> None:
        """
        Build the responsive 3-step visual interface using Tkinter grid weights
        so cards scale horizontally and the bottom log expands vertically.
        """
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.main_column = tk.Frame(self.root, bg=self.BG_WINDOW, padx=26, pady=14)
        self.main_column.grid(row=0, column=0, sticky="nsew")
        self.main_column.columnconfigure(0, weight=1)
        # Row 5 (details drawer) expands vertically when window is resized/maximized
        self.main_column.rowconfigure(5, weight=1)

        # --- Row 0: App Header ---
        header = tk.Frame(self.main_column, bg=self.BG_WINDOW)
        header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        header.columnconfigure(0, weight=1)

        tk.Label(
            header,
            text="Easy File Organizer",
            font=(UI_FONT, 16, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_WINDOW,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew")

        os_label = "macOS" if CURRENT_OS == "Darwin" else CURRENT_OS
        sub_text = (
            f"Smart Priority Queue ({os_label}) — Messiest folders automatically come first."
        )
        if self.running_elevated:
            priv_name = "Administrator" if CURRENT_OS == "Windows" else "root"
            sub_text += f"  •  🛡️ Running as {priv_name} (standard user recommended)."

        tk.Label(
            header,
            text=sub_text,
            font=(UI_FONT, 9),
            fg=self.TEXT_SECONDARY,
            bg=self.BG_WINDOW,
            anchor="w",
        ).grid(row=1, column=0, sticky="ew", pady=(1, 0))

        # ======================================================================
        # ROW 1 — STEP 1: DYNAMIC MESSY FOLDERS QUEUE
        # ======================================================================
        step1_card = self._create_card(self.main_column, row=1)

        step1_header = tk.Frame(step1_card, bg=self.BG_CARD)
        step1_header.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        step1_header.columnconfigure(0, weight=1)

        tk.Label(
            step1_header,
            text="Step 1: Where are your messy files? (Auto-prioritized by messiness)",
            font=(UI_FONT, 11, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        # Dynamic folder queue container
        self.queue_container = tk.Frame(step1_card, bg=self.BG_CARD)
        self.queue_container.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        self.current_folder_label = tk.Label(
            step1_card,
            text="Currently organizing: Downloads",
            font=(UI_FONT, 11, "bold"),
            fg=self.PILL_ACTIVE_BG,
            bg=self.BG_CARD,
            anchor="w",
        )
        self.current_folder_label.grid(row=2, column=0, sticky="ew")

        # ======================================================================
        # ROW 2 — STEP 2: SAFE PREVIEW & VISUAL CATEGORY SUMMARY CARDS
        # ======================================================================
        step2_card = self._create_card(self.main_column, row=2)

        step2_top = tk.Frame(step2_card, bg=self.BG_CARD)
        step2_top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        step2_top.columnconfigure(0, weight=1)

        tk.Label(
            step2_top,
            text="Step 2: Safe Preview",
            font=(UI_FONT, 11, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD,
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

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
        self.preview_btn.grid(row=0, column=1, sticky="e")

        self.preview_summary_label = tk.Label(
            step2_card,
            text="Checking folder...",
            font=(UI_FONT, 10),
            fg=self.TEXT_SECONDARY,
            bg=self.BG_CARD,
            wraplength=760,
            justify=tk.LEFT,
            anchor="w",
        )
        self.preview_summary_label.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        self.badges_container = tk.Frame(step2_card, bg=self.BG_CARD)
        self.badges_container.grid(row=2, column=0, sticky="ew")

        # ======================================================================
        # ROW 3 — STEP 3: ORGANIZE, UNDO & LIVE AUTO-SORT WATCHER
        # ======================================================================
        step3_card = self._create_card(self.main_column, row=3, pady=(0, 6))

        tk.Label(
            step3_card,
            text="Step 3: Organize",
            font=(UI_FONT, 11, "bold"),
            fg=self.TEXT_PRIMARY,
            bg=self.BG_CARD,
            anchor="w",
        ).grid(row=0, column=0, sticky="ew", pady=(0, 8))

        action_outer = tk.Frame(step3_card, bg=self.BG_CARD)
        action_outer.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        action_group = tk.Frame(action_outer, bg=self.BG_CARD)
        action_group.pack(anchor=tk.CENTER)

        self.organize_btn = RoundedButton(
            action_group,
            text="✨ Organize My Files",
            width=255,
            height=44,
            corner_radius=12,
            bg_color=self.ORGANIZE_BTN_BG,
            hover_color=self.ORGANIZE_BTN_HOVER,
            fg_color="#FFFFFF",
            font=(UI_FONT, 12, "bold"),
            canvas_bg=self.BG_CARD,
            command=self._run_organize_files,
        )
        self.organize_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.undo_btn = RoundedButton(
            action_group,
            text="↩ Undo Last Organize",
            width=190,
            height=44,
            corner_radius=12,
            bg_color=self.UNDO_BTN_BG,
            hover_color=self.UNDO_BTN_HOVER,
            fg_color="#FFFFFF",
            font=(UI_FONT, 10, "bold"),
            canvas_bg=self.BG_CARD,
            enabled=False,
            command=self._run_undo_last_organize,
        )
        self.undo_btn.pack(side=tk.LEFT)

        watcher_row = tk.Frame(
            step3_card,
            bg="#F8FAFC",
            highlightbackground="#E2E8F0",
            highlightthickness=1,
            padx=10,
            pady=6,
        )
        watcher_row.grid(row=2, column=0, sticky="ew", pady=(2, 2))

        self.auto_sort_checkbox = tk.Checkbutton(
            watcher_row,
            text="Auto-sort new files as they arrive (Live Watcher)",
            variable=self.auto_sort_var,
            font=(UI_FONT, 9, "bold"),
            fg=self.TEXT_PRIMARY,
            bg="#F8FAFC",
            activebackground="#F8FAFC",
            activeforeground=self.TEXT_PRIMARY,
            selectcolor="#FFFFFF",
            cursor="hand2",
            command=self._on_toggle_auto_sort,
        )
        self.auto_sort_checkbox.pack(side=tk.LEFT)

        self.watcher_badge_label = tk.Label(
            watcher_row,
            text="",
            font=(UI_FONT, 9, "bold"),
            fg="#047857",
            bg="#ECFDF5",
            padx=8,
            pady=2,
        )

        self.banner_frame = tk.Frame(step3_card, bg=self.BG_CARD)
        self.banner_frame.grid(row=3, column=0, sticky="ew", pady=(4, 0))
        self.banner_frame.columnconfigure(0, weight=1)

        self.status_banner = tk.Label(
            self.banner_frame,
            text="",
            font=(UI_FONT, 10, "bold"),
            bg=self.BG_CARD,
            fg=self.TEXT_SECONDARY,
            padx=12,
            pady=7,
            wraplength=740,
            justify=tk.CENTER,
        )

        self.warning_label = tk.Label(
            self.banner_frame,
            text="",
            font=(UI_FONT, 9, "bold"),
            bg=self.BG_CARD,
            fg="#B45309",
            wraplength=740,
            justify=tk.CENTER,
        )

        # ======================================================================
        # ROW 4 & 5 — COLLAPSIBLE / EXPANDABLE ACTIVITY DETAILS VIEW
        # ======================================================================
        advanced_bar = tk.Frame(self.main_column, bg=self.BG_WINDOW)
        advanced_bar.grid(row=4, column=0, sticky="ew", pady=(2, 4))

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
        self.details_drawer.columnconfigure(0, weight=1)
        self.details_drawer.rowconfigure(0, weight=1)

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

        self.status_box.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        # Bind responsive wraplength adjustment when window is resized
        self.main_column.bind("<Configure>", self._on_main_column_resize)

    def _on_main_column_resize(self, event) -> None:
        """Dynamically adjust label wraplengths when the user resizes the window."""
        if event.width > 200:
            new_wrap = max(400, event.width - 96)
            self.preview_summary_label.configure(wraplength=new_wrap)
            self.status_banner.configure(wraplength=new_wrap)
            self.warning_label.configure(wraplength=new_wrap)

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
        """Display or hide the friendly celebration / restoration banner in Step 3."""
        if not text:
            self.status_banner.grid_forget()
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
            self.status_banner.grid(row=0, column=0, sticky="ew", pady=(4, 2))

        if warnings:
            shown = warnings[:3]
            if len(warnings) > 3:
                shown.append(
                    f"...and {len(warnings) - 3} more skipped items (see advanced details)."
                )
            self.warning_label.configure(text="\n".join(f"⚠️ {w}" for w in shown))
            self.warning_label.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        else:
            self.warning_label.grid_forget()

    def _toggle_advanced_details(self, _event=None) -> None:
        """Open or close the collapsible individual file details box."""
        self.details_expanded = not self.details_expanded
        if self.details_expanded:
            self.toggle_details_btn.configure(
                text="▾ Hide individual file details (advanced)"
            )
            self.details_drawer.grid(row=5, column=0, sticky="nsew", pady=(2, 0))
            # If window height is compact, expand slightly to show the log comfortably
            self.root.update_idletasks()
            cur_w = self.root.winfo_width()
            cur_h = self.root.winfo_height()
            if cur_h < 780:
                self.root.geometry(f"{cur_w}x790")
        else:
            self.toggle_details_btn.configure(
                text="▸ Show individual file details (advanced)"
            )
            self.details_drawer.grid_forget()

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
    # STEP 1: FOLDER QUEUE SELECTION & CUSTOM FOLDER ADDITION
    # ==========================================================================

    def _try_set_target_folder(self, candidate: Path, add_to_queue: bool = True) -> bool:
        """
        Validate `candidate` against the OS system path blacklist, add it to the
        dynamic candidate queue if new, re-rank, and focus `candidate`.
        """
        is_blocked, _reason = is_protected_system_path(candidate)
        if is_blocked:
            messagebox.showerror(
                "Protected System Folder",
                PROTECTED_FOLDER_MESSAGE,
                parent=self.root,
            )
            return False

        if add_to_queue:
            self._add_candidate_folder_internal(candidate)

        self.current_folder = candidate
        self._watched_file_states.clear()
        self._recalculate_folder_rankings()
        self._refresh_folder_queue_ui()
        self._update_folder_display()
        self._update_watcher_badge()
        return True

    def _select_queued_folder(self, folder: Path) -> None:
        """Handle clicking any folder button in the dynamic queue."""
        self._try_set_target_folder(folder, add_to_queue=False)

    def _browse_custom_folder(self) -> None:
        """Handle clicking [📂 Browse / Add Folder...] to queue a custom directory."""
        initial = (
            str(self.current_folder)
            if self.current_folder.exists()
            else str(Path.home())
        )
        chosen = filedialog.askdirectory(
            parent=self.root,
            initialdir=initial,
            title="Choose a Folder to Add & Organize",
        )
        if chosen:
            self._try_set_target_folder(Path(chosen), add_to_queue=True)

    def _update_folder_display(self) -> None:
        """Update Step 1 active folder label and refresh Step 2 preview badges."""
        friendly_name = self.current_folder.name or str(self.current_folder)
        cur_count = self.folder_loose_counts.get(
            self._folder_key(self.current_folder), 0
        )
        if cur_count > 0:
            file_word = "loose file" if cur_count == 1 else "loose files"
            status_suffix = f" ({cur_count} {file_word} waiting)"
        else:
            status_suffix = " (Clean — 0 loose files)"

        self.current_folder_label.configure(
            text=f"Currently organizing: {friendly_name}{status_suffix}"
        )

        self._show_banner("")
        self._run_safe_preview(show_error_modal=False)

    # ==========================================================================
    # STEP 2 (SAFE PREVIEW) & STEP 3 (ORGANIZE + AUTO-ADVANCE + UNDO)
    # ==========================================================================

    def _scan_eligible_files(
        self, target_folder: Optional[Path] = None
    ) -> Tuple[List[Tuple[Path, str]], List[str], str]:
        """
        Scan only loose top-level files in `target_folder` (defaults to `self.current_folder`)
        while enforcing all security, symlink, and hidden-file rules.
        """
        folder = target_folder if target_folder is not None else self.current_folder

        is_blocked, _reason = is_protected_system_path(folder)
        if is_blocked:
            return [], [], PROTECTED_FOLDER_MESSAGE

        if not folder.exists() or not folder.is_dir():
            return (
                [],
                [],
                "We couldn't find that folder on your computer. Please choose another folder in Step 1.",
            )

        try:
            entries = sorted(folder.iterdir(), key=lambda p: p.name.lower())
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
        """
        Step 3: Move loose files into neat category subfolders, record Undo transaction,
        demote the cleaned folder in the queue, and automatically advance to the next
        messiest folder if one exists!
        """
        with self._op_lock:
            organized_folder = self.current_folder
            organized_folder_name = organized_folder.name or str(organized_folder)
            eligible_items, security_notes, error_msg = self._scan_eligible_files(
                target_folder=organized_folder
            )

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
                self._recalculate_folder_rankings()
                self._refresh_folder_queue_ui()
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
            current_transaction: List[Tuple[Path, Path]] = []

            for file_path, sanitized_name in eligible_items:
                try:
                    category = get_category_for_filename(sanitized_name)
                    category_dir = organized_folder / category
                    safe_dest = get_safe_destination_path(
                        category_dir, sanitized_name, reserved_destinations
                    )

                    success, warn_msg = atomic_verified_move(
                        source_path=file_path,
                        dest_path=safe_dest,
                        base_dir=organized_folder,
                        category_dir=category_dir,
                    )

                    if success:
                        reserved_destinations.add(os.path.normcase(str(safe_dest)))
                        current_transaction.append((safe_dest, file_path))
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
                self.last_transaction = current_transaction
                self.undo_btn.set_enabled(True)

                # Re-rank all candidate folders after organizing
                self._recalculate_folder_rankings()
                remaining_in_current = self.folder_loose_counts.get(
                    self._folder_key(organized_folder), 0
                )

                # Auto-Demotion & Progression: if current folder reached 0 loose files
                # and another queued folder still has loose files, transition to it!
                next_messy_folder: Optional[Path] = None
                if remaining_in_current == 0 and self.ranked_folders:
                    top_candidate = self.ranked_folders[0]
                    top_count = self.folder_loose_counts.get(
                        self._folder_key(top_candidate), 0
                    )
                    if (
                        top_count > 0
                        and self._folder_key(top_candidate)
                        != self._folder_key(organized_folder)
                    ):
                        next_messy_folder = top_candidate

                if next_messy_folder is not None:
                    next_name = next_messy_folder.name or str(next_messy_folder)
                    next_count = self.folder_loose_counts.get(
                        self._folder_key(next_messy_folder), 0
                    )
                    self.current_folder = next_messy_folder
                    self._watched_file_states.clear()
                    self._refresh_folder_queue_ui()
                    self._update_folder_display()
                    self._update_watcher_badge()

                    banner_text = (
                        f"🎉 All clean! {moved_count} {file_word} organized successfully in {organized_folder_name}. "
                        f"Switched to next messy folder: {next_name} ({next_count})."
                    )
                    self._show_banner(
                        banner_text, is_success=True, warnings=skipped_warnings
                    )
                else:
                    self._refresh_folder_queue_ui()
                    friendly_name = self.current_folder.name or str(self.current_folder)
                    self.current_folder_label.configure(
                        text=f"Currently organizing: {friendly_name} (Clean — 0 loose files)"
                        if remaining_in_current == 0
                        else f"Currently organizing: {friendly_name} ({remaining_in_current} loose files waiting)"
                    )
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

    def _run_undo_last_organize(self) -> None:
        """
        Safely reverse `self.last_transaction`, moving sorted files back to their
        original locations, re-ranking the folder queue, and focusing the restored folder.
        """
        with self._op_lock:
            if not self.last_transaction:
                self.undo_btn.set_enabled(False)
                return

            restored_count = 0
            reserved_restore_paths: Set[str] = set()
            restore_details: List[str] = []
            restore_warnings: List[str] = []
            remaining_transaction: List[Tuple[Path, Path]] = []
            restored_folder: Optional[Path] = None

            for moved_dest_path, original_source_path in reversed(self.last_transaction):
                try:
                    base_dir = original_source_path.parent
                    restored_folder = base_dir
                    is_blocked, _ = is_protected_system_path(base_dir)
                    if is_blocked:
                        restore_warnings.append(
                            f"Blocked restore to protected folder '{base_dir}'."
                        )
                        continue

                    is_safe, clean_orig_name, _ = inspect_and_sanitize_filename(
                        original_source_path.name
                    )
                    target_name = (
                        clean_orig_name if is_safe else moved_dest_path.name
                    )

                    safe_restore_path = get_safe_destination_path(
                        base_dir, target_name, reserved_restore_paths
                    )

                    success, warn_msg = atomic_verified_restore(
                        moved_path=moved_dest_path,
                        restore_dest=safe_restore_path,
                        base_dir=base_dir,
                    )

                    if success:
                        reserved_restore_paths.add(
                            os.path.normcase(str(safe_restore_path))
                        )
                        restored_count += 1
                        if safe_restore_path.name != original_source_path.name:
                            restore_details.append(
                                f"↩ Restored '{moved_dest_path.name}' as '{safe_restore_path.name}' (to avoid conflict)"
                            )
                        else:
                            restore_details.append(
                                f"↩ Restored '{original_source_path.name}' back to {base_dir.name}"
                            )
                    else:
                        remaining_transaction.append(
                            (moved_dest_path, original_source_path)
                        )
                        if warn_msg:
                            restore_warnings.append(warn_msg)

                except (PermissionError, OSError, ValueError) as exc:
                    remaining_transaction.append(
                        (moved_dest_path, original_source_path)
                    )
                    restore_warnings.append(
                        f"Could not restore '{moved_dest_path.name}' ({exc.__class__.__name__})."
                    )

            self.last_transaction = list(reversed(remaining_transaction))
            self.undo_btn.set_enabled(bool(self.last_transaction))

            if restored_folder is not None:
                self.current_folder = restored_folder

            self._recalculate_folder_rankings()
            self._refresh_folder_queue_ui()
            self._update_folder_display()
            self._update_watcher_badge()

            spot_word = (
                "file back to its original spot"
                if restored_count == 1
                else "files back to their original spots"
            )
            if restored_count > 0:
                banner_msg = f"Restored {restored_count} {spot_word}."
                self._show_banner(
                    banner_msg, is_success=True, warnings=restore_warnings
                )
            else:
                self._show_banner(
                    "Could not restore files because they were moved or are currently open.",
                    is_success=False,
                    warnings=restore_warnings,
                )

            self._set_advanced_details(restore_details + restore_warnings)

    # ==========================================================================
    # FEATURE 3: "AUTO-SORT" BACKGROUND WATCHER (LIVE WATCHER)
    # ==========================================================================

    def _update_watcher_badge(self) -> None:
        """Show or hide the subtle '🟢 Live auto-sorting is active for [Folder]' indicator."""
        if self.auto_sort_var.get():
            friendly_name = self.current_folder.name or str(self.current_folder)
            self.watcher_badge_label.configure(
                text=f"🟢 Live auto-sorting is active for {friendly_name}",
                highlightbackground="#A7F3D0",
                highlightthickness=1,
            )
            self.watcher_badge_label.pack(side=tk.RIGHT)
        else:
            self.watcher_badge_label.pack_forget()

    def _on_toggle_auto_sort(self) -> None:
        """Start or pause the background Live Watcher thread when checkbox is toggled."""
        self._auto_sort_enabled = bool(self.auto_sort_var.get())
        self._watched_file_states.clear()
        self._update_watcher_badge()

        if self._auto_sort_enabled:
            if self._watcher_thread is None or not self._watcher_thread.is_alive():
                self._watcher_stop_event.clear()
                self._watcher_thread = threading.Thread(
                    target=self._auto_sort_watcher_loop,
                    name="EasyFileOrganizerLiveWatcher",
                    daemon=True,
                )
                self._watcher_thread.start()
            self.root.after(250, self._poll_watcher_ui_updates)

    def _auto_sort_watcher_loop(self) -> None:
        """
        Background daemon thread that monitors `self.current_folder` while
        `self._auto_sort_enabled` is True.
        """
        while not self._watcher_stop_event.is_set():
            time.sleep(WATCHER_POLL_INTERVAL_SEC)
            if self._watcher_stop_event.is_set() or not self._auto_sort_enabled:
                continue

            folder = self.current_folder
            eligible_items, _, error_msg = self._scan_eligible_files(
                target_folder=folder
            )
            if error_msg or not eligible_items:
                self._watched_file_states.clear()
                continue

            now = time.monotonic()
            current_paths: Set[Path] = set()
            ready_to_sort: List[Tuple[Path, str]] = []

            for file_path, sanitized_name in eligible_items:
                current_paths.add(file_path)
                try:
                    st = os.lstat(file_path)
                    cur_size = st.st_size
                    cur_mtime = getattr(st, "st_mtime_ns", int(st.st_mtime * 1e9))
                except OSError:
                    continue

                prev = self._watched_file_states.get(file_path)
                if prev is None:
                    self._watched_file_states[file_path] = (
                        cur_size,
                        cur_mtime,
                        now,
                    )
                else:
                    prev_size, prev_mtime, stable_since = prev
                    if cur_size == prev_size and cur_mtime == prev_mtime:
                        if (now - stable_since) >= WATCHER_STABILITY_WINDOW_SEC:
                            ready_to_sort.append((file_path, sanitized_name))
                    else:
                        self._watched_file_states[file_path] = (
                            cur_size,
                            cur_mtime,
                            now,
                        )

            for tracked in list(self._watched_file_states.keys()):
                if tracked not in current_paths:
                    self._watched_file_states.pop(tracked, None)

            if ready_to_sort:
                self._sort_ready_files_in_worker(ready_to_sort, folder)

    def _sort_ready_files_in_worker(
        self, ready_items: List[Tuple[Path, str]], target_folder: Path
    ) -> None:
        """
        Thread-safely move stability-verified files in the background worker and
        append results to `self._pending_auto_sorted` for the main UI thread.
        """
        if not self._auto_sort_enabled or target_folder != self.current_folder:
            return

        if not self._op_lock.acquire(blocking=False):
            return

        try:
            is_blocked, _ = is_protected_system_path(target_folder)
            if is_blocked:
                return

            reserved_destinations: Set[str] = set()

            for file_path, sanitized_name in ready_items:
                if not file_path.exists():
                    continue

                category = get_category_for_filename(sanitized_name)
                category_dir = target_folder / category
                safe_dest = get_safe_destination_path(
                    category_dir, sanitized_name, reserved_destinations
                )

                success, _ = atomic_verified_move(
                    source_path=file_path,
                    dest_path=safe_dest,
                    base_dir=target_folder,
                    category_dir=category_dir,
                )

                if success:
                    reserved_destinations.add(os.path.normcase(str(safe_dest)))
                    self._watched_file_states.pop(file_path, None)
                    self._pending_auto_sorted.append(
                        (safe_dest, file_path, category)
                    )
        finally:
            self._op_lock.release()

    def _poll_watcher_ui_updates(self) -> None:
        """
        Periodic main-thread callback that drains `self._pending_auto_sorted`
        and updates the folder queue rankings, Undo button, badges, and banner.
        """
        if self._watcher_stop_event.is_set():
            return

        if self._pending_auto_sorted:
            with self._op_lock:
                drained = list(self._pending_auto_sorted)
                self._pending_auto_sorted.clear()

            if drained:
                batch_tx = [(dest, orig) for dest, orig, _ in drained]
                batch_details = [
                    f"🟢 Auto-sorted '{orig.name}' into {cat}"
                    for _, orig, cat in drained
                ]
                self.last_transaction.extend(batch_tx)
                self.undo_btn.set_enabled(True)
                self._recalculate_folder_rankings()
                self._refresh_folder_queue_ui()
                self._update_folder_display()

                count = len(drained)
                file_word = "file" if count == 1 else "files"
                self._show_banner(
                    f"🎉 Auto-sorted {count} new {file_word} automatically!",
                    is_success=True,
                )
                self._set_advanced_details(batch_details)

        if self._auto_sort_enabled and not self._watcher_stop_event.is_set():
            self.root.after(250, self._poll_watcher_ui_updates)


def main() -> None:
    """Register Windows AppUserModelID and start the Easy File Organizer desktop app."""
    set_windows_app_user_model_id()
    root = tk.Tk()
    FriendlyFileOrganizerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
