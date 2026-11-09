# Easy File Organizer (Windows, macOS & Linux)

A modern, compact, beginner-friendly desktop file organizer for **Windows**, **macOS**, and **Linux** built purely with Python's standard library (`tkinter`, `pathlib`, `platform`, `shutil`, `os`, `stat`, `ctypes`).

## Features

- **Cross-Platform OS Detection & Quick Folders**:
  - Dynamically detects **Windows**, **macOS** (`Darwin`), and **Linux** via `platform.system()`.
  - Resolves **Downloads**, **Desktop**, and **Documents** across Windows (with OneDrive redirection support), macOS (`~/Downloads`, etc.), and Linux (`XDG_CONFIG_HOME` / `~/.config/user-dirs.dirs` with `~/Downloads` fallback).
- **Simple 3-Step Interface**:
  1. **Step 1 — Choose Folder**: One-click rounded shortcut buttons for **Downloads**, **Desktop**, and **Documents**, plus a **Browse Other Folder...** button.
  2. **Step 2 — Safe Preview**: Visual category summary cards (`📷 Photos & Images`, `📄 Documents`, `📦 Zip Files`, `⚙️ Installers`, `🎬 Videos`, `🎵 Music & Audio`, `💻 Code & Scripts`, `📁 Other Files`) and a collapsible advanced details drawer.
  3. **Step 3 — Organize**: One-click sorting with a completion banner (`🎉 All clean!`).
- **Enterprise-Grade Cross-Platform Security**:
  - **OS-Specific Blacklisted System Directories**:
    - **Windows**: Blocks root drives (`C:\`, `D:\`), `C:\Windows`, `System32`, `SysWOW64`, `WinSxS`, `Program Files`, `Program Files (x86)`, `C:\Users`, and root `AppData`.
    - **macOS**: Blocks `/`, `/System`, `/Library`, `/Applications`, `/private`, `/usr`, `/bin`, `/sbin`, `/Users`, and `~/Library`.
    - **Linux**: Blocks `/`, `/boot`, `/etc`, `/sys`, `/proc`, `/dev`, `/usr`, `/bin`, `/sbin`, `/var`, `/root`, and `/home`.
    - **All Platforms**: Prevents organizing the root user home directory itself (`Path.home()`).
  - **Platform-Specific Hidden & Metadata File Filtering**:
    - Skips dotfiles (`.`), Windows system/lock files (`desktop.ini`, `thumbs.db`, `~$*`), macOS metadata (`.DS_Store`, `._*`, `.localized`, `.Trashes`, `.Spotlight-V100`, `Icon\r`, `UF_HIDDEN`), and Linux editor swap/backup files (`*.swp`, `*~`, `#*#`).
  - **Path Containment & Filename Sanitization**: Enforces `os.path.commonpath` containment, blocks NTFS Alternate Data Streams (`:`), strips Unicode Right-to-Left Override (`\u202E`) spoofing characters, and blocks Reserved Device Names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`).
  - **Cross-Platform Privilege & Permission Checks**: Detects Administrator (`IsUserAnAdmin`) on Windows and `root` (`os.geteuid() == 0`) on macOS/Linux, verifies POSIX write permissions (`os.access(..., os.W_OK)`), and guarantees zero file deletions or overwrites.

## How to Run

No `pip install` required—uses only the Python 3 standard library.

```bash
python3 file_organizer.py
```
