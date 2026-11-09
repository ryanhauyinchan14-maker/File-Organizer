# Easy File Organizer

A clean, beginner-friendly desktop utility for **Windows 10/11**, **macOS**, and **Linux** that tidies up loose files in a folder by sorting them into clearly named category subfolders in three simple steps.

Built strictly with Python's standard library—**zero external packages or `pip install` commands required**.

---

## Project Overview

Messy folders like `Downloads` or `Desktop` quickly fill up with hundreds of loose photos, PDFs, zip archives, and installers. **Easy File Organizer** gives you a compact, foolproof window where you can pick a folder, preview a visual summary of what will happen, and sort your loose files with a single click—without ever touching existing folders or overwriting your files.

---

## Key Features

- **Simple 3-Step Visual Interface**:
  1. **Step 1 — Where are your messy files?**: One-click rounded buttons for **Downloads**, **Desktop**, and **Documents**, plus a **Browse Other Folder...** button.
  2. **Step 2 — Safe Preview**: Displays clean 2-column visual category badges (`📷 Photos & Images`, `📄 Documents`, `📦 Zip Files`, `⚙️ Installers`, `🎬 Videos`, `🎵 Music & Audio`, `💻 Code & Scripts`, `📁 Other Files`) and a plain-English summary before moving a single file. Includes an optional collapsible drawer (`Show individual file details`) that stays closed by default.
  3. **Step 3 — Organize**: A centered **Organize My Files** button and a celebratory completion banner (`🎉 All clean!`).
- **Non-Destructive Duplicate Handling**:
  - Never overwrites existing files. If `report.pdf` or `backup.tar.gz` already exists in the destination subfolder, the incoming file is automatically renamed to `report (1).pdf` or `backup (1).tar.gz`.
- **Full Cross-Platform Support (Windows, macOS, Linux)**:
  - Dynamically detects the host OS via `platform.system()`.
  - Automatically resolves Windows OneDrive-redirected folders, standard macOS user folders, and Linux XDG user directories (`XDG_CONFIG_HOME` / `~/.config/user-dirs.dirs`).
- **Enterprise Security Hardening**:
  - **OS-Specific System Path Blacklists**: Blocks root drives (`C:\`, `D:\`, `/`), system directories (`C:\Windows`, `System32`, `Program Files`, `/System`, `/Library`, `/etc`, `/usr`, `/boot`, `/proc`, `/var`), user home roots (`Path.home()`), and critical config directories (`AppData`, `~/Library`, `~/.ssh`, `~/.gnupg`).
  - **Path Containment & Filename Sanitization**: Enforces `os.path.commonpath()` containment, blocks NTFS Alternate Data Streams (`:`), strips Unicode Right-to-Left Override (`\u202E`) spoofing characters, and filters Windows Reserved Device Names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`).
  - **Symlink & Junction Defense**: Uses `os.lstat()` to detect and skip symbolic links, NTFS junction points, and reparse points.
  - **TOCTOU & Integrity Verification**: Verifies file inode and byte size before and after atomic moves, checks POSIX write permissions (`os.access`), and safely skips files open in other apps (such as Word or Excel).

---

## How to Run

Make sure **Python 3** is installed on your computer. No third-party packages are needed.

### Windows (PowerShell or Command Prompt)

```powershell
python file_organizer.py
```

*(Tip: To launch the window without a background console window on Windows, run `pythonw file_organizer.py` or double-click `file_organizer.py` in File Explorer.)*

### macOS (Terminal)

```bash
python3 file_organizer.py
```

### Linux (Terminal)

```bash
python3 file_organizer.py
```

---

## Safety & Privacy

- **Zero File Deletions**: No file or folder removal calls (`os.remove`, `os.unlink`, `shutil.rmtree`) exist anywhere in the codebase.
- **Zero Overwrites**: Existing files are always preserved; duplicate names receive automatic `(1)`, `(2)` numbering.
- **100% Local & Offline**: Runs completely on your local machine with zero network requests, telemetry, or external dependencies.
- **Protected System Directories**: Built-in guardrails prevent running the organizer on operating system folders or your root user profile directory.
