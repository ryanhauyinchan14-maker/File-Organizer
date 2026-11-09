# Easy File Organizer

A clean, beginner-friendly desktop utility for **Windows 10/11**, **macOS**, and **Linux** that tidies up loose files in a folder by sorting them into clearly named category subfolders in three simple steps.

Built strictly with Python's standard library—**zero external packages or `pip install` commands required**.

---

## Project Overview

Messy folders like `Downloads` or `Desktop` quickly fill up with hundreds of loose photos, PDFs, zip archives, and installers. **Easy File Organizer** gives you a compact, foolproof window where you can pick a folder, preview a visual summary of what will happen, and sort your loose files with a single click—without ever touching existing folders or overwriting your files.

---

## Key Features

- **Simple 3-Step Visual Interface (with Smart Folder Queue)**:
  1. **Step 1 — Where are your messy files? (Auto-Prioritized Queue)**:
     - Scans candidate folders (**Downloads**, **Desktop**, **Documents**, plus any custom folders added via **`📂 Browse / Add Folder...`**) and counts loose files in each.
     - Automatically ranks the messiest folders to the front of the queue with live count badges (e.g., `📥 Downloads (15)`, `🖥️ Desktop (4)`), while clean folders (`✓ Documents (0)`) are demoted to the end of the line.
     - Automatically focuses the messiest folder on launch and auto-advances to the next messy folder as soon as the current one is organized.
  2. **Step 2 — Safe Preview**: Displays clean 2-column visual category badges (`📷 Photos & Images`, `📄 Documents`, `📦 Zip Files`, `⚙️ Installers`, `🎬 Videos`, `🎵 Music & Audio`, `💻 Code & Scripts`, `📁 Other Files`) and a plain-English summary before moving a single file. Includes an optional collapsible drawer (`Show individual file details`) that expands vertically when the window is resized.
  3. **Step 3 — Organize, Undo & Live Auto-Sort**:
     - **Organize My Files**: One-click sorting with a celebratory completion banner (`🎉 All clean!`).
     - **Undo Last Organize**: Reverses the previous batch of sorted files back to their original locations (`Restored X files back to their original spots.`), gracefully resolving any name conflicts without overwriting.
     - **Live Auto-Sort Watcher**: Optional background watcher (`Auto-sort new files as they arrive`) with a live status badge (`🟢 Live auto-sorting is active for [Folder]`) that ignores partial downloads (`.crdownload`, `.part`, `.tmp`, `~$*`) and waits for file size stability before moving new files.
- **Responsive, Freely Resizable Window**:
  - Launches at a comfortable `860×730` size (`720×620` minimum) and scales smoothly using responsive Tkinter grid weights when enlarged or maximized.
- **Custom Standalone App & Taskbar Icon**:
  - Generates a crisp, modern folder-organizer PNG icon in memory using only Python's standard library (`zlib`, `struct`, `base64`) and registers a dedicated Windows `AppUserModelID` so both the title bar and Windows taskbar show the custom icon.
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
