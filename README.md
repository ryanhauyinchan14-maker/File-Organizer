# Easy File Organizer for Windows 10/11

A modern, compact, beginner-friendly desktop file organizer for Windows 10 and 11 built with Python's standard library (`tkinter`, `pathlib`, `shutil`, `os`, `stat`, `ctypes`).

## Features

- **Simple 3-Step Interface**:
  1. **Step 1 — Choose Folder**: One-click rounded shortcut buttons for **Downloads**, **Desktop**, and **Documents**, plus a **Browse Other Folder...** button.
  2. **Step 2 — Safe Preview**: Visual category summary cards (`📷 Photos & Images`, `📄 Documents`, `📦 Zip Files`, `⚙️ Installers`, `🎬 Videos`, `🎵 Music & Audio`, `💻 Code & Scripts`, `📁 Other Files`) and a collapsible advanced details drawer.
  3. **Step 3 — Organize**: One-click sorting with a completion banner (`🎉 All clean!`).
- **Enterprise-Grade Safety & Security**:
  - **Protected System Path Blacklist**: Hard-blocks root drives (`C:\`, `D:\`), `C:\Windows`, `System32`, `SysWOW64`, `WinSxS`, `Program Files`, `C:\Users`, `AppData` roots, and `Start Menu` / `Startup`.
  - **Path Containment & Filename Sanitization**: Enforces `os.path.commonpath` containment, blocks NTFS Alternate Data Streams (`:`), strips Unicode Right-to-Left Override (`\u202E`) spoofing characters, and filters Windows Reserved Device Names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`).
  - **Symlink & NTFS Junction Defense**: Never follows or moves symbolic links or NTFS junction points.
  - **Non-Destructive & Zero-Deletion Guarantee**: Never deletes or overwrites files. Automatically renames duplicates (`photo (1).png`), verifies pre/post-move file size and inode (`TOCTOU` defense), and safely skips files currently open in other apps.

## How to Run

No `pip install` required—uses only the Python 3 standard library.

```powershell
python file_organizer.py
```

Or simply **double-click `file_organizer.py`** in Windows File Explorer.
