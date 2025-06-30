# 🔒 av-cli — Static PE Scanner & Hash Intelligence Tool

A lightweight, **command-line antivirus tool** focused entirely on **static analysis of Windows executables** (PE files). This tool is designed for **security researchers** to quickly identify potentially malicious files, flag them based on entropy, and build a **crowdsourced hash intelligence database**.

---

## 🚀 Features

✅ **PE Header Parsing**  
Reads and analyzes the Portable Executable (PE) file structure using the Windows API.

✅ **Entropy Calculation**  
Calculates Shannon entropy of the entire file to detect obfuscated or packed executables.  
Higher entropy (typically > 7.2) may indicate packing or encryption.

✅ **Malicious File Detection**  
Flags files with suspicious entropy for manual review. Files are **not deleted automatically**.

✅ **User Approval System**  
After scanning:
- View flagged files
- Choose to **approve** (ignore future warnings) or **deny** (mark as malicious)

✅ **External Hash Server Integration** *(Planned)*  
When a file is **denied**, its hash will be sent to an external server:
- For storage
- For future scanning comparisons
- To contribute to a shared intelligence database

✅ **Scan Options** *(Planned)*  
- Scan a single file  
- Recursively scan all `.exe`/`.dll` files in a directory

---

## 🛠️ How It Works

1. You run the CLI tool on a file or folder.
2. Each `.exe` or `.dll` file is:
   - Parsed for valid PE headers
   - Measured for entropy
   - Compared against thresholds for suspicious properties
3. Suspicious files are added to a **"review list"**.
4. You are prompted to **approve** or **deny** each.
5. **Denied hashes** are (optionally) sent to an external server and optionally deleted.

---

## 📦 Installation & Build

**Build on Windows with GCC (MinGW):**
```bash
gcc -o av-cli.exe antivirus.c hashutil.c -ladvapi32
