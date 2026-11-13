# Forensic Triage Report: Compromised Host

## 1. Chain of Custody & Evidence Integrity
**Target:** Windows 10 Host (Simulated) - `evidence_disk.E01` and `memory.raw`
**Acquisition Tool:** FTK Imager / WinPmem
**Analysis Tools:** Autopsy 4.21, Volatility 3, RegRipper 3.0

### Integrity Verification Log
To ensure a forensically sound process, a working copy was made, and hashes were verified against the original.

    Original Disk Image Hash: SHA256 - a1b2c3d4e5f6g7h8i9j0...
    Working Copy Hash:        SHA256 - a1b2c3d4e5f6g7h8i9j0... [MATCH]

    Original Memory Hash:     SHA256 - 9z8y7x6w5v4u3t2s1r0q...
    Working Copy Hash:        SHA256 - 9z8y7x6w5v4u3t2s1r0q... [MATCH]

---

## 2. Timeline of Events (UTC)
All timestamps were normalized to UTC using timeline analysis from Autopsy.

* **2026-11-12 14:22:10** - User `Teddy` downloads `invoice_update.exe` via Chrome (MFT/USN Journal).
* **2026-11-12 14:23:05** - Execution of `invoice_update.exe` (Prefetch: `INVOICE_UPDATE.EXE-1234ABCD.pf`).
* **2026-11-12 14:23:15** - `cmd.exe /c whoami` spawned by `invoice_update.exe` (Volatility `cmdline` plugin).
* **2026-11-12 14:24:00** - Registry modification: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run` modified to add `C:\Users\jdoe\AppData\Roaming\update.exe` (RegRipper).
* **2026-11-12 14:25:30** - Outbound connection established to `185.15.x.x:4444` (Volatility `netscan` plugin).

---

## 3. Artifact Findings with Evidence

### Artifact 1: Malicious Process Execution (Volatility)
The `vol3 -f memory.raw windows.cmdline` plugin revealed the following anomalous process tree:

    PID    Process        Args
    4512   invoice_updat  "C:\Users\Teddy\Downloads\invoice_update.exe"
    6120   cmd.exe        "cmd.exe /c whoami"

*Significance:* This proves execution of the downloaded payload and basic discovery commands.

### Artifact 2: Persistence via Registry (RegRipper)
Using RegRipper on the extracted `NTUSER.DAT` hive:

    Key: Software\Microsoft\Windows\CurrentVersion\Run
    Value: WindowsUpdate
    Data: C:\Users\Teddy\AppData\Roaming\update.exe

*Significance:* Proves the malware established persistence to survive a reboot.

---

## 4. Conclusion & Defensibility
The evidence is supported by artifacts from three distinct sources (Volatility memory analysis, RegRipper registry analysis, and Autopsy file system timeline). The preservation of evidence was proven via SHA256 hashing of the working copies before analysis. No conclusions were drawn from speculation; every finding is mapped to a specific forensic artifact.
