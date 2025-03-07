# 🛡️ Malware Sandbox Detector  

A **Malware Sandbox Detector** written in C that detects if the system is running in a virtualized or sandboxed environment. This tool checks for common indicators used by malware sandboxes, virtual machines (VMs), and debuggers.

---

## 🚀 Features  

✅ **System Uptime Check** – Detects if the system has been running for a short time (common in sandboxes).  
✅ **CPU Core Count Check** – Identifies if only one CPU core is available (typical for VMs).  
✅ **Virtual Machine Detection** – Scans for VMware, VirtualBox, and Hyper-V registry keys.  
✅ **BIOS and Manufacturer Check** – Checks if the system BIOS belongs to a virtualized environment.  
✅ **MAC Address Check** – Identifies virtual network adapters.  
✅ **Debugger Detection** – Detects if the program is being debugged (`IsDebuggerPresent()`).  
✅ **Sleep Timing Analysis** – Detects artificial time acceleration used by sandboxes.  
✅ **Process Scanning** – Detects sandbox-related processes (`VBoxService.exe`, `Procmon.exe`, etc.).  
✅ **Memory and Disk Check** – Identifies if the system has very low RAM or storage (common in VMs).  

---

## 🖥️ Installation & Usage  

### 🔹 **Requirements**  
- Windows OS  
- MinGW or any C compiler  

### 🔹 **Compile the Code**  
```sh
git clone https://github.com/4stersec/sandbox_detector.git ; 
gcc sandbox_detector.c -o sandbox_detector.exe
```

### 🔹 **Run the Tool**  
```sh
sandbox_detector.exe
```

---

## 🔍 Detection Techniques  

| Check | Method | Detection Criteria |
|--------|-----------------|--------------------|
| **System Uptime** | `GetTickCount()` | If uptime < 5 minutes → Suspicious |
| **CPU Core Count** | `GetSystemInfo()` | If CPU cores ≤ 1 → VM detected |
| **VM Detection** | Registry Query | Checks VMware, VirtualBox keys |
| **BIOS Check** | Registry Query | Looks for VM-related BIOS info |
| **Debugger Detection** | `IsDebuggerPresent()` | Detects active debugging |
| **Sleep Timing** | `Sleep(5000)` & `clock()` | If time < 4.5s → Sandbox detected |
| **Process Scan** | `CreateToolhelp32Snapshot()` | Looks for sandbox/forensic tools |
| **Memory Check** | `GlobalMemoryStatusEx()` | If RAM < 512MB → Suspicious |
| **Disk Size Check** | `GetDiskFreeSpaceEx()` | If disk size < 10GB → VM detected |

---

## 🛠️ Possible Enhancements  

🔸 **Hypervisor Detection** – Use CPUID instruction to detect hidden virtualization.  
🔸 **Advanced Anti-Debugging** – Detect breakpoints and memory alterations.  
🔸 **Network Analysis** – Detect virtual MAC addresses and sandboxed network configurations.  
🔸 **Fake User Interaction** – Check if the system has real mouse and keyboard activity.  

---

## ⚠️ Disclaimer  

🚨 **This tool is for educational and research purposes only.**  
🚨 Do **not** use this tool for illegal or unethical activities.  

---

## 📜 License  

This project is released under the **MIT License**.  



## ⭐ Contribute  

Contributions are welcome! Feel free to open an issue or a pull request.  
```
```
```
🚀 **Stay ahead of cybersecurity threats!**  
```

