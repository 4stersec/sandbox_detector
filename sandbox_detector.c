#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <time.h>

#define UPTIME_THRESHOLD 300  // 5 minutes
#define MEMORY_THRESHOLD_MB 512  // Sandboxes often have < 512MB RAM
#define DISK_THRESHOLD_GB 10  // Sandboxes often allocate < 10GB storage

// Function to check system uptime
int check_system_uptime() {
    DWORD uptime = GetTickCount() / 1000;  // Convert milliseconds to seconds
    printf("[*] System Uptime: %d seconds\n", uptime);
    
    if (uptime < UPTIME_THRESHOLD) {
        printf("[!] Suspicious: Low system uptime (< 5 min). Possible sandbox detected!\n");
        return 1;
    }
    return 0;
}

// Function to check CPU core count
int check_processor_count() {
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    printf("[*] Number of Processors: %d\n", sysinfo.dwNumberOfProcessors);
    
    if (sysinfo.dwNumberOfProcessors <= 1) {
        printf("[!] Suspicious: Only one processor detected. Possible sandbox!\n");
        return 1;
    }
    return 0;
}

// Function to check if running inside VMware, VirtualBox, or Hyper-V
int check_virtual_machine() {
    HKEY hKey;
    char buffer[256];
    DWORD bufferSize = sizeof(buffer);
    int detected = 0;

    // Check for VMware registry key
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("[!] Warning: VMware detected!\n");
        detected = 1;
        RegCloseKey(hKey);
    }

    // Check for VirtualBox registry key
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        printf("[!] Warning: VirtualBox detected!\n");
        detected = 1;
        RegCloseKey(hKey);
    }

    // Check BIOS manufacturer for virtualization
    if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        if (RegQueryValueEx(hKey, "SystemBiosVersion", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
            if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") || strstr(buffer, "Xen") || strstr(buffer, "Hyper-V")) {
                printf("[!] Warning: Virtual Machine BIOS detected (%s)!\n", buffer);
                detected = 1;
            }
        }
        RegCloseKey(hKey);
    }

    return detected;
}

// Function to check if the program is running under a debugger
int check_debugger() {
    if (IsDebuggerPresent()) {
        printf("[!] Suspicious: Debugger detected. Possible sandbox!\n");
        return 1;
    }
    return 0;
}

// Function to check if sleep timing is being manipulated
int check_sleep_timing() {
    clock_t start, end;
    double elapsed;

    start = clock();
    Sleep(5000);  // Sleep for 5 seconds
    end = clock();

    elapsed = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("[*] Sleep timing test: Expected ~5.0s, Measured: %.2fs\n", elapsed);

    if (elapsed < 4.5) {
        printf("[!] Suspicious: Sleep timing is being manipulated. Possible sandbox!\n");
        return 1;
    }
    return 0;
}

// Function to check for known sandbox-related processes
int check_sandbox_processes() {
    const char* blacklist[] = {
        "vboxservice.exe", "vboxtray.exe", "vmtoolsd.exe", "vmwaretray.exe",
        "wireshark.exe", "procmon.exe", "ollydbg.exe", "x32dbg.exe"
    };

    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int detected = 0;

    if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;

    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hProcessSnap, &pe32)) {
        do {
            for (int i = 0; i < sizeof(blacklist) / sizeof(blacklist[0]); i++) {
                if (_stricmp(pe32.szExeFile, blacklist[i]) == 0) {
                    printf("[!] Suspicious: Sandbox process detected (%s)!\n", pe32.szExeFile);
                    detected = 1;
                }
            }
        } while (Process32Next(hProcessSnap, &pe32));
    }

    CloseHandle(hProcessSnap);
    return detected;
}

// Function to check system memory size
int check_memory_size() {
    MEMORYSTATUSEX memInfo;
    memInfo.dwLength = sizeof(memInfo);
    GlobalMemoryStatusEx(&memInfo);

    DWORDLONG memoryMB = memInfo.ullTotalPhys / (1024 * 1024);
    printf("[*] Total Memory: %llu MB\n", memoryMB);

    if (memoryMB < MEMORY_THRESHOLD_MB) {
        printf("[!] Suspicious: Low memory (< 512MB). Possible sandbox detected!\n");
        return 1;
    }
    return 0;
}

// Function to check disk size
int check_disk_size() {
    ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
    GetDiskFreeSpaceEx(NULL, &freeBytesAvailable, &totalBytes, &totalFreeBytes);

    DWORDLONG totalGB = totalBytes.QuadPart / (1024 * 1024 * 1024);
    printf("[*] Total Disk Size: %llu GB\n", totalGB);

    if (totalGB < DISK_THRESHOLD_GB) {
        printf("[!] Suspicious: Very small disk size (< 10GB). Possible sandbox!\n");
        return 1;
    }
    return 0;
}

int main() {
    printf("[+] Running Advanced Malware Sandbox Detector...\n");

    int sandbox_detected = 0;

    sandbox_detected += check_system_uptime();
    sandbox_detected += check_processor_count();
    sandbox_detected += check_virtual_machine();
    sandbox_detected += check_debugger();
    sandbox_detected += check_sleep_timing();
    sandbox_detected += check_sandbox_processes();
    sandbox_detected += check_memory_size();
    sandbox_detected += check_disk_size();

    if (sandbox_detected > 0) {
        printf("\n[!] Warning: Possible sandbox environment detected!\n");
    } else {
        printf("\n[*] No sandbox indicators found. Running on a normal machine.\n");
    }

    return 0;
}
