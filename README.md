# Nexon Game Security Bypass (2023/06)

Bypass Nexon Game Security anti-cheat software security features.
Makes use of the Keystone assembler library so we can define inline assembly
and inject it into the process.

Nexon Game Security bypass features:
* <b>Memory integrity</b>:
  Hooks NtReadVirtualMemory and various memory integrity checks implemented in the game security modules (BlackCall64.aes & BlackCipher64.aes)
  and redirects the address being read to a copy of the security module.
  Denies access to the maplestory.exe module
* <b>External hacking program detection</b>
  Prevent detection of external programs such as CheatEngine
  Hooks NtOpenProcess and NtQuerySystemInformation
* <b>Module scanning</b>
  Prevent BlackCipher64.aes from scanning for signatures of modules
  Iterate through static filtered list of modules 
* <b>Debugger</b>
  Bypass some of the debugger checks
  Some of these are implemented by Themida and some rely on the flow of execution

Game bypass features:
* <b>CRC</b>	             - Bypass the games memory integrity check / CRC; redirect to copy of the game image
* <b>IsDebuggerPresent</b>   - Do nothing, Return false
* <b>Nexon Game Analytics enqueue log</b> - Do nothing, Return false
* <b>MachineID</b>           - Generate random machine ID
* <b>Crash reporter init</b> - Don't initialize the crash reporter

<b>This project is strictly for educational purposes. It is not intended as a means to provide you with an unfair advantage on games protected by Nexon Game Security</b>
