# Nexon Game Security Bypass (2023/06)

Bypass Nexon Game Security features:
* <b>Memory integrity</b>:
  Hooks NtReadVirtualMemory and various memory integrity checks implemented in the game security modules (BlackCall64.aes & BlackCipher64.aes)
  and redirects the address being read to a copy of the security module.
  Denies access to the maplestory.exe module
* <b>External hacking program detection</b>
  Prevent detection of external programs such as CheatEngine

Game security related features:
* <b>CRC</b>	           - Bypass the games memory integrity check / CRC; redirect to copy of the game image
* <b>IsDebuggerPresent</b> - Do nothing, Return false
* <b>Nexon Game Analytics enqueue log</b> - Do nothing, Return false
* <b>MachineID</b>         - Generate random machine ID
* <b>Crash reporter init</b> - Don't initialize the crash reporter

<b>This project is strictly for educational purposes. <br/>It is not intended as a means to provide you with an unfair advantage on games protected by Nexon Game Security</b>
