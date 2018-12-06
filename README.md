# Kaiser
File-less persistence, attacks and anti-forensic capabilities.

**This project is discontinued.**

Related paper: https://github.com/NtRaiseHardError/NtRaiseHardError.github.io/blob/master/_posts/2018-12-06-Anti-forensic-Malware-and-File-less-Malware.md

## How to Build:

1. Compile _Kaiser.dll_ in Release mode
2. Run _BuildKaiser.ps1_

## How to Use:

1. Run _BuildKaiser.ps1_ to build the _Payload.ps1_ script
2. Upload the _Payload.ps1_ script such that it can be directly downloaded as raw text
3. Update the _BuildKaiser.ps1_ script to include the URL of _Payload.ps1_
4. Run _BuildKaiser.ps1_ to build the _Installer.ps1_ script
5. Run the _Installer.ps1_ script with administrative privileges on the target machine

## Known bugs:

* Threaded `XxxNetSend` sends will buffer (reason unknown)
* `PurgeXxx` functions are not guaranteed to work (perhaps this is because it uses `ShellExecuteEx`
* More?

## TODO

* `CommandPrintStatus` to print the status of Kaiser?
* Convert functions in `firewall.c` to WinAPI
* [OPTIONAL] Make C2 connection loop until established
*  Convert Functions in `registry.c` to WinAPI
* Send debugging warnings/errors back to C2
* Make `PurgeProcessMonitor` asynchronous (`IWbemServices::ExecNotificationQueryAsync`)
