```
// Hunting for Rare Parent Process to Windows Shell with Enrichment
#event_simpleName=ProcessRollup2 event_platform=Win
| case { in(field=FileName, values=["powershell.exe", "cmd.exe", "pwsh.exe"]) | IsChild := "1"; * | IsChild := "0" }
| case { IsChild = "1" | ProcId := ParentProcessId | ChildProcess := FileName | ChildCommandLine := CommandLine;
IsChild = "0" | ProcId := TargetProcessId | ParentCommandLine := CommandLine | ParentFileName := FileName | ParentFilePath := FilePath | ParentSHA256HashData := SHA256HashData; }
| groupBy([ComputerName, ProcId], function=([count(ParentProcessId, distinct=true, as=EventCount), collect([ParentFileName, ParentSHA256HashData, ParentFilePath, ParentCommandLine, ChildProcess]), collect(ChildCommandLine, limit=4)]), limit=max)
| EventCount > 1
| groupBy([ParentSHA256HashData], function=([collect([aid, ParentFileName, ParentFilePath, ParentCommandLine, ChildProcess, ChildCommandLine]), count(ComputerName, as=HostCount)]))
| HostCount < 5
| sort([HostCount, ParentFileName], order=asc)
```