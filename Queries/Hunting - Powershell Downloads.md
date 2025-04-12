```
// Powershell Downloads
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
| CommandLine=/Invoke\-WebRequest|Net\.WebClient|Start\-BitsTransfer/i
| regex("(?<URL>https?://[^'\"]+)", field=CommandLine)
| replace("https://", with="", field=Domain, as=vt_lookup)
| UrlBase:="https://www.virustotal.com/gui/domain/"
| format(format="[Virustotal](%s%s)", field=[UrlBase, vt_lookup], as=DomainLookup)
| table([DomainLookup, URL, ComputerName, UserName, CommandLine], limit=20000)
```