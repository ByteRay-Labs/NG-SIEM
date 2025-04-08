```
//Get Powershell, Powershell_ise and pwsh events
#event_simpleName=ProcessRollup2 
| event_platform=Win 
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
//Search for "-EncodeCommand" and variations   
| CommandLine=/\s-[eE^]{1,2}[ncodema^]*\s(?<base64String>\S+)/i
| groupby([ParentBaseFileName, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
//Set endpoint prevalence threshold
| uniqueEndpointCount < 3
//Calculating command length & Isolate Base64 sting
| cmdLength := length("CommandLine")
| CommandLine=/\s-[eE^]{1,2}[ncodema^]*\s(?<base64String>\S+)/i
//Get Entropy of Base64 String
| b64Entroy := shannonEntropy("base64String")
// Set entropy threshold
| b64Entroy > ?EntropyGreaterThan
//Decode encoded command blob
| decodedCommand := base64Decode(base64String, charset="UTF-16LE")
//Outputting to table
 | table([ParentBaseFileName, uniqueEndpointCount, executionCount, cmdLength,  b64Entroy, decodedCommand])
//Search for URLs and IPs in decoded command
//| decodedCommand=/https?/i
//|regex("(?<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\:(?<port>\d{2,5})", field=decodedCommand)
//|regex("(?<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\"", field=decodedCommand)
```