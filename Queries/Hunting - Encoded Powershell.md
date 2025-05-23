# Powershell Obfuscation 

## Warum Powershell für Angreifer interessant ist

Powershell ist ein fester Bestandteil moderner Windows-Systeme und bietet durch .NET-Anbindung mächtige Möglichkeiten zur Automatisierung. Diese Eigenschaften machen es auch für Angreifer attraktiv:

- Auf jedem Windows-System vorhanden (kein zusätzlicher Code nötig)
- Direkter Zugriff auf Windows-APIs und Netzwerkressourcen
- Kann Code aus dem Speicher ausführen (fileless execution)
- Oft unzureichend überwacht oder eingeschränkt

## Warum Encoded Powershell ein Risiko darstellt
Angreifer codieren PowerShell-Befehle um Sicherheitsmechanismen zu umgehen:

* Einfache Signaturen und Filter, Intrusion Detection Systems und SIEM-Regeln können die eigentlichen Befehle nicht erkennen, wenn sie Base64-kodiert sind. Die Codierung verschleiert Schlüsselwörter wie `Invoke-Expression`, `Net.WebClient`, `DownloadString` oder Namen bekannter Schadsoftware wie Mimikatz.   
* Fileless Execution: Codierte Befehle werden oft verwendet, um Skripte oder Binaries direkt aus dem Internet in den Speicher zu laden und auszuführen (`IEX (New-Object Net.WebClient).DownloadString(...)`), ohne dass eine Datei auf die Festplatte geschrieben wird. Dies erschwert die forensische Analyse und die Erkennung erheblich.
* Umgehung von Execution Policies: Die Verwendung von Parametern wie `-Command` oder `-EncodedCommand` kann die Powershell Execution Policy umgehen, die standardmäßig das Ausführen von Skripten einschränken soll.
* Verschleierung der Gesamtaktivität: Codierung ist oft Teil einer mehrstufigen Obfuskationsstrategie. Angreifer können Base64 mit anderen Techniken wie String-Manipulation, Zeichenkettenzerlegung, zufälliger Groß- / Kleinschreibung oder Komprimierung kombinieren, um die Analyse weiter zu erschweren.
* Living off the Land: Als vorinstalliertes Windows Tool verhält sich Powershell mit codierten Befehlen unaufälliger als externe Tools / Frameworks.   

## Legitime Verwendung
Laut Microsoft-Dokumentation ist der Hauptzweck von `-EncodedCommand`, die Ausführung von Befehlen zu ermöglichen, die komplexe Anführungszeichen, geschweifte Klammern oder andere Sonderzeichen enthalten, die bei der direkten Übergabe an die Kommandozeile zu Problemen führen könnten. Durch die Kodierung des Befehls als Base64-String werden diese Interpretationsprobleme vermieden. Außerdem sind wir in Kundenumgebungen bereits auf die folgenden Verwendungen gestoßen: 

* Systemadministration & Automatisierung:
  * Ausführen von Skripten mit komplexen Parametern: Übergabe von Parametern, die Sonderzeichen, JSON-Strings oder andere komplexe Daten enthalten, an ein PowerShell-Skript, das über powershell.exe aufgerufen wird.
  * Scheduled Tasks / Remote-Ausführung: In Szenarien, in denen Befehle über mehrere Schichten oder Systeme übergeben werden, die komplexe Strings verändern könnten (z.B. Argumente im Task Scheduler, bestimmte Remote-Management-Tools, Skripte, die andere Skripte aufrufen).
  * Einbetten von Befehlen: Speichern oder Übertragen von Powershell-Befehlen innerhalb anderer Dateiformate (z.B. XML-Konfigurationsdateien, JSON-Nutzdaten, HTML-Seiten), bei denen die direkte Einbettung zu Syntaxkonflikten führen würde.
* Interoperabilität: Bei Aufrufen von Powershell aus anderen Programmier- oder Skriptsprachen (z.B. Python, Batch, C#), bei denen das korrekte Escaping der Powershell-Syntax schwierig sein kann.
  * Seltene / Nischenfälle: In wenigen Fällen verwendet von legitimen Software-Installationsprogrammen oder Konfigurationstools.
  * Einbetten von nicht-textuellen Daten (wie Icons für GUI-Skripte) direkt in eine Skriptdatei. Dies verwendet jedoch typischerweise `[Convert]::FromBase64String` innerhalb des Skripts, nicht den `-EncodedCommand` Parameter beim Aufruf.

## Der `-EncodedCommand` Parameter
Der Parameter `-EncodedCommand` ist ein legitimes Feature von `powershell.exe` (Windows Powershell 5.1 und früher) und `pwsh.exe` (Powershell 6 und neuer).
Powershell erlaubt es, Parameter in vollständig ausgeschriebener Form (z. B. `-EncodedCommand`) oder in verkürzter Schreibweise (wie `-enc` oder sogar `-e`) zu verwenden, solange die Kurzform eindeutig auf einen gültigen Parameter verweist. Dieses Verhalten basiert auf einem eingebauten Mechanismus zur automatischen Parametervervollständigung, der dem Nutzer Arbeit abnehmen und Fehler reduzieren soll. Um codierte Powershell-Befehle zu finden, reicht es also nicht nach dem Parameter `-EncodedCommand` zu suchen. Die alternativen Schreibweisen müssen in der Suche berücksichtigt werden.

| Variante      | Beschreibung                             |
| ------------- |------------------------------------------|
|-e	| Kürzeste eindeutige Abkürzung (Achtung: Konflikt mit -ExecutionPolicy)|
|-enc	| Gängige Abkürzung|
|-e... -encodedcomman	| Längere Abkürzungen|
|-encodedcommand |	Vollständiger Parameter|
|-ec |	Weniger gängige, aber gültige Abkürzung|
|-EnCoDeDcOmMaNd	| Beispiel für zufällige Groß-/Kleinschreibung|
|-^e^n^c	| Beispiel für eine Caret Interruption|

``` Powershell Encoding
# Der ursprüngliche Befehl
$command = "ping 8.8.8.8"

# 1. String in Bytes umwandeln (unter Verwendung von UTF-16LE)
$bytesUtf16le = [System.Text.Encoding]::Unicode.GetBytes($command)

# 2. Bytes in einen Base64-String umwandeln
$base64CommandUtf16le = [System.Convert]::ToBase64String($bytesUtf16le)

# Ausgabe
Write-Host "Ursprünglicher Befehl: $command"
Write-Host "Bytes (UTF-16LE) als Hex-String: $($bytesUtf16le | ForEach-Object { $_.ToString('X2') })"
Write-Host "Base64-kodierter Befehl (aus UTF-16LE Bytes): $base64CommandUtf16le"
```
Ausgeführt wird das encodierte Kommando dann in Base64:
``` Powershell
powershell.exe -EncodedCommand $encodedCommand
```

## CrowdStrike NextGen SIEM Query
Im Rahmen unserer Arbeit mit CrowdStrike NG-SIEM und LogScale haben wir eine bestehende [Query](https://www.reddit.com/r/crowdstrike/comments/xm7lsn/20220923_cool_query_friday_logscale_humio/?rdt=54594) zur Erkennung von obfuskierten PowerShell-Kommandos übernommen und erweitert. 

```
//Get Powershell and pwsh events
#event_simpleName=ProcessRollup2 
| event_platform=Win 
| ImageFileName=/\\(powershell|pwsh)\.exe/i
//Search for "-EncodeCommand" and variations   
| groupby([ParentBaseFileName, CommandLine], function=stats([count(aid, distinct=true, as="uniqueEndpointCount"), count(aid, as="executionCount")]), limit=max)
//Set endpoint prevalence threshold
| uniqueEndpointCount < 3
//Calculating command length & Isolate Base64 sting
| cmdLength := length("CommandLine")
//| CommandLine=/\s(|[\^])-(|[\^])[e]{1,2}[ncodema^]*\s(?<base64String>\S+)|^/i
//| CommandLine=/\s-[eE^]{1,2}[ncodema^]*\s(?<base64String>\S+)/i
| CommandLine=/\s(|[\^])-(|[\^])[e]{1,2}[ncodema^]*\s(?<base64String>\S+)/i
//| replace("^", with="", field=base64String, as=CleanBase64String)
//Get Entropy of Base64 String
| b64Entropy := shannonEntropy("base64String")
// Set entropy threshold
| b64Entropy > ?EntropyGreaterThan
//Decode encoded command blob
| decodedCommand := base64Decode(base64String, charset="UTF-16LE")
//Outputting to table
| table([ParentBaseFileName, uniqueEndpointCount, executionCount, cmdLength,  b64Entropy, decodedCommand, CommandLine])
//Uncomment next line to search URLs in the decoded command
//| decodedCommand=/https?/i
//Uncomment next line to search IP:Port in the decoded command 
//|regex("(?<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\:(?<port>\d{2,5})", field=decodedCommand)
//Uncomment next line to search IP in the decoded command 
//|regex("(?<ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", field=decodedCommand)
```
## Erwartete Ausgabe
<img width="2343" alt="Image" src="https://github.com/user-attachments/assets/72cc5ce1-a396-4e32-a8f0-6952fe586473" />
