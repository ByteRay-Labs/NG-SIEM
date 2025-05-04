# Rare Powershell Parents

## Warum Powershell für Angreifer interessant ist
Powershell ist ein fester Bestandteil moderner Windows-Systeme und bietet durch .NET-Anbindung mächtige Möglichkeiten zur Automatisierung. Diese Eigenschaften machen es auch für Angreifer attraktiv:

- Auf jedem Windows-System vorhanden (kein zusätzlicher Code nötig)
- Direkter Zugriff auf Windows-APIs und Netzwerkressourcen
- Kann Code aus dem Speicher ausführen (fileless execution)
- Oft unzureichend überwacht oder eingeschränkt

**Living off the Land**-Taktiken nutzen Powershell, um Angriffe unauffällig und ohne zusätzliche Tools durchzuführen.

## Warum ungewöhnliche Powershell Parent-Prozesse ein Risiko darstellen
Der Kontext eines Powershell Prozesses kann auf einen möglichen Missbrauch von Powershell hinweisen. Nachfolgend beschreiben wir, in welchen Fällen die Prozessbeziehungen von Powershell verdächtig sind und wie wir mit CrowdStrike NextGen SIEM nach verdächtigen Prozessbeziehnugnen suchen. 

* Initial Execution: Oft ist das Starten von Powershell der erste Schritt nach einer erfolgreichen Kompromittierung, um weitere Aktionen durchzuführen oder Payloads nachzuladen.
  * Beispiel: Ein schadhaftes Office-Makro (`winword.exe`, `excel.exe`) startet Powershell, um die nächste Angriffsstufe herunterzuladen und auszuführen.
  * Beispiel: Die Ausnutzung einer Sicherheitslücke in einem Browser (`chrome.exe`, `msedge.exe`) führt zur Ausführung von Powershell.

* Evasion: Angreifer versuchen aktiv, Erkennungsregeln zu umgehen, die auf erwarteten Prozessbeziehungen basieren. 
  * Beispiel: Ausführung von Powershell über WMI (Windows Management Instrumentation). Hierbei wird `wmiprvse.exe` zum Parent-Prozess anstelle des eigentlichen initiierenden Prozesses (z. B. eines Makros in Word).
  * Beispiel: Anwendung von Parent Process ID (PPID) Spoofing. Dabei wird Powershell so manipuliert, dass es aussieht, als wäre es von einem harmlosen Prozess wie `explorer.exe` gestartet worden, obwohl der tatsächliche Auslöser Malware war.
  
* Persistence: Angreifer nutzen Mechanismen, bei denen ein Systemprozess der natürliche Elternprozess ist, die ausgeführte Aktion jedoch bösartig ist.
  * Beispiel: WMI Event Subscriptions (Ereignisabonnements), die bei bestimmten Systemereignissen Powershell-Code über `wmiprvse.exe` ausführen ([T1546.003](https://attack.mitre.org/techniques/T1546/003/)).
  * Beispiel: Bösartige geplante Aufgaben (Scheduled Tasks), die Powershell über die Task Scheduler-Instanz von `svchost.exe` starten ([T1053.005](https://attack.mitre.org/techniques/T1053/005/)).

* Lateral Movement: Ausführung von Powershell auf entfernten Systemen unter Nutzung eingebauter Windows-Protokolle und -Werkzeuge.
  * Beispiel: Verwendung von WMI (`wmiprvse.exe` oder `wmic.exe` initiiert Remote-Ausführung), WinRM (`wsmprovhost.exe`) oder potenziell DCOM (`svchost.exe`), um Powershell auf einem Zielsystem zu starten. Auf dem Zielsystem erscheinen dann diese Dienstprozesse als Parent von Powershell.   

Ein zentraler Treiber für viele dieser Szenarien ist die Evasion. Techniken wie die WMI-Ausführung oder PPID-Spoofing wurden speziell entwickelt, um die Überwachung der Prozessabstammung zu täuschen oder zu brechen. Detection-Regeln wie "Blockiere Powershell als Child-Prozess von Word" verleiten Angreifer dazu, weniger verdächtigen Parent-Prozesse wie `wmiprvse.exe` zu starten. 
Die Beobachtung von alternativen, ungewöhnlichen Parent-Prozessen wird somit zu einer neuen Erkennungsmöglichkeit. Darüber hinaus kann ein einzelner ungewöhnlicher Parent-Prozess auf mehrere Angriffsziele gleichzeitig hindeuten. 
Beispielsweise kann `wmiprvse.exe` als Parent-Prozess von Powershell auf eine Erstausführung via WMI, auf Persistenz durch ein WMI-Ereignisabonnement oder auf Lateral Movement durch Remote-WMI-Ausführung hinweisen. WMI ist ein vielseitiges Werkzeug für Angreifer und erfordert die Beobachtung der Kette `wmiprvse.exe -> powershell.exe` für eine weitergehende Untersuchung (Analyse der Kommandozeile, WMI-Protokolle, Netzwerkverbindungen), um die spezifische Angriffsaktivität zu bestimmen.

## Häufige legitime Powershell-Elternprozesse
Um Anomalien erkennen zu können, ist es wichtig, den Normalzustand zu verstehen. Powershell wird in vielen administrativen und interaktiven Szenarien legitim gestartet. Die folgenden Elternprozesse sind typischerweise unbedenklich:

* `explorer.exe` (Windows Explorer): Dies ist der häufigste Parent-Prozess für interaktive Powershell-Sitzungen. Er tritt auf, wenn ein Benutzer Powershell über das Startmenü, oder Ausführen (Win + R), die Adressleiste des Explorers oder durch Klicken auf eine `.ps1`-Skriptdatei startet.   
* `cmd.exe` (Eingabeaufforderung): Wenn ein Benutzer Powershell aus einer bereits laufenden Eingabeaufforderungssitzung heraus startet, wird `cmd.exe` zum Parent-Prozess.
* `svchost.exe` (Task Scheduler Service): Powershell-Skripte, die über Scheduled Tasks ausgeführt werden, haben eine spezifische Instanz von `svchost.exe` als Parent-Prozess. Diese Instanz ist typischerweise durch `-k netsvcs -p -s Schedule` identifizierbar. 
* IDEs / Konsolen: Werkzeuge wie Powershell ISE (`powershell_ise.exe`), Visual Studio Code (`Code.exe`), Windows Terminal (`wt.exe`) oder andere Entwicklerkonsolen starten legitimerweise Powershell-Prozesse, wenn Benutzer Skripte entwickeln, ausführen oder debuggen.
* Andere administrative Werkzeuge: Systemmanagementlösungen (z. B. SCCM-Agent) oder spezialisierte Drittanbieter-Administrationswerkzeuge können ebenfalls legitime Parent-Prozesse für Powershell sein.
* `powershell.exe`: Eine Powershell-Instanz kann eine weitere Powershell-Instanz starten. Dies geschieht beispielsweise bei der Verwendung unterschiedlicher Anmeldeinformationen, beim Aufbau von Remoting-Sitzungen (Enter-PSSession) oder innerhalb komplexer Skriptkonstrukte, die separate Ausführungsumgebungen erfordern.

Es ist wichtig zu betonen, dass selbst ein legitimer Parent-Prozess keine Garantie für legitime Aktivitäten ist. Die Kommandozeilenargumente, mit denen `powershell.exe` gestartet wird, sind ebenso entscheidend für die Bewertung. Stark verschleierte Befehle (z. B. mittels `-EncodedCommand` oder `-e`), der Einsatz von Download-Cradles (wie `DownloadString` oder `System.Net.WebClient`) oder das Ausführen in einem versteckten Fenster (`-WindowStyle Hidden` oder `-w Hidden`) sind unabhängig vom Parent verdächtig.

Besondere Aufmerksamkeit erfordert der Parent-Prozess `svchost.exe` (Task Scheduler). Obwohl dies ein legitimer Mechanismus ist, missbrauchen Angreifer Scheduled Tasks für Persistenz und Ausführung (MITRE ATT&CK [T1053.005](https://attack.mitre.org/techniques/T1053/005/)). Daher erfordert die Prozesskette `svchost.exe -> powershell.exe` immer eine genauere Untersuchung: Welche Aufgabe wurde ausgeführt? Welchen Inhalt hat das Powershell-Skript oder der Befehl? Im Gegensatz dazu ist eine Kette wie `winword.exe -> powershell.exe` fast immer ein klares Anzeichen für schadhaftes Verhalten. 

## Verdächtige Parent-Prozesse
Im Folgenden gehen wir im Detail auf ungewöhnliche Parent-Prozesse ein.

### Microsoft Office-Anwendungen (`winword.exe`, `excel.exe`, `powerpnt.exe`, etc.)
Office-Anwendungen sollten normalerweise keine Kommandozeilen-Interpreter oder Skripting-Engines direkt starten. Dies ist ein klassischer Indikator für die Ausführung bösartiger Makros (bsp. [T1566.001](https://attack.mitre.org/techniques/T1566/001/) Spearphishing Attachment).

**Mechanismus:** Bösartige VBA-Makros verwenden Funktionen wie `Shell()` oder WMI-Objekte , um `powershell.exe` zu starten.

### Webbrowser (`chrome.exe`, `msedge.exe`, `firefox.exe`, `iexplore.exe`, etc.)
Browser sollten Powershell normalerweise nicht direkt starten. Dies deutet oft auf die Ausnutzung einer Browser-Schwachstelle, Aktivitäten einer bösartigen Erweiterung oder die Ausführung eines Drive-by-Downloads hin (T1204 User Execution).

**Mechanismus:** Exploits erlangen Codeausführung innerhalb des Browserprozesses oder bösartige Erweiterungen mit ausreichenden Berechtigungen starten Powershell.

### WMI Provider Host (`wmiprvse.exe`)
Obwohl `wmiprvse.exe` ein legitimer Windows-Prozess ist, kann sein Starten von Powershell hochgradig verdächtig sein. Es deutet auf den Missbrauch von WMI für Ausführung ([T1047](https://attack.mitre.org/techniques/T1047/) Windows Management Instrumentation), Persistenz ([T1546.003](https://attack.mitre.org/techniques/T1546/003/) WMI Event Subscription) oder Lateral Movement ([T1021.006](https://attack.mitre.org/techniques/T1021/006/) Remote Services: Windows Remote Management) hin. 

**Mechanismus:** Angreifer verwenden `wmic.exe` (lokal oder remote), Powershells WMI-Cmdlets (`Invoke-WmiMethod`, `Get-WmiObject`) oder COM-APIs, um mit WMI-Klassen (`Win32_Process`, `Win32_ScheduledJob`, Ereignis-Consumer / Filter) zu interagieren und Befehle oder Skripte auszuführen. Die Ausführung wird von einem WMI-Provider gehandhabt, der in `wmiprvse.exe` gehostet wird.

### Maskierte Elternprozesse (via PPID Spoofing)
Ein normalerweise harmloser Prozess wie `explorer.exe` oder sogar eine `svchost.exe`-Instanz (die nicht zum Task Scheduler gehört) startet Powershell mit bösartigen Kommandozeilenargumenten oder zeigt verdächtiges Netzwerkverhalten. Dies deutet auf potenzielles PPID Spoofing hin ([T1134](https://attack.mitre.org/techniques/T1134/) Access Token Manipulation, bezogene Techniken zur Prozessmanipulation).

**Mechanismus:** Angreifer verwenden spezifische Windows-API-Aufrufe (wie `CreateProcess`) mit Flags (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`) während der Prozesserstellung, um einen beliebigen Parent-Prozess anzugeben.
Erkennungshinweis: Kann durch Vergleich der echten Parent-PID (manchmal von fortgeschrittenen EDRs oder über ETW Kernel-Prozessprotokolle protokolliert) mit der gemeldeten Parent-PID erkannt werden, oder durch Fokussierung auf das Verhalten des Kindprozesses (Kommandozeile, Netzwerkverbindungen) unabhängig vom gemeldeten Parent-Prozess.

### Andere LOLBINs / Unerwartete Systemprozesse (`regsvr32.exe`, `mshta.exe`, `rundll32.exe`, etc.)
Diese legitimen Windows-Binärdateien werden oft von Angreifern missbraucht, um die Ausführung zu verschleiern ([T1218](https://attack.mitre.org/techniques/T1218/) System Binary Proxy Execution). Wenn sie Powershell starten, ist dies oft ein Zeichen für bösartige Aktivitäten.

**Mechanismus:**  Angreifer rufen diese LOLBINs (Living Off The Land Binaries) mit spezifischen Argumenten auf, die auf bösartige Skripte verweisen (lokal oder remote, z. B. `.sct`-Dateien für `regsvr32.exe`), welche dann Powershell-Befehle ausführen.
Wenn ein Angreifer beispielsweise Powershell aus einem Word-Makro heraus ausführen möchte, aber die Erkennung von `winword.exe -> powershell.exe` vermeiden will, kann er WMI verwenden, was zur Kette `wmiprvse.exe -> powershell.exe` führt , oder PPID-Spoofing mit Ziel `explorer.exe`, was zur (gefälschten) Kette `explorer.exe -> powershell.exe` führt.

Eine wichtige verwandte Evasionstechnik ist "Powershell without Powershell". Hierbei führen Angreifer Powershell-Logik aus, ohne `powershell.exe` zu starten, indem sie .NET-Assemblies direkt laden (z. B. über `rundll32.exe` oder `msbuild.exe`). Dies erzeugt zwar keinen `powershell.exe`-Prozess (und somit keinen Parent-Prozess für `powershell.exe`), umgeht aber die Überwachung, wenn diese sich ausschließlich auf die Prozesserstellung von `powershell.exe` konzentriert. Die Erkennung erfordert die Überwachung von LOLBINs, die `System.Management.Automation.dll` laden, oder anderer Verhaltensanomalien. Die Überwachung ungewöhnlicher Parent-Prozesse für `powershell.exe` ist notwendig, aber nicht ausreichend; die Überwachung ungewöhnlicher Modulladungen im Zusammenhang mit Powershell in anderen Prozessen ist ebenfalls für eine umfassende Erkennung erforderlich.


## CrowdStrike NextGen SIEM Query
```
// Hunting for Rare Parent Process to Windows Shell with Enrichment
#event_simpleName=ProcessRollup2 event_platform=Win
| case { in(field=FileName, values=["powershell.exe", "powershell_ise.exe", "cmd.exe", "pwsh.exe"]) | IsChild := "1"; * | IsChild := "0" }
| case { IsChild = "1" | ProcId := ParentProcessId | ChildProcess := FileName | ChildCommandLine := CommandLine;
IsChild = "0" | ProcId := TargetProcessId | ParentCommandLine := CommandLine | ParentFileName := FileName | ParentFilePath := FilePath | ParentSHA256HashData := SHA256HashData; }
| groupBy([ComputerName, ProcId], function=([count(ParentProcessId, distinct=true, as=EventCount), collect([ParentFileName, ParentSHA256HashData, ParentFilePath, ParentCommandLine, ChildProcess]), collect(ChildCommandLine, limit=4)]), limit=max)
| EventCount > 1
| groupBy([ParentSHA256HashData], function=([collect([aid, ParentFileName, ParentFilePath, ParentCommandLine, ChildProcess, ChildCommandLine]), count(ComputerName, as=HostCount)]))
| HostCount < 5
| sort([HostCount, ParentFileName], order=asc)
```
