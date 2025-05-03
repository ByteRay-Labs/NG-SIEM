# Powershell Command Length
## Warum Abweichungen der Befehlslänge auf potenzielle Bedrohungen hinweisen 
Angreifer verwenden häufig Methoden in Powershell, die zu ungewöhnlich langen Befehlszeilen führen. Das Überwachen von Abweichungen gegenüber der üblichen Befehlslänge kann daher ein wertvoller Ansatz zur Erkennung verdächtiger Aktivitäten sein.
Ungewöhnlich lange Befehle können ein Indikator für einen Angriff sein.

* Verschleierung / Obfuscation
  * Kodierung: Verwendung von Base64 (`-EncodedCommand`, `-e`, `-ec`), Hexadezimal oder ASCII zur Darstellung von Befehlen oder Skriptblöcken.   
  * Escape-Zeichen: Einsatz von Backticks (`) innerhalb von Zeichenketten oder Befehlen, um die Lesbarkeit zu beeinträchtigen.   
  * Leerzeichen & Kommentare: Einfügen unnötiger Leerzeichen oder Kommentare.
  * Einbetten von Payloads & Skripten: Einfügen ganzer Skripte oder binärer Payloads direkt in die Befehlszeile.   
  
* Dateilose Ausführung & LotL: Fileless-Angriffe oder welche, die nur integrierte Werkzeuge verwenden (Living off the Land), verlassen sich oft auf komplexe, einzeilige Befehle, die an powershell.exe übergeben werden, um Payloads von entfernten Quellen herunterzuladen und auszuführen oder verkettete Aktionen durchzuführen. Diese komplexen Anweisungen führen naturgemäß zu längeren Befehlen.   
* Offensive Frameworks: Werkzeuge wie Empire, PowerSploit, Cobalt Strike usw. nutzen PowerShell intensiv und generieren oft lange, verschleierte Befehle für ihre Payloads.   
* Ungewöhnlich lange Befehle sind ein starker Indikator, da sie direkt mit gängigen Angreifertechniken zur Umgehung und Ausführung korrelieren ([T1027.010](https://attack.mitre.org/techniques/T1027/010/) Obfuscated Files or Information). Legitime administrative Aufgaben erfordern selten die extremen Längen, die oft durch die genannten Methoden erzeugt werden. Legitime Administratoren verwenden typischerweise Skriptdateien (.ps1) für komplexe Logik , nicht verschleierte Einzeiler. Angreifer verwenden lange, verschleierte Befehlszeilen genau deshalb, um das Schreiben von Dateien auf die Festplatte zu vermeiden (dateilose Ausführung) und um einfache Erkennungslogiken zu umgehen. Dieser Unterschied in der Betriebspraxis macht die Länge zu einem relativ nützlichen Unterscheidungsmerkmal.   


| Technik       |  Auswirkung auf Länge | Beschreibung                             |
| ------------- |-----------------------|------------------------------------------|
| Base64 (`-EncodedCommand`)|	Signifikante Zunahme	| Versteckt Skriptinhalt, sehr häufig für Payload-Übermittlung. 	
| String-Verkettung / Formatierung |	Mäßige/Variable Zunahme | Wird verwendet, um Schlüsselwörter aufzubrechen und einfache String-Übereinstimmungen zu umgehen. Kann je nach Komplexität erheblichen Overhead hinzufügen.	
| Caret / Backtick Escaping	| Leichte/Mäßige Zunahme |	Einfache Umgehungstechnik, fügt ein Zeichen pro maskiertem Zeichen hinzu. Oft minimal verwendet. (`^`)	
| Remote Download Cradles | Variabel (Oft lang)	|  Befehle wie `IEX (New-Object Net.WebClient).DownloadString(...)` können lang sein, insbesondere mit verschleierten URLs oder zusätzlicher Logik.	
| Eingebettete Skriptblöcke/Payloads |	Signifikante Zunahme |	Ganze Skripte oder kodierte Binärdateien werden direkt in der Befehlszeile übergeben. Kann fast maximale Befehlslängen erreichen.	
| Kompression (Gzip, etc.) + Encode |	Variabel (Potenziell lang)	| Payload mag kleiner sein, aber Dekompressionslogik fügt Länge hinzu. Führt oft immer noch zu langen Base64-Strings. (Konzeptionell diskutiert in ).

# Die Macht des Baselining: "Normal" etablieren

## Grundlagen der Anomalieerkennung
Die Kernidee besteht darin, darzustellen was "normale" Aktivität für die länge der ausgeführten Powershell-Befehle ist, und dann Abweichungen von dieser Norm zu identifizieren.   

## Erstellung der Baseline
Die Abfrage analysiert historische PowerShell-Executions und die jeweiligen Befehlslängen über einen definierten Zeitraum.
Sie berechnet statistische Maße der zentralen Tendenz (z. B. Mittelwert, Median) und Streuung (z. B. Standardabweichung) für Befehlslängen während dieses Baseline-Zeitraums (implizit aus ). Dies definiert den erwarteten Bereich der Befehlslängen.   

## Zeitraum: 7-Tage-Baseline
* Erfassung wöchentlicher Zyklen: Viele organisatorische Arbeitsabläufe und administrative Aufgaben folgen wöchentlichen Mustern (z. B. unterschiedliche Aktivitäten an Wochentagen vs. Wochenenden, wöchentliche Berichte, Patching-Zeitpläne). Eine 7-Tage-Baseline reicht oft aus, um diese typischen Rhythmen zu erfassen.   
* Stabilität vs. Anpassungsfähigkeit: der gewählte Zeitraum ist eine Balance. Kürzere Baselines (z. B. 24 Stunden) können übermäßig empfindlich auf tägliche Schwankungen reagieren. Längere Baselines passen sich möglicherweise zu langsam an legitime Verhaltensänderungen an oder riskieren, vergangene Anomalien in das "normale" Profil zu integrieren. * Ein 7-Tage-Fenster glättet tägliche Variationen und bleibt gleichzeitig einigermaßen anpassungsfähig. 
Die Wahl einer 7-Tage-Baseline ist eine bewusste Abwägung, die darauf abzielt, das Signal/Rausch Verhältnis für die Erkennung von Anomalien im Zusammenhang mit wöchentlichen menschlichen/systemischen Verhaltensmustern zu maximieren. Geschäfts- und IT-Betriebe haben oft wöchentliche Rhythmen. Ein Server könnte bestimmte Wartungsskripte nur am Wochenende ausführen, oder Benutzer könnten bestimmte Aufgaben nur montags erledigen. Wenn am Mittwoch ein sehr langer Befehl auftaucht, aber ähnliche lange Befehle jeden Samstag aufgrund von Backups normal sind, hilft die 7-Tage-Baseline dabei, das potenziell anomale Ereignis am Mittwoch vom normalen Ereignis am Samstag zu unterscheiden. Dies reduziert Fehlalarme im Vergleich zu einer kürzeren Baseline, die den wöchentlichen Kontext nicht erfasst.
* Anpassung an die betriebliche Realität: Je nach Umgebung kann eine Anpassung des Zeitraums für bessere Ergebnisse sorgen.

## CrowdStrike NextGen SIEM Query
```
// Average Powershell Command Length
#event_simpleName=ProcessRollup2
| ImageFileName=/\\(powershell(_ise)?|pwsh)\.exe/i
| CommandLength := length("CommandLine") | CommandLength>0
| aid=?AID
// Classify Data into Historical and LastDay
| case {
    test(@timestamp < (end() - duration(7d))) | DataSet:="Historical";
    test(@timestamp > (end() - duration(1d))) | DataSet:="LastDay"; 
    *}
// Calculate Average Command Length
| groupBy([DataSet, aid], function=avg(CommandLength))
| case {
    DataSet="Historical" | rename(field="_avg", as="historicalAvg");
    DataSet="LastDay" | rename(field="_avg", as="todaysAvg");
    *
}
// Aggregate Averages
| groupBy([aid], function=[avg("historicalAvg", as=historicalAvg), avg("todaysAvg", as=todaysAvg)])
// Calculate Percentage Increase
| PercentIncrease := (todaysAvg - historicalAvg) / historicalAvg * 100
| format("%d", field=PercentIncrease, as=PercentIncrease)
| format(format="%.2f", field=[historicalAvg], as=historicalAvg)
// Filter and Sort Results
| PercentIncrease > 0
| sort(PercentIncrease, limit=10000)
```
