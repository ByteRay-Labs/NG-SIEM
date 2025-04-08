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