param([int]$Port = 0)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$context = Get-Content -LiteralPath (Join-Path $projectRoot 'power_bi/project_context.json') -Raw | ConvertFrom-Json
$clientLibrary = 'C:\Program Files\Microsoft Power BI Desktop\bin\Microsoft.PowerBI.AdomdClient.dll'
$null = [System.Reflection.Assembly]::LoadFrom($clientLibrary)

function Read-Dax([object]$Connection, [string]$Query) {
    $command = $Connection.CreateCommand()
    $command.CommandText = $Query
    $reader = $command.ExecuteReader()
    $rows = [System.Collections.Generic.List[object]]::new()
    try {
        while ($reader.Read()) {
            $row = [ordered]@{}
            for ($index = 0; $index -lt $reader.FieldCount; $index++) {
                $name = $reader.GetName($index)
                if ($name -match '\[([^\]]+)\]$') { $name = $Matches[1] }
                $row[$name] = if ($reader.IsDBNull($index)) { $null } else { $reader.GetValue($index) }
            }
            $rows.Add([pscustomobject]$row)
        }
    } finally { $reader.Close() }
    return $rows.ToArray()
}

$ports = if ($Port) { @($Port) } else {
    Get-ChildItem -LiteralPath "$env:LOCALAPPDATA\Microsoft\Power BI Desktop\AnalysisServicesWorkspaces" -Filter msmdsrv.port.txt -Recurse |
        ForEach-Object { [int]([System.IO.File]::ReadAllText($_.FullName) -replace '[^0-9]', '') }
}
$connection = $null
foreach ($candidate in $ports) {
    $trial = $null
    try {
        $trial = [Microsoft.AnalysisServices.AdomdClient.AdomdConnection]::new("Data Source=localhost:$candidate")
        $trial.Open()
        $count = @(Read-Dax $trial 'EVALUATE ROW("windows", COUNTROWS(''Window''))')
        if ($count[0].windows -eq 11398) { $connection = $trial; break }
        $trial.Close()
    } catch { if ($trial) { $trial.Dispose() } }
}
if (-not $connection) { throw 'No refreshed CyberShield model found. Complete Home > Refresh (including the user privacy classification) first.' }

$results = [ordered]@{ report_bundle_id = $context.report_bundle_id; status = 'passed'; scope = 'Read-only DAX against actual Power BI Desktop model' }
try {
    $totals = @(Read-Dax $connection @'
EVALUATE ROW("windows", COUNTROWS('Window'), "flows", SUM('Window'[flow_count]),
 "supporting", COUNTROWS('SupportingFlows'), "decisions", COUNTROWS('FactPrototypeDecision'),
 "multiple_detector_alerts", [Alerts],
 "sql_development_alerts", CALCULATE([Alerts], 'DimDetector'[detector_id]="sql", 'Window'[split]="development"),
 "sql_development_false", CALCULATE([False alerts], 'DimDetector'[detector_id]="sql", 'Window'[split]="development"),
 "detector_filtered_flows", CALCULATE([Observed flows], 'DimDetector'[detector_id] IN {"lr","sql"}))
'@)
    $r = $totals[0]
    if ($r.windows -ne 11398 -or $r.flows -ne 207006 -or $r.supporting -ne 207006 -or $r.decisions -ne 91184) { throw 'DAX population reconciliation failed' }
    if ($null -ne $r.multiple_detector_alerts -or $r.sql_development_alerts -ne 26 -or $r.sql_development_false -ne 21 -or $r.detector_filtered_flows -ne 207006) { throw 'DAX detector/filter semantics failed' }
    $results.totals = $totals
    $roles = @(Read-Dax $connection @'
EVALUATE SUMMARIZECOLUMNS('Window'[split], "windows", COUNTROWS('Window'),
 "flows", SUM('Window'[flow_count]), "supporting", COUNTROWS('SupportingFlows'))
'@)
    $expectedRoles = @{ train=3493; calibration=1245; development=3413; unscored=3247 }
    foreach ($row in $roles) {
        if ($row.windows -ne $expectedRoles[$row.split] -or $row.flows -ne $row.supporting) { throw "DAX role propagation failed: $($row.split)" }
    }
    $results.roles = $roles
    $quality = @(Read-Dax $connection @'
EVALUATE SUMMARIZECOLUMNS('DimDetector'[detector_id], "tp", [Caught positives],
 "fp", [False positive windows], "recall", [Recall rate], "precision", [Precision rate],
 "f1", [F1 score], "average_precision", [Average precision], "false_positives_per_1000", [False alerts per 1000])
'@)
    $expected = Import-Csv -LiteralPath (Join-Path $context.bundle_path 'FactEvaluation.csv')
    if ($quality.Count -ne $expected.Count) { throw 'DAX detector count differs from bundle' }
    foreach ($row in $quality) {
        $match = @($expected | Where-Object detector_id -eq $row.detector_id)
        if ($match.Count -ne 1) { throw 'DAX unknown or repeated detector' }
        foreach ($metric in @('tp','fp','recall','precision','f1','average_precision','false_positives_per_1000')) {
            $value = $match[0].$metric
            if ([string]::IsNullOrWhiteSpace($value)) {
                if ($null -ne $row.$metric) { throw "Undefined $metric is not blank for $($row.detector_id)" }
            } else {
                $number = [double]::Parse($value, [System.Globalization.CultureInfo]::InvariantCulture)
                if ($null -eq $row.$metric -or [Math]::Abs([double]$row.$metric - $number) -gt 1e-10) { throw "DAX $metric differs for $($row.detector_id)" }
            }
        }
    }
    $results.quality = $quality
    $timing = @(Read-Dax $connection @'
EVALUATE SUMMARIZECOLUMNS('DimDetector'[detector_id], 'FactLatency'[scope], 'FactLatency'[batch_size],
 "p95_ms", [P95 call ms], "calls", [Measured calls])
'@)
    $expectedTiming = Import-Csv -LiteralPath (Join-Path $context.bundle_path 'FactLatency.csv')
    if ($timing.Count -ne 64) { throw 'DAX timing groups missing' }
    foreach ($row in $timing) {
        $match = @($expectedTiming | Where-Object { $_.detector_id -eq $row.detector_id -and $_.scope -eq $row.scope -and [int]$_.batch_size -eq $row.batch_size })
        if ($match.Count -ne 1 -or [int]$match[0].calls -ne $row.calls -or [Math]::Abs([double]::Parse($match[0].p95_ms,[System.Globalization.CultureInfo]::InvariantCulture)-$row.p95_ms) -gt 1e-10) { throw 'DAX timing mismatch' }
    }
    $results.timing_groups = $timing.Count
    $output = Join-Path $projectRoot 'power_bi/validation/desktop_dax.json'
    $results | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $output -Encoding utf8
    Write-Output 'Actual Desktop DAX validation passed: populations, role propagation, 15 detector quality rows, and 64 timing groups.'
} finally { $connection.Close() }
