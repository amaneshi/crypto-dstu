param(
    [ValidatePattern('^[1-9][0-9]*(s|m|h)$')][string]$Duration = '3m',
    [ValidateRange(1, 16)][int]$Workers = 2,
    [string]$GoExecutable = 'go',
    [string[]]$Targets,
    [string]$OutputDirectory = (Join-Path ([IO.Path]::GetTempPath()) ('crypto-dstu-fuzz-' + [Guid]::NewGuid().ToString('N')))
)
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$packages = [ordered]@{
    FuzzParseRawKey = './internal/keystore'
    FuzzParseKey6 = './internal/keystore'
    FuzzParseJKSAuthenticated = './internal/keystore'
    FuzzParsePKCS12 = './internal/keystore'
    FuzzPKCS12AuthenticatedSafe = './internal/keystore'
    FuzzParseAndCheckResponse = './internal/ocsp'
    FuzzCheckResponderCRL = './internal/ocsp'
    FuzzParseAndVerify = './internal/csr'
    FuzzParseCertificates = './internal/cert'
    FuzzParseAndVerifySigned = './internal/cms'
    FuzzParseAndDecryptEnveloped = './internal/cms'
    FuzzDecode = './internal/transport'
}
if (!$Targets) { $Targets = @($packages.Keys) }
foreach ($target in $Targets) {
    if (!$packages.Contains($target)) { throw "Unknown parser fuzz target: $target" }
}
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$outputRoot = (Resolve-Path -LiteralPath $OutputDirectory).Path
$records = @()
Push-Location (Split-Path -Parent $PSScriptRoot)
try {
    $version = & $GoExecutable version
    if ($LASTEXITCODE -ne 0) { throw 'Go version check failed' }
    foreach ($target in $Targets) {
        $log = Join-Path $outputRoot ($target + '.log')
        Write-Output "Starting $target ($Duration, $Workers workers); log: $log"
        $timer = [Diagnostics.Stopwatch]::StartNew()
        & $GoExecutable test -mod=readonly '-run=^$' "-fuzz=^${target}$" "-fuzztime=$Duration" "-parallel=$Workers" "-timeout=${Duration}2m" $packages[$target] *> $log
        $code = $LASTEXITCODE
        $timer.Stop()
        $matches = @(Select-String -LiteralPath $log -Pattern 'execs: ([0-9]+)')
        $executions = if ($matches.Count) { [long]$matches[-1].Matches[0].Groups[1].Value } else { 0 }
        $record = [ordered]@{
            target = $target; package = $packages[$target]; toolchain = "$version"
            duration = $Duration; workers = $Workers; exitCode = $code
            executions = $executions; elapsedSeconds = [math]::Round($timer.Elapsed.TotalSeconds, 2)
            log = $log
        }
        $records += [pscustomobject]$record
        ConvertTo-Json -InputObject $records -Depth 3 | Set-Content -LiteralPath (Join-Path $outputRoot 'results.json') -Encoding utf8
        Write-Output ($record | ConvertTo-Json -Compress)
        if ($code -ne 0) {
            Get-Content -LiteralPath $log -Tail 60
            throw "Fuzz target failed: $target"
        }
    }
} finally { Pop-Location }
