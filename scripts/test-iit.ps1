param(
    [Parameter(Mandatory=$true)][string]$SdkDirectory,
    [string]$TestCADirectory,
    [string]$ExpectedSDKHash,
    [string]$GoExecutable='go'
)
$ErrorActionPreference='Stop'
$projectRoot=Split-Path -Parent $PSScriptRoot
$sdkRoot=(Resolve-Path -LiteralPath $SdkDirectory).Path
$dllPath=Join-Path $sdkRoot 'EUSignCP.dll'
$actualHash=(Get-FileHash -LiteralPath $dllPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($ExpectedSDKHash -and $actualHash -ine $ExpectedSDKHash) {throw 'IIT SDK hash differs from the expected version'}
$dllBytes=[IO.File]::ReadAllBytes($dllPath)
$peOffset=[BitConverter]::ToInt32($dllBytes,0x3c)
$machine=[BitConverter]::ToUInt16($dllBytes,$peOffset+4)
$oracleArchitecture=switch($machine){0x014c {'386'};0x8664 {'amd64'};default {throw "Unsupported IIT DLL architecture: $machine"}}
$testCA=$null
if($TestCADirectory){$testCA=(Resolve-Path -LiteralPath $TestCADirectory).Path}
$temporary=Join-Path ([IO.Path]::GetTempPath()) ('crypto-dstu-iit-run-'+[Guid]::NewGuid().ToString('N'))
$saved=@{}
foreach($name in @('GOARCH','IIT_ORACLE','IIT_SDK_DIR','IIT_TEST_CA_DIR','IIT_SDK_SHA256')) {$saved[$name]=[Environment]::GetEnvironmentVariable($name,'Process')}
New-Item -ItemType Directory -Path $temporary | Out-Null
try {
    # Copy native binaries only. Do not reuse a real application's settings,
    # certificate store, key files, or registry configuration.
    Get-ChildItem -LiteralPath $sdkRoot -Filter '*.dll' -File | ForEach-Object {Copy-Item -LiteralPath $_.FullName -Destination $temporary}
    $oracle=Join-Path $temporary 'iit-oracle.exe'
    Push-Location $projectRoot
    try {
        $env:GOARCH=$oracleArchitecture
        & $GoExecutable build -mod=readonly -o $oracle ./cmd/iit-oracle
        if($LASTEXITCODE -ne 0){throw 'IIT oracle build failed'}
        [Environment]::SetEnvironmentVariable('GOARCH',$saved['GOARCH'],'Process')
        $env:IIT_ORACLE=$oracle
        $env:IIT_SDK_DIR=$temporary
        $env:IIT_SDK_SHA256=$actualHash
        [Environment]::SetEnvironmentVariable('IIT_TEST_CA_DIR',$testCA,'Process')
        Write-Output "IIT SDK SHA256: $actualHash; oracle architecture: $oracleArchitecture"
        & $GoExecutable test -tags=integration -mod=readonly -count=1 -timeout=180s -v ./internal/cms -run '^TestIIT'
        if($LASTEXITCODE -ne 0){throw 'IIT interoperability tests failed'}
        # Run after CMS initializes the shared public CZO fixture cache.
        & $GoExecutable test -tags=integration -mod=readonly -count=1 -timeout=180s -v ./internal/interop -run '^TestIIT'
        if($LASTEXITCODE -ne 0){throw 'IIT profile/timestamp interoperability tests failed'}
    } finally {Pop-Location}
} finally {
    foreach($name in $saved.Keys){[Environment]::SetEnvironmentVariable($name,$saved[$name],'Process')}
    $resolvedTemporary=[IO.Path]::GetFullPath($temporary)
    $resolvedTempRoot=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(!$resolvedTemporary.StartsWith($resolvedTempRoot,[StringComparison]::OrdinalIgnoreCase) -or !(Split-Path -Leaf $resolvedTemporary).StartsWith('crypto-dstu-iit-run-')){throw 'Refusing to remove an unexpected temporary directory'}
    Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force
}
