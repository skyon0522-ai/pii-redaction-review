[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PythonCommand
)

$ErrorActionPreference = 'Stop'
$pythonInfo = Get-Command -Name $PythonCommand -ErrorAction Stop
$python = if ($pythonInfo.Source) { $pythonInfo.Source } elseif ($pythonInfo.Path) { $pythonInfo.Path } else { $PythonCommand }
$stagePath = [IO.Path]::GetFullPath($PSScriptRoot)
$runPath = $stagePath
$mapping = $null
$mappingCreated = $false
$locationPushed = $false
$exitCode = 1

try {
    if ([IO.Path]::DirectorySeparatorChar -eq '\') {
        $used = @(Get-PSDrive -PSProvider FileSystem | ForEach-Object { $_.Name.ToUpperInvariant() })
        foreach ($letter in @('Z','Y','X','W','V','U','T','S','R','Q','P','O','N','M','L','K','J','I','H','G','F','E','D')) {
            if ($used -notcontains $letter -and -not (Test-Path -LiteralPath "$letter`:")) {
                $mapping = $letter + ':'
                break
            }
        }
        if (-not $mapping) {
            throw 'No free drive letter is available for the temporary long-path mapping.'
        }
        $subst = Get-Command -Name subst -ErrorAction Stop
        & $subst.Source $mapping $stagePath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not create the temporary drive mapping $mapping."
        }
        $mappingCreated = $true
        $runPath = "$mapping\"
        Write-Host "Using temporary drive $mapping for this verification run."
    }

    Push-Location -LiteralPath $runPath
    $locationPushed = $true
    & $python -B -m unittest -v test_redaction_cli
    $exitCode = $LASTEXITCODE
} finally {
    if ($locationPushed) {
        Pop-Location
    }
    if ($mapping -and $mappingCreated) {
        $subst = Get-Command -Name subst -ErrorAction Stop
        & $subst.Source $mapping /d
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not remove temporary drive mapping $mapping."
        }
    }
}

exit $exitCode
