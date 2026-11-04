param(
 [Parameter(Mandatory)][string]$ProjectRoot,
 [Parameter(Mandatory)][string]$BuildRoot,
 [Parameter(Mandatory)][string]$Destination,
 [Parameter(Mandatory)][string]$ExpectedManifestSha256
)
$ErrorActionPreference='Stop';Set-StrictMode -Version 3
. (Join-Path $PSScriptRoot 'release-checks.ps1')
$rows=Assert-ReleaseBuilds $ProjectRoot $BuildRoot $ExpectedManifestSha256
$dest=[IO.Path]::GetFullPath($Destination)
if(Test-Path -LiteralPath $dest){throw 'FreshArtifactStageRequired'}
$null=Assert-ReleasePath ([IO.Path]::GetDirectoryName($dest))
[void][IO.Directory]::CreateDirectory($dest)
foreach($label in @('Compact','Extended','PolicyTests')) {
    $folder=Join-Path $dest $label;[void][IO.Directory]::CreateDirectory($folder)
    [IO.File]::Copy($rows[$label].path,(Join-Path $folder 'BoundedExecution.Windows.dll'),$false)
}
Assert-UnsignedStage $dest $rows
# Copy only those three files to the workflow artifact. Build receipts remain
# separate evidence; no source tree, host files or private consumer is uploaded.
[pscustomobject]@{status='PASS_EXACT_UNSIGNED_STAGE';files=3;output_loaded=$false;signing_performed=$false}
