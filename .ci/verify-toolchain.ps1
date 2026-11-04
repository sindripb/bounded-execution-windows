param([Parameter(Mandatory)][string]$RuntimeDirectory)
$ErrorActionPreference='Stop';Set-StrictMode -Version 3
$project=Split-Path -Parent $PSScriptRoot
$pins=Get-Content -LiteralPath (Join-Path $project 'toolchain.json') -Raw|ConvertFrom-Json -AsHashtable
$root=[IO.Path]::GetFullPath($RuntimeDirectory)
function Hash([string]$path){(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Leaf([string]$path){$f=Get-Item -LiteralPath $path -Force;if($f.PSIsContainer -or ($f.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'RuntimeLeafReparse'};return $f.FullName}
for($p=[IO.DirectoryInfo]::new($root);$null -ne $p;$p=$p.Parent){if(-not $p.Exists -or ($p.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'RuntimeReparseOrMissing'}}
if((Hash (Leaf (Join-Path $root 'pwsh.exe'))) -cne $pins.compiler_host_sha256){throw 'PinnedPowerShellHostMismatch'}
foreach($name in $pins.compiler_bindings.Keys){if((Hash (Leaf (Join-Path $root $name))) -cne $pins.compiler_bindings[$name]){throw 'CompilerMismatch'}}
if((Get-Item -LiteralPath (Join-Path $root 'ref')).Attributes-band[IO.FileAttributes]::ReparsePoint){throw 'ReferenceDirectoryReparse'}
$refs=Get-ChildItem -LiteralPath (Join-Path $root 'ref') -File -Filter '*.dll'
if($refs.Count -ne $pins.reference_bindings.Count){throw 'ReferenceMembershipMismatch'}
foreach($file in $refs){if(($file.Attributes-band[IO.FileAttributes]::ReparsePoint) -or (Hash $file.FullName) -cne $pins.reference_bindings[$file.Name]){throw 'ReferenceMismatch'}}
$config=Get-Content -LiteralPath (Leaf (Join-Path $root 'pwsh.runtimeconfig.json')) -Raw|ConvertFrom-Json
$frameworks=@($config.runtimeOptions.includedFrameworks)
if($frameworks.Count -ne 2 -or (@($frameworks.name|Sort-Object)-join ',') -cne 'Microsoft.NETCore.App,Microsoft.WindowsDesktop.App' -or @($frameworks|Where-Object version -cne $pins.dotnet_version).Count){throw 'FrameworkVersionMismatch'}
[pscustomobject]@{status='EXACT_TOOLCHAIN_METADATA_MATCH';references=$refs.Count;helper_loaded=$false;hosted_origin_verified=$false}
