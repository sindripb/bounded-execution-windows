# Metadata/readback only. This file neither loads helpers nor grants execution.
Set-StrictMode -Version 3
$ErrorActionPreference = 'Stop'

function Assert-ReleasePath([string]$Path) {
    $value=[IO.Path]::GetFullPath($Path)
    for($p=Get-Item -LiteralPath $value -Force;$null -ne $p;$p=$(if($p -is [IO.FileInfo]){$p.Directory}else{$p.Parent})) {
        if(-not $p.Exists -or ($p.Attributes -band [IO.FileAttributes]::ReparsePoint)){throw 'MissingOrReparseReleasePath'}
    }
    return $value
}
function Get-ReleaseHash([string]$Path) {
    $path=Assert-ReleasePath $Path
    return (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Assert-ReleaseMember([string]$Name) {
    if([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains('\') -or $Name.Contains(':') -or $Name.StartsWith('/')){throw 'NoncanonicalReleaseMember'}
    foreach($part in $Name.Split('/')) {
        if($part -in @('','.','..') -or $part -cne $part.TrimEnd(' ','.') -or
           $part -match '[\x00-\x1f<>"|?*]' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\.|$)'){throw 'UnsafeReleaseMember'}
    }
}
function Assert-ReleaseTree([string]$ProjectRoot,[string]$ExpectedManifestSha256) {
    $root=Assert-ReleasePath $ProjectRoot
    if($ExpectedManifestSha256 -cnotmatch '^[0-9a-f]{64}$'){throw 'ExactReviewedManifestRequired'}
    $path=Join-Path $root 'source-manifest.json'
    if((Get-ReleaseHash $path) -cne $ExpectedManifestSha256){throw 'ReviewedReleaseManifestMismatch'}
    $manifest=Get-Content -LiteralPath $path -Raw | ConvertFrom-Json -AsHashtable
    if($manifest.format -cne 'PRIVATE_OSS_PREVIEW_1'){throw 'ExistingSourceManifestFormatRequired'}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach($name in $manifest.files.Keys) {
        Assert-ReleaseMember $name
        if(-not $seen.Add($name) -or $name -eq 'source-manifest.json' -or $name.Split('/')[0] -eq '.git'){throw 'RepeatedOrExcludedReleaseMember'}
        $actualHash=Get-ReleaseHash (Join-Path $root $name)
        if($actualHash -cne $manifest.files[$name]){throw ('ReleaseMemberHashMismatch: '+$name+' expected='+$manifest.files[$name]+' actual='+$actualHash)}
    }
    $actual=@(Get-ChildItem -LiteralPath $root -Recurse -Force -File | ForEach-Object {
        $n=[IO.Path]::GetRelativePath($root,$_.FullName).Replace('\','/')
        if($n -ne 'source-manifest.json' -and $n.Split('/')[0] -ne '.git'){$n}
    })
    if($actual.Count -ne $seen.Count -or @($actual|Where-Object {-not $seen.Contains($_)}).Count){throw 'UnexpectedReleaseMembership'}
    return $manifest
}
function Assert-ReleaseNumber($Value,[double]$Limit) {
    if($Value -is [bool] -or $Value -is [string] -or $null -eq $Value -or
       $Value -isnot [ValueType] -or -not [double]::IsFinite([double]$Value) -or
       [double]$Value -lt 0 -or [double]$Value -ge $Limit){throw 'IncompleteOrExceededBuildResourceObservation'}
}
function Assert-ReleaseMap($Actual,$Expected) {
    if($Actual -isnot [Collections.IDictionary] -or $Actual.Count -ne $Expected.Count){throw 'BuildBindingMembershipMismatch'}
    foreach($key in $Expected.Keys){if(-not $Actual.Contains($key) -or $Actual[$key] -cne $Expected[$key]){throw 'BuildBindingMismatch'}}
}
function Assert-ReleaseBuilds([string]$ProjectRoot,[string]$BuildRoot,[string]$ExpectedManifestSha256) {
    $root=Assert-ReleasePath $ProjectRoot;$builds=Assert-ReleasePath $BuildRoot
    $manifest=Assert-ReleaseTree $root $ExpectedManifestSha256
    $contract=Get-Content -LiteralPath (Join-Path $root '.ci/release-contract.json') -Raw|ConvertFrom-Json -AsHashtable
    $toolchain=Get-Content -LiteralPath (Join-Path $root 'toolchain.json') -Raw|ConvertFrom-Json -AsHashtable
    $rows=[ordered]@{}
    foreach($label in @('Compact','Extended','PolicyTests')) {
        $expected=$contract.artifacts[$label];$folder=Join-Path $builds $label
        $dll=Join-Path $folder 'BoundedExecution.Windows.dll';$receipt=Join-Path $folder 'BUILD_RECEIPT.json'
        $r=Get-Content -LiteralPath (Assert-ReleasePath $receipt) -Raw|ConvertFrom-Json -AsHashtable
        $profile=if($label -eq 'PolicyTests'){'Compact'}else{$label};$tests=$label -eq 'PolicyTests'
        if($r.status -cne 'PASS_COMPILE_ONLY' -or $null -ne $r.first_failure -or $r.profile -cne $profile -or
           $r.tests_compiled -isnot [bool] -or $r.tests_compiled -ne $tests){throw 'ExactSuccessfulCompileReceiptRequired'}
        foreach($flag in @('tests_executed','output_loaded','signing_performed','execution_authority')){
            if($r[$flag] -isnot [bool] -or $r[$flag]){throw 'CompileOnlyReceiptRequired'}
        }
        if($r.source_manifest_sha256 -cne $ExpectedManifestSha256 -or
           $r.build_script_sha256 -cne $manifest.files['build.ps1'] -or
           $r.compiler_host_sha256 -cne $toolchain.compiler_host_sha256 -or
           $r.powershell_version -cne $toolchain.powershell_version -or $r.dotnet_version -cne $toolchain.dotnet_version){throw 'BuildSourceOrRuntimeMismatch'}
        $source=[ordered]@{};$names=@($manifest.common)+@($manifest.profiles[$profile])
        if($tests){$names+=@('tests/PolicyContractCases.cs')}
        foreach($name in $names){$source[$name]=$manifest.files[$name]}
        Assert-ReleaseMap $r.source_hashes $source
        Assert-ReleaseMap $r.compiler_bindings $toolchain.compiler_bindings
        Assert-ReleaseMap $r.reference_bindings $toolchain.reference_bindings
        Assert-ReleaseNumber $r.cpu_seconds 6
        Assert-ReleaseNumber $r.wall_seconds 10
        Assert-ReleaseNumber $r.peak_committed_bytes 536870912
        Assert-ReleaseNumber $r.peak_working_set_bytes 536870912
        $hash=Get-ReleaseHash $dll;$size=(Get-Item -LiteralPath $dll).Length
        if($r.dll_bytes -isnot [long] -and $r.dll_bytes -isnot [int]){throw 'ExactIntegerDllLength'}
        if($hash -cne $expected.sha256 -or $size -ne $expected.bytes -or
           $r.dll_sha256 -cne $hash -or $r.dll_bytes -ne $size -or $size -gt 131072){throw 'UnsignedImageOrSizeMismatch'}
        $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($dll)
        if($info.ProductName -cne $contract.product -or $info.ProductVersion -cne $contract.product_version -or
           $info.FileVersion -cne $contract.file_version){throw 'ProviderArtifactMetadataMismatch'}
        $rows[$label]=[ordered]@{path=$dll;bytes=$size;sha256=$hash;receipt_sha256=(Get-ReleaseHash $receipt)}
    }
    return $rows
}
function Assert-UnsignedStage([string]$Directory,$Rows) {
    $root=Assert-ReleasePath $Directory
    $files=@(Get-ChildItem -LiteralPath $root -Force -File -Recurse)
    $dirs=@(Get-ChildItem -LiteralPath $root -Force -Directory -Recurse)
    if($files.Count -ne 3 -or $dirs.Count -ne 3){throw 'ExactUnsignedArtifactMembership'}
    foreach($label in @('Compact','Extended','PolicyTests')) {
        $path=Join-Path $root "$label/BoundedExecution.Windows.dll"
        if((Get-ReleaseHash $path) -cne $Rows[$label].sha256 -or
           (Get-Item -LiteralPath $path).Length -ne $Rows[$label].bytes){throw 'StagedArtifactChanged'}
    }
}
