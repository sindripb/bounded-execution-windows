param([Parameter(Mandatory)][string]$Destination,[Parameter(Mandatory)]$Limits,[Parameter(Mandatory)][scriptblock]$Check)
$ErrorActionPreference='Stop';Set-StrictMode -Version 3
. (Join-Path $PSScriptRoot 'hosted-safety.ps1')
$project=Split-Path -Parent $PSScriptRoot
$asset=(Get-Content -LiteralPath (Join-Path $project 'HOSTED_TOOLCHAIN_PLAN.json') -Raw|ConvertFrom-Json).asset
if($asset.bytes -ne 106319290 -or $asset.sha256 -cne '32eb8f6cdce08f86e987d625a2733e54ac3e289ae7e1621b14c0b5bcec2434ea' -or $asset.url -cne 'https://github.com/PowerShell/PowerShell/releases/download/v7.6.5/PowerShell-7.6.5-win-x64.zip'){throw 'ExactOfficialArchiveRequired'}
$dest=[IO.Path]::GetFullPath($Destination);Assert-HostedParent ([IO.Path]::GetDirectoryName($dest))
if(Test-Path -LiteralPath $dest){throw 'FreshHostedSetupRequired'}
[void][IO.Directory]::CreateDirectory($dest)
$drive=[IO.Path]::GetPathRoot($dest).TrimEnd('\').TrimEnd(':')
$volume=Get-Volume -DriveLetter $drive -ErrorAction Stop
if($volume.FileSystemType -cne 'NTFS' -or $volume.SizeRemaining -lt $Limits.allocated_bytes){throw 'NTFSAndReservedFreeSpaceRequired'}
$cluster=[long]$volume.AllocationUnitSize;$null=Get-AllocationUpper 1 $cluster
$archive=Join-Path $dest 'official.zip';$runtime=Join-Path $dest 'runtime'
$client=[Net.Http.HttpClient]::new();$client.Timeout=[TimeSpan]::FromSeconds(120)
$cancel=[Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds(120));$download=[Diagnostics.Stopwatch]::StartNew()
$buffer=[byte[]]::new(65536);[long]$written=0
try{
 & $Check
 $response=$client.GetAsync($asset.url,[Net.Http.HttpCompletionOption]::ResponseHeadersRead,$cancel.Token).GetAwaiter().GetResult()
 try{
  if(-not $response.IsSuccessStatusCode){throw ('OfficialDownloadHttpStatus:'+([int]$response.StatusCode))}
  if($response.RequestMessage.RequestUri.Scheme -cne 'https' -or $response.RequestMessage.RequestUri.Host -notin @('github.com','release-assets.githubusercontent.com','objects.githubusercontent.com')){throw 'OfficialHttpsRedirectRequired'}
  if($null -ne $response.Content.Headers.ContentLength -and $response.Content.Headers.ContentLength -ne $asset.bytes){throw 'OfficialDownloadLength'}
  $input=$response.Content.ReadAsStreamAsync($cancel.Token).GetAwaiter().GetResult()
  $output=[IO.File]::Open($archive,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
  try{
   while(($n=$input.ReadAsync($buffer,0,$buffer.Length,$cancel.Token).GetAwaiter().GetResult()) -gt 0){
    if($written+$n -gt $asset.bytes){throw 'DownloadByteLimit'}
    $output.Write($buffer,0,$n);$written+=$n;& $Check
   };$output.Flush($true)
  }finally{$output.Dispose();$input.Dispose()}
 }finally{$response.Dispose()}
 & $Check
 $archiveHandle=[IO.File]::Open($archive,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
 try{
  $digest=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($archiveHandle)).ToLowerInvariant()
  if($written -ne $asset.bytes -or $archiveHandle.Length -ne $asset.bytes -or $digest -cne $asset.sha256){throw 'OfficialArchiveIdentity'}
  $archiveHandle.Position=0
  $zip=[IO.Compression.ZipArchive]::new($archiveHandle,[IO.Compression.ZipArchiveMode]::Read,$true)
  try{
  $plan=Get-HostedZipPlan $zip $written $cluster $Limits $Check
  [void][IO.Directory]::CreateDirectory($runtime)
  foreach($entry in $zip.Entries){
   $name=Assert-HostedMember $entry.FullName;$target=[IO.Path]::GetFullPath((Join-Path $runtime $name))
   if(-not $target.StartsWith($runtime+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'ZipEscape'}
   if($entry.FullName.EndsWith('/')){[void][IO.Directory]::CreateDirectory($target);continue}
   [void][IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($target));Assert-HostedParent ([IO.Path]::GetDirectoryName($target))
   $input=$entry.Open();$output=[IO.File]::Open($target,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
   try{
    [long]$copied=0
    while(($n=$input.Read($buffer,0,$buffer.Length)) -gt 0){
     if($copied+$n -gt $entry.Length){throw 'ZipLength'}
     $output.Write($buffer,0,$n);$copied+=$n;& $Check
    }
    if($copied -ne $entry.Length){throw 'ZipLength'};$output.Flush($true)
   }finally{$output.Dispose();$input.Dispose()}
  }
  }finally{$zip.Dispose()}
 }finally{$archiveHandle.Dispose()}
 & (Join-Path $PSScriptRoot 'verify-toolchain.ps1') -RuntimeDirectory $runtime|Out-Null
 & $Check
 return [ordered]@{runtime=$runtime;archive_sha256=$asset.sha256;archive_bytes=$written;allocation=$plan;toolchain='EXACT_TOOLCHAIN_METADATA_MATCH';download_wall_seconds=$download.Elapsed.TotalSeconds;output_loaded=$false}
}finally{$cancel.Dispose();$client.Dispose()}
