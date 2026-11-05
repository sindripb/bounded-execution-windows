# Pure validation shared by the hosted setup and invented-archive tests.
Set-StrictMode -Version 3
$ErrorActionPreference='Stop'
function Assert-HostedMember([string]$Name) {
 if([string]::IsNullOrWhiteSpace($Name) -or $Name.Contains('\') -or $Name.Contains('//') -or $Name.Contains(':') -or $Name.StartsWith('/')){throw 'UnsafeZipName'}
 $clean=$Name.TrimEnd('/')
 foreach($part in $clean.Split('/')){
  if($part -in @('','.','..') -or $part -cne $part.TrimEnd(' ','.') -or $part -match '[\x00-\x1f<>"|?*]' -or $part -match '^(?i:CON|PRN|AUX|NUL|COM[0-9¹²³]|LPT[0-9¹²³])(?:\.|$)'){throw 'UnsafeZipName'}
 }
 return $clean
}
function Assert-HostedParent([string]$Path) {
 $p=Get-Item -LiteralPath ([IO.Path]::GetFullPath($Path)) -Force
 for(;$null -ne $p;$p=$(if($p -is [IO.FileInfo]){$p.Directory}else{$p.Parent})){
  if(-not $p.Exists -or ($p.Attributes-band[IO.FileAttributes]::ReparsePoint)){throw 'MissingOrReparseHostedPath'}
 }
}
function Get-AllocationUpper([long]$Length,[long]$Cluster) {
 if($Length -lt 0 -or $Cluster -lt 512 -or $Cluster -gt 16777216 -or ($Cluster-band($Cluster-1)) -ne 0){throw 'InvalidAllocationGeometry'}
 return [long]([decimal]::Ceiling([decimal]$Length/[decimal]$Cluster)*$Cluster)
}
function Get-HostedZipPlan($Zip,[long]$ArchiveBytes,[long]$Cluster,$Limits,[scriptblock]$Check={}) {
 & $Check
 if($Zip.Entries.Count -gt $Limits.files){throw 'ArchiveMemberLimit'}
 $seen=[Collections.Generic.Dictionary[string,bool]]::new([StringComparer]::OrdinalIgnoreCase)
 [long]$logical=$ArchiveBytes+$Limits.reserve_logical_bytes
 [long]$allocation=(Get-AllocationUpper $ArchiveBytes $Cluster)+$Limits.reserve_allocated_bytes
 [int]$files=1+$Limits.reserve_files
 foreach($entry in $Zip.Entries){
  & $Check
  $name=Assert-HostedMember $entry.FullName;$directory=$entry.FullName.EndsWith('/')
  if($seen.ContainsKey($name)){throw 'DuplicateZipName'}
  if((($entry.ExternalAttributes -shr 16)-band 61440) -eq 40960){throw 'ZipSymlink'}
  if($directory -and $entry.Length -ne 0){throw 'DirectoryHasPayload'}
  $seen.Add($name,$directory)
  if(-not $directory){
   if($entry.Length -lt 0 -or $entry.Length -gt $Limits.logical_bytes){throw 'ExpandedSetupLimit'}
   $logical+=$entry.Length;$allocation+=Get-AllocationUpper $entry.Length $Cluster;$files++
  }
  if($logical -gt $Limits.logical_bytes -or $allocation -gt $Limits.allocated_bytes -or $files -gt $Limits.files){throw 'ExpandedSetupLimit'}
 }
 foreach($name in $seen.Keys){
  & $Check
  $parts=$name.Split('/');$prefix=''
  for($i=0;$i -lt $parts.Length-1;$i++){
   $prefix=$(if($i){$prefix+'/'+$parts[$i]}else{$parts[$i]})
   if($seen.ContainsKey($prefix) -and -not $seen[$prefix]){throw 'ZipFileDirectoryCollision'}
  }
 }
 return [ordered]@{logical_with_reservations=$logical;allocated_estimate_with_reservations=$allocation;files_with_reservations=$files;cluster_bytes=$Cluster;allocation_kind='PREFLIGHT_CLUSTER_ROUNDING_ESTIMATE_REQUIRES_ACTUAL_CENSUS';whole_volume_metadata_included=$false}
}
function Assert-HostedWindow([string]$ApprovedAt,[string]$ExpiresAt,[DateTimeOffset]$Now) {
 $style=[Globalization.DateTimeStyles]::AssumeUniversal-bor[Globalization.DateTimeStyles]::AdjustToUniversal
 $approved=[DateTimeOffset]::ParseExact($ApprovedAt,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,$style)
 $expiry=[DateTimeOffset]::ParseExact($ExpiresAt,'yyyy-MM-ddTHH:mm:ssZ',[Globalization.CultureInfo]::InvariantCulture,$style)
 if($expiry -le $approved -or ($expiry-$approved).TotalHours -gt 24 -or $Now -lt $approved -or $Now -ge $expiry){throw 'OutsideFiniteHostedWindow'}
}
function Write-HostedJson([string]$Path,$Value) {
 $bytes=[Text.Encoding]::UTF8.GetBytes(($Value|ConvertTo-Json -Depth 20 -Compress))
 $f=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
 try{$f.Write($bytes);$f.Flush($true)}finally{$f.Dispose()}
 if(-not [Linq.Enumerable]::SequenceEqual([byte[]]$bytes,[byte[]][IO.File]::ReadAllBytes($Path))){throw 'HostedJsonReadback'}
}
function Invoke-HostedCleanup([scriptblock]$Action,[Collections.Generic.List[string]]$Secondary) {
 try{& $Action}catch{$Secondary.Add($_.Exception.GetType().FullName+':'+$_.Exception.Message)}
}
