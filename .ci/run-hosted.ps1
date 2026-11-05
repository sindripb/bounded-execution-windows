# One public unsigned build experiment. No signing or financial/helper loading.
$ErrorActionPreference='Stop';Set-StrictMode -Version 3
. (Join-Path $PSScriptRoot 'hosted-safety.ps1')
. (Join-Path $PSScriptRoot 'release-checks.ps1')
$root=Split-Path -Parent $PSScriptRoot
$limits=Get-Content -LiteralPath (Join-Path $PSScriptRoot 'hosted-scope.json') -Raw|ConvertFrom-Json -AsHashtable
$watch=[Diagnostics.Stopwatch]::StartNew();$owner=[Diagnostics.Process]::GetCurrentProcess()
$first=$null;$secondary=[Collections.Generic.List[string]]::new();$phase='authority';$setup=$null;$children=[Collections.Generic.List[object]]::new()
if($env:GITHUB_ACTIONS -cne 'true' -or $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:GITHUB_REPOSITORY_ID -cne '1445835004' -or $env:GITHUB_ACTOR_ID -cne '190190923' -or $env:GITHUB_EVENT_NAME -cne 'workflow_dispatch' -or $env:GITHUB_REF -cne 'refs/heads/main' -or $env:GITHUB_RUN_NUMBER -cne '1' -or $env:GITHUB_RUN_ATTEMPT -cne '1'){throw 'ExactFirstHostedRunRequired'}
if($env:OWNER_CLAIM_SHA256 -cnotmatch '^[0-9a-f]{64}$' -or $env:EXPECTED_MANIFEST -cnotmatch '^[0-9a-f]{64}$'){throw 'ReviewedClaimAndManifestRequired'}
Assert-HostedWindow $env:OWNER_APPROVED_AT $env:OWNER_EXPIRES_AT ([DateTimeOffset]::UtcNow)
$out=Join-Path $env:RUNNER_TEMP 'hosted335';Assert-HostedParent $env:RUNNER_TEMP
if(Test-Path -LiteralPath $out){throw 'FreshHostedOutputRequired'}
[void][IO.Directory]::CreateDirectory($out);$evidence=Join-Path $out 'evidence';[void][IO.Directory]::CreateDirectory($evidence)
function Check {
 $owner.Refresh()
 if($owner.TotalProcessorTime.TotalSeconds -ge $limits.parent_cpu_seconds -or $watch.Elapsed.TotalSeconds -ge $limits.parent_wall_seconds -or $owner.PeakPagedMemorySize64 -ge $limits.memory_bytes -or $owner.PeakWorkingSet64 -ge $limits.memory_bytes){throw 'HostedParentResourceLimit'}
 Assert-HostedWindow $env:OWNER_APPROVED_AT $env:OWNER_EXPIRES_AT ([DateTimeOffset]::UtcNow)
}
function Observe-Storage([string]$Label) {
 $priorSecondary=$secondary.Count
 $python=(Get-Command python -CommandType Application -ErrorAction Stop).Source
 Assert-HostedParent $python;$runtimeHash=Get-ReleaseHash $python
 $receipt=Join-Path $evidence ('STORAGE-'+$Label+'.json')
 $info=[Diagnostics.ProcessStartInfo]::new($python);$info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardError=$true
 foreach($arg in @('-I','-B',(Join-Path $PSScriptRoot 'observe-hosted.py'),$out,$receipt)){$info.ArgumentList.Add($arg)}
 $p=[Diagnostics.Process]::Start($info);$errors=$p.StandardError.ReadToEndAsync();$failure=$null
 try{
  $observerClock=[Diagnostics.Stopwatch]::StartNew();[long]$observerPeak=0
  while(-not $p.WaitForExit(25)){
   try{$p.Refresh();$observerPeak=[Math]::Max($observerPeak,[Math]::Max($p.PeakPagedMemorySize64,$p.PeakWorkingSet64))}catch{if(-not $p.HasExited){throw}}
   Check
   if($observerClock.Elapsed.TotalSeconds -ge 10 -or $p.TotalProcessorTime.TotalSeconds -ge 6 -or $observerPeak+[Math]::Max($owner.PeakPagedMemorySize64,$owner.PeakWorkingSet64) -ge $limits.memory_bytes){throw 'ObserverAggregateResourceLimit'}
  }
  if($p.ExitCode -ne 0){throw 'ObserverFailedSeeOriginalReceipt'}
  if($p.TotalProcessorTime.TotalSeconds -ge 6){throw 'ObserverCpuLimit'}
  $r=Get-Content -LiteralPath $receipt -Raw|ConvertFrom-Json -AsHashtable
  if($r.status -cne 'PASS_OBSERVED_HOSTED_STORAGE' -or $r.peak_observed_bytes+[Math]::Max($owner.PeakPagedMemorySize64,$owner.PeakWorkingSet64) -ge $limits.memory_bytes){throw 'ObserverReceiptRejected'}
  return [ordered]@{label=$Label;python_sha256=$runtimeHash;closed_cpu_seconds=$p.TotalProcessorTime.TotalSeconds;receipt_sha256=(Get-ReleaseHash $receipt)}
 }catch{$failure=$_;throw
 }finally{
  Invoke-HostedCleanup {if(-not $p.HasExited){$p.Kill($true);if(-not $p.WaitForExit(2000)){throw 'ObserverTerminationUnconfirmed'}}} $secondary
  if($p.HasExited){Invoke-HostedCleanup {
   $s=$errors.GetAwaiter().GetResult()
   if([Text.Encoding]::UTF8.GetByteCount($s) -gt 16384){throw 'ObserverDiagnosticTooLarge'}
   [IO.File]::WriteAllText((Join-Path $evidence ('STORAGE-'+$Label+'-stderr.txt')),$s)
  } $secondary}
  Invoke-HostedCleanup {$p.Dispose()} $secondary
  if($null -eq $failure -and $secondary.Count -ne $priorSecondary){throw 'ObserverCleanupFailurePreserved'}
 }
}
$observations=[Collections.Generic.List[object]]::new()
try{
 $null=Assert-ReleaseTree $root $env:EXPECTED_MANIFEST;Check
 $phase='official-toolchain';$setup=& (Join-Path $PSScriptRoot 'provision-hosted.ps1') -Destination (Join-Path $out 'setup') -Limits $limits -Check ${function:Check}
 $phase='setup-storage';$observations.Add((Observe-Storage 'setup'));Check
 $builds=Join-Path $out 'builds';[void][IO.Directory]::CreateDirectory($builds)
 foreach($label in @('Compact','Extended','PolicyTests')){
  $phase='compile-'+$label;$exe=Join-Path $setup.runtime 'pwsh.exe'
  $pins=Get-Content -LiteralPath (Join-Path $root 'toolchain.json') -Raw|ConvertFrom-Json
  if((Get-ReleaseHash $exe) -cne $pins.compiler_host_sha256){throw 'PrelaunchRuntimeIdentity'}
  $psi=[Diagnostics.ProcessStartInfo]::new($exe);$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardOutput=$true;$psi.RedirectStandardError=$true
  $profile=if($label -eq 'PolicyTests'){'Compact'}else{$label}
  foreach($arg in @('-NoLogo','-NoProfile','-NonInteractive','-File',(Join-Path $root 'build.ps1'),'-Profile',$profile,'-OutputDirectory',(Join-Path $builds $label))){$psi.ArgumentList.Add($arg)}
  if($label -eq 'PolicyTests'){$psi.ArgumentList.Add('-IncludeContractTests')}
  $child=[Diagnostics.Process]::Start($psi);$clock=[Diagnostics.Stopwatch]::StartNew();$stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
  $compileFailure=$null;$secondaryBefore=$secondary.Count;[long]$peakCommit=0;[long]$peakWorking=0;$sampled=$false
  try{
   while(-not $child.WaitForExit(50)){
    try{
     $child.Refresh();$peakCommit=[Math]::Max($peakCommit,$child.PeakPagedMemorySize64);$peakWorking=[Math]::Max($peakWorking,$child.PeakWorkingSet64);$sampled=$true
    }catch{if(-not $child.HasExited){throw}}
    Check
    if($child.TotalProcessorTime.TotalSeconds -ge 6 -or $clock.Elapsed.TotalSeconds -ge 10 -or [Math]::Max($peakCommit,$peakWorking)+[Math]::Max($owner.PeakPagedMemorySize64,$owner.PeakWorkingSet64) -ge $limits.memory_bytes){throw 'OriginalCompileResourceLimit'}
   }
   $row=[ordered]@{label=$label;cpu_seconds=$child.TotalProcessorTime.TotalSeconds;wall_seconds=$clock.Elapsed.TotalSeconds;observed_peak_committed_bytes=$peakCommit;observed_peak_working_set_bytes=$peakWorking;memory_sampled=$sampled;exit_code=$child.ExitCode}
   $children.Add($row)
   if(-not $sampled -or $row.cpu_seconds -ge 6 -or $row.wall_seconds -ge 10 -or $peakCommit -ge $limits.memory_bytes -or $peakWorking -ge $limits.memory_bytes){throw 'OriginalCompileCloseoutLimit'}
   if($child.ExitCode -ne 0){throw 'CompileFailedSeeOriginalReceipt'}
  }catch{$compileFailure=$_
  }finally{
   Invoke-HostedCleanup {if(-not $child.HasExited){$child.Kill($true);if(-not $child.WaitForExit(2000)){throw 'CompilerTerminationUnconfirmed'}}} $secondary
   if($child.HasExited){
    Invoke-HostedCleanup {
     $outText=$stdout.GetAwaiter().GetResult();$errText=$stderr.GetAwaiter().GetResult()
     if([Text.Encoding]::UTF8.GetByteCount($outText)+[Text.Encoding]::UTF8.GetByteCount($errText) -gt 65536){throw 'OversizedCompilerLogNotCopied'}
     [IO.File]::WriteAllText((Join-Path $evidence ($label+'-stdout.txt')),$outText)
     [IO.File]::WriteAllText((Join-Path $evidence ($label+'-stderr.txt')),$errText)
    } $secondary
   }
   Invoke-HostedCleanup {
    $receipt=Join-Path (Join-Path $builds $label) 'BUILD_RECEIPT.json'
    if(Test-Path -LiteralPath $receipt){[IO.File]::Copy($receipt,(Join-Path $evidence ($label+'-BUILD_RECEIPT.json')),$false)}
   } $secondary
   Invoke-HostedCleanup {$child.Dispose()} $secondary
  }
  if($null -ne $compileFailure){throw $compileFailure}
  if($secondary.Count -ne $secondaryBefore){throw 'CompileCleanupFailurePreserved'}
 }
 $phase='strict-stage';$stage=Join-Path $evidence 'unsigned'
 & (Join-Path $PSScriptRoot 'stage-artifacts.ps1') -ProjectRoot $root -BuildRoot $builds -Destination $stage -ExpectedManifestSha256 $env:EXPECTED_MANIFEST|Out-Null
 $owner.Refresh()
 foreach($label in @('Compact','Extended','PolicyTests')){
  $r=Get-Content -LiteralPath (Join-Path (Join-Path $builds $label) 'BUILD_RECEIPT.json') -Raw|ConvertFrom-Json
  if([Math]::Max($r.peak_committed_bytes,$r.peak_working_set_bytes)+[Math]::Max($owner.PeakPagedMemorySize64,$owner.PeakWorkingSet64) -ge $limits.memory_bytes){throw 'ClosedCompileAggregateObservedMemoryLimit'}
 }
 $phase='final-source-readback';$null=Assert-ReleaseTree $root $env:EXPECTED_MANIFEST;Check
 $phase='final-storage';$observations.Add((Observe-Storage 'final'));Check
 if($secondary.Count){throw 'SecondaryFailurePreventsAcceptance'}
}catch{$first=[ordered]@{phase=$phase;type=$_.Exception.GetType().FullName;message=$_.Exception.Message}}
$owner.Refresh()
$result=[ordered]@{schema='HOSTED_UNSIGNED_QUALIFICATION335';status=$(if($null -eq $first){'PASS_UNSIGNED_HOSTED_BUILD'}else{'FAIL'});first_failure=$first;secondary_failures=$secondary.ToArray();source_sha=$env:GITHUB_SHA;source_manifest_sha256=$env:EXPECTED_MANIFEST;claim_sha256=$env:OWNER_CLAIM_SHA256;run_id=$env:GITHUB_RUN_ID;run_attempt=$env:GITHUB_RUN_ATTEMPT;parent_cpu_seconds=$owner.TotalProcessorTime.TotalSeconds;parent_wall_seconds=$watch.Elapsed.TotalSeconds;peak_committed_bytes=$owner.PeakPagedMemorySize64;peak_working_set_bytes=$owner.PeakWorkingSet64;bootstrap_powershell_version=$PSVersionTable.PSVersion.ToString();bootstrap_runtime=[Environment]::Version.ToString();bootstrap_sha256=(Get-ReleaseHash $owner.Path);children=$children.ToArray();storage_observations=$observations.ToArray();setup=$setup;helper_loaded=$false;signing=$false;provider_origin_verified=$false;observed_inventory_complete=($null -eq $first);final_closed_inventory=$false;pending_receipt_reservations=$true;transient_storage_peak='UNKNOWN';os_service_cpu='EXCLUDED_UNOBSERVED'}
try{Write-HostedJson (Join-Path $evidence 'HOSTED_RESULT.json') $result}catch{
 $secondary.Add('SECONDARY_RESULT_PUBLICATION:'+ $_.Exception.Message);$result.secondary_failures=$secondary.ToArray()
 $result|ConvertTo-Json -Depth 20 -Compress
 throw 'HostedResultPublicationFailurePreservedInLog'
}
$files=@(Get-ChildItem -LiteralPath $evidence -File -Recurse);$size=($files|Measure-Object Length -Sum).Sum
if($size -gt $limits.evidence_logical_bytes -or $files.Count -gt $limits.evidence_files){throw 'EvidenceUploadScopeExceeded'}
$result|ConvertTo-Json -Depth 20 -Compress
if($null -ne $first){throw 'HostedFailurePreserved'}
Check
