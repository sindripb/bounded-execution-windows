param(
 [Parameter(Mandatory)][ValidateSet('Compact','Extended')][string]$Profile,
 [Parameter(Mandatory)][string]$OutputDirectory,
 [switch]$IncludeContractTests
)
# Compile only. No invocation, reflection load, trust-store change or signing.
$ErrorActionPreference='Stop';Set-StrictMode -Version 3
$watch=[Diagnostics.Stopwatch]::StartNew();$process=[Diagnostics.Process]::GetCurrentProcess()
$root=[IO.Path]::GetFullPath($PSScriptRoot);$out=[IO.Path]::GetFullPath($OutputDirectory)
if($PSVersionTable.PSVersion.ToString() -cne '7.6.5' -or [Environment]::Version.ToString() -cne '10.0.11'){throw 'ReviewedCompilerRuntimeRequired'}
if(Test-Path -LiteralPath $out){throw 'FreshBuildOutputRequired'}
for($p=[IO.DirectoryInfo]::new($root);$null -ne $p;$p=$p.Parent){if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'SourceReparse'}}
$parent=[IO.DirectoryInfo]::new([IO.Path]::GetDirectoryName($out))
if(-not $parent.Exists){throw 'ExistingOutputParentRequired'}
for($p=$parent;$null -ne $p;$p=$p.Parent){if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'OutputReparse'}}
[void][IO.Directory]::CreateDirectory($out)
$first=$null;$bindings=[ordered]@{};$dll=Join-Path $out 'BoundedExecution.Windows.dll'
function Hash([string]$Path){return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()}
function Check-Limits {
 $process.Refresh()
 if($process.TotalProcessorTime.TotalSeconds -ge 6 -or $watch.Elapsed.TotalSeconds -ge 10 -or
    $process.PeakPagedMemorySize64 -ge 536870912 -or $process.PeakWorkingSet64 -ge 536870912){throw 'OrdinaryCompileLimit'}
}
try {
 $manifest=Get-Content -LiteralPath (Join-Path $root 'source-manifest.json') -Raw | ConvertFrom-Json -AsHashtable
 if($manifest.format -cne 'PRIVATE_OSS_PREVIEW_1'){throw 'SourceManifestFormat'}
 $toolchainPath=Join-Path $root 'toolchain.json'
 if((Hash $toolchainPath) -cne $manifest.files['toolchain.json']){throw 'ToolchainManifestIdentity'}
 $toolchain=Get-Content -LiteralPath $toolchainPath -Raw | ConvertFrom-Json -AsHashtable
 if((Hash $process.Path) -cne $toolchain.compiler_host_sha256){throw 'ExactCompilerHostRequired'}
 $names=@($manifest.common)+@($manifest.profiles[$Profile])
 if($IncludeContractTests){$names+=@('tests/PolicyContractCases.cs')}
 $paths=@()
 foreach($name in $names){
  $path=[IO.Path]::GetFullPath((Join-Path $root $name))
  if(-not $path.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)){throw 'SourceEscape'}
  for($p=[IO.FileInfo]::new($path);$null -ne $p -and $p.FullName -cne $root;$p=$(if($p -is [IO.FileInfo]){$p.Directory}else{$p.Parent})){
   if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'SourceReparse'}
  }
  $digest=Hash $path
  if($digest -cne $manifest.files[$name]){throw 'ExactSourceHash'}
  $bindings[$name]=$digest;$paths+=,$path;Check-Limits
 }
 # Load the installed compiler libraries, never the newly compiled helper.
 # Add-Type's source compiler chooses a random assembly name. Roslyn's explicit
 # compilation name and virtual source paths make this build reproducible.
 Add-Type -AssemblyName Microsoft.CodeAnalysis
 Add-Type -AssemblyName Microsoft.CodeAnalysis.CSharp
 $compilerBindings=[ordered]@{}
 foreach($assembly in @('Microsoft.CodeAnalysis.dll','Microsoft.CodeAnalysis.CSharp.dll')){
  $compilerBindings[$assembly]=Hash (Join-Path $PSHOME $assembly)
  if($compilerBindings[$assembly] -cne $toolchain.compiler_bindings[$assembly]){throw 'ExactCompilerLibraryRequired'}
 }
 foreach($compilerType in @([Microsoft.CodeAnalysis.Compilation],[Microsoft.CodeAnalysis.CSharp.CSharpCompilation])){
  $actual=$compilerType.Assembly.Location
  if([IO.Path]::GetDirectoryName($actual) -cne $PSHOME -or (Hash $actual) -cne $compilerBindings[[IO.Path]::GetFileName($actual)]){throw 'LoadedCompilerLocationIdentity'}
 }
 $referenceBindings=[ordered]@{}
 $references=[Collections.Generic.List[Microsoft.CodeAnalysis.MetadataReference]]::new()
 foreach($reference in (Get-ChildItem -LiteralPath (Join-Path $PSHOME ref) -Filter '*.dll' -File | Sort-Object Name)){
  if($reference.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'CompilerReferenceReparse'}
  $referenceBindings[$reference.Name]=Hash $reference.FullName
  if($referenceBindings[$reference.Name] -cne $toolchain.reference_bindings[$reference.Name]){throw 'ExactReferenceRequired'}
  $references.Add([Microsoft.CodeAnalysis.MetadataReference]::CreateFromFile($reference.FullName))
 }
 if($referenceBindings.Count -ne $toolchain.reference_bindings.Count){throw 'ExactReferenceMembershipRequired'}
 $trees=[Collections.Generic.List[Microsoft.CodeAnalysis.SyntaxTree]]::new()
 $parse=[Microsoft.CodeAnalysis.CSharp.CSharpParseOptions]::Default
 for($i=0;$i -lt $paths.Count;$i++){
  $trees.Add([Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText([IO.File]::ReadAllText($paths[$i]),$parse,('/_/bounded-execution-windows/'+$names[$i]),[Text.Encoding]::UTF8))
 }
 $options=[Microsoft.CodeAnalysis.CSharp.CSharpCompilationOptions]::new([Microsoft.CodeAnalysis.OutputKind]::DynamicallyLinkedLibrary)
 $options=$options.WithOptimizationLevel([Microsoft.CodeAnalysis.OptimizationLevel]::Release).WithConcurrentBuild($false).WithDeterministic($true)
 $compilation=[Microsoft.CodeAnalysis.CSharp.CSharpCompilation]::Create('BoundedExecution.Windows',$trees,$references,$options)
 $versionResources=$compilation.CreateDefaultWin32Resources($true,$false,$null,$null)
 $stream=[IO.File]::Open($dll,[IO.FileMode]::CreateNew)
 try{
  $emitted=$compilation.Emit($stream,$null,$null,$versionResources,$null,$null,[Threading.CancellationToken]::None)
  $stream.Flush($true)
  if(-not $emitted.Success){throw ('CompilerDiagnostics:'+($emitted.Diagnostics -join [Environment]::NewLine))}
 }finally{$stream.Dispose();$versionResources.Dispose()}
 if(@([AppDomain]::CurrentDomain.GetAssemblies()|Where-Object {$_.Location -eq $dll}).Count -ne 0){throw 'UnexpectedOutputLoad'}
 if((Get-Item -LiteralPath $dll).Length -gt 131072){throw 'ExistingHelperByteCap'}
 foreach($name in $names){if((Hash (Join-Path $root $name)) -cne $bindings[$name]){throw 'CompileSourceChanged'}}
 foreach($name in $compilerBindings.Keys){if((Hash (Join-Path $PSHOME $name)) -cne $compilerBindings[$name]){throw 'CompilerChanged'}}
 foreach($name in $referenceBindings.Keys){if((Hash (Join-Path (Join-Path $PSHOME ref) $name)) -cne $referenceBindings[$name]){throw 'ReferenceChanged'}}
 Check-Limits
}catch{$first=$_.Exception.ToString()}
$process.Refresh()
$receipt=[ordered]@{status=$(if($null -eq $first){'PASS_COMPILE_ONLY'}else{'FAIL'});first_failure=$first;
 profile=$Profile;tests_compiled=[bool]$IncludeContractTests;tests_executed=$false;output_loaded=$false;
 signing_performed=$false;execution_authority=$false;source_hashes=$bindings;source_manifest_sha256=(Hash (Join-Path $root 'source-manifest.json'));
 build_script_sha256=(Hash $PSCommandPath);compiler_host_sha256=(Hash $process.Path);powershell_version=$PSVersionTable.PSVersion.ToString();
 dotnet_version=[Environment]::Version.ToString();cpu_seconds=$process.TotalProcessorTime.TotalSeconds;
 wall_seconds=$watch.Elapsed.TotalSeconds;peak_committed_bytes=$process.PeakPagedMemorySize64;peak_working_set_bytes=$process.PeakWorkingSet64}
if(Test-Path -LiteralPath $dll){$receipt.dll_sha256=Hash $dll;$receipt.dll_bytes=(Get-Item -LiteralPath $dll).Length}
if($null -ne (Get-Variable compilerBindings -ErrorAction SilentlyContinue)){$receipt.compiler_bindings=$compilerBindings;$receipt.reference_bindings=$referenceBindings}
$bytes=[Text.Encoding]::UTF8.GetBytes(($receipt|ConvertTo-Json -Depth 8 -Compress))
$stream=[IO.File]::Open((Join-Path $out 'BUILD_RECEIPT.json'),[IO.FileMode]::CreateNew)
try{$stream.Write($bytes);$stream.Flush($true)}finally{$stream.Dispose()}
$receipt|ConvertTo-Json -Depth 8 -Compress
if($null -ne $first){throw 'CompileFailurePreserved'}
