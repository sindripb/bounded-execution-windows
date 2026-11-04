// Optional, explicitly weaker synthetic-inert storage contract. No process/Job/observer APIs.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;

public static class RuntimeScratch {
    public const string Model="OBSERVED_PLUS_RESERVED_RUNTIME_SCRATCH";
    public const string Scope="GENUINE_HISTORICAL_PRICES_WITH_DECLARED_PAPER_ECONOMICS";
    public const string Prefix="control/temporary/",Journal="control/RUNTIME_SCRATCH_OBSERVATION.json";
    public const long Logical=32768,Physical=262144,ObservationLogical=32768,ObservationPhysical=65536;
    public const int Files=8,ObservationFiles=2,PerFileLogical=4096,PerFilePhysical=32768,RecordCap=16384;
    public const long ControlBaseLogical=370688,ControlBasePhysical=1441792;
    static readonly HashSet<string> Failures=new HashSet<string>(new[]{"control/C_FIRST_FAILURE.json","control/P_FAILURE_OUTPUT.json","control/OWNER_FAILURE.json","control/FIRST_HOST_FAILURE.json","control/HOST_POST_PUBLICATION_FAILURE.json","control/ROOT_TOPOLOGY_FORENSICS.json","control/ROOT_FORENSIC_EXITS.json"},StringComparer.OrdinalIgnoreCase);
    public sealed class Artifact {
        public string path="",sha256="",kind="DURABLE";public long bytes;public bool required=true;
    }
    public sealed class Contract {
        public readonly string root,policy,rootHash;
        readonly Dictionary<string,Artifact> artifacts=new Dictionary<string,Artifact>(StringComparer.OrdinalIgnoreCase);
        readonly HashSet<string> declared=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        readonly Dictionary<string,string> identities=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        internal bool baseline;
        public bool closed_phase;
        internal IOException first;
        public Contract(string directory,string policySha,string scope,Artifact[] required,string[] durableDeclarations) {
            root=Path.GetFullPath(directory);
            if(scope!=Scope||!Hex(policySha)||root.StartsWith("\\\\",StringComparison.Ordinal))throw new IOException("RuntimeScratch:ScopeOrPolicy");
            policy=policySha;rootHash=Hash(Encoding.UTF8.GetBytes(root));
            declared.Add(Journal);
            foreach(var p in durableDeclarations??Array.Empty<string>())declared.Add(Canonical(p));
            foreach(var a in required??Array.Empty<Artifact>()) {
                string p=Canonical(a.path);
                if(a.bytes<0||a.bytes>LiveStorage.LogicalLimit||!Hex(a.sha256)||!a.required||artifacts.ContainsKey(p))throw new IOException("RuntimeScratch:ArtifactContract");
                artifacts.Add(p,new Artifact{path=p,bytes=a.bytes,sha256=a.sha256,kind=a.kind,required=true});declared.Add(p);
            }
            SafeDirectories();
        }
        internal string Canonical(string p) {
            if(string.IsNullOrEmpty(p)||p.Contains('\\')||p.StartsWith("/",StringComparison.Ordinal)||p.Contains(':'))throw new IOException("RuntimeScratch:NoncanonicalPath");
            string r=LiveStorage.Relative(root,Path.Combine(root,p));
            if(!string.Equals(p,r,StringComparison.Ordinal))throw new IOException("RuntimeScratch:NoncanonicalPath");return r;
        }
        internal void SafeDirectories() {
            for(var d=new DirectoryInfo(root);d!=null;d=d.Parent)if((d.Attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("RuntimeScratch:ReparseAncestor");
            foreach(string d in new[]{root,Path.Combine(root,"control"),Path.Combine(root,"control","temporary")}) {
                var a=File.GetAttributes(d);
                if((a&FileAttributes.Directory)==0||(a&FileAttributes.ReparsePoint)!=0)throw new IOException("RuntimeScratch:UnsafeDirectory");
            }
        }
        public bool Scratch(string relative) {
            string p=Canonical(relative);
            return p.StartsWith(Prefix,StringComparison.OrdinalIgnoreCase)&&!declared.Contains(p)&&!artifacts.ContainsKey(p);
        }
        public void RequiredNames(string[] names,string phase) {
            SafeDirectories();var set=new HashSet<string>(names,StringComparer.OrdinalIgnoreCase);
            foreach(var a in artifacts.Values)if(a.required&&!set.Contains(a.path))
                throw LiveStorage.Fault(root,Path.Combine(root,a.path),"REGISTERED_ARTIFACT_MISSING",phase,"NOT_ENUMERATED",false,2);
        }
        public void VerifyEntry(LiveStorage.Entry entry,IntPtr handle,string phase,string snapshot) {
            // No filename-based safety inference. Every declared immutable byte identity wins.
            if(artifacts.TryGetValue(entry.path,out Artifact a)) {
                if(identities.TryGetValue(entry.path,out string prior)&&prior!=entry.Identity())throw LiveStorage.Fault(root,Path.Combine(root,entry.path),"REGISTERED_ARTIFACT_CHANGED",phase,snapshot,true,null);
                if(entry.bytes!=a.bytes)throw LiveStorage.Fault(root,Path.Combine(root,entry.path),"REGISTERED_ARTIFACT_CHANGED",phase,snapshot,true,null);
                using(var s=new FileStream(new SafeFileHandle(handle,false),FileAccess.Read)) {
                    s.Position=0;
                    string actual=LiveStorage.StreamHash(s);
                    if(actual!=a.sha256)throw LiveStorage.Fault(root,Path.Combine(root,entry.path),"REGISTERED_ARTIFACT_CHANGED",phase,snapshot,true,null);
                }
                identities[entry.path]=entry.Identity();
            }
        }
        public void Publication(string destination,string temporary,byte[] raw) {
            foreach(string p in new[]{destination,temporary}) {
                string r=LiveStorage.Relative(root,p);Canonical(r);declared.Add(r);
                if(artifacts.TryGetValue(r,out Artifact old)&&old.required)throw new IOException("RuntimeScratch:RegisteredPublicationCollision");
                artifacts[r]=new Artifact{path=r,bytes=raw.Length,sha256=Hash(raw),kind="PUBLISHER_TRANSACTION",required=false};
            }
        }
        public void Mark(string path,bool required) {artifacts[LiveStorage.Relative(root,path)].required=required;}
        internal void LoadJournal() {
            SafeDirectories();string file=Path.Combine(root,Journal);
            if(Directory.GetFiles(Path.Combine(root,"control"),"RUNTIME_SCRATCH_OBSERVATION.json.*.tmp",SearchOption.TopDirectoryOnly).Length!=0)
                throw new IOException("RuntimeScratch:IncompleteObservationPublication");
            if(!File.Exists(file)) {
                if(first!=null)throw new IOException("RuntimeScratch:ObservationMissing");return;
            }
            byte[] raw=ReadBounded(root,file,RecordCap);
            using(var doc=JsonDocument.Parse(raw)) {
                var e=doc.RootElement;string[] keys=e.EnumerateObject().Select(p=>p.Name).ToArray();
                string[] wanted={"schema_version","model","policy_sha256","root_sha256","first_message","first_diagnostic"};
                if(keys.Length!=wanted.Length||keys.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=keys.Length||!new HashSet<string>(keys).SetEquals(wanted)||
                    e.GetProperty("schema_version").GetInt32()!=1||e.GetProperty("model").GetString()!=Model||
                    e.GetProperty("policy_sha256").GetString()!=policy||e.GetProperty("root_sha256").GetString()!=rootHash)
                    throw new IOException("RuntimeScratch:ObservationBinding");
                string diagnostic=e.GetProperty("first_diagnostic").GetString(),message=e.GetProperty("first_message").GetString();
                if(message==null||message.Length>2048||diagnostic==null||Encoding.UTF8.GetByteCount(diagnostic)>4096)throw new IOException("RuntimeScratch:ObservationBound");
                var recovered=new IOException(message);recovered.Data["StorageDiagnosticJson"]=diagnostic;
                using(var detail=JsonDocument.Parse(diagnostic))if(detail.RootElement.EnumerateObject().Select(p=>p.Name).Distinct(StringComparer.OrdinalIgnoreCase).Count()!=detail.RootElement.EnumerateObject().Count())throw new IOException("RuntimeScratch:ObservationBinding");
                if(!Qualifying(this,recovered))throw new IOException("RuntimeScratch:ObservationBinding");
                if(first==null)first=recovered;
                if(artifacts.TryGetValue(Journal,out Artifact old)&&old.sha256!=Hash(raw))throw new IOException("RuntimeScratch:ObservationChanged");
                artifacts[Journal]=new Artifact{path=Journal,bytes=raw.Length,sha256=Hash(raw),required=true};
            }
        }
        internal void PublishObservation(IOException original,long end) {
            Deadline(end);LoadJournal();if(first!=null)throw new IOException("RuntimeScratch:RestartAlreadySpent");
            string diagnostic=(string)original.Data["StorageDiagnosticJson"];
            byte[] raw=JsonSerializer.SerializeToUtf8Bytes(new {schema_version=1,model=Model,policy_sha256=policy,root_sha256=rootHash,
                first_message=original.Message,first_diagnostic=diagnostic});
            if(raw.Length>RecordCap)throw new IOException("RuntimeScratch:ObservationBound");
            string path=Path.GetFullPath(Path.Combine(root,Journal)),temporary=path+"."+Environment.ProcessId+".tmp";
            string directory=Path.GetDirectoryName(path);
            var parent=LocalControl.RetainExisting(directory,directory,end);Exception publicationFailure=null;
            try {
            // Existing scope lease remains held. Two bounded files are reserved in advance.
            // A partial temp permanently blocks recovery; no repair or replacement is attempted.
            Publication(path,temporary,raw);
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)){stream.Write(raw);stream.Flush(true);}
            Mark(temporary,true);Deadline(end);
            LiveStorage.Entry expected;
            if(!ReadBounded(root,temporary,RecordCap,out expected).SequenceEqual(raw))throw new IOException("RuntimeScratch:TemporaryObservationChanged");
            LiveStorage.RenameSameParent(root,temporary,path,expected,raw,parent,end);Mark(temporary,false);Mark(path,true);
            if(!ReadBounded(root,path,RecordCap).SequenceEqual(raw))throw new IOException("RuntimeScratch:ObservationReadback");
            first=original;Deadline(end);
            }catch(Exception error){publicationFailure=error;throw;}
            finally{try{parent.Dispose();}catch(Exception cleanup){if(publicationFailure==null)throw;LiveStorage.Secondary(publicationFailure,cleanup);}}
        }
        internal void Decorate(LiveStorage.Census value) {
            var scratch=value.entries.Where(e=>Scratch(e.path)).ToArray();
            if(scratch.Length>Files||scratch.Any(e=>e.bytes>PerFileLogical||e.allocated_bytes>PerFilePhysical)||scratch.Sum(e=>e.bytes)>Logical||scratch.Sum(e=>e.allocated_bytes)>Physical)
                throw new IOException("RuntimeScratch:ReservationExhausted");
            var observation=value.entries.Where(e=>e.path.Equals(Journal,StringComparison.OrdinalIgnoreCase)||e.path.StartsWith(Journal+".",StringComparison.OrdinalIgnoreCase)).ToArray();
            if(observation.Length>ObservationFiles||observation.Any(e=>e.bytes>RecordCap||e.allocated_bytes>32768)||observation.Sum(e=>e.bytes)>ObservationLogical||observation.Sum(e=>e.allocated_bytes)>ObservationPhysical)throw new IOException("RuntimeScratch:ObservationReservationExhausted");
            var control=value.entries.Where(e=>e.path.StartsWith("control/",StringComparison.OrdinalIgnoreCase)&&!Scratch(e.path)&&!observation.Contains(e)&&!Failures.Contains(e.path)&&
                !e.path.Equals("control/HOST_CLOSED_INVENTORY.json",StringComparison.OrdinalIgnoreCase)&&!e.path.Equals("control/INERT_DIAGNOSTIC_CLOSEOUT.json",StringComparison.OrdinalIgnoreCase)&&
                !(artifacts.TryGetValue(e.path,out Artifact a)&&a.kind=="SOURCE")).ToArray();
            if(control.Sum(e=>e.bytes)>ControlBaseLogical||control.Sum(e=>e.allocated_bytes)>ControlBasePhysical)throw new IOException("RuntimeScratch:ControlPartitionExhausted");
            value.accounting_scope=Model;value.transient_peak="UNKNOWN_NOT_ZERO_NOT_HARD_CONTAINMENT";
            // Charge observed files PLUS the complete reservation, including the observation.
            value.scratch_logical_reserve=Logical+ObservationLogical;value.scratch_physical_reserve=Physical+ObservationPhysical;
            value.scratch_file_reserve=Files+ObservationFiles;
            value.first_disappearance_json=first==null?null:(string)first.Data["StorageDiagnosticJson"];
        }
    }
    public static bool Hex(string value){return value!=null&&value.Length==64&&value.All(c=>(c>='0'&&c<='9')||(c>='a'&&c<='f'));}
    static string Hash(byte[] raw){return Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();}
    static byte[] ReadBounded(string root,string path,int cap) {
        LiveStorage.Entry ignored;return ReadBounded(root,path,cap,out ignored);
    }
    static byte[] ReadBounded(string root,string path,int cap,out LiveStorage.Entry identity) {
        identity=null;
        IntPtr h=LiveStorage.CreateFileW(path,0x80000080,1,IntPtr.Zero,3,0x200000,IntPtr.Zero);Exception first=null;
        if(h==new IntPtr(-1))throw new IOException("RuntimeScratch:ObservationOpen");
        try {
            var before=LiveStorage.Metadata(root,path,h,"OBSERVATION_METADATA","RUNTIME_SCRATCH","NOT_ENUMERATED");
            identity=before;
            if(before.bytes>cap)throw new IOException("RuntimeScratch:ObservationBound");
            using(var s=new FileStream(new SafeFileHandle(h,false),FileAccess.Read)) {
                byte[] bytes=new byte[(int)before.bytes];s.ReadExactly(bytes);
                if(LiveStorage.Metadata(root,path,h,"OBSERVATION_RECHECK","RUNTIME_SCRATCH","NOT_ENUMERATED").Identity()!=before.Identity())throw new IOException("RuntimeScratch:ObservationChanged");
                return bytes;
            }
        }catch(Exception e){first=e;throw;}
        finally{if(!LiveStorage.CloseHandle(h)){var e=new IOException("RuntimeScratch:ObservationClose");if(first==null)throw e;LiveStorage.Secondary(first,e);}}
    }
    internal static void Deadline(long end){if(end<=0||Stopwatch.GetTimestamp()>=end)throw new IOException("RuntimeScratch:AbsoluteDeadline");}
    static bool Qualifying(Contract c,IOException e) {
        if(e.Data.Contains("StorageCleanupErrors")||!e.Data.Contains("StorageDiagnosticJson"))return false;
        using(var d=JsonDocument.Parse((string)e.Data["StorageDiagnosticJson"])) {
            var r=d.RootElement;string op=r.GetProperty("operation").GetString();
            return r.GetProperty("windows_error").ValueKind==JsonValueKind.Number&&r.GetProperty("windows_error").GetInt32()==2&&
                (op=="OPEN_CENSUS_FILE"||op=="ENUMERATE")&&c.Scratch(r.GetProperty("path").GetString());
        }
    }
    public static LiveStorage.Census Capture(string root,LiveStorage.Lease lease,bool closed,string phase,long end,Contract contract,string[] initialNames=null) {
        if(Path.GetFullPath(root)!=contract.root)throw new IOException("RuntimeScratch:ScopeMismatch");
        closed=closed||contract.closed_phase;
        contract.LoadJournal();IOException original=contract.first;
        try {
            Deadline(end);
            var value=LiveStorage.Capture(root,lease,initialNames??LiveStorage.Discover(root,phase),closed,phase,contract);
            contract.Decorate(value);LiveStorage.Budget(value,0,0);Deadline(end);contract.baseline=true;return value;
        }catch(IOException failure) {
            if(closed||!contract.baseline||!Qualifying(contract,failure))throw;
            if(original!=null){LiveStorage.Secondary(original,failure);throw original;}
            try {
                contract.PublishObservation(failure,end);
                // Exactly one fresh full discovery/capture; the same absolute endpoint and lease.
                var value=LiveStorage.Capture(root,lease,LiveStorage.Discover(root,phase),false,phase,contract);
                contract.Decorate(value);LiveStorage.Budget(value,0,0);Deadline(end);return value;
            }catch(Exception second){LiveStorage.Secondary(failure,second);throw failure;}
        }
    }
}
