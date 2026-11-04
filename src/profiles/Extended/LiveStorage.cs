// Scoped file publication/census coordination only. No process, Job or financial APIs.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class LiveStorage {
    // Preparation-only diagnostic hook. No sharing, access, publication or close rule changes.
    public static Action<string,string,string> DiagnosticObserver;
    public static string DiagnosticObserverFailure;
    static readonly Queue<string> GateHistory=new Queue<string>();
    public static string[] GateDiagnostics(){return GateHistory.ToArray();}
    static void GateTrace(string value){if(GateHistory.Count==12)GateHistory.Dequeue();GateHistory.Enqueue(Stopwatch.GetTimestamp()+":"+value);}

    internal static void Trace(string operation,string path,string detail) {
        if(operation=="GATE_OPEN"||operation=="GATE_CLOSE")GateTrace(operation+":"+detail);
        try {if(DiagnosticObserver!=null)DiagnosticObserver(operation,path,detail);}
        catch(Exception failure) {if(DiagnosticObserverFailure==null)DiagnosticObserverFailure=failure.Message.Substring(0,Math.Min(256,failure.Message.Length));}
    }
    public const long LogicalLimit=12806754328, PhysicalLimit=14954225664;
    public const int FileLimit=256;
    public const string GateName="STORAGE_GATE.lock";
    [StructLayout(LayoutKind.Sequential)] struct Standard {public long allocation,end;public uint links;public byte pending,directory;}
    [StructLayout(LayoutKind.Sequential)] struct FT {public uint low,high;public ulong Value {get{return ((ulong)high<<32)|low;}}}
    [StructLayout(LayoutKind.Sequential)] struct FI {public uint attributes;public FT created,accessed,written;public uint volume,sizeHigh,sizeLow,links,idHigh,idLow;}
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] internal static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
    [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr h,int c,out Standard s,uint n);
    [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out FI s);
    [DllImport("kernel32",SetLastError=true)] internal static extern bool CloseHandle(IntPtr h);
    [StructLayout(LayoutKind.Sequential)] struct RenameLayout { public uint flags;public IntPtr root;public uint nameBytes;public char first; }
    [StructLayout(LayoutKind.Sequential)] struct IoStatus { public IntPtr status;public UIntPtr information; }
    [DllImport("ntdll.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern int NtSetInformationFile(IntPtr handle,out IoStatus io,[In] byte[] information,uint length,int informationClass);
    [DllImport("ntdll.dll",ExactSpelling=true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    static extern uint RtlNtStatusToDosError(int status);
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern uint GetFinalPathNameByHandleW(IntPtr handle,StringBuilder path,uint capacity,uint flags);
    static IOException RenameError(string phase,int error) {
        return new IOException("AtomicRename:"+phase+":"+error,unchecked((int)(0x80070000u|(uint)error)));
    }
    static void ExactFilePath(IntPtr handle,string expected) {
        var text=new StringBuilder(1024);uint length=GetFinalPathNameByHandleW(handle,text,(uint)text.Capacity,0);
        if(length==0)throw RenameError("ResolvedFilePath",Marshal.GetLastWin32Error());
        if(length>=text.Capacity||!string.Equals(text.ToString(),"\\\\?\\"+expected,StringComparison.OrdinalIgnoreCase))throw new IOException("AtomicRename:ResolvedFilePathMismatch");
    }
    internal static string StreamHash(Stream stream) {
        byte[] buffer=System.Buffers.ArrayPool<byte>.Shared.Rent(65536);
        try{using(var hash=IncrementalHash.CreateHash(HashAlgorithmName.SHA256)){
            int n;while((n=stream.Read(buffer,0,65536))!=0)hash.AppendData(buffer,0,n);
            return Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant();
        }}finally{System.Buffers.ArrayPool<byte>.Shared.Return(buffer);}
    }
    static string HeldHash(IntPtr handle) {
        using(var stream=new FileStream(new SafeFileHandle(handle,false),FileAccess.Read)) {
            stream.Position=0;return StreamHash(stream);
        }
    }
    // FILE_RENAME_INFORMATION: NULL RootDirectory + a simple leaf renames within
    // the source handle's existing directory. No absolute-path parent reopen.
    // https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
    static string PublicationLeaf(string temporary,string destination) {
        string directory=Path.GetDirectoryName(temporary),leaf=Path.GetFileName(destination);
        if(!string.Equals(directory,Path.GetDirectoryName(destination),StringComparison.Ordinal)||
           leaf.Length==0||leaf=="."||leaf==".."||leaf.EndsWith(".",StringComparison.Ordinal)||leaf.EndsWith(" ",StringComparison.Ordinal)||
           leaf.IndexOfAny(Path.GetInvalidFileNameChars())>=0||leaf.Contains(':')||leaf.Contains('\\')||leaf.Contains('/'))throw new IOException("AtomicRename:SameParentSimpleLeafRequired");
        string stem=leaf.Split('.')[0].TrimEnd(' ').ToUpperInvariant();
        if(stem=="CON"||stem=="PRN"||stem=="AUX"||stem=="NUL"||stem=="CONIN$"||stem=="CONOUT$"||
           (stem.Length==4&&(stem.StartsWith("COM",StringComparison.Ordinal)||stem.StartsWith("LPT",StringComparison.Ordinal))&&(char.IsDigit(stem[3])||"ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â¹ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â²ÃƒÆ’Ã¢â‚¬Å¡Ãƒâ€šÃ‚Â³".Contains(stem[3]))))throw new IOException("AtomicRename:DeviceNameRejected");
        return leaf;
    }
    static byte[] RenameInformation(string leaf) {
        int offset=(int)Marshal.OffsetOf<RenameLayout>(nameof(RenameLayout.first));
        if(offset!=20||Marshal.SizeOf<RenameLayout>()!=24||Marshal.SizeOf<IoStatus>()!=16)throw new IOException("AtomicRename:NativeLayoutMismatch");
        byte[] name=Encoding.Unicode.GetBytes(leaf),buffer=new byte[24+Encoding.Unicode.GetByteCount(leaf)];
        // Zeroed flags/ReplaceIfExists and RootDirectory; no POSIX or replacement flags.
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(16,4),(uint)name.Length);
        Buffer.BlockCopy(name,0,buffer,offset,name.Length);return buffer;
    }
    internal static void RenameSameParent(string root,string temporary,string destination,Entry expected,byte[] raw,LocalControl parent,long end) {
        if(!OperatingSystem.IsWindows()||IntPtr.Size!=8)throw new IOException("AtomicRename:PinnedWindowsX64Required");
        if(Stopwatch.GetTimestamp()>=end)throw new IOException("AtomicRename:AbsoluteDeadline");
        string leaf=PublicationLeaf(temporary,destination);
        Relative(root,temporary);Relative(root,destination);parent.Validate();
        // Synchronous CreateFile; READ verifies bytes, DELETE permits rename.
        // READ-only sharing retains denial of other writers/deleters on this file.
        IntPtr h=CreateFileW(temporary,0x80010080,1,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
        if(h==new IntPtr(-1)){int error=Marshal.GetLastWin32Error();Trace("RENAME_SOURCE_OPEN_FAILURE",temporary,"access=0x80010080;share=1;win32="+error);throw RenameError("OpenSource",error);}
        Exception first=null;
        try {
            ExactFilePath(h,temporary);
            var before=Metadata(root,temporary,h,"RENAME_SOURCE","ATOMIC_CREATE_NEW_RENAME","HELD_SOURCE");
            Trace("RENAME_SOURCE_OPEN",temporary,"handle=0x"+h.ToInt64().ToString("x")+";access=0x80010080;share=1;identity="+before.Identity());
            string expectedHash=Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant();
            if(before.Identity()!=expected.Identity()||before.bytes!=raw.Length||HeldHash(h)!=expectedHash)throw new IOException("AtomicRename:TemporaryIdentityOrBytesChanged");
            byte[] buffer=RenameInformation(leaf);
            parent.Validate();
            Trace("NATIVE_RENAME_BEGIN",temporary,"class=10;replace=false;root=NULL;leaf="+leaf+";handle=0x"+h.ToInt64().ToString("x"));
            IoStatus io;int status=NtSetInformationFile(h,out io,buffer,(uint)buffer.Length,10);
            Trace("NATIVE_RENAME_RESULT",temporary,"ntstatus=0x"+unchecked((uint)status).ToString("x8")+";io_status=0x"+unchecked((uint)io.status.ToInt64()).ToString("x8"));
            if(status!=0)throw RenameError("NtSetInformationFile",checked((int)RtlNtStatusToDosError(status)));
            if(io.status!=IntPtr.Zero)throw new IOException("AtomicRename:UnexpectedCompletionStatus");
            ExactFilePath(h,destination);parent.Validate();
            if(Metadata(root,destination,h,"RENAME_DESTINATION","READBACK","HELD_SOURCE").Identity()!=before.Identity()||HeldHash(h)!=expectedHash)throw new IOException("AtomicRename:HeldDestinationIdentityOrBytesChanged");
        }catch(Exception error){first=error;throw;}
        finally {
            bool ok=CloseHandle(h);int error=ok?0:Marshal.GetLastWin32Error();Trace("RENAME_SOURCE_CLOSE",temporary,"handle=0x"+h.ToInt64().ToString("x")+";closed="+ok);
            if(!ok){var cleanup=RenameError("CloseSource",error);if(first==null)throw cleanup;Secondary(first,cleanup);}
        }
    }
    public sealed class Entry {
        public string path="",sha256=null;public long bytes,allocated_bytes;public uint volume;
        public ulong file_id,creation_filetime,write_filetime;
        public string Identity(){return bytes+":"+allocated_bytes+":"+volume+":"+file_id+":"+creation_filetime+":"+write_filetime;}
    }
    public sealed class Census {
        public long original_source_bytes,original_source_allocated_allowance;
        public int files;public long logical_bytes,allocated_bytes,begin_qpc,end_qpc;
        public string snapshot_sha256="",mode="";public Entry[] entries=Array.Empty<Entry>();
        public string accounting_scope="ORIGINAL_STRICT",transient_peak="UNKNOWN_NOT_MEASURED";
        public long scratch_logical_reserve,scratch_physical_reserve;public int scratch_file_reserve;
        public string first_disappearance_json=null;
    }
    internal static string Relative(string root,string path) {
        string full=Path.GetFullPath(path),r=Path.GetRelativePath(root,full).Replace('\\','/');
        if(r==".."||r.StartsWith("../",StringComparison.Ordinal)||Path.IsPathFullyQualified(r))throw new IOException("StoragePathOutsideScope");
        return r;
    }
    internal static IOException Fault(string root,string path,string operation,string phase,string snapshot,bool opened,int? code,Exception original=null) {
        string relative;
        try{relative=Relative(root,path);}catch{relative="OUTSIDE_SCOPE_REJECTED";}
        if(relative.Length>512)relative="SCOPED_PATH_SHA256:"+Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(relative))).ToLowerInvariant();
        var e=new IOException("Storage:"+operation+":"+(code.HasValue?code.Value.ToString():"UNKNOWN_WIN32")+":"+relative,original);
        e.Data["StorageDiagnosticJson"]=JsonSerializer.Serialize(new{path=relative,operation,phase,windows_error=code,snapshot_sha256=snapshot,
            handle_opened=opened,publication_state="SCOPE_GATE_REQUIRED; TEMP_AND_FINAL_FULLY_CHARGED; CREATE_NEW_NO_REPLACEMENT"});
        return e;
    }
    static int? Win32(Exception e){uint code=unchecked((uint)e.HResult);return (code&0xffff0000)==0x80070000?(int?)(code&65535):null;}
    internal static void Secondary(Exception first,Exception cleanup) {
        string prior=first.Data["StorageCleanupErrors"] as string;
        string combined=(prior??"")+" | "+cleanup.Message;
        first.Data["StorageCleanupErrors"]=combined.Substring(0,Math.Min(2048,combined.Length));
        if(combined.Length>2048)first.Data["StorageCleanupErrorsTruncated"]=true;
    }
    public sealed class Lease : IDisposable {
        internal IntPtr handle;internal readonly string root;
        internal Lease(string r,IntPtr h){root=r;handle=h;}
        public void Dispose(){if(handle==IntPtr.Zero)return;IntPtr h=handle;handle=IntPtr.Zero;bool ok=CloseHandle(h);int error=ok?0:Marshal.GetLastWin32Error();Trace("GATE_CLOSE",Path.Combine(root,GateName),"handle=0x"+h.ToInt64().ToString("x")+";closed="+ok);if(!ok)throw Fault(root,Path.Combine(root,GateName),"CLOSE_GATE","RELEASE","NOT_ENUMERATED",true,error);}
    }
    public static Lease Acquire(string scope,long absoluteEnd,string phase) {
        string root=Path.GetFullPath(scope),path=Path.Combine(root,GateName);
        long end=Math.Min(absoluteEnd>0?absoluteEnd:long.MaxValue,Stopwatch.GetTimestamp()+2*Stopwatch.Frequency);
        while(true) {
            // GENERIC_READ is required: attributes-only opens do not serialize sharing.
            IntPtr h=CreateFileW(path,0x80000080,0,IntPtr.Zero,3,0x200000,IntPtr.Zero);
            if(h!=new IntPtr(-1)) {
                var lease=new Lease(root,h);
                try{var meta=Metadata(root,path,h,"OPEN_GATE",phase,"NOT_ENUMERATED");if(meta.bytes!=0)throw Fault(root,path,"NONEMPTY_GATE",phase,"NOT_ENUMERATED",true,null);Trace("GATE_OPEN",path,"handle=0x"+h.ToInt64().ToString("x")+";access=0x80000080;share=0;identity="+meta.Identity());return lease;}
                catch(Exception first){try{lease.Dispose();}catch(Exception close){Secondary(first,close);}throw;}
            }
            int error=Marshal.GetLastWin32Error();
            if(error!=32||Stopwatch.GetTimestamp()>=end){var failure=Fault(root,path,"OPEN_GATE",phase,"NOT_ENUMERATED",false,error);failure.Data["GateDiagnosticJson"]=JsonSerializer.Serialize(new{pid=Environment.ProcessId,qpc=Stopwatch.GetTimestamp(),phase,history=GateDiagnostics()});throw failure;}
            Thread.Sleep(5); // Bounded contention wait, never a missing-file retry.
        }
    }
    internal static Entry Metadata(string root,string path,IntPtr h,string op,string phase,string snapshot) {
        Standard s;FI i;
        if(!GetFileInformationByHandleEx(h,1,out s,(uint)Marshal.SizeOf<Standard>())||!GetFileInformationByHandle(h,out i))
            throw Fault(root,path,op,phase,snapshot,true,Marshal.GetLastWin32Error());
        if(s.allocation<0||s.end<0||s.directory!=0||s.pending!=0||(i.attributes&0x400)!=0)
            throw Fault(root,path,"UNSAFE_FILE_METADATA",phase,snapshot,true,null);
        return new Entry{path=Relative(root,path),bytes=s.end,allocated_bytes=s.allocation,volume=i.volume,
            file_id=((ulong)i.idHigh<<32)|i.idLow,creation_filetime=i.created.Value,write_filetime=i.written.Value};
    }
    public static string[] Discover(string scope,string phase) {
        string root=Path.GetFullPath(scope),current=root;var paths=new List<string>();int directories=0;
        try {
            var rootAttributes=File.GetAttributes(root);
            if((rootAttributes&FileAttributes.Directory)==0)throw Fault(root,root,"NOT_A_DIRECTORY",phase,"NOT_ENUMERATED",false,null);
            if((rootAttributes&FileAttributes.ReparsePoint)!=0)throw Fault(root,root,"REPARSE_SCOPE",phase,"NOT_ENUMERATED",false,null);
            var pending=new Stack<string>();pending.Push(root);
            while(pending.Count>0)foreach(string path in Directory.EnumerateFileSystemEntries(pending.Pop())) {
                current=path;
                var attributes=File.GetAttributes(path);
                if((attributes&FileAttributes.ReparsePoint)!=0)throw Fault(root,path,"REPARSE_ARTIFACT",phase,"NOT_ENUMERATED",false,null);
                if((attributes&FileAttributes.Directory)!=0){if(++directories>256)throw Fault(root,path,"DIRECTORY_BOUND",phase,"NOT_ENUMERATED",false,null);pending.Push(path);}else paths.Add(Relative(root,path));
                if(paths.Count>FileLimit)throw Fault(root,path,"MEMBERSHIP_LIMIT",phase,"NOT_ENUMERATED",false,null);
            }
            paths.Sort(StringComparer.Ordinal);
            if(paths.Count>FileLimit||paths.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=paths.Count)throw Fault(root,root,"MEMBERSHIP_LIMIT",phase,"NOT_ENUMERATED",false,null);
            return paths.ToArray();
        }catch(Exception e){if(!e.Data.Contains("StorageDiagnosticJson"))throw Fault(root,current,"ENUMERATE",phase,"NOT_ENUMERATED",false,Win32(e),e);throw;}
    }
    public static Census Capture(string scope,Lease lease,string[] discovered,bool closed,string phase,RuntimeScratch.Contract contract=null) {
        string root=Path.GetFullPath(scope);
        if(lease==null||lease.handle==IntPtr.Zero||root!=lease.root)throw Fault(root,root,"GATE_OWNERSHIP",phase,"NOT_ENUMERATED",false,null);
        long begin=Stopwatch.GetTimestamp();
        string snapshot=Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(string.Join("\n",discovered)+"\nQPC:"+begin))).ToLowerInvariant();
        var handles=new Dictionary<string,IntPtr>(StringComparer.Ordinal);var entries=new List<Entry>();Exception primary=null;
        var result=new Census{begin_qpc=begin,snapshot_sha256=snapshot,mode=closed?"CLOSED_EXCLUSIVE_HASH_READBACK":"LIVE_GATE_HELD_METADATA"};
        try {
            if(contract!=null)contract.RequiredNames(discovered,phase);
            if(!discovered.SequenceEqual(discovered.OrderBy(x=>x,StringComparer.Ordinal),StringComparer.Ordinal)||discovered.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=discovered.Length||discovered.Length>FileLimit)
                throw Fault(root,root,"DISCOVERY_CONTRACT",phase,snapshot,false,null);
            foreach(string name in discovered) {
                string path=Path.GetFullPath(Path.Combine(root,name));Relative(root,path);
                IntPtr h;
                if(name==GateName)h=lease.handle;else {
                    h=CreateFileW(path,0x80000080,closed?0u:1u,IntPtr.Zero,3,0x200000,IntPtr.Zero);
                    if(h==new IntPtr(-1))throw Fault(root,path,"OPEN_CENSUS_FILE",phase,snapshot,false,Marshal.GetLastWin32Error());
                    handles.Add(name,h);
                }
                var observed=Metadata(root,path,h,"FILE_METADATA",phase,snapshot);entries.Add(observed);
                Trace("CENSUS_OPEN",path,"handle=0x"+h.ToInt64().ToString("x")+";access=0x80000080;share="+(closed?0:1)+";identity="+observed.Identity());
            }
            if(closed)foreach(var entry in entries) {
                string pendingPath=Path.Combine(root,entry.path);
                if((pendingPath.EndsWith(".sqlite-wal",StringComparison.Ordinal)||pendingPath.EndsWith(".sqlite-journal",StringComparison.Ordinal))&&entry.bytes!=0)
                    throw Fault(root,pendingPath,"SQLITE_NOT_FINALIZED",phase,snapshot,true,null);
            }
            // Every large file is hashed afresh under its original exclusive handle.
            // The synchronous bounded loop joins all readers before identity checks/close.
            if(closed) {
                var large=entries.Where(e=>e.bytes>=262144).ToArray();
                foreach(var e in large)if(e.bytes>(FullSource(root,e)?24511426:LogicalLimit))throw Fault(root,Path.Combine(root,e.path),"CLOSED_FILE_BYTES_CAP",phase,snapshot,true,null);
                Exception firstHash=null;var later=new System.Collections.Concurrent.ConcurrentQueue<Exception>();
                System.Threading.Tasks.Parallel.ForEach(large,new System.Threading.Tasks.ParallelOptions{MaxDegreeOfParallelism=2},entry=>{
                    try {
                        IntPtr handle=entry.path==GateName?lease.handle:handles[entry.path];
                        using(var stream=new FileStream(new SafeFileHandle(handle,false),FileAccess.Read)){stream.Position=0;entry.sha256=StreamHash(stream);}
                    }catch(Exception failure){if(Interlocked.CompareExchange(ref firstHash,failure,null)!=null)later.Enqueue(failure);}
                });
                if(firstHash!=null){foreach(var failure in later)Secondary(firstHash,failure);throw firstHash;}
            }
            for(int n=0;n<entries.Count;n++) {
                Entry before=entries[n];string path=Path.Combine(root,before.path);
                IntPtr h=before.path==GateName?lease.handle:handles[before.path];
                if(closed&&before.bytes>=262144&&before.sha256==null)throw Fault(root,path,"CLOSED_HASH_MISSING",phase,snapshot,true,null);
                if(closed&&before.bytes<262144) {
                    using(var stream=new FileStream(new SafeFileHandle(h,false),FileAccess.Read)) {
                        if(before.bytes>(FullSource(root,before)?24511426:LogicalLimit))throw Fault(root,path,"CLOSED_FILE_BYTES_CAP",phase,snapshot,true,null);
                        before.sha256=StreamHash(stream);
                    }
                }
                if(contract!=null)contract.VerifyEntry(before,h,phase,snapshot);
                Entry after=Metadata(root,path,h,"RECHECK_FILE_METADATA",phase,snapshot);
                if(after.Identity()!=before.Identity())throw Fault(root,path,"FILE_CHANGED_DURING_CENSUS",phase,snapshot,true,null);
                if(FullSource(root,before)){result.original_source_bytes=before.bytes;result.original_source_allocated_allowance=Math.Min(before.bytes,before.allocated_bytes);}
                result.logical_bytes=checked(result.logical_bytes+before.bytes);result.allocated_bytes=checked(result.allocated_bytes+before.allocated_bytes);
            }
            if(!discovered.SequenceEqual(Discover(root,phase),StringComparer.Ordinal))throw Fault(root,root,"MEMBERSHIP_CHANGED_DURING_CENSUS",phase,snapshot,true,null);
            result.files=entries.Count;result.entries=entries.ToArray();result.end_qpc=Stopwatch.GetTimestamp();return result;
        }catch(Exception e){primary=e;throw;}
        finally {
            foreach(var item in handles) {
                bool ok=CloseHandle(item.Value);int error=ok?0:Marshal.GetLastWin32Error();
                Trace("CENSUS_CLOSE",Path.Combine(root,item.Key),"handle=0x"+item.Value.ToInt64().ToString("x")+";closed="+ok);
                if(!ok) {
                var cleanup=Fault(root,Path.Combine(root,item.Key),"CLOSE_CENSUS_HANDLE",phase,snapshot,true,error);
                if(primary!=null)Secondary(primary,cleanup);else primary=cleanup;
                }
            }
            // A close failure on an otherwise successful census must also fail.
            if(primary!=null&&primary.Message.StartsWith("Storage:CLOSE_CENSUS_HANDLE",StringComparison.Ordinal))throw primary;
        }
    }
    static bool FullSource(string root,Entry e) {
        if(e.path.EndsWith("ARTIFICIAL_MAX_SOURCE.tsv",StringComparison.OrdinalIgnoreCase))throw new IOException("FullSourceNotAuthorized");
        return false;
    }
    public static void Budget(Census value,long logicalReserve,long physicalReserve,int fileReserve=0) {
        if(value.original_source_bytes<0||value.original_source_bytes>24511426||value.original_source_bytes>value.logical_bytes||
           value.original_source_allocated_allowance<0||value.original_source_allocated_allowance>Math.Min(value.original_source_bytes,value.allocated_bytes))throw new IOException("FullSourceChargeContract");
        logicalReserve=checked(logicalReserve+value.scratch_logical_reserve);
        physicalReserve=checked(physicalReserve+value.scratch_physical_reserve);
        fileReserve=checked(fileReserve+value.scratch_file_reserve);
        if(logicalReserve<0||physicalReserve<0||fileReserve<0||value.logical_bytes-value.original_source_bytes>LogicalLimit-logicalReserve||value.allocated_bytes-value.original_source_allocated_allowance>PhysicalLimit-physicalReserve||value.files>FileLimit-fileReserve) {
            var e=new IOException("AggregateStorageLimit:"+value.snapshot_sha256);
            e.Data["StorageDiagnosticJson"]=JsonSerializer.Serialize(new{path="SCOPED_AGGREGATE",operation="BUDGET",phase=value.mode,
                windows_error=(int?)null,snapshot_sha256=value.snapshot_sha256,handle_opened=true,
                publication_state="MEASURED_CENSUS_PLUS_EXPLICIT_RESERVATIONS"});throw e;
        }
    }
    public static Census Snapshot(string root,long logicalReserve,long physicalReserve,long end,string phase,bool closed) {
        return SnapshotRuntime(root,logicalReserve,physicalReserve,end,phase,closed,null);
    }
    public static Census SnapshotRuntime(string root,long logicalReserve,long physicalReserve,long end,string phase,bool closed,RuntimeScratch.Contract contract) {
        Lease lease=Acquire(root,end,phase);Exception first=null;
        try{var value=contract==null?Capture(root,lease,Discover(root,phase),closed,phase):RuntimeScratch.Capture(root,lease,closed,phase,end,contract);Budget(value,logicalReserve,physicalReserve);return value;}
        catch(Exception e){first=e;throw;}
        finally{try{lease.Dispose();}catch(Exception e){if(first==null)throw;Secondary(first,e);}}
    }
    public static void Publish(string root,string destination,byte[] raw,int cap,long end,string phase) {
        PublishRuntime(root,destination,raw,cap,end,phase,null);
    }
    public static void PublishRuntime(string root,string destination,byte[] raw,int cap,long end,string phase,RuntimeScratch.Contract contract) {
        if(cap<1||cap>65536||raw.Length>cap)throw new IOException("ControlPublicationCap");
        root=Path.GetFullPath(root);destination=Path.GetFullPath(destination);Relative(root,destination);
        string temporary=destination+"."+Environment.ProcessId+".tmp",stage="PREPUBLICATION";
        PublicationLeaf(temporary,destination); // Reject stream/device/name ambiguity before any file creation.
        Lease lease;
        try{lease=Acquire(root,end,phase);}catch(Exception failure){failure.Data["PublicationDestination"]=Relative(root,destination);throw;}
        Exception first=null;LocalControl parentAnchors=null;
        try {
            string parentDirectory=Path.GetDirectoryName(destination);
            parentAnchors=LocalControl.RetainExisting(parentDirectory,parentDirectory,end);
            if(contract!=null)contract.Publication(destination,temporary,raw);
            if(File.Exists(destination))throw Fault(root,destination,"CREATE_NEW_DESTINATION_EXISTS",phase,"NOT_ENUMERATED",false,80);
            Func<Census> capture=()=>contract==null?Capture(root,lease,Discover(root,phase),false,phase):RuntimeScratch.Capture(root,lease,false,phase,end,contract);
            var before=capture();
            // Existing bounded control/failure reserve plus one maximum publisher.
            // Physical reserve is provisional; actual allocation is mandatory after close.
            Budget(before,98304+cap,196608+2L*cap+65536,1);
            stage="CREATE_AND_FLUSH_TEMP";
            using(var stream=new FileStream(temporary,FileMode.CreateNew,FileAccess.Write,FileShare.None)) {Trace("TEMP_WRITER_OPEN",temporary,"handle=0x"+stream.SafeFileHandle.DangerousGetHandle().ToInt64().ToString("x")+";access=WRITE;share=NONE;mode=CREATE_NEW");stream.Write(raw,0,raw.Length);stream.Flush(true);}
            Trace("TEMP_WRITER_CLOSED",temporary,"using Dispose completed after Flush(true)");
            if(contract!=null)contract.Mark(temporary,true);
            stage="TEMP_CLOSED_CENSUS";var temporaryCensus=capture();Budget(temporaryCensus,98304,196608);
            var expectedTemporary=temporaryCensus.entries.Single(e=>e.path==Relative(root,temporary));
            stage="ATOMIC_CREATE_NEW_RENAME";Trace("BEFORE_RENAME",temporary,"destination="+destination+";overwrite=false");RenameSameParent(root,temporary,destination,expectedTemporary,raw,parentAnchors,end);
            Trace("RENAME_COMMITTED",destination,"same-parent source-handle rename; overwrite=false");
            if(contract!=null){contract.Mark(temporary,false);contract.Mark(destination,true);}
            stage="READBACK";
            if(!File.ReadAllBytes(destination).SequenceEqual(raw))throw Fault(root,destination,"CLOSED_READBACK",phase,before.snapshot_sha256,true,null);
            stage="FINAL_PUBLISHED_CENSUS";Budget(capture(),98304,196608);
        }catch(Exception e){first=e;if(!e.Data.Contains("StorageDiagnosticJson"))first=Fault(root,stage=="CREATE_AND_FLUSH_TEMP"?temporary:destination,stage,phase,"NOT_RETAINED",false,Win32(e),e);first.Data["PublicationStage"]=stage;Trace("PUBLICATION_FAILURE",destination,"stage="+stage+";message="+first.Message);throw first;}
        finally{
            Exception cleanup=null;
            foreach(IDisposable owned in new IDisposable[]{lease,parentAnchors})if(owned!=null)try{owned.Dispose();}catch(Exception e){if(first!=null)Secondary(first,e);else if(cleanup==null)cleanup=e;else Secondary(cleanup,e);}
            if(first==null&&cleanup!=null)throw cleanup;
        }
    }
}
