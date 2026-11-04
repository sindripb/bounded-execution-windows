// Fixed host-boundary interop. Loading this type does not call a native API.
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

public static class CapacityHostNative {
    [StructLayout(LayoutKind.Sequential)] public struct Basic {
        public long process_time, job_time; public uint flags;
        public UIntPtr min_ws, max_ws; public uint active;
        public UIntPtr affinity; public uint priority, scheduling;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Io {
        public ulong reads,writes,other,read_bytes,write_bytes,other_bytes;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Extended {
        public Basic basic; public Io io;
        public UIntPtr process_memory,job_memory,peak_process,peak_job;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Accounting {
        public long user,kernel,period_user,period_kernel;
        public uint faults,total,active,terminated;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Times {
        public long creation,exit,kernel,user;
        public long Combined { get { return checked(user+kernel); } }
    }
    [StructLayout(LayoutKind.Sequential)] public struct Pids {
        public uint assigned,listed;
        [MarshalAs(UnmanagedType.ByValArray,SizeConst=32)] public UIntPtr[] ids;
    }
    [StructLayout(LayoutKind.Sequential)] public struct Standard {
        public long allocation,end; public uint links; public byte pending,directory;
    }
    [StructLayout(LayoutKind.Sequential)] public struct FileTime { public uint low,high; public ulong Value {get{return ((ulong)high<<32)|low;}} }
    [StructLayout(LayoutKind.Sequential)] public struct FileIdentity {
        public uint attributes; public FileTime created,accessed,written;
        public uint volume,size_high,size_low,links,index_high,index_low;
    }
    public sealed class ClosedFileInfo {
        public long bytes,allocated_bytes; public uint volume;
        public ulong file_id,creation_filetime,write_filetime; public string sha256="";
    }
    [DllImport("kernel32",SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr a,IntPtr n);
    [DllImport("kernel32",SetLastError=true)] static extern bool SetInformationJobObject(IntPtr j,int c,ref Extended x,uint n);
    [DllImport("kernel32",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int c,out Accounting x,uint n,IntPtr r);
    [DllImport("kernel32",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int c,out Extended x,uint n,IntPtr r);
    [DllImport("kernel32",SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr j,int c,ref Pids x,uint n,IntPtr r);
    [DllImport("kernel32",SetLastError=true)] static extern bool AssignProcessToJobObject(IntPtr j,IntPtr p);
    [DllImport("kernel32",SetLastError=true)] static extern bool IsProcessInJob(IntPtr p,IntPtr j,out bool result);
    [DllImport("kernel32",SetLastError=true)] static extern bool GetProcessTimes(IntPtr p,out long c,out long e,out long k,out long u);
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageNameW(IntPtr p,uint f,StringBuilder b,ref uint n);
    [DllImport("kernel32",SetLastError=true)] static extern bool DuplicateHandle(IntPtr s,IntPtr h,IntPtr t,out IntPtr d,uint a,bool i,uint o);
    [DllImport("kernel32",SetLastError=true)] static extern IntPtr OpenProcess(uint a,bool i,uint p);
    [DllImport("kernel32")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint t);
    [DllImport("kernel32",SetLastError=true)] static extern bool TerminateJobObject(IntPtr j,uint e);
    [DllImport("kernel32",SetLastError=true)] static extern bool TerminateProcess(IntPtr p,uint e);
    [DllImport("kernel32",SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr p,out uint e);
    [DllImport("kernel32",SetLastError=true)] static extern bool PeekNamedPipe(IntPtr p,IntPtr b,uint s,IntPtr r,out uint a,IntPtr l);
    [DllImport("kernel32",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string p,uint a,uint s,IntPtr z,uint d,uint f,IntPtr t);
    [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr h,int c,out Standard x,uint n);
    [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out FileIdentity x);
    static void Need(bool b,string s) { if(!b) throw new IOException(s+":"+Marshal.GetLastWin32Error()); }
    public static IntPtr Job(int processUserSeconds,int jobUserSeconds) {
        IntPtr h=CreateJobObjectW(IntPtr.Zero,IntPtr.Zero); Need(h!=IntPtr.Zero,"CreateJob");
        try {
            Extended x=new Extended(); x.basic.flags=0x2|0x4|0x100|0x200|0x2000;
            x.basic.process_time=checked((long)processUserSeconds*10000000);
            x.basic.job_time=checked((long)jobUserSeconds*10000000);
            x.process_memory=new UIntPtr(536870912); x.job_memory=new UIntPtr(536870912);
            Need(SetInformationJobObject(h,9,ref x,(uint)Marshal.SizeOf<Extended>()),"SetJob");
            // No breakaway, named handle, reset, or inherited ownership handle.
            return h;
        } catch { CloseHandle(h); throw; }
    }
    public static void Assign(IntPtr j,IntPtr p) { Need(AssignProcessToJobObject(j,p),"AssignJob"); }
    public static bool Member(IntPtr p,IntPtr j) { bool v; Need(IsProcessInJob(p,j,out v),"JobMembership"); return v; }
    public static Accounting Cpu(IntPtr j) { Accounting x; Need(QueryInformationJobObject(j,1,out x,(uint)Marshal.SizeOf<Accounting>(),IntPtr.Zero),"JobCpu");return x; }
    public static Extended Limits(IntPtr j) { Extended x; Need(QueryInformationJobObject(j,9,out x,(uint)Marshal.SizeOf<Extended>(),IntPtr.Zero),"JobMemory");return x; }
    public static ulong[] Members(IntPtr j) {
        Pids x=new Pids(); x.ids=new UIntPtr[32];
        Need(QueryInformationJobObject(j,3,ref x,(uint)Marshal.SizeOf<Pids>(),IntPtr.Zero),"JobPids");
        Need(x.assigned==x.listed && x.listed<=32,"IncompleteJobPids");
        ulong[] v=new ulong[x.listed]; for(int i=0;i<v.Length;i++)v[i]=x.ids[i].ToUInt64(); return v;
    }
    public static Times Time(IntPtr p) {
        Times x=new Times(); Need(GetProcessTimes(p,out x.creation,out x.exit,out x.kernel,out x.user),"ProcessTimes");return x;
    }
    public static string Image(IntPtr p) {
        StringBuilder b=new StringBuilder(32768); uint n=32768;
        Need(QueryFullProcessImageNameW(p,0,b,ref n),"ProcessImage"); return b.ToString();
    }
    // Only process handles and inner Job QUERY handles may be exported.
    // The campaign ownership handle NEVER calls this function.
    public static long Export(IntPtr h,uint target,uint rights) {
        IntPtr t=OpenProcess(0x40,false,target); Need(t!=IntPtr.Zero,"TargetDuplicateProcess");
        try { IntPtr d; Need(DuplicateHandle(GetCurrentProcess(),h,t,out d,rights,false,0),"DuplicateHeldHandle");return d.ToInt64(); }
        finally { CloseHandle(t); }
    }
    public static IntPtr ObserveActive(uint pid) {
        IntPtr h=OpenProcess(0x101000,false,pid);
        Need(h!=IntPtr.Zero,"ForensicOpenProcess");return h;
    }
    public static bool Exited(IntPtr h) { uint v=WaitForSingleObject(h,0);Need(v==0||v==258,"ProcessWait");return v==0; }
    public static uint ExitCode(IntPtr h) { uint v;Need(GetExitCodeProcess(h,out v),"ExitCode");return v; }
    public static void KillJob(IntPtr j) { Need(TerminateJobObject(j,124),"TerminateCampaignJob"); }
    public static void KillProcess(IntPtr p) { Need(TerminateProcess(p,125),"TerminateProcess"); }
    public static void Close(IntPtr h) { if(h!=IntPtr.Zero)Need(CloseHandle(h),"CloseHandle"); }
    public static byte[] Read(Stream s,IntPtr pipe,int cap,long end,long hz,Action check) {
        using(var result=new MemoryStream()) {
            while(true) {
                check(); uint n;
                if(!PeekNamedPipe(pipe,IntPtr.Zero,0,IntPtr.Zero,out n,IntPtr.Zero)) {
                    int e=Marshal.GetLastWin32Error(); if(e==109||e==232)return result.ToArray();
                    throw new IOException("PeekPipe:"+e);
                }
                if(n>0) {
                    int count=(int)Math.Min(n,(uint)(cap+1-result.Length));
                    byte[] b=new byte[count]; int got=s.Read(b,0,b.Length);
                    if(got==0)return result.ToArray(); result.Write(b,0,got);
                    if(result.Length>cap)throw new IOException("BoundedPipeExceeded");
                } else { if(Stopwatch.GetTimestamp()>=end)throw new TimeoutException("PipeDeadline");Thread.Sleep(10); }
            }
        }
    }
    public static IntPtr PipeHandle(Stream s) {
        if(s is PipeStream)return ((PipeStream)s).SafePipeHandle.DangerousGetHandle();
        if(s is FileStream)return ((FileStream)s).SafeFileHandle.DangerousGetHandle();
        throw new IOException("UnknownPipeStreamType");
    }
    // V009: expose the existing bounded peek for a single READY stream owner.
    // No creation, handle inheritance, Job or detached-adapter change.
    public static uint Available(Stream stream,out bool eof) {
        uint count;
        if(PeekNamedPipe(PipeHandle(stream),IntPtr.Zero,0,IntPtr.Zero,out count,IntPtr.Zero)) { eof=false;return count; }
        int error=Marshal.GetLastWin32Error();
        if(error==109||error==232) { eof=true;return 0; }
        throw new IOException("PeekPipe:"+error);
    }
    public static long Allocation(string path,long length) {
        IntPtr h=CreateFileW(path,0x80,1,IntPtr.Zero,3,0,IntPtr.Zero);Need(h!=new IntPtr(-1),"FileAllocationHandle");
        try {Standard x;Need(GetFileInformationByHandleEx(h,1,out x,(uint)Marshal.SizeOf<Standard>())&&x.end==length&&x.allocation>=0,"FileAllocation");return x.allocation;}
        finally {CloseHandle(h);}
    }
    public static ClosedFileInfo ClosedFile(string path) {
        IntPtr h=CreateFileW(path,0x80000080,0,IntPtr.Zero,3,0x200000,IntPtr.Zero);
        Need(h!=new IntPtr(-1),"ExclusiveClosedFile");
        try {
            Standard a=new Standard(),b=new Standard(); FileIdentity x=new FileIdentity(),y=new FileIdentity();
            Need(GetFileInformationByHandleEx(h,1,out a,(uint)Marshal.SizeOf<Standard>())&&GetFileInformationByHandle(h,out x),"ClosedMetadata");
            Need(a.allocation>=0&&a.end>=0&&a.directory==0&&(x.attributes&0x400)==0,"UnsafeClosedFile");
            string hash;
            using(var s=new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(h,false),FileAccess.Read))
                hash=Convert.ToHexString(SHA256.HashData(s)).ToLowerInvariant();
            Need(GetFileInformationByHandleEx(h,1,out b,(uint)Marshal.SizeOf<Standard>())&&GetFileInformationByHandle(h,out y),"ClosedMetadataAfter");
            Need(a.end==b.end&&a.allocation==b.allocation&&x.volume==y.volume&&x.index_high==y.index_high&&x.index_low==y.index_low&&x.created.Value==y.created.Value&&x.written.Value==y.written.Value,"FileChangedDuringReadback");
            return new ClosedFileInfo{bytes=a.end,allocated_bytes=a.allocation,volume=x.volume,
                file_id=((ulong)x.index_high<<32)|x.index_low,creation_filetime=x.created.Value,write_filetime=x.written.Value,sha256=hash};
        } finally {CloseHandle(h);}
    }

    // C -> P adaptation of accepted Popen(DETACHED_PROCESS, binary PIPEs,
    // close_fds=True). No helper process, console API, breakaway or new Job.
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
        public uint cb; public IntPtr reserved,desktop,title;
        public uint x,y,xsize,ysize,xchars,ychars,fill,flags;
        public ushort show,reservedBytes; public IntPtr reserved2,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct StartupEx {
        public Startup startup; public IntPtr attributes;
    }
    [StructLayout(LayoutKind.Sequential)] struct CreatedProcess {
        public IntPtr process,thread; public uint pid,tid;
    }
    [DllImport("kernel32",SetLastError=true)] static extern bool GetHandleInformation(IntPtr h,out uint flags);
    [DllImport("kernel32",SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr p,int count,uint flags,ref UIntPtr bytes);
    [DllImport("kernel32",SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr p,uint flags,UIntPtr key,IntPtr value,UIntPtr bytes,IntPtr previous,IntPtr returned);
    [DllImport("kernel32")] static extern void DeleteProcThreadAttributeList(IntPtr p);
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true,ExactSpelling=true)]
    static extern bool CreateProcessW(string application,StringBuilder command,IntPtr processSecurity,IntPtr threadSecurity,
        bool inherit,uint flags,IntPtr environment,string cwd,ref StartupEx startup,out CreatedProcess result);

    static string QuoteArgument(string value) {
        if(value==null || value.IndexOf('\0')>=0)throw new IOException("InvalidDetachedArgument");
        var text=new StringBuilder("\"");int slashes=0;
        foreach(char c in value) {
            if(c=='\\'){slashes++;continue;}
            text.Append('\\',c=='\"'?2*slashes+1:slashes);text.Append(c);slashes=0;
        }
        text.Append('\\',2*slashes);return text.Append('"').ToString();
    }
    static string DetachedEnvironment(string cwd) {
        var values=new System.Collections.Generic.SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach(System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
            values[(string)entry.Key]=(string)entry.Value;
        values["DOTNET_TieredCompilation"]="0";values.Remove("COMPlus_TieredCompilation");
        string temporary=Path.Combine(cwd,"control","temporary");Directory.CreateDirectory(temporary);
        foreach(string name in new[]{"TEMP","TMP","TMPDIR"})values[name]=temporary;
        var block=new StringBuilder();
        foreach(var entry in values){
            if(entry.Key.IndexOf('\0')>=0||entry.Value.IndexOf('\0')>=0)throw new IOException("InvalidEnvironmentNul");
            block.Append(entry.Key).Append('=').Append(entry.Value).Append('\0');
        }
        return block.Append('\0').ToString();
    }
    public sealed class BinaryEndpoint {
        public Stream BaseStream {get;private set;}
        public BinaryEndpoint(Stream stream){BaseStream=stream;}
        public void Close(){BaseStream.Dispose();}
    }
    public sealed class DetachedChild : IDisposable {
        public IntPtr Handle {get;private set;}
        public int Id {get;private set;}
        public BinaryEndpoint StandardInput {get;private set;}
        public BinaryEndpoint StandardOutput {get;private set;}
        public BinaryEndpoint StandardError {get;private set;}
        public string CommandLine {get;private set;}
        // Same effective kernel flags as CPython _winapi: detached + Unicode + extended startup.
        public const uint NativeCreationFlags=0x00000008|0x00000400|0x00080000;
        public uint CreationFlags {get{return NativeCreationFlags;}}
        public int InheritedHandleCount {get{return 3;}}
        readonly System.Collections.Generic.List<string> setupFailures=new System.Collections.Generic.List<string>();
        public string[] SetupFailures {get{return setupFailures.ToArray();}}
        public bool HasExited {get{return Exited(Handle);}}
        public int ExitCode {get{return checked((int)CapacityHostNative.ExitCode(Handle));}}
        public bool WaitForExit(int milliseconds) {
            if(milliseconds<0)throw new IOException("UnboundedDetachedWait");
            uint answer=WaitForSingleObject(Handle,(uint)milliseconds);
            Need(answer==0||answer==258,"DetachedWait");return answer==0;
        }
        public void Kill(){if(!HasExited)KillProcess(Handle);}
        void CloseEndpoint(BinaryEndpoint value) {
            if(value==null)return;try{value.Close();}catch(Exception e){setupFailures.Add("PipeClose:"+e.Message);}
        }
        public void Dispose() {
            int before=setupFailures.Count;
            CloseEndpoint(StandardInput);CloseEndpoint(StandardOutput);CloseEndpoint(StandardError);
            if(Handle!=IntPtr.Zero){IntPtr held=Handle;Handle=IntPtr.Zero;try{Close(held);}catch(Exception e){setupFailures.Add(e.Message);}}
            if(setupFailures.Count!=before)throw new IOException(string.Join(";",setupFailures.GetRange(before,setupFailures.Count-before)));
        }
        public static DetachedChild Start(string image,string[] arguments,string cwd) {
            if(IntPtr.Size!=8||!Path.IsPathFullyQualified(image)||!Path.IsPathFullyQualified(cwd))throw new IOException("DetachedAbsoluteX64Contract");
            var child=new DetachedChild();var command=new StringBuilder(QuoteArgument(image));
            foreach(string arg in arguments)command.Append(' ').Append(QuoteArgument(arg));
            if(command.Length>=32767)throw new IOException("DetachedCommandCap");
            child.CommandLine=command.ToString();
            AnonymousPipeServerStream input=null,output=null,error=null;
            IntPtr attribute=IntPtr.Zero,handles=IntPtr.Zero,environment=IntPtr.Zero;
            bool initialized=false,created=false;CreatedProcess info=new CreatedProcess();
            try {
                input=new AnonymousPipeServerStream(PipeDirection.Out,HandleInheritability.Inheritable);
                child.StandardInput=new BinaryEndpoint(input);
                output=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable);
                child.StandardOutput=new BinaryEndpoint(output);
                error=new AnonymousPipeServerStream(PipeDirection.In,HandleInheritability.Inheritable);
                child.StandardError=new BinaryEndpoint(error);
                var server=new[]{input,output,error};var inherit=new IntPtr[3];
                for(int i=0;i<3;i++) {
                    inherit[i]=server[i].ClientSafePipeHandle.DangerousGetHandle();uint a,b;
                    Need(GetHandleInformation(inherit[i],out a)&&(a&1)==1,"ChildPipeInheritance");
                    Need(GetHandleInformation(server[i].SafePipeHandle.DangerousGetHandle(),out b)&&(b&1)==0,"ParentPipeNotInherited");
                }
                UIntPtr size=UIntPtr.Zero;bool first=InitializeProcThreadAttributeList(IntPtr.Zero,1,0,ref size);
                Need(!first&&Marshal.GetLastWin32Error()==122&&size.ToUInt64()>0,"AttributeListSize");
                attribute=Marshal.AllocHGlobal(checked((int)size.ToUInt64()));
                Need(InitializeProcThreadAttributeList(attribute,1,0,ref size),"AttributeListInit");initialized=true;
                handles=Marshal.AllocHGlobal(3*IntPtr.Size);Marshal.Copy(inherit,0,handles,3);
                Need(UpdateProcThreadAttribute(attribute,0,new UIntPtr(0x00020002),handles,new UIntPtr((uint)(3*IntPtr.Size)),IntPtr.Zero,IntPtr.Zero),"ExactThreePipeHandles");
                environment=Marshal.StringToHGlobalUni(DetachedEnvironment(cwd));
                StartupEx startup=new StartupEx();startup.startup.cb=(uint)Marshal.SizeOf<StartupEx>();
                startup.startup.flags=0x100;startup.startup.input=inherit[0];startup.startup.output=inherit[1];startup.startup.error=inherit[2];startup.attributes=attribute;
                // Only these three pipe handles are inherited. No Job ownership,
                // QUERY, process or observer handle can enter the list.
                Need(CreateProcessW(image,command,IntPtr.Zero,IntPtr.Zero,true,NativeCreationFlags,environment,cwd,ref startup,out info),"DetachedCreateProcessW");
                // Capture the ORIGINAL returned process handle before any publication.
                child.Handle=info.process;created=true;child.Id=unchecked((int)info.pid);
                if(info.pid>int.MaxValue)child.setupFailures.Add("PIDOutsideAcceptedInt32");
            } catch(Exception original) {
                if(!created){
                    child.CloseEndpoint(child.StandardInput);child.CloseEndpoint(child.StandardOutput);child.CloseEndpoint(child.StandardError);
                    original.Data["precreation_cleanup_errors"]=child.SetupFailures;
                }
                throw;
            } finally {
                if(initialized)DeleteProcThreadAttributeList(attribute);
                if(attribute!=IntPtr.Zero)Marshal.FreeHGlobal(attribute);
                if(handles!=IntPtr.Zero)Marshal.FreeHGlobal(handles);
                if(environment!=IntPtr.Zero)Marshal.FreeHGlobal(environment);
            }
            // After successful creation NEVER throw away the only original handle.
            // Caller registers this returned object before rejecting setup errors.
            try{Close(info.thread);}catch(Exception e){child.setupFailures.Add("PrimaryThreadClose:"+e.Message);}
            foreach(var pipe in new[]{input,output,error}){
                try{pipe.DisposeLocalCopyOfClientHandle();}catch(Exception e){child.setupFailures.Add("ChildPipeLocalClose:"+e.Message);}
            }
            return child;
        }
    }
}

// Additional trusted polling only. Original CapacityHostNative bytes precede it.
// No creation, handle export/closure, limit change, or publication is performed.
public static class FinancialPolling {
    static void Require(bool value,string code){if(!value)throw new IOException(code);}
    public static void Resource(CapacityHostNative.Accounting a,CapacityHostNative.Extended m){
        Require(a.user>=0&&a.kernel>=0&&checked(a.user+a.kernel)<164800000000,"CampaignResourceStop");
        Require(a.terminated==0&&m.basic.flags==8966&&m.basic.job_time==200000000000&&m.basic.process_time==80000000000&&
            m.peak_job.ToUInt64()<=536870912&&m.job_memory.ToUInt64()==536870912&&m.process_memory.ToUInt64()==536870912,"CampaignResourceStop");
    }
    [DllImport("kernel32",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h,uint milliseconds);
    public static int StableCampaign(IntPtr job,IntPtr controller,IntPtr[] handles,long[] created,ulong[] pids,bool[] isController,uint total,long deadline,long outsideCaptured,IntPtr pythonJob,IntPtr archiveJob){
        Require(handles.Length==created.Length&&created.Length==pids.Length&&pids.Length==isController.Length,"PollingOriginalHandles");
        int polls=0;using var self=Process.GetCurrentProcess();
        while(true){
            Require(Stopwatch.GetTimestamp()<deadline,"OwnerAbsoluteSoftDeadline");
            var a=CapacityHostNative.Cpu(job);Resource(a,CapacityHostNative.Limits(job));
            var active=JobMembership.Members(job);polls++;
            long outside=checked(CapacityHostNative.Time(self.Handle).Combined+outsideCaptured);
            if(pythonJob!=IntPtr.Zero)Require(CapacityHostNative.Cpu(pythonJob).user+CapacityHostNative.Cpu(pythonJob).kernel<160000000000,"PythonCombinedStop");
            if(archiveJob!=IntPtr.Zero)Require(CapacityHostNative.Cpu(archiveJob).user+CapacityHostNative.Cpu(archiveJob).kernel<80000000000,"ArchiveCombinedStop");
            if(a.total!=total||a.active!=active.Length||active.Length!=handles.Length)return polls;
            foreach(ulong pid in active)if(Array.IndexOf(pids,pid)<0)return polls;
            for(int i=0;i<handles.Length;i++){
                var t=CapacityHostNative.Time(handles[i]);
                Require(t.creation==created[i],"LiveCreationIdentity");
                Require(CapacityHostNative.Member(handles[i],job),"LiveCampaignMembership");
                if(isController[i])outside=checked(outside+t.Combined);else Require(t.Combined<80000000000,"PythonRoleCpuStop");
                if(CapacityHostNative.Exited(handles[i]))return polls;
            }
            Require(outside<3600000000,"OutsideCpuWithDriverReserve");
            // Original O wait interval is ten milliseconds, C's is twenty.
            uint result=WaitForSingleObject(controller,10);Require(result==0||result==258,"OriginalControllerWait");
            if(result==0)return polls;
        }
    }
    public static int ControllerChild(IntPtr child,long deadline,string cancel){
        int polls=0;
        using(var self=Process.GetCurrentProcess()){
            while(!CapacityHostNative.Exited(child)){
                Require(!File.Exists(cancel),"INJECTED_DEADLINE");
                Require(Stopwatch.GetTimestamp()<deadline,"ControllerAbsoluteDeadline");
                Require(CapacityHostNative.Time(self.Handle).Combined<1800000000,"ControllerCpuStop");
                uint result=WaitForSingleObject(child,20);Require(result==0||result==258,"OriginalChildWait");polls++;
            }
        }
        return polls;
    }
    public static void InventedChecks(){
        for(int test=0;test<9;test++){
            var a=new CapacityHostNative.Accounting{user=100,kernel=200};
            var m=new CapacityHostNative.Extended();m.basic.flags=8966;m.basic.job_time=200000000000;m.basic.process_time=80000000000;
            m.job_memory=new UIntPtr(536870912);m.process_memory=new UIntPtr(536870912);m.peak_job=new UIntPtr(100);
            switch(test){case 1:a.user=-1;break;case 2:a.user=164800000000-a.kernel;break;case 3:a.terminated=1;break;case 4:m.basic.flags=0;break;case 5:m.basic.job_time++;break;case 6:m.basic.process_time++;break;case 7:m.peak_job=new UIntPtr(536870913);break;case 8:m.job_memory=new UIntPtr(536870913);break;}
            bool rejected=false;try{Resource(a,m);}catch(IOException){rejected=true;}
            Require(rejected==(test!=0),"NativePollingPredicateRegression:"+test);
        }
    }
}

// Query-only adapter. It never admits an incomplete PID list or opens a process.
public static class JobMembership {
    public sealed class Query {
        public bool success; public int error,capacity; public uint assigned,listed;
        public ulong[] ids=System.Array.Empty<ulong>();
    }
    [System.Runtime.InteropServices.DllImport("kernel32",SetLastError=true)]
    static extern bool QueryInformationJobObject(System.IntPtr job,int kind,System.IntPtr buffer,uint bytes,System.IntPtr returned);
    public static readonly System.Collections.Generic.List<string> Observations=new System.Collections.Generic.List<string>();
    static Query Native(System.IntPtr job,int capacity) {
        int bytes=checked(8+capacity*System.IntPtr.Size);
        var buffer=System.Runtime.InteropServices.Marshal.AllocHGlobal(bytes);
        try {
            System.Runtime.InteropServices.Marshal.Copy(new byte[bytes],0,buffer,bytes);
            bool ok=QueryInformationJobObject(job,3,buffer,(uint)bytes,System.IntPtr.Zero);
            int error=ok?0:System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            var q=new Query{success=ok,error=error,capacity=capacity,
                assigned=unchecked((uint)System.Runtime.InteropServices.Marshal.ReadInt32(buffer)),
                listed=unchecked((uint)System.Runtime.InteropServices.Marshal.ReadInt32(buffer,4))};
            if(q.listed<=(uint)capacity){q.ids=new ulong[q.listed];for(int n=0;n<q.ids.Length;n++)
                q.ids[n]=unchecked((ulong)System.Runtime.InteropServices.Marshal.ReadIntPtr(buffer,8+n*System.IntPtr.Size).ToInt64());}
            return q;
        } finally {System.Runtime.InteropServices.Marshal.FreeHGlobal(buffer);}
    }
    public static ulong[] Read(System.Func<int,Query> query,System.Action<string> observe) {
        string detail="";
        for(int attempt=0;attempt<3;attempt++) {
            int capacity=32<<attempt;var q=query(capacity);
            detail="attempt="+attempt+",capacity="+capacity+",success="+q.success+",error="+q.error+",assigned="+q.assigned+",listed="+q.listed;
            if(q.capacity!=capacity||q.listed>(uint)capacity||q.assigned>128||q.ids.Length!=q.listed)
                throw new System.IO.IOException("InvalidJobPidQuery:"+detail);
            if(!q.success&&q.error!=234)throw new System.IO.IOException("JobPidQuery:"+detail);
            if(q.success&&q.assigned==q.listed) {
                var seen=new System.Collections.Generic.HashSet<ulong>();
                foreach(ulong id in q.ids)if(id==0||!seen.Add(id))throw new System.IO.IOException("InvalidJobPidIdentity:"+detail);
                if(attempt!=0)observe("COMPLETE:"+detail);
                return q.ids;
            }
            observe("INCOMPLETE_NOT_ACCEPTED:"+detail);
        }
        throw new System.IO.IOException("IncompleteJobPidsAfterThreeQueries:"+detail);
    }
    public static ulong[] Members(System.IntPtr job) {
        return Read(capacity=>Native(job,capacity),detail=>{
            if(Observations.Count>=12)throw new System.IO.IOException("JobMembershipObservationBound");
            Observations.Add("job="+job.ToInt64()+",qpc="+System.Diagnostics.Stopwatch.GetTimestamp()+","+detail);
        });
    }
    public static void InventedChecks() {
        for(int test=0;test<7;test++) {
            int calls=0;bool rejected=false;
            try {
                var result=Read(cap=>{
                    calls++;var q=new Query{success=true,capacity=cap,assigned=2,listed=2,ids=new ulong[]{41,42}};
                    if(test==1&&calls==1){q.assigned=3;}
                    if(test==2){q.assigned=3;}
                    if(test==3){q.success=false;q.error=6;}
                    if(test==4){q.ids[1]=41;}
                    if(test==5){q.ids[0]=0;}
                    if(test==6&&calls==1){q.success=false;q.error=234;q.assigned=33;}
                    return q;
                },detail=>{});
                if(result.Length!=2||result[0]!=41||result[1]!=42)throw new System.Exception("InventedReturnedList");
            }catch(System.IO.IOException){rejected=true;}
            if(rejected!=(test>=2&&test<=5)||calls>3||calls!=(test==2?3:test==1||test==6?2:1))
                throw new System.Exception("JobMembershipInventedCase:"+test);
        }
    }
}

// Read the existing two pipes while retaining the original child handle.
// No new process, Job, thread, inheritance, output allowance or financial policy.
public static class BoundedChildOutput {
    public sealed class Result { public string stdout,stderr; public int polls; }
    static bool Drain(Stream stream,MemoryStream output,byte[] buffer) {
        bool eof;uint available=CapacityHostNative.Available(stream,out eof);
        if(eof)return true;
        if(available>0) {
            int count=(int)Math.Min(available,(uint)Math.Min(buffer.Length,16385-output.Length));
            int got=stream.Read(buffer,0,count);
            if(got<=0)throw new IOException("UnexpectedPipeShortRead");
            output.Write(buffer,0,got);
            if(output.Length>16384)throw new IOException("BoundedPipeExceeded");
        }
        return false;
    }
    public static Result Read(Stream stdout,Stream stderr,Func<bool> exited,Action check,long deadline) {
        using(var output=new MemoryStream())using(var error=new MemoryStream()) {
            byte[] buffer=new byte[1024];bool outEof=false,errorEof=false;int polls=0;
            while(true) {
                check();
                if(Stopwatch.GetTimestamp()>=deadline)throw new IOException("ControllerAbsoluteDeadline");
                if(!outEof)outEof=Drain(stdout,output,buffer);
                if(!errorEof)errorEof=Drain(stderr,error,buffer);
                if(exited()&&outEof&&errorEof)return new Result{stdout=Encoding.UTF8.GetString(output.ToArray()),stderr=Encoding.UTF8.GetString(error.ToArray()),polls=polls};
                Thread.Sleep(20);polls++;
            }
        }
    }
    public static Result Capture(CapacityHostNative.DetachedChild child,long deadline,string cancel,long cpuLimit) {
        if(cpuLimit!=280000000&&cpuLimit!=1800000000)throw new IOException("ExactControllerCpuScope");
        using(var self=Process.GetCurrentProcess()) {
            Action check=()=>{
                if(File.Exists(cancel))throw new IOException("INJECTED_DEADLINE");
                if(CapacityHostNative.Time(self.Handle).Combined>=cpuLimit)throw new IOException("ControllerCpuStop");
            };
            return Read(child.StandardOutput.BaseStream,child.StandardError.BaseStream,()=>child.HasExited,check,deadline);
        }
    }
}
