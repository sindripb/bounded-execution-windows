// Local metadata publication bootstrap only. No process, Job, retry or cloud exceptions.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

public sealed class LocalControl : IDisposable {
    [StructLayout(LayoutKind.Sequential)] struct FT { public uint low,high; }
    [StructLayout(LayoutKind.Sequential)] struct Info {
        public uint attributes; public FT created,accessed,written;
        public uint volume,sizeHigh,sizeLow,links,idHigh,idLow;
    }
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern bool CreateDirectoryW(string path,IntPtr security);
    [DllImport("kernel32",SetLastError=true)]
    static extern bool GetFileInformationByHandle(IntPtr handle,out Info info);
    [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern uint GetFinalPathNameByHandleW(IntPtr handle,StringBuilder path,uint capacity,uint flags);
    sealed class Anchor { public string path,identity; public IntPtr handle; }
    readonly List<Anchor> anchors=new List<Anchor>();
    readonly string root;
    readonly long end;
    bool closed;
    LocalControl(string directory,long absoluteEnd) { root=directory;end=absoluteEnd; }
    void Deadline() { if(end<=0||Stopwatch.GetTimestamp()>=end)throw new IOException("LocalControl:AbsoluteDeadline"); }
    static IOException Failure(string operation) {
        return new IOException("LocalControl:"+operation+":"+Marshal.GetLastWin32Error());
    }
    static string Inspect(string path,IntPtr handle) {
        Info info;
        if(!GetFileInformationByHandle(handle,out info))throw Failure("DirectoryMetadata");
        if((info.attributes&0x10)==0||(info.attributes&0x400)!=0)throw new IOException("LocalControl:UnsafeDirectory");
        var buffer=new StringBuilder(1024);
        uint length=GetFinalPathNameByHandleW(handle,buffer,(uint)buffer.Capacity,0);
        if(length==0||length>=buffer.Capacity)throw Failure("FinalPathUnavailable");
        string expected="\\\\?\\"+Path.GetFullPath(path).TrimEnd('\\');
        if(!string.Equals(buffer.ToString().TrimEnd('\\'),expected,StringComparison.OrdinalIgnoreCase))
            throw new IOException("LocalControl:ResolvedPathMismatch");
        return info.volume+":"+info.idHigh+":"+info.idLow+":"+info.created.high+":"+info.created.low;
    }
    void Hold(string path) {
        Deadline();
        // No write/delete sharing. OPEN_REPARSE_POINT + BACKUP_SEMANTICS: inspect directory itself.
        IntPtr handle=LiveStorage.CreateFileW(path,0x80000080,1,IntPtr.Zero,3,0x02200000,IntPtr.Zero);
        if(handle==new IntPtr(-1))throw Failure("OpenDirectory");
        var anchor=new Anchor{path=path,handle=handle};anchors.Add(anchor);
        anchor.identity=Inspect(path,handle);
    }
    // Retain an existing publication parent without creating another control namespace.
    public static LocalControl RetainExisting(string directory,string expectedDirectory,long absoluteEnd) {
        string full=Path.GetFullPath(directory);
        if(full!=expectedDirectory||full.StartsWith("\\\\",StringComparison.Ordinal)||full.Length>240)
            throw new IOException("LocalControl:ExactLocalPathBinding");
        if(new DriveInfo(Path.GetPathRoot(full)).DriveFormat!="NTFS")throw new IOException("LocalControl:LocalNTFSRequired");
        var lease=new LocalControl(full,absoluteEnd);
        try {
            var chain=new Stack<string>();
            for(var d=new DirectoryInfo(full);d!=null;d=d.Parent)chain.Push(d.FullName);
            while(chain.Count>0)lease.Hold(chain.Pop());
            lease.Validate();return lease;
        } catch(Exception first) {
            try{lease.Dispose();}catch(Exception secondary){LiveStorage.Secondary(first,secondary);}throw;
        }
    }
    public static LocalControl Initialize(string directory,string expectedDirectory,long absoluteEnd) {
        var lease=RetainExisting(directory,expectedDirectory,absoluteEnd);
        try {
            string full=Path.GetFullPath(directory);
            string control=Path.Combine(full,"control");
            // Single final component, fail if any object already occupies this fresh namespace.
            if(!CreateDirectoryW(control,IntPtr.Zero))throw Failure("CreateFreshControl");
            lease.Hold(control);lease.Validate();return lease;
        } catch(Exception first) {
            try{lease.Dispose();}catch(Exception secondary){LiveStorage.Secondary(first,secondary);}throw;
        }
    }
    public void Validate() {
        Deadline();if(closed)throw new IOException("LocalControl:ClosedAnchor");
        foreach(var anchor in anchors) {
            if(Inspect(anchor.path,anchor.handle)!=anchor.identity)throw new IOException("LocalControl:ChangedDirectoryIdentity");
            var attributes=File.GetAttributes(anchor.path);
            if((attributes&FileAttributes.Directory)==0||(attributes&FileAttributes.ReparsePoint)!=0)
                throw new IOException("LocalControl:UnsafeDirectory");
        }
    }
    // Diagnostic observation only: original access/share flags and lifetimes are unchanged.
    public string DiagnosticState() {
        Validate();
        var rows=new List<object>();
        foreach(var anchor in anchors)rows.Add(new {
            path=anchor.path,handle="0x"+anchor.handle.ToInt64().ToString("x"),
            desired_access="0x80000080",share_mode="0x00000001",flags="0x02200000",
            original_identity=anchor.identity,current_identity=Inspect(anchor.path,anchor.handle)
        });
        return System.Text.Json.JsonSerializer.Serialize(rows);
    }
    public void Dispose() {
        if(closed)return;closed=true;Exception first=null;
        for(int n=anchors.Count-1;n>=0;n--)if(!LiveStorage.CloseHandle(anchors[n].handle)) {
            var failure=Failure("CloseDirectory");if(first==null)first=failure;else LiveStorage.Secondary(first,failure);
        }
        if(first!=null)throw first;
    }
}
