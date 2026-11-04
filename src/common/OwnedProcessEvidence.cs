// Read the exact original process handle, including after exit. Never reopen by PID.
// https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getprocessmemoryinfo
using System;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class OwnedProcessEvidence {
    [StructLayout(LayoutKind.Sequential)] struct Memory {
        public uint cb,faults;
        public UIntPtr peakWorking,working,peakPaged,paged,peakNonpaged,nonpaged,pagefile,peakPagefile,privateBytes;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool K32GetProcessMemoryInfo(SafeProcessHandle h,ref Memory value,uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(SafeProcessHandle h,out ulong created,out ulong exited,out ulong kernel,out ulong user);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetProcessId(SafeProcessHandle h);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetExitCodeProcess(SafeProcessHandle h,out uint code);
    [DllImport("kernel32.dll",SetLastError=true)] static extern uint WaitForSingleObject(SafeProcessHandle h,uint milliseconds);
    public sealed class Sample {
        public uint pid,exit_code;public ulong creation_filetime,exit_filetime,peak_working_set_bytes,working_set_bytes,private_bytes;
        public double CPU_seconds;public bool exited;
    }
    static void Need(bool condition,string why){if(!condition)throw new IOException("OwnedProcess:"+why+":"+Marshal.GetLastWin32Error());}
    public static Sample Read(SafeProcessHandle handle) {
        Need(IntPtr.Size==8&&!handle.IsClosed&&!handle.IsInvalid,"OriginalHandleRequired");
        uint size=(uint)Marshal.SizeOf<Memory>();Need(size==80,"MemoryLayout");
        var memory=new Memory{cb=size};
        Need(K32GetProcessMemoryInfo(handle,ref memory,size),"MemoryInformation");
        ulong created,exited,kernel,user;Need(GetProcessTimes(handle,out created,out exited,out kernel,out user),"ProcessTimes");
        uint pid=GetProcessId(handle),code;Need(pid!=0,"ProcessIdentity");Need(GetExitCodeProcess(handle,out code),"ExitCode");
        uint wait=WaitForSingleObject(handle,0);Need(wait==0||wait==258,"WaitState");
        Need(memory.peakWorking.ToUInt64()>0,"MissingPeakMemory");
        return new Sample{pid=pid,creation_filetime=created,exit_filetime=wait==0?exited:0,CPU_seconds=(kernel+user)/10000000.0,
            peak_working_set_bytes=memory.peakWorking.ToUInt64(),working_set_bytes=memory.working.ToUInt64(),private_bytes=memory.privateBytes.ToUInt64(),exited=wait==0,exit_code=code};
    }
}
