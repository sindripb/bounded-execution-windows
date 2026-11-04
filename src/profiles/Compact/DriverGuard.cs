// The pre-export D polling predicates, using the same original handles/counters.
// Final inclusive reconciliation remains in the unchanged accounting.ps1.
using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
public static class DriverGuard {
    public sealed class Sample {
        public long user_100ns,kernel_100ns,combined_100ns,process_user_limit_100ns,job_user_limit_100ns;
        public uint total_processes,active_processes,terminated_processes,flags;
        public ulong peak_commit_bytes,job_memory_limit_bytes,process_memory_limit_bytes;
        public ulong[] active_pids=Array.Empty<ulong>();
    }
    public sealed class Result {public Sample snapshot;public string failure;public int polls;public double polling_cpu_seconds;}
    static void Need(bool ok,string why){if(!ok)throw new IOException(why);}
    public static string Evaluate(Sample s,long startupUser,long startupKernel,long heldUser,long heldKernel,bool bootstrap,int pid){
        Need(s.user_100ns>=0&&s.kernel_100ns>=0&&s.combined_100ns>=0&&checked(s.user_100ns+s.kernel_100ns)==s.combined_100ns,"HostCpuSum");
        Need(startupUser>=0&&startupKernel>=0,"StartupCpuSum");long startup=checked(startupUser+startupKernel);
        Need(heldUser>=0&&heldKernel>=0,"InclusiveHeldCpuSum");long held=checked(heldUser+heldKernel);
        Need(s.peak_commit_bytes<=long.MaxValue&&s.job_memory_limit_bytes<=long.MaxValue&&s.process_memory_limit_bytes<=long.MaxValue,"CounterRange");
        Need(s.flags==8966&&s.process_user_limit_100ns==300000000&&s.job_user_limit_100ns==1200000000&&s.job_memory_limit_bytes==536870912&&s.process_memory_limit_bytes==536870912&&s.peak_commit_bytes<=536870912&&s.terminated_processes==0,"InclusiveNativeLimits");
        Need(Math.Max(checked(s.combined_100ns+startup),held)<720000000&&Math.Max(checked(s.user_100ns+startupUser),heldUser)<1200000000,"InclusiveCpuStop");
        if(s.total_processes<1||s.total_processes>5)return "UnexpectedInclusiveLifetimeCount";
        if(bootstrap&&!(s.total_processes==1&&s.active_processes==1&&s.active_pids.Length==1&&s.active_pids[0]==(ulong)pid&&held<30000000))return "OwnerBootstrapTopologyAndCpu";
        return null;
    }
    public static Result Poll(IntPtr job,IntPtr owner,long creation,int pid,long startupUser,long startupKernel,bool bootstrap){
        var a=CapacityHostNative.Cpu(job);var m=CapacityHostNative.Limits(job);
        var s=new Sample{user_100ns=a.user,kernel_100ns=a.kernel,combined_100ns=checked(a.user+a.kernel),total_processes=a.total,active_processes=a.active,terminated_processes=a.terminated,active_pids=JobMembership.Members(job),peak_commit_bytes=m.peak_job.ToUInt64(),job_memory_limit_bytes=m.job_memory.ToUInt64(),process_memory_limit_bytes=m.process_memory.ToUInt64(),flags=m.basic.flags,process_user_limit_100ns=m.basic.process_time,job_user_limit_100ns=m.basic.job_time};
        // GetProcessTimes on the current-process pseudo-handle observes the same
        // complete D lifetime without opening/closing a Process object per poll.
        // Never close this pseudo-handle. All original O/Job handles stay intact.
        long own=CapacityHostNative.Time(new IntPtr(-1)).Combined;
        Need(checked(s.combined_100ns+startupUser+startupKernel+own)<720000000,"WholeCpuIncludingObservedDriver");
        var t=CapacityHostNative.Time(owner);Need(t.creation==creation&&CapacityHostNative.Member(owner,job),"LiveOriginalOuterOwner");
        return new Result{snapshot=s,failure=Evaluate(s,startupUser,startupKernel,t.user,t.kernel,bootstrap,pid)};
    }
    public static Result AwaitReady(string path,long deadline,IntPtr job,IntPtr owner,long creation,int pid,long startupUser,long startupKernel){
        var result=new Result();int polls=0;var self=Process.GetCurrentProcess();double start=self.TotalProcessorTime.TotalSeconds;
        try{
            while(!File.Exists(path)){
                Need(Stopwatch.GetTimestamp()<deadline,"InclusiveAbsoluteDeadline");
                if(CapacityHostNative.Exited(owner)){result.failure="OWNER_EXITED";break;}
                result=Poll(job,owner,creation,pid,startupUser,startupKernel,false);polls++;
                if(result.failure!=null)break;
                // Same 20 ms bounded wait, on the original process handle.
                uint waited=WaitForSingleObject(owner,20);
                Need(waited==0||waited==258,"OriginalOwnerWait");
                if(waited==0){result.failure="OWNER_EXITED";break;}
            }
            return result;
        }finally{result.polls=polls;result.polling_cpu_seconds=self.TotalProcessorTime.TotalSeconds-start;self.Dispose();}
    }
    public static Result AwaitExit(long deadline,IntPtr job,IntPtr owner,long creation,int pid,long startupUser,long startupKernel){
        var r=new Result();
        while(!CapacityHostNative.Exited(owner)){
            Need(Stopwatch.GetTimestamp()<deadline,"InclusiveAbsoluteDeadline");
            r=Poll(job,owner,creation,pid,startupUser,startupKernel,false);
            if(r.failure!=null)return r;
            uint waited=WaitForSingleObject(owner,20);Need(waited==0||waited==258,"OriginalOwnerWait");
        }
        return r;
    }
    [System.Runtime.InteropServices.DllImport("kernel32",SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    public static long[] PollingCostObservation(){
        const int count=2000;var current=new IntPtr(-1);
        long first=CapacityHostNative.Time(current).Combined;
        for(int i=0;i<count;i++){using(var p=Process.GetCurrentProcess()){long before=p.TotalProcessorTime.Ticks;long native=CapacityHostNative.Time(current).Combined;long after=p.TotalProcessorTime.Ticks;Need(before<=native&&native<=after,"SameCurrentProcessCpuCounters");}}
        long middle=CapacityHostNative.Time(current).Combined;
        for(int i=0;i<count;i++){long before=CapacityHostNative.Time(current).Combined;long after=CapacityHostNative.Time(current).Combined;Need(before<=after,"MonotoneNativeCpuCounters");}
        long last=CapacityHostNative.Time(current).Combined;
        return new long[]{count,middle-first,last-middle};
    }
    public static void InventedChecks(){
        for(int test=0;test<10;test++){
            var s=new Sample{user_100ns=100,kernel_100ns=200,combined_100ns=300,total_processes=1,active_processes=1,active_pids=new ulong[]{42},flags=8966,process_user_limit_100ns=300000000,job_user_limit_100ns=1200000000,job_memory_limit_bytes=536870912,process_memory_limit_bytes=536870912,peak_commit_bytes=100};
            long su=10,sk=20,hu=100,hk=200;
            switch(test){case 1:s.total_processes=6;break;case 2:s.active_pids=new ulong[]{43};break;case 3:s.user_100ns=720000000;s.combined_100ns=s.user_100ns+s.kernel_100ns;break;case 4:hu=720000000;break;case 5:s.peak_commit_bytes=536870913;break;case 6:s.terminated_processes=1;break;case 7:s.flags=0;break;case 8:s.combined_100ns++;break;case 9:hu=30000000;break;}
            bool rejected=false;try{rejected=Evaluate(s,su,sk,hu,hk,true,42)!=null;}catch(IOException){rejected=true;}
            if(rejected!=(test!=0))throw new IOException("DriverGuardInventedCase:"+test);
        }
    }
}
