// Existing observer loop compiled as one unit. No launch, Job or file authority.
// Caller owns the original Process, SafeProcessHandle, stopwatch and channels.
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using Microsoft.Win32.SafeHandles;

public static class ObserverSampleLoop {
    public interface Runtime {
        void Poll();
        int BytesRead { get; }
        bool Overflow { get; }
        bool AllClosed { get; }
        OwnedProcessEvidence.Sample Read();
        double Seconds { get; }
        void Kill();
        void Sleep(int milliseconds);
    }
    public sealed class Limits {
        public readonly double Wall, Cpu, Drain;
        public readonly ulong Memory;
        public Limits(double wall,double cpu,ulong memory,double drain) {
            if(!double.IsFinite(wall)||!double.IsFinite(cpu)||!double.IsFinite(drain)||wall<=0||cpu<=0||memory==0||drain<wall)
                throw new ArgumentException("ExplicitObserverLimits");
            Wall=wall;Cpu=cpu;Memory=memory;Drain=drain;
        }
    }
    public sealed class State {
        public OwnedProcessEvidence.Sample First,Last;
        public double? LastWall,Wall;
        public long Samples;
        public int BytesRead;
        public bool Overflow;
        public string Forced;
    }
    public static bool Step(Runtime runtime,Limits limits,State state) {
        // Original order, priorities, inequalities and one sample per iteration.
        runtime.Poll();state.BytesRead=runtime.BytesRead;state.Overflow=runtime.Overflow;
        state.Last=runtime.Read();state.LastWall=runtime.Seconds;state.Samples++;
        if(state.First==null)state.First=state.Last;
        else if(state.Last.pid!=state.First.pid||state.Last.creation_filetime!=state.First.creation_filetime)
            throw new IOException("OriginalInvokerIdentity");
        if(state.Last.exited&&state.Wall==null)state.Wall=runtime.Seconds;
        if(!state.Last.exited&&state.Forced==null) {
            if(state.Overflow)state.Forced="OUTPUT_CAP";
            else if(runtime.Seconds>=limits.Wall)state.Forced="WALL";
            else if(state.Last.CPU_seconds>=limits.Cpu)state.Forced="CPU";
            else if(state.Last.peak_working_set_bytes>limits.Memory)state.Forced="MEMORY";
            if(state.Forced!=null)runtime.Kill();
        }
        if(state.Last.exited&&runtime.AllClosed)return true;
        if(runtime.Seconds>limits.Drain)throw new IOException("BoundedDrainOrExitIncomplete");
        runtime.Sleep(10);return false;
    }
    public static void Run(Runtime runtime,Limits limits,State state) {
        if(state.Samples!=0||state.First!=null||state.Last!=null||state.Forced!=null||state.Wall!=null)
            throw new InvalidOperationException("FreshObserverLoopState");
        while(!Step(runtime,limits,state)){}
    }
    public sealed class OriginalRuntime : Runtime {
        readonly ObserverChannels channels;
        readonly Process process;
        readonly SafeProcessHandle handle;
        readonly Stopwatch watch;
        public OriginalRuntime(ObserverChannels c,Process p,SafeProcessHandle h,Stopwatch w) {
            if(c==null||p==null||h==null||h.IsInvalid||h.IsClosed||w==null||!w.IsRunning||p.SafeHandle!=h)
                throw new ArgumentException("OriginalObserverObjectsRequired");
            channels=c;process=p;handle=h;watch=w;
        }
        public void Poll(){channels.Poll();}
        public int BytesRead{get{return channels.BytesRead;}}
        public bool Overflow{get{return channels.Overflow;}}
        public bool AllClosed{get{return channels.AllClosed;}}
        public OwnedProcessEvidence.Sample Read(){return OwnedProcessEvidence.Read(handle);}
        public double Seconds{get{return watch.Elapsed.TotalSeconds;}}
        public void Kill(){process.Kill();}
        public void Sleep(int milliseconds){Thread.Sleep(milliseconds);}
    }
}
