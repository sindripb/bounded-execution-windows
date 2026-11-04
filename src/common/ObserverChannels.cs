// Independently implemented after reviewing dotnet/runtime and Microsoft BuildXL.
// No process creation, handle lookup, resource decisions, text decoding or file I/O.
using System;
using System.IO;
using System.Threading.Tasks;

public sealed class ObserverChannels : IDisposable {
    public const int CaptureLimit = 24576;
    public const int ReadSize = 4096;
    sealed class Channel {
        internal readonly Stream Input;
        internal readonly byte[] Buffer = new byte[ReadSize];
        internal readonly MemoryStream Saved = new MemoryStream();
        internal Task<int> Pending;
        internal bool Eof;
        internal Channel(Stream input) { Input = input; }
    }
    readonly Channel output, error;
    bool started, disposed;
    public int BytesRead { get; private set; }
    public bool Overflow { get; private set; }
    public bool AllClosed { get { return started && output.Eof && error.Eof; } }
    public bool OutputClosed { get { return output.Eof; } }
    public bool ErrorClosed { get { return error.Eof; } }

    public ObserverChannels(Stream stdout, Stream stderr) {
        if (stdout == null || stderr == null || !stdout.CanRead || !stderr.CanRead)
            throw new ArgumentException("ReadableObserverStreamsRequired");
        output = new Channel(stdout); error = new Channel(stderr);
    }
    public void Start() {
        NeedLive();
        if (started) throw new InvalidOperationException("ObserverChannelsAlreadyStarted");
        started = true;
        // Caller retains this object even if either read initiation fails.
        output.Pending = output.Input.ReadAsync(output.Buffer, 0, ReadSize);
        error.Pending = error.Input.ReadAsync(error.Buffer, 0, ReadSize);
    }
    public void Poll() {
        NeedLive();
        if (!started) throw new InvalidOperationException("ObserverChannelsNotStarted");
        // Exact original priority: at most one completed read per channel per sample.
        PollOne(output); PollOne(error);
    }
    void PollOne(Channel channel) {
        if (channel.Eof) return;
        if (channel.Pending == null) throw new InvalidOperationException("ObserverReadNotInitialized");
        if (!channel.Pending.IsCompleted) return;
        int n = channel.Pending.GetAwaiter().GetResult();
        if (n < 0 || n > ReadSize) throw new IOException("ObserverInvalidReadCount");
        if (n == 0) { channel.Eof = true; return; }
        int keep = Math.Min(n, CaptureLimit - BytesRead);
        if (keep > 0) { channel.Saved.Write(channel.Buffer, 0, keep); BytesRead += keep; }
        if (keep != n) Overflow = true;
        // Still drain after overflow; no unbounded capture and no manufactured EOF.
        channel.Pending = channel.Input.ReadAsync(channel.Buffer, 0, ReadSize);
    }
    public byte[] OutputBytes() { NeedLive(); return output.Saved.ToArray(); }
    public byte[] ErrorBytes() { NeedLive(); return error.Saved.ToArray(); }
    void NeedLive() { if (disposed) throw new ObjectDisposedException(nameof(ObserverChannels)); }
    public void Dispose() {
        if (disposed) return;
        disposed = true;
        output.Saved.Dispose(); error.Saved.Dispose();
        // Borrowed streams and original process handle remain owned by the caller.
    }
}
