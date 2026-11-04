// Complete byte verification, batched to avoid per-file PowerShell dispatch cost.
// No process, Job, publication, allowance, or financial APIs.
using System;
using System.IO;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.Json;
public static class BindingVerifier {
    // Same JsonDocument and ordinal-ignore-case recursive duplicate contract.
    // Used by the already-compiled driver to avoid PowerShell dispatch per node.
    public static void UniqueJson(JsonElement value) { Unique(value); }
    static void Unique(JsonElement value) {
        if(value.ValueKind==JsonValueKind.Object) {
            var keys=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var p in value.EnumerateObject()){if(!keys.Add(p.Name))throw new IOException("DuplicateJsonField");Unique(p.Value);}
        } else if(value.ValueKind==JsonValueKind.Array)foreach(var p in value.EnumerateArray())Unique(p);
    }
    static JsonDocument Parse(string file) {
        byte[] raw=File.ReadAllBytes(file);if(raw.Length>1048576)throw new IOException("JsonByteCap");
        var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=48});
        try{Unique(doc.RootElement);return doc;}catch{doc.Dispose();throw;}
    }
    static string Contained(string root,string relative) {
        string full=Path.GetFullPath(Path.Combine(root,relative));
        if(Path.IsPathRooted(relative)||relative.Contains(':')||relative.Contains('\\')||
           !full.StartsWith(Path.GetFullPath(root)+"\\",StringComparison.OrdinalIgnoreCase)||
           Path.GetRelativePath(root,full).Replace('\\','/')!=relative)
            throw new IOException("BindingPathEscape:"+relative);
        return full;
    }
    static void Check(string path,string expected,long? bytes) {
        if(expected==null||expected.Length!=64)throw new IOException("MissingBindingHash:"+path);
        // Read every byte with the same sharing and before/after length checks.
        // Larger sequential buffering reduces kernel reads for pinned runtimes.
        using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read,1,FileOptions.SequentialScan)) {
            if(bytes.HasValue&&stream.Length!=bytes.Value)throw new IOException("BindingLength:"+path);
            string actual;byte[] buffer=System.Buffers.ArrayPool<byte>.Shared.Rent(65536);
            try{
                long length=stream.Length;
                if(length<=65536){
                    int used=0;
                    while(used<(int)length){int n=stream.Read(buffer,used,(int)length-used);if(n==0)throw new IOException("BindingShortRead:"+path);used+=n;}
                    if(stream.ReadByte()!=-1||stream.Length!=length)throw new IOException("BindingLengthChanged:"+path);
                    actual=Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0,used))).ToLowerInvariant();
                }else{using(var digest=IncrementalHash.CreateHash(HashAlgorithmName.SHA256)){
                    int read;while((read=stream.Read(buffer,0,65536))!=0)digest.AppendData(buffer,0,read);
                    actual=Convert.ToHexString(digest.GetHashAndReset()).ToLowerInvariant();
                }}
            }finally{System.Buffers.ArrayPool<byte>.Shared.Return(buffer);}
            if(actual!=expected)throw new IOException("BindingHash:"+path);
            if(bytes.HasValue&&stream.Length!=bytes.Value)throw new IOException("BindingLengthChanged:"+path);
        }
    }
    public static int Package(string root,string file) {
        using(var doc=Parse(file)) {
            var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var e in doc.RootElement.GetProperty("files").EnumerateArray()) {
                string path=Contained(root,e.GetProperty("path").GetString());
                if(!seen.Add(path))throw new IOException("DuplicateBinding:"+path);
                Check(path,e.GetProperty("sha256").GetString(),e.GetProperty("bytes").GetInt64());
            }
            return seen.Count;
        }
    }
    // Lossless transport only. Outer Package verification still binds every
    // encoded byte; all decoded rows continue through the original Parents loop.
    public static byte[] ParentBytes(byte[] raw) {
        if(raw.Length>1048576)throw new IOException("ParentTransportByteCap");
        using(var outer=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=48})) {
            Unique(outer.RootElement);var e=outer.RootElement;
            int version=e.GetProperty("schema_version").GetInt32();
            if(version==2||version==3)return raw;
            var required=new HashSet<string>(new[]{"schema_version","encoding","original_sha256","original_bytes","gzip_sha256","gzip_bytes","payload"},StringComparer.Ordinal);
            foreach(var field in e.EnumerateObject())if(!required.Remove(field.Name))throw new IOException("ParentTransportFields");
            if(required.Count!=0||version!=4||e.GetProperty("encoding").GetString()!="GZIP_ORIGINAL_PARENT_JSON_V1")throw new IOException("ParentTransportSchema");
            int size=e.GetProperty("original_bytes").GetInt32(),packedSize=e.GetProperty("gzip_bytes").GetInt32();
            if(size<1||size>1048576||packedSize<18||packedSize>131072)throw new IOException("ParentTransportLength");
            string text=e.GetProperty("payload").GetString();
            if(text==null||text.Length!=4*((packedSize+2)/3))throw new IOException("ParentBase64Length");
            byte[] packed=Convert.FromBase64String(text);
            if(packed.Length!=packedSize||Convert.ToBase64String(packed)!=text||
               Convert.ToHexString(SHA256.HashData(packed)).ToLowerInvariant()!=e.GetProperty("gzip_sha256").GetString())throw new IOException("ParentTransportHash");
            if(packed[0]!=31||packed[1]!=139||packed[2]!=8||packed[3]!=0||
               System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(packed.AsSpan(packed.Length-4))!=size)throw new IOException("ParentGzipFrame");
            byte[] original=new byte[size];int used=0;
            using(var input=new MemoryStream(packed,false))
            using(var zip=new System.IO.Compression.GZipStream(input,System.IO.Compression.CompressionMode.Decompress)) {
                while(used<size){int n=zip.Read(original,used,size-used);if(n==0)throw new IOException("ParentShortRead");used+=n;}
                if(zip.ReadByte()!=-1)throw new IOException("ParentExpansionCap");
            }
            if(Convert.ToHexString(SHA256.HashData(original)).ToLowerInvariant()!=e.GetProperty("original_sha256").GetString())throw new IOException("OriginalParentHash");
            using(var decoded=JsonDocument.Parse(original,new JsonDocumentOptions{MaxDepth=48})) {
                Unique(decoded.RootElement);int v=decoded.RootElement.GetProperty("schema_version").GetInt32();
                if(v!=2&&v!=3)throw new IOException("OriginalParentSchema");
            }
            return original;
        }
    }
    static JsonDocument ParentDocument(string file) {
        var doc=JsonDocument.Parse(ParentBytes(File.ReadAllBytes(file)),new JsonDocumentOptions{MaxDepth=48});
        try{Unique(doc.RootElement);return doc;}catch{doc.Dispose();throw;}
    }

    public static int Parents(string root,string file) {
        using(var doc=ParentDocument(file)) {
            var e=doc.RootElement;
            int version=e.GetProperty("schema_version").GetInt32();
            if((version!=2&&version!=3)||e.GetProperty("base_root").GetString()!=root||e.GetProperty("unread_payloads").GetInt32()!=0)
                throw new IOException("PreservationRootOrSchema");
            if(version==3&&e.GetProperty("file_fields").ToString()!="[\"path\",\"bytes\",\"sha256\"]")throw new IOException("PreservationFields");
            var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var row in e.GetProperty("files").EnumerateArray()) {
                if(version==3&&row.GetArrayLength()!=3)throw new IOException("PreservationRow");
                string name=(version==3?row[0]:row.GetProperty("path")).GetString();
                string path=Path.IsPathFullyQualified(name)?Path.GetFullPath(name):Contained(root,name);
                if(!seen.Add(path))throw new IOException("DuplicateBinding:"+path);
                Check(path,(version==3?row[2]:row.GetProperty("sha256")).GetString(),(version==3?row[1]:row.GetProperty("bytes")).GetInt64());
            }
            return seen.Count;
        }
    }
    public static int Map(string root,string file,string property,bool absolute) {
        using(var doc=Parse(file)) {
            var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach(var e in doc.RootElement.GetProperty(property).EnumerateObject()) {
                string path=absolute?Path.GetFullPath(e.Name):Contained(root,e.Name);
                if(absolute&&(!Path.IsPathFullyQualified(e.Name)||path.Contains("\\OneDrive\\",StringComparison.OrdinalIgnoreCase)))throw new IOException("RuntimePath:"+e.Name);
                if(!seen.Add(path))throw new IOException("DuplicateBinding:"+path);
                Check(path,e.Value.GetString(),null);
            }
            return seen.Count;
        }
    }
    // Same complete row hashing, without one PowerShell hashing pipeline per file.
    public static int EvidenceRows(string root,System.Collections.IEnumerable rows,int width,int hashIndex) {
        int count=0;
        foreach(object value in rows) {
            object[] row=value as object[];
            if(row==null||row.Length!=width||!(row[0] is string)||!(row[hashIndex] is string)||
               !(row[1] is long||row[1] is int))throw new IOException("EvidenceRowSchema");
            Check(Contained(root,(string)row[0]),(string)row[hashIndex],Convert.ToInt64(row[1]));count++;
        }
        return count;
    }
    public static void ReceiptMap(string root,System.Collections.IDictionary map) {
        foreach(System.Collections.DictionaryEntry e in map)Check(Contained(root,(string)e.Key),(string)e.Value,null);
    }
    public static void Membership(string root,System.Collections.IEnumerable names) {
        var expected=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach(object n in names){string p=Contained(root,(string)n);if(!expected.Add(p))throw new IOException("DuplicateExpectedFile");}
        var pending=new Stack<string>();pending.Push(root);int count=0;
        while(pending.Count>0){string dir=pending.Pop();if((File.GetAttributes(dir)&FileAttributes.ReparsePoint)!=0)throw new IOException("EvidenceReparse");
            foreach(string p in Directory.EnumerateFileSystemEntries(dir)){
                var a=File.GetAttributes(p);if((a&FileAttributes.ReparsePoint)!=0)throw new IOException("EvidenceReparse");
                if((a&FileAttributes.Directory)!=0)pending.Push(p);
                else{if(!expected.Contains(Path.GetFullPath(p)))throw new IOException("EvidenceExtraFile");count++;}
            }
        }
        if(count!=expected.Count)throw new IOException("EvidenceMissingFile");
    }
}
