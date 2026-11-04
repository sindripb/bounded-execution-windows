using System;
using System.Collections.Generic;
using System.IO;

/// <summary>Immutable exact-path exceptions; never a directory or filename wildcard.</summary>
/// <remarks>Callers must bind the complete policy to their own execution authority.
/// This object does not grant access or an execution/resource allowance.</remarks>
public sealed class ExternalReadPolicy {
    public const long DefaultBytes=6291456;
    public const long MaximumExceptionBytes=3758096384;
    public static readonly ExternalReadPolicy Default=new ExternalReadPolicy(Array.Empty<PathLimit>());
    public readonly struct PathLimit {
        public readonly string Path;
        public readonly long MaximumBytes;
        public readonly bool CaseSensitive;
        public PathLimit(string path,long maximumBytes,bool caseSensitive) {
            Path=path;MaximumBytes=maximumBytes;CaseSensitive=caseSensitive;
        }
    }
    readonly PathLimit[] rules;
    public ExternalReadPolicy(PathLimit[] paths) {
        if(paths==null||paths.Length>4)throw new ArgumentException("BoundedExactReadPolicy");
        rules=(PathLimit[])paths.Clone();
        var seen=new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for(int i=0;i<rules.Length;i++) {
            var r=rules[i];
            if(string.IsNullOrWhiteSpace(r.Path)||!System.IO.Path.IsPathFullyQualified(r.Path)
                ||r.Path.Length<3||!char.IsAsciiLetter(r.Path[0])||r.Path[1]!=':'
                ||(r.Path[2]!='\\'&&r.Path[2]!='/')||r.Path.IndexOf(':',2)>=0
                ||r.MaximumBytes<DefaultBytes||r.MaximumBytes>MaximumExceptionBytes)
                throw new ArgumentException("ExactLocalReadPolicyRule");
            string full=System.IO.Path.GetFullPath(r.Path);
            if(!seen.Add(full))throw new ArgumentException("DuplicateReadPolicyPath");
            rules[i]=new PathLimit(full,r.MaximumBytes,r.CaseSensitive);
        }
    }
    public long Limit(string path) {
        string full=System.IO.Path.GetFullPath(path);
        foreach(var r in rules)if(string.Equals(full,r.Path,
            r.CaseSensitive?StringComparison.Ordinal:StringComparison.OrdinalIgnoreCase))return r.MaximumBytes;
        return DefaultBytes;
    }
}
