using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class AtomicPostReadback {
 [StructLayout(LayoutKind.Sequential)] struct Standard {public long allocation,end;public uint links;public byte pending,directory;}
 [StructLayout(LayoutKind.Sequential)] struct FT {public uint low,high;public ulong Value {get{return ((ulong)high<<32)|low;}}}
 [StructLayout(LayoutKind.Sequential)] struct Info {public uint attributes;public FT created,accessed,written;public uint volume,sizeHigh,sizeLow,links,idHigh,idLow;}
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr CreateFileW(string path,uint access,uint share,IntPtr security,uint disposition,uint flags,IntPtr template);
 [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandleEx(IntPtr h,int cls,out Standard info,uint length);
 [DllImport("kernel32",SetLastError=true)] static extern bool GetFileInformationByHandle(IntPtr h,out Info info);
 [DllImport("kernel32",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(IntPtr h,StringBuilder text,uint length,uint flags);
 [DllImport("kernel32",SetLastError=true)] static extern bool CloseHandle(IntPtr h);
 public sealed class Sample {public long bytes,allocated_bytes;public uint volume;public string file_id,creation_filetime,write_filetime,sha256;}
 public sealed class Totals {public long logical,physical;public int count;}
 public static long ReadLimit(string path){return ExternalReadPolicy.Default.Limit(path);}
 public static long ReadLimit(string path,ExternalReadPolicy policy){
  if(policy==null)throw new ArgumentNullException(nameof(policy));return policy.Limit(path);
 }
 public static Totals Preparation(string root){return Preparation(root,ExternalReadPolicy.Default);}
 public static Totals Preparation(string root,ExternalReadPolicy policy){
  if(policy==null)throw new ArgumentNullException(nameof(policy));
  var result=new Totals();var pending=new System.Collections.Generic.Stack<string>();pending.Push(root);int directories=0;
  while(pending.Count>0){string directory=pending.Pop();
   if((File.GetAttributes(directory)&FileAttributes.ReparsePoint)!=0)throw new IOException("PreparationReparse");
   foreach(string path in Directory.EnumerateFileSystemEntries(directory)){
    var attributes=File.GetAttributes(path);
    if((attributes&FileAttributes.ReparsePoint)!=0)throw new IOException("PreparationReparse");
    if((attributes&FileAttributes.Directory)!=0){if(++directories>256)throw new IOException("PreparationDirectoryBound");pending.Push(path);continue;}
    var value=Read(path,policy);result.logical=checked(result.logical+value.bytes);result.physical=checked(result.physical+value.allocated_bytes);
    if(++result.count>256)throw new IOException("PreparationFileBound");
   }
  }
  return result;
 }
 public static Sample Read(string path){return Read(path,ExternalReadPolicy.Default);}
 public static Sample Read(string path,ExternalReadPolicy policy) {
  long limit=ReadLimit(path,policy);
  IntPtr h=CreateFileW(path,0x80000080,0,IntPtr.Zero,3,0x00200000,IntPtr.Zero);
  if(h==new IntPtr(-1))throw new IOException("ExternalReadOpen:"+Marshal.GetLastWin32Error());
  Exception first=null;
  try {
   Standard s;Info a,b;
   if(!GetFileInformationByHandleEx(h,1,out s,(uint)Marshal.SizeOf<Standard>())||!GetFileInformationByHandle(h,out a))throw new IOException("ExternalReadMetadata:"+Marshal.GetLastWin32Error());
   if(s.allocation<0||s.end<0||s.end>limit||s.directory!=0||s.pending!=0||(a.attributes&0x400)!=0)throw new IOException("ExternalUnsafeMetadata");
   var resolved=new StringBuilder(1024);uint n=GetFinalPathNameByHandleW(h,resolved,1024,0);
   if(n==0||n>=1024||!string.Equals(resolved.ToString(),"\\\\?\\"+Path.GetFullPath(path),StringComparison.OrdinalIgnoreCase))throw new IOException("ExternalResolvedPath");
   string hash;
   using(var stream=new FileStream(new SafeFileHandle(h,false),FileAccess.Read)){hash=Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();}
   Standard after;
   if(!GetFileInformationByHandle(h,out b)||!GetFileInformationByHandleEx(h,1,out after,(uint)Marshal.SizeOf<Standard>()))throw new IOException("ExternalRecheckMetadata");
   if(s.allocation!=after.allocation||s.end!=after.end||a.volume!=b.volume||a.idHigh!=b.idHigh||a.idLow!=b.idLow||a.created.Value!=b.created.Value||a.written.Value!=b.written.Value)throw new IOException("ExternalReadChanged");
   return new Sample{bytes=s.end,allocated_bytes=s.allocation,volume=a.volume,file_id=(((ulong)a.idHigh<<32)|a.idLow).ToString(),creation_filetime=a.created.Value.ToString(),write_filetime=a.written.Value.ToString(),sha256=hash};
  }catch(Exception e){first=e;throw;}
  finally{if(!CloseHandle(h)){if(first==null)throw new IOException("ExternalReadClose");first.Data["secondary_close_failure"]=true;}}
 }
}
