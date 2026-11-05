"""Read-only Windows data-stream allocation census; no helper DLL or prices.

Uses same-handle FILE_STANDARD_INFO/identity queries. The caller owns the root.
Transient peaks, filesystem metadata and other processes remain unobserved.
"""
import ctypes,os,stat,sys,time,json
from ctypes import wintypes as W
from pathlib import Path
class Standard(ctypes.Structure):
    _fields_=[('AllocationSize',ctypes.c_longlong),('EndOfFile',ctypes.c_longlong),('NumberOfLinks',W.DWORD),('DeletePending',W.BOOLEAN),('Directory',W.BOOLEAN)]
class Identity(ctypes.Structure):
    _fields_=[('attributes',W.DWORD),('created',W.FILETIME),('accessed',W.FILETIME),('written',W.FILETIME),('volume',W.DWORD),('size_high',W.DWORD),('size_low',W.DWORD),('links',W.DWORD),('index_high',W.DWORD),('index_low',W.DWORD)]
class Memory(ctypes.Structure):
    _fields_=[('cb',W.DWORD),('faults',W.DWORD)]+[(n,ctypes.c_size_t) for n in ('peak_ws','ws','peak_pool','pool','peak_nonpool','nonpool','commit','peak_commit')]
K=ctypes.WinDLL('kernel32',use_last_error=True)
K.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,ctypes.c_void_p,W.DWORD,W.DWORD,W.HANDLE];K.CreateFileW.restype=W.HANDLE
K.GetFileInformationByHandleEx.argtypes=[W.HANDLE,ctypes.c_int,ctypes.c_void_p,W.DWORD];K.GetFileInformationByHandleEx.restype=W.BOOL
K.GetFileInformationByHandle.argtypes=[W.HANDLE,ctypes.POINTER(Identity)];K.GetFileInformationByHandle.restype=W.BOOL
K.CloseHandle.argtypes=[W.HANDLE];K.CloseHandle.restype=W.BOOL
K.GetCurrentProcess.restype=W.HANDLE
P=ctypes.WinDLL('psapi',use_last_error=True);P.GetProcessMemoryInfo.argtypes=[W.HANDLE,ctypes.c_void_p,W.DWORD];P.GetProcessMemoryInfo.restype=W.BOOL
def require(ok,label):
    if not ok:raise ValueError(label)
def check_path(path):
    p=Path(path);require(p.is_absolute() and '..' not in p.parts and ':' not in str(p)[2:],'Absolute ordinary path required')
    for q in (p,*p.parents):
        s=q.lstat();require(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'Reparse path')
    return p
def file_observation(path):
    handle=K.CreateFileW(str(path),0x80,7,None,3,0x200000,None)
    if handle==ctypes.c_void_p(-1).value:raise ctypes.WinError(ctypes.get_last_error())
    first=None
    try:
        a=Standard();i=Identity()
        if not K.GetFileInformationByHandleEx(handle,1,ctypes.byref(a),ctypes.sizeof(a)) or not K.GetFileInformationByHandle(handle,ctypes.byref(i)):raise ctypes.WinError(ctypes.get_last_error())
        require(a.EndOfFile==((i.size_high<<32)|i.size_low) and a.AllocationSize>=0 and not a.Directory and not a.DeletePending and not i.attributes&0x410,'Allocation observation differs')
        return a.EndOfFile,a.AllocationSize
    except BaseException as e:first=e;raise
    finally:
        if not K.CloseHandle(handle):
            e=ctypes.WinError(ctypes.get_last_error())
            if first is None:raise e
            first.add_note('SECONDARY_CLOSE:'+str(e))
def census(root,check):
    pending=[check_path(root)];files=logical=allocated=0
    while pending:
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                check();s=entry.stat(follow_symlinks=False)
                require(not entry.is_symlink() and not getattr(s,'st_file_attributes',0)&0x400,'Reparse storage entry')
                if entry.is_dir(follow_symlinks=False):pending.append(entry.path)
                elif entry.is_file(follow_symlinks=False):
                    n,a=file_observation(entry.path);files+=1;logical+=n;allocated+=a
                    require(files+4<=5000 and logical+65536<1073741824 and allocated+65536<2147483648,'Hosted storage limit')
                else:raise ValueError('Unknown storage entry')
    return dict(files=files,logical_bytes=logical,allocated_bytes=allocated,transient_peak='UNKNOWN',publication_reserve_bytes=65536,publication_reserve_files=4)
def main(root,output):
    require(sys.version_info >= (3,11),'Python 3.11 or newer required')
    start=time.monotonic();m=Memory();m.cb=ctypes.sizeof(m);peak=0
    def check():
        nonlocal peak
        require(time.process_time()<6 and time.monotonic()-start<10,'Observer CPU/wall limit')
        if not P.GetProcessMemoryInfo(K.GetCurrentProcess(),ctypes.byref(m),m.cb):raise ctypes.WinError(ctypes.get_last_error())
        peak=max(peak,m.peak_ws,m.peak_commit);require(peak<536870912,'Observer memory limit')
    target=Path(output);check_path(target.parent);require(not target.exists(),'Fresh observer receipt')
    first=None
    try:
        result=dict(status='PASS_OBSERVED_HOSTED_STORAGE',**census(root,check));check()
    except BaseException as error:
        first=error
        result=dict(status='FAIL',first_failure=dict(type=type(error).__name__,message=str(error)),inventory_complete=False)
    finally:
        result.update(cpu_seconds=time.process_time(),wall_seconds=time.monotonic()-start,peak_observed_bytes=peak,python_version=sys.version,helper_loaded=False)
        raw=json.dumps(result,sort_keys=True,separators=(',',':'),allow_nan=False).encode()
        try:
            require(len(raw)<=16384,'Small receipt required')
            with target.open('xb') as f:f.write(raw);f.flush();os.fsync(f.fileno())
            require(target.read_bytes()==raw,'Observer receipt readback')
        except BaseException as publication:
            if first is None:raise
            first.add_note('SECONDARY_PUBLICATION:'+type(publication).__name__+':'+str(publication))
    if first is not None:raise first
if __name__=='__main__':main(*sys.argv[1:])
