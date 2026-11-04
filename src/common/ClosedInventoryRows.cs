using System;
using System.IO;
using System.Collections.Generic;
// Pure comparison of the already acquired strict census. No IO, cache, process,
// resource policy or financial calculation. Every row and all seven fields stay
// mandatory; each invocation compares a fresh caller-owned census.
public static class ClosedInventoryRows {
    static string Text(object v) {return Convert.ToString(v,System.Globalization.CultureInfo.InvariantCulture);}
    static void Need(bool condition,string code){if(!condition)throw new IOException(code);}
    static object[] Fields(LiveStorage.Entry e){return new object[]{e.path,e.bytes,e.allocated_bytes,e.volume,e.file_id,e.creation_filetime,e.write_filetime,e.sha256};}
    // Pure encoding of a freshly acquired exclusive census. No IO or cache.
    public static object[] Project(LiveStorage.Entry[] entries) {
        var rows=new object[entries.Length];
        for(int i=0;i<entries.Length;i++){var e=entries[i];rows[i]=new object[]{e.path,e.bytes,e.allocated_bytes,e.volume,Text(e.file_id),Text(e.creation_filetime),Text(e.write_filetime),e.sha256};}
        return rows;
    }
    public static byte[] Encode(LiveStorage.Census s,string inventory,string receipt) {
        return System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(new {
            schema_version=2,host_inventory_encoding="ORDERED_ROWS_V1",
            file_fields=new[]{"path","bytes","allocated_bytes","volume","file_id","creation_filetime","write_filetime","sha256"},
            accounting="CONSERVATIVE_FULL_FILE_V2",all_file_handles_exclusive=true,sqlite_opened_during_census=false,
            files=Project(s.entries),totals=new{files=s.files,logical_bytes=s.logical_bytes,allocated_bytes=s.allocated_bytes},
            append_only_control_files=new[]{inventory,receipt},source_snapshot_sha256=s.snapshot_sha256,
            accounting_scope=s.accounting_scope,unobserved_transient_peak=s.transient_peak,
            genuine_eligibility=false,hard_peak_storage_enforcement=false});
    }
    public static void Verify(object[] rows,long count,long logical,long allocated,
        LiveStorage.Entry[] actual,string inventoryPath,LiveStorage.Entry inventoryEntry,
        string receiptPath,string receiptHash) {
        var expected=new Dictionary<string,object[]>(StringComparer.OrdinalIgnoreCase);
        long sumLogical=0,sumAllocated=0;
        foreach(object value in rows){
            var row=value as object[];Need(row!=null&&row.Length==8,"HostClosedInventoryRow");
            string name=Text(row[0]);Need(!expected.ContainsKey(name),"HostClosedInventoryDuplicate");
            expected.Add(name,row);
            sumLogical=checked(sumLogical+Convert.ToInt64(row[1],System.Globalization.CultureInfo.InvariantCulture));
            sumAllocated=checked(sumAllocated+Convert.ToInt64(row[2],System.Globalization.CultureInfo.InvariantCulture));
        }
        Need(count==expected.Count&&logical==sumLogical&&allocated==sumAllocated,"HostClosedInventoryTotals");
        expected[inventoryPath]=Fields(inventoryEntry);
        var names=new HashSet<string>(StringComparer.Ordinal);
        foreach(var key in expected.Keys)Need(names.Add(key),"HostClosedMembership");
        Need(names.Add(receiptPath)&&names.Count==actual.Length,"HostClosedMembership");
        foreach(var entry in actual)Need(names.Remove(entry.path),"HostClosedMembership");
        Need(names.Count==0,"HostClosedMembership");
        string[] labels={"path","bytes","allocated_bytes","volume","file_id","creation_filetime","write_filetime","sha256"};
        foreach(var entry in actual){
            if(entry.path==receiptPath){Need(entry.sha256==receiptHash&&entry.bytes<=32768&&entry.allocated_bytes<=65536,"HostClosedFinalReceipt");continue;}
            var wanted=expected[entry.path];var observed=Fields(entry);
            for(int i=1;i<8;i++)Need(Text(observed[i])==Text(wanted[i]),"HostClosedFile:"+labels[i]);
        }
    }
}
