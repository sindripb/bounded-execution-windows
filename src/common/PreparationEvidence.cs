// Batches the original preparation-preservation traversal. Every original
// receipt/package/evidence byte and complete membership is still checked.
// No cache, process, grant, financial or publication functions.
using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;

public static class PreparationEvidence {
    static JsonDocument Read(string path) {
        byte[] raw=File.ReadAllBytes(path);
        if(raw.Length>1048576)throw new IOException("JsonByteCap");
        var doc=JsonDocument.Parse(raw,new JsonDocumentOptions{MaxDepth=48});
        try{BindingVerifier.UniqueJson(doc.RootElement);return doc;}
        catch{doc.Dispose();throw;}
    }
    static bool Has(JsonElement e,string name){return e.TryGetProperty(name,out _);}
    static List<string> PackageNames(string scope) {
        var result=new List<string>();
        using(var doc=Read(Path.Combine(scope,"PACKAGE_MANIFEST.json")))
            foreach(var row in doc.RootElement.GetProperty("files").EnumerateArray())result.Add(row.GetProperty("path").GetString());
        return result;
    }
    static List<string> EvidenceRows(string scope,JsonElement values,int width,int hashIndex) {
        var names=new List<string>();var rows=new List<object[]>();
        foreach(var e in values.EnumerateArray()) {
            if(e.ValueKind!=JsonValueKind.Array||e.GetArrayLength()!=width||e[0].ValueKind!=JsonValueKind.String
                ||e[hashIndex].ValueKind!=JsonValueKind.String||!e[1].TryGetInt64(out long length))throw new IOException("EvidenceRowSchema");
            var row=new object[width];row[0]=e[0].GetString();row[1]=length;row[hashIndex]=e[hashIndex].GetString();
            rows.Add(row);names.Add((string)row[0]);
        }
        BindingVerifier.EvidenceRows(scope,rows,width,hashIndex);return names;
    }
    public static int Verify(string candidate,string evidenceRoot) {
        string baseRoot=Path.GetFullPath(evidenceRoot);
        string checks=Path.Combine(baseRoot,"checks")+Path.DirectorySeparatorChar;
        string finance="^"+Regex.Escape(baseRoot+Path.DirectorySeparatorChar)+"candidate_[0-9]{3}$";
        using(var doc=Read(Path.Combine(candidate,"CHECK_PRESERVATION.json"))) {
            int count=0;var groups=new List<JsonElement>{doc.RootElement.GetProperty("checks")};
            if(Has(doc.RootElement,"financial"))groups.Add(doc.RootElement.GetProperty("financial"));
            foreach(var group in groups)foreach(var entry in group.EnumerateArray()) {
                string kind=Has(entry,"kind")?entry.GetProperty("kind").GetString():null;
                bool financial=kind=="financial"||kind=="financial_partial"||kind=="financial_prepared";
                string scope=Path.GetFullPath(entry.GetProperty("root").GetString());
                if(financial?!Regex.IsMatch(scope,finance):!scope.StartsWith(checks,StringComparison.Ordinal))
                    throw new IOException(financial?"FinancialEvidenceScopeEscape":"CheckScopeEscape");
                var bindings=new Dictionary<string,string>(StringComparer.Ordinal);
                foreach(var item in entry.GetProperty("bindings").EnumerateObject())bindings.Add(item.Name,item.Value.GetString());
                BindingVerifier.ReceiptMap(scope,bindings);
                BindingVerifier.Package(scope,Path.Combine(scope,"PACKAGE_MANIFEST.json"));
                List<string> expected;
                if(kind=="financial_partial"||kind=="check_partial") {
                    expected=EvidenceRows(scope,entry.GetProperty("available_files"),3,2);
                    if(Has(entry,"source_members_covered_by_package")&&entry.GetProperty("source_members_covered_by_package").GetBoolean())
                        expected.AddRange(PackageNames(scope));
                } else if(financial&&kind=="financial_prepared") {
                    expected=PackageNames(scope);expected.Add("PACKAGE_MANIFEST.json");expected.Add("PREPARATION_SEAL.json");
                } else {
                    using(var inventory=Read(Path.Combine(scope,"control/HOST_CLOSED_INVENTORY.json"))) {
                        var fields=new List<string>();foreach(var f in inventory.RootElement.GetProperty("file_fields").EnumerateArray())fields.Add(f.GetString());
                        if(String.Join(",",fields)!="path,bytes,allocated_bytes,volume,file_id,creation_filetime,write_filetime,sha256")
                            throw new IOException("CheckInventorySchema");
                        expected=EvidenceRows(scope,inventory.RootElement.GetProperty("files"),8,7);
                    }
                    expected.AddRange(new[]{"control/HOST_CLOSED_INVENTORY.json",financial?"control/FINANCIAL_HOST_CLOSEOUT.json":"METADATA_EXECUTION_CLOSEOUT.json",
                        "STDOUT.txt","STDERR.txt","EXTERNAL_CLOSEOUT.json"});
                }
                BindingVerifier.Membership(scope,expected);count++;
            }
            return count;
        }
    }
}
