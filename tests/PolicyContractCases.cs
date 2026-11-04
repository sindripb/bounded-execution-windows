// Prepared pure-policy cases. Compile-only preparation does NOT execute these.
// Run only after a trusted, independently qualified library is available.
using System;
using System.IO;
public static class PolicyContractCases {
    static void Need(bool value,string name){if(!value)throw new Exception(name);}
    static void Reject(Action action,string name){bool failed=false;try{action();}catch(ArgumentException){failed=true;}Need(failed,name);}
    public static int Run() {
        const string file=@"C:\invented\fixture.tsv";
        var rule=new ExternalReadPolicy.PathLimit(file,24511426,true);
        var inputs=new[]{rule};var p=new ExternalReadPolicy(inputs);
        Need(p.Limit(file)==24511426,"exact source");
        Need(p.Limit(@"C:\other\fixture.tsv")==6291456,"same basename cannot inherit exception");
        Need(p.Limit(file+".copy")==6291456,"suffix spoof rejected");
        Need(p.Limit(@"C:\invented\FIXTURE.tsv")==6291456,"ordinal semantics");
        inputs[0]=new ExternalReadPolicy.PathLimit(@"C:\other\fixture.tsv",3758096384,false);
        Need(p.Limit(file)==24511426&&p.Limit(@"C:\other\fixture.tsv")==6291456,"caller mutation isolated");
        var insensitive=new ExternalReadPolicy(new[]{new ExternalReadPolicy.PathLimit(file,3758096384,false)});
        Need(insensitive.Limit(@"C:\INVENTED\FIXTURE.tsv")==3758096384,"declared insensitive semantics");
        Need(ExternalReadPolicy.Default.Limit(file)==6291456,"no implicit exception");
        Reject(()=>new ExternalReadPolicy(null),"null rules");
        Reject(()=>new ExternalReadPolicy(new ExternalReadPolicy.PathLimit[5]),"rule count bound");
        Reject(()=>new ExternalReadPolicy(new[]{new ExternalReadPolicy.PathLimit("relative.tsv",24511426,true)}),"absolute required");
        Reject(()=>new ExternalReadPolicy(new[]{new ExternalReadPolicy.PathLimit(file+":hidden",24511426,true)}),"alternate stream rejected");
        Reject(()=>new ExternalReadPolicy(new[]{new ExternalReadPolicy.PathLimit(file,3758096385,true)}),"maximum retained");
        Reject(()=>new ExternalReadPolicy(new[]{new ExternalReadPolicy.PathLimit(file,0,true)}),"invalid limit");
        Reject(()=>new ExternalReadPolicy(new[]{rule,rule}),"duplicate policy rejected");
        return 14;
    }
}
