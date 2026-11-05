# Bounded Execution Windows — unsigned developer preview

Published under MIT. The original reviewed release is v0.1.0-preview.1. This candidate adds a finite unsigned hosted-build qualification; no hosted PASS, signing or runtime qualification is claimed. Prepublication notices below and in the original release are historical review records.


A Windows/.NET helper library for process accounting, held-handle identity checks,
strict file publication, runtime-scratch classification and evidence readback.
This is a proposed standalone open-source extraction. It is not published,
signed, approved by a signing provider, or qualified for production execution.

The library contains no trading strategy, price archive, financial evaluator,
account credentials, research database or private campaign configuration.
Some legacy API/schema names refer to financial hosts; they are retained for
consumer compatibility and contain no financial calculations. It is intended
to be maintained as a reusable developer library, not as a signature wrapper.

## Build without loading the output

Windows, PowerShell7.6.5 and .NET10.0.11 are the reviewed compile environment.
No third-party runtime packages or network restore are used by this build.

```powershell
./build.ps1 -Profile Compact -OutputDirectory C:/build-output/compact-001
```

The parent output directory must exist and the chosen output directory must be
new. The script verifies an explicit source manifest, rejects reparse paths,
compiles a library, and writes a bounded build receipt without loading the DLL.
The installed compiler and complete reference set must match `toolchain.json`;
all hashes are checked again after compilation. No compiler is downloaded by it.
`-IncludeContractTests` compiles prepared pure-policy assertions into a separate
test artifact; it does not run them. A separately named PolicyTests artifact is proposed for signing only if the provider accepts it; tests are not executed by this build.
Build each profile in its own process. Do not silently raise the local6CPU/10wall/
512MiB compilation limits. The helper's131,072-byte total signed-file cap remains.

`Compact` and `Extended` select separate fixed source variants. These preserve
the original accounting predicates; they are not interchangeable resource grants.
The extended variant's presence does not authorize a larger workload. A consumer
must independently authorize, bind and enforce its process and storage budgets.

## Read policies

`AtomicPostReadback.Read(path)` has a conservative6MiB per-file ceiling.
Explicit exceptions use an immutable `ExternalReadPolicy` containing at most
four exact absolute local paths. Rules retain their declared ordinal or
ordinal-ignore-case comparison. No filename or directory wildcard is accepted.
The caller must seal the complete policy alongside its sources and authority.
`Read(path, policy)` and `Preparation(root, policy)` apply that policy without
changing native access/share flags, reparse rejection, final-path checks,
held-file identity, hashing, close order or first-failure preservation.

Legacy consumers with hard-coded private path exceptions need a separately
reviewed adapter to pass their exact original policy. This preview is not a
drop-in runtime replacement for those consumers. Default reads cannot silently
inherit a former private exception. Native runtime qualification remains pending.

## Security and privacy

This library calls Windows APIs using the caller's existing permissions. It can
start/account/terminate processes and operate on explicitly supplied files.
It is not a security sandbox or a privilege boundary by itself. Callers must
retain trusted source bindings, authorization, cancellation and containment.
There is no network client, trading operation, system-policy modification,
certificate-store installer or unsigned-code loading workaround in this project.
Diagnostics can contain caller-supplied paths; users control their destination.
Do not publish logs containing private paths or data. Installation consists of
copying a reviewed artifact into a consumer package; uninstall by removing that
consumer-owned copy after its processes exit. No service is installed.

## License and signing status

MIT is proposed in `LICENSE` (exact proposed text; see `PREPUBLICATION_NOTICE.md`), subject to the copyright holder's
approval. No effective public license or provider acceptance is claimed yet.
See `docs/SIGNING_POLICY.md`, `docs/RELEASE_REVIEW.md` and
`HOSTED_TOOLCHAIN_PLAN.json`. No signing secrets are embedded.

Compile and metadata/static results do not prove successful enforced Windows
loading, native containment, runtime financial equivalence or replay throughput.

The default hosted image is not the pinned runtime. `.ci/hosted-release.yml.in`
is an inactive proposal, not an installed GitHub workflow. The portable official
archive must satisfy every toolchain hash before it can build these sources.
Provisioning has a separate, not-yet-authorized budget; local compile limits stay
unchanged. No repository history, PDB, private adapter or market data is included.

Unsigned builds and signing requests are separate workflow choices. Release staging verifies exact source, compiler, resources and all three build receipts before any upload. The workflow remains inactive and intentionally stops before provisioning until its finite hosted setup is reviewed.
