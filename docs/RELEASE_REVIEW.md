# Release review â€” not yet a release

Before public release or provider submission:

1. Approve the exact source membership and source disclosure; confirm ownership
   and any third-party notices, copyright holder and MIT license text.
2. Review the extracted policy API and its prepared tests. Compile-only and
   Python contract/model checks do not count as executed C# native tests.
3. Name the public repository, maintainers, reviewers and signing approvers;
   verify MFA and a genuine ongoing maintenance/release process.
4. Review the manual build workflow, pinned actions and runtime. Hosted-runner
   availability of the pinned compiler is unverified; fail rather than drift.
5. Make an actual source/binary release only with owner publication approval.
   SignPath requires an existing maintained release and decides eligibility.
6. Submit only the approved project information, with its real qualification
   limitations. No current preview has an approved certificate or trusted load.

Consumer adoption is separate: private path-policy bindings, full preservation,
signature trust, actual enforced-load checks, unchanged Job/handle/accounting
semantics and fresh finite execution authority are mandatory. The extracted
library is a new version. Original accepted binaries and failures remain intact.

No performance improvement or regression has yet been established for a signed
version. Deterministic compile comparison, if passed, applies only to the exact
recorded environment and source sets; it is not a runtime performance benchmark.

The exact proposed MIT attribution is "Copyright (c) 2026 Bounded Execution Windows contributors". The owner must confirm that attribution and rights to every included source before adoption. No third-party code or compiler binaries are redistributed. Existing private source provenance is reviewed separately and is not release content.
