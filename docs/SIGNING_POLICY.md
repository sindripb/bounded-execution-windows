# Code signing policy — proposed

This is an unsigned private release candidate. SignPath has given conditional
eligibility guidance; project acceptance, trusted builds and signed releases
remain pending. No sponsorship or certificate is claimed.

The proposed signing scope is the Compact and Extended library profiles and a
separately identified PolicyTests library. All must be built from this project's
public source. Compiler/runtime dependencies and private downstream applications
are not signing artifacts. The library must remain independently maintained and
fully open source; the proposed license is MIT without commercial dual licensing.

The project owner must name the author/reviewer and release approver before
application. One maintainer may perform all roles. MFA is required for repository
and signing access. Each signing request requires manual release approval.

Only a reviewed source revision, exact source manifest, fixed compiler/reference
identities and three verified build receipts may reach artifact staging. All jobs
leading to an OSS signing request must run on GitHub-hosted agents. SignPath must
verify the repository/ref and artifact origin. Repository variables and a passing
build alone do not authorize signing or spending resources.

The inactive workflow supports unsigned builds separately from a signing request.
It has no pull-request trigger, no self-hosted runner, no broad write token and no
automatic release publishing. Token access belongs only to the conditional
signing step. All action revisions are commit-pinned. Setup allocation, repository
identity, maintainer roles, provider configuration and protected environment need
review before activation. The official toolchain archive has not been downloaded
or qualified on a hosted runner.

The XML artifact configuration fixes three DLL paths and product/file versions.
Provider acceptance of this configuration is pending. Signed outputs will need
separate trust/timestamp/image-delta checks and target-machine policy testing.
Successful signing cannot substitute for runtime qualification.

Privacy: this library sends no network telemetry. It inspects caller-selected
processes and files and may include paths in diagnostics. Build and signing
services process the public source and library artifacts under their own terms.
Private downstream data, credentials and configuration must never be uploaded.

After actual provider acceptance, update this page with the approved named roles
and the provider's required attribution. Do not imply acceptance beforehand.

References:
- https://signpath.org/terms
- https://docs.signpath.io/trusted-build-systems/github
- https://docs.signpath.io/artifact-configuration/reference
