# Continuous integration

CI is paused. Both workflow definitions have the `.yml.disabled` suffix, so
GitHub Actions does not discover them. No push, pull-request, scheduled or manual
workflow is active in this checkout. This change takes effect on GitHub when
pushed; it does not cancel an already running job. To reactivate, rename
`ci.yml.disabled` and `iit.yml.disabled` to `.yml` in `.github/workflows`.
While paused, validate their syntax with:

```sh
actionlint .github/workflows/ci.yml.disabled .github/workflows/iit.yml.disabled
```

The following describes the workflows when enabled.

`.github/workflows/ci.yml` runs on pushes, pull requests, manual dispatches and
Monday mornings. It uses the Go minor version declared in `go.mod` with the
latest available patch (`check-latest: true`). In the initial local check,
Go 1.27.0 had nine reachable standard-library advisories; Go 1.27.3 passed
`govulncheck`. Use a patched toolchain when reproducing the jobs.

The hosted jobs run:

- Windows and Linux unit tests with `-count=1 -shuffle=on`, plus `go vet`.
- The full Linux suite with the race detector, and a CGo-free CLI build on
  both platforms.
- golangci-lint 2.15.0 with `.golangci-ci.yml`: vet, ineffective assignments,
  bidirectional-text checks and staticcheck's `SA` correctness checks.
- govulncheck 1.9.0 against the current public Go vulnerability database.
- actionlint 1.7.12 to validate the workflow definitions.

Action revisions are pinned to commit hashes. Tool installation is versioned
and does not add tool dependencies to this module. Module commands use
`-mod=readonly`. The normal jobs use hosted runners and need no SDK or secrets.
The checked-in CZO examples are used directly; the existing test fixture helper
can fetch missing examples from CZO. Native and live timestamp checks are not
part of these jobs.

The stricter `.golangci.yml` remains available for style/complexity and unused-code
cleanup; it is not the CI baseline. Three narrowly scoped staticcheck exclusions
cover two intentional nil-context rejection tests and the standard-library OFB
reference test. `task lint-ci` reproduces CI without staging files or running
`go mod tidy`. The broader `task lint-only` also avoids staging; `task lint` and
`task lint-fix` currently have a staging/tidy step. Both use linter 2.15.0, since
the previous 2.11.4 cannot read Go 1.27 export data.

## Optional licensed IIT runner

`.github/workflows/iit.yml` is manually dispatched and accepts only the default
branch. It never runs pull-request revisions. Provision a dedicated disposable
Windows x64 runner with labels `self-hosted`, `Windows`, `X64`, `crypto-dstu-iit`,
PowerShell 7, Git, and access to Go downloads. Restrict the runner to this trusted
repository; do not use a workstation with taxpayer keys or application stores.

Install the licensed SDK and extracted public CZO test CA bundle outside the
checkout. Configure these repository Actions variables:

| Variable | Value |
| --- | --- |
| `IIT_SDK_DIRECTORY` | Absolute runner directory containing `EUSignCP.dll` and auxiliary DLLs |
| `IIT_TEST_CA_DIRECTORY` | Absolute directory containing the public test CA bundle |
| `IIT_SDK_SHA256` | Approved 64-digit SHA256 of `EUSignCP.dll` |

Missing directories or a missing/mismatched hash fail the selected job. No SDK,
CA archive, private key, or native configuration is downloaded or uploaded by
this workflow. The runner invokes the existing isolated `scripts/test-iit.ps1`,
which builds the adapter for the DLL architecture, uses temporary settings and
stores, disables SDK network services/UI, checks the hash, and removes temporary
files. It exercises the PKCS#12, CMS and profile matrix, including the opt-in ONB
diagnostic. Known ONB diagnostic errors are recorded outcomes, not evidence of
successful ONB interoperability; see [the native matrix](iit-interoperability.md).
The live CZO TSA test remains disabled.

The workflow files do not provision a runner or change repository settings.
An actual hosted run and a configured native runner run are still required after
pushing these changes. Local workflow validation uses actionlint 1.7.12; the
custom runner label is declared in `.github/actionlint.yaml`.
