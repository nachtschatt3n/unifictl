# CI, dependency policy and releases

`ci.yml` checks formatting, Clippy, tests/builds on Linux, macOS and Windows,
and dependencies. `test.yml` additionally exercises stable, beta and nightly
Rust. Cargo build, check and test commands use the committed lockfile. Action
implementations are pinned to full commit hashes; review these pins when
updating them. The stable Rust toolchain itself follows stable releases.

## Dependency policy

All three CI/release workflows run
`bash .github/workflows/audit.sh "$RUNNER_TEMP/audit.json"`. The artifact upload
uses the same runner temporary path, outside the Git checkout, so audit evidence
cannot dirty the source package or become part of a published crate.
The script installs **cargo-audit 0.22.2 with its locked dependencies** into an
isolated temporary directory. Missing tooling, installation/network/database
errors, vulnerability matches and advisory warnings all fail the job. There are
no blanket advisory ignores or successful fallbacks. The JSON report is retained
as an Actions artifact; the tool version is recorded in the step log and the
report records the advisory database metadata when fetched.

A green audit checks the lockfile against the database at that time. It is not
proof that all code or downloaded binaries are safe. Any proposed exception
needs a specific advisory, dependency/feature/target scope, owner, justification,
expiry and review before changing the gate. No exceptions are currently defined.

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets
python3 .github/workflows/test_supply_chain.py  # Python 3.11+
audit_report=$(mktemp)
bash .github/workflows/audit.sh "$audit_report"
```

CI also runs `cargo package --locked` after the audit, before a release tag is
needed. CI, comprehensive tests and release validation all reject Clippy warnings.

The Python tests are offline failure injections: audit installation/execution
failures, malformed/mismatched release tags, missing/empty/duplicate/unexpected
assets, and altered/incomplete uploaded bytes must block their gate. A minimal
committed Cargo fixture executes the actual workflow audit commands with a mock
auditor, then packages successfully with evidence outside its checkout; an
untracked audit file inside the checkout must fail packaging. This fixture has
its own Cargo target directory.

## Release contract

A tag push or manual dispatch starts `release.yml`. A manual dispatch requires
an **existing stable `vMAJOR.MINOR.PATCH` tag pointing to the selected commit**.
A prerelease tag matching the trigger starts validation and is rejected.
The tag's version must match `Cargo.toml`. The validation job records the exact
commit, then runs formatting, Clippy, all tests, the negative gate tests, the
strict dependency audit and a locked crates.io publish dry run. Every build and
publication depends on this common validation.

The required asset set is:

- Linux x86_64 binary archive;
- macOS x86_64 and aarch64 binary archives;
- Windows x86_64 ZIP archive;
- Debian amd64 and arm64 packages;
- Arch x86_64 and aarch64 packages.

All eight files must exist, be nonempty, and have exactly the expected names.
Artifact download or build failure blocks publication. The verified set is
flattened into `dist/`, with SHA-256 checksums and `release-source.json` containing
the source commit and lockfile digest. No partial build matrix is published.

The GitHub release is published first. crates.io publication runs only after the
GitHub release is public, and is optional: without `CRATES_IO_TOKEN`, its step
reports that the channel is disabled. A failed GitHub release therefore never
leaves an unretractable crates.io version behind. The GitHub job refuses to alter
an already-public release, uploads to a draft, downloads the uploaded assets, and
compares every file's bytes to the verified set. Only then does it make the draft
public/latest. An interrupted upload leaves a draft for inspection or a retry; it
must not be promoted manually without repeating verification. There is no atomic
transaction between the two channels: if crates.io fails after the GitHub release
is public, re-run only the publish job.

Only the GitHub publication job has `contents: write`; build/validation jobs
have read access and do not persist checkout credentials. Configure repository
rules to protect version tags and require human review of release-workflow
changes. Registry credentials should have only the required publishing scope.
These repository/account settings cannot be enforced by this YAML alone.

Checksums detect corruption relative to this pipeline's output. They are not an
independent signature, build attestation or reproducible-build proof. No release
or foreign-platform build is implied by local tests of the workflow contracts.
The separate manually triggered Homebrew workflow is not part of this validated
release transaction and needs its own publication review.
